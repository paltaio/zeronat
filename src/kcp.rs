use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use kcp::Kcp;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

pub const CLASS_KCP: u8 = 0x01;
pub const CLASS_SETUP: u8 = 0x02;
pub const CLASS_DGRAM: u8 = 0x03;
pub const KCP_MTU: usize = 1350;

/// High bit marking a UDP-forward setup/datagram conv. Auto-allocated stream
/// convs (control + TCP-forward) come from a counter starting at 1 and stay in
/// the low half, so setup convs derived from the control id never collide with
/// an already-open stream conv.
pub const SETUP_CONV_BIT: u32 = 0x8000_0000;

/// Fixed conv id tagging a connection as the L2 bridge setup conv over UDP. Uses
/// `SETUP_CONV_BIT` with zero low bits; auto-allocated stream convs start at 1 and
/// UDP-forward setup convs derive from ids that also start at 1, so this value
/// never collides with either. It is a per-connection role marker: the server
/// attaches each client carrying it to its own switch port.
pub const BRIDGE_CONV: u32 = SETUP_CONV_BIT;

/// Reserved stream id tagging a connection as the L2 bridge data stream over the
/// TCP fallback. A per-connection role marker: each client using it gets its own
/// switch port on the server.
pub const BRIDGE_ID: u64 = u64::MAX;

const SOCKET_SEND_CAP: usize = 1024;
const APP_CHAN_CAP: usize = 256;

/// Cap on concurrent convs a single peer session may hold open. A legitimate
/// client carries the control conv plus a handful of TCP/UDP-forward convs, so
/// this sits orders of magnitude above real usage; it exists only to stop one
/// source on the public control port from streaming unbounded distinct conv-ids
/// and spawning a driver (each holds a ~64KB recv buffer) per id. Combined with
/// `server::MAX_UDP_SESSIONS`, the worst-case driver-buffer ceiling is
/// MAX_UDP_SESSIONS * MAX_CONVS_PER_SESSION * ~64KB ~= 512 * 256 * 64KB ~= 8GB.
pub const MAX_CONVS_PER_SESSION: usize = 256;

/// Per-conv idle deadline. A conv with no inbound packet for this long is dead
/// (KCP has no FIN, so a silent peer never signals close). Set far above the
/// KCP RTO and any normal inter-packet gap so an active-but-slow conv survives,
/// and >= the app-level 90s control deadline so the app layer trips first on the
/// control conv (the client pings every 25s, well within this window).
const CONV_IDLE: Duration = Duration::from_secs(180);

/// `std::io::Write` sink handed to a `Kcp`. Each `write` is one KCP packet; we
/// prefix the class byte and hand it to the socket-sender channel without
/// blocking (KCP retransmits anything dropped under backpressure).
pub struct ChannelWriter {
    tx: mpsc::Sender<Vec<u8>>,
    class: u8,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut pkt = Vec::with_capacity(buf.len() + 1);
        pkt.push(self.class);
        pkt.extend_from_slice(buf);
        let _ = self.tx.try_send(pkt);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn new_kcp(conv: u32, tx: mpsc::Sender<Vec<u8>>, class: u8) -> Kcp<ChannelWriter> {
    let mut k = Kcp::new(conv, ChannelWriter { tx, class });
    k.set_nodelay(true, 10, 2, true);
    k.set_wndsize(256, 256);
    let _ = k.set_mtu(KCP_MTU);
    k
}

/// Drains the socket-sender channel to the single per-session peer address.
async fn socket_writer(
    socket: Arc<UdpSocket>,
    peer: std::net::SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(pkt) = rx.recv().await {
        let _ = socket.send_to(&pkt, peer).await;
    }
}

/// Channels connecting a `KcpStream` to its driver task.
struct ConvChannels {
    inbound_rx: mpsc::Receiver<Vec<u8>>, // KCP packets (class byte stripped)
    write_rx: mpsc::Receiver<Vec<u8>>,   // app bytes to send
    read_tx: mpsc::Sender<Vec<u8>>, // decoded app bytes out (empty Vec => EOF not used; closing the channel signals EOF)
}

async fn drive_conv(mut kcp: Kcp<ChannelWriter>, mut ch: ConvChannels) {
    let base = Instant::now();
    let now_ms = move || base.elapsed().as_millis() as u32;
    let mut buf = vec![0u8; 65535];
    let mut write_open = true;
    let mut reader_open = true;
    // Monotonic last-progress mark; immune to wall-clock steps. Reset on every
    // inbound packet so an active conv never trips the idle deadline.
    let mut last_seen = Instant::now();

    loop {
        let now = now_ms();
        if kcp.update(now).is_err() {
            return;
        }
        // Drain all complete messages KCP has reassembled.
        while let Ok(n) = kcp.recv(&mut buf) {
            if ch.read_tx.send(buf[..n].to_vec()).await.is_err() {
                return; // reader gone
            }
        }
        // Both stream halves are gone and every queued byte has been sent and
        // acked: the conv is finished, so release its slot now rather than
        // holding it until CONV_IDLE. A dropped stream with unacked data keeps
        // the driver alive to retransmit the tail; against a silent peer the
        // idle deadline below still bounds that. A stray late segment for a
        // reaped conv re-enters route_kcp as a new peer-initiated conv; it
        // fails its handshake and idles out, bounded by MAX_CONVS_PER_SESSION.
        if !reader_open && !write_open && kcp.wait_snd() == 0 {
            return;
        }
        let delay = kcp.check(now_ms()).max(1);
        tokio::select! {
            pkt = ch.inbound_rx.recv() => match pkt {
                Some(p) => { let _ = kcp.input(&p); last_seen = Instant::now(); }
                None => return, // mux dropped this conv
            },
            data = ch.write_rx.recv(), if write_open => match data {
                Some(d) => { let _ = kcp.send(&d); }
                None => { write_open = false; }
            },
            _ = ch.read_tx.closed(), if reader_open => { reader_open = false; }
            _ = tokio::time::sleep(Duration::from_millis(delay as u64)) => {
                if last_seen.elapsed() >= CONV_IDLE {
                    return; // silent peer; reclaim KCP state and the map entry
                }
            }
        }
    }
}

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{OwnedPermit, Sender};

type ReserveFut = Pin<
    Box<
        dyn Future<Output = Result<OwnedPermit<Vec<u8>>, tokio::sync::mpsc::error::SendError<()>>>
            + Send,
    >,
>;

pub struct KcpStream {
    write_tx: Sender<Vec<u8>>,
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    reserve: Option<ReserveFut>,
}

impl KcpStream {
    pub fn new(write_tx: Sender<Vec<u8>>, read_rx: mpsc::Receiver<Vec<u8>>) -> Self {
        KcpStream {
            write_tx,
            read_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            reserve: None,
        }
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos >= self.read_buf.len() {
            match self.read_rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.read_buf = chunk;
                    self.read_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = std::cmp::min(buf.remaining(), self.read_buf.len() - self.read_pos);
        buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Some(fut) = self.reserve.as_mut() {
                return match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        permit.send(buf.to_vec());
                        self.reserve = None;
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Err(_)) => {
                        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            let tx = self.write_tx.clone();
            self.reserve = Some(Box::pin(tx.reserve_owned()));
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

type ConvMap = Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>;

/// When a conv driver or dgram receiver ends, decrements the session's live
/// counter (so an idle session can be reclaimed) and erases its own entry from
/// the owning map (so the convs/dgrams maps stay bounded by concurrent, not
/// cumulative, connections). One guard, both cleanups, fires on every exit path.
pub struct ConvGuard {
    live: Arc<AtomicUsize>,
    map: ConvMap,
    key: u32,
}

impl Drop for ConvGuard {
    fn drop(&mut self) {
        // std::sync::Mutex only, no .await in this scope: cannot block a runtime.
        self.map.lock().unwrap().remove(&self.key);
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Released when an attached bridge ends, clearing the session's bridge-attached
/// flag so a later reconnect within the same session can attach again.
pub struct BridgeGuard {
    attached: Arc<AtomicBool>,
}

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        self.attached.store(false, Ordering::Release);
    }
}

/// Shared per-(socket,peer) multiplexing state.
pub struct Session {
    send_tx: mpsc::Sender<Vec<u8>>,
    convs: ConvMap,  // conv id -> inbound packets
    dgrams: ConvMap, // tag -> [nonce][ct] bodies
    next_conv: Mutex<u32>,
    // Count of live conv drivers + dgram receivers; reaches zero when the session
    // carries nothing, letting the control listener reclaim it.
    live: Arc<AtomicUsize>,
    // Set while this session has one live bridge port. One bridge per session is
    // expected; a second concurrent attach is refused so two switch ports never
    // learn and ping-pong the same client's MAC.
    bridge_attached: Arc<AtomicBool>,
}

impl Session {
    fn spawn_conv(&self, conv: u32, class: u8) -> KcpStream {
        let (inbound_tx, inbound_rx) = mpsc::channel(SOCKET_SEND_CAP);
        let (write_tx, write_rx) = mpsc::channel(APP_CHAN_CAP);
        let (read_tx, read_rx) = mpsc::channel(APP_CHAN_CAP);
        self.convs.lock().unwrap().insert(conv, inbound_tx);
        self.live.fetch_add(1, Ordering::Relaxed);
        let guard = ConvGuard {
            live: self.live.clone(),
            map: self.convs.clone(),
            key: conv,
        };
        let kcp = new_kcp(conv, self.send_tx.clone(), class);
        tokio::spawn(async move {
            let _guard = guard;
            drive_conv(
                kcp,
                ConvChannels {
                    inbound_rx,
                    write_rx,
                    read_tx,
                },
            )
            .await;
        });
        KcpStream::new(write_tx, read_rx)
    }

    /// True once the session carries no live conv or dgram (and never did, or all
    /// have ended). A freshly built session reads zero until a conv is opened.
    pub fn is_idle(&self) -> bool {
        self.live.load(Ordering::Relaxed) == 0
    }

    /// Initiator: open a stream/setup conv with a caller-chosen conv id.
    pub fn open_conv_with(&self, class: u8, conv: u32) -> KcpStream {
        self.spawn_conv(conv, class)
    }

    /// Initiator: allocate a fresh conv id and open a stream/setup conv.
    pub fn open_conv(&self, class: u8) -> (u32, KcpStream) {
        let conv = {
            let mut n = self.next_conv.lock().unwrap();
            let c = *n;
            *n = n.wrapping_add(1);
            c
        };
        (conv, self.spawn_conv(conv, class))
    }

    fn route_kcp(&self, conv: u32, class: u8, payload: Vec<u8>) -> Option<KcpStream> {
        {
            let convs = self.convs.lock().unwrap();
            if let Some(tx) = convs.get(&conv) {
                let _ = tx.try_send(payload);
                return None;
            }
            // Unknown conv beyond the per-session cap: drop the datagram and spawn
            // no driver. Existing convs keep flowing; only new ids are refused, so
            // one flooding source cannot grow this session's driver count without
            // bound. The map len is the live conv count (ConvGuard erases an entry
            // when its driver ends), and the check holds the lock so it is exact.
            if convs.len() >= MAX_CONVS_PER_SESSION {
                return None;
            }
        }
        // Unknown conv: a peer-initiated connection. Create it, deliver the packet.
        let stream = self.spawn_conv(conv, class);
        if let Some(tx) = self.convs.lock().unwrap().get(&conv) {
            let _ = tx.try_send(payload);
        }
        Some(stream)
    }

    fn route_dgram(&self, tag: u32, body: Vec<u8>) {
        if let Some(tx) = self.dgrams.lock().unwrap().get(&tag) {
            let _ = tx.try_send(body);
        }
    }

    /// Register a dgram tag. The returned guard must outlive the dgram bridge so
    /// the session is not reclaimed while the bridge is still running.
    pub fn register_dgram(&self, tag: u32) -> (mpsc::Receiver<Vec<u8>>, ConvGuard) {
        let (tx, rx) = mpsc::channel(APP_CHAN_CAP);
        self.dgrams.lock().unwrap().insert(tag, tx);
        self.live.fetch_add(1, Ordering::Relaxed);
        let guard = ConvGuard {
            live: self.live.clone(),
            map: self.dgrams.clone(),
            key: tag,
        };
        (rx, guard)
    }

    pub fn send_tx(&self) -> mpsc::Sender<Vec<u8>> {
        self.send_tx.clone()
    }

    /// Claim this session's single bridge slot. Returns `Some(guard)` for the
    /// first attach and `None` while a bridge is already live, so a second
    /// concurrent bridge attach in the same session is refused. The guard clears
    /// the slot on drop, so a later reconnect within the session can attach again.
    pub fn try_attach_bridge(&self) -> Option<BridgeGuard> {
        match self.bridge_attached.compare_exchange(
            false,
            true,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Some(BridgeGuard {
                attached: self.bridge_attached.clone(),
            }),
            Err(_) => None,
        }
    }
}

/// What the RX router yields when a peer opens a new conv.
pub enum Accepted {
    Stream { conv: u32, stream: KcpStream },
    Setup { conv: u32, stream: KcpStream },
}

/// Build a session bound to `peer` and spawn its socket-sender task. Returns the
/// session plus the receive loop driver inputs. The caller runs `recv_loop`.
pub fn session(socket: Arc<UdpSocket>, peer: SocketAddr, first_conv: u32) -> Arc<Session> {
    let (send_tx, send_rx) = mpsc::channel(SOCKET_SEND_CAP);
    tokio::spawn(socket_writer(socket, peer, send_rx));
    Arc::new(Session {
        send_tx,
        convs: Arc::new(Mutex::new(HashMap::new())),
        dgrams: Arc::new(Mutex::new(HashMap::new())),
        next_conv: Mutex::new(first_conv),
        live: Arc::new(AtomicUsize::new(0)),
        bridge_attached: Arc::new(AtomicBool::new(false)),
    })
}

/// Feed one received datagram (already addressed to this session's peer) into the
/// router. Returns `Some(Accepted)` when it opened a new peer-initiated conv.
pub fn route(session: &Session, datagram: &[u8]) -> Option<Accepted> {
    let (&class, rest) = datagram.split_first()?;
    match class {
        CLASS_KCP | CLASS_SETUP => {
            if rest.len() < kcp::KCP_OVERHEAD {
                return None;
            }
            let conv = kcp::get_conv(rest);
            match session.route_kcp(conv, class, rest.to_vec()) {
                Some(stream) if class == CLASS_KCP => Some(Accepted::Stream { conv, stream }),
                Some(stream) => Some(Accepted::Setup { conv, stream }),
                None => None,
            }
        }
        CLASS_DGRAM => {
            if rest.len() < 4 {
                return None;
            }
            let tag = u32::from_be_bytes(rest[..4].try_into().unwrap());
            session.route_dgram(tag, rest[4..].to_vec());
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{client_handshake, derive_psk, server_handshake};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kcpstream_carries_noise() {
        let psk = derive_psk("kcp loopback");
        let cli_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let srv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let cli_addr = cli_sock.local_addr().unwrap();
        let srv_addr = srv_sock.local_addr().unwrap();

        let cli = session(cli_sock.clone(), srv_addr, 1);
        let srv = session(srv_sock.clone(), cli_addr, 0);

        // Server RX loop: accept the first stream conv, run a server handshake, echo one frame.
        let srv_run = {
            let srv = srv.clone();
            let srv_sock = srv_sock.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    let (n, _) = srv_sock.recv_from(&mut buf).await.unwrap();
                    if let Some(Accepted::Stream { stream, .. }) = route(&srv, &buf[..n]) {
                        tokio::spawn(async move {
                            let (mut r, mut w) = server_handshake(stream, &psk).await.unwrap();
                            let msg = r.recv().await.unwrap();
                            w.send(&msg).await.unwrap();
                        });
                    }
                }
            })
        };
        // Client RX loop.
        let cli_run = {
            let cli = cli.clone();
            let cli_sock = cli_sock.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    let (n, _) = cli_sock.recv_from(&mut buf).await.unwrap();
                    route(&cli, &buf[..n]);
                }
            })
        };

        let (_conv, stream) = cli.open_conv(CLASS_KCP);
        let (mut r, mut w) = client_handshake(stream, &psk).await.unwrap();
        w.send(b"over-kcp").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), r.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"over-kcp");

        srv_run.abort();
        cli_run.abort();
    }

    // Dropping a KcpStream with nothing in flight must release the conv's map
    // slot promptly, not hold it for the full CONV_IDLE window. The peer stays
    // silent, so only the stream drop can trigger the reap.
    #[tokio::test(start_paused = true)]
    async fn dropped_stream_releases_conv_slot() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = sock.local_addr().unwrap();
        let sess = session(sock, peer, 1);

        let (conv, stream) = sess.open_conv(CLASS_KCP);
        assert!(sess.convs.lock().unwrap().contains_key(&conv));

        drop(stream);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !sess.convs.lock().unwrap().contains_key(&conv),
            "conv slot still held after stream drop"
        );
        assert!(sess.is_idle(), "live counter must reach zero after reap");
    }

    // Data written right before the stream drops must still reach the peer:
    // the driver lingers to retransmit the unacked tail and reaps only once
    // the peer has acked it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_stream_flushes_pending_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cli_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let srv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let cli_addr = cli_sock.local_addr().unwrap();
        let srv_addr = srv_sock.local_addr().unwrap();

        let cli = session(cli_sock.clone(), srv_addr, 1);
        let srv = session(srv_sock.clone(), cli_addr, 0);

        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let srv_run = {
            let srv = srv.clone();
            tokio::spawn(async move {
                let mut accepted_tx = Some(accepted_tx);
                let mut buf = [0u8; 65535];
                loop {
                    let (n, _) = srv_sock.recv_from(&mut buf).await.unwrap();
                    if let Some(Accepted::Stream { stream, .. }) = route(&srv, &buf[..n]) {
                        if let Some(tx) = accepted_tx.take() {
                            let _ = tx.send(stream);
                        }
                    }
                }
            })
        };
        let cli_run = {
            let cli = cli.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    let (n, _) = cli_sock.recv_from(&mut buf).await.unwrap();
                    route(&cli, &buf[..n]);
                }
            })
        };

        let payload = vec![0xABu8; 64 * 1024];
        let (_conv, mut stream) = cli.open_conv(CLASS_KCP);
        for chunk in payload.chunks(16 * 1024) {
            stream.write_all(chunk).await.unwrap();
        }
        drop(stream);

        let mut srv_stream = tokio::time::timeout(Duration::from_secs(5), accepted_rx)
            .await
            .unwrap()
            .unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), srv_stream.read_exact(&mut got))
            .await
            .expect("peer must receive the full payload despite the stream drop")
            .unwrap();
        assert_eq!(got, payload);

        // Once the tail is acked the client's conv slot must be released.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cli.convs.lock().unwrap().is_empty() {
            assert!(
                Instant::now() < deadline,
                "conv slot not reaped after flush"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        srv_run.abort();
        cli_run.abort();
    }

    /// One CLASS_KCP datagram (class byte + minimal KCP header) naming `conv`,
    /// the shape `route` parses on the public control port.
    fn kcp_datagram(conv: u32) -> Vec<u8> {
        let mut pkt = vec![0u8; 1 + kcp::KCP_OVERHEAD];
        pkt[0] = CLASS_KCP;
        kcp::set_conv(&mut pkt[1..], conv);
        pkt
    }

    // A flood of distinct conv-ids from one peer must never grow the session's
    // live conv count past MAX_CONVS_PER_SESSION: beyond the cap each unknown
    // conv is dropped with no driver spawned, while convs already open keep
    // their slot. This is the anti-OOM bound on a single source. The accepted
    // streams are held for the test's duration; a dropped stream would release
    // its slot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn route_kcp_caps_convs_per_session() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = sock.local_addr().unwrap();
        let sess = session(sock, peer, 0);

        let mut streams = Vec::new();
        for conv in 0..(MAX_CONVS_PER_SESSION as u32 + 200) {
            if let Some(Accepted::Stream { stream, .. }) = route(&sess, &kcp_datagram(conv)) {
                streams.push(stream);
            }
            assert!(
                sess.convs.lock().unwrap().len() <= MAX_CONVS_PER_SESSION,
                "conv count exceeded cap at conv {conv}"
            );
        }
        assert_eq!(
            sess.convs.lock().unwrap().len(),
            MAX_CONVS_PER_SESSION,
            "first MAX_CONVS_PER_SESSION convs must stay open; the rest dropped"
        );
    }
}
