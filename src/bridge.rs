use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::noise::{NoiseReader, NoiseWriter};
#[cfg(target_os = "linux")]
use crate::tap::TapDevice;

const TCP_BUF: usize = 16 * 1024;
const UDP_BUF: usize = 65535;
pub const UDP_IDLE: Duration = Duration::from_secs(120);
/// Upper bound on a single reliable-writer send/probe. Without it, an arm parked
/// in `nw.send` against a black-holed peer would starve the idle `tick`, so the
/// last_in reaper could never run. A bounded send fails closed and reaps.
const UDP_SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// A forwarded TCP stream idle in both directions for this long is treated as
/// dead (black-holed by a NAT/firewall with no FIN/RST) and reaped.
pub const TCP_IDLE: Duration = Duration::from_secs(120);

/// The local plaintext side of a reliable relay. `read` yields the next chunk
/// (an empty `Vec` signals a closed local side, e.g. a TCP EOF); `write`
/// delivers a decrypted frame back to it. Both take `&mut self` and are driven
/// from independent halves so the two directions never serialize.
trait LocalRead {
    fn read(&mut self) -> impl Future<Output = crate::Result<Vec<u8>>>;
}
trait LocalWrite {
    fn write(&mut self, buf: &[u8]) -> impl Future<Output = crate::Result<()>>;
}

impl LocalRead for OwnedReadHalf {
    async fn read(&mut self) -> crate::Result<Vec<u8>> {
        let mut buf = [0u8; TCP_BUF];
        let n = AsyncReadExt::read(self, &mut buf).await?;
        Ok(buf[..n].to_vec()) // empty == EOF
    }
}
impl LocalWrite for OwnedWriteHalf {
    async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.write_all(buf).await?;
        Ok(())
    }
}

/// Copy frames both ways between a reliable local side and the encrypted Noise
/// stream, on a probe-then-reap watchdog. Returns when the local side closes,
/// the encrypted stream errors, the peer stops answering liveness probes for
/// TCP_IDLE, or `cancel` resolves.
///
/// Both directions run concurrently so a write blocked on backpressure in one
/// never stalls the other (serializing them can deadlock a full-duplex stream).
/// The down half marks a shared timestamp on every inbound frame (including
/// empty keepalive probes) and the up half emits a probe once the link has been
/// quiet for half the window; a live peer answers and refreshes the mark, so the
/// independent watchdog reaps only on a true black hole (no inbound frame for the
/// whole window). The mark is in whole seconds: 32-bit targets (mips) have no
/// AtomicU64 and second resolution is ample for a 120s window.
async fn stream_relay<R, W, C>(
    mut local_r: R,
    mut local_w: W,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
    cancel: C,
) where
    R: LocalRead,
    W: LocalWrite,
    C: Future<Output = ()>,
{
    // tokio's clock so the idle math and the watchdog's sleep share one time
    // source (and so a paused-time test can drive it deterministically).
    let base = tokio::time::Instant::now();
    let last_in = Arc::new(AtomicU32::new(0));
    let win = TCP_IDLE.as_secs();

    let up = async move {
        loop {
            match timeout(Duration::from_secs(win / 2), local_r.read()).await {
                Ok(r) => {
                    let m = r?;
                    if m.is_empty() {
                        break;
                    }
                    // Bound the send so a send-side black hole cannot park here
                    // forever and starve the idle watchdog below.
                    match timeout(UDP_SEND_TIMEOUT, nw.send(&m)).await {
                        Ok(r) => r?,
                        Err(_) => break,
                    }
                }
                // Quiet for half the window: poke the peer. A live peer answers
                // (refreshing last_in via `down`); the independent watchdog below
                // reaps only if the whole window passes with no inbound frame.
                Err(_) => match timeout(UDP_SEND_TIMEOUT, nw.probe()).await {
                    Ok(r) => r?,
                    Err(_) => break,
                },
            }
        }
        Ok::<_, crate::Error>(())
    };
    let watch_in = last_in.clone();
    let down = async move {
        while let Ok(m) = nr.recv().await {
            watch_in.store(base.elapsed().as_secs() as u32, Ordering::Relaxed);
            if m.is_empty() {
                continue; // keepalive probe; nothing to forward
            }
            local_w.write(&m).await?;
        }
        Ok::<_, crate::Error>(())
    };
    // Independent watchdog so a peer that black-holes outbound traffic (parking
    // both `up` in nw.send and `down` in nr.recv) is still reaped once the probe
    // window elapses with no inbound frame.
    let idle = async {
        loop {
            let idle_for = base
                .elapsed()
                .as_secs()
                .saturating_sub(last_in.load(Ordering::Relaxed) as u64);
            if idle_for >= win {
                break;
            }
            tokio::time::sleep(Duration::from_secs(win - idle_for)).await;
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
        _ = idle => {}
        _ = cancel => {}
    }
}

/// Copy bytes both ways between a plaintext TCP stream and the encrypted
/// connection. Returns when either side closes or the peer stops answering
/// liveness probes for TCP_IDLE.
pub async fn tcp(plain: TcpStream, nr: NoiseReader, nw: NoiseWriter) {
    plain.set_nodelay(true).ok();
    let (pr, pw) = plain.into_split();
    stream_relay(pr, pw, nr, nw, std::future::pending()).await;
}

/// Client side of a UDP stream: shuttle datagrams between a local UDP socket
/// (connected to the target service) and the encrypted connection.
pub async fn udp_client(local: UdpSocket, mut nr: NoiseReader, mut nw: NoiseWriter) {
    let mut buf = [0u8; UDP_BUF];
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            m = nr.recv() => match m {
                Ok(m) => {
                    last_in = Instant::now();
                    m.is_empty() || local.send(&m).await.is_ok()
                }
                Err(_) => false,
            },
            r = local.recv(&mut buf) => match r {
                Ok(n) => matches!(timeout(UDP_SEND_TIMEOUT, nw.send(&buf[..n])).await, Ok(Ok(()))),
                Err(_) => false,
            },
            _ = tick.tick() => {
                last_in.elapsed() < UDP_IDLE
                    && matches!(timeout(UDP_SEND_TIMEOUT, nw.probe()).await, Ok(Ok(())))
            }
        };
        if !alive {
            break;
        }
    }
}

/// Server side of a UDP stream: forward inbound datagrams (from the public
/// socket, delivered via `dgram_rx`) to the client, and client datagrams back
/// out to the original source address.
pub async fn udp_server(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
) {
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            d = dgram_rx.recv() => match d {
                Some(d) => matches!(timeout(UDP_SEND_TIMEOUT, nw.send(&d)).await, Ok(Ok(()))),
                None => false,
            },
            m = nr.recv() => match m {
                Ok(m) => {
                    last_in = Instant::now();
                    m.is_empty() || socket.send_to(&m, src).await.is_ok()
                }
                Err(_) => false,
            },
            _ = tick.tick() => {
                last_in.elapsed() < UDP_IDLE
                    && matches!(timeout(UDP_SEND_TIMEOUT, nw.probe()).await, Ok(Ok(())))
            }
        };
        if !alive {
            break;
        }
    }
}

/// Local-side adapters for the TAP device: both halves share the device via
/// `Arc` because `read_frame`/`write_frame` take `&self`.
#[cfg(target_os = "linux")]
struct TapRead(Arc<TapDevice>);
#[cfg(target_os = "linux")]
struct TapWrite(Arc<TapDevice>);

#[cfg(target_os = "linux")]
impl LocalRead for TapRead {
    async fn read(&mut self) -> crate::Result<Vec<u8>> {
        // A TAP read is one whole Ethernet frame and never empty, so it never
        // collides with the empty-Vec EOF sentinel the relay uses for TCP.
        self.0.read_frame().await
    }
}
#[cfg(target_os = "linux")]
impl LocalWrite for TapWrite {
    async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.0.write_frame(buf).await
    }
}

/// Relay Ethernet frames between a TAP device and the unreliable datagram
/// channel (UDP transport). Returns when either side fails, the peer stops
/// answering keepalives for UDP_IDLE, or `cancel` fires (a newer bridge
/// superseding this one).
///
/// The tick keeps the CG-NAT UDP mapping warm and, paired with the idle mark,
/// self-heals if the mapping silently expires: with no inbound frame for the
/// whole window the relay reaps and the reconnect loop redials.
#[cfg(target_os = "linux")]
pub async fn tap_dgram(tap: Arc<TapDevice>, mut rx: DgramRx, tx: DgramTx, cancel: Arc<Notify>) {
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            _ = cancel.notified() => false,
            frame = tap.read_frame() => match frame {
                Ok(f) => tx.send(&f).await.is_ok(),
                Err(_) => false,
            },
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    match f {
                        Frame::Keepalive => true,
                        Frame::Data(d) => tap.write_frame(&d).await.is_ok(),
                    }
                }
                None => false,
            },
            _ = tick.tick() => last_in.elapsed() < UDP_IDLE && tx.probe().await.is_ok(),
        };
        if !alive {
            break;
        }
    }
}

/// Relay Ethernet frames between a TAP device and a reliable Noise stream (TCP
/// fallback). Each `send`/`recv` is one record, so frame boundaries are
/// preserved. Returns when either side closes, the peer stops answering probes
/// for TCP_IDLE, or `cancel` fires.
#[cfg(target_os = "linux")]
pub async fn tap_stream(
    tap: Arc<TapDevice>,
    nr: NoiseReader,
    nw: NoiseWriter,
    cancel: Arc<Notify>,
) {
    stream_relay(
        TapRead(tap.clone()),
        TapWrite(tap),
        nr,
        nw,
        cancel.notified(),
    )
    .await;
}

/// Client side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_client_stateless(local: UdpSocket, mut rx: DgramRx, tx: DgramTx) {
    let mut buf = [0u8; UDP_BUF];
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    match f {
                        Frame::Keepalive => true,
                        Frame::Data(d) => local.send(&d).await.is_ok(),
                    }
                }
                None => false,
            },
            r = local.recv(&mut buf) => match r {
                Ok(n) => tx.send(&buf[..n]).await.is_ok(),
                Err(_) => false,
            },
            _ = tick.tick() => last_in.elapsed() < UDP_IDLE && tx.probe().await.is_ok(),
        };
        if !alive {
            break;
        }
    }
}

/// Server side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_server_stateless(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    mut rx: DgramRx,
    tx: DgramTx,
) {
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            d = dgram_rx.recv() => match d {
                Some(d) => tx.send(&d).await.is_ok(),
                None => false,
            },
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    match f {
                        Frame::Keepalive => true,
                        Frame::Data(d) => socket.send_to(&d, src).await.is_ok(),
                    }
                }
                None => false,
            },
            _ = tick.tick() => last_in.elapsed() < UDP_IDLE && tx.probe().await.is_ok(),
        };
        if !alive {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{client_handshake, derive_psk, server_handshake};
    use tokio::sync::mpsc;

    // Test-only local side: `read` blocks on an mpsc the test feeds, `write`
    // records every forwarded frame so a test can assert what reached it.
    struct ChanRead(mpsc::Receiver<Vec<u8>>);
    struct ChanWrite(mpsc::UnboundedSender<Vec<u8>>);

    impl LocalRead for ChanRead {
        async fn read(&mut self) -> crate::Result<Vec<u8>> {
            // None == closed local side, signalled as the empty-Vec EOF sentinel.
            Ok(self.0.recv().await.unwrap_or_default())
        }
    }
    impl LocalWrite for ChanWrite {
        async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
            self.0.send(buf.to_vec()).map_err(|_| "closed".into())
        }
    }

    async fn noise_pair() -> (NoiseReader, NoiseWriter, NoiseReader, NoiseWriter) {
        let psk = derive_psk("bridge relay test");
        let (a, b) = tokio::io::duplex(1 << 16);
        let srv = tokio::spawn(async move { server_handshake(b, &psk).await.unwrap() });
        let (cr, cw) = client_handshake(a, &psk).await.unwrap();
        let (sr, sw) = srv.await.unwrap();
        (cr, cw, sr, sw)
    }

    // (a) A peer that never sends and never reads (so probes pile up unanswered)
    // makes the relay reap within roughly the idle window.
    #[tokio::test(start_paused = true)]
    async fn black_holed_peer_is_reaped() {
        let (cr, cw, _sr, _sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let start = tokio::time::Instant::now();
        // Keep the peer halves alive but inert; dropping them would close the
        // stream and reap via the error path instead of the idle watchdog.
        let relay = tokio::spawn(stream_relay(
            ChanRead(feed_rx),
            ChanWrite(out_tx),
            cr,
            cw,
            std::future::pending(),
        ));
        relay.await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= TCP_IDLE && elapsed < TCP_IDLE * 2,
            "reaped at {elapsed:?}, expected near {TCP_IDLE:?}"
        );
    }

    // (b) A peer that answers every probe keeps the relay alive well past the
    // idle window.
    #[tokio::test(start_paused = true)]
    async fn answered_probes_keep_relay_alive() {
        let (cr, cw, mut sr, mut sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let peer = tokio::spawn(async move {
            // Echo a keepalive back for every inbound frame, refreshing last_in.
            while let Ok(_m) = sr.recv().await {
                if sw.probe().await.is_err() {
                    break;
                }
            }
        });
        let relay = tokio::spawn(stream_relay(
            ChanRead(feed_rx),
            ChanWrite(out_tx),
            cr,
            cw,
            std::future::pending(),
        ));
        // Far longer than one idle window: a live peer must not be reaped.
        if tokio::time::timeout(TCP_IDLE * 5, relay).await.is_ok() {
            panic!("relay reaped a peer that answered probes");
        }
        peer.abort();
    }

    // (c) Empty keepalive frames from the peer are never forwarded to the local
    // write side; real data frames are.
    #[tokio::test(start_paused = true)]
    async fn empty_keepalives_not_forwarded() {
        let (cr, cw, mut sr, mut sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let relay = tokio::spawn(stream_relay(
            ChanRead(feed_rx),
            ChanWrite(out_tx),
            cr,
            cw,
            std::future::pending(),
        ));
        // Drain inbound on the peer so the relay's nw.send/probe never blocks.
        let drain = tokio::spawn(async move { while sr.recv().await.is_ok() {} });
        sw.probe().await.unwrap(); // empty keepalive: must be dropped
        sw.send(b"real-frame").await.unwrap();
        sw.probe().await.unwrap(); // another keepalive
        let got = out_rx.recv().await.unwrap();
        assert_eq!(got, b"real-frame");
        // Nothing else should arrive: only the single data frame was forwarded.
        assert!(out_rx.try_recv().is_err());
        relay.abort();
        drain.abort();
    }
}
