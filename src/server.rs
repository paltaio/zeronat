use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Result;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
#[cfg(target_os = "linux")]
use tokio::sync::Notify;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::{timeout, Instant};

use crate::bridge;
use crate::dgram::{DgramRx, DgramTx};
use crate::kcp::{route, session, Accepted, Session};
#[cfg(target_os = "linux")]
use crate::kcp::{BRIDGE_CONV, BRIDGE_ID};
use crate::noise::{server_handshake, server_handshake_stateless, Noise, StatelessNoise};
use crate::proto::{Msg, Proto};
use crate::tap::TapConfig;
#[cfg(target_os = "linux")]
use crate::tap::TapDevice;

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Liveness window for the control channel. The client pings every 25s, so no
/// inbound control frame for this long means the link is a black hole (no
/// FIN/RST on a NAT rebind, WAN re-dial, or silent firewall drop). Sized to a
/// few ping intervals to tolerate a missed ping without falsely tearing down a
/// healthy idle link.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_INFLIGHT_HANDSHAKES: usize = 256;
/// Pause after a transient accept/recv error so a persistent failure (e.g. EMFILE
/// under fd pressure) does not spin the listener loop at 100% CPU.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Idle window for a per-source UDP control session. A real client sends KCP ACKs
/// and 25s control pings, so a session silent this long is dead (NAT rebind, churn,
/// or stray probe traffic). The sweep evicts it, bounding the session map on a
/// public port. Sized above the control ping interval so a healthy link survives.
const UDP_SESSION_TTL: Duration = Duration::from_secs(90);
/// How often the control loop sweeps idle/empty sessions.
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Backstop TTL for a per-source data-listener entry. The bridge self-reaps at
/// `bridge::UDP_IDLE` (120s), closing its channel, which is the precise reclaim
/// signal; this is sized above that so the sweep never evicts a live bridge and
/// only bounds an entry whose channel somehow lingers.
const UDP_DATA_TTL: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, PartialEq)]
pub enum ActiveTransport {
    Tcp,
    Udp,
}

/// A parked public UDP source, the public socket its replies must go out on, and
/// the channel carrying its inbound datagrams, awaiting the matching UDP-forward
/// setup conv.
type UdpPending = (Arc<UdpSocket>, SocketAddr, mpsc::Receiver<Vec<u8>>);

pub(crate) struct Server {
    psk: [u8; 32],
    next_id: Mutex<u64>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Noise>>>,
    udp_pending: Mutex<HashMap<u64, UdpPending>>,
    control_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    active_transport: Mutex<ActiveTransport>,
    handshakes: Arc<Semaphore>,
    #[cfg(target_os = "linux")]
    tap: Option<Arc<TapDevice>>,
    #[cfg(target_os = "linux")]
    bridge_cancel: Mutex<Option<Arc<Notify>>>,
}

#[cfg(target_os = "linux")]
impl Server {
    /// Take ownership of the bridge: cancel any previously running bridge relay
    /// and return the cancel handle for the new one. The TAP is point-to-point,
    /// so the newest bridge wins and the old relay stops touching the device.
    fn supersede_bridge(&self) -> Arc<Notify> {
        let cancel = Arc::new(Notify::new());
        if let Some(prev) = self.bridge_cancel.lock().unwrap().replace(cancel.clone()) {
            prev.notify_one();
        }
        cancel
    }
}

impl Server {
    fn next_id(&self) -> u64 {
        let mut id = self.next_id.lock().unwrap();
        let next = *id;
        *id += 1;
        next
    }

    fn control(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.control_tx.lock().unwrap().clone()
    }

    /// Register a new public stream, notify the client, and return the channel
    /// that will receive the matching data connection. `None` if no client is
    /// currently connected.
    fn open(&self, proto: Proto, port: u16) -> Option<(u64, oneshot::Receiver<Noise>)> {
        let ctl = self.control()?;
        let id = self.next_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let msg = Msg::Open { proto, port, id }.encode();
        if ctl.try_send(msg).is_err() {
            self.pending.lock().unwrap().remove(&id);
            return None;
        }
        Some((id, rx))
    }
}

/// DHT announce settings. An unset IP is auto-detected via the DHT; an unset port
/// defaults to the control port.
pub struct DhtAnnounce {
    pub ip: Option<Ipv4Addr>,
    pub port: Option<u16>,
}

pub async fn run(
    bind: String,
    control_port: u16,
    secret: String,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    tap: Option<TapConfig>,
    dht: Option<DhtAnnounce>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    let tap = match &tap {
        Some(cfg) => Some(Arc::new(TapDevice::open(cfg)?)),
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    if tap.is_some() {
        return Err("L2 TAP bridge (--tap) is only supported on Linux".into());
    }

    if let Some(ann) = dht {
        #[cfg(feature = "dht")]
        {
            let secret = secret.clone();
            let ip = ann.ip;
            let port = ann.port.unwrap_or(control_port);
            tokio::spawn(async move {
                crate::dht::announce_loop(&secret, ip, port).await;
            });
        }
        #[cfg(not(feature = "dht"))]
        {
            let _ = ann;
            return Err("this build has no dht support".into());
        }
    }

    let srv = Arc::new(Server {
        psk: crate::noise::derive_psk(&secret),
        next_id: Mutex::new(1),
        pending: Mutex::new(HashMap::new()),
        udp_pending: Mutex::new(HashMap::new()),
        control_tx: Mutex::new(None),
        active_transport: Mutex::new(ActiveTransport::Tcp),
        handshakes: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES)),
        #[cfg(target_os = "linux")]
        tap,
        #[cfg(target_os = "linux")]
        bridge_cancel: Mutex::new(None),
    });

    for port in tcp_ports {
        let srv = srv.clone();
        let bind = bind.clone();
        tokio::spawn(async move {
            if let Err(e) = tcp_listener(srv, bind, port).await {
                eprintln!("tcp listener :{port} stopped: {e}");
            }
        });
    }
    for port in udp_ports {
        let srv = srv.clone();
        let bind = bind.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_listener(srv, bind, port).await {
                eprintln!("udp listener :{port} stopped: {e}");
            }
        });
    }

    {
        let srv = srv.clone();
        let bind = bind.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_control_listener(srv, bind, control_port).await {
                eprintln!("udp control listener stopped: {e}");
            }
        });
    }

    let l = TcpListener::bind((bind.as_str(), control_port)).await?;
    eprintln!("control listening on {bind}:{control_port}");
    loop {
        // A transient accept error (EMFILE, ECONNABORTED, ...) must not kill the
        // control loop or the process; log it, back off briefly, and keep serving.
        let (sock, peer) = match l.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("control accept error: {e}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let srv = srv.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(srv, sock).await {
                eprintln!("connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle_incoming(srv: Arc<Server>, sock: TcpStream) -> Result<()> {
    sock.set_nodelay(true).ok();
    let (r, w) = {
        let _permit = srv.handshakes.clone().acquire_owned().await?;
        match timeout(HANDSHAKE_TIMEOUT, server_handshake(sock, &srv.psk)).await {
            Ok(res) => res?,
            Err(_) => return Err("handshake timed out".into()),
        }
    };
    serve_stream(srv, r, w, ActiveTransport::Tcp).await
}

/// Dispatch a freshly handshaked stream (control or TCP-forward data),
/// transport-agnostic. The first message decides the role.
pub(crate) async fn serve_stream(
    srv: Arc<Server>,
    mut r: crate::noise::NoiseReader,
    w: crate::noise::NoiseWriter,
    transport: ActiveTransport,
) -> Result<()> {
    match Msg::decode(&r.recv().await?)? {
        Msg::Hello => {
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
            *srv.control_tx.lock().unwrap() = Some(tx.clone());
            *srv.active_transport.lock().unwrap() = transport;
            eprintln!("client connected");
            let mut w = w;
            let writer = tokio::spawn(async move {
                while let Some(bytes) = rx.recv().await {
                    if w.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
            // Drain inbound control frames. Any frame (Ping, ...) resets the
            // liveness deadline; reply to Ping with Pong so the client's own
            // deadline also keeps resetting. A timeout (no inbound frame for the
            // whole window) or a recv error breaks the loop and tears down: a
            // black-holed link delivers no FIN/RST, so only the deadline catches it.
            while let Ok(Ok(bytes)) = timeout(CONTROL_TIMEOUT, r.recv()).await {
                if let Ok(Msg::Ping) = Msg::decode(&bytes) {
                    tx.try_send(Msg::Pong.encode()).ok();
                }
            }
            // Only clear control_tx if it still points at this session's channel;
            // a newer client may have reconnected and overwritten it.
            {
                let mut ctl = srv.control_tx.lock().unwrap();
                if ctl.as_ref().is_some_and(|cur| cur.same_channel(&tx)) {
                    *ctl = None;
                }
            }
            writer.abort();
            eprintln!("client disconnected");
            Ok(())
        }
        Msg::Data { id } => {
            #[cfg(target_os = "linux")]
            if id == BRIDGE_ID {
                if let Some(tap) = srv.tap.clone() {
                    let cancel = srv.supersede_bridge();
                    bridge::tap_stream(tap, r, w, cancel).await;
                }
                return Ok(());
            }
            if let Some(tx) = srv.pending.lock().unwrap().remove(&id) {
                let _ = tx.send((r, w));
            }
            Ok(())
        }
        other => Err(format!("unexpected first message: {other:?}").into()),
    }
}

async fn tcp_listener(srv: Arc<Server>, bind: String, port: u16) -> Result<()> {
    let l = TcpListener::bind((bind.as_str(), port)).await?;
    loop {
        // Keep the forwarded port alive across transient accept errors so fd
        // pressure does not silently and permanently kill this listener.
        let (public, _) = match l.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("tcp listener :{port} accept error: {e}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let srv = srv.clone();
        tokio::spawn(async move {
            let Some((id, rx)) = srv.open(Proto::Tcp, port) else {
                return;
            };
            match timeout(OPEN_TIMEOUT, rx).await {
                Ok(Ok((nr, nw))) => bridge::tcp(public, nr, nw).await,
                _ => {
                    srv.pending.lock().unwrap().remove(&id);
                }
            }
        });
    }
}

async fn udp_listener(srv: Arc<Server>, bind: String, port: u16) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind((bind.as_str(), port)).await?);
    // Each entry holds the bridge's inbound channel and the last time a datagram
    // reached it. A closed channel (bridge ended) or a stale TTL evicts the entry,
    // so a one-shot/vanished source cannot pin a dead Sender slot forever.
    let mut sessions: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
    let mut buf = [0u8; 65535];
    let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // A transient recv error must not kill the forwarded UDP port; log, back
        // off briefly, and keep serving. The sweep runs between recvs.
        let (n, src) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("udp listener :{port} recv error: {e}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
            _ = sweep.tick() => {
                let now = Instant::now();
                sessions.retain(|_, (tx, last)| {
                    !tx.is_closed() && now.duration_since(*last) < UDP_DATA_TTL
                });
                continue;
            }
        };
        let data = buf[..n].to_vec();

        // Route to an existing session; recover the datagram if it is dead.
        let data = if let Some((tx, last)) = sessions.get_mut(&src) {
            match tx.try_send(data) {
                Ok(()) => {
                    *last = Instant::now();
                    continue;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    *last = Instant::now();
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(v)) => {
                    sessions.remove(&src);
                    v
                }
            }
        } else {
            data
        };

        let (dtx, drx) = mpsc::channel::<Vec<u8>>(64);
        dtx.try_send(data).ok();
        sessions.insert(src, (dtx, Instant::now()));

        let transport = *srv.active_transport.lock().unwrap();
        match transport {
            ActiveTransport::Tcp => {
                let Some((id, rx)) = srv.open(Proto::Udp, port) else {
                    sessions.remove(&src);
                    continue;
                };
                let socket = socket.clone();
                let srv = srv.clone();
                tokio::spawn(async move {
                    match timeout(OPEN_TIMEOUT, rx).await {
                        Ok(Ok((nr, nw))) => bridge::udp_server(socket, src, drx, nr, nw).await,
                        _ => {
                            srv.pending.lock().unwrap().remove(&id);
                        }
                    }
                });
            }
            ActiveTransport::Udp => {
                let Some(ctl) = srv.control() else {
                    sessions.remove(&src);
                    continue;
                };
                let id = srv.next_id();
                srv.udp_pending
                    .lock()
                    .unwrap()
                    .insert(id, (socket.clone(), src, drx));
                if ctl
                    .try_send(
                        Msg::Open {
                            proto: Proto::Udp,
                            port,
                            id,
                        }
                        .encode(),
                    )
                    .is_err()
                {
                    srv.udp_pending.lock().unwrap().remove(&id);
                    sessions.remove(&src);
                } else {
                    // Reclaim the parked entry if the matching setup conv never
                    // arrives (vanished/spoofed source). `remove` by id is a no-op
                    // once `take_udp_pending` claimed it, so this is idempotent.
                    let srv = srv.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(OPEN_TIMEOUT).await;
                        srv.udp_pending.lock().unwrap().remove(&id);
                    });
                }
            }
        }
    }
}

/// Bind a UDP socket on the control port, demux per source address into a session
/// registry, and dispatch accepted convs: stream convs run the streaming server
/// handshake plus `serve_stream`; setup convs run the stateless handshake plus the
/// UDP-forward bridge.
async fn udp_control_listener(srv: Arc<Server>, bind: String, port: u16) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind((bind.as_str(), port)).await?);
    eprintln!("udp control listening on {bind}:{port}");
    // Each entry holds the session and the last time a datagram reached it. The
    // map only retains a source once a datagram from it routes to a valid conv,
    // and the periodic sweep evicts idle or conv-less entries, so the map cannot
    // grow without bound from stray/unroutable traffic on a public port.
    let mut sessions: HashMap<SocketAddr, (Arc<Session>, Instant)> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // A transient recv error must not kill the control loop or the process;
        // log, back off briefly, and keep serving. The sweep runs between recvs;
        // dropping a session's `Arc` closes its send channel and ends socket_writer.
        let (n, src) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("udp control recv error: {e}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
            _ = sweep.tick() => {
                let now = Instant::now();
                sessions.retain(|_, (sess, last)| {
                    now.duration_since(*last) < UDP_SESSION_TTL && !sess.is_idle()
                });
                continue;
            }
        };

        // Route through the existing session for this source, or a fresh candidate.
        // A candidate that yields no valid conv is dropped on this iteration, so
        // stray/unroutable datagrams leave no lasting session or socket_writer task.
        let (sess, known) = match sessions.get(&src) {
            Some((sess, _)) => (sess.clone(), true),
            None => (session(socket.clone(), src, 0), false),
        };

        let accepted = route(&sess, &buf[..n]);
        if known {
            // Existing session: refresh its activity deadline.
            if let Some(entry) = sessions.get_mut(&src) {
                entry.1 = Instant::now();
            }
        } else if accepted.is_some() || !sess.is_idle() {
            // First datagram from this source routed to a valid conv: retain it.
            sessions.insert(src, (sess.clone(), Instant::now()));
        }
        // Otherwise `sess` is a candidate that routed nothing; dropping it here
        // closes its send channel and ends its socket_writer task.

        match accepted {
            Some(Accepted::Stream { stream, .. }) => {
                let srv = srv.clone();
                let psk = srv.psk;
                tokio::spawn(async move {
                    let Ok(permit) = srv.handshakes.clone().acquire_owned().await else {
                        return;
                    };
                    let handshake =
                        timeout(HANDSHAKE_TIMEOUT, server_handshake(stream, &psk)).await;
                    drop(permit);
                    if let Ok(Ok((r, w))) = handshake {
                        let _ = serve_stream(srv, r, w, ActiveTransport::Udp).await;
                    }
                });
            }
            Some(Accepted::Setup { conv, stream }) => {
                let srv = srv.clone();
                let sess2 = sess.clone();
                let psk = srv.psk;
                tokio::spawn(async move {
                    let Ok(permit) = srv.handshakes.clone().acquire_owned().await else {
                        return;
                    };
                    let handshake =
                        timeout(HANDSHAKE_TIMEOUT, server_handshake_stateless(stream, &psk)).await;
                    drop(permit);
                    if let Ok(Ok((id, noise))) = handshake {
                        #[cfg(target_os = "linux")]
                        if conv == BRIDGE_CONV {
                            accept_bridge(srv, sess2, conv, noise).await;
                        } else {
                            accept_udp_forward(srv, sess2, conv, id, noise).await;
                        }
                        #[cfg(not(target_os = "linux"))]
                        accept_udp_forward(srv, sess2, conv, id, noise).await;
                    }
                });
            }
            None => {}
        }
    }
}

/// Bridge a UDP-forward setup conv to its parked public source. The matching public
/// `Open` parked `(public socket, public src, inbound datagram channel)` under `id`;
/// the setup conv carries the same id, with `conv` (== `(id as u32) | high bit`) used
/// as the datagram tag. Replies must go out on the parked public socket so the public
/// client sees them from the port it sent to.
async fn accept_udp_forward(
    srv: Arc<Server>,
    sess: Arc<Session>,
    conv: u32,
    id: u64,
    noise: StatelessNoise,
) {
    let Some((public_socket, public_src, dgram_rx)) = take_udp_pending(&srv, id) else {
        return;
    };
    let noise = Arc::new(noise);
    // `_guard` keeps the session counted live for the whole bridge.
    let (inbound, _guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    crate::bridge::udp_server_stateless(public_socket, public_src, dgram_rx, rx, tx).await;
}

fn take_udp_pending(srv: &Server, id: u64) -> Option<UdpPending> {
    srv.udp_pending.lock().unwrap().remove(&id)
}

/// Run the L2 bridge over the UDP datagram channel against the server's TAP. The
/// bridge setup conv carries the fixed `BRIDGE_CONV`, also used as the datagram tag.
#[cfg(target_os = "linux")]
async fn accept_bridge(srv: Arc<Server>, sess: Arc<Session>, conv: u32, noise: StatelessNoise) {
    let Some(tap) = srv.tap.clone() else {
        return;
    };
    let cancel = srv.supersede_bridge();
    let noise = Arc::new(noise);
    // `_guard` keeps the session counted live for the whole bridge.
    let (inbound, _guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    bridge::tap_dgram(tap, rx, tx, cancel).await;
}
