use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Result;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::timeout;

use crate::bridge;
use crate::dgram::{DgramRx, DgramTx};
use crate::kcp::{route, session, Accepted, Session, BRIDGE_CONV, BRIDGE_ID};
use crate::noise::{server_handshake, server_handshake_stateless, Noise, StatelessNoise};
use crate::proto::{Msg, Proto};
use crate::tap::{TapConfig, TapDevice};

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

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
    tap: Option<Arc<TapDevice>>,
    bridge_cancel: Mutex<Option<Arc<Notify>>>,
}

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

pub async fn run(
    bind: String,
    control_port: u16,
    secret: String,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    tap: Option<TapConfig>,
) -> Result<()> {
    let tap = match &tap {
        Some(cfg) => Some(Arc::new(TapDevice::open(cfg)?)),
        None => None,
    };
    let srv = Arc::new(Server {
        psk: crate::noise::derive_psk(&secret),
        next_id: Mutex::new(1),
        pending: Mutex::new(HashMap::new()),
        udp_pending: Mutex::new(HashMap::new()),
        control_tx: Mutex::new(None),
        active_transport: Mutex::new(ActiveTransport::Tcp),
        tap,
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
        let (sock, peer) = l.accept().await?;
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
    let (r, w) = server_handshake(sock, &srv.psk).await?;
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
            *srv.control_tx.lock().unwrap() = Some(tx);
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
            while r.recv().await.is_ok() {}
            *srv.control_tx.lock().unwrap() = None;
            writer.abort();
            eprintln!("client disconnected");
            Ok(())
        }
        Msg::Data { id } => {
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
        let (public, _) = l.accept().await?;
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
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = [0u8; 65535];

    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();

        // Route to an existing session; recover the datagram if it is dead.
        let data = if let Some(tx) = sessions.get(&src) {
            match tx.try_send(data) {
                Ok(()) => continue,
                Err(mpsc::error::TrySendError::Full(_)) => continue,
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
        sessions.insert(src, dtx);

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
    let mut sessions: HashMap<SocketAddr, Arc<Session>> = HashMap::new();
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let sess = sessions
            .entry(src)
            .or_insert_with(|| session(socket.clone(), src, 0))
            .clone();

        match route(&sess, &buf[..n]) {
            Some(Accepted::Stream { stream, .. }) => {
                let srv = srv.clone();
                let psk = srv.psk;
                tokio::spawn(async move {
                    if let Ok((r, w)) = server_handshake(stream, &psk).await {
                        let _ = serve_stream(srv, r, w, ActiveTransport::Udp).await;
                    }
                });
            }
            Some(Accepted::Setup { conv, stream }) => {
                let srv = srv.clone();
                let sess2 = sess.clone();
                let psk = srv.psk;
                tokio::spawn(async move {
                    if let Ok((id, noise)) = server_handshake_stateless(stream, &psk).await {
                        if conv == BRIDGE_CONV {
                            accept_bridge(srv, sess2, conv, noise).await;
                        } else {
                            accept_udp_forward(srv, sess2, conv, id, noise).await;
                        }
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
    let inbound = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    crate::bridge::udp_server_stateless(public_socket, public_src, dgram_rx, rx, tx).await;
}

fn take_udp_pending(srv: &Server, id: u64) -> Option<UdpPending> {
    srv.udp_pending.lock().unwrap().remove(&id)
}

/// Run the L2 bridge over the UDP datagram channel against the server's TAP. The
/// bridge setup conv carries the fixed `BRIDGE_CONV`, also used as the datagram tag.
async fn accept_bridge(srv: Arc<Server>, sess: Arc<Session>, conv: u32, noise: StatelessNoise) {
    let Some(tap) = srv.tap.clone() else {
        return;
    };
    let cancel = srv.supersede_bridge();
    let noise = Arc::new(noise);
    let inbound = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    bridge::tap_dgram(tap, rx, tx, cancel).await;
}
