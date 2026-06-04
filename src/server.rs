use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use crate::bridge;
use crate::noise::{server_handshake, Noise};
use crate::proto::{Msg, Proto};

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq)]
pub enum ActiveTransport { Tcp, Udp }

pub(crate) struct Server {
    psk: [u8; 32],
    next_id: Mutex<u64>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Noise>>>,
    control_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    active_transport: Mutex<ActiveTransport>,
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
) -> Result<()> {
    let srv = Arc::new(Server {
        psk: crate::noise::derive_psk(&secret),
        next_id: Mutex::new(1),
        pending: Mutex::new(HashMap::new()),
        control_tx: Mutex::new(None),
        active_transport: Mutex::new(ActiveTransport::Tcp),
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
            if let Some(tx) = srv.pending.lock().unwrap().remove(&id) {
                let _ = tx.send((r, w));
            }
            Ok(())
        }
        other => anyhow::bail!("unexpected first message: {other:?}"),
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

        let Some((id, rx)) = srv.open(Proto::Udp, port) else {
            continue;
        };
        let (dtx, drx) = mpsc::channel::<Vec<u8>>(64);
        dtx.try_send(data).ok();
        sessions.insert(src, dtx);

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
}
