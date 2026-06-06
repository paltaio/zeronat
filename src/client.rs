use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::Result;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify};
use tokio::time::timeout as tokio_timeout;
use tokio::time::{interval, sleep};

use crate::bridge;
use crate::dgram::{DgramRx, DgramTx};
use crate::kcp::{
    route, session as kcp_session, Session, BRIDGE_CONV, BRIDGE_ID, CLASS_KCP, CLASS_SETUP,
    SETUP_CONV_BIT,
};
use crate::noise::{client_handshake, client_handshake_stateless};
use crate::proto::{Msg, Proto};
use crate::tap::{TapConfig, TapDevice};

const PING_INTERVAL: Duration = Duration::from_secs(25);
const RETRY_DELAY: Duration = Duration::from_secs(3);
const UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Clone, Copy, PartialEq)]
pub enum Transport {
    Auto,
    Udp,
    Tcp,
}

struct Client {
    server: String,
    psk: [u8; 32],
    tcp: HashMap<u16, String>,
    udp: HashMap<u16, String>,
    transport: Transport,
}

/// How the control loop opens data connections back to the server.
enum Link {
    Tcp,               // data conns dial new TcpStreams
    Udp(Arc<Session>), // data conns open KCP convs on the shared UDP session
}

pub async fn run(
    server: String,
    secret: String,
    tcp: Vec<(u16, String)>,
    udp: Vec<(u16, String)>,
    transport: Transport,
    tap: Option<TapConfig>,
) -> Result<()> {
    let client = Arc::new(Client {
        server,
        psk: crate::noise::derive_psk(&secret),
        tcp: tcp.into_iter().collect(),
        udp: udp.into_iter().collect(),
        transport,
    });

    if let Some(cfg) = tap {
        let tap = Arc::new(TapDevice::open(&cfg)?);
        loop {
            if let Err(e) = bridge_session(client.clone(), tap.clone()).await {
                eprintln!("bridge connection lost: {e}");
            }
            sleep(RETRY_DELAY).await;
        }
    }

    loop {
        if let Err(e) = session(client.clone()).await {
            eprintln!("control connection lost: {e}");
        }
        sleep(RETRY_DELAY).await;
    }
}

/// Bring up the L2 bridge: UDP first for Auto/Udp, TCP otherwise or as fallback.
async fn bridge_session(client: Arc<Client>, tap: Arc<TapDevice>) -> Result<()> {
    if client.transport == Transport::Tcp {
        return bridge_tcp(client, tap).await;
    }
    match bridge_udp(client.clone(), tap.clone()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if client.transport == Transport::Udp {
                return Err(e);
            }
            eprintln!("udp transport unavailable ({e}); falling back to tcp");
            bridge_tcp(client, tap).await
        }
    }
}

/// Bind a local UDP socket, connect it to the server, start the KCP session, and
/// spawn the inbound RX pump. Shared by the control and bridge UDP paths.
async fn udp_connect(client: &Client) -> Result<Arc<Session>> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let server: SocketAddr = client
        .server
        .parse()
        .map_err(|_| -> crate::Error { "server must be host:port for UDP".into() })?;
    socket.connect(server).await?;
    let sess = kcp_session(socket.clone(), server, 1);
    {
        let sess = sess.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok(n) = socket.recv(&mut buf).await {
                route(&sess, &buf[..n]);
            }
        });
    }
    Ok(sess)
}

/// L2 bridge over the UDP transport: frames ride the unreliable datagram channel.
async fn bridge_udp(client: Arc<Client>, tap: Arc<TapDevice>) -> Result<()> {
    let sess = udp_connect(&client).await?;
    let stream = sess.open_conv_with(CLASS_SETUP, BRIDGE_CONV);
    let noise = tokio_timeout(
        UDP_HANDSHAKE_TIMEOUT,
        client_handshake_stateless(stream, &client.psk, BRIDGE_ID),
    )
    .await
    .map_err(|_| -> crate::Error { "udp handshake timed out".into() })??;
    eprintln!("bridge connected to {} over udp", client.server);

    let noise = Arc::new(noise);
    let inbound = sess.register_dgram(BRIDGE_CONV);
    let tx = DgramTx::new(sess.send_tx(), BRIDGE_CONV, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    // The client runs one bridge at a time, so nothing ever cancels it.
    bridge::tap_dgram(tap, rx, tx, Arc::new(Notify::new())).await;
    Ok(())
}

/// L2 bridge over the TCP fallback: frames ride a reliable Noise stream.
async fn bridge_tcp(client: Arc<Client>, tap: Arc<TapDevice>) -> Result<()> {
    let sock = TcpStream::connect(&client.server)
        .await
        .map_err(|e| -> crate::Error { format!("connecting to {}: {e}", client.server).into() })?;
    sock.set_nodelay(true).ok();
    let (nr, mut nw) = client_handshake(sock, &client.psk).await?;
    nw.send(&Msg::Data { id: BRIDGE_ID }.encode()).await?;
    eprintln!("bridge connected to {} over tcp", client.server);
    bridge::tap_stream(tap, nr, nw, Arc::new(Notify::new())).await;
    Ok(())
}

/// Establish the control channel over UDP/KCP. Returns the session and the
/// handshaked control reader/writer, or an error to trigger TCP fallback.
async fn udp_session(client: Arc<Client>) -> Result<(Arc<Session>, crate::noise::Noise)> {
    let sess = udp_connect(&client).await?;
    let (_conv, stream) = sess.open_conv(CLASS_KCP);
    let noise = tokio_timeout(UDP_HANDSHAKE_TIMEOUT, client_handshake(stream, &client.psk))
        .await
        .map_err(|_| -> crate::Error { "udp handshake timed out".into() })??;
    Ok((sess, noise))
}

/// Establish the control connection and dispatch `Open` requests until it drops.
async fn session(client: Arc<Client>) -> Result<()> {
    let mode = client.transport;

    // Try UDP first for Auto/Udp; fall back to TCP for Auto/Tcp.
    let (link, r, w) = if mode != Transport::Tcp {
        match udp_session(client.clone()).await {
            Ok((sess, (r, w))) => {
                eprintln!("connected to {} over udp", client.server);
                (Link::Udp(sess), r, w)
            }
            Err(e) => {
                if mode == Transport::Udp {
                    return Err(e);
                }
                eprintln!("udp transport unavailable ({e}); falling back to tcp");
                let (r, w) = tcp_control(client.clone()).await?;
                (Link::Tcp, r, w)
            }
        }
    } else {
        let (r, w) = tcp_control(client.clone()).await?;
        (Link::Tcp, r, w)
    };

    control_loop(client, link, r, w).await
}

/// Dial the TCP control connection and run the Noise handshake.
async fn tcp_control(client: Arc<Client>) -> Result<crate::noise::Noise> {
    let sock = TcpStream::connect(&client.server)
        .await
        .map_err(|e| -> crate::Error { format!("connecting to {}: {e}", client.server).into() })?;
    sock.set_nodelay(true).ok();
    let noise = client_handshake(sock, &client.psk).await?;
    eprintln!("connected to {}", client.server);
    Ok(noise)
}

/// Run the control loop over an established Noise control channel, dispatching
/// `Open` requests via `link` until the channel drops.
async fn control_loop(
    client: Arc<Client>,
    link: Link,
    mut r: crate::noise::NoiseReader,
    w: crate::noise::NoiseWriter,
) -> Result<()> {
    let link = Arc::new(link);

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    tx.try_send(Msg::Hello.encode()).ok();

    let mut w = w;
    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if w.send(&bytes).await.is_err() {
                break;
            }
        }
    });

    let ping_tx = tx.clone();
    let pinger = tokio::spawn(async move {
        let mut tick = interval(PING_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            if ping_tx.try_send(Msg::Ping.encode()).is_err() {
                break;
            }
        }
    });

    let result = loop {
        let msg = match r.recv().await {
            Ok(m) => m,
            Err(e) => break Err(e),
        };
        match Msg::decode(&msg) {
            Ok(Msg::Open { proto, port, id }) => {
                let client = client.clone();
                let link = link.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_open(client, link, proto, port, id).await {
                        eprintln!("stream {id} ({proto:?} :{port}) failed: {e}");
                    }
                });
            }
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };

    writer.abort();
    pinger.abort();
    result
}

/// Open a data connection back to the server and bridge it to the local target.
async fn handle_open(
    client: Arc<Client>,
    link: Arc<Link>,
    proto: Proto,
    port: u16,
    id: u64,
) -> Result<()> {
    let target = match proto {
        Proto::Tcp => client.tcp.get(&port),
        Proto::Udp => client.udp.get(&port),
    }
    .ok_or_else(|| -> crate::Error {
        format!("no local target configured for {proto:?} :{port}").into()
    })?
    .clone();

    match (link.as_ref(), proto) {
        // --- TCP transport (unchanged behavior) ---
        (Link::Tcp, Proto::Tcp) => {
            let sock = TcpStream::connect(&client.server).await?;
            sock.set_nodelay(true).ok();
            let (nr, mut nw) = client_handshake(sock, &client.psk).await?;
            nw.send(&Msg::Data { id }.encode()).await?;
            let local = TcpStream::connect(&target)
                .await
                .map_err(|e| -> crate::Error {
                    format!("connecting to local {target}: {e}").into()
                })?;
            bridge::tcp(local, nr, nw).await;
        }
        (Link::Tcp, Proto::Udp) => {
            let sock = TcpStream::connect(&client.server).await?;
            sock.set_nodelay(true).ok();
            let (nr, mut nw) = client_handshake(sock, &client.psk).await?;
            nw.send(&Msg::Data { id }.encode()).await?;
            let local = UdpSocket::bind("0.0.0.0:0").await?;
            local.connect(&target).await.map_err(|e| -> crate::Error {
                format!("connecting to local {target}: {e}").into()
            })?;
            bridge::udp_client(local, nr, nw).await;
        }
        // --- UDP transport ---
        (Link::Udp(sess), Proto::Tcp) => {
            let (_conv, stream) = sess.open_conv(CLASS_KCP);
            let (nr, mut nw) = client_handshake(stream, &client.psk).await?;
            nw.send(&Msg::Data { id }.encode()).await?;
            let local = TcpStream::connect(&target)
                .await
                .map_err(|e| -> crate::Error {
                    format!("connecting to local {target}: {e}").into()
                })?;
            bridge::tcp(local, nr, nw).await;
        }
        (Link::Udp(sess), Proto::Udp) => {
            let conv = (id as u32) | SETUP_CONV_BIT;
            let stream = sess.open_conv_with(CLASS_SETUP, conv);
            let noise = Arc::new(client_handshake_stateless(stream, &client.psk, id).await?);
            let local = UdpSocket::bind("0.0.0.0:0").await?;
            local.connect(&target).await.map_err(|e| -> crate::Error {
                format!("connecting to local {target}: {e}").into()
            })?;
            let inbound = sess.register_dgram(conv);
            let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
            let rx = DgramRx::new(inbound, noise);
            bridge::udp_client_stateless(local, rx, tx).await;
        }
    }
    Ok(())
}
