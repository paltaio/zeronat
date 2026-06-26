//! One zeronat L2 bridge channel to the server, carried over UDP/KCP. Every
//! PPPoE session in this process shares this single channel; the server learns
//! all of their MACs on the one port and bridges them to the real PPPoE segment.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use zeronat::dgram::{DgramRx, DgramTx};
use zeronat::kcp::{route, session as kcp_session, Session, BRIDGE_CONV, BRIDGE_ID, CLASS_SETUP};
use zeronat::noise::{client_handshake_stateless, derive_psk};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the server lives: a fixed address, or a DHT identity resolved at dial
/// time (and re-resolved on reconnect). The DHT identity is derived from the same
/// secret the server announces under.
pub enum Target {
    Host(SocketAddr),
    Dht(Arc<zeronat::dht::Identity>),
}

impl Target {
    pub fn new(host: Option<&str>, dht: bool, secret: &str) -> Result<Target> {
        if dht {
            Ok(Target::Dht(Arc::new(zeronat::dht::Identity::derive(
                secret,
            ))))
        } else {
            let h = host.context("--host IP:PORT or --dht is required")?;
            Ok(Target::Host(h.parse().with_context(|| {
                format!("--host must be ip:port, got {h}")
            })?))
        }
    }

    /// Resolve to a concrete address, using the DHT cache when present.
    pub async fn resolve(&self) -> Result<SocketAddr> {
        match self {
            Target::Host(a) => Ok(*a),
            Target::Dht(id) => {
                if let Some(a) = zeronat::dht::read_cache(id) {
                    return Ok(a);
                }
                eprintln!("znpppoe: resolving server via dht...");
                let a = zeronat::dht::resolve(id)
                    .await
                    .map_err(|e| anyhow!("dht resolve: {e}"))?;
                eprintln!("znpppoe: dht resolved server to {a}");
                zeronat::dht::write_cache(id, a);
                Ok(a)
            }
        }
    }

    /// Drop a stale cached address so the next `resolve` re-queries the DHT.
    pub fn invalidate(&self) {
        if let Target::Dht(id) = self {
            zeronat::dht::clear_cache(id);
        }
    }
}

/// The frame send/receive ends of the bridge plus the handles that must outlive
/// them: the KCP session, the conv registration guard, and the UDP receive pump.
pub struct Bridge {
    pub tx: DgramTx,
    pub rx: DgramRx,
    pub cancel: Arc<Notify>,
    _sess: Arc<Session>,
    _guard: zeronat::kcp::ConvGuard,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Dial `addr`, establish the bridge setup conv, run the stateless Noise
/// handshake, and return the bridge ready to carry L2 frames. `client_id` is
/// announced so the server's fleet view names the port.
pub async fn connect(addr: SocketAddr, secret: &str, client_id: &str) -> Result<Bridge> {
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind udp socket")?,
    );
    socket.connect(addr).await.context("connect udp socket")?;

    let sess = kcp_session(socket.clone(), addr, 1);

    let cancel = Arc::new(Notify::new());
    let pump = {
        let sess = sess.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv(&mut buf).await {
                    Ok(n) => {
                        route(&sess, &buf[..n]);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        cancel.notify_one();
                        return;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        })
    };

    let psk = derive_psk(secret);
    let stream = sess.open_conv_with(CLASS_SETUP, BRIDGE_CONV);
    let noise = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_handshake_stateless(stream, &psk, BRIDGE_ID),
    )
    .await
    .context("bridge handshake timed out")?
    .map_err(|e| anyhow::anyhow!("bridge handshake failed: {e}"))?;

    let noise = Arc::new(noise);
    let (inbound, guard) = sess.register_dgram(BRIDGE_CONV);
    let tx = DgramTx::new(sess.send_tx(), BRIDGE_CONV, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    tx.send_name(client_id).await.ok();

    Ok(Bridge {
        tx,
        rx,
        cancel,
        _sess: sess,
        _guard: guard,
        pump,
    })
}
