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
use zeronat::kcp::{
    route, session as kcp_session, Session, BRIDGE_CONV, BRIDGE_ID, CLASS_KCP, CLASS_SETUP,
};
use zeronat::noise::{
    client_handshake_remote, client_handshake_stateless_claim_remote, derive_psk, AuthRole,
};
use zeronat::proto::Msg;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the server lives: a fixed address, or a DHT identity resolved at dial
/// time (and re-resolved on reconnect).
pub enum Target {
    Host(SocketAddr),
    Dht(Arc<zeronat::dht::Identity>),
}

impl Target {
    pub fn new(
        host: Option<&str>,
        dht: bool,
        server_public: &str,
        credential: &str,
    ) -> Result<Target> {
        let server_public = zeronat::secret::normalize(server_public)?;
        let credential = zeronat::secret::normalize(credential)?;
        if server_public == credential {
            return Err(anyhow!(
                "ZN_SECRET and ZN_CLIENT_SECRET must contain different values"
            ));
        }
        if dht {
            Ok(Target::Dht(Arc::new(
                zeronat::dht::Identity::derive(&server_public, &credential)
                    .map_err(|e| anyhow!("invalid server identity or client credential: {e}"))?,
            )))
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
/// them.
pub struct Bridge {
    pub tx: DgramTx,
    pub rx: DgramRx,
    pub cancel: Arc<Notify>,
    pub hold: BridgeHold,
}

/// What the send and receive ends need alive under them: the control session,
/// KCP session, conv registration guard, and UDP receive pump.
pub struct BridgeHold {
    _sess: Arc<Session>,
    _guard: zeronat::kcp::ConvGuard,
    _pump: AbortOnDrop,
    _control: AbortOnDrop,
}

/// Aborts its task when dropped. Ties a task's lifetime to the scope that owns
/// this guard, so no error path can strand it (and whatever it holds open) as a
/// detached task.
pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Dial `addr`, establish the bridge setup conv, run the stateless Noise
/// handshake, and return the bridge ready to carry L2 frames. `client_id` is
/// announced so the server's fleet view names the port.
pub async fn connect(addr: SocketAddr, credential: &str, client_id: &str) -> Result<Bridge> {
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind udp socket")?,
    );
    socket.connect(addr).await.context("connect udp socket")?;
    zeronat::admission::admit(&socket, addr)
        .await
        .map_err(|e| anyhow!("udp source admission failed: {e}"))?;

    let sess = kcp_session(socket.clone(), addr, 1);

    let cancel = Arc::new(Notify::new());
    let pump = AbortOnDrop({
        let sess = sess.clone();
        let cancel = cancel.clone();
        crate::spawn(async move {
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
    });

    let credential_psk = derive_psk(credential);
    let (_control_conv, control_stream) = sess.open_conv(CLASS_KCP);
    let (mut control_r, mut control_w) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_handshake_remote(control_stream, &credential_psk, AuthRole::Client),
    )
    .await
    .context("client authorization handshake timed out")?
    .map_err(|e| anyhow::anyhow!("client authorization handshake failed: {e}"))?;
    control_w
        .send(
            &Msg::ClientHello {
                version: zeronat::identity::PROTO_VERSION,
                client_id: client_id.to_string(),
            }
            .encode(),
        )
        .await
        .map_err(|e| anyhow!("send client authorization: {e}"))?;
    let frame = tokio::time::timeout(HANDSHAKE_TIMEOUT, control_r.recv())
        .await
        .context("client authorization timed out")?
        .map_err(|e| anyhow!("read client authorization: {e}"))?;
    let Msg::ClientHelloAck {
        bridge_capability, ..
    } = Msg::decode(&frame).map_err(|e| anyhow::anyhow!(e.to_string()))?
    else {
        return Err(anyhow!("server did not authorize the bridge client"));
    };
    let control = AbortOnDrop(crate::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if control_w.send(&Msg::Ping.encode()).await.is_err() {
                return;
            }
            if !matches!(
                tokio::time::timeout(Duration::from_secs(30), control_r.recv()).await,
                Ok(Ok(_))
            ) {
                return;
            }
        }
    }));

    let stream = sess.open_conv_with(CLASS_SETUP, BRIDGE_CONV);
    let noise = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_handshake_stateless_claim_remote(
            stream,
            &credential_psk,
            BRIDGE_ID,
            &bridge_capability,
        ),
    )
    .await
    .context("bridge handshake timed out")?
    .map_err(|e| anyhow::anyhow!("bridge handshake failed: {e}"))?;

    let noise = Arc::new(noise);
    let (inbound, guard) = sess.register_dgram(BRIDGE_CONV);
    let tx = DgramTx::new(sess.send_tx(), BRIDGE_CONV, noise.clone());
    let rx = DgramRx::new(inbound, noise);

    Ok(Bridge {
        tx,
        rx,
        cancel,
        hold: BridgeHold {
            _sess: sess,
            _guard: guard,
            _pump: pump,
            _control: control,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_rejects_copied_enrollment_values() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        let error = match Target::new(Some("127.0.0.1:2222"), false, secret, secret) {
            Ok(_) => panic!("copied enrollment values must be rejected"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("ZN_SECRET and ZN_CLIENT_SECRET must contain different values"));
    }

    /// A dial whose handshake times out must not strand any task: the pump
    /// guard aborts on the error return, the conv driver exits at its idle
    /// backstop, and the socket-writer follows once every sender is gone. The
    /// socket is held only by those tasks, so no surviving task means the fd
    /// is released too.
    #[tokio::test(start_paused = true)]
    async fn handshake_timeout_leaves_no_tasks_behind() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let metrics = tokio::runtime::Handle::current().metrics();
        let baseline = metrics.num_alive_tasks();

        assert!(connect(addr, "credential", "test").await.is_err());

        for _ in 0..200 {
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
            if metrics.num_alive_tasks() <= baseline {
                break;
            }
        }
        assert_eq!(metrics.num_alive_tasks(), baseline);
    }
}
