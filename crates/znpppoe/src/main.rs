//! znpppoe: spawn N userspace PPPoE sessions over one zeronat tunnel and expose
//! each as a SOCKS5 egress. No kernel interface, no host routing, no privileges.
//!
//! The SOCKS5 username picks the egress: the bare proxy user round-robins over the
//! live sessions, `_pppoe<K>` pins session K, and `_s<token>` is sticky per token.

mod bridge;
mod driver;
mod httpproxy;
mod netstack;
mod proxy;
mod socks5;
mod uplink;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::Semaphore;
use zeronat::identity::ClientId;
use zeronat::seed::Seed;

/// Spawn a task on the tokio runtime.
///
/// A direct `tokio::spawn` instantiates the spawn path and the task vtable for
/// every future type it is handed; erasing the future first leaves one
/// instantiation per output type, at the cost of an allocation per task and an
/// indirect call per poll.
#[track_caller]
#[allow(clippy::disallowed_methods)]
pub(crate) fn spawn<T: Send + 'static>(
    f: impl std::future::Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    let f: std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>> = Box::pin(f);
    tokio::spawn(f)
}

/// Default PPPoE MTU. Each forwarded frame crosses the tunnel as one unreliable
/// `CLASS_DGRAM` UDP packet (no retransmit, and IP fragments rarely survive the
/// path), wrapped with 52 bytes of framing (class+tag+nonce+AEAD tag and the
/// Ethernet/PPPoE/PPP headers). So `pppoe_mtu + 52` must fit the tunnel's
/// single-packet budget, `kcp::KCP_MTU`; the ceiling is `KCP_MTU - 52`. 1280 leaves
/// margin for extra underlay encapsulation and is the IPv6 minimum MTU. Paths with
/// a larger usable MTU can raise it with `--pppoe-mtu`.
const DEFAULT_PPPOE_MTU: u16 = 1280;
const _: () = assert!(DEFAULT_PPPOE_MTU as usize + 52 <= zeronat::kcp::KCP_MTU);

/// Default per-connection smoltcp TCP buffers, in bytes. The receive buffer sets
/// the advertised window and so bounds throughput (~ window / RTT); smoltcp only
/// turns on RFC 7323 window scaling once it reaches 64 KiB. 256 KiB fills a fast
/// link at low RTT while staying cheap per connection. The send buffer bounds upload
/// throughput (~ tx / RTT) the same way; it is smaller because this proxy's traffic
/// is download-dominated, so raise `--sock-tx` for upload-heavy or high-RTT paths.
/// Both are tunable in KiB.
const DEFAULT_SOCK_RX: usize = 256 * 1024;
const DEFAULT_SOCK_TX: usize = 64 * 1024;
/// smoltcp panics on a TCP buffer larger than 1 GiB.
const MAX_SOCK_BUF: usize = 1 << 30;
/// Default ceiling on concurrent proxied connections. With fixed (non-autotuning)
/// buffers this cap is the only bound on total buffer memory:
/// ~max_conns * (rx + tx + the netstack staging budget).
const DEFAULT_MAX_CONNS: usize = 1024;

struct Config {
    host: Option<String>,
    dht: bool,
    discovery: Option<String>,
    peer: Option<String>,
    peer_secret: Option<String>,
    secret: String,
    credential: String,
    /// The id sent as-is when `ZN_CLIENT_ID` is set; a seed-derived
    /// credential is bound to it.
    client_id: Option<String>,
    username: String,
    password: String,
    service: String,
    proxy_user: String,
    proxy_pass: String,
    connections: usize,
    socks_listen: SocketAddr,
    http_listen: SocketAddr,
    pppoe_mtu: u16,
    sock_rx: usize,
    sock_tx: usize,
    max_conns: usize,
}

fn runtime_secret(value: String) -> Result<String> {
    zeronat::secret::normalize(&value).map_err(Into::into)
}

fn runtime_peer_secret(value: String, secret: &str, credential: &str) -> Result<String> {
    let value = runtime_secret(value)?;
    if value == secret || value == credential {
        bail!("ZN_PEER_SECRET must differ from ZN_SECRET and ZN_CLIENT_SECRET");
    }
    Ok(value)
}

/// The DHT discovery credential: locates the server, authenticates nothing,
/// and so must never equal a value that does.
fn runtime_discovery_secret(
    value: String,
    secret: &str,
    credential: &str,
    peer_secret: Option<&str>,
) -> Result<String> {
    let value = runtime_secret(value)?;
    if value == secret || value == credential || peer_secret == Some(value.as_str()) {
        bail!(
            "ZN_DISCOVERY_SECRET must differ from ZN_SECRET, ZN_CLIENT_SECRET, and ZN_PEER_SECRET"
        );
    }
    Ok(value)
}

fn usage() -> ! {
    eprintln!(
        "znpppoe (--host IP:PORT | --dht) [--peer PEER_IDENTITY] [--connections N]\n\
         [--socks-listen ADDR] [--http-listen ADDR] [--pppoe-mtu N]\n\
         [--sock-rx KIB] [--sock-tx KIB] [--max-conns N]\n\
         --peer attaches the sessions to the L2 segment of the peer with that\n\
         64-hex identity; the default is a bridge port on the server\n\
         env: ZN_SECRET, ZN_CLIENT_SECRET, ZN_USER, ZN_PASSWORD (PPPoE login),\n\
         ZN_PROXY_USER, ZN_PROXY_PASS\n\
         (proxy auth) required; ZN_SERVICE optional;\n\
         ZN_DISCOVERY_SECRET (the server's discovery credential) required with --dht\n\
         ZN_PEER_SECRET (this process's x25519 static key) required with --peer\n\
         ZN_SEED (64-hex) fills ZN_SECRET, ZN_CLIENT_SECRET, ZN_DISCOVERY_SECRET, and\n\
         ZN_PEER_SECRET when they are unset; the client credential is derived for\n\
         ZN_CLIENT_ID, which the server lists as a bare --client ID\n\
         ZN_CLIENT_ID is sent as this client's id whenever set\n\
         SOCKS5 and HTTP CONNECT proxies share auth: password = ZN_PROXY_PASS; username\n\
         <ZN_PROXY_USER> round-robins, _pppoe<K> pins session K, _s<token> is sticky\n\
         listens default to 127.0.0.1:1080 (socks) and 127.0.0.1:8081 (http)"
    );
    std::process::exit(2);
}

fn parse() -> Result<Config> {
    let mut host = None;
    let mut dht = false;
    let mut peer = None;
    let mut connections = 1usize;
    let mut socks_listen: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let mut http_listen: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    let mut pppoe_mtu = DEFAULT_PPPOE_MTU;
    let mut sock_rx = DEFAULT_SOCK_RX;
    let mut sock_tx = DEFAULT_SOCK_TX;
    let mut max_conns = DEFAULT_MAX_CONNS;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => host = Some(args.next().context("--host needs a value")?),
            "--dht" => dht = true,
            "--peer" => peer = Some(args.next().context("--peer needs a value")?),
            "--connections" => {
                connections = args
                    .next()
                    .context("--connections needs a value")?
                    .parse()
                    .context("--connections must be a number")?;
            }
            "--socks-listen" => {
                socks_listen = args
                    .next()
                    .context("--socks-listen needs a value")?
                    .parse()
                    .context("--socks-listen must be addr:port")?;
            }
            "--http-listen" => {
                http_listen = args
                    .next()
                    .context("--http-listen needs a value")?
                    .parse()
                    .context("--http-listen must be addr:port")?;
            }
            "--pppoe-mtu" => {
                pppoe_mtu = args
                    .next()
                    .context("--pppoe-mtu needs a value")?
                    .parse()
                    .context("--pppoe-mtu must be a number")?;
            }
            "--sock-rx" => {
                let kib: usize = args
                    .next()
                    .context("--sock-rx needs a value")?
                    .parse()
                    .context("--sock-rx must be a number (KiB)")?;
                sock_rx = kib.saturating_mul(1024);
            }
            "--sock-tx" => {
                let kib: usize = args
                    .next()
                    .context("--sock-tx needs a value")?
                    .parse()
                    .context("--sock-tx must be a number (KiB)")?;
                sock_tx = kib.saturating_mul(1024);
            }
            "--max-conns" => {
                max_conns = args
                    .next()
                    .context("--max-conns needs a value")?
                    .parse()
                    .context("--max-conns must be a number")?;
            }
            "-h" | "--help" => usage(),
            other => bail!("unknown argument: {other}"),
        }
    }

    if connections == 0 {
        bail!("--connections must be at least 1");
    }
    // A larger MTU makes each forwarded frame exceed the tunnel's single-packet
    // budget, silently black-holing large flows (see DEFAULT_PPPOE_MTU); reject it
    // up front instead.
    let mtu_ceiling = zeronat::kcp::KCP_MTU - 52;
    if pppoe_mtu as usize > mtu_ceiling {
        bail!("--pppoe-mtu must be at most {mtu_ceiling}");
    }
    if sock_rx == 0 || sock_rx > MAX_SOCK_BUF {
        bail!("--sock-rx must be 1..={} KiB", MAX_SOCK_BUF / 1024);
    }
    if sock_tx == 0 || sock_tx > MAX_SOCK_BUF {
        bail!("--sock-tx must be 1..={} KiB", MAX_SOCK_BUF / 1024);
    }
    if sock_rx < 64 * 1024 {
        eprintln!(
            "znpppoe: --sock-rx {} KiB is below 64 KiB; TCP window scaling stays off and download throughput is capped",
            sock_rx / 1024
        );
    }
    if max_conns == 0 || max_conns > Semaphore::MAX_PERMITS {
        bail!("--max-conns must be 1..={}", Semaphore::MAX_PERMITS);
    }
    if dht && host.is_some() {
        bail!("--dht and --host are mutually exclusive");
    }
    if !dht && host.is_none() {
        bail!("pass --host IP:PORT or --dht");
    }
    if let Some(h) = &host {
        h.parse::<SocketAddr>()
            .with_context(|| format!("--host must be ip:port, got {h}"))?;
    }
    if let Some(peer) = &peer {
        zeronat::secret::decode(peer).context("--peer must be a 64-hex peer identity")?;
    }
    // A value set on its own always wins; the seed fills what is left.
    let seed = std::env::var("ZN_SEED")
        .ok()
        .map(|value| Seed::parse(&value).map_err(|e| anyhow!("ZN_SEED: {e}")))
        .transpose()?;
    let client_id = std::env::var("ZN_CLIENT_ID").ok();
    if client_id.as_deref() == Some("") {
        bail!("ZN_CLIENT_ID must not be empty");
    }
    let secret = match std::env::var("ZN_SECRET") {
        Ok(value) => runtime_secret(value)?,
        Err(_) => seed
            .as_ref()
            .map(Seed::network)
            .context("ZN_SECRET or ZN_SEED env is required")?,
    };
    let credential = match (std::env::var("ZN_CLIENT_SECRET"), &seed) {
        (Ok(value), _) => runtime_secret(value)?,
        (Err(_), Some(seed)) => seed.client(client_id.as_deref().context(
            "ZN_CLIENT_ID env is required with ZN_SEED: the client credential is derived for it, and the server lists the same id under --client",
        )?),
        (Err(_), None) => secret.clone(),
    };
    let peer_secret = peer
        .as_ref()
        .map(|_| match (std::env::var("ZN_PEER_SECRET"), &seed) {
            (Ok(value), _) => runtime_peer_secret(value, &secret, &credential),
            (Err(_), Some(seed)) => Ok(seed.peer()),
            (Err(_), None) => Err(anyhow!(
                "ZN_PEER_SECRET or ZN_SEED env is required with --peer"
            )),
        })
        .transpose()?;
    let discovery = if dht {
        Some(match (std::env::var("ZN_DISCOVERY_SECRET"), &seed) {
            (Ok(value), _) => {
                runtime_discovery_secret(value, &secret, &credential, peer_secret.as_deref())?
            }
            (Err(_), Some(seed)) => seed.discovery(),
            (Err(_), None) => bail!("ZN_DISCOVERY_SECRET or ZN_SEED env is required with --dht"),
        })
    } else {
        None
    };
    let username = std::env::var("ZN_USER").context("ZN_USER env is required")?;
    let password = std::env::var("ZN_PASSWORD").context("ZN_PASSWORD env is required")?;
    let service = std::env::var("ZN_SERVICE").unwrap_or_default();
    let proxy_user = std::env::var("ZN_PROXY_USER").context("ZN_PROXY_USER env is required")?;
    let proxy_pass = std::env::var("ZN_PROXY_PASS").context("ZN_PROXY_PASS env is required")?;
    if proxy_user.is_empty() || proxy_pass.is_empty() {
        bail!("ZN_PROXY_USER and ZN_PROXY_PASS must be non-empty");
    }

    Ok(Config {
        host,
        dht,
        discovery,
        peer,
        peer_secret,
        secret,
        credential,
        client_id,
        username,
        password,
        service,
        proxy_user,
        proxy_pass,
        connections,
        socks_listen,
        http_listen,
        pppoe_mtu,
        sock_rx,
        sock_tx,
        max_conns,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = parse()?;
    // Both paths announce the one name a fleet view lists the process under.
    let id = match cfg.client_id {
        Some(id) => ClientId::Exact(id),
        None => ClientId::Prefix(Some(format!("znpppoe-{}", std::process::id()))),
    };
    let client_id = id.resolve();

    eprintln!(
        "znpppoe: server {} ({} session{})",
        if cfg.dht {
            "via dht".to_string()
        } else {
            cfg.host.clone().unwrap_or_default()
        },
        cfg.connections,
        if cfg.connections == 1 { "" } else { "s" }
    );

    let uplink = match &cfg.peer {
        Some(peer) => {
            eprintln!("znpppoe: attaching to {peer}'s L2 segment");
            // The peer is paired through the server, whose discovery reads a
            // dht target as the address `dht`.
            let server = cfg.host.as_deref().unwrap_or("dht");
            uplink::peer(
                server,
                &cfg.secret,
                &cfg.credential,
                cfg.discovery.as_deref(),
                cfg.peer_secret.as_deref().expect("validated peer secret"),
                id,
                uplink::PeerId(peer),
            )
        }
        None => uplink::Uplink::Server(uplink::Dialer::new(
            bridge::Target::new(cfg.host.as_deref(), cfg.dht, cfg.discovery.as_deref())?,
            cfg.credential.clone(),
            client_id,
        )),
    };
    let creds = driver::Creds {
        username: cfg.username.into_bytes(),
        password: cfg.password.into_bytes(),
        service: cfg.service.into_bytes(),
        mru: cfg.pppoe_mtu,
        request_dns: true,
        clamp_mss: Some(cfg.pppoe_mtu.saturating_sub(40)),
    };

    let (sessions, driver) = driver::spawn(uplink, cfg.connections, creds);
    let mtu = cfg.pppoe_mtu as usize;
    let mut handles = Vec::with_capacity(cfg.connections);
    let mut live = Vec::with_capacity(cfg.connections);
    for s in sessions {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        handles.push(netstack::spawn(
            s,
            mtu,
            cfg.sock_rx,
            cfg.sock_tx,
            flag.clone(),
        ));
        live.push(flag);
    }

    let selector = Arc::new(proxy::Selector::new(cfg.proxy_user, cfg.proxy_pass, live));
    let handles = Arc::new(handles);
    // One cap shared by both front ends bounds total concurrent connections, and so
    // the total fixed buffer memory they hold.
    let conns = Arc::new(Semaphore::new(cfg.max_conns));
    tokio::try_join!(
        socks5::serve(
            cfg.socks_listen,
            selector.clone(),
            handles.clone(),
            conns.clone()
        ),
        httpproxy::serve(cfg.http_listen, selector, handles, conns),
        driver_exit(driver),
    )?;
    Ok(())
}

/// The driver stops only once no further channel can come up, which leaves both
/// front ends accepting connections onto sessions that will never be back. Fail
/// the process instead, so a supervisor restarts it.
async fn driver_exit(driver: tokio::task::JoinHandle<()>) -> Result<()> {
    let _ = driver.await;
    bail!("the pppoe driver stopped; no session can come up")
}

#[cfg(test)]
mod tests {
    use super::{runtime_discovery_secret, runtime_peer_secret, runtime_secret};

    #[test]
    fn zn_secret_accepts_only_32_byte_hex() {
        let upper = "A".repeat(64);
        assert_eq!(runtime_secret(upper).unwrap(), "a".repeat(64));
        for invalid in ["short".to_string(), "a".repeat(63), "g".repeat(64)] {
            assert!(runtime_secret(invalid).is_err());
        }
    }

    #[test]
    fn peer_secret_must_differ_from_relay_known_values() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let credential = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        for copied in [secret.to_ascii_uppercase(), credential.to_string()] {
            let error = runtime_peer_secret(copied, secret, credential).unwrap_err();
            assert!(error.to_string().contains("ZN_PEER_SECRET must differ"));
        }
        assert!(runtime_peer_secret("3".repeat(64), secret, credential).is_ok());
    }

    #[test]
    fn discovery_secret_must_differ_from_every_authenticating_value() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let credential = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        let peer = "3".repeat(64);
        for copied in [
            secret.to_ascii_uppercase(),
            credential.to_string(),
            peer.clone(),
        ] {
            let error =
                runtime_discovery_secret(copied, secret, credential, Some(&peer)).unwrap_err();
            assert!(error
                .to_string()
                .contains("ZN_DISCOVERY_SECRET must differ"));
        }
        assert!(runtime_discovery_secret("5".repeat(64), secret, credential, Some(&peer)).is_ok());
        assert!(runtime_discovery_secret("5".repeat(64), secret, credential, None).is_ok());
    }
}
