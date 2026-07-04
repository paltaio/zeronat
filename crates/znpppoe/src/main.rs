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

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::Semaphore;

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
    secret: String,
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

fn usage() -> ! {
    eprintln!(
        "znpppoe (--host IP:PORT | --dht) [--connections N]\n\
         [--socks-listen ADDR] [--http-listen ADDR] [--pppoe-mtu N]\n\
         [--sock-rx KIB] [--sock-tx KIB] [--max-conns N]\n\
         env: ZN_SECRET, ZN_USER, ZN_PASSWORD (PPPoE login), ZN_PROXY_USER, ZN_PROXY_PASS\n\
         (proxy auth) required; ZN_SERVICE optional\n\
         SOCKS5 and HTTP CONNECT proxies share auth: password = ZN_PROXY_PASS; username\n\
         <ZN_PROXY_USER> round-robins, _pppoe<K> pins session K, _s<token> is sticky\n\
         listens default to 127.0.0.1:1080 (socks) and 127.0.0.1:8081 (http)"
    );
    std::process::exit(2);
}

fn parse() -> Result<Config> {
    let mut host = None;
    let mut dht = false;
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
    let secret = std::env::var("ZN_SECRET").context("ZN_SECRET env is required")?;
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
        secret,
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
    let client_id = format!("znpppoe-{}", std::process::id());

    let target = bridge::Target::new(cfg.host.as_deref(), cfg.dht, &cfg.secret)?;
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

    let dialer = driver::Dialer {
        target,
        secret: cfg.secret,
        client_id,
    };
    let creds = driver::Creds {
        username: cfg.username.into_bytes(),
        password: cfg.password.into_bytes(),
        service: cfg.service.into_bytes(),
        mru: cfg.pppoe_mtu,
        request_dns: true,
        clamp_mss: Some(cfg.pppoe_mtu.saturating_sub(40)),
    };

    let sessions = driver::spawn(dialer, cfg.connections, creds);
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
    )?;
    Ok(())
}
