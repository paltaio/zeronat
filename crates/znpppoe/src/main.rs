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

/// Default PPPoE MTU. Each forwarded frame crosses the tunnel as one unreliable
/// `CLASS_DGRAM` UDP packet (no retransmit, and IP fragments rarely survive the
/// path), wrapped with 52 bytes of framing (class+tag+nonce+AEAD tag and the
/// Ethernet/PPPoE/PPP headers). So `pppoe_mtu + 52` must fit the tunnel's
/// single-packet budget, `kcp::KCP_MTU`; the ceiling is `KCP_MTU - 52`. 1280 leaves
/// margin for extra underlay encapsulation and is the IPv6 minimum MTU. Paths with
/// a larger usable MTU can raise it with `--pppoe-mtu`.
const DEFAULT_PPPOE_MTU: u16 = 1280;
const _: () = assert!(DEFAULT_PPPOE_MTU as usize + 52 <= zeronat::kcp::KCP_MTU);

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
}

fn usage() -> ! {
    eprintln!(
        "znpppoe (--host IP:PORT | --dht) [--connections N]\n\
         [--socks-listen ADDR] [--http-listen ADDR] [--pppoe-mtu N]\n\
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
        handles.push(netstack::spawn(s, mtu, flag.clone()));
        live.push(flag);
    }

    let selector = Arc::new(proxy::Selector::new(cfg.proxy_user, cfg.proxy_pass, live));
    let handles = Arc::new(handles);
    tokio::try_join!(
        socks5::serve(cfg.socks_listen, selector.clone(), handles.clone()),
        httpproxy::serve(cfg.http_listen, selector, handles),
    )?;
    Ok(())
}
