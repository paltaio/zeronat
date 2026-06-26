//! znpppoe: spawn N userspace PPPoE sessions over one zeronat tunnel and expose
//! each as a SOCKS5 egress. No kernel interface, no host routing, no privileges.
//!
//! The SOCKS5 username selects the egress session: `<user>_pppoe<K>` routes
//! through PPPoE session K (0-based).

mod bridge;
mod driver;
mod netstack;
mod socks5;

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};

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
    pppoe_mtu: u16,
}

fn usage() -> ! {
    eprintln!(
        "znpppoe (--host IP:PORT | --dht) [--connections N] [--socks-listen ADDR] [--pppoe-mtu N]\n\
         env: ZN_SECRET, ZN_USER, ZN_PASSWORD (PPPoE login), ZN_PROXY_USER, ZN_PROXY_PASS\n\
         (SOCKS auth) required; ZN_SERVICE optional\n\
         SOCKS5 auth: password = ZN_PROXY_PASS, username = <ZN_PROXY_USER>_pppoe<K> selects session K\n\
         --socks-listen defaults to 127.0.0.1:1080"
    );
    std::process::exit(2);
}

fn parse() -> Result<Config> {
    let mut host = None;
    let mut dht = false;
    let mut connections = 1usize;
    let mut socks_listen: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let mut pppoe_mtu = 1492u16;

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
    let handles: Vec<netstack::Handle> = sessions
        .into_iter()
        .map(|s| netstack::spawn(s, mtu))
        .collect();

    socks5::serve(cfg.socks_listen, cfg.proxy_user, cfg.proxy_pass, handles)
        .await
        .context("socks5 server")
}
