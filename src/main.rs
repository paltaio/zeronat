use std::net::Ipv4Addr;

use zeronat::tap::TapConfig;
use zeronat::{client, server, Result};

const DEFAULT_TAP_MTU: usize = 1400;

static USAGE: &str = "\
Usage: zeronat <SUBCOMMAND> [OPTIONS]

Subcommands:
  server   Run on the public host (VPS)
  client   Run on the host behind CG-NAT

server options:
  --bind <ADDR>       Address to bind on (default: 0.0.0.0)
  --control <PORT>    Control port (default: 2222)
  --secret <SECRET>   Shared secret (or env ZERONAT_SECRET)
  --tcp <PORT>        Public TCP port to expose (repeatable)
  --udp <PORT>        Public UDP port to expose (repeatable)
  --tap <NAME>        L2 bridge mode (Linux only): create/attach this TAP device
  --tap-mtu <N>       TAP MTU (default: 1400)
  --bridge <NAME>     Enslave the TAP to this existing bridge
  --server dht        Publish this server's address to the DHT for discovery
  --announce-ip <IP>  Public IPv4 to announce (default: auto-detected via DHT)
  --announce-port <P> Public port to announce (default: control port)

client options:
  --server <ADDR>     Server control address host:port, or 'dht' to discover via DHT
  --secret <SECRET>   Shared secret (or env ZERONAT_SECRET)
  --tcp <SPEC>        Forward TCP: PORT | PORT:LOCALPORT | PORT:HOST:PORT (repeatable)
  --udp <SPEC>        Forward UDP: PORT | PORT:LOCALPORT | PORT:HOST:PORT (repeatable)
  --transport <MODE>  auto|udp|tcp (default: auto)
  --tap <NAME>        L2 bridge mode (Linux only): create/attach this TAP device
  --tap-mtu <N>       TAP MTU (default: 1400)
  --bridge <NAME>     Enslave the TAP to this existing bridge

Options:
  -h, --help          Print this help and exit
";

enum Cmd {
    Server {
        bind: String,
        control: u16,
        secret: String,
        tcp: Vec<u16>,
        udp: Vec<u16>,
        tap: Option<TapConfig>,
        dht: bool,
        announce_ip: Option<Ipv4Addr>,
        announce_port: Option<u16>,
    },
    Client {
        server: String,
        secret: String,
        tcp: Vec<String>,
        udp: Vec<String>,
        transport: String,
        tap: Option<TapConfig>,
    },
}

fn build_tap(name: Option<String>, mtu: usize, bridge: Option<String>) -> Option<TapConfig> {
    name.map(|name| TapConfig { name, mtu, bridge })
}

/// Parse a forward spec into (public_port, "host:port" target).
fn parse_forward(spec: &str) -> Result<(u16, String)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [p] => {
            let port: u16 = p.parse()?;
            Ok((port, format!("127.0.0.1:{port}")))
        }
        [p, lp] => {
            let port: u16 = p.parse()?;
            let lport: u16 = lp.parse()?;
            Ok((port, format!("127.0.0.1:{lport}")))
        }
        [p, host, lp] => {
            let port: u16 = p.parse()?;
            let lport: u16 = lp.parse()?;
            Ok((port, format!("{host}:{lport}")))
        }
        _ => Err(format!("invalid forward spec '{spec}'").into()),
    }
}

fn parse_args() -> Result<Cmd> {
    let mut args = std::env::args().skip(1);

    let subcmd = match args.next().as_deref() {
        Some("-h") | Some("--help") => {
            print!("{USAGE}");
            std::process::exit(0);
        }
        Some("server") => "server",
        Some("client") => "client",
        Some(other) => {
            eprintln!("error: unknown subcommand '{other}'\n{USAGE}");
            std::process::exit(1);
        }
        None => {
            eprintln!("error: subcommand required\n{USAGE}");
            std::process::exit(1);
        }
    };

    // Collect remaining args into a flat list, splitting --flag=value pairs.
    let mut tokens: Vec<String> = Vec::new();
    for arg in args {
        if let Some(rest) = arg.strip_prefix("--") {
            if let Some(eq) = rest.find('=') {
                tokens.push(format!("--{}", &rest[..eq]));
                tokens.push(rest[eq + 1..].to_string());
            } else {
                tokens.push(arg);
            }
        } else {
            tokens.push(arg);
        }
    }

    let mut iter = tokens.into_iter();

    if subcmd == "server" {
        let mut bind = "0.0.0.0".to_string();
        let mut control: u16 = 2222;
        let mut secret: Option<String> = None;
        let mut tcp: Vec<u16> = Vec::new();
        let mut udp: Vec<u16> = Vec::new();
        let mut tap_name: Option<String> = None;
        let mut tap_mtu: usize = DEFAULT_TAP_MTU;
        let mut bridge: Option<String> = None;
        let mut dht = false;
        let mut announce_ip: Option<Ipv4Addr> = None;
        let mut announce_port: Option<u16> = None;

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "--bind" => {
                    bind = iter.next().ok_or("--bind requires a value")?;
                }
                "--server" => {
                    let v = iter.next().ok_or("--server requires a value")?;
                    if v != "dht" {
                        return Err(format!("server --server only accepts 'dht', got '{v}'").into());
                    }
                    dht = true;
                }
                "--announce-ip" => {
                    let v = iter.next().ok_or("--announce-ip requires a value")?;
                    announce_ip = Some(v.parse().map_err(|_| -> zeronat::Error {
                        format!("--announce-ip must be an IPv4 address, got '{v}'").into()
                    })?);
                }
                "--announce-port" => {
                    let v = iter.next().ok_or("--announce-port requires a value")?;
                    announce_port = Some(v.parse().map_err(|_| -> zeronat::Error {
                        format!("--announce-port must be a u16, got '{v}'").into()
                    })?);
                }
                "--control" => {
                    let v = iter.next().ok_or("--control requires a value")?;
                    control = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--control must be a u16, got '{v}'").into()
                    })?;
                }
                "--secret" => {
                    secret = Some(iter.next().ok_or("--secret requires a value")?);
                }
                "--tcp" => {
                    let v = iter.next().ok_or("--tcp requires a value")?;
                    let port: u16 = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--tcp must be a u16, got '{v}'").into()
                    })?;
                    tcp.push(port);
                }
                "--udp" => {
                    let v = iter.next().ok_or("--udp requires a value")?;
                    let port: u16 = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--udp must be a u16, got '{v}'").into()
                    })?;
                    udp.push(port);
                }
                "--tap" => {
                    tap_name = Some(iter.next().ok_or("--tap requires a value")?);
                }
                "--tap-mtu" => {
                    let v = iter.next().ok_or("--tap-mtu requires a value")?;
                    tap_mtu = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--tap-mtu must be a positive integer, got '{v}'").into()
                    })?;
                }
                "--bridge" => {
                    bridge = Some(iter.next().ok_or("--bridge requires a value")?);
                }
                other => {
                    eprintln!("error: unknown flag '{other}'");
                    std::process::exit(1);
                }
            }
        }

        let secret = secret
            .or_else(|| std::env::var("ZERONAT_SECRET").ok())
            .ok_or("--secret or ZERONAT_SECRET is required")?;

        let tap = build_tap(tap_name, tap_mtu, bridge);
        Ok(Cmd::Server {
            bind,
            control,
            secret,
            tcp,
            udp,
            tap,
            dht,
            announce_ip,
            announce_port,
        })
    } else {
        // client
        let mut server: Option<String> = None;
        let mut secret: Option<String> = None;
        let mut tcp: Vec<String> = Vec::new();
        let mut udp: Vec<String> = Vec::new();
        let mut transport = "auto".to_string();
        let mut tap_name: Option<String> = None;
        let mut tap_mtu: usize = DEFAULT_TAP_MTU;
        let mut bridge: Option<String> = None;

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "--server" => {
                    server = Some(iter.next().ok_or("--server requires a value")?);
                }
                "--secret" => {
                    secret = Some(iter.next().ok_or("--secret requires a value")?);
                }
                "--tcp" => {
                    let v = iter.next().ok_or("--tcp requires a value")?;
                    tcp.push(v);
                }
                "--udp" => {
                    let v = iter.next().ok_or("--udp requires a value")?;
                    udp.push(v);
                }
                "--transport" => {
                    transport = iter.next().ok_or("--transport requires a value")?;
                }
                "--tap" => {
                    tap_name = Some(iter.next().ok_or("--tap requires a value")?);
                }
                "--tap-mtu" => {
                    let v = iter.next().ok_or("--tap-mtu requires a value")?;
                    tap_mtu = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--tap-mtu must be a positive integer, got '{v}'").into()
                    })?;
                }
                "--bridge" => {
                    bridge = Some(iter.next().ok_or("--bridge requires a value")?);
                }
                other => {
                    eprintln!("error: unknown flag '{other}'");
                    std::process::exit(1);
                }
            }
        }

        let server = server.ok_or("--server is required")?;
        let secret = secret
            .or_else(|| std::env::var("ZERONAT_SECRET").ok())
            .ok_or("--secret or ZERONAT_SECRET is required")?;

        let tap = build_tap(tap_name, tap_mtu, bridge);
        Ok(Cmd::Client {
            server,
            secret,
            tcp,
            udp,
            transport,
            tap,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = parse_args()?;
    tokio::select! {
        r = run(cmd) => r,
        _ = shutdown() => Ok(()),
    }
}

/// Resolve on the first SIGTERM or SIGINT so the process exits promptly when a
/// supervisor (Docker, systemd) stops it, including when it runs as PID 1 where
/// the default signal disposition does not apply.
#[cfg(unix)]
async fn shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut term, mut int) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(term), Ok(int)) => (term, int),
        _ => return std::future::pending().await,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

/// Resolve on Ctrl-C or a console break/close so a supervisor can stop the
/// process promptly on Windows.
#[cfg(windows)]
async fn shutdown() {
    use tokio::signal::windows;
    let (mut cc, mut cb, mut cl) = match (
        windows::ctrl_c(),
        windows::ctrl_break(),
        windows::ctrl_close(),
    ) {
        (Ok(cc), Ok(cb), Ok(cl)) => (cc, cb, cl),
        _ => return std::future::pending().await,
    };
    tokio::select! {
        _ = cc.recv() => {}
        _ = cb.recv() => {}
        _ = cl.recv() => {}
    }
}

async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Server {
            bind,
            control,
            secret,
            tcp,
            udp,
            tap,
            dht,
            announce_ip,
            announce_port,
        } => {
            if tap.is_some() && (!tcp.is_empty() || !udp.is_empty()) {
                return Err("--tap cannot be combined with --tcp/--udp forwards".into());
            }
            if tap.is_none() && tcp.is_empty() && udp.is_empty() {
                return Err("nothing to do: pass --tap or at least one --tcp/--udp".into());
            }
            let dht = dht.then_some(server::DhtAnnounce {
                ip: announce_ip,
                port: announce_port,
            });
            server::run(bind, control, secret, tcp, udp, tap, dht).await
        }
        Cmd::Client {
            server,
            secret,
            tcp,
            udp,
            transport,
            tap,
        } => {
            if tap.is_some() && (!tcp.is_empty() || !udp.is_empty()) {
                return Err("--tap cannot be combined with --tcp/--udp forwards".into());
            }
            if tap.is_none() && tcp.is_empty() && udp.is_empty() {
                return Err("nothing to do: pass --tap or at least one --tcp/--udp".into());
            }
            let tcp = tcp
                .iter()
                .map(|s| parse_forward(s))
                .collect::<Result<Vec<_>>>()?;
            let udp = udp
                .iter()
                .map(|s| parse_forward(s))
                .collect::<Result<Vec<_>>>()?;
            let transport = match transport.as_str() {
                "auto" => client::Transport::Auto,
                "udp" => client::Transport::Udp,
                "tcp" => client::Transport::Tcp,
                other => {
                    return Err(
                        format!("invalid --transport '{other}' (expected auto|udp|tcp)").into(),
                    )
                }
            };
            client::run(server, secret, tcp, udp, transport, tap).await
        }
    }
}
