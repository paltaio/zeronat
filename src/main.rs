use std::net::{Ipv4Addr, SocketAddrV4};

use zeronat::proto::{Proto, Source};
use zeronat::tap::TapConfig;
use zeronat::{admin, client, server, Result};

const DEFAULT_TAP_MTU: usize = 1400;

static USAGE: &str = "\
Usage: zeronat <SUBCOMMAND> [OPTIONS]

Subcommands:
  server   Run on the public host (VPS)
  client   Run on the host behind CG-NAT
  admin    Inspect and control topology (interactive on a terminal)

server options:
  --bind <ADDR>       Address to bind on (default: 0.0.0.0)
  --control <PORT>    Control port (default: 2222)
  --secret <SECRET>   Shared secret (or env ZERONAT_SECRET)
  --id <ID>           Server identity label (default: 0)
  --config <PATH>     Load listeners/routes/identity from a config file
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
  --id <PREFIX>       Client id prefix (default: short hostname)
  --tcp <SPEC>        Forward TCP: PORT | PORT:LOCALPORT | PORT:HOST:PORT (repeatable)
  --udp <SPEC>        Forward UDP: PORT | PORT:LOCALPORT | PORT:HOST:PORT (repeatable)
  --transport <MODE>  auto|udp|tcp (default: auto)
  --tap <NAME>        L2 bridge mode (Linux only): create/attach this TAP device
  --tap-mtu <N>       TAP MTU (default: 1400)
  --bridge <NAME>     Enslave the TAP to this existing bridge

admin options:
  (no command)        Open the interactive console on a terminal; prints a
                      one-shot snapshot when piped or redirected
  show                Print the server's current topology and exit
  --server <ADDR>     Server control address host:port
  --secret <SECRET>   Shared secret (or env ZERONAT_SECRET)

Options:
  -h, --help          Print this help and exit
";

enum Cmd {
    Server {
        bind: Option<Ipv4Addr>,
        control: Option<u16>,
        secret: String,
        server_id: Option<String>,
        tcp: Vec<u16>,
        udp: Vec<u16>,
        tap: Option<TapConfig>,
        dht: bool,
        announce_ip: Option<Ipv4Addr>,
        announce_port: Option<u16>,
        config: Option<std::path::PathBuf>,
    },
    Client {
        server: String,
        secret: String,
        id_prefix: Option<String>,
        tcp: Vec<String>,
        udp: Vec<String>,
        transport: String,
        tap: Option<TapConfig>,
    },
    Admin {
        server: String,
        secret: String,
        interactive: bool,
    },
}

/// Whether `admin` with no command should open the interactive console: only
/// when built with the console and stdout is a terminal.
#[cfg(all(feature = "tui", unix))]
fn interactive_default() -> bool {
    zeronat::tui::stdout_is_tty()
}
#[cfg(not(all(feature = "tui", unix)))]
fn interactive_default() -> bool {
    false
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
        Some("admin") => "admin",
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
        let mut bind: Option<Ipv4Addr> = None;
        let mut control: Option<u16> = None;
        let mut secret: Option<String> = None;
        let mut server_id: Option<String> = None;
        let mut tcp: Vec<u16> = Vec::new();
        let mut udp: Vec<u16> = Vec::new();
        let mut tap_name: Option<String> = None;
        let mut tap_mtu: usize = DEFAULT_TAP_MTU;
        let mut bridge: Option<String> = None;
        let mut dht = false;
        let mut announce_ip: Option<Ipv4Addr> = None;
        let mut announce_port: Option<u16> = None;
        let mut config: Option<std::path::PathBuf> = None;

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "--bind" => {
                    let v = iter.next().ok_or("--bind requires a value")?;
                    bind = Some(v.parse().map_err(|_| -> zeronat::Error {
                        format!("--bind must be an IPv4 address, got '{v}'").into()
                    })?);
                }
                "--config" => {
                    config = Some(iter.next().ok_or("--config requires a value")?.into());
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
                    control = Some(v.parse().map_err(|_| -> zeronat::Error {
                        format!("--control must be a u16, got '{v}'").into()
                    })?);
                }
                "--secret" => {
                    secret = Some(iter.next().ok_or("--secret requires a value")?);
                }
                "--id" => {
                    server_id = Some(iter.next().ok_or("--id requires a value")?);
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
            server_id,
            tcp,
            udp,
            tap,
            dht,
            announce_ip,
            announce_port,
            config,
        })
    } else if subcmd == "client" {
        // client
        let mut server: Option<String> = None;
        let mut secret: Option<String> = None;
        let mut id_prefix: Option<String> = None;
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
                "--id" => {
                    id_prefix = Some(iter.next().ok_or("--id requires a value")?);
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
            id_prefix,
            tcp,
            udp,
            transport,
            tap,
        })
    } else {
        // admin
        let mut command: Option<String> = None;
        let mut server: Option<String> = None;
        let mut secret: Option<String> = None;

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
                other if other.starts_with('-') => {
                    eprintln!("error: unknown flag '{other}'");
                    std::process::exit(1);
                }
                other => {
                    if command.is_some() {
                        return Err(format!("unexpected argument '{other}'").into());
                    }
                    command = Some(other.to_string());
                }
            }
        }

        match command.as_deref() {
            None | Some("show") => {}
            Some(other) => return Err(format!("unknown admin command '{other}'").into()),
        }

        let server = server.ok_or("--server is required")?;
        let secret = secret
            .or_else(|| std::env::var("ZERONAT_SECRET").ok())
            .ok_or("--secret or ZERONAT_SECRET is required")?;

        let interactive = command.is_none() && interactive_default();
        Ok(Cmd::Admin {
            server,
            secret,
            interactive,
        })
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_main().await {
        // Print via Display, not Debug. The size-optimized release build
        // (-Zfmt-debug=none) compiles Debug formatting to nothing, so a
        // `main() -> Result` would surface every fatal error as a blank line.
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run_main() -> Result<()> {
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
            server_id,
            tcp,
            udp,
            tap,
            dht,
            announce_ip,
            announce_port,
            config,
        } => {
            // A malformed config must fail loud at startup, not boot half-configured.
            let file = match &config {
                Some(path) => zeronat::config::load(path)?,
                None => zeronat::config::ServerConfig::default(),
            };

            let server_id = server_id
                .or_else(|| file.id.clone())
                .unwrap_or_else(|| "0".to_string());

            // The file's `control` (if any) names the default control endpoint;
            // CLI --bind/--control override the address and port respectively.
            let (file_ip, file_port) = match &file.control {
                Some(ctrl) => {
                    let addr: SocketAddrV4 = ctrl.parse().map_err(|_| -> zeronat::Error {
                        format!("[server].control must be IPv4:port, got '{ctrl}'").into()
                    })?;
                    (Some(*addr.ip()), Some(addr.port()))
                }
                None => (None, None),
            };
            let bind_ip = bind.or(file_ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
            let control_port = control.or(file_port).unwrap_or(2222);

            // Listeners: start from the file's, then fold in CLI forwards. A CLI
            // port that matches a file listener locks that file listener (kept as
            // File so it still persists); a CLI-only port is a locked Cli listener.
            let mut listeners: Vec<server::ListenerSpec> = file
                .listeners
                .iter()
                .map(|l| server::ListenerSpec {
                    bind_ip: l.bind_ip,
                    proto: l.proto,
                    port: l.port,
                    source: Source::File,
                    cli_locked: false,
                })
                .collect();
            let mut add_cli_listener = |proto: Proto, port: u16| {
                let key = (bind_ip, proto, port);
                if let Some(spec) = listeners
                    .iter_mut()
                    .find(|s| (s.bind_ip, s.proto, s.port) == key)
                {
                    spec.cli_locked = true;
                } else {
                    listeners.push(server::ListenerSpec {
                        bind_ip,
                        proto,
                        port,
                        source: Source::Cli,
                        cli_locked: true,
                    });
                }
            };
            for port in &tcp {
                add_cli_listener(Proto::Tcp, *port);
            }
            for port in &udp {
                add_cli_listener(Proto::Udp, *port);
            }

            let routes: Vec<server::RouteSpec> = file
                .routes
                .iter()
                .map(|r| server::RouteSpec {
                    bind_ip: r.bind_ip,
                    proto: r.proto,
                    port: r.port,
                    client_id: r.client.clone(),
                    source: Source::File,
                })
                .collect();

            // Validate against the merged set: a config-only server with listeners
            // and no CLI flags is valid, and --tap still cannot coexist with forwards.
            if tap.is_some() && !listeners.is_empty() {
                return Err("--tap cannot be combined with --tcp/--udp forwards".into());
            }
            if tap.is_none() && listeners.is_empty() {
                return Err(
                    "nothing to do: pass --tap, a --config with listeners, or at least one --tcp/--udp"
                        .into(),
                );
            }

            let dht = dht.then_some(server::DhtAnnounce {
                ip: announce_ip,
                port: announce_port,
            });
            server::run(server::ServerSettings {
                bind: bind_ip,
                control_port,
                secret,
                server_id,
                tap,
                dht,
                listeners,
                routes,
                config_path: config,
                file_id: file.id,
                file_control: file.control,
            })
            .await
        }
        Cmd::Client {
            server,
            secret,
            id_prefix,
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
            client::run(server, secret, tcp, udp, transport, tap, id_prefix).await
        }
        Cmd::Admin {
            server,
            secret,
            interactive,
        } => {
            #[cfg(all(feature = "tui", unix))]
            if interactive {
                return zeronat::tui::run(server, secret).await;
            }
            let _ = interactive;
            admin::show(server, secret).await
        }
    }
}
