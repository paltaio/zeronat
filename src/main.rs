use std::net::{Ipv4Addr, SocketAddrV4};

use zeronat::clientcfg::{CfgForward, CfgPppoe, CfgServer, ClientConfig};
use zeronat::proto::{Proto, Source};
use zeronat::tap::TapConfig;
use zeronat::{admin, client, client_admin, server, Result};

const DEFAULT_TAP_MTU: usize = 1400;
const DEFAULT_TUN_NAME: &str = "zn0";
const TUN_PREFIX_LEN: u8 = 24;

/// The tunnel `/24` for `secret`: `(network base, server .1, client .2)`.
fn tun_addrs(secret: &str) -> (Ipv4Addr, Ipv4Addr, Ipv4Addr) {
    let base = zeronat::identity::derive_tun_subnet(secret);
    let host = |h: u8| Ipv4Addr::new(base[0], base[1], base[2], h);
    (host(0), host(1), host(2))
}

static USAGE: &str = "\
Usage: zeronat <SUBCOMMAND> [OPTIONS]

Subcommands:
  server   Run on the public host (VPS)
  client   Run on the host behind CG-NAT
  admin    Inspect and control topology (interactive on a terminal)
  upgrade  Fetch the latest release and restart this host's deployment

server options:
  --bind <ADDR>       Address to bind on (default: 0.0.0.0)
  --control <PORT>    Control port (default: 2222)
  --secret <SECRET>   Shared secret (or env ZERONAT_SECRET)
  --id <ID>           Server identity label (default: 0)
  --config <PATH>     Load listeners/routes/identity from a config file
  --tcp <PORT>        Public TCP port to expose (repeatable)
  --udp <PORT>        Public UDP port to expose (repeatable)
  --tun               L3 all-ports mode (Linux only): forward every port except
                      the control port (and --except) plus ICMP to the client
  --except <PORT>     Port to keep on the host in --tun mode (repeatable)
  --tap <NAME>        L2 bridge mode (Linux only): create/attach this TAP device
  --tap-mtu <N>       TAP/TUN MTU (default: 1400; alias --tun-mtu)
  --bridge <NAME>     Enslave the TAP to this existing bridge
  --server dht        Publish this server's address to the DHT for discovery
  --announce-ip <IP>  Public IPv4 to announce (default: auto-detected via DHT)
  --announce-port <P> Public port to announce (default: control port)

client options:
  --server <ADDR>     Server control address host:port, or 'dht' to discover via DHT
  --secret <SECRET>   Shared secret (or env ZERONAT_SECRET)
  --id <PREFIX>       Client id prefix (default: short hostname)
  --config <PATH>     Load servers/forwards/identity from a config file
  --tcp <SPEC>        Forward TCP: PORT | PORT:LOCALPORT | PORT:HOST:PORT, plus
                      optional +proxy (send a PROXY protocol v2 header to the
                      target) and +idle=SECS modifiers (repeatable)
  --udp <SPEC>        Forward UDP: PORT | PORT:LOCALPORT | PORT:HOST:PORT, plus
                      an optional +idle=SECS modifier (repeatable)
  --proxy             Send a PROXY protocol v2 header on every --tcp forward
  --tun               L3 all-ports mode (Linux only): receive every forwarded
                      port on local services (bind 0.0.0.0 or the tunnel address)
  --transport <MODE>  auto|udp|tcp (default: auto)
  --tap <NAME>        L2 bridge mode (Linux only): create/attach this TAP device
  --tap-mtu <N>       TAP/TUN MTU (default: 1400; alias --tun-mtu)
  --bridge <NAME>     Enslave the TAP to this existing bridge
  --pppoe             In-process PPPoE client (Linux only): dial an ISP PPPoE
                      line over the tunnel and expose it as a TUN (zppp0)
  --pppoe-user <U>    PPPoE username (or env ZERONAT_PPPOE_USER)
  --pppoe-pass-file <P> File (mode 600) holding the PPPoE password (preferred)
  --pppoe-pass <P>    PPPoE password inline; visible in ps/argv, prefer
                      --pppoe-pass-file or ZERONAT_PPPOE_PASS
  --pppoe-service <NAME> PPPoE Service-Name to request (default: any)
  --pppoe-ac <NAME>   Preferred Access Concentrator name (accepted; AC-name
                      filtering not yet active)
  --pppoe-tun <NAME>  TUN device name (default: zppp0)
  --pppoe-mtu <N>     Requested PPP MTU/MRU (default: 1492; capped to tunnel
                      MTU minus 8)
  --pppoe-default-route  Route all traffic out zppp0 except the tunnel to the
                      server; brings on the TCP MSS clamp; reverts on exit
  --pppoe-no-mss-clamp   Opt out of the MSS clamp that rides with
                      --pppoe-default-route
  --pppoe-dns         Apply IPCP-provided DNS to /etc/resolv.conf (fragile under
                      Docker; the servers are also logged)

client admin options:
  (no command)        Open the interactive console on a terminal; prints the
                      status and exits when piped or redirected
  show                Print the running client's status and exit
  select-server <NAME> Switch the active server profile
  add-server <NAME> <ADDR> [--transport auto|udp|tcp]
                      Add a server profile; the secret is read from stdin
  remove-server <NAME> Remove a server profile (the active one is refused)
  enable-forward <PROTO:PORT>  Enable a forward, e.g. tcp:443
  disable-forward <PROTO:PORT> Disable a forward without removing it
  connect [NAME]      Leave offline mode and bring up the boot session body
  disconnect          Tear the session down; nothing dials until connect
  spawn-pppoe <NAME>  Bring up the named PPPoE session
  stop-pppoe <NAME>   Stop the named PPPoE session and return to the base mode
  --socket <PATH>     Admin socket path (default: /run/zeronat/client.sock,
                      else $XDG_RUNTIME_DIR/zeronat/client.sock)

admin options:
  (no command)        Open the interactive console on a terminal; prints the
                      status and exits when piped or redirected
  show                Print the server's current topology and exit
  --server <ADDR>     Server control address host:port
  --secret <SECRET>   Shared secret (or env ZERONAT_SECRET, or the ZERONAT_SECRET
                      in /etc/zeronat/.env)

upgrade options:
  --check             Report whether a newer release exists, without applying it

Options:
  -h, --help          Print this help and exit
  -V, --version       Print the version and exit
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
        tun: bool,
        mtu: usize,
        except: Vec<u16>,
        dht: bool,
        announce_ip: Option<Ipv4Addr>,
        announce_port: Option<u16>,
        config: Option<std::path::PathBuf>,
    },
    Client {
        server: Option<String>,
        secret: Option<String>,
        id_prefix: Option<String>,
        tcp: Vec<String>,
        udp: Vec<String>,
        proxy: bool,
        transport: Option<String>,
        tap_name: Option<String>,
        bridge: Option<String>,
        tun: bool,
        mtu: Option<usize>,
        pppoe: bool,
        pppoe_user: Option<String>,
        pppoe_pass: Option<String>,
        pppoe_pass_file: Option<std::path::PathBuf>,
        pppoe_service: Option<String>,
        pppoe_ac: Option<String>,
        pppoe_tun: String,
        pppoe_mtu: usize,
        pppoe_default_route: bool,
        pppoe_no_mss_clamp: bool,
        pppoe_dns: bool,
        config: Option<std::path::PathBuf>,
    },
    ClientAdmin {
        command: Option<ClientAdminCmd>,
        socket: Option<std::path::PathBuf>,
        interactive: bool,
    },
    Admin {
        server: String,
        secret: String,
        interactive: bool,
    },
    Upgrade {
        check: bool,
    },
}

enum ClientAdminCmd {
    Show,
    SelectServer(String),
    AddServer {
        name: String,
        addr: String,
        transport: client::Transport,
    },
    RemoveServer(String),
    EnableForward(String),
    DisableForward(String),
    Connect(Option<String>),
    Disconnect,
    SpawnPppoe(String),
    StopPppoe(String),
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

/// `"on"`/`"off"` for a boolean flag in the startup banner.
fn onoff(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

/// `--transport` value to transport mode; `None` means auto.
fn parse_transport(v: Option<&str>) -> Result<client::Transport> {
    match v.unwrap_or("auto") {
        "auto" => Ok(client::Transport::Auto),
        "udp" => Ok(client::Transport::Udp),
        "tcp" => Ok(client::Transport::Tcp),
        other => Err(format!("invalid --transport '{other}' (expected auto|udp|tcp)").into()),
    }
}

/// Short label for the transport mode in the startup banner.
fn transport_label(t: client::Transport) -> &'static str {
    match t {
        client::Transport::Auto => "auto",
        client::Transport::Udp => "udp",
        client::Transport::Tcp => "tcp",
    }
}

/// Parse a client forward spec: `PORT | PORT:LOCALPORT | PORT:HOST:PORT`, then
/// optional `+`-appended modifiers (`+proxy`, `+idle=SECS`). Splitting on the
/// first `+` cannot collide with the base grammar: `+` appears in neither ports
/// nor hostnames. `+proxy` is a TCP framing, so it is a parse error on a udp
/// spec; duplicate and unknown modifiers are parse errors too.
fn parse_forward(spec: &str, proto: Proto) -> Result<client::Forward> {
    let (base, mods) = match spec.split_once('+') {
        Some((base, mods)) => (base, Some(mods)),
        None => (spec, None),
    };

    let parts: Vec<&str> = base.split(':').collect();
    let (port, target) = match parts.as_slice() {
        [p] => {
            let port: u16 = p.parse()?;
            (port, format!("127.0.0.1:{port}"))
        }
        [p, lp] => {
            let port: u16 = p.parse()?;
            let lport: u16 = lp.parse()?;
            (port, format!("127.0.0.1:{lport}"))
        }
        [p, host, lp] => {
            let port: u16 = p.parse()?;
            let lport: u16 = lp.parse()?;
            (port, format!("{host}:{lport}"))
        }
        _ => return Err(format!("invalid forward spec '{spec}'").into()),
    };

    let mut proxy = false;
    let mut idle: Option<std::time::Duration> = None;
    if let Some(mods) = mods {
        for m in mods.split('+') {
            if m == "proxy" {
                if proxy {
                    return Err(format!("duplicate modifier '+proxy' in '{spec}'").into());
                }
                if proto == Proto::Udp {
                    return Err("+proxy is not supported on udp forwards".into());
                }
                proxy = true;
            } else if let Some(v) = m.strip_prefix("idle=") {
                if idle.is_some() {
                    return Err(format!("duplicate modifier '+idle' in '{spec}'").into());
                }
                let secs: u32 = v.parse().map_err(|_| -> zeronat::Error {
                    format!("+idle wants whole seconds, got '{v}'").into()
                })?;
                if secs == 0 {
                    return Err("+idle must be at least 1 second".into());
                }
                idle = Some(std::time::Duration::from_secs(secs.into()));
            } else {
                return Err(format!("unknown modifier '+{m}' in '{spec}'").into());
            }
        }
    }

    Ok(client::Forward {
        port,
        target,
        proxy,
        idle,
        enabled: true,
    })
}

/// Whether the config file declares any list-shaped setting. Declaring even one
/// makes the file authoritative for the whole client shape, so the matching CLI
/// flags are ignored.
fn declares_shape(cfg: &ClientConfig) -> bool {
    !cfg.servers.is_empty()
        || !cfg.forwards.is_empty()
        || !cfg.pppoe.is_empty()
        || cfg.tap.is_some()
        || cfg.tun.is_some()
}

/// The `[[servers]]` entry to dial at boot: `[client].active` when set (its
/// target is guaranteed by `validate`), else the first entry.
fn active_server(cfg: &ClientConfig) -> Result<&CfgServer> {
    match &cfg.active {
        Some(name) => cfg.servers.iter().find(|s| &s.name == name),
        None => cfg.servers.first(),
    }
    .ok_or_else(|| "config declares no [[servers]] entry to dial".into())
}

/// Split `[[forwards]]` entries into the per-proto lists `client::run` takes.
fn split_forwards(fwds: &[CfgForward]) -> (Vec<client::Forward>, Vec<client::Forward>) {
    let (mut tcp, mut udp) = (Vec::new(), Vec::new());
    for f in fwds {
        let fwd = client::Forward {
            port: f.port,
            target: f.target.clone(),
            proxy: f.proxy,
            idle: f
                .idle
                .map(|secs| std::time::Duration::from_secs(secs.into())),
            enabled: f.enabled,
        };
        match f.proto {
            Proto::Tcp => tcp.push(fwd),
            Proto::Udp => udp.push(fwd),
        }
    }
    (tcp, udp)
}

/// Resolve a `[[pppoe]]` entry into a run config. `password_file` wins over the
/// inline `password`; the MTU cap uses the default tunnel MTU, since the file
/// grammar has no tunnel-MTU key.
fn pppoe_from_entry(p: &CfgPppoe) -> Result<client::PppoeRunConfig> {
    use zeronat::pppoe::cli;
    if p.password.is_none() && p.password_file.is_none() {
        return Err(format!("pppoe '{}' needs `password` or `password_file`", p.name).into());
    }
    let pass_file = match &p.password_file {
        Some(path) => Some(std::fs::read(path).map_err(|e| -> zeronat::Error {
            format!("reading [[pppoe]] password_file {path}: {e}").into()
        })?),
        None => None,
    };
    let password = cli::resolve_password(pass_file, None, p.password.clone())?;
    let resolved = cli::resolve_effective_mtu(p.mtu, DEFAULT_TAP_MTU as u16)?;
    if resolved.capped {
        eprintln!(
            "pppoe: requested MTU {} exceeds what the tunnel carries; using {}",
            p.mtu, resolved.effective
        );
    }
    Ok(client::PppoeRunConfig {
        username: p.username.clone().into_bytes(),
        password,
        service_name: p.service.clone().into_bytes(),
        ac_name: None,
        tun_name: "zppp0".to_string(),
        effective_mtu: resolved.effective,
        default_route: p.default_route,
        // The MSS clamp rides with default_route unless opted out; value is the
        // effective IP MTU minus the IPv4+TCP headers.
        clamp_mss: if p.default_route && p.clamp_mss {
            Some(resolved.effective.saturating_sub(40).max(536))
        } else {
            None
        },
        request_dns: p.request_dns,
    })
}

fn parse_args() -> Result<Cmd> {
    let mut args = std::env::args().skip(1);

    let subcmd = match args.next().as_deref() {
        Some("-h") | Some("--help") => {
            print!("{USAGE}");
            std::process::exit(0);
        }
        Some("-V") | Some("--version") => {
            println!("zeronat {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Some("server") => "server",
        Some("client") => "client",
        Some("admin") => "admin",
        Some("upgrade") => "upgrade",
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

    // `client admin` drives a running client; everything else under `client`
    // runs one.
    let client_admin = subcmd == "client" && tokens.first().is_some_and(|t| t == "admin");

    let mut iter = tokens.into_iter();

    if client_admin {
        iter.next();
        let mut command: Option<String> = None;
        let mut pos: Vec<String> = Vec::new();
        let mut socket: Option<std::path::PathBuf> = None;
        let mut transport: Option<String> = None;

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "--socket" => {
                    socket = Some(iter.next().ok_or("--socket requires a value")?.into());
                }
                "--transport" => {
                    transport = Some(iter.next().ok_or("--transport requires a value")?);
                }
                other if other.starts_with('-') => {
                    eprintln!("error: unknown flag '{other}'");
                    std::process::exit(1);
                }
                other => {
                    if command.is_none() {
                        command = Some(other.to_string());
                    } else {
                        pos.push(other.to_string());
                    }
                }
            }
        }
        if transport.is_some() && command.as_deref() != Some("add-server") {
            return Err("--transport only applies to add-server".into());
        }

        let mut pos = pos.into_iter();
        let named = |pos: &mut std::vec::IntoIter<String>, cmd: &str| -> Result<String> {
            pos.next()
                .ok_or_else(|| format!("{cmd} requires a name").into())
        };
        let command = match command.as_deref() {
            None => None,
            Some("show") => Some(ClientAdminCmd::Show),
            Some("select-server") => Some(ClientAdminCmd::SelectServer(named(
                &mut pos,
                "select-server",
            )?)),
            Some("add-server") => {
                let name = named(&mut pos, "add-server")?;
                let addr = pos
                    .next()
                    .ok_or("add-server requires a name and an address")?;
                Some(ClientAdminCmd::AddServer {
                    name,
                    addr,
                    transport: parse_transport(transport.as_deref())?,
                })
            }
            Some("remove-server") => Some(ClientAdminCmd::RemoveServer(named(
                &mut pos,
                "remove-server",
            )?)),
            Some("enable-forward") => Some(ClientAdminCmd::EnableForward(named(
                &mut pos,
                "enable-forward",
            )?)),
            Some("disable-forward") => Some(ClientAdminCmd::DisableForward(named(
                &mut pos,
                "disable-forward",
            )?)),
            Some("connect") => Some(ClientAdminCmd::Connect(pos.next())),
            Some("disconnect") => Some(ClientAdminCmd::Disconnect),
            Some("spawn-pppoe") => {
                Some(ClientAdminCmd::SpawnPppoe(named(&mut pos, "spawn-pppoe")?))
            }
            Some("stop-pppoe") => Some(ClientAdminCmd::StopPppoe(named(&mut pos, "stop-pppoe")?)),
            Some(other) => return Err(format!("unknown client admin command '{other}'").into()),
        };
        if let Some(extra) = pos.next() {
            return Err(format!("unexpected argument '{extra}'").into());
        }

        let interactive = command.is_none() && interactive_default();
        return Ok(Cmd::ClientAdmin {
            command,
            socket,
            interactive,
        });
    }

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
        let mut tun = false;
        let mut except: Vec<u16> = Vec::new();
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
                "--tap-mtu" | "--tun-mtu" => {
                    let v = iter.next().ok_or("--tap-mtu requires a value")?;
                    tap_mtu = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--tap-mtu must be a positive integer, got '{v}'").into()
                    })?;
                }
                "--bridge" => {
                    bridge = Some(iter.next().ok_or("--bridge requires a value")?);
                }
                "--tun" => {
                    tun = true;
                }
                "--except" => {
                    let v = iter.next().ok_or("--except requires a value")?;
                    let port: u16 = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--except must be a u16, got '{v}'").into()
                    })?;
                    except.push(port);
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

        if tun && bridge.is_some() {
            return Err("--bridge applies to --tap only, not --tun".into());
        }

        let tap = build_tap(tap_name, tap_mtu, bridge);
        Ok(Cmd::Server {
            bind,
            control,
            secret,
            server_id,
            tcp,
            udp,
            tap,
            tun,
            mtu: tap_mtu,
            except,
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
        let mut proxy = false;
        let mut transport: Option<String> = None;
        let mut tap_name: Option<String> = None;
        let mut tap_mtu: Option<usize> = None;
        let mut bridge: Option<String> = None;
        let mut tun = false;
        let mut config: Option<std::path::PathBuf> = None;
        let mut pppoe = false;
        let mut pppoe_user: Option<String> = None;
        let mut pppoe_pass: Option<String> = None;
        let mut pppoe_pass_file: Option<std::path::PathBuf> = None;
        let mut pppoe_service: Option<String> = None;
        let mut pppoe_ac: Option<String> = None;
        let mut pppoe_tun = "zppp0".to_string();
        let mut pppoe_mtu: usize = 1492;
        let mut pppoe_default_route = false;
        let mut pppoe_no_mss_clamp = false;
        let mut pppoe_dns = false;

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "--tun" => {
                    tun = true;
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
                "--proxy" => {
                    proxy = true;
                }
                "--transport" => {
                    transport = Some(iter.next().ok_or("--transport requires a value")?);
                }
                "--config" => {
                    config = Some(iter.next().ok_or("--config requires a value")?.into());
                }
                "--tap" => {
                    tap_name = Some(iter.next().ok_or("--tap requires a value")?);
                }
                "--tap-mtu" | "--tun-mtu" => {
                    let v = iter.next().ok_or("--tap-mtu requires a value")?;
                    tap_mtu = Some(v.parse().map_err(|_| -> zeronat::Error {
                        format!("--tap-mtu must be a positive integer, got '{v}'").into()
                    })?);
                }
                "--bridge" => {
                    bridge = Some(iter.next().ok_or("--bridge requires a value")?);
                }
                "--pppoe" => {
                    pppoe = true;
                }
                "--pppoe-user" => {
                    pppoe_user = Some(iter.next().ok_or("--pppoe-user requires a value")?);
                }
                "--pppoe-pass" => {
                    pppoe_pass = Some(iter.next().ok_or("--pppoe-pass requires a value")?);
                }
                "--pppoe-pass-file" => {
                    pppoe_pass_file = Some(
                        iter.next()
                            .ok_or("--pppoe-pass-file requires a value")?
                            .into(),
                    );
                }
                "--pppoe-service" => {
                    pppoe_service = Some(iter.next().ok_or("--pppoe-service requires a value")?);
                }
                "--pppoe-ac" => {
                    pppoe_ac = Some(iter.next().ok_or("--pppoe-ac requires a value")?);
                }
                "--pppoe-tun" => {
                    pppoe_tun = iter.next().ok_or("--pppoe-tun requires a value")?;
                }
                "--pppoe-mtu" => {
                    let v = iter.next().ok_or("--pppoe-mtu requires a value")?;
                    pppoe_mtu = v.parse().map_err(|_| -> zeronat::Error {
                        format!("--pppoe-mtu must be a positive integer, got '{v}'").into()
                    })?;
                }
                "--pppoe-default-route" => pppoe_default_route = true,
                "--pppoe-no-mss-clamp" => pppoe_no_mss_clamp = true,
                "--pppoe-dns" => pppoe_dns = true,
                other => {
                    eprintln!("error: unknown flag '{other}'");
                    std::process::exit(1);
                }
            }
        }

        Ok(Cmd::Client {
            server,
            secret,
            id_prefix,
            tcp,
            udp,
            proxy,
            transport,
            tun,
            mtu: tap_mtu,
            tap_name,
            bridge,
            pppoe,
            pppoe_user,
            pppoe_pass,
            pppoe_pass_file,
            pppoe_service,
            pppoe_ac,
            pppoe_tun,
            pppoe_mtu,
            pppoe_default_route,
            pppoe_no_mss_clamp,
            pppoe_dns,
            config,
        })
    } else if subcmd == "upgrade" {
        let mut check = false;
        for flag in iter {
            match flag.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "--check" => check = true,
                other => {
                    eprintln!("error: unknown flag '{other}'");
                    std::process::exit(1);
                }
            }
        }
        Ok(Cmd::Upgrade { check })
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
            .or_else(zeronat::admin::secret_from_env_file)
            .ok_or("no secret: pass --secret, set ZERONAT_SECRET, or run where /etc/zeronat/.env has one")?;

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
            tun,
            mtu,
            except,
            dht,
            announce_ip,
            announce_port,
            config,
        } => {
            // A valid config is authoritative. The recovery for a broken one
            // depends on why it broke: a missing file is a normal first boot
            // (default, then self-heal); a malformed file is set aside so its
            // routes stay recoverable before we rewrite a fresh one, rather than
            // crash-looping under a restart policy; an unreadable file (permission
            // or transient IO) is fatal, because falling back here would let the
            // next mutation overwrite intact state we never managed to read.
            let mut self_healed = false;
            let file = match &config {
                Some(path) => match zeronat::config::load(path) {
                    Ok(cfg) => cfg,
                    Err(zeronat::config::LoadError::Malformed(e)) => {
                        match zeronat::config::quarantine(path) {
                            Some(b) => zeronat::elog!(
                                "config: {e}; moved aside to {}; starting from command-line settings and rewriting on the next change",
                                b.display()
                            ),
                            None => zeronat::elog!(
                                "config: {e}; could not set the file aside; starting from command-line settings and overwriting on the next change"
                            ),
                        }
                        self_healed = true;
                        zeronat::config::ServerConfig::default()
                    }
                    Err(zeronat::config::LoadError::Unreadable(e)) => return Err(e),
                },
                None => zeronat::config::ServerConfig::default(),
            };

            // A valid file's identity/control win over the CLI; a present CLI flag
            // that the file overrides is logged so the override is visible.
            let (cli_id, cli_bind, cli_control) = (server_id, bind, control);
            if let (Some(f), Some(c)) = (&file.id, &cli_id) {
                if f != c {
                    zeronat::elog!("config [server].id '{f}' overrides --server-id '{c}'");
                }
            }
            let server_id = file
                .id
                .clone()
                .or_else(|| cli_id.clone())
                .unwrap_or_else(|| "0".to_string());

            let (file_ip, file_port) = match &file.control {
                Some(ctrl) => {
                    let addr: SocketAddrV4 = ctrl.parse().map_err(|_| -> zeronat::Error {
                        format!("[server].control must be IPv4:port, got '{ctrl}'").into()
                    })?;
                    (Some(*addr.ip()), Some(addr.port()))
                }
                None => (None, None),
            };
            if let (Some(f), Some(c)) = (file_ip, cli_bind) {
                if f != c {
                    zeronat::elog!("config [server].control address {f} overrides --bind {c}");
                }
            }
            if let (Some(f), Some(c)) = (file_port, cli_control) {
                if f != c {
                    zeronat::elog!("config [server].control port {f} overrides --control {c}");
                }
            }
            let bind_ip = file_ip.or(cli_bind).unwrap_or(Ipv4Addr::UNSPECIFIED);
            let control_port = file_port.or(cli_control).unwrap_or(2222);

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

            // Validate against the merged set. --tun owns every port and cannot
            // coexist with --tap or any per-port forward; --tap cannot coexist
            // with forwards; a config-only server with listeners is valid.
            if tun {
                if tap.is_some() {
                    return Err("--tun cannot be combined with --tap".into());
                }
                if !listeners.is_empty() || !routes.is_empty() {
                    return Err(
                        "--tun cannot be combined with --tcp/--udp or config listeners/routes"
                            .into(),
                    );
                }
                // The iptables fallback matches kept ports with the multiport
                // module, which caps at 15 ports (control port + exclusions).
                let mut kept: Vec<u16> = except
                    .iter()
                    .copied()
                    .filter(|&p| p != control_port)
                    .collect();
                kept.sort_unstable();
                kept.dedup();
                if kept.len() + 1 > 15 {
                    return Err(format!(
                        "--except has {} distinct ports; at most 14 are allowed besides the control port",
                        kept.len()
                    )
                    .into());
                }
            }
            if !except.is_empty() && !tun {
                return Err("--except requires --tun".into());
            }
            if tap.is_some() && !listeners.is_empty() {
                return Err("--tap cannot be combined with --tcp/--udp forwards".into());
            }
            if !tun && tap.is_none() && listeners.is_empty() {
                return Err(
                    "nothing to do: pass --tun, --tap, a --config with listeners, or at least one --tcp/--udp"
                        .into(),
                );
            }

            let tun = if tun {
                let (subnet, server_ip, client_ip) = tun_addrs(&secret);
                Some(server::ServerTun {
                    device: zeronat::tap::TunConfig {
                        name: DEFAULT_TUN_NAME.to_string(),
                        mtu,
                        addr: server_ip,
                        prefix_len: TUN_PREFIX_LEN,
                    },
                    subnet,
                    client_ip,
                    except,
                })
            } else {
                None
            };

            let dht = dht.then_some(server::DhtAnnounce {
                ip: announce_ip,
                port: announce_port,
            });
            zeronat::elog!(
                "zeronat {} server: bind={bind_ip} control={control_port} tap={} tun={} dht={}",
                env!("CARGO_PKG_VERSION"),
                onoff(tap.is_some()),
                onoff(tun.is_some()),
                onoff(dht.is_some())
            );
            // On a self-heal the file lost its [server] table; record the resolved
            // identity so the rewritten file matches the running server and an
            // operator can later drop the CLI flags without a silent change.
            let (file_id, file_control) = if self_healed {
                (
                    Some(server_id.clone()),
                    Some(format!("{bind_ip}:{control_port}")),
                )
            } else {
                (file.id, file.control)
            };
            server::run(server::ServerSettings {
                bind: bind_ip,
                control_port,
                secret,
                server_id,
                tap,
                tun,
                dht,
                listeners,
                routes,
                config_path: config,
                file_id,
                file_control,
            })
            .await
        }
        Cmd::Client {
            server,
            secret,
            id_prefix,
            tcp,
            udp,
            proxy,
            transport,
            tap_name,
            bridge,
            tun,
            mtu,
            pppoe,
            pppoe_user,
            pppoe_pass,
            pppoe_pass_file,
            pppoe_service,
            pppoe_ac,
            pppoe_tun,
            pppoe_mtu,
            pppoe_default_route,
            pppoe_no_mss_clamp,
            pppoe_dns,
            config,
        } => {
            use zeronat::pppoe::cli;
            // Same recovery split as the server: a missing file is a normal
            // first boot; a malformed file is set aside so its contents stay
            // recoverable and the client starts from command-line settings; an
            // unreadable file (permission or transient IO) is fatal, so a
            // restart retries rather than running with settings we never
            // managed to read.
            let file = match &config {
                Some(path) => match zeronat::clientcfg::load(path) {
                    Ok(cfg) => cfg,
                    Err(zeronat::config::LoadError::Malformed(e)) => {
                        match zeronat::config::quarantine(path) {
                            Some(b) => zeronat::elog!(
                                "config: {e}; moved aside to {}; starting from command-line settings",
                                b.display()
                            ),
                            None => zeronat::elog!(
                                "config: {e}; could not set the file aside; starting from command-line settings"
                            ),
                        }
                        ClientConfig::default()
                    }
                    Err(zeronat::config::LoadError::Unreadable(e)) => return Err(e),
                },
                None => ClientConfig::default(),
            };
            // A parseable but contradictory file is an operator error to fix
            // in place, never quarantined.
            file.validate()?;

            // Scalars merge field by field; a valid file wins over the CLI and
            // a present CLI flag it overrides is logged.
            if let (Some(f), Some(c)) = (&file.id, &id_prefix) {
                if f != c {
                    zeronat::elog!("config [client].id '{f}' overrides --id '{c}'");
                }
            }
            let id_prefix = file.id.clone().or(id_prefix);

            // Admin socket path: the file value when set (that path must
            // work), else the default under /run/zeronat, falling back to
            // $XDG_RUNTIME_DIR/zeronat and then to no admin socket at all;
            // the tunnel never depends on it.
            let control = match &file.control {
                Some(path) => Some(zeronat::clientctl::ControlPath::Explicit(
                    std::path::PathBuf::from(path),
                )),
                None => zeronat::clientctl::default_control(),
            };

            if declares_shape(&file) {
                if let Some(v) = &server {
                    zeronat::elog!("config overrides --server '{v}'");
                }
                if secret.is_some() {
                    zeronat::elog!("config overrides --secret");
                }
                if let Some(v) = &transport {
                    zeronat::elog!("config overrides --transport '{v}'");
                }
                for spec in &tcp {
                    zeronat::elog!("config overrides --tcp '{spec}'");
                }
                for spec in &udp {
                    zeronat::elog!("config overrides --udp '{spec}'");
                }
                if proxy {
                    zeronat::elog!("config overrides --proxy");
                }
                if let Some(v) = &tap_name {
                    zeronat::elog!("config overrides --tap '{v}'");
                }
                if tun {
                    zeronat::elog!("config overrides --tun");
                }
                if let Some(v) = mtu {
                    zeronat::elog!("config overrides --tap-mtu {v}");
                }
                if let Some(v) = &bridge {
                    zeronat::elog!("config overrides --bridge '{v}'");
                }
                if pppoe {
                    zeronat::elog!("config overrides --pppoe");
                }

                let srv = active_server(&file)?;
                let (tcp, udp) = split_forwards(&file.forwards);
                let tap = file.tap.as_ref().map(|t| TapConfig {
                    name: t.dev.clone(),
                    mtu: DEFAULT_TAP_MTU,
                    bridge: None,
                });
                // An unpinned [tun] address is derived from the active
                // server's secret at each bringup, so a server switch moves
                // the device onto the new server's subnet.
                let tun = file.tun.as_ref().map(|t| client::ClientTun {
                    name: t
                        .dev
                        .clone()
                        .unwrap_or_else(|| DEFAULT_TUN_NAME.to_string()),
                    mtu: DEFAULT_TAP_MTU,
                    address: t.address,
                });
                // Every [[pppoe]] entry is resolved at boot so the admin can
                // spawn any of them; run_switchable derives the boot body
                // (forwards, else the autostart entry, else the device, else
                // idle with only the admin socket up).
                let pppoe = file
                    .pppoe
                    .iter()
                    .map(|p| {
                        Ok(client::PppoeSession {
                            name: p.name.clone(),
                            config: pppoe_from_entry(p)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let autostart = file
                    .pppoe
                    .iter()
                    .find(|p| p.autostart)
                    .map(|p| p.name.clone());
                let servers: Vec<client::ServerTarget> = file
                    .servers
                    .iter()
                    .map(|s| client::ServerTarget {
                        name: s.name.clone(),
                        addr: s.addr.clone(),
                        secret: s.secret.0.clone(),
                        transport: s.transport,
                    })
                    .collect();
                let target = client::ServerTarget {
                    name: srv.name.clone(),
                    addr: srv.addr.clone(),
                    secret: srv.secret.0.clone(),
                    transport: srv.transport,
                };

                let v = env!("CARGO_PKG_VERSION");
                zeronat::elog!(
                    "zeronat {v} client: server={} transport={} tcp-forwards={} udp-forwards={} pppoe-sessions={} tap={} tun={}",
                    target.addr,
                    transport_label(target.transport),
                    tcp.len(),
                    udp.len(),
                    pppoe.len(),
                    onoff(tap.is_some()),
                    onoff(tun.is_some())
                );
                let settings = client::ClientSettings {
                    servers,
                    tcp,
                    udp,
                    tap,
                    tun,
                    pppoe,
                    autostart,
                    id_prefix,
                    control,
                    // The shape came from the file, so admin mutations
                    // persist back to it.
                    config: config.map(|path| (path, file)),
                };
                client::run_switchable(client::ActiveTarget::new(target), settings).await
            } else {
                let server = server.ok_or("--server is required")?;
                let secret = secret
                    .or_else(|| std::env::var("ZERONAT_SECRET").ok())
                    .ok_or("--secret or ZERONAT_SECRET is required")?;
                if tun && bridge.is_some() {
                    return Err("--bridge applies to --tap only, not --tun".into());
                }
                let mtu = mtu.unwrap_or(DEFAULT_TAP_MTU);
                let tap = build_tap(tap_name, mtu, bridge);
                // --pppoe owns the L2 channel; reject the device/forward flags it
                // conflicts with. --transport is orthogonal and stays valid.
                cli::validate_pppoe_exclusions(
                    pppoe,
                    tap.is_some(),
                    tun,
                    !tcp.is_empty() || !udp.is_empty(),
                )?;
                cli::validate_pppoe_netcfg(
                    pppoe,
                    pppoe_default_route,
                    pppoe_no_mss_clamp,
                    pppoe_dns,
                )?;
                if tun {
                    if tap.is_some() {
                        return Err("--tun cannot be combined with --tap".into());
                    }
                    if !tcp.is_empty() || !udp.is_empty() {
                        return Err("--tun cannot be combined with --tcp/--udp forwards".into());
                    }
                }
                if tap.is_some() && (!tcp.is_empty() || !udp.is_empty()) {
                    return Err("--tap cannot be combined with --tcp/--udp forwards".into());
                }
                if !pppoe && !tun && tap.is_none() && tcp.is_empty() && udp.is_empty() {
                    return Err(
                        "nothing to do: pass --pppoe, --tun, --tap, or at least one --tcp/--udp"
                            .into(),
                    );
                }
                if proxy && tcp.is_empty() {
                    return Err("--proxy requires at least one --tcp forward".into());
                }

                // Resolve the PPPoE config: credentials (file > env > flag) and the
                // effective MTU (capped to the tunnel MTU minus 8, floored). The
                // password file is read here so the precedence helper stays pure.
                let pppoe = if pppoe {
                    let user = cli::resolve_username(
                        pppoe_user,
                        std::env::var("ZERONAT_PPPOE_USER").ok(),
                    )?;
                    let pass_file = match &pppoe_pass_file {
                        Some(path) => Some(std::fs::read(path).map_err(|e| -> zeronat::Error {
                            format!("reading --pppoe-pass-file {}: {e}", path.display()).into()
                        })?),
                        None => None,
                    };
                    let pass = cli::resolve_password(
                        pass_file,
                        std::env::var("ZERONAT_PPPOE_PASS").ok(),
                        pppoe_pass,
                    )?;
                    let pppoe_mtu_u16: u16 =
                        pppoe_mtu.try_into().map_err(|_| -> zeronat::Error {
                            format!("--pppoe-mtu {pppoe_mtu} exceeds the 65535 MTU limit").into()
                        })?;
                    let tap_mtu_u16: u16 = mtu.try_into().map_err(|_| -> zeronat::Error {
                        format!("--tap-mtu {mtu} exceeds the 65535 MTU limit").into()
                    })?;
                    let resolved = cli::resolve_effective_mtu(pppoe_mtu_u16, tap_mtu_u16)?;
                    if resolved.capped {
                        eprintln!(
                        "pppoe: requested MTU {pppoe_mtu} exceeds what the tunnel carries; using {}",
                        resolved.effective
                    );
                    }
                    Some(client::PppoeRunConfig {
                        username: user,
                        password: pass,
                        service_name: pppoe_service.map(String::into_bytes).unwrap_or_default(),
                        ac_name: pppoe_ac.map(String::into_bytes),
                        tun_name: pppoe_tun,
                        effective_mtu: resolved.effective,
                        default_route: pppoe_default_route,
                        // The MSS clamp rides with --pppoe-default-route unless opted out;
                        // value is the effective IP MTU minus the IPv4+TCP headers.
                        clamp_mss: if pppoe_default_route && !pppoe_no_mss_clamp {
                            Some(resolved.effective.saturating_sub(40).max(536))
                        } else {
                            None
                        },
                        request_dns: pppoe_dns,
                    })
                } else {
                    None
                };
                let tun = if tun {
                    Some(client::ClientTun {
                        name: DEFAULT_TUN_NAME.to_string(),
                        mtu,
                        address: None,
                    })
                } else {
                    None
                };
                let mut tcp = tcp
                    .iter()
                    .map(|s| parse_forward(s, Proto::Tcp))
                    .collect::<Result<Vec<_>>>()?;
                if proxy {
                    for f in &mut tcp {
                        f.proxy = true;
                    }
                }
                let udp = udp
                    .iter()
                    .map(|s| parse_forward(s, Proto::Udp))
                    .collect::<Result<Vec<_>>>()?;
                let transport = parse_transport(transport.as_deref())?;
                let v = env!("CARGO_PKG_VERSION");
                let tl = transport_label(transport);
                match &pppoe {
                    Some(pp) => zeronat::elog!(
                        "zeronat {v} client: pppoe server={server} transport={tl} tun={} mtu={} default-route={} mss-clamp={} dns={}",
                        pp.tun_name, pp.effective_mtu, onoff(pp.default_route), onoff(pp.clamp_mss.is_some()), onoff(pp.request_dns)
                    ),
                    None => zeronat::elog!(
                        "zeronat {v} client: server={server} transport={tl} tcp-forwards={} udp-forwards={} tap={} tun={}",
                        tcp.len(), udp.len(), onoff(tap.is_some()), onoff(tun.is_some())
                    ),
                }
                client::run(
                    server, secret, tcp, udp, transport, tap, tun, pppoe, id_prefix, control,
                )
                .await
            }
        }
        Cmd::ClientAdmin {
            command,
            socket,
            interactive,
        } => {
            #[cfg(all(feature = "tui", unix))]
            if interactive {
                return zeronat::tui::run_client(socket).await;
            }
            let _ = interactive;
            let socket = socket.as_deref();
            match command {
                None | Some(ClientAdminCmd::Show) => client_admin::show(socket).await,
                Some(ClientAdminCmd::SelectServer(name)) => {
                    client_admin::select_server(socket, name).await
                }
                Some(ClientAdminCmd::AddServer {
                    name,
                    addr,
                    transport,
                }) => client_admin::add_server(socket, name, addr, transport).await,
                Some(ClientAdminCmd::RemoveServer(name)) => {
                    client_admin::remove_server(socket, name).await
                }
                Some(ClientAdminCmd::EnableForward(spec)) => {
                    client_admin::set_forward_enabled(socket, &spec, true).await
                }
                Some(ClientAdminCmd::DisableForward(spec)) => {
                    client_admin::set_forward_enabled(socket, &spec, false).await
                }
                Some(ClientAdminCmd::Connect(name)) => client_admin::connect(socket, name).await,
                Some(ClientAdminCmd::Disconnect) => client_admin::disconnect(socket).await,
                Some(ClientAdminCmd::SpawnPppoe(name)) => {
                    client_admin::spawn_pppoe(socket, name).await
                }
                Some(ClientAdminCmd::StopPppoe(name)) => {
                    client_admin::stop_pppoe(socket, name).await
                }
            }
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
        Cmd::Upgrade { check } => zeronat::upgrade::run(check),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use zeronat::client::Forward;

    fn fwd(port: u16, target: &str, proxy: bool, idle: Option<u64>) -> Forward {
        Forward {
            port,
            target: target.into(),
            proxy,
            idle: idle.map(Duration::from_secs),
            enabled: true,
        }
    }

    #[test]
    fn forward_base_forms() {
        for proto in [Proto::Tcp, Proto::Udp] {
            assert_eq!(
                parse_forward("443", proto).unwrap(),
                fwd(443, "127.0.0.1:443", false, None)
            );
            assert_eq!(
                parse_forward("443:8443", proto).unwrap(),
                fwd(443, "127.0.0.1:8443", false, None)
            );
            assert_eq!(
                parse_forward("443:10.0.0.5:8443", proto).unwrap(),
                fwd(443, "10.0.0.5:8443", false, None)
            );
        }
        assert!(parse_forward("a:b:c:d", Proto::Tcp).is_err());
        assert!(parse_forward("notaport", Proto::Tcp).is_err());
    }

    #[test]
    fn forward_proxy_modifier_on_every_base_form() {
        assert_eq!(
            parse_forward("443+proxy", Proto::Tcp).unwrap(),
            fwd(443, "127.0.0.1:443", true, None)
        );
        assert_eq!(
            parse_forward("443:8443+proxy", Proto::Tcp).unwrap(),
            fwd(443, "127.0.0.1:8443", true, None)
        );
        assert_eq!(
            parse_forward("443:10.0.0.5:443+proxy", Proto::Tcp).unwrap(),
            fwd(443, "10.0.0.5:443", true, None)
        );
    }

    #[test]
    fn forward_idle_modifier_on_every_base_form() {
        for proto in [Proto::Tcp, Proto::Udp] {
            assert_eq!(
                parse_forward("51820+idle=300", proto).unwrap(),
                fwd(51820, "127.0.0.1:51820", false, Some(300))
            );
            assert_eq!(
                parse_forward("51820:51821+idle=300", proto).unwrap(),
                fwd(51820, "127.0.0.1:51821", false, Some(300))
            );
            assert_eq!(
                parse_forward("51820:10.0.0.5:51820+idle=300", proto).unwrap(),
                fwd(51820, "10.0.0.5:51820", false, Some(300))
            );
        }
    }

    #[test]
    fn forward_modifiers_combine() {
        assert_eq!(
            parse_forward("443:10.0.0.5:443+proxy+idle=600", Proto::Tcp).unwrap(),
            fwd(443, "10.0.0.5:443", true, Some(600))
        );
        assert_eq!(
            parse_forward("443+idle=600+proxy", Proto::Tcp).unwrap(),
            fwd(443, "127.0.0.1:443", true, Some(600))
        );
    }

    #[test]
    fn forward_proxy_rejected_on_udp() {
        let err = parse_forward("51820+proxy", Proto::Udp).unwrap_err();
        assert!(err.to_string().contains("not supported on udp"));
        assert!(parse_forward("51820+proxy+idle=300", Proto::Udp).is_err());
    }

    #[test]
    fn forward_idle_rejects_zero_and_junk() {
        assert!(parse_forward("443+idle=0", Proto::Tcp).is_err());
        assert!(parse_forward("443+idle=abc", Proto::Tcp).is_err());
        assert!(parse_forward("443+idle=", Proto::Tcp).is_err());
        assert!(parse_forward("443+idle=-5", Proto::Tcp).is_err());
    }

    #[test]
    fn forward_duplicate_modifiers_rejected() {
        assert!(parse_forward("443+proxy+proxy", Proto::Tcp).is_err());
        assert!(parse_forward("443+idle=30+idle=60", Proto::Tcp).is_err());
    }

    #[test]
    fn forward_unknown_modifier_rejected() {
        assert!(parse_forward("443+nope", Proto::Tcp).is_err());
        assert!(parse_forward("443+", Proto::Tcp).is_err());
        assert!(parse_forward("443+PROXY", Proto::Tcp).is_err());
    }

    fn cfg_server(name: &str) -> CfgServer {
        CfgServer {
            name: name.into(),
            addr: format!("{name}.example:2222"),
            secret: zeronat::clientproto::ServerSecret("s".into()),
            transport: zeronat::client::Transport::Auto,
        }
    }

    #[test]
    fn shape_declared_by_any_list_kind() {
        assert!(!declares_shape(&ClientConfig::default()));
        assert!(!declares_shape(&ClientConfig {
            id: Some("x".into()),
            control: Some("/tmp/x.sock".into()),
            ..ClientConfig::default()
        }));
        for cfg in [
            ClientConfig {
                servers: vec![cfg_server("a")],
                ..ClientConfig::default()
            },
            ClientConfig {
                forwards: vec![CfgForward {
                    proto: Proto::Tcp,
                    port: 443,
                    target: "127.0.0.1:443".into(),
                    proxy: false,
                    idle: None,
                    enabled: true,
                }],
                ..ClientConfig::default()
            },
            ClientConfig {
                pppoe: vec![cfg_pppoe(false)],
                ..ClientConfig::default()
            },
            ClientConfig {
                tap: Some(zeronat::clientcfg::CfgTap { dev: "t0".into() }),
                ..ClientConfig::default()
            },
            ClientConfig {
                tun: Some(zeronat::clientcfg::CfgTun {
                    dev: None,
                    address: None,
                }),
                ..ClientConfig::default()
            },
        ] {
            assert!(declares_shape(&cfg));
        }
    }

    #[test]
    fn active_server_prefers_named_entry_then_first() {
        let cfg = ClientConfig {
            servers: vec![cfg_server("a"), cfg_server("b")],
            ..ClientConfig::default()
        };
        assert_eq!(active_server(&cfg).unwrap().name, "a");

        let cfg = ClientConfig {
            active: Some("b".into()),
            ..cfg
        };
        assert_eq!(active_server(&cfg).unwrap().name, "b");
    }

    #[test]
    fn active_server_requires_an_entry() {
        assert!(active_server(&ClientConfig::default()).is_err());
    }

    #[test]
    fn split_forwards_by_proto_with_options() {
        let fwds = [
            CfgForward {
                proto: Proto::Tcp,
                port: 443,
                target: "10.0.0.5:8443".into(),
                proxy: true,
                idle: Some(600),
                enabled: true,
            },
            CfgForward {
                proto: Proto::Udp,
                port: 51820,
                target: "127.0.0.1:51820".into(),
                proxy: false,
                idle: None,
                enabled: false,
            },
        ];
        let (tcp, udp) = split_forwards(&fwds);
        assert_eq!(tcp, vec![fwd(443, "10.0.0.5:8443", true, Some(600))]);
        let disabled = Forward {
            enabled: false,
            ..fwd(51820, "127.0.0.1:51820", false, None)
        };
        assert_eq!(udp, vec![disabled]);
    }

    fn cfg_pppoe(default_route: bool) -> zeronat::clientcfg::CfgPppoe {
        zeronat::clientcfg::CfgPppoe {
            name: "wan".into(),
            autostart: true,
            username: "user@isp".into(),
            password: Some("pw".into()),
            password_file: None,
            service: "fibra".into(),
            mtu: 1492,
            default_route,
            clamp_mss: true,
            request_dns: true,
        }
    }

    #[test]
    fn pppoe_entry_resolves_run_config() {
        let cfg = pppoe_from_entry(&cfg_pppoe(true)).unwrap();
        assert_eq!(cfg.username, b"user@isp");
        assert_eq!(cfg.password, b"pw");
        assert_eq!(cfg.service_name, b"fibra");
        assert_eq!(cfg.tun_name, "zppp0");
        // 1492 caps to the 1400-byte tunnel minus the PPPoE overhead.
        assert_eq!(cfg.effective_mtu, 1392);
        assert_eq!(cfg.clamp_mss, Some(1352));
        assert!(cfg.default_route);
        assert!(cfg.request_dns);
    }

    #[test]
    fn pppoe_entry_clamp_rides_with_default_route() {
        let cfg = pppoe_from_entry(&cfg_pppoe(false)).unwrap();
        assert_eq!(cfg.clamp_mss, None);
    }

    #[test]
    fn pppoe_entry_needs_a_password_source() {
        let entry = zeronat::clientcfg::CfgPppoe {
            password: None,
            ..cfg_pppoe(false)
        };
        assert!(pppoe_from_entry(&entry).is_err());
    }
}
