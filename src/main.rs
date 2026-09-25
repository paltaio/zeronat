use std::net::{Ipv4Addr, SocketAddrV4};

use zeronat::client::{DEFAULT_TAP_MTU, DEFAULT_TUN_NAME};
use zeronat::clientcfg::{CfgForward, CfgPppoe, CfgServer, ClientConfig};
use zeronat::clientproto::ClientMsg;
use zeronat::identity::ClientId;
use zeronat::proto::{Proto, Source};
use zeronat::seed::Seed;
use zeronat::tap::TapConfig;
use zeronat::{admin, client, client_admin, errf, server, Result};

const TUN_PREFIX_LEN: u8 = 24;

/// Apply the KCP window from `--kcp-window` or `ZERONAT_KCP_WINDOW`, leaving the
/// default in place when neither is set. Runs before any session is built, so
/// every conv this process opens sees the same value.
fn apply_kcp_window(flag: Option<String>) -> zeronat::Result<()> {
    let (source, value) = match flag {
        Some(value) => ("--kcp-window", value),
        None => match std::env::var("ZERONAT_KCP_WINDOW") {
            Ok(value) => ("ZERONAT_KCP_WINDOW", value),
            Err(_) => return Ok(()),
        },
    };
    zeronat::kcp::set_window(
        zeronat::kcp::parse_window(&value)
            .map_err(|e| -> zeronat::Error { errf!("{source}: {e}") })?,
    );
    Ok(())
}

fn runtime_secret(value: String) -> Result<String> {
    zeronat::secret::normalize(&value).map_err(Into::into)
}

/// The seed from `--seed` or `ZERONAT_SEED`, if either is set.
fn seed_from(flag: Option<String>) -> Result<Option<Seed>> {
    flag.or_else(|| std::env::var("ZERONAT_SEED").ok())
        .map(|value| Seed::parse(&value))
        .transpose()
}

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
  derive-client <ID>  Print the env lines that start client ID without the seed
  upgrade  Fetch the latest release and restart this host's deployment

server options:
  --bind <ADDR>       Address to bind on (default: 0.0.0.0)
  --control <PORT>    Control port (default: 2222)
  --seed <64-HEX>     Seed for every credential left unset (or env ZERONAT_SEED):
                      the network secret, the admin secret, the discovery
                      credential, and the credential of each --client given as
                      a bare ID. A credential set on its own always wins
  --secret <64-HEX>   32-byte hex secret (or env ZERONAT_SECRET, or derived from
                      the seed)
  --client <ID>[:<64-HEX>]  Authorize a client id and credential (repeatable; or
                      env ZERONAT_CLIENT_ID and ZERONAT_CLIENT_SECRET). A bare
                      ID takes its credential from the seed
  --admin-secret <64-HEX>  Independent remote admin secret (or env
                      ZERONAT_ADMIN_SECRET, or derived from the seed; remote
                      admin is disabled when none is set)
  --id <ID>           Server identity label (default: 0)
  --config <PATH>     Load listeners/routes/identity from a config file
  --tcp <PORT>        Public TCP port to expose (repeatable)
  --udp <PORT>        Public UDP port to expose (repeatable)
  --tun               L3 all-ports mode (Linux only): forward every port except
                      the control port (and --except) plus ICMP to the client
  --except <PORT>     Port to keep on the host in --tun mode (repeatable)
  --exit              Exit mode (requires --tun): masquerade the client's
                      outbound traffic through this host
  --exit-iface <IF>   Interface --exit masquerades out of (default: the
                      default-route interface)
  --tap <NAME>        L2 bridge mode (Linux only): create/attach this TAP device
  --tap-mtu <N>       TAP/TUN MTU (default: 1400; alias --tun-mtu)
  --bridge <NAME>     Enslave the TAP to this existing bridge
  --kcp-window <N>    KCP window in segments for the udp transport (default: 256,
                      range 32-4096; or env ZERONAT_KCP_WINDOW). Both ends must
                      set it; raising it lifts the per-connection ceiling on an
                      uncongested path and lowers throughput on a congested one
  --server dht        Publish this server's address to the DHT for discovery
  --discovery <64-HEX>  Discovery credential the DHT record is keyed by (or env
                      ZERONAT_DISCOVERY_SECRET, or derived from the seed);
                      required with --server dht
  --announce-ip <IP>  Public IPv4 to announce (default: auto-detected via DHT)
  --announce-port <P> Public port to announce (default: control port)

client options:
  --server <ADDR>     Server control address host:port, or 'dht' to discover via DHT
  --seed <64-HEX>     Seed for every credential left unset (or env ZERONAT_SEED):
                      the network secret, the discovery credential, and this
                      client's credential for --id. A credential set on its own
                      always wins
  --secret <64-HEX>   32-byte hex secret (or env ZERONAT_SECRET, or derived from
                      the seed)
  --credential <64-HEX>  Client credential (or env ZERONAT_CLIENT_SECRET, or
                      derived from the seed for --id; defaults to --secret)
  --discovery <64-HEX>  Discovery credential the server's DHT record is keyed
                      by (or env ZERONAT_DISCOVERY_SECRET, or derived from the
                      seed); required with --server dht
  --id <ID>           Client id. With a seed-derived credential it is sent as-is
                      and must equal the id in the server's --client entry;
                      otherwise it is a prefix a host suffix is appended to
                      (default: short hostname)
  --config <PATH>     Load servers/forwards/identity from a config file
  --tcp <SPEC>        Forward TCP: PORT | PORT:LOCALPORT | PORT:HOST:PORT, plus
                      optional +proxy (send a PROXY protocol v2 header to the
                      target) and +idle=SECS modifiers (repeatable)
  --udp <SPEC>        Forward UDP: PORT | PORT:LOCALPORT | PORT:HOST:PORT, plus
                      an optional +idle=SECS modifier (repeatable)
  --proxy             Send a PROXY protocol v2 header on every --tcp forward
  --tun               L3 all-ports mode (Linux only): receive every forwarded
                      port on local services (bind 0.0.0.0 or the tunnel address)
  --exit              Exit mode (requires --tun): route this host's IPv4
                      traffic through the server
  --exit-strict       Strict exit (requires --exit): delete the default routes
                      and send IPv6 to loopback while the routes are up; a
                      crash leaves the host without a default route
  --kcp-window <N>    KCP window in segments for the udp transport (default: 256,
                      range 32-4096; or env ZERONAT_KCP_WINDOW). Both ends must
                      set it; raising it lifts the per-connection ceiling on an
                      uncongested path and lowers throughput on a congested one
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
  add-forward <PROTO:SPEC>  Add an enabled forward; SPEC as in --tcp/--udp,
                      e.g. tcp:443:10.0.0.5:8443+proxy+idle=600
  remove-forward <PROTO:PORT>  Remove a forward, e.g. tcp:443
  connect [NAME]      Leave offline mode and bring up the boot session body
  disconnect          Tear the session down; nothing dials until connect
  spawn-pppoe <NAME>  Bring up the named PPPoE session
  stop-pppoe <NAME>   Stop the named PPPoE session and return to the base mode
  attach-peer <PEER-ID> [--dev <NAME>] [--exit] [--exit-strict]
                      Exit through the named peer; --exit routes this host's
                      IPv4 traffic through the pair
  attach-provider exit|segment [<NAME>]
                      Serve a capability to peers; NAME is the masquerade
                      interface for exit (default: the default-route one) and
                      the bridge for segment, which is required
  detach-peer <PEER-ID>     Remove the consumer slot exiting through that peer
  detach-provider exit|segment  Stop providing a capability; its pairs go down
  --socket <PATH>     Admin socket path (default: /run/zeronat/client.sock,
                      else $XDG_RUNTIME_DIR/zeronat/client.sock)

admin options:
  (no command)        Open the interactive console on a terminal; prints the
                      status and exits when piped or redirected
  show                Print the server's current topology and exit
  --server <ADDR>     Server control address host:port
  --secret <64-HEX>   32-byte admin secret (or env ZERONAT_ADMIN_SECRET, or
                      derived from env ZERONAT_SEED, or either one read from
                      /etc/zeronat/.env)

derive-client options:
  <ID>                The client id, as the server lists it under --client.
                      Prints ZERONAT_SECRET and ZERONAT_CLIENT_SECRET
  --seed <64-HEX>     The seed (or env ZERONAT_SEED)
  --dht               Also print ZERONAT_DISCOVERY_SECRET, for a client that
                      runs with --server dht

upgrade options:
  --check             Report whether a newer release exists, without applying it

Options:
  -h, --help          Print this help and exit
  -V, --version       Print the version and exit
";

struct ClientArgs {
    server: Option<String>,
    seed: Option<String>,
    secret: Option<String>,
    credential: Option<String>,
    discovery: Option<String>,
    id_prefix: Option<String>,
    tcp: Vec<String>,
    udp: Vec<String>,
    proxy: bool,
    transport: Option<String>,
    tap_name: Option<String>,
    bridge: Option<String>,
    tun: bool,
    exit: bool,
    exit_strict: bool,
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
}

struct ServerArgs {
    bind: Option<Ipv4Addr>,
    control: Option<u16>,
    seed: Option<String>,
    secret: Option<String>,
    discovery: Option<String>,
    client_credentials: Vec<zeronat::config::CfgClient>,
    admin_secret: Option<String>,
    server_id: Option<String>,
    tcp: Vec<u16>,
    udp: Vec<u16>,
    tap: Option<TapConfig>,
    tun: bool,
    mtu: usize,
    except: Vec<u16>,
    exit: bool,
    exit_iface: Option<String>,
    dht: bool,
    announce_ip: Option<Ipv4Addr>,
    announce_port: Option<u16>,
    config: Option<std::path::PathBuf>,
}

enum Cmd {
    Server(Box<ServerArgs>),
    Client(Box<ClientArgs>),
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
    DeriveClient {
        secret: String,
        credential: String,
        discovery: Option<String>,
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
    AddForward(String),
    RemoveForward(String),
    Connect(Option<String>),
    Disconnect,
    SpawnPppoe(String),
    StopPppoe(String),
    AttachPeer {
        peer: String,
        dev: Option<String>,
        exit: bool,
        exit_strict: bool,
    },
    AttachProvider {
        capability: String,
        iface: Option<String>,
    },
    DetachPeer(String),
    DetachProvider(String),
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
        other => Err(errf!(
            "invalid --transport '{other}' (expected auto|udp|tcp)"
        )),
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
    let (p, host, lp) = match parts.as_slice() {
        [p] => (p, "127.0.0.1", p),
        [p, lp] => (p, "127.0.0.1", lp),
        [p, host, lp] => (p, *host, lp),
        _ => return Err(errf!("invalid forward spec '{spec}'")),
    };
    let port: u16 = p.parse()?;
    let lport: u16 = lp.parse()?;
    let target = format!("{host}:{lport}");

    let mut proxy = false;
    let mut idle: Option<std::time::Duration> = None;
    if let Some(mods) = mods {
        for m in mods.split('+') {
            if m == "proxy" {
                if proxy {
                    return Err(errf!("duplicate modifier '+proxy' in '{spec}'"));
                }
                if proto == Proto::Udp {
                    return Err("+proxy is not supported on udp forwards".into());
                }
                proxy = true;
            } else if let Some(v) = m.strip_prefix("idle=") {
                if idle.is_some() {
                    return Err(errf!("duplicate modifier '+idle' in '{spec}'"));
                }
                let secs: u32 = v.parse().map_err(|_| -> zeronat::Error {
                    errf!("+idle wants whole seconds, got '{v}'")
                })?;
                if secs == 0 {
                    return Err("+idle must be at least 1 second".into());
                }
                idle = Some(std::time::Duration::from_secs(secs.into()));
            } else {
                return Err(errf!("unknown modifier '+{m}' in '{spec}'"));
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

/// An admin `PROTO:SPEC` forward: the proto prefix picks the forward map, the
/// rest is the same spec grammar `--tcp`/`--udp` take, defaults included.
fn parse_proto_forward(spec: &str) -> Result<(Proto, client::Forward)> {
    let (proto, rest) = spec
        .split_once(':')
        .ok_or_else(|| -> zeronat::Error { errf!("expected PROTO:SPEC, got '{spec}'") })?;
    let proto = match proto {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => return Err(errf!("proto must be tcp or udp, got '{other}'")),
    };
    Ok((proto, parse_forward(rest, proto)?))
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
        || cfg.peer.is_some()
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
        return Err(errf!(
            "pppoe '{}' needs `password` or `password_file`",
            p.name
        ));
    }
    let pass_file = match &p.password_file {
        Some(path) => Some(std::fs::read(path).map_err(|e| -> zeronat::Error {
            errf!("reading [[pppoe]] password_file {path}: {e}")
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

fn usage_exit() -> ! {
    print!("{USAGE}");
    std::process::exit(0);
}

fn unknown_flag(flag: &str) -> ! {
    eprintln!("error: unknown flag '{flag}'");
    std::process::exit(1);
}

/// The value following `flag`.
#[inline(never)]
fn value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String> {
    iter.next().ok_or_else(|| errf!("{flag} requires a value"))
}

/// The value following `flag`, parsed as `what`: an integer up to `max`.
#[inline(never)]
fn parsed(iter: &mut std::vec::IntoIter<String>, flag: &str, what: &str, max: u64) -> Result<u64> {
    let v = value(iter, flag)?;
    match v.parse::<u64>() {
        Ok(n) if n <= max => Ok(n),
        _ => Err(errf!("{flag} must be {what}, got '{v}'")),
    }
}

/// The value following `flag`, parsed as an IPv4 address.
#[inline(never)]
fn parsed_ip(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<Ipv4Addr> {
    let v = value(iter, flag)?;
    v.parse()
        .map_err(|_| errf!("{flag} must be an IPv4 address, got '{v}'"))
}

/// The position of `name` in the space-separated `names`.
#[inline(never)]
fn lookup(names: &'static str, name: &str) -> Option<usize> {
    names.split(' ').position(|n| n == name)
}

/// How a flag in a subcommand's table is consumed.
#[derive(Clone, Copy)]
enum Kind {
    /// `-h` / `--help`.
    Help,
    /// A bare switch; sets `switches[i]`.
    Switch(u8),
    /// A string value; sets `strs[i]`.
    Str(u8),
    /// A repeatable string value; appends to `lists[i]`.
    List(u8),
    /// A u16 value; sets `u16s[i]`.
    U16(u8),
    /// A repeatable u16 value; appends to `ports[i]`.
    Port(u8),
    /// A positive integer; sets `sizes[i]`.
    Size(u8),
    /// An IPv4 address; sets `ipv4s[i]`.
    Ipv4(u8),
    /// `server --server dht`.
    Dht,
    /// `server --client ID[:64-HEX]`.
    Client,
}

/// A subcommand's flags: space-separated names, each with the kind at the
/// same position.
struct Table {
    names: &'static str,
    kinds: &'static [Kind],
}

/// Everything a subcommand's flags set.
#[derive(Default)]
struct Parsed {
    switches: [bool; 8],
    strs: [Option<String>; 17],
    lists: [Vec<String>; 2],
    u16s: [Option<u16>; 2],
    ports: [Vec<u16>; 3],
    sizes: [Option<usize>; 2],
    ipv4s: [Option<Ipv4Addr>; 2],
    dht: bool,
    clients: Vec<zeronat::config::CfgClient>,
    /// Bare arguments, in order.
    pos: Vec<String>,
}

/// Consume `iter` against `table`. `positional` is how many bare arguments
/// the subcommand takes: `None` makes every unknown token an unknown flag,
/// `Some(n)` collects bare tokens and rejects the `n+1`th.
fn walk(
    mut iter: std::vec::IntoIter<String>,
    table: &Table,
    positional: Option<usize>,
) -> Result<Parsed> {
    let iter = &mut iter;
    let mut p = Parsed::default();
    while let Some(flag) = iter.next() {
        let name = if flag == "--tun-mtu" {
            "--tap-mtu"
        } else {
            flag.as_str()
        };
        let Some(kind) = lookup(table.names, name).map(|i| table.kinds[i]) else {
            match positional {
                Some(max) if !flag.starts_with('-') => {
                    if p.pos.len() >= max {
                        return Err(errf!("unexpected argument '{flag}'"));
                    }
                    p.pos.push(flag);
                    continue;
                }
                _ => unknown_flag(&flag),
            }
        };
        match kind {
            Kind::Help => usage_exit(),
            Kind::Switch(i) => p.switches[i as usize] = true,
            Kind::Str(i) => p.strs[i as usize] = Some(value(iter, name)?),
            Kind::List(i) => p.lists[i as usize].push(value(iter, name)?),
            Kind::U16(i) => {
                p.u16s[i as usize] = Some(parsed(iter, name, "a u16", u16::MAX.into())? as u16)
            }
            Kind::Port(i) => {
                p.ports[i as usize].push(parsed(iter, name, "a u16", u16::MAX.into())? as u16)
            }
            Kind::Size(i) => {
                p.sizes[i as usize] =
                    Some(parsed(iter, name, "a positive integer", usize::MAX as u64)? as usize)
            }
            Kind::Ipv4(i) => p.ipv4s[i as usize] = Some(parsed_ip(iter, name)?),
            Kind::Dht => {
                let v = value(iter, name)?;
                if v != "dht" {
                    return Err(errf!("server --server only accepts 'dht', got '{v}'"));
                }
                p.dht = true;
            }
            Kind::Client => {
                let value = iter.next().ok_or("--client requires ID or ID:64-HEX")?;
                let (client_id, secret) = match value.split_once(':') {
                    Some((client_id, secret)) => {
                        (client_id, Some(runtime_secret(secret.to_string())?))
                    }
                    None => (value.as_str(), None),
                };
                if client_id.is_empty() {
                    return Err("--client id must not be empty".into());
                }
                p.clients.push(zeronat::config::CfgClient {
                    id: client_id.to_string(),
                    secret,
                });
            }
        }
    }
    Ok(p)
}

const SERVER_FLAGS: Table = Table {
    names: "-h --help --bind --config --server --announce-ip --announce-port --control --seed \
            --secret --discovery --client --admin-secret --kcp-window --id --tcp --udp --tap \
            --tap-mtu --bridge --tun --except --exit --exit-iface",
    kinds: &[
        Kind::Help,
        Kind::Help,
        Kind::Ipv4(0),
        Kind::Str(0),
        Kind::Dht,
        Kind::Ipv4(1),
        Kind::U16(0),
        Kind::U16(1),
        Kind::Str(1),
        Kind::Str(2),
        Kind::Str(3),
        Kind::Client,
        Kind::Str(4),
        Kind::Str(5),
        Kind::Str(6),
        Kind::Port(0),
        Kind::Port(1),
        Kind::Str(7),
        Kind::Size(0),
        Kind::Str(8),
        Kind::Switch(0),
        Kind::Port(2),
        Kind::Switch(1),
        Kind::Str(9),
    ],
};

const CLIENT_FLAGS: Table = Table {
    names:
        "-h --help --tun --exit --exit-strict --server --seed --secret --credential --discovery \
            --id --tcp --udp --proxy --kcp-window --transport --config --tap --tap-mtu --bridge \
            --pppoe --pppoe-user --pppoe-pass --pppoe-pass-file --pppoe-service --pppoe-ac \
            --pppoe-tun --pppoe-mtu --pppoe-default-route --pppoe-no-mss-clamp --pppoe-dns",
    kinds: &[
        Kind::Help,
        Kind::Help,
        Kind::Switch(0),
        Kind::Switch(1),
        Kind::Switch(2),
        Kind::Str(0),
        Kind::Str(1),
        Kind::Str(2),
        Kind::Str(3),
        Kind::Str(4),
        Kind::Str(5),
        Kind::List(0),
        Kind::List(1),
        Kind::Switch(3),
        Kind::Str(6),
        Kind::Str(7),
        Kind::Str(8),
        Kind::Str(9),
        Kind::Size(0),
        Kind::Str(10),
        Kind::Switch(4),
        Kind::Str(11),
        Kind::Str(12),
        Kind::Str(13),
        Kind::Str(14),
        Kind::Str(15),
        Kind::Str(16),
        Kind::Size(1),
        Kind::Switch(5),
        Kind::Switch(6),
        Kind::Switch(7),
    ],
};

const CLIENT_ADMIN_FLAGS: Table = Table {
    names: "-h --help --socket --transport --dev --exit --exit-strict",
    kinds: &[
        Kind::Help,
        Kind::Help,
        Kind::Str(0),
        Kind::Str(1),
        Kind::Str(2),
        Kind::Switch(0),
        Kind::Switch(1),
    ],
};

const DERIVE_CLIENT_FLAGS: Table = Table {
    names: "-h --help --seed --dht",
    kinds: &[Kind::Help, Kind::Help, Kind::Str(0), Kind::Switch(0)],
};

const UPGRADE_FLAGS: Table = Table {
    names: "-h --help --check",
    kinds: &[Kind::Help, Kind::Help, Kind::Switch(0)],
};

const CLIENT_ADMIN_COMMANDS: &str = "show select-server add-server remove-server enable-forward \
                                     disable-forward add-forward remove-forward connect disconnect \
                                     spawn-pppoe stop-pppoe attach-peer attach-provider detach-peer \
                                     detach-provider";

const ADMIN_FLAGS: Table = Table {
    names: "-h --help --server --secret",
    kinds: &[Kind::Help, Kind::Help, Kind::Str(0), Kind::Str(1)],
};

#[derive(Clone, Copy, PartialEq)]
enum Sub {
    Server,
    Client,
    Admin,
    DeriveClient,
    Upgrade,
}

#[inline(never)]
fn parse_args() -> Result<Cmd> {
    let mut args = std::env::args().skip(1);

    let subcmd = match args.next().as_deref() {
        Some("-h") | Some("--help") => usage_exit(),
        Some("-V") | Some("--version") => {
            println!("zeronat {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Some("server") => Sub::Server,
        Some("client") => Sub::Client,
        Some("admin") => Sub::Admin,
        Some("derive-client") => Sub::DeriveClient,
        Some("upgrade") => Sub::Upgrade,
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
    let client_admin = subcmd == Sub::Client && tokens.first().is_some_and(|t| t == "admin");

    let mut iter = tokens.into_iter();

    if client_admin {
        iter.next();
        return parse_client_admin(iter);
    }
    match subcmd {
        Sub::Server => parse_server(iter),
        Sub::Client => parse_client(iter),
        Sub::DeriveClient => parse_derive_client(iter),
        Sub::Upgrade => {
            let p = walk(iter, &UPGRADE_FLAGS, None)?;
            Ok(Cmd::Upgrade {
                check: p.switches[0],
            })
        }
        Sub::Admin => parse_admin(iter),
    }
}

type Args = std::vec::IntoIter<String>;

#[inline(never)]
fn parse_client_admin(iter: Args) -> Result<Cmd> {
    let mut p = walk(iter, &CLIENT_ADMIN_FLAGS, Some(usize::MAX))?;
    let mut pos = std::mem::take(&mut p.pos).into_iter();
    let command = pos.next();
    let [exit, exit_strict, ..] = p.switches;

    if p.strs[1].is_some() && command.as_deref() != Some("add-server") {
        return Err("--transport only applies to add-server".into());
    }
    if (p.strs[2].is_some() || exit || exit_strict) && command.as_deref() != Some("attach-peer") {
        return Err("--dev, --exit, and --exit-strict only apply to attach-peer".into());
    }

    let named = |pos: &mut std::vec::IntoIter<String>, cmd: &str| -> Result<String> {
        pos.next().ok_or_else(|| errf!("{cmd} requires a name"))
    };
    let command = match command {
        None => None,
        Some(cmd) => Some(match lookup(CLIENT_ADMIN_COMMANDS, &cmd) {
            Some(0) => ClientAdminCmd::Show,
            Some(1) => ClientAdminCmd::SelectServer(named(&mut pos, &cmd)?),
            Some(2) => {
                let name = named(&mut pos, &cmd)?;
                let addr = pos
                    .next()
                    .ok_or("add-server requires a name and an address")?;
                ClientAdminCmd::AddServer {
                    name,
                    addr,
                    transport: parse_transport(p.strs[1].as_deref())?,
                }
            }
            Some(3) => ClientAdminCmd::RemoveServer(named(&mut pos, &cmd)?),
            Some(4) => ClientAdminCmd::EnableForward(named(&mut pos, &cmd)?),
            Some(5) => ClientAdminCmd::DisableForward(named(&mut pos, &cmd)?),
            Some(6) => ClientAdminCmd::AddForward(named(&mut pos, &cmd)?),
            Some(7) => ClientAdminCmd::RemoveForward(named(&mut pos, &cmd)?),
            Some(8) => ClientAdminCmd::Connect(pos.next()),
            Some(9) => ClientAdminCmd::Disconnect,
            Some(10) => ClientAdminCmd::SpawnPppoe(named(&mut pos, &cmd)?),
            Some(11) => ClientAdminCmd::StopPppoe(named(&mut pos, &cmd)?),
            Some(12) => ClientAdminCmd::AttachPeer {
                peer: named(&mut pos, &cmd)?,
                dev: p.strs[2].take(),
                exit,
                exit_strict,
            },
            Some(13) => ClientAdminCmd::AttachProvider {
                capability: pos
                    .next()
                    .ok_or("attach-provider requires exit or segment")?,
                iface: pos.next(),
            },
            Some(14) => ClientAdminCmd::DetachPeer(named(&mut pos, &cmd)?),
            Some(15) => ClientAdminCmd::DetachProvider(
                pos.next()
                    .ok_or("detach-provider requires exit or segment")?,
            ),
            _ => return Err(errf!("unknown client admin command '{cmd}'")),
        }),
    };
    if let Some(extra) = pos.next() {
        return Err(errf!("unexpected argument '{extra}'"));
    }

    let interactive = command.is_none() && interactive_default();
    Ok(Cmd::ClientAdmin {
        command,
        socket: p.strs[0].take().map(Into::into),
        interactive,
    })
}

#[inline(never)]
fn parse_server(iter: Args) -> Result<Cmd> {
    let mut p = walk(iter, &SERVER_FLAGS, None)?;

    apply_kcp_window(p.strs[5].take())?;

    // Credentials the seed may fill stay unresolved here: the config file,
    // read at run time, may carry the seed.
    p.strs[1] = seed_from(p.strs[1].take())?.map(|seed| seed.to_hex());
    p.strs[2] = p.strs[2]
        .take()
        .or_else(|| std::env::var("ZERONAT_SECRET").ok())
        .map(runtime_secret)
        .transpose()?;
    if p.clients.is_empty() {
        match (
            std::env::var("ZERONAT_CLIENT_ID").ok(),
            std::env::var("ZERONAT_CLIENT_SECRET").ok(),
        ) {
            (Some(id), secret) => {
                if id.is_empty() {
                    return Err("ZERONAT_CLIENT_ID must not be empty".into());
                }
                p.clients.push(zeronat::config::CfgClient {
                    id,
                    secret: secret.map(runtime_secret).transpose()?,
                });
            }
            (None, Some(_)) => {
                return Err("ZERONAT_CLIENT_SECRET is set without ZERONAT_CLIENT_ID".into());
            }
            (None, None) => {}
        }
    }

    let [tun, exit, ..] = p.switches;
    if tun && p.strs[8].is_some() {
        return Err("--bridge applies to --tap only, not --tun".into());
    }

    let tap_mtu = p.sizes[0].unwrap_or(DEFAULT_TAP_MTU);
    let [config, seed, secret, discovery, admin_secret, _, server_id, tap_name, bridge, exit_iface, ..] =
        p.strs;
    let [tcp, udp, except] = p.ports;
    Ok(Cmd::Server(Box::new(ServerArgs {
        bind: p.ipv4s[0],
        control: p.u16s[1],
        seed,
        secret,
        discovery: discovery.or_else(|| std::env::var("ZERONAT_DISCOVERY_SECRET").ok()),
        client_credentials: p.clients,
        admin_secret: admin_secret.or_else(|| std::env::var("ZERONAT_ADMIN_SECRET").ok()),
        server_id,
        tcp,
        udp,
        tap: build_tap(tap_name, tap_mtu, bridge),
        tun,
        mtu: tap_mtu,
        except,
        exit,
        exit_iface,
        dht: p.dht,
        announce_ip: p.ipv4s[1],
        announce_port: p.u16s[0],
        config: config.map(Into::into),
    })))
}

#[inline(never)]
fn parse_client(iter: Args) -> Result<Cmd> {
    let mut p = walk(iter, &CLIENT_FLAGS, None)?;

    apply_kcp_window(p.strs[6].take())?;

    let [tun, exit, exit_strict, proxy, pppoe, pppoe_default_route, pppoe_no_mss_clamp, pppoe_dns] =
        p.switches;
    let [server, seed, secret, credential, discovery, id_prefix, _, transport, config, tap_name, bridge, pppoe_user, pppoe_pass, pppoe_pass_file, pppoe_service, pppoe_ac, pppoe_tun] =
        p.strs;
    let [tcp, udp] = p.lists;
    Ok(Cmd::Client(Box::new(ClientArgs {
        server,
        seed,
        secret,
        credential,
        discovery,
        id_prefix,
        tcp,
        udp,
        proxy,
        transport,
        tun,
        exit,
        exit_strict,
        mtu: p.sizes[0],
        tap_name,
        bridge,
        pppoe,
        pppoe_user,
        pppoe_pass,
        pppoe_pass_file: pppoe_pass_file.map(Into::into),
        pppoe_service,
        pppoe_ac,
        pppoe_tun: pppoe_tun.unwrap_or_else(|| "zppp0".to_string()),
        pppoe_mtu: p.sizes[1].unwrap_or(1492),
        pppoe_default_route,
        pppoe_no_mss_clamp,
        pppoe_dns,
        config: config.map(Into::into),
    })))
}

#[inline(never)]
fn parse_derive_client(iter: Args) -> Result<Cmd> {
    let mut p = walk(iter, &DERIVE_CLIENT_FLAGS, Some(1))?;
    let id = p.pos.pop().ok_or("derive-client requires a client id")?;
    if id.is_empty() {
        return Err("client id must not be empty".into());
    }
    let seed = seed_from(p.strs[0].take())?.ok_or("--seed or ZERONAT_SEED is required")?;
    Ok(Cmd::DeriveClient {
        secret: seed.network(),
        credential: seed.client(&id),
        discovery: p.switches[0].then(|| seed.discovery()),
    })
}

#[inline(never)]
fn parse_admin(iter: Args) -> Result<Cmd> {
    let mut p = walk(iter, &ADMIN_FLAGS, Some(1))?;
    let command = p.pos.pop();

    match command.as_deref() {
        None | Some("show") => {}
        Some(other) => return Err(errf!("unknown admin command '{other}'")),
    }

    let server = p.strs[0].take().ok_or("--server is required")?;
    let secret = match p.strs[1]
        .take()
        .or_else(|| std::env::var("ZERONAT_ADMIN_SECRET").ok())
    {
        Some(secret) => secret,
        None => match seed_from(None)? {
            Some(seed) => seed.admin(),
            None => zeronat::admin::admin_secret_from_env_file().ok_or(
                "no admin secret: pass --secret, set ZERONAT_ADMIN_SECRET or ZERONAT_SEED, or add either to /etc/zeronat/.env",
            )?,
        },
    };
    let secret = runtime_secret(secret)?;

    let interactive = command.is_none() && interactive_default();
    Ok(Cmd::Admin {
        server,
        secret,
        interactive,
    })
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

/// The config at `path`. A missing file is a normal first boot; a malformed
/// file is set aside so its contents stay recoverable and the client starts
/// from command-line settings; an unreadable file (permission or transient
/// IO) is fatal, so a restart retries rather than running with settings we
/// never managed to read.
#[inline(never)]
fn load_client_file(path: &std::path::Path) -> Result<Box<ClientConfig>> {
    match zeronat::clientcfg::load(path) {
        Ok(cfg) => Ok(Box::new(cfg)),
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
            Ok(Box::default())
        }
        Err(zeronat::config::LoadError::Unreadable(e)) => Err(e),
    }
}

/// Resolve the server command line against its config file into the settings
/// the server boots from.
#[inline(never)]
fn server_boot(args: ServerArgs) -> Result<server::ServerSettings> {
    let ServerArgs {
        bind,
        control,
        seed,
        secret,
        discovery,
        client_credentials,
        admin_secret,
        server_id,
        tcp,
        udp,
        tap,
        tun,
        mtu,
        except,
        exit,
        exit_iface,
        dht,
        announce_ip,
        announce_port,
        config,
    } = args;
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
    let (cli_id, cli_bind, cli_control, cli_seed, cli_admin_secret) =
        (server_id, bind, control, seed, admin_secret);
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
                errf!("[server].control must be IPv4:port, got '{ctrl}'")
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

    let file_seed = file
        .seed
        .as_deref()
        .map(|value| {
            Seed::parse(value)
                .map(|seed| seed.to_hex())
                .map_err(|e| -> zeronat::Error { errf!("config [server].{e}") })
        })
        .transpose()?;
    if let (Some(f), Some(c)) = (&file_seed, &cli_seed) {
        if f != c {
            zeronat::elog!("config [server].seed overrides --seed");
        }
    }
    let seed_hex = file_seed.or(cli_seed);
    let seed = seed_hex.as_deref().map(Seed::parse).transpose()?;

    // An explicit value always wins; the seed fills what is left.
    let secret = match secret {
        Some(secret) => secret,
        None => seed.as_ref().map(Seed::network).ok_or(
            "--secret, ZERONAT_SECRET, or a seed (--seed, ZERONAT_SEED, [server].seed) is required",
        )?,
    };
    let discovery = discovery.or_else(|| seed.as_ref().map(Seed::discovery));
    if dht && discovery.is_none() {
        return Err(
            "--server dht requires --discovery, ZERONAT_DISCOVERY_SECRET, or a seed".into(),
        );
    }
    if file.admin_secret.is_some() && cli_admin_secret.is_some() {
        zeronat::elog!("config [server].admin_secret overrides --admin-secret");
    }
    let explicit_admin_secret = file
        .admin_secret
        .clone()
        .or(cli_admin_secret)
        .map(runtime_secret)
        .transpose()?;
    let admin_secret = explicit_admin_secret
        .clone()
        .or_else(|| seed.as_ref().map(Seed::admin));

    let (client_entries, no_credential) = if file.clients.is_empty() {
        (
            &client_credentials,
            "give --client ID:64-HEX or set a seed (--seed or ZERONAT_SEED)",
        )
    } else {
        if !client_credentials.is_empty() {
            zeronat::elog!("config [[clients]] overrides --client");
        }
        (&file.clients, "add `secret` or set [server].seed")
    };
    let client_credentials = client_entries
        .iter()
        .map(|client| -> Result<server::ClientCredentialSpec> {
            let secret = match (&client.secret, &seed) {
                (Some(secret), _) => secret.clone(),
                (None, Some(seed)) => seed.client(&client.id),
                (None, None) => {
                    return Err(errf!(
                        "client `{}` has no credential: {no_credential}",
                        client.id
                    ));
                }
            };
            Ok(server::ClientCredentialSpec {
                client_id: client.id.clone(),
                secret,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let (cli_exit, cli_exit_iface) = (exit, exit_iface);
    if file.exit == Some(false) && cli_exit {
        zeronat::elog!("config [server].exit = false overrides --exit");
    }
    let exit = file.exit.unwrap_or(cli_exit);
    if let (Some(f), Some(c)) = (&file.exit_iface, &cli_exit_iface) {
        if f != c {
            zeronat::elog!("config [server].exit_iface '{f}' overrides --exit-iface '{c}'");
        }
    }
    let exit_iface = file.exit_iface.clone().or(cli_exit_iface);

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
                "--tun cannot be combined with --tcp/--udp or config listeners/routes".into(),
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
            return Err(errf!(
                "--except has {} distinct ports; at most 14 are allowed besides the control port",
                kept.len()
            ));
        }
    }
    if !except.is_empty() && !tun {
        return Err("--except requires --tun".into());
    }
    if exit && !tun {
        return Err("--exit requires --tun".into());
    }
    if exit_iface.is_some() && !exit {
        return Err("--exit-iface requires --exit".into());
    }
    if exit_iface.as_deref() == Some(DEFAULT_TUN_NAME) {
        return Err(errf!(
            "--exit-iface cannot be the tun device {DEFAULT_TUN_NAME}"
        ));
    }
    if tap.is_some() && !listeners.is_empty() {
        return Err("--tap cannot be combined with --tcp/--udp forwards".into());
    }
    // A server with no forwards and no device still registers clients,
    // pairs them, and splices the relays their pairs fall back to.

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
            exit,
            exit_iface: exit_iface.clone(),
        })
    } else {
        None
    };

    let dht = dht.then_some(server::DhtAnnounce {
        ip: announce_ip,
        port: announce_port,
    });
    zeronat::elog!(
        "zeronat {} server: bind={bind_ip} control={control_port} tcp-forwards={} udp-forwards={} tap={} tun={} exit={} dht={}",
        env!("CARGO_PKG_VERSION"),
        listeners.iter().filter(|l| l.proto == Proto::Tcp).count(),
        listeners.iter().filter(|l| l.proto == Proto::Udp).count(),
        onoff(tap.is_some()),
        onoff(tun.is_some()),
        onoff(exit),
        onoff(dht.is_some())
    );
    // On a self-heal the file lost its [server] table; record the resolved
    // identity so the rewritten file matches the running server and an
    // operator can later drop the CLI flags without a silent change.
    let (file_id, file_control, file_seed, file_admin_secret, file_exit, file_exit_iface) =
        if self_healed {
            (
                Some(server_id.clone()),
                Some(format!("{bind_ip}:{control_port}")),
                seed_hex,
                explicit_admin_secret,
                exit.then_some(true),
                exit_iface,
            )
        } else {
            (
                file.id,
                file.control,
                file.seed,
                file.admin_secret,
                file.exit,
                file.exit_iface,
            )
        };
    Ok(server::ServerSettings {
        bind: bind_ip,
        control_port,
        secret,
        discovery,
        client_credentials,
        admin_secret,
        server_id,
        tap,
        tun,
        dht,
        listeners,
        routes,
        config_path: config,
        file_id,
        file_control,
        file_seed,
        file_admin_secret,
        file_clients: file.clients,
        file_exit,
        file_exit_iface,
    })
}

/// Resolve the client settings from the command line and the config file.
#[inline(never)]
fn client_boot(
    mut args: Box<ClientArgs>,
) -> Result<(client::ActiveTarget, client::ClientSettings)> {
    let file = match &args.config {
        Some(path) => load_client_file(path)?,
        None => Box::default(),
    };
    // A parseable but contradictory file is an operator error to fix
    // in place, never quarantined.
    file.validate()?;

    // Scalars merge field by field; a valid file wins over the CLI and
    // a present CLI flag it overrides is logged.
    if let (Some(f), Some(c)) = (&file.id, &args.id_prefix) {
        if f != c {
            zeronat::elog!("config [client].id '{f}' overrides --id '{c}'");
        }
    }
    let id_prefix = file.id.clone().or(args.id_prefix.take());

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
        log_overrides(&args);
        boot_from_file(file, args.config, id_prefix, control)
    } else {
        boot_from_cli(args, id_prefix, control)
    }
}

#[inline(never)]
fn overridden(flag: &str, value: &str) {
    zeronat::elog!("config overrides {flag}{value}");
}

/// Log every command-line setting the file overrides, in the order the flags
/// are documented.
#[inline(never)]
fn log_overrides(a: &ClientArgs) {
    let quoted = |flag: &str, v: &str| overridden(flag, &format!(" '{v}'"));
    let bare = |flag: &str, on: bool| {
        if on {
            overridden(flag, "");
        }
    };
    if let Some(v) = &a.server {
        quoted("--server", v);
    }
    bare("--seed", a.seed.is_some());
    bare("--secret", a.secret.is_some());
    bare("--credential", a.credential.is_some());
    bare("--discovery", a.discovery.is_some());
    if let Some(v) = &a.transport {
        quoted("--transport", v);
    }
    for spec in &a.tcp {
        quoted("--tcp", spec);
    }
    for spec in &a.udp {
        quoted("--udp", spec);
    }
    bare("--proxy", a.proxy);
    if let Some(v) = &a.tap_name {
        quoted("--tap", v);
    }
    bare("--tun", a.tun);
    bare("--exit", a.exit);
    bare("--exit-strict", a.exit_strict);
    if let Some(v) = a.mtu {
        overridden("--tap-mtu", &format!(" {v}"));
    }
    if let Some(v) = &a.bridge {
        quoted("--bridge", v);
    }
    bare("--pppoe", a.pppoe);
}

/// The dial target for a `[[servers]]` entry.
fn server_target(s: &CfgServer) -> client::ServerTarget {
    client::ServerTarget {
        name: s.name.clone(),
        addr: s.addr.clone(),
        secret: s.secret.0.clone(),
        credential: s.credential.0.clone(),
        discovery: s.discovery.as_ref().map(|d| d.0.clone()),
        transport: s.transport,
    }
}

/// The settings of a client whose shape the config file declares.
#[inline(never)]
fn boot_from_file(
    file: Box<ClientConfig>,
    config: Option<std::path::PathBuf>,
    id_prefix: Option<String>,
    control: Option<zeronat::clientctl::ControlPath>,
) -> Result<(client::ActiveTarget, client::ClientSettings)> {
    let srv = active_server(&file)?;
    let (tcp, udp) = split_forwards(&file.forwards);
    let tap = file.tap.as_ref().map(|t| TapConfig {
        name: t.dev.clone(),
        mtu: DEFAULT_TAP_MTU,
        bridge: None,
    });
    let peers = client::peer_slots(file.tun.as_ref(), file.peer.as_ref())?;
    // An unpinned [tun] address is derived from the active
    // server's secret at each bringup, so a server switch moves
    // the device onto the new server's subnet. A [tun] naming a
    // peer feeds that consumer slot instead of the server slot.
    let tun = file
        .tun
        .as_ref()
        .filter(|t| !t.is_peer())
        .map(|t| client::ClientTun {
            name: t
                .dev
                .clone()
                .unwrap_or_else(|| DEFAULT_TUN_NAME.to_string()),
            mtu: DEFAULT_TAP_MTU,
            address: t.address,
            exit: t.exit,
            exit_strict: t.exit_strict,
        });
    // Every [[pppoe]] entry is resolved at boot so the admin can
    // spawn any of them; run_switchable derives the boot body
    // (forwards, else the autostart entry, else the device, else
    // idle with only the admin socket up).
    let mut pppoe = Vec::new();
    for p in &file.pppoe {
        pppoe.push(client::PppoeSession {
            name: p.name.clone(),
            config: pppoe_from_entry(p)?,
        });
    }
    let autostart = file
        .pppoe
        .iter()
        .find(|p| p.autostart)
        .map(|p| p.name.clone());
    let servers: Vec<client::ServerTarget> = file.servers.iter().map(server_target).collect();
    let target = server_target(srv);

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
    // A seeded profile's credential names `[client].id`, so that
    // id is what the client goes by.
    let id = match (&file.id, file.servers.iter().any(|s| s.seed.is_some())) {
        (Some(id), true) => ClientId::Exact(id.clone()),
        _ => ClientId::Prefix(id_prefix),
    };
    let settings = client::ClientSettings {
        servers,
        tcp,
        udp,
        tap,
        tun,
        pppoe,
        autostart,
        id,
        peer_secret: file.peer_secret.as_ref().map(|s| s.0.clone()),
        control,
        // The shape came from the file, so admin mutations
        // persist back to it.
        config: config.map(|path| (path, *file)),
        peers,
        peer_sessions: None,
    };
    Ok((client::ActiveTarget::new(target), settings))
}

/// The settings of a client whose shape the command line declares.
#[inline(never)]
fn boot_from_cli(
    mut a: Box<ClientArgs>,
    id_prefix: Option<String>,
    control: Option<zeronat::clientctl::ControlPath>,
) -> Result<(client::ActiveTarget, client::ClientSettings)> {
    use zeronat::pppoe::cli;
    let server = a.server.take().ok_or("--server is required")?;
    // An explicit value always wins; the seed fills what is left.
    let seed = seed_from(a.seed.take())?;
    let secret = match a
        .secret
        .take()
        .or_else(|| std::env::var("ZERONAT_SECRET").ok())
    {
        Some(secret) => runtime_secret(secret)?,
        None => seed
            .as_ref()
            .map(Seed::network)
            .ok_or("--secret, ZERONAT_SECRET, or a seed (--seed or ZERONAT_SEED) is required")?,
    };
    let (credential, id) = match (
        a.credential
            .take()
            .or_else(|| std::env::var("ZERONAT_CLIENT_SECRET").ok()),
        &seed,
    ) {
        (Some(credential), _) => (runtime_secret(credential)?, ClientId::Prefix(id_prefix)),
        (None, Some(seed)) => {
            let id = id_prefix.ok_or(
                "--id is required with a seed: the credential is derived for it, and the server lists the same id under --client",
            )?;
            (seed.client(&id), ClientId::Exact(id))
        }
        (None, None) => (secret.clone(), ClientId::Prefix(id_prefix)),
    };
    let discovery = a
        .discovery
        .take()
        .or_else(|| std::env::var("ZERONAT_DISCOVERY_SECRET").ok())
        .or_else(|| seed.as_ref().map(Seed::discovery));
    let discovery = match (server == "dht", discovery) {
        (true, None) => {
            return Err(
                "--server dht requires --discovery, ZERONAT_DISCOVERY_SECRET, or a seed".into(),
            );
        }
        (_, Some(value)) => Some(runtime_secret(value)?),
        (false, None) => None,
    };
    if discovery.as_deref() == Some(secret.as_str())
        || discovery.as_deref() == Some(credential.as_str())
    {
        return Err("--discovery must differ from --secret and --credential".into());
    }
    if a.tun && a.bridge.is_some() {
        return Err("--bridge applies to --tap only, not --tun".into());
    }
    let mtu = a.mtu.unwrap_or(DEFAULT_TAP_MTU);
    let tap = build_tap(a.tap_name.take(), mtu, a.bridge.take());
    let forwards = !a.tcp.is_empty() || !a.udp.is_empty();
    // --pppoe owns the L2 channel; reject the device/forward flags it
    // conflicts with. --transport is orthogonal and stays valid.
    cli::validate_pppoe_exclusions(a.pppoe, tap.is_some(), a.tun, forwards)?;
    cli::validate_pppoe_netcfg(
        a.pppoe,
        a.pppoe_default_route,
        a.pppoe_no_mss_clamp,
        a.pppoe_dns,
    )?;
    if a.tun {
        if tap.is_some() {
            return Err("--tun cannot be combined with --tap".into());
        }
        if forwards {
            return Err("--tun cannot be combined with --tcp/--udp forwards".into());
        }
    }
    if a.exit && !a.tun {
        return Err("--exit requires --tun".into());
    }
    if a.exit_strict && !a.exit {
        return Err("--exit-strict requires --exit".into());
    }
    if tap.is_some() && forwards {
        return Err("--tap cannot be combined with --tcp/--udp forwards".into());
    }
    if !a.pppoe && !a.tun && tap.is_none() && !forwards {
        return Err(
            "nothing to do: pass --pppoe, --tun, --tap, or at least one --tcp/--udp".into(),
        );
    }
    if a.proxy && a.tcp.is_empty() {
        return Err("--proxy requires at least one --tcp forward".into());
    }

    // Resolve the PPPoE config: credentials (file > env > flag) and the
    // effective MTU (capped to the tunnel MTU minus 8, floored). The
    // password file is read here so the precedence helper stays pure.
    let pppoe = if a.pppoe {
        let user = cli::resolve_username(
            a.pppoe_user.take(),
            std::env::var("ZERONAT_PPPOE_USER").ok(),
        )?;
        let pass_file = match &a.pppoe_pass_file {
            Some(path) => Some(std::fs::read(path).map_err(|e| -> zeronat::Error {
                errf!("reading --pppoe-pass-file {}: {e}", path.display())
            })?),
            None => None,
        };
        let pass = cli::resolve_password(
            pass_file,
            std::env::var("ZERONAT_PPPOE_PASS").ok(),
            a.pppoe_pass.take(),
        )?;
        let pppoe_mtu = a.pppoe_mtu;
        let pppoe_mtu_u16: u16 = pppoe_mtu.try_into().map_err(|_| -> zeronat::Error {
            errf!("--pppoe-mtu {pppoe_mtu} exceeds the 65535 MTU limit")
        })?;
        let tap_mtu_u16: u16 = mtu.try_into().map_err(|_| -> zeronat::Error {
            errf!("--tap-mtu {mtu} exceeds the 65535 MTU limit")
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
            service_name: a
                .pppoe_service
                .take()
                .map(String::into_bytes)
                .unwrap_or_default(),
            ac_name: a.pppoe_ac.take().map(String::into_bytes),
            tun_name: std::mem::take(&mut a.pppoe_tun),
            effective_mtu: resolved.effective,
            default_route: a.pppoe_default_route,
            // The MSS clamp rides with --pppoe-default-route unless opted out;
            // value is the effective IP MTU minus the IPv4+TCP headers.
            clamp_mss: if a.pppoe_default_route && !a.pppoe_no_mss_clamp {
                Some(resolved.effective.saturating_sub(40).max(536))
            } else {
                None
            },
            request_dns: a.pppoe_dns,
        })
    } else {
        None
    };
    let tun = a.tun.then(|| client::ClientTun {
        name: DEFAULT_TUN_NAME.to_string(),
        mtu,
        address: None,
        exit: a.exit,
        exit_strict: a.exit_strict,
    });
    let mut tcp = Vec::new();
    for s in &a.tcp {
        let mut f = parse_forward(s, Proto::Tcp)?;
        f.proxy |= a.proxy;
        tcp.push(f);
    }
    let mut udp = Vec::new();
    for s in &a.udp {
        udp.push(parse_forward(s, Proto::Udp)?);
    }
    let transport = parse_transport(a.transport.as_deref())?;
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
    Ok(client::direct(
        server, secret, credential, discovery, tcp, udp, transport, tap, tun, pppoe, id, control,
    ))
}

async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Server(args) => server::run(server_boot(*args)?).await,
        Cmd::Client(args) => {
            let (active, settings) = client_boot(args)?;
            client::run_switchable(active, settings).await
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
            let req = match command {
                None | Some(ClientAdminCmd::Show) => return client_admin::show(socket).await,
                Some(ClientAdminCmd::SelectServer(name)) => ClientMsg::SelectServer { name },
                Some(ClientAdminCmd::AddServer {
                    name,
                    addr,
                    transport,
                }) => client_admin::add_server(name, addr, transport)?,
                Some(ClientAdminCmd::RemoveServer(name)) => ClientMsg::RemoveServer { name },
                Some(ClientAdminCmd::EnableForward(spec)) => {
                    return client_admin::set_forward_enabled(socket, &spec, true).await
                }
                Some(ClientAdminCmd::DisableForward(spec)) => {
                    return client_admin::set_forward_enabled(socket, &spec, false).await
                }
                Some(ClientAdminCmd::AddForward(spec)) => {
                    let (proto, fwd) = parse_proto_forward(&spec)?;
                    client_admin::add_forward(proto, fwd)
                }
                Some(ClientAdminCmd::RemoveForward(spec)) => client_admin::remove_forward(&spec)?,
                Some(ClientAdminCmd::Connect(name)) => {
                    return client_admin::connect(socket, name).await
                }
                Some(ClientAdminCmd::Disconnect) => ClientMsg::Disconnect,
                Some(ClientAdminCmd::SpawnPppoe(name)) => ClientMsg::SpawnPppoe { name },
                Some(ClientAdminCmd::StopPppoe(name)) => ClientMsg::StopSession { name },
                Some(ClientAdminCmd::AttachPeer {
                    peer,
                    dev,
                    exit,
                    exit_strict,
                }) => client_admin::attach_peer(peer, dev, exit, exit_strict)?,
                Some(ClientAdminCmd::AttachProvider { capability, iface }) => {
                    client_admin::attach_provider(&capability, iface)?
                }
                Some(ClientAdminCmd::DetachPeer(peer)) => client_admin::detach_peer(peer)?,
                Some(ClientAdminCmd::DetachProvider(capability)) => {
                    client_admin::detach_provider(&capability)?
                }
            };
            client_admin::command(socket, req).await
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
        Cmd::DeriveClient {
            secret,
            credential,
            discovery,
        } => {
            println!("ZERONAT_SECRET={secret}");
            println!("ZERONAT_CLIENT_SECRET={credential}");
            if let Some(discovery) = discovery {
                println!("ZERONAT_DISCOVERY_SECRET={discovery}");
            }
            Ok(())
        }
        Cmd::Upgrade { check } => zeronat::upgrade::run(check),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use zeronat::client::Forward;

    #[test]
    fn runtime_secret_accepts_only_32_byte_hex() {
        assert_eq!(runtime_secret("A".repeat(64)).unwrap(), "a".repeat(64));
        for invalid in ["short".to_string(), "a".repeat(63), "g".repeat(64)] {
            assert!(runtime_secret(invalid).is_err());
        }
    }

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

    #[test]
    fn proto_forward_specs_reuse_the_forward_grammar() {
        let (proto, f) = parse_proto_forward("tcp:443:10.0.0.5:8443+proxy+idle=600").unwrap();
        assert_eq!(proto, Proto::Tcp);
        assert_eq!(f, fwd(443, "10.0.0.5:8443", true, Some(600)));
        // The bare form resolves the default target, as the flags do.
        let (proto, f) = parse_proto_forward("udp:53").unwrap();
        assert_eq!(proto, Proto::Udp);
        assert_eq!(f, fwd(53, "127.0.0.1:53", false, None));
        for bad in ["443", "icmp:1", "udp:53+proxy", "tcp:a:b:c:d", "tcp:"] {
            assert!(parse_proto_forward(bad).is_err(), "{bad} should not parse");
        }
    }

    fn cfg_server(name: &str) -> CfgServer {
        CfgServer {
            name: name.into(),
            addr: format!("{name}.example:2222"),
            seed: None,
            secret: zeronat::clientproto::ServerSecret("s".into()),
            credential: zeronat::clientproto::ServerSecret("s".into()),
            discovery: None,
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
                    exit: false,
                    exit_strict: false,
                    exit_via: None,
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
