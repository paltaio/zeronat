//! Strict TOML-subset grammar for the client config file.
//!
//! A `[client]` singleton plus `[[servers]]`/`[[forwards]]`/`[[pppoe]]`
//! arrays-of-tables and an optional `[tap]` or `[tun]` device table, built on
//! the value-agnostic lexer in [`crate::config::codec`]. `parse_client`
//! enforces the grammar and per-entry rules; cross-entry rules live in
//! [`ClientConfig::validate`] so that a parseable but contradictory file is a
//! fatal boot error the operator can fix in place, never quarantined.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use crate::client::Transport;
use crate::clientproto::ServerSecret;
use crate::config::codec::{
    err, parse_bool, parse_int, parse_string, parse_u32, quote, reject_dup, split_kv, strip_comment,
};
use crate::config::parse_proto;
use crate::config::LoadError;
use crate::proto::{proto_name, Proto};
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgServer {
    /// Unique profile name; the select-server key.
    pub name: String,
    /// `"dht"` or `host:port`.
    pub addr: String,
    pub secret: ServerSecret,
    pub transport: Transport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgForward {
    pub proto: Proto,
    pub port: u16,
    pub target: String,
    /// Prefix each local connection with a PROXY protocol v2 header (TCP only).
    pub proxy: bool,
    /// Relay idle window override in whole seconds, minimum 1.
    pub idle: Option<u32>,
    /// Whether the forward is served; a disabled entry keeps its
    /// configuration.
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgPppoe {
    /// Unique session name; the spawn/stop key.
    pub name: String,
    /// Bring this session up at boot when no `[[forwards]]` are declared.
    pub autostart: bool,
    pub username: String,
    pub password: Option<String>,
    /// Path to a file holding the password; takes precedence over `password`.
    pub password_file: Option<String>,
    /// PPPoE Service-Name selector (empty = any).
    pub service: String,
    pub mtu: u16,
    pub default_route: bool,
    /// MSS clamp that rides with `default_route`.
    pub clamp_mss: bool,
    pub request_dns: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgTap {
    pub dev: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgTun {
    pub dev: Option<String>,
    /// This node's tunnel address as `(ip, prefix_len)`; derived from the
    /// active server's secret when unset.
    pub address: Option<(Ipv4Addr, u8)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientConfig {
    pub id: Option<String>,
    /// Which `[[servers]]` entry to dial at boot; the first entry when unset.
    pub active: Option<String>,
    /// Admin socket path override.
    pub control: Option<String>,
    pub servers: Vec<CfgServer>,
    pub forwards: Vec<CfgForward>,
    pub pppoe: Vec<CfgPppoe>,
    pub tap: Option<CfgTap>,
    pub tun: Option<CfgTun>,
}

impl ClientConfig {
    /// Cross-entry rules over a successfully parsed config: the active
    /// reference, name and forward-key uniqueness, the single-autostart rule,
    /// and device exclusivity. A violation here is a fatal boot error, kept
    /// out of `parse_client` so the file is never quarantined for it.
    pub fn validate(&self) -> Result<()> {
        let mut names: HashSet<&str> = HashSet::new();
        for s in &self.servers {
            if !names.insert(&s.name) {
                return Err(format!("duplicate server name `{}`", s.name).into());
            }
        }
        if let Some(active) = &self.active {
            if !self.servers.iter().any(|s| &s.name == active) {
                return Err(
                    format!("active = {} names no [[servers]] entry", quote(active)).into(),
                );
            }
        }
        let mut fwd: HashSet<(Proto, u16)> = HashSet::new();
        for f in &self.forwards {
            if !fwd.insert((f.proto, f.port)) {
                return Err(format!("duplicate forward {} {}", proto_name(f.proto), f.port).into());
            }
        }
        let mut sessions: HashSet<&str> = HashSet::new();
        for p in &self.pppoe {
            if !sessions.insert(&p.name) {
                return Err(format!("duplicate pppoe name `{}`", p.name).into());
            }
        }
        if self.pppoe.iter().filter(|p| p.autostart).count() > 1 {
            return Err("more than one [[pppoe]] entry sets autostart = true".into());
        }
        if self.tap.is_some() && self.tun.is_some() {
            return Err("[tap] and [tun] are mutually exclusive".into());
        }
        if (self.tap.is_some() || self.tun.is_some())
            && (!self.forwards.is_empty() || !self.pppoe.is_empty())
        {
            return Err("[tap]/[tun] cannot be combined with [[forwards]] or [[pppoe]]".into());
        }
        Ok(())
    }
}

/// Which table the parser is currently filling.
enum Section {
    None,
    Client,
    Server,
    Forward,
    Pppoe,
    Tap,
    Tun,
}

/// One in-progress record; a superset of the fields of every table. Fields are
/// filled as keys are seen and validated for completeness when the record
/// closes.
#[derive(Default)]
struct PartialRecord {
    name: Option<String>,
    addr: Option<String>,
    secret: Option<String>,
    transport: Option<Transport>,
    proto: Option<Proto>,
    port: Option<u16>,
    target: Option<String>,
    proxy: Option<bool>,
    idle: Option<u32>,
    enabled: Option<bool>,
    autostart: Option<bool>,
    username: Option<String>,
    password: Option<String>,
    password_file: Option<String>,
    service: Option<String>,
    mtu: Option<u16>,
    default_route: Option<bool>,
    clamp_mss: Option<bool>,
    request_dns: Option<bool>,
    dev: Option<String>,
    address: Option<(Ipv4Addr, u8)>,
}

/// Load a client config. A missing file yields the default (empty) config so a
/// first boot with `--config` pointing at a not-yet-written path is not an
/// error.
pub fn load(path: &Path) -> std::result::Result<ClientConfig, LoadError> {
    crate::config::codec::load(path, parse_client)
}

pub fn parse_client(text: &str) -> Result<ClientConfig> {
    let mut cfg = ClientConfig::default();
    let mut section = Section::None;
    let mut seen_client = false;
    let mut seen_tap = false;
    let mut seen_tun = false;
    let mut client_keys: Vec<&str> = Vec::new();
    let mut record = PartialRecord::default();
    let mut record_keys: Vec<&str> = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let n = lineno + 1;

        if let Some(header) = line.strip_prefix('[') {
            // A table header closes the previous record.
            close_record(&section, &mut cfg, &mut record, n)?;
            record = PartialRecord::default();
            record_keys.clear();

            let header = header
                .strip_suffix(']')
                .ok_or_else(|| err(n, "unterminated table header"))?;
            match header {
                "client" => {
                    if seen_client {
                        return Err(err(n, "duplicate [client] table"));
                    }
                    seen_client = true;
                    client_keys.clear();
                    section = Section::Client;
                }
                "[servers]" => section = Section::Server,
                "[forwards]" => section = Section::Forward,
                "[pppoe]" => section = Section::Pppoe,
                "tap" => {
                    if seen_tap {
                        return Err(err(n, "duplicate [tap] table"));
                    }
                    seen_tap = true;
                    section = Section::Tap;
                }
                "tun" => {
                    if seen_tun {
                        return Err(err(n, "duplicate [tun] table"));
                    }
                    seen_tun = true;
                    section = Section::Tun;
                }
                other => {
                    return Err(err(n, &format!("unknown table header [{other}]")));
                }
            }
            continue;
        }

        let (key, value) = split_kv(line).ok_or_else(|| err(n, "expected key = value"))?;
        if key.is_empty() || key.contains(|c: char| c.is_whitespace()) {
            return Err(err(n, "invalid key"));
        }

        match section {
            Section::None => {
                return Err(err(n, &format!("key `{key}` before any table header")));
            }
            Section::Client => {
                reject_dup(&mut client_keys, key, n)?;
                match key {
                    "id" => cfg.id = Some(parse_string(value, n)?),
                    "active" => cfg.active = Some(parse_string(value, n)?),
                    "control" => cfg.control = Some(parse_string(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [client]")));
                    }
                }
            }
            Section::Server => {
                reject_dup(&mut record_keys, key, n)?;
                match key {
                    "name" => record.name = Some(parse_string(value, n)?),
                    "addr" => record.addr = Some(parse_string(value, n)?),
                    "secret" => record.secret = Some(parse_string(value, n)?),
                    "transport" => record.transport = Some(parse_transport(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [[servers]]")));
                    }
                }
            }
            Section::Forward => {
                reject_dup(&mut record_keys, key, n)?;
                match key {
                    "proto" => record.proto = Some(parse_proto(value, n)?),
                    "port" => record.port = Some(parse_int(value, n)?),
                    "target" => record.target = Some(parse_string(value, n)?),
                    "proxy" => record.proxy = Some(parse_bool(value, n)?),
                    "idle" => {
                        let secs = parse_u32(value, n)?;
                        if secs == 0 {
                            return Err(err(n, "`idle` must be at least 1 second"));
                        }
                        record.idle = Some(secs);
                    }
                    "enabled" => record.enabled = Some(parse_bool(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [[forwards]]")));
                    }
                }
            }
            Section::Pppoe => {
                reject_dup(&mut record_keys, key, n)?;
                match key {
                    "name" => record.name = Some(parse_string(value, n)?),
                    "autostart" => record.autostart = Some(parse_bool(value, n)?),
                    "username" => record.username = Some(parse_string(value, n)?),
                    "password" => record.password = Some(parse_string(value, n)?),
                    "password_file" => record.password_file = Some(parse_string(value, n)?),
                    "service" => record.service = Some(parse_string(value, n)?),
                    "mtu" => record.mtu = Some(parse_int(value, n)?),
                    "default_route" => record.default_route = Some(parse_bool(value, n)?),
                    "clamp_mss" => record.clamp_mss = Some(parse_bool(value, n)?),
                    "request_dns" => record.request_dns = Some(parse_bool(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [[pppoe]]")));
                    }
                }
            }
            Section::Tap => {
                reject_dup(&mut record_keys, key, n)?;
                match key {
                    "dev" => record.dev = Some(parse_string(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [tap]")));
                    }
                }
            }
            Section::Tun => {
                reject_dup(&mut record_keys, key, n)?;
                match key {
                    "dev" => record.dev = Some(parse_string(value, n)?),
                    "address" => record.address = Some(parse_cidr(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [tun]")));
                    }
                }
            }
        }
    }

    // Close the final open record at EOF.
    let last = text.lines().count();
    close_record(&section, &mut cfg, &mut record, last)?;
    Ok(cfg)
}

/// Validate and commit the in-progress record, if any. Required keys and
/// combinations that depend on more than one key of the same entry (`proxy`
/// against `proto`, `clamp_mss` against `default_route`) are checked here,
/// where the whole entry is known.
fn close_record(
    section: &Section,
    cfg: &mut ClientConfig,
    record: &mut PartialRecord,
    n: usize,
) -> Result<()> {
    match section {
        Section::Server => {
            let name = record
                .name
                .take()
                .ok_or_else(|| err(n, "server missing `name`"))?;
            if name.is_empty() {
                return Err(err(n, "server `name` must not be empty"));
            }
            let addr = record
                .addr
                .take()
                .ok_or_else(|| err(n, "server missing `addr`"))?;
            let secret = record
                .secret
                .take()
                .ok_or_else(|| err(n, "server missing `secret`"))?;
            cfg.servers.push(CfgServer {
                name,
                addr,
                secret: ServerSecret(secret),
                transport: record.transport.take().unwrap_or(Transport::Auto),
            });
        }
        Section::Forward => {
            let proto = record
                .proto
                .ok_or_else(|| err(n, "forward missing `proto`"))?;
            let port = record
                .port
                .ok_or_else(|| err(n, "forward missing `port`"))?;
            if record.proxy.is_some() && proto == Proto::Udp {
                return Err(err(n, "`proxy` is not supported on udp forwards"));
            }
            cfg.forwards.push(CfgForward {
                proto,
                port,
                target: record
                    .target
                    .take()
                    .unwrap_or_else(|| format!("127.0.0.1:{port}")),
                proxy: record.proxy.take().unwrap_or(false),
                idle: record.idle.take(),
                enabled: record.enabled.take().unwrap_or(true),
            });
        }
        Section::Pppoe => {
            let name = record
                .name
                .take()
                .ok_or_else(|| err(n, "pppoe missing `name`"))?;
            if name.is_empty() {
                return Err(err(n, "pppoe `name` must not be empty"));
            }
            let username = record
                .username
                .take()
                .ok_or_else(|| err(n, "pppoe missing `username`"))?;
            let default_route = record.default_route.take().unwrap_or(false);
            if record.clamp_mss == Some(false) && !default_route {
                return Err(err(
                    n,
                    "`clamp_mss = false` requires `default_route = true`",
                ));
            }
            cfg.pppoe.push(CfgPppoe {
                name,
                autostart: record.autostart.take().unwrap_or(false),
                username,
                password: record.password.take(),
                password_file: record.password_file.take(),
                service: record.service.take().unwrap_or_default(),
                mtu: record.mtu.take().unwrap_or(1492),
                default_route,
                clamp_mss: record.clamp_mss.take().unwrap_or(true),
                request_dns: record.request_dns.take().unwrap_or(false),
            });
        }
        Section::Tap => {
            let dev = record
                .dev
                .take()
                .ok_or_else(|| err(n, "tap missing `dev`"))?;
            if dev.is_empty() {
                return Err(err(n, "tap `dev` must not be empty"));
            }
            cfg.tap = Some(CfgTap { dev });
        }
        Section::Tun => {
            cfg.tun = Some(CfgTun {
                dev: record.dev.take(),
                address: record.address.take(),
            });
        }
        Section::None | Section::Client => {}
    }
    Ok(())
}

fn parse_transport(value: &str, n: usize) -> Result<Transport> {
    let s = parse_string(value, n)?;
    match s.as_str() {
        "auto" => Ok(Transport::Auto),
        "udp" => Ok(Transport::Udp),
        "tcp" => Ok(Transport::Tcp),
        other => Err(err(n, &format!("unknown transport `{other}`"))),
    }
}

fn parse_cidr(value: &str, n: usize) -> Result<(Ipv4Addr, u8)> {
    let s = parse_string(value, n)?;
    let invalid = || err(n, &format!("invalid address `{s}` (expected A.B.C.D/N)"));
    let (ip, len) = s.split_once('/').ok_or_else(invalid)?;
    let ip = Ipv4Addr::from_str(ip).map_err(|_| invalid())?;
    let len: u8 = len.parse().map_err(|_| invalid())?;
    if len > 32 {
        return Err(invalid());
    }
    Ok((ip, len))
}

fn transport_str(t: Transport) -> &'static str {
    match t {
        Transport::Auto => "auto",
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    }
}

/// Emit a deterministic, comment-free rendering of `cfg`. Entries keep their
/// declaration order (the first `[[servers]]` entry is the boot default when
/// `active` is unset) and default-valued keys are omitted.
pub fn serialize_client(cfg: &ClientConfig) -> String {
    let mut out = String::new();

    if cfg.id.is_some() || cfg.active.is_some() || cfg.control.is_some() {
        out.push_str("[client]\n");
        if let Some(id) = &cfg.id {
            out.push_str(&format!("id = {}\n", quote(id)));
        }
        if let Some(active) = &cfg.active {
            out.push_str(&format!("active = {}\n", quote(active)));
        }
        if let Some(control) = &cfg.control {
            out.push_str(&format!("control = {}\n", quote(control)));
        }
    }

    let table = |out: &mut String, header: &str| {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(header);
        out.push('\n');
    };

    for s in &cfg.servers {
        table(&mut out, "[[servers]]");
        out.push_str(&format!("name = {}\n", quote(&s.name)));
        out.push_str(&format!("addr = {}\n", quote(&s.addr)));
        out.push_str(&format!("secret = {}\n", quote(&s.secret.0)));
        if s.transport != Transport::Auto {
            out.push_str(&format!(
                "transport = {}\n",
                quote(transport_str(s.transport))
            ));
        }
    }

    for f in &cfg.forwards {
        table(&mut out, "[[forwards]]");
        out.push_str(&format!("proto = {}\n", quote(proto_name(f.proto))));
        out.push_str(&format!("port = {}\n", f.port));
        out.push_str(&format!("target = {}\n", quote(&f.target)));
        if !f.enabled {
            out.push_str("enabled = false\n");
        }
        if f.proxy {
            out.push_str("proxy = true\n");
        }
        if let Some(secs) = f.idle {
            out.push_str(&format!("idle = {secs}\n"));
        }
    }

    for p in &cfg.pppoe {
        table(&mut out, "[[pppoe]]");
        out.push_str(&format!("name = {}\n", quote(&p.name)));
        if p.autostart {
            out.push_str("autostart = true\n");
        }
        out.push_str(&format!("username = {}\n", quote(&p.username)));
        if let Some(password) = &p.password {
            out.push_str(&format!("password = {}\n", quote(password)));
        }
        if let Some(path) = &p.password_file {
            out.push_str(&format!("password_file = {}\n", quote(path)));
        }
        if !p.service.is_empty() {
            out.push_str(&format!("service = {}\n", quote(&p.service)));
        }
        if p.mtu != 1492 {
            out.push_str(&format!("mtu = {}\n", p.mtu));
        }
        if p.default_route {
            out.push_str("default_route = true\n");
        }
        if !p.clamp_mss {
            out.push_str("clamp_mss = false\n");
        }
        if p.request_dns {
            out.push_str("request_dns = true\n");
        }
    }

    if let Some(tap) = &cfg.tap {
        table(&mut out, "[tap]");
        out.push_str(&format!("dev = {}\n", quote(&tap.dev)));
    }

    if let Some(tun) = &cfg.tun {
        table(&mut out, "[tun]");
        if let Some(dev) = &tun.dev {
            out.push_str(&format!("dev = {}\n", quote(dev)));
        }
        if let Some((ip, len)) = tun.address {
            out.push_str(&format!("address = {}\n", quote(&format!("{ip}/{len}"))));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientConfig {
        ClientConfig {
            id: Some("rpi-2".into()),
            active: Some("home".into()),
            control: Some("/run/zeronat/client.sock".into()),
            servers: vec![
                CfgServer {
                    name: "home".into(),
                    addr: "dht".into(),
                    secret: ServerSecret("hunter2".into()),
                    transport: Transport::Auto,
                },
                CfgServer {
                    name: "oci".into(),
                    addr: "203.0.113.10:2222".into(),
                    secret: ServerSecret("hunter3".into()),
                    transport: Transport::Tcp,
                },
            ],
            forwards: vec![
                CfgForward {
                    proto: Proto::Tcp,
                    port: 8080,
                    target: "127.0.0.1:80".into(),
                    proxy: true,
                    idle: Some(600),
                    enabled: true,
                },
                CfgForward {
                    proto: Proto::Udp,
                    port: 51820,
                    target: "10.0.0.5:51820".into(),
                    proxy: false,
                    idle: None,
                    enabled: false,
                },
            ],
            pppoe: vec![CfgPppoe {
                name: "wan".into(),
                autostart: true,
                username: "user@isp".into(),
                password: None,
                password_file: Some("/etc/zeronat/wan.pass".into()),
                service: "fibra".into(),
                mtu: 1480,
                default_route: true,
                clamp_mss: false,
                request_dns: true,
            }],
            tap: None,
            tun: None,
        }
    }

    #[test]
    fn roundtrip() {
        let cfg = sample();
        cfg.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&cfg)).unwrap(), cfg);
    }

    // Assertion failures and logged errors debug-print whole configs, so a
    // debug-printed config must not carry any server secret.
    #[test]
    fn cfg_debug_redacts_the_server_secret() {
        let s = format!("{:?}", sample());
        assert!(!s.contains("hunter2"), "{s}");
        assert!(!s.contains("hunter3"), "{s}");
        assert!(s.contains("home"));
    }

    #[test]
    fn roundtrip_devices() {
        let tap = ClientConfig {
            servers: vec![CfgServer {
                name: "home".into(),
                addr: "dht".into(),
                secret: ServerSecret("s".into()),
                transport: Transport::Auto,
            }],
            tap: Some(CfgTap {
                dev: "ztap0".into(),
            }),
            ..ClientConfig::default()
        };
        tap.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&tap)).unwrap(), tap);

        let tun = ClientConfig {
            tun: Some(CfgTun {
                dev: Some("zn0".into()),
                address: Some((Ipv4Addr::new(10, 0, 0, 2), 24)),
            }),
            ..ClientConfig::default()
        };
        tun.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&tun)).unwrap(), tun);

        let bare_tun = ClientConfig {
            tun: Some(CfgTun {
                dev: None,
                address: None,
            }),
            ..ClientConfig::default()
        };
        assert_eq!(parse_client("[tun]\n").unwrap(), bare_tun);
        assert_eq!(
            parse_client(&serialize_client(&bare_tun)).unwrap(),
            bare_tun
        );
    }

    #[test]
    fn entry_defaults() {
        let cfg = parse_client(
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = 8080\n\
             [[pppoe]]\nname = \"wan\"\nusername = \"u\"\n",
        )
        .unwrap();
        assert_eq!(cfg.servers[0].transport, Transport::Auto);
        let f = &cfg.forwards[0];
        assert_eq!(f.target, "127.0.0.1:8080");
        assert!(!f.proxy);
        assert_eq!(f.idle, None);
        assert!(f.enabled);
        let p = &cfg.pppoe[0];
        assert!(!p.autostart);
        assert_eq!(p.password, None);
        assert_eq!(p.password_file, None);
        assert_eq!(p.service, "");
        assert_eq!(p.mtu, 1492);
        assert!(!p.default_route);
        assert!(p.clamp_mss);
        assert!(!p.request_dns);
        cfg.validate().unwrap();
    }

    #[test]
    fn serialize_omits_defaults() {
        let cfg = parse_client(
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = 8080\n\
             [[pppoe]]\nname = \"wan\"\nusername = \"u\"\n",
        )
        .unwrap();
        let out = serialize_client(&cfg);
        for key in [
            "transport",
            "proxy",
            "idle",
            "enabled",
            "autostart",
            "service",
            "mtu",
        ] {
            assert!(
                !out.contains(key),
                "default `{key}` must be omitted:\n{out}"
            );
        }
    }

    #[test]
    fn idle_wider_than_port_range() {
        let cfg =
            parse_client("[[forwards]]\nproto = \"tcp\"\nport = 443\nidle = 100000\n").unwrap();
        assert_eq!(cfg.forwards[0].idle, Some(100_000));
    }

    #[test]
    fn rejects_malformed() {
        let cases = [
            // Unknown tables and keys.
            "[bogus]\n",
            "[client]\nfoo = 1\n",
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\nfoo = 1\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nfoo = 1\n",
            "[[pppoe]]\nname = \"w\"\nusername = \"u\"\nfoo = 1\n",
            "[tap]\ndev = \"t0\"\nfoo = 1\n",
            "[tun]\nfoo = 1\n",
            "id = \"x\"\n",
            // Missing required keys.
            "[[servers]]\naddr = \"dht\"\nsecret = \"s\"\n",
            "[[servers]]\nname = \"a\"\nsecret = \"s\"\n",
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\n",
            "[[forwards]]\nport = 1\n",
            "[[forwards]]\nproto = \"tcp\"\n",
            "[[pppoe]]\nusername = \"u\"\n",
            "[[pppoe]]\nname = \"w\"\n",
            "[tap]\n",
            // Empty names and devices.
            "[[servers]]\nname = \"\"\naddr = \"dht\"\nsecret = \"s\"\n",
            "[[pppoe]]\nname = \"\"\nusername = \"u\"\n",
            "[tap]\ndev = \"\"\n",
            // Type and value errors.
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\ntransport = \"quic\"\n",
            "[[forwards]]\nproto = \"tap\"\nport = 1\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 99999\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nidle = 0\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nidle = \"x\"\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nproxy = 1\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nenabled = 1\n",
            "[tun]\naddress = \"10.0.0.2\"\n",
            "[tun]\naddress = \"bogus/24\"\n",
            "[tun]\naddress = \"10.0.0.2/33\"\n",
            // `proxy` belongs to tcp entries only, whatever its value and
            // whatever `enabled` says.
            "[[forwards]]\nproto = \"udp\"\nport = 1\nproxy = true\n",
            "[[forwards]]\nproto = \"udp\"\nport = 1\nproxy = false\n",
            "[[forwards]]\nproto = \"udp\"\nport = 1\nenabled = false\nproxy = true\n",
            // `clamp_mss = false` without the default-route swap it rides with.
            "[[pppoe]]\nname = \"w\"\nusername = \"u\"\nclamp_mss = false\n",
            // Duplicate keys and singleton tables.
            "[client]\nid = \"a\"\nid = \"b\"\n",
            "[client]\nid = \"a\"\n[client]\ncontrol = \"c\"\n",
            "[tap]\ndev = \"t0\"\n[tap]\ndev = \"t1\"\n",
            "[tun]\n[tun]\n",
            "[[servers]]\nname = \"a\"\nname = \"b\"\naddr = \"dht\"\nsecret = \"s\"\n",
        ];
        for case in cases {
            assert!(parse_client(case).is_err(), "expected Err for:\n{case}");
        }
    }

    #[test]
    fn semantic_errors_parse_but_fail_validate() {
        let cases = [
            // active names no [[servers]] entry.
            "[client]\nactive = \"gone\"\n[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\n",
            // Duplicate server names.
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\n\
             [[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"t\"\n",
            // Duplicate (proto, port) forwards.
            "[[forwards]]\nproto = \"tcp\"\nport = 443\n[[forwards]]\nproto = \"tcp\"\nport = 443\n",
            // More than one autostart.
            "[[pppoe]]\nname = \"a\"\nusername = \"u\"\nautostart = true\n\
             [[pppoe]]\nname = \"b\"\nusername = \"u\"\nautostart = true\n",
            // Duplicate pppoe names.
            "[[pppoe]]\nname = \"a\"\nusername = \"u\"\n[[pppoe]]\nname = \"a\"\nusername = \"v\"\n",
            // Device exclusivity.
            "[tap]\ndev = \"t0\"\n[tun]\n",
            "[tap]\ndev = \"t0\"\n[[forwards]]\nproto = \"tcp\"\nport = 443\n",
            "[tun]\n[[pppoe]]\nname = \"w\"\nusername = \"u\"\n",
        ];
        for case in cases {
            let cfg = parse_client(case).unwrap_or_else(|e| {
                panic!("expected a clean parse (semantic error only) for:\n{case}\ngot: {e}")
            });
            assert!(
                cfg.validate().is_err(),
                "expected validate Err for:\n{case}"
            );
        }
    }

    #[test]
    fn tcp_and_udp_may_share_a_port() {
        let cfg = parse_client(
            "[[forwards]]\nproto = \"tcp\"\nport = 443\n[[forwards]]\nproto = \"udp\"\nport = 443\n",
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.forwards.len(), 2);
    }

    #[test]
    fn empty_input() {
        let cfg = parse_client("").unwrap();
        assert_eq!(cfg, ClientConfig::default());
        cfg.validate().unwrap();
    }

    #[test]
    fn load_missing_file_is_default() {
        let path =
            std::env::temp_dir().join(format!("zeronat-client-absent-{}.toml", std::process::id()));
        assert_eq!(load(&path).unwrap(), ClientConfig::default());
    }

    #[test]
    fn load_reports_malformed() {
        let dir = std::env::temp_dir().join(format!("zeronat-client-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        std::fs::write(&path, "[client\nid = ").unwrap();
        assert!(matches!(load(&path), Err(LoadError::Malformed(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
