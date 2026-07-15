//! Strict TOML-subset grammar for the server config file.
//!
//! The grammar is intentionally tiny: a `[server]` singleton plus
//! `[[listeners]]`/`[[routes]]` arrays-of-tables, with only double-quoted
//! strings and bare integers as scalars. The value-agnostic lexer and the
//! crash-safe file handling live in [`codec`].

pub(crate) mod codec;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use codec::{err, parse_int, parse_string, quote, reject_dup, split_kv, strip_comment};
pub use codec::{quarantine, save_atomic, LoadError};

use crate::proto::Proto;
use crate::Result;

#[derive(Debug, Clone, PartialEq)]
pub struct CfgListener {
    pub bind_ip: Ipv4Addr,
    pub proto: Proto,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CfgRoute {
    pub bind_ip: Ipv4Addr,
    pub proto: Proto,
    pub port: u16,
    pub client: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServerConfig {
    pub id: Option<String>,
    pub control: Option<String>,
    pub listeners: Vec<CfgListener>,
    pub routes: Vec<CfgRoute>,
}

/// Which table the parser is currently filling.
enum Section {
    None,
    Server,
    Listener,
    Route,
}

/// One in-progress array-of-tables record. Fields are filled as keys are seen
/// and validated for completeness when the record closes.
#[derive(Default)]
struct PartialRecord {
    bind_ip: Option<Ipv4Addr>,
    proto: Option<Proto>,
    port: Option<u16>,
    client: Option<String>,
}

pub fn parse(text: &str) -> Result<ServerConfig> {
    let mut cfg = ServerConfig::default();
    let mut section = Section::None;
    let mut seen_server = false;
    let mut server_keys: Vec<&str> = Vec::new();
    let mut record = PartialRecord::default();
    let mut record_keys: Vec<&str> = Vec::new();
    // A listener and a route may share a (bind_ip, proto, port) key (a route
    // targets a listener), but two listeners or two routes may not.
    let mut seen_listeners: HashSet<(Ipv4Addr, Proto, u16)> = HashSet::new();
    let mut seen_routes: HashSet<(Ipv4Addr, Proto, u16)> = HashSet::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let n = lineno + 1;

        if let Some(header) = line.strip_prefix('[') {
            // A table header closes the previous array-of-tables record.
            close_record(
                &section,
                &mut cfg,
                &mut record,
                &mut seen_listeners,
                &mut seen_routes,
                n,
            )?;
            record = PartialRecord::default();
            record_keys.clear();

            let header = header
                .strip_suffix(']')
                .ok_or_else(|| err(n, "unterminated table header"))?;
            match header {
                "server" => {
                    if seen_server {
                        return Err(err(n, "duplicate [server] table"));
                    }
                    seen_server = true;
                    server_keys.clear();
                    section = Section::Server;
                }
                "[listeners]" => section = Section::Listener,
                "[routes]" => section = Section::Route,
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
            Section::Server => {
                reject_dup(&mut server_keys, key, n)?;
                match key {
                    "id" => cfg.id = Some(parse_string(value, n)?),
                    "control" => cfg.control = Some(parse_string(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [server]")));
                    }
                }
            }
            Section::Listener => {
                reject_dup(&mut record_keys, key, n)?;
                match key {
                    "bind_ip" => record.bind_ip = Some(parse_ip(value, n)?),
                    "proto" => record.proto = Some(parse_proto(value, n)?),
                    "port" => record.port = Some(parse_int(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [[listeners]]")));
                    }
                }
            }
            Section::Route => {
                reject_dup(&mut record_keys, key, n)?;
                match key {
                    "bind_ip" => record.bind_ip = Some(parse_ip(value, n)?),
                    "proto" => record.proto = Some(parse_proto(value, n)?),
                    "port" => record.port = Some(parse_int(value, n)?),
                    "client" => record.client = Some(parse_string(value, n)?),
                    other => {
                        return Err(err(n, &format!("unknown key `{other}` in [[routes]]")));
                    }
                }
            }
        }
    }

    // Close the final open record at EOF.
    let last = text.lines().count();
    close_record(
        &section,
        &mut cfg,
        &mut record,
        &mut seen_listeners,
        &mut seen_routes,
        last,
    )?;
    Ok(cfg)
}

/// Validate and commit the in-progress array-of-tables record, if any. Rejects a
/// listener or route whose `(bind_ip, proto, port)` key already appeared, since
/// each such key maps to exactly one listener and at most one route.
fn close_record(
    section: &Section,
    cfg: &mut ServerConfig,
    record: &mut PartialRecord,
    seen_listeners: &mut HashSet<(Ipv4Addr, Proto, u16)>,
    seen_routes: &mut HashSet<(Ipv4Addr, Proto, u16)>,
    n: usize,
) -> Result<()> {
    match section {
        Section::Listener => {
            let bind_ip = record
                .bind_ip
                .ok_or_else(|| err(n, "listener missing `bind_ip`"))?;
            let proto = record
                .proto
                .ok_or_else(|| err(n, "listener missing `proto`"))?;
            let port = record
                .port
                .ok_or_else(|| err(n, "listener missing `port`"))?;
            if !seen_listeners.insert((bind_ip, proto, port)) {
                return Err(err(
                    n,
                    &format!(
                        "duplicate listener {bind_ip} {} {port}",
                        crate::proto::proto_name(proto)
                    ),
                ));
            }
            cfg.listeners.push(CfgListener {
                bind_ip,
                proto,
                port,
            });
        }
        Section::Route => {
            let bind_ip = record
                .bind_ip
                .ok_or_else(|| err(n, "route missing `bind_ip`"))?;
            let proto = record
                .proto
                .ok_or_else(|| err(n, "route missing `proto`"))?;
            let port = record.port.ok_or_else(|| err(n, "route missing `port`"))?;
            let client = record
                .client
                .take()
                .ok_or_else(|| err(n, "route missing `client`"))?;
            if !seen_routes.insert((bind_ip, proto, port)) {
                return Err(err(
                    n,
                    &format!(
                        "duplicate route {bind_ip} {} {port}",
                        crate::proto::proto_name(proto)
                    ),
                ));
            }
            cfg.routes.push(CfgRoute {
                bind_ip,
                proto,
                port,
                client,
            });
        }
        Section::None | Section::Server => {}
    }
    Ok(())
}

pub(crate) fn parse_proto(value: &str, n: usize) -> Result<Proto> {
    let s = parse_string(value, n)?;
    match s.as_str() {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        "tap" => Err(err(n, "proto `tap` is not supported in this version")),
        other => Err(err(n, &format!("unknown proto `{other}`"))),
    }
}

fn parse_ip(value: &str, n: usize) -> Result<Ipv4Addr> {
    let s = parse_string(value, n)?;
    Ipv4Addr::from_str(&s).map_err(|_| err(n, &format!("invalid IPv4 address `{s}`")))
}

/// Emit a deterministic, sorted, comment-free rendering of `cfg`.
pub fn serialize(cfg: &ServerConfig) -> String {
    let mut out = String::new();

    if cfg.id.is_some() || cfg.control.is_some() {
        out.push_str("[server]\n");
        if let Some(id) = &cfg.id {
            out.push_str(&format!("id = {}\n", quote(id)));
        }
        if let Some(control) = &cfg.control {
            out.push_str(&format!("control = {}\n", quote(control)));
        }
    }

    let mut listeners = cfg.listeners.clone();
    listeners.sort_by(|a, b| {
        (a.bind_ip, proto_rank(a.proto), a.port).cmp(&(b.bind_ip, proto_rank(b.proto), b.port))
    });
    for l in &listeners {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("[[listeners]]\n");
        out.push_str(&format!("bind_ip = {}\n", quote(&l.bind_ip.to_string())));
        out.push_str(&format!("proto = {}\n", quote(proto_str(l.proto))));
        out.push_str(&format!("port = {}\n", l.port));
    }

    let mut routes = cfg.routes.clone();
    routes.sort_by(|a, b| {
        (a.bind_ip, proto_rank(a.proto), a.port).cmp(&(b.bind_ip, proto_rank(b.proto), b.port))
    });
    for r in &routes {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("[[routes]]\n");
        out.push_str(&format!("bind_ip = {}\n", quote(&r.bind_ip.to_string())));
        out.push_str(&format!("proto = {}\n", quote(proto_str(r.proto))));
        out.push_str(&format!("port = {}\n", r.port));
        out.push_str(&format!("client = {}\n", quote(&r.client)));
    }

    out
}

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn proto_rank(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 0,
        Proto::Udp => 1,
    }
}

/// Load a server config. A missing file yields the default (empty) config so a
/// first boot with `--config` pointing at a not-yet-written path is not an error;
/// the file is created on the first persisted mutation.
pub fn load(path: &Path) -> std::result::Result<ServerConfig, LoadError> {
    codec::load(path, parse)
}

#[cfg(test)]
mod tests {
    use super::codec::COUNTER;
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn sample() -> ServerConfig {
        ServerConfig {
            id: Some("oci".into()),
            control: Some("0.0.0.0:2222".into()),
            listeners: vec![
                CfgListener {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 10),
                    proto: Proto::Tcp,
                    port: 443,
                },
                CfgListener {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 11),
                    proto: Proto::Udp,
                    port: 51820,
                },
            ],
            routes: vec![
                CfgRoute {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 10),
                    proto: Proto::Tcp,
                    port: 443,
                    client: "rpi-2".into(),
                },
                CfgRoute {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 11),
                    proto: Proto::Udp,
                    port: 51820,
                    client: "rpi-1".into(),
                },
            ],
        }
    }

    #[test]
    fn roundtrip() {
        let cfg = sample();
        assert_eq!(parse(&serialize(&cfg)).unwrap(), cfg);
    }

    #[test]
    fn serialize_is_sorted_and_deterministic() {
        let cfg = ServerConfig {
            id: None,
            control: None,
            listeners: vec![
                CfgListener {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 11),
                    proto: Proto::Udp,
                    port: 51820,
                },
                CfgListener {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 10),
                    proto: Proto::Tcp,
                    port: 443,
                },
            ],
            routes: Vec::new(),
        };
        let text = serialize(&cfg);
        let first = text.find("203.0.113.10").unwrap();
        let second = text.find("203.0.113.11").unwrap();
        assert!(first < second, "listeners must be emitted sorted");
        assert_eq!(serialize(&parse(&text).unwrap()), text);
    }

    #[test]
    fn rejects_malformed() {
        let cases = [
            "[bogus]\n",
            "[server]\nfoo = 1\n",
            "id = \"x\"\n",
            "[[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tap\"\nport = 1\n",
            "[[listeners]]\nbind_ip = \"::1\"\nproto = \"tcp\"\nport = 1\n",
            "[[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 99999\n",
            "[[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = \"443\"\n",
            "[server]\nid = \"x\n",
            "[[listeners]]\nbind_ip = \"127.0.0.1\"\nbind_ip = \"127.0.0.2\"\nproto = \"tcp\"\nport = 1\n",
            "[server]\nid = \"a\"\n[server]\ncontrol = \"b\"\n",
            "[[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\n",
            "[[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 443 x\n",
            // Two listeners with the same (bind_ip, proto, port) key.
            "[[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 443\n\
             [[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 443\n",
            // Two routes with the same key.
            "[[routes]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 443\nclient = \"a\"\n\
             [[routes]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 443\nclient = \"b\"\n",
        ];
        for case in cases {
            assert!(parse(case).is_err(), "expected Err for:\n{case}");
        }
    }

    #[test]
    fn listener_and_route_may_share_a_key() {
        // A route targets a listener, so the same (bind_ip, proto, port) is legal
        // across the two sections; only same-section duplicates are rejected.
        let text = "[[listeners]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 443\n\
                    [[routes]]\nbind_ip = \"127.0.0.1\"\nproto = \"tcp\"\nport = 443\nclient = \"a\"\n";
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
    }

    #[test]
    fn drops_comments_keeps_in_string() {
        let text = "# a standalone comment\n\
                    [server]\n\
                    id = \"a#b\" # trailing comment\n\
                    [[listeners]]\n\
                    bind_ip = \"127.0.0.1\"\n\
                    proto = \"tcp\"\n\
                    port = 443 # c\n";
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.id.as_deref(), Some("a#b"));
        assert_eq!(cfg.listeners[0].port, 443);
        // The only surviving `#` is the literal one inside the id string.
        let out = serialize(&cfg);
        assert!(out.contains("a#b"));
        assert!(!out.contains("standalone"));
        assert!(!out.contains("trailing comment"));
        assert_eq!(parse(&out).unwrap(), cfg);
    }

    #[test]
    fn non_ascii_value() {
        let text = "[server]\nid = \"naïve-Ñ-クライアント\"\n";
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.id.as_deref(), Some("naïve-Ñ-クライアント"));
        assert_eq!(parse(&serialize(&cfg)).unwrap(), cfg);
    }

    #[test]
    fn empty_input() {
        assert_eq!(parse("").unwrap(), ServerConfig::default());
        assert_eq!(
            parse("\n  \n# only a comment\n").unwrap(),
            ServerConfig::default()
        );
    }

    #[test]
    fn crlf() {
        let unix = "[server]\nid = \"a\"\ncontrol = \"b\"\n";
        let dos = "[server]\r\nid = \"a\"\r\ncontrol = \"b\"\r\n";
        assert_eq!(parse(unix).unwrap(), parse(dos).unwrap());
        let cfg = parse(dos).unwrap();
        assert_eq!(cfg.id.as_deref(), Some("a"));
        assert_eq!(cfg.control.as_deref(), Some("b"));
    }

    #[test]
    fn save_atomic_roundtrip() {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zeronat-cfg-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.toml");

        let cfg = sample();
        save_atomic(&path, &serialize(&cfg)).unwrap();
        let back = load(&path).unwrap();
        assert_eq!(back, cfg);

        let mut other = cfg.clone();
        other.id = Some("other".into());
        save_atomic(&path, &serialize(&other)).unwrap();
        assert_eq!(load(&path).unwrap(), other);

        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "no temp file should remain");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_missing_file_is_default() {
        let path = std::env::temp_dir().join(format!(
            "zeronat-absent-{}-{}.toml",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        assert_eq!(load(&path).unwrap(), ServerConfig::default());
    }

    #[test]
    fn load_malformed_file_is_recoverable_and_quarantinable() {
        let dir = std::env::temp_dir().join(format!(
            "zeronat-bad-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.toml");
        std::fs::write(&path, "[server\nid = ").unwrap();
        assert!(matches!(load(&path), Err(LoadError::Malformed(_))));

        // Quarantine preserves the original bytes under a sibling name and frees
        // the path so a fresh file can take its place.
        let backup = quarantine(&path).expect("rename aside succeeds");
        assert!(!path.exists(), "original is moved");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "[server\nid = ");
        assert!(backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("server.toml.corrupt-"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
