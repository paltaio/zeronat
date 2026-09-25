//! Strict TOML-subset grammar for the server config file.
//!
//! The grammar is intentionally tiny: a `[server]` singleton plus
//! `[[listeners]]`/`[[routes]]` arrays-of-tables, with only double-quoted
//! strings and bare integers as scalars. The value-agnostic lexer and the
//! crash-safe file handling live in [`codec`].

pub(crate) mod codec;

use std::net::Ipv4Addr;
use std::path::Path;

use codec::{err, kv_bool, kv_num, kv_quoted, parse_tables, table, Grammar, Key, Record, TableDef};
pub use codec::{quarantine, save_atomic, LoadError};

use crate::admin::order;
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

#[derive(Debug, Clone, PartialEq)]
pub struct CfgClient {
    pub id: String,
    /// Absent when the credential is derived from the seed.
    pub secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServerConfig {
    pub id: Option<String>,
    pub control: Option<String>,
    /// Fills the network, admin, and discovery credentials, and the
    /// credential of any `[[clients]]` entry without a `secret`.
    pub seed: Option<String>,
    pub admin_secret: Option<String>,
    pub clients: Vec<CfgClient>,
    /// Exit mode: masquerade the tunnel client's outbound traffic.
    pub exit: Option<bool>,
    /// Egress interface for exit mode; unset auto-detects the default route.
    pub exit_iface: Option<String>,
    pub listeners: Vec<CfgListener>,
    pub routes: Vec<CfgRoute>,
}

const GRAMMAR: Grammar = Grammar {
    headers: "server [listeners] [routes] [clients]",
    tables: &[
        TableDef {
            label: "[server]",
            single: true,
            keys: "id control seed admin_secret exit exit_iface",
            kinds: &[
                Key::Str(0),
                Key::Str(1),
                Key::Str(2),
                Key::Str(3),
                Key::Bool(0),
                Key::Str(4),
            ],
        },
        TableDef {
            label: "[[listeners]]",
            single: false,
            keys: "bind_ip proto port",
            kinds: &[Key::Ip, Key::Proto, Key::Int(0)],
        },
        TableDef {
            label: "[[routes]]",
            single: false,
            keys: "bind_ip proto port client",
            kinds: &[Key::Ip, Key::Proto, Key::Int(0), Key::Str(0)],
        },
        TableDef {
            label: "[[clients]]",
            single: false,
            keys: "id secret",
            kinds: &[Key::Str(0), Key::Str(1)],
        },
    ],
};

#[inline(never)]
pub fn parse(text: &str) -> Result<ServerConfig> {
    let mut cfg = ServerConfig::default();
    // A listener and a route may share a (bind_ip, proto, port) key (a route
    // targets a listener), but two listeners or two routes may not.
    let mut seen_listeners: Vec<(Ipv4Addr, Proto, u16)> = Vec::new();
    let mut seen_routes: Vec<(Ipv4Addr, Proto, u16)> = Vec::new();
    parse_tables(text, &GRAMMAR, &mut |table, record, n| {
        close_record(
            table,
            &mut cfg,
            record,
            &mut seen_listeners,
            &mut seen_routes,
            n,
        )
    })?;
    Ok(cfg)
}

/// The `(bind_ip, proto, port)` key of a listener or route table, each part
/// required; `what` names the table in the errors.
#[inline(never)]
fn target(record: &Record, what: &str, n: usize) -> Result<(Ipv4Addr, Proto, u16)> {
    let missing = |key: &str| err(n, &format!("{what} missing `{key}`"));
    let bind_ip = record.ip.ok_or_else(|| missing("bind_ip"))?;
    let proto = record.proto.ok_or_else(|| missing("proto"))?;
    let port = record.ints[0].ok_or_else(|| missing("port"))?;
    Ok((bind_ip, proto, port))
}

/// Validate and commit the in-progress array-of-tables record, if any. Rejects a
/// listener or route whose `(bind_ip, proto, port)` key already appeared, since
/// each such key maps to exactly one listener and at most one route.
#[inline(never)]
fn close_record(
    table: usize,
    cfg: &mut ServerConfig,
    record: &mut Record,
    seen_listeners: &mut Vec<(Ipv4Addr, Proto, u16)>,
    seen_routes: &mut Vec<(Ipv4Addr, Proto, u16)>,
    n: usize,
) -> Result<()> {
    match table {
        0 => {
            cfg.id = record.strs[0].take();
            cfg.control = record.strs[1].take();
            cfg.seed = record.strs[2].take();
            cfg.admin_secret = record.strs[3].take();
            cfg.exit = record.bools[0];
            cfg.exit_iface = record.strs[4].take();
        }
        1 => {
            let (bind_ip, proto, port) = target(record, "listener", n)?;
            if seen_listeners.contains(&(bind_ip, proto, port)) {
                return Err(duplicate("listener", bind_ip, proto, port, n));
            }
            seen_listeners.push((bind_ip, proto, port));
            cfg.listeners.push(CfgListener {
                bind_ip,
                proto,
                port,
            });
        }
        2 => {
            let (bind_ip, proto, port) = target(record, "route", n)?;
            let client = record.required(0, n, "route missing `client`")?;
            if seen_routes.contains(&(bind_ip, proto, port)) {
                return Err(duplicate("route", bind_ip, proto, port, n));
            }
            seen_routes.push((bind_ip, proto, port));
            cfg.routes.push(CfgRoute {
                bind_ip,
                proto,
                port,
                client,
            });
        }
        _ => {
            let id = record.required(0, n, "client missing `id`")?;
            if id.is_empty() {
                return Err(err(n, "client `id` must not be empty"));
            }
            cfg.clients.push(CfgClient {
                id,
                secret: record.strs[1].take(),
            });
        }
    }
    Ok(())
}

#[inline(never)]
fn duplicate(what: &str, bind_ip: Ipv4Addr, proto: Proto, port: u16, n: usize) -> crate::Error {
    err(
        n,
        &format!(
            "duplicate {what} {bind_ip} {} {port}",
            crate::proto::proto_name(proto)
        ),
    )
}

/// Emit a deterministic, sorted, comment-free rendering of `cfg`.
#[inline(never)]
pub fn serialize(cfg: &ServerConfig) -> String {
    let mut out = String::new();

    if cfg.id.is_some()
        || cfg.control.is_some()
        || cfg.seed.is_some()
        || cfg.admin_secret.is_some()
        || cfg.exit.is_some()
        || cfg.exit_iface.is_some()
    {
        out.push_str("[server]\n");
        if let Some(id) = &cfg.id {
            kv_quoted(&mut out, "id", id);
        }
        if let Some(control) = &cfg.control {
            kv_quoted(&mut out, "control", control);
        }
        if let Some(seed) = &cfg.seed {
            kv_quoted(&mut out, "seed", seed);
        }
        if let Some(admin_secret) = &cfg.admin_secret {
            kv_quoted(&mut out, "admin_secret", admin_secret);
        }
        if let Some(exit) = cfg.exit {
            kv_bool(&mut out, "exit", exit);
        }
        if let Some(iface) = &cfg.exit_iface {
            kv_quoted(&mut out, "exit_iface", iface);
        }
    }

    let clients = &cfg.clients;
    for &i in &order(clients.len(), &mut |a, b| clients[a].id < clients[b].id) {
        let client = &clients[i];
        table(&mut out, "[[clients]]");
        kv_quoted(&mut out, "id", &client.id);
        if let Some(secret) = &client.secret {
            kv_quoted(&mut out, "secret", secret);
        }
    }

    let listeners = &cfg.listeners;
    let key = |l: &CfgListener| (l.bind_ip, proto_rank(l.proto), l.port);
    for &i in &order(listeners.len(), &mut |a, b| {
        key(&listeners[a]) < key(&listeners[b])
    }) {
        let l = &listeners[i];
        table(&mut out, "[[listeners]]");
        put_target(&mut out, l.bind_ip, l.proto, l.port);
    }

    let routes = &cfg.routes;
    let key = |r: &CfgRoute| (r.bind_ip, proto_rank(r.proto), r.port);
    for &i in &order(routes.len(), &mut |a, b| key(&routes[a]) < key(&routes[b])) {
        let r = &routes[i];
        table(&mut out, "[[routes]]");
        put_target(&mut out, r.bind_ip, r.proto, r.port);
        kv_quoted(&mut out, "client", &r.client);
    }

    out
}

/// The `bind_ip`, `proto`, `port` keys of a listener or route.
#[inline(never)]
fn put_target(out: &mut String, bind_ip: Ipv4Addr, proto: Proto, port: u16) {
    kv_quoted(out, "bind_ip", &bind_ip.to_string());
    kv_quoted(out, "proto", proto_str(proto));
    kv_num(out, "port", port.into());
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
            seed: Some("seed".into()),
            admin_secret: Some("admin-secret".into()),
            clients: vec![
                CfgClient {
                    id: "rpi-1".into(),
                    secret: Some("client-secret".into()),
                },
                CfgClient {
                    id: "rpi-2".into(),
                    secret: None,
                },
            ],
            exit: Some(true),
            exit_iface: Some("eth0".into()),
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
    fn exit_keys_roundtrip() {
        // `exit = false` is distinct from an absent key and must survive a save.
        let cfg = ServerConfig {
            exit: Some(false),
            ..ServerConfig::default()
        };
        assert_eq!(parse(&serialize(&cfg)).unwrap(), cfg);

        let text = "[server]\nexit = true\nexit_iface = \"eth0\"\n";
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.exit, Some(true));
        assert_eq!(cfg.exit_iface.as_deref(), Some("eth0"));
        assert_eq!(serialize(&cfg), text);
    }

    #[test]
    fn serialize_is_sorted_and_deterministic() {
        let cfg = ServerConfig {
            id: None,
            control: None,
            seed: None,
            admin_secret: None,
            clients: Vec::new(),
            exit: None,
            exit_iface: None,
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
            "[server]\nexit = 1\n",
            "[server]\nexit = \"true\"\n",
            "[server]\nexit_iface = true\n",
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
    fn client_secret_is_optional() {
        let text = "[[clients]]\nid = \"a\"\n\n[[clients]]\nid = \"b\"\nsecret = \"s\"\n";
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.clients[0].secret, None);
        assert_eq!(cfg.clients[1].secret.as_deref(), Some("s"));
        assert_eq!(serialize(&cfg), text);
        assert!(parse("[[clients]]\nsecret = \"s\"\n").is_err());
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
    fn save_atomic_preserves_the_target_mode() {
        use std::os::unix::fs::PermissionsExt;
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zeronat-cfg-mode-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.toml");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let cfg = sample();
        save_atomic(&path, &serialize(&cfg)).unwrap();
        assert_eq!(mode(&path), 0o600, "a fresh config file must be owner-only");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        save_atomic(&path, &serialize(&cfg)).unwrap();
        assert_eq!(mode(&path), 0o640, "a save must keep the target's mode");

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
