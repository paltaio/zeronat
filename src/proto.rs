use std::net::Ipv4Addr;

use crate::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Where a mutable setting came from. `File` is loaded from config and persisted
/// on mutation; `Cli` is passed as a process arg and read-only to admin; `Runtime`
/// is applied this process lifetime on a node with no config file and is not saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    File,
    Cli,
    Runtime,
}

/// A public port the server is listening on, as reported in a `Snapshot`.
#[derive(Debug, Clone, PartialEq)]
pub struct Listener {
    pub bind_ip: Ipv4Addr,
    pub proto: Proto,
    pub port: u16,
    pub source: Source,
}

/// A connected client, as reported in a `Snapshot`. `transport` is the observed
/// control transport: 1 = tcp, 2 = udp.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientEntry {
    pub client_id: String,
    pub transport: u8,
}

/// A route in the server's table, as reported in a `Snapshot`. `state` is 0 when
/// the target client is connected (active) and 1 when it is offline.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteEntry {
    pub bind_ip: Ipv4Addr,
    pub proto: Proto,
    pub port: u16,
    pub client_id: String,
    pub state: u8,
    pub source: Source,
}

/// A point-in-time view of one server's topology, returned to admin on request.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotBody {
    pub version: u8,
    pub server_id: String,
    pub listeners: Vec<Listener>,
    pub clients: Vec<ClientEntry>,
    pub routes: Vec<RouteEntry>,
}

/// Messages exchanged over the encrypted Noise channels.
///
/// Control channel (client -> server): `ClientHello`, then periodic `Ping`.
/// Control channel (server -> client): `Pong` in reply to each `Ping`, and
/// `Open` for each new public connection.
/// Data channel (client -> server, first message): `Data` carrying the stream id.
/// Admin channel (admin -> server): `AdminHello` mode 0 -> `Snapshot`; mode 1 ->
/// one mutation message (`AddListener`/`RemoveListener`/`SetRoute`/`ClearRoute`),
/// answered by `MutationResult`.
#[derive(Debug)]
pub enum Msg {
    Ping,
    Open {
        proto: Proto,
        port: u16,
        id: u64,
    },
    Data {
        id: u64,
    },
    Pong,
    ClientHello {
        version: u8,
        client_id: String,
    },
    AdminHello {
        version: u8,
        mode: u8,
    },
    Snapshot(SnapshotBody),
    AddListener {
        bind_ip: Ipv4Addr,
        proto: Proto,
        port: u16,
    },
    RemoveListener {
        bind_ip: Ipv4Addr,
        proto: Proto,
        port: u16,
    },
    SetRoute {
        bind_ip: Ipv4Addr,
        proto: Proto,
        port: u16,
        client_id: String,
    },
    ClearRoute {
        bind_ip: Ipv4Addr,
        proto: Proto,
        port: u16,
    },
    MutationResult {
        ok: bool,
        msg: String,
    },
}

fn proto_byte(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 1,
        Proto::Udp => 2,
    }
}

fn proto_from_byte(n: u8) -> Result<Proto> {
    match n {
        1 => Ok(Proto::Tcp),
        2 => Ok(Proto::Udp),
        n => Err(format!("unknown proto byte {n}").into()),
    }
}

pub(crate) fn source_byte(s: Source) -> u8 {
    match s {
        Source::File => 0,
        Source::Cli => 1,
        Source::Runtime => 2,
    }
}

fn source_from_byte(n: u8) -> Result<Source> {
    match n {
        0 => Ok(Source::File),
        1 => Ok(Source::Cli),
        2 => Ok(Source::Runtime),
        n => Err(format!("unknown source byte {n}").into()),
    }
}

/// Lowercase protocol name for logs and admin output.
pub(crate) fn proto_name(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

/// Append a u16-length-prefixed UTF-8 string. Ids are short, well under
/// u16::MAX; the debug assert guards against a future caller violating that.
fn put_str(b: &mut Vec<u8>, s: &str) {
    debug_assert!(s.len() <= u16::MAX as usize);
    b.extend_from_slice(&(s.len() as u16).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
}

/// Read a u16-length-prefixed UTF-8 string at `*at`, advancing the cursor.
/// Bounds-checks both the length prefix and the body, and validates UTF-8.
fn take_str(b: &[u8], at: &mut usize) -> Result<String> {
    if *at + 2 > b.len() {
        return Err("truncated string length".into());
    }
    let len = u16::from_be_bytes([b[*at], b[*at + 1]]) as usize;
    *at += 2;
    if *at + len > b.len() {
        return Err("truncated string body".into());
    }
    let s = String::from_utf8(b[*at..*at + len].to_vec())
        .map_err(|_| -> crate::Error { "invalid utf-8 in string".into() })?;
    *at += len;
    Ok(s)
}

/// Append the 4 octets of an IPv4 address.
fn put_ip(b: &mut Vec<u8>, ip: Ipv4Addr) {
    b.extend_from_slice(&ip.octets());
}

/// Read 4 octets at `*at` as an IPv4 address, advancing the cursor.
fn take_ip(b: &[u8], at: &mut usize) -> Result<Ipv4Addr> {
    if *at + 4 > b.len() {
        return Err("truncated ipv4 address".into());
    }
    let ip = Ipv4Addr::new(b[*at], b[*at + 1], b[*at + 2], b[*at + 3]);
    *at += 4;
    Ok(ip)
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Msg::Ping => vec![1],
            Msg::Open { proto, port, id } => {
                let mut b = Vec::with_capacity(12);
                b.push(2);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                b.extend_from_slice(&id.to_be_bytes());
                b
            }
            Msg::Data { id } => {
                let mut b = Vec::with_capacity(9);
                b.push(3);
                b.extend_from_slice(&id.to_be_bytes());
                b
            }
            Msg::Pong => vec![4],
            Msg::ClientHello { version, client_id } => {
                let mut b = Vec::new();
                b.push(5);
                b.push(*version);
                put_str(&mut b, client_id);
                b
            }
            Msg::AdminHello { version, mode } => {
                vec![6, *version, *mode]
            }
            Msg::Snapshot(snap) => {
                let mut b = Vec::new();
                b.push(7);
                b.push(snap.version);
                put_str(&mut b, &snap.server_id);
                debug_assert!(snap.listeners.len() <= u16::MAX as usize);
                b.extend_from_slice(&(snap.listeners.len() as u16).to_be_bytes());
                for l in &snap.listeners {
                    put_ip(&mut b, l.bind_ip);
                    b.push(proto_byte(l.proto));
                    b.extend_from_slice(&l.port.to_be_bytes());
                    b.push(source_byte(l.source));
                }
                debug_assert!(snap.clients.len() <= u16::MAX as usize);
                b.extend_from_slice(&(snap.clients.len() as u16).to_be_bytes());
                for c in &snap.clients {
                    put_str(&mut b, &c.client_id);
                    b.push(c.transport);
                }
                debug_assert!(snap.routes.len() <= u16::MAX as usize);
                b.extend_from_slice(&(snap.routes.len() as u16).to_be_bytes());
                for route in &snap.routes {
                    put_ip(&mut b, route.bind_ip);
                    b.push(proto_byte(route.proto));
                    b.extend_from_slice(&route.port.to_be_bytes());
                    put_str(&mut b, &route.client_id);
                    b.push(route.state);
                    b.push(source_byte(route.source));
                }
                b
            }
            Msg::AddListener {
                bind_ip,
                proto,
                port,
            } => {
                let mut b = Vec::with_capacity(8);
                b.push(8);
                put_ip(&mut b, *bind_ip);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                b
            }
            Msg::RemoveListener {
                bind_ip,
                proto,
                port,
            } => {
                let mut b = Vec::with_capacity(8);
                b.push(9);
                put_ip(&mut b, *bind_ip);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                b
            }
            Msg::SetRoute {
                bind_ip,
                proto,
                port,
                client_id,
            } => {
                let mut b = Vec::new();
                b.push(10);
                put_ip(&mut b, *bind_ip);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                put_str(&mut b, client_id);
                b
            }
            Msg::ClearRoute {
                bind_ip,
                proto,
                port,
            } => {
                let mut b = Vec::with_capacity(8);
                b.push(11);
                put_ip(&mut b, *bind_ip);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                b
            }
            Msg::MutationResult { ok, msg } => {
                let mut b = Vec::new();
                b.push(12);
                b.push(u8::from(*ok));
                put_str(&mut b, msg);
                b
            }
        }
    }

    pub fn decode(b: &[u8]) -> Result<Msg> {
        match b.first() {
            Some(1) => Ok(Msg::Ping),
            Some(2) if b.len() == 12 => {
                let proto = proto_from_byte(b[1])?;
                let port = u16::from_be_bytes([b[2], b[3]]);
                let id = u64::from_be_bytes(b[4..12].try_into().unwrap());
                Ok(Msg::Open { proto, port, id })
            }
            Some(3) if b.len() == 9 => {
                let id = u64::from_be_bytes(b[1..9].try_into().unwrap());
                Ok(Msg::Data { id })
            }
            Some(4) => Ok(Msg::Pong),
            Some(5) => {
                let mut at = 2;
                if b.len() < at {
                    return Err("truncated client hello".into());
                }
                let version = b[1];
                let client_id = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in client hello".into());
                }
                Ok(Msg::ClientHello { version, client_id })
            }
            Some(6) if b.len() == 3 => Ok(Msg::AdminHello {
                version: b[1],
                mode: b[2],
            }),
            Some(7) => {
                let mut at = 2;
                if b.len() < at {
                    return Err("truncated snapshot".into());
                }
                let version = b[1];
                let server_id = take_str(b, &mut at)?;
                if at + 2 > b.len() {
                    return Err("truncated listener count".into());
                }
                let count = u16::from_be_bytes([b[at], b[at + 1]]) as usize;
                at += 2;
                let mut listeners = Vec::new();
                for _ in 0..count {
                    let bind_ip = take_ip(b, &mut at)?;
                    if at + 4 > b.len() {
                        return Err("truncated listener".into());
                    }
                    let proto = proto_from_byte(b[at])?;
                    let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                    let source = source_from_byte(b[at + 3])?;
                    at += 4;
                    listeners.push(Listener {
                        bind_ip,
                        proto,
                        port,
                        source,
                    });
                }
                if at + 2 > b.len() {
                    return Err("truncated client count".into());
                }
                let count = u16::from_be_bytes([b[at], b[at + 1]]) as usize;
                at += 2;
                let mut clients = Vec::new();
                for _ in 0..count {
                    let client_id = take_str(b, &mut at)?;
                    if at >= b.len() {
                        return Err("truncated client transport".into());
                    }
                    let transport = b[at];
                    at += 1;
                    if transport != 1 && transport != 2 {
                        return Err(format!("unknown transport byte {transport}").into());
                    }
                    clients.push(ClientEntry {
                        client_id,
                        transport,
                    });
                }
                if at + 2 > b.len() {
                    return Err("truncated route count".into());
                }
                let count = u16::from_be_bytes([b[at], b[at + 1]]) as usize;
                at += 2;
                let mut routes = Vec::new();
                for _ in 0..count {
                    let bind_ip = take_ip(b, &mut at)?;
                    if at + 3 > b.len() {
                        return Err("truncated route".into());
                    }
                    let proto = proto_from_byte(b[at])?;
                    let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                    at += 3;
                    let client_id = take_str(b, &mut at)?;
                    if at + 2 > b.len() {
                        return Err("truncated route state".into());
                    }
                    let state = b[at];
                    if state != 0 && state != 1 {
                        return Err(format!("unknown route state byte {state}").into());
                    }
                    let source = source_from_byte(b[at + 1])?;
                    at += 2;
                    routes.push(RouteEntry {
                        bind_ip,
                        proto,
                        port,
                        client_id,
                        state,
                        source,
                    });
                }
                if at != b.len() {
                    return Err("trailing bytes in snapshot".into());
                }
                Ok(Msg::Snapshot(SnapshotBody {
                    version,
                    server_id,
                    listeners,
                    clients,
                    routes,
                }))
            }
            Some(8) if b.len() == 8 => {
                let mut at = 1;
                let bind_ip = take_ip(b, &mut at)?;
                let proto = proto_from_byte(b[at])?;
                let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                Ok(Msg::AddListener {
                    bind_ip,
                    proto,
                    port,
                })
            }
            Some(9) if b.len() == 8 => {
                let mut at = 1;
                let bind_ip = take_ip(b, &mut at)?;
                let proto = proto_from_byte(b[at])?;
                let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                Ok(Msg::RemoveListener {
                    bind_ip,
                    proto,
                    port,
                })
            }
            Some(10) => {
                let mut at = 1;
                let bind_ip = take_ip(b, &mut at)?;
                if at + 3 > b.len() {
                    return Err("truncated set route".into());
                }
                let proto = proto_from_byte(b[at])?;
                let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                at += 3;
                let client_id = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in set route".into());
                }
                Ok(Msg::SetRoute {
                    bind_ip,
                    proto,
                    port,
                    client_id,
                })
            }
            Some(11) if b.len() == 8 => {
                let mut at = 1;
                let bind_ip = take_ip(b, &mut at)?;
                let proto = proto_from_byte(b[at])?;
                let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                Ok(Msg::ClearRoute {
                    bind_ip,
                    proto,
                    port,
                })
            }
            Some(12) => {
                if b.len() < 2 {
                    return Err("truncated mutation result".into());
                }
                let ok = match b[1] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown mutation result ok byte {n}").into()),
                };
                let mut at = 2;
                let msg = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in mutation result".into());
                }
                Ok(Msg::MutationResult { ok, msg })
            }
            _ => Err(format!("malformed message ({} bytes)", b.len()).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(m: &Msg) -> Msg {
        Msg::decode(&m.encode()).expect("decode")
    }

    #[test]
    fn client_hello_roundtrip() {
        for id in ["rpi-2-ab12", "", "naïve-Ñ-クライアント"] {
            let m = Msg::ClientHello {
                version: 1,
                client_id: id.into(),
            };
            match roundtrip(&m) {
                Msg::ClientHello { version, client_id } => {
                    assert_eq!(version, 1);
                    assert_eq!(client_id, id);
                }
                other => panic!("expected client hello, got {other:?}"),
            }
        }
    }

    #[test]
    fn admin_hello_roundtrip() {
        for mode in [0u8, 1u8] {
            let m = Msg::AdminHello { version: 1, mode };
            match roundtrip(&m) {
                Msg::AdminHello { version, mode: got } => {
                    assert_eq!(version, 1);
                    assert_eq!(got, mode);
                }
                other => panic!("expected admin hello, got {other:?}"),
            }
        }
        assert!(Msg::decode(&[6, 1]).is_err());
        assert!(Msg::decode(&[6, 1, 0, 0]).is_err());
    }

    #[test]
    fn snapshot_grown_roundtrip() {
        let body = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: vec![
                Listener {
                    bind_ip: Ipv4Addr::UNSPECIFIED,
                    proto: Proto::Tcp,
                    port: 443,
                    source: Source::File,
                },
                Listener {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 10),
                    proto: Proto::Udp,
                    port: 51820,
                    source: Source::Cli,
                },
            ],
            clients: vec![
                ClientEntry {
                    client_id: "rpi-1-ab12".into(),
                    transport: 1,
                },
                ClientEntry {
                    client_id: "rpi-2-cd34".into(),
                    transport: 2,
                },
            ],
            routes: vec![
                RouteEntry {
                    bind_ip: Ipv4Addr::LOCALHOST,
                    proto: Proto::Tcp,
                    port: 443,
                    client_id: "rpi-1-ab12".into(),
                    state: 0,
                    source: Source::File,
                },
                RouteEntry {
                    bind_ip: Ipv4Addr::new(203, 0, 113, 10),
                    proto: Proto::Udp,
                    port: 51820,
                    client_id: "rpi-2-cd34".into(),
                    state: 0,
                    source: Source::Runtime,
                },
                RouteEntry {
                    bind_ip: Ipv4Addr::new(198, 51, 100, 20),
                    proto: Proto::Tcp,
                    port: 8443,
                    client_id: "nat-box-ef56".into(),
                    state: 1,
                    source: Source::Cli,
                },
            ],
        };
        match roundtrip(&Msg::Snapshot(body.clone())) {
            Msg::Snapshot(decoded) => assert_eq!(decoded, body),
            other => panic!("expected snapshot, got {other:?}"),
        }

        let empty = SnapshotBody {
            version: 1,
            server_id: "srv".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
        };
        match roundtrip(&Msg::Snapshot(empty.clone())) {
            Msg::Snapshot(decoded) => assert_eq!(decoded, empty),
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    #[test]
    fn mutation_roundtrips() {
        let add = Msg::AddListener {
            bind_ip: Ipv4Addr::new(127, 0, 0, 1),
            proto: Proto::Tcp,
            port: 8443,
        };
        match roundtrip(&add) {
            Msg::AddListener {
                bind_ip,
                proto,
                port,
            } => {
                assert_eq!(bind_ip, Ipv4Addr::new(127, 0, 0, 1));
                assert_eq!(proto, Proto::Tcp);
                assert_eq!(port, 8443);
            }
            other => panic!("expected add listener, got {other:?}"),
        }

        let remove = Msg::RemoveListener {
            bind_ip: Ipv4Addr::UNSPECIFIED,
            proto: Proto::Udp,
            port: 51820,
        };
        match roundtrip(&remove) {
            Msg::RemoveListener {
                bind_ip,
                proto,
                port,
            } => {
                assert_eq!(bind_ip, Ipv4Addr::UNSPECIFIED);
                assert_eq!(proto, Proto::Udp);
                assert_eq!(port, 51820);
            }
            other => panic!("expected remove listener, got {other:?}"),
        }

        let set = Msg::SetRoute {
            bind_ip: Ipv4Addr::LOCALHOST,
            proto: Proto::Tcp,
            port: 443,
            client_id: "rpi-2-ab12".into(),
        };
        match roundtrip(&set) {
            Msg::SetRoute {
                bind_ip,
                proto,
                port,
                client_id,
            } => {
                assert_eq!(bind_ip, Ipv4Addr::LOCALHOST);
                assert_eq!(proto, Proto::Tcp);
                assert_eq!(port, 443);
                assert_eq!(client_id, "rpi-2-ab12");
            }
            other => panic!("expected set route, got {other:?}"),
        }

        let clear = Msg::ClearRoute {
            bind_ip: Ipv4Addr::LOCALHOST,
            proto: Proto::Udp,
            port: 53,
        };
        match roundtrip(&clear) {
            Msg::ClearRoute {
                bind_ip,
                proto,
                port,
            } => {
                assert_eq!(bind_ip, Ipv4Addr::LOCALHOST);
                assert_eq!(proto, Proto::Udp);
                assert_eq!(port, 53);
            }
            other => panic!("expected clear route, got {other:?}"),
        }

        for (ok, text) in [(true, ""), (false, "no such listener")] {
            let m = Msg::MutationResult {
                ok,
                msg: text.into(),
            };
            match roundtrip(&m) {
                Msg::MutationResult { ok: got_ok, msg } => {
                    assert_eq!(got_ok, ok);
                    assert_eq!(msg, text);
                }
                other => panic!("expected mutation result, got {other:?}"),
            }
        }

        // Malformed: AddListener with the wrong length.
        assert!(Msg::decode(&[8, 127, 0, 0, 1, 1, 0]).is_err());
        // Malformed: SetRoute truncated mid client_id length.
        assert!(Msg::decode(&[10, 127, 0, 0, 1, 1, 1, 0xbb, 0]).is_err());
        // Malformed: SetRoute with trailing bytes after the client_id.
        let mut set_bytes = set.encode();
        set_bytes.push(0xff);
        assert!(Msg::decode(&set_bytes).is_err());
        // Malformed: MutationResult ok byte not in {0, 1}.
        assert!(Msg::decode(&[12, 2, 0, 0]).is_err());
        // Malformed: MutationResult with trailing bytes.
        let mut mr = Msg::MutationResult {
            ok: true,
            msg: "x".into(),
        }
        .encode();
        mr.push(0x00);
        assert!(Msg::decode(&mr).is_err());
    }

    #[test]
    fn decode_rejects_malformed() {
        // tag-5 client_id length claims more bytes than present.
        assert!(Msg::decode(&[5, 1, 0, 8, b'x', b'y']).is_err());
        // tag-7 listener count larger than the remaining bytes.
        assert!(Msg::decode(&[7, 1, 0, 1, b'0', 0, 5]).is_err());
        // trailing junk after a valid ClientHello.
        let mut hello = Msg::ClientHello {
            version: 1,
            client_id: "ok".into(),
        }
        .encode();
        hello.push(0xff);
        assert!(Msg::decode(&hello).is_err());
        // tag-7 with a bad transport byte (3).
        let mut snap = Msg::Snapshot(SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: Vec::new(),
            clients: vec![ClientEntry {
                client_id: "rpi".into(),
                transport: 1,
            }],
            routes: Vec::new(),
        })
        .encode();
        // The last byte is the empty-routes count low byte; back up to the
        // transport byte (which precedes the two route-count bytes) and corrupt it.
        let n = snap.len();
        snap[n - 3] = 3;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a bad listener source byte (5). A single listener and no
        // clients/routes puts the listener source byte before the two zero
        // counts (client + route), i.e. five bytes from the end.
        let mut snap = Msg::Snapshot(SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: vec![Listener {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: 443,
                source: Source::File,
            }],
            clients: Vec::new(),
            routes: Vec::new(),
        })
        .encode();
        let n = snap.len();
        snap[n - 5] = 5;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a bad route source byte (7). A single route and no
        // clients/listeners puts the route source byte at the very end, after the
        // route state byte.
        let mut snap = Msg::Snapshot(SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: vec![RouteEntry {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: 443,
                client_id: "rpi".into(),
                state: 0,
                source: Source::File,
            }],
        })
        .encode();
        let n = snap.len();
        snap[n - 1] = 7;
        assert!(Msg::decode(&snap).is_err());
    }

    #[test]
    fn legacy_tags_unchanged() {
        assert_eq!(Msg::Ping.encode(), vec![1]);
        assert_eq!(Msg::Pong.encode(), vec![4]);

        let open = Msg::Open {
            proto: Proto::Udp,
            port: 443,
            id: 7,
        };
        let bytes = open.encode();
        assert_eq!(bytes.len(), 12);
        match Msg::decode(&bytes).unwrap() {
            Msg::Open { proto, port, id } => {
                assert_eq!(proto, Proto::Udp);
                assert_eq!(port, 443);
                assert_eq!(id, 7);
            }
            other => panic!("expected open, got {other:?}"),
        }

        let data = Msg::Data { id: 42 };
        let bytes = data.encode();
        assert_eq!(bytes.len(), 9);
        match Msg::decode(&bytes).unwrap() {
            Msg::Data { id } => assert_eq!(id, 42),
            other => panic!("expected data, got {other:?}"),
        }

        // Hello (tag 0) is gone: byte 0 must decode to Err.
        assert!(Msg::decode(&[0]).is_err());
    }
}
