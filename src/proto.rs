use crate::Result;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A public port the server is listening on, as reported in a `Snapshot`.
#[derive(Debug, Clone, PartialEq)]
pub struct Listener {
    pub proto: Proto,
    pub port: u16,
}

/// The currently connected client, as reported in a `Snapshot`. `transport` is
/// the observed control transport: 1 = tcp, 2 = udp.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientEntry {
    pub client_id: String,
    pub transport: u8,
}

/// A point-in-time view of one server's topology, returned to admin on request.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotBody {
    pub version: u8,
    pub server_id: String,
    pub listeners: Vec<Listener>,
    pub client: Option<ClientEntry>,
}

/// Messages exchanged over the encrypted Noise channels.
///
/// Control channel (client -> server): `ClientHello`, then periodic `Ping`.
/// Control channel (server -> client): `Pong` in reply to each `Ping`, and
/// `Open` for each new public connection.
/// Data channel (client -> server, first message): `Data` carrying the stream id.
/// Admin channel (admin -> server): `AdminHello`; server replies `Snapshot`.
#[derive(Debug)]
pub enum Msg {
    Ping,
    Open { proto: Proto, port: u16, id: u64 },
    Data { id: u64 },
    Pong,
    ClientHello { version: u8, client_id: String },
    AdminHello { version: u8, mode: u8 },
    Snapshot(SnapshotBody),
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
                    b.push(proto_byte(l.proto));
                    b.extend_from_slice(&l.port.to_be_bytes());
                }
                match &snap.client {
                    Some(c) => {
                        b.push(1);
                        put_str(&mut b, &c.client_id);
                        b.push(c.transport);
                    }
                    None => b.push(0),
                }
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
                let mut listeners = Vec::with_capacity(count);
                for _ in 0..count {
                    if at + 3 > b.len() {
                        return Err("truncated listener".into());
                    }
                    let proto = proto_from_byte(b[at])?;
                    let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                    at += 3;
                    listeners.push(Listener { proto, port });
                }
                if at >= b.len() {
                    return Err("truncated client present flag".into());
                }
                let present = b[at];
                at += 1;
                let client = match present {
                    0 => None,
                    1 => {
                        let client_id = take_str(b, &mut at)?;
                        if at >= b.len() {
                            return Err("truncated client transport".into());
                        }
                        let transport = b[at];
                        at += 1;
                        if transport != 1 && transport != 2 {
                            return Err(format!("unknown transport byte {transport}").into());
                        }
                        Some(ClientEntry {
                            client_id,
                            transport,
                        })
                    }
                    n => return Err(format!("unknown client present flag {n}").into()),
                };
                if at != b.len() {
                    return Err("trailing bytes in snapshot".into());
                }
                Ok(Msg::Snapshot(SnapshotBody {
                    version,
                    server_id,
                    listeners,
                    client,
                }))
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
        let m = Msg::AdminHello {
            version: 1,
            mode: 0,
        };
        match roundtrip(&m) {
            Msg::AdminHello { version, mode } => {
                assert_eq!(version, 1);
                assert_eq!(mode, 0);
            }
            other => panic!("expected admin hello, got {other:?}"),
        }
        assert!(Msg::decode(&[6, 1]).is_err());
        assert!(Msg::decode(&[6, 1, 0, 0]).is_err());
    }

    #[test]
    fn snapshot_roundtrip() {
        let body = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: vec![
                Listener {
                    proto: Proto::Tcp,
                    port: 443,
                },
                Listener {
                    proto: Proto::Udp,
                    port: 51820,
                },
            ],
            client: Some(ClientEntry {
                client_id: "rpi-2-ab12".into(),
                transport: 1,
            }),
        };
        match roundtrip(&Msg::Snapshot(body.clone())) {
            Msg::Snapshot(decoded) => assert_eq!(decoded, body),
            other => panic!("expected snapshot, got {other:?}"),
        }

        let empty = SnapshotBody {
            version: 1,
            server_id: "srv".into(),
            listeners: Vec::new(),
            client: None,
        };
        match roundtrip(&Msg::Snapshot(empty.clone())) {
            Msg::Snapshot(decoded) => assert_eq!(decoded, empty),
            other => panic!("expected snapshot, got {other:?}"),
        }
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
            client: Some(ClientEntry {
                client_id: "rpi".into(),
                transport: 1,
            }),
        })
        .encode();
        *snap.last_mut().unwrap() = 3;
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
