//! Messages for a running client's local admin socket.
//!
//! A tag space of its own, fully separate from the server protocol in
//! [`crate::proto`]: the two enums never share a stream, so their tags may
//! overlap freely. Bodies follow the same encoding conventions (big-endian
//! integers, u16-length-prefixed UTF-8 strings, exact-length validation) and
//! ride the Noise framing unchanged.

use crate::proto::{proto_byte, proto_from_byte, put_str, take_str, Proto};
use crate::Result;

/// The session body a client runs at any instant: the forwards control loop,
/// an L2/L3 device tunnel, one named PPPoE session, or nothing but the admin
/// socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    Idle,
    Forwards,
    Device,
    Pppoe,
}

/// PPP link phase of the active session, as reported in a `ClientSnapshot`.
/// `None` when there is no PPPoE phase to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PppPhase {
    None,
    Discovery,
    Negotiating,
    Established,
    LinkDown,
    Dead,
}

fn mode_byte(m: SessionMode) -> u8 {
    match m {
        SessionMode::Idle => 0,
        SessionMode::Forwards => 1,
        SessionMode::Device => 2,
        SessionMode::Pppoe => 3,
    }
}

fn mode_from_byte(n: u8) -> Result<SessionMode> {
    match n {
        0 => Ok(SessionMode::Idle),
        1 => Ok(SessionMode::Forwards),
        2 => Ok(SessionMode::Device),
        3 => Ok(SessionMode::Pppoe),
        n => Err(format!("unknown session mode byte {n}").into()),
    }
}

fn phase_byte(p: PppPhase) -> u8 {
    match p {
        PppPhase::None => 0,
        PppPhase::Discovery => 1,
        PppPhase::Negotiating => 2,
        PppPhase::Established => 3,
        PppPhase::LinkDown => 4,
        PppPhase::Dead => 5,
    }
}

fn phase_from_byte(n: u8) -> Result<PppPhase> {
    match n {
        0 => Ok(PppPhase::None),
        1 => Ok(PppPhase::Discovery),
        2 => Ok(PppPhase::Negotiating),
        3 => Ok(PppPhase::Established),
        4 => Ok(PppPhase::LinkDown),
        5 => Ok(PppPhase::Dead),
        n => Err(format!("unknown ppp phase byte {n}").into()),
    }
}

/// A forward as reported in a `ClientSnapshot`: the public port, the local
/// target it dials, and the per-forward options. `idle_secs` 0 means the proto
/// default idle window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientForwardEntry {
    pub proto: Proto,
    pub port: u16,
    pub target: String,
    pub proxy: bool,
    pub idle_secs: u32,
}

/// A point-in-time view of one running client, returned to admin on request.
/// Carries no secret field: server secrets and PPPoE credentials stay out of
/// the snapshot by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSnapshotBody {
    pub version: u8,
    /// Name of the active server profile.
    pub active: String,
    pub mode: SessionMode,
    pub phase: PppPhase,
    pub forwards: Vec<ClientForwardEntry>,
}

/// Messages exchanged over a client's admin socket.
///
/// Admin -> client: `ClientAdminHello` mode 0 requests one `ClientSnapshot`;
/// mode 1 is followed by exactly one mutation message (`SelectServer` /
/// `SetForwardOptions` / `SpawnPppoe` / `StopSession`), answered by
/// `MutationResult`. The connection closes after the single exchange.
#[derive(Debug)]
pub enum ClientMsg {
    ClientAdminHello {
        version: u8,
        mode: u8,
    },
    ClientSnapshot(ClientSnapshotBody),
    MutationResult {
        ok: bool,
        msg: String,
    },
    SelectServer {
        name: String,
    },
    /// The complete option state for one existing forward, keyed by
    /// `(proto, port)`; `idle_secs` 0 clears any idle override.
    SetForwardOptions {
        proto: Proto,
        port: u16,
        proxy: bool,
        idle_secs: u32,
    },
    SpawnPppoe {
        name: String,
    },
    StopSession {
        name: String,
    },
}

impl ClientMsg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ClientMsg::ClientAdminHello { version, mode } => vec![1, *version, *mode],
            ClientMsg::ClientSnapshot(snap) => {
                let mut b = Vec::new();
                b.push(2);
                b.push(snap.version);
                put_str(&mut b, &snap.active);
                b.push(mode_byte(snap.mode));
                b.push(phase_byte(snap.phase));
                // A client can carry up to two full port maps (tcp + udp),
                // more forwards than the u16 wire count can name; encode the
                // first u16::MAX rather than let the count wrap.
                let count = snap.forwards.len().min(u16::MAX as usize);
                b.extend_from_slice(&(count as u16).to_be_bytes());
                for f in &snap.forwards[..count] {
                    b.push(proto_byte(f.proto));
                    b.extend_from_slice(&f.port.to_be_bytes());
                    put_str(&mut b, &f.target);
                    b.push(u8::from(f.proxy));
                    b.extend_from_slice(&f.idle_secs.to_be_bytes());
                }
                b
            }
            ClientMsg::MutationResult { ok, msg } => {
                let mut b = Vec::new();
                b.push(3);
                b.push(u8::from(*ok));
                put_str(&mut b, msg);
                b
            }
            ClientMsg::SelectServer { name } => {
                let mut b = Vec::new();
                b.push(4);
                put_str(&mut b, name);
                b
            }
            ClientMsg::SetForwardOptions {
                proto,
                port,
                proxy,
                idle_secs,
            } => {
                let mut b = Vec::with_capacity(9);
                b.push(5);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                b.push(u8::from(*proxy));
                b.extend_from_slice(&idle_secs.to_be_bytes());
                b
            }
            ClientMsg::SpawnPppoe { name } => {
                let mut b = Vec::new();
                b.push(6);
                put_str(&mut b, name);
                b
            }
            ClientMsg::StopSession { name } => {
                let mut b = Vec::new();
                b.push(7);
                put_str(&mut b, name);
                b
            }
        }
    }

    pub fn decode(b: &[u8]) -> Result<ClientMsg> {
        match b.first() {
            Some(1) if b.len() == 3 => Ok(ClientMsg::ClientAdminHello {
                version: b[1],
                mode: b[2],
            }),
            Some(2) => {
                let mut at = 2;
                if b.len() < at {
                    return Err("truncated client snapshot".into());
                }
                let version = b[1];
                let active = take_str(b, &mut at)?;
                if at + 4 > b.len() {
                    return Err("truncated client snapshot header".into());
                }
                let mode = mode_from_byte(b[at])?;
                let phase = phase_from_byte(b[at + 1])?;
                let count = u16::from_be_bytes([b[at + 2], b[at + 3]]) as usize;
                at += 4;
                let mut forwards = Vec::new();
                for _ in 0..count {
                    if at + 3 > b.len() {
                        return Err("truncated forward entry".into());
                    }
                    let proto = proto_from_byte(b[at])?;
                    let port = u16::from_be_bytes([b[at + 1], b[at + 2]]);
                    at += 3;
                    let target = take_str(b, &mut at)?;
                    if at + 5 > b.len() {
                        return Err("truncated forward entry options".into());
                    }
                    let proxy = match b[at] {
                        0 => false,
                        1 => true,
                        n => return Err(format!("unknown forward proxy byte {n}").into()),
                    };
                    let idle_secs = u32::from_be_bytes(b[at + 1..at + 5].try_into().unwrap());
                    at += 5;
                    forwards.push(ClientForwardEntry {
                        proto,
                        port,
                        target,
                        proxy,
                        idle_secs,
                    });
                }
                if at != b.len() {
                    return Err("trailing bytes in client snapshot".into());
                }
                Ok(ClientMsg::ClientSnapshot(ClientSnapshotBody {
                    version,
                    active,
                    mode,
                    phase,
                    forwards,
                }))
            }
            Some(3) => {
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
                Ok(ClientMsg::MutationResult { ok, msg })
            }
            Some(4) => {
                let mut at = 1;
                let name = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in select server".into());
                }
                Ok(ClientMsg::SelectServer { name })
            }
            Some(5) if b.len() == 9 => {
                let proto = proto_from_byte(b[1])?;
                let port = u16::from_be_bytes([b[2], b[3]]);
                let proxy = match b[4] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown forward proxy byte {n}").into()),
                };
                let idle_secs = u32::from_be_bytes(b[5..9].try_into().unwrap());
                Ok(ClientMsg::SetForwardOptions {
                    proto,
                    port,
                    proxy,
                    idle_secs,
                })
            }
            Some(6) => {
                let mut at = 1;
                let name = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in spawn pppoe".into());
                }
                Ok(ClientMsg::SpawnPppoe { name })
            }
            Some(7) => {
                let mut at = 1;
                let name = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in stop session".into());
                }
                Ok(ClientMsg::StopSession { name })
            }
            _ => Err(format!("malformed client message ({} bytes)", b.len()).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(m: &ClientMsg) -> ClientMsg {
        ClientMsg::decode(&m.encode()).expect("decode")
    }

    #[test]
    fn client_admin_hello_roundtrip() {
        for mode in [0u8, 1u8] {
            let m = ClientMsg::ClientAdminHello { version: 1, mode };
            match roundtrip(&m) {
                ClientMsg::ClientAdminHello { version, mode: got } => {
                    assert_eq!(version, 1);
                    assert_eq!(got, mode);
                }
                other => panic!("expected client admin hello, got {other:?}"),
            }
        }
        assert!(ClientMsg::decode(&[1]).is_err());
        assert!(ClientMsg::decode(&[1, 1]).is_err());
        assert!(ClientMsg::decode(&[1, 1, 0, 0]).is_err());
    }

    fn sample_snapshot() -> ClientSnapshotBody {
        ClientSnapshotBody {
            version: 1,
            active: "home".into(),
            mode: SessionMode::Forwards,
            phase: PppPhase::None,
            forwards: vec![
                ClientForwardEntry {
                    proto: Proto::Tcp,
                    port: 8080,
                    target: "127.0.0.1:80".into(),
                    proxy: true,
                    idle_secs: 600,
                },
                ClientForwardEntry {
                    proto: Proto::Udp,
                    port: 51820,
                    target: "10.0.0.5:51820".into(),
                    proxy: false,
                    idle_secs: 0,
                },
            ],
        }
    }

    #[test]
    fn snapshot_roundtrip() {
        let body = sample_snapshot();
        match roundtrip(&ClientMsg::ClientSnapshot(body.clone())) {
            ClientMsg::ClientSnapshot(decoded) => assert_eq!(decoded, body),
            other => panic!("expected client snapshot, got {other:?}"),
        }

        let empty = ClientSnapshotBody {
            version: 2,
            active: "naïve-Ñ-クライアント".into(),
            mode: SessionMode::Pppoe,
            phase: PppPhase::Established,
            forwards: Vec::new(),
        };
        match roundtrip(&ClientMsg::ClientSnapshot(empty.clone())) {
            ClientMsg::ClientSnapshot(decoded) => assert_eq!(decoded, empty),
            other => panic!("expected client snapshot, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_every_mode_and_phase_roundtrips() {
        for mode in [
            SessionMode::Idle,
            SessionMode::Forwards,
            SessionMode::Device,
            SessionMode::Pppoe,
        ] {
            for phase in [
                PppPhase::None,
                PppPhase::Discovery,
                PppPhase::Negotiating,
                PppPhase::Established,
                PppPhase::LinkDown,
                PppPhase::Dead,
            ] {
                let body = ClientSnapshotBody {
                    version: 1,
                    active: "a".into(),
                    mode,
                    phase,
                    forwards: Vec::new(),
                };
                match roundtrip(&ClientMsg::ClientSnapshot(body.clone())) {
                    ClientMsg::ClientSnapshot(decoded) => assert_eq!(decoded, body),
                    other => panic!("expected client snapshot, got {other:?}"),
                }
            }
        }
    }

    /// Every malformed snapshot must error, never panic (panic=abort).
    #[test]
    fn snapshot_rejects_malformed() {
        // One single-char string each, so the byte offsets below are fixed:
        // 0 tag, 1 version, 2-4 active ("a"), 5 mode, 6 phase, 7-8 count,
        // 9 proto, 10-11 port, 12-14 target ("t"), 15 proxy, 16-19 idle.
        let good = ClientMsg::ClientSnapshot(ClientSnapshotBody {
            version: 1,
            active: "a".into(),
            mode: SessionMode::Forwards,
            phase: PppPhase::None,
            forwards: vec![ClientForwardEntry {
                proto: Proto::Tcp,
                port: 443,
                target: "t".into(),
                proxy: true,
                idle_secs: 600,
            }],
        })
        .encode();
        assert_eq!(good.len(), 20);
        // Any truncation errors, never panics.
        for cut in 1..good.len() {
            assert!(
                ClientMsg::decode(&good[..cut]).is_err(),
                "cut {cut} should error"
            );
        }
        // Trailing junk after a valid body.
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(ClientMsg::decode(&junk).is_err());
        // A forward count larger than the remaining bytes.
        let mut big = good.clone();
        big[7] = 0xff;
        big[8] = 0xff;
        assert!(ClientMsg::decode(&big).is_err());
        // Unknown mode, phase, proto, and proxy bytes.
        for (at, bad) in [(5, 4u8), (6, 6u8), (9, 9u8), (15, 2u8)] {
            let mut corrupt = good.clone();
            corrupt[at] = bad;
            assert!(
                ClientMsg::decode(&corrupt).is_err(),
                "byte {at} = {bad} should error"
            );
        }
    }

    #[test]
    fn mutation_roundtrips() {
        for name in ["home", "", "naïve-Ñ"] {
            let m = ClientMsg::SelectServer { name: name.into() };
            match roundtrip(&m) {
                ClientMsg::SelectServer { name: got } => assert_eq!(got, name),
                other => panic!("expected select server, got {other:?}"),
            }
        }

        let set = ClientMsg::SetForwardOptions {
            proto: Proto::Tcp,
            port: 8443,
            proxy: true,
            idle_secs: 600,
        };
        match roundtrip(&set) {
            ClientMsg::SetForwardOptions {
                proto,
                port,
                proxy,
                idle_secs,
            } => {
                assert_eq!(proto, Proto::Tcp);
                assert_eq!(port, 8443);
                assert!(proxy);
                assert_eq!(idle_secs, 600);
            }
            other => panic!("expected set forward options, got {other:?}"),
        }
        match roundtrip(&ClientMsg::SetForwardOptions {
            proto: Proto::Udp,
            port: 51820,
            proxy: false,
            idle_secs: 0,
        }) {
            ClientMsg::SetForwardOptions {
                proto,
                port,
                proxy,
                idle_secs,
            } => {
                assert_eq!(proto, Proto::Udp);
                assert_eq!(port, 51820);
                assert!(!proxy);
                assert_eq!(idle_secs, 0);
            }
            other => panic!("expected set forward options, got {other:?}"),
        }

        match roundtrip(&ClientMsg::SpawnPppoe { name: "wan".into() }) {
            ClientMsg::SpawnPppoe { name } => assert_eq!(name, "wan"),
            other => panic!("expected spawn pppoe, got {other:?}"),
        }
        match roundtrip(&ClientMsg::StopSession { name: "wan".into() }) {
            ClientMsg::StopSession { name } => assert_eq!(name, "wan"),
            other => panic!("expected stop session, got {other:?}"),
        }

        for (ok, text) in [(true, ""), (false, "no such server")] {
            let m = ClientMsg::MutationResult {
                ok,
                msg: text.into(),
            };
            match roundtrip(&m) {
                ClientMsg::MutationResult { ok: got_ok, msg } => {
                    assert_eq!(got_ok, ok);
                    assert_eq!(msg, text);
                }
                other => panic!("expected mutation result, got {other:?}"),
            }
        }
    }

    #[test]
    fn mutations_reject_malformed() {
        // SetForwardOptions with the wrong length.
        assert!(ClientMsg::decode(&[5, 1, 0, 1, 1]).is_err());
        let mut long = ClientMsg::SetForwardOptions {
            proto: Proto::Tcp,
            port: 1,
            proxy: false,
            idle_secs: 0,
        }
        .encode();
        long.push(0x00);
        assert!(ClientMsg::decode(&long).is_err());
        // SetForwardOptions with a bad proto or proxy byte.
        assert!(ClientMsg::decode(&[5, 9, 0, 1, 0, 0, 0, 0, 0]).is_err());
        assert!(ClientMsg::decode(&[5, 1, 0, 1, 2, 0, 0, 0, 0]).is_err());
        // Name-carrying mutations: truncated length prefix and trailing junk.
        for tag in [4u8, 6, 7] {
            assert!(ClientMsg::decode(&[tag, 0]).is_err());
            assert!(ClientMsg::decode(&[tag, 0, 8, b'x']).is_err());
            let mut junk = vec![tag, 0, 1, b'x'];
            junk.push(0xff);
            assert!(ClientMsg::decode(&junk).is_err());
        }
        // MutationResult ok byte not in {0, 1} and trailing bytes.
        assert!(ClientMsg::decode(&[3, 2, 0, 0]).is_err());
        let mut mr = ClientMsg::MutationResult {
            ok: true,
            msg: "x".into(),
        }
        .encode();
        mr.push(0x00);
        assert!(ClientMsg::decode(&mr).is_err());
        // Unknown tags and the empty frame.
        assert!(ClientMsg::decode(&[]).is_err());
        assert!(ClientMsg::decode(&[0]).is_err());
        assert!(ClientMsg::decode(&[8]).is_err());
    }
}
