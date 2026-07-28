use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

/// `provides` bit: the announcing client offers an L3 exit.
pub const PROVIDES_EXIT: u8 = 1 << 0;
/// `provides` bit: the announcing client offers an L2 segment.
pub const PROVIDES_SEGMENT: u8 = 1 << 1;

const PROVIDES_MASK: u8 = PROVIDES_EXIT | PROVIDES_SEGMENT;

/// Outcome of a `PeerConnect`, reported to the consumer in `PeerResult`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Accepted,
    UnknownPeer,
    PeerOffline,
    NotProvided,
    PeerBusy,
}

/// The path a party settled on for a pair, reported in `PeerPath`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStatus {
    Direct,
    Relay,
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
/// control transport: 1 = tcp, 2 = udp. `fwd` is the client's announced
/// per-forward options, which cover only forwards carrying a non-default
/// option (empty until a `FwdOptions` arrives).
#[derive(Debug, Clone, PartialEq)]
pub struct ClientEntry {
    pub client_id: String,
    pub transport: u8,
    pub fwd: Vec<FwdOptionEntry>,
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

/// An L2 bridge client attached to the server's software switch, as reported in a
/// `Snapshot`. These attach over the data channel (not as routed forward clients),
/// so the fleet view sources them from the switch rather than the client registry.
/// `label` is the client's id when it announced one (`named` true) or a fallback
/// (peer address, else `bridge-<port>`). `transport` is 1 = tcp, 2 = udp. Counters
/// and `peer` are observed server-side; the bridge's negotiated WAN IP is not.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeEntry {
    pub label: String,
    pub named: bool,
    pub transport: u8,
    pub peer: String,
    pub macs: Vec<[u8; 6]>,
    pub rx_bytes: u64,
    pub rx_frames: u64,
    pub tx_bytes: u64,
    pub tx_frames: u64,
    pub uptime_secs: u32,
    pub idle_secs: u32,
}

/// A point-in-time view of one server's topology, returned to admin on request.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotBody {
    pub version: u8,
    pub server_id: String,
    pub listeners: Vec<Listener>,
    pub clients: Vec<ClientEntry>,
    pub routes: Vec<RouteEntry>,
    pub bridge_clients: Vec<BridgeEntry>,
}

/// Per-forward options a client announces for one of its public ports.
/// `idle_secs` 0 means the proto default idle window; `proxy` asks the server to
/// send `OpenProxy` (with the real peer addresses) instead of `Open` for TCP
/// connections on this port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwdOptionEntry {
    pub proto: Proto,
    pub port: u16,
    pub proxy: bool,
    pub idle_secs: u32,
}

/// Messages exchanged over the encrypted Noise channels.
///
/// Control channel (client -> server): `ClientHello`, then optionally one
/// `FwdOptions` (only when at least one forward carries a non-default option),
/// then periodic `Ping`.
/// Control channel (server -> client): `Pong` in reply to each `Ping`,
/// `FwdOptionsAck` strictly in reply to `FwdOptions` (an old client cannot
/// decode it, so it is never sent unsolicited; an old server silently ignores
/// `FwdOptions` and never acks), and `Open` for each new public connection,
/// replaced by `OpenProxy` on TCP ports the client flagged `proxy` (TCP-only by
/// construction, so it carries no proto byte).
/// Data channel (client -> server, first message): `Data` carrying the stream id.
/// Admin channel (admin -> server): `AdminHello` mode 0 -> `Snapshot`; mode 1 ->
/// one mutation message (`AddListener`/`RemoveListener`/`SetRoute`/`ClearRoute`),
/// answered by `MutationResult`.
/// Peer rendezvous (control channel): a peer-capable client sends `PeerAnnounce`
/// after `ClientHello`; the server replies `PeerAnnounceAck` (an old server never
/// acks, so an unacked announce means no peer support). A consumer sends
/// `PeerConnect`, answered by `PeerResult`; on acceptance the server sends
/// `PeerProbe` and `PeerInfo` to both parties, each party reports its punch
/// outcome with `PeerPath`, and on fallback the server sends `PeerRelayOpen`
/// to both parties.
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
        /// Client label when this `Data` opens a bridge attach; `None` for a
        /// forward-data stream, which carries no label. A bridge attach sends the
        /// client's id so the server's fleet view can name the port.
        name: Option<String>,
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
    FwdOptions {
        entries: Vec<FwdOptionEntry>,
    },
    FwdOptionsAck,
    OpenProxy {
        port: u16,
        id: u64,
        /// The public connection's real source address.
        peer: SocketAddr,
        /// The public listener address the connection arrived on.
        local: SocketAddr,
    },
    PeerAnnounce {
        /// Capability bitset: `PROVIDES_EXIT` and/or `PROVIDES_SEGMENT`; a
        /// consumer announces with no bits set.
        provides: u8,
    },
    PeerAnnounceAck {
        /// The control socket's source address as the server observed it.
        /// Diagnostic only; never a punch candidate.
        observed: SocketAddr,
    },
    PeerConnect {
        /// The provider's `client_id`.
        peer_id: String,
        /// The requested capability: exactly one provides bit.
        want: u8,
    },
    PeerResult {
        peer_id: String,
        /// The requested capability echoed back, so concurrent connects to
        /// one peer correlate.
        want: u8,
        pair_id: u64,
        status: PeerStatus,
    },
    PeerProbe {
        pair_id: u64,
        /// The other party's `client_id`.
        peer_id: String,
        /// This party's server-assigned probe id, carried in the punch
        /// probe's handshake app id.
        probe_id: u64,
        /// The pair's capability: the consumer's `want` bit, forwarded to
        /// both parties.
        provides: u8,
    },
    PeerInfo {
        pair_id: u64,
        /// The other party's punch candidates; empty when it is relay-only.
        candidates: Vec<SocketAddr>,
    },
    PeerRelayOpen {
        pair_id: u64,
        /// This party's relay leg id, claimed with `Data`.
        id: u64,
    },
    PeerPath {
        pair_id: u64,
        status: PathStatus,
    },
}

pub(crate) fn proto_byte(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 1,
        Proto::Udp => 2,
    }
}

pub(crate) fn proto_from_byte(n: u8) -> Result<Proto> {
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

/// Validate a `provides` bitset: any bit outside the defined set is rejected.
fn provides_from_byte(n: u8) -> Result<u8> {
    if n & !PROVIDES_MASK != 0 {
        return Err(format!("unknown provides byte {n}").into());
    }
    Ok(n)
}

/// Validate a requested capability: exactly one defined provides bit.
fn want_from_byte(n: u8) -> Result<u8> {
    if n & !PROVIDES_MASK != 0 || n.count_ones() != 1 {
        return Err(format!("invalid want byte {n}").into());
    }
    Ok(n)
}

fn peer_status_byte(s: PeerStatus) -> u8 {
    match s {
        PeerStatus::Accepted => 0,
        PeerStatus::UnknownPeer => 1,
        PeerStatus::PeerOffline => 2,
        PeerStatus::NotProvided => 3,
        PeerStatus::PeerBusy => 4,
    }
}

fn peer_status_from_byte(n: u8) -> Result<PeerStatus> {
    match n {
        0 => Ok(PeerStatus::Accepted),
        1 => Ok(PeerStatus::UnknownPeer),
        2 => Ok(PeerStatus::PeerOffline),
        3 => Ok(PeerStatus::NotProvided),
        4 => Ok(PeerStatus::PeerBusy),
        n => Err(format!("unknown peer status byte {n}").into()),
    }
}

fn path_status_byte(s: PathStatus) -> u8 {
    match s {
        PathStatus::Direct => 0,
        PathStatus::Relay => 1,
    }
}

fn path_status_from_byte(n: u8) -> Result<PathStatus> {
    match n {
        0 => Ok(PathStatus::Direct),
        1 => Ok(PathStatus::Relay),
        n => Err(format!("unknown path status byte {n}").into()),
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
pub(crate) fn put_str(b: &mut Vec<u8>, s: &str) {
    debug_assert!(s.len() <= u16::MAX as usize);
    b.extend_from_slice(&(s.len() as u16).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
}

/// Read a u16-length-prefixed UTF-8 string at `*at`, advancing the cursor.
/// Bounds-checks both the length prefix and the body, and validates UTF-8.
pub(crate) fn take_str(b: &[u8], at: &mut usize) -> Result<String> {
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

/// Append a socket address: a family byte (4 or 6), the raw ip octets, then the
/// port. Addresses are carried verbatim; collapsing an IPv4-mapped IPv6 address
/// is the consumer's concern, not the codec's.
fn put_sockaddr(b: &mut Vec<u8>, a: SocketAddr) {
    match a.ip() {
        IpAddr::V4(ip) => {
            b.push(4);
            b.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            b.push(6);
            b.extend_from_slice(&ip.octets());
        }
    }
    b.extend_from_slice(&a.port().to_be_bytes());
}

/// Read a socket address at `*at`, advancing the cursor. Rejects any family byte
/// other than 4 or 6 and length-guards the octets and port.
fn take_sockaddr(b: &[u8], at: &mut usize) -> Result<SocketAddr> {
    if *at >= b.len() {
        return Err("truncated address family".into());
    }
    let fam = b[*at];
    *at += 1;
    let ip: IpAddr = match fam {
        4 => {
            if *at + 4 > b.len() {
                return Err("truncated ipv4 socket address".into());
            }
            let mut o = [0u8; 4];
            o.copy_from_slice(&b[*at..*at + 4]);
            *at += 4;
            IpAddr::from(o)
        }
        6 => {
            if *at + 16 > b.len() {
                return Err("truncated ipv6 socket address".into());
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[*at..*at + 16]);
            *at += 16;
            IpAddr::from(o)
        }
        n => return Err(format!("unknown address family byte {n}").into()),
    };
    if *at + 2 > b.len() {
        return Err("truncated socket address port".into());
    }
    let port = u16::from_be_bytes([b[*at], b[*at + 1]]);
    *at += 2;
    Ok(SocketAddr::new(ip, port))
}

/// Encode a socket address as a standalone body: a family byte, the raw ip
/// octets, then the port. Carried in the probe handshake's message-2 payload
/// (the server-observed public mapping) and in the probe session's first
/// frame (the party's local candidate).
pub fn encode_sockaddr(a: SocketAddr) -> Vec<u8> {
    let mut b = Vec::with_capacity(19);
    put_sockaddr(&mut b, a);
    b
}

/// Decode a standalone socket address body written by [`encode_sockaddr`],
/// rejecting trailing bytes.
pub fn decode_sockaddr(b: &[u8]) -> Result<SocketAddr> {
    let mut at = 0;
    let a = take_sockaddr(b, &mut at)?;
    if at != b.len() {
        return Err("trailing bytes in socket address".into());
    }
    Ok(a)
}

/// Encode a forward-option list: a u16 count then the fixed 8-byte entries.
/// Shared by the `FwdOptions` body and each snapshot client's announced list;
/// the count is a u16 on the wire, so the encoded entries are capped to match
/// and the count and body never disagree.
fn put_fwd_entries(b: &mut Vec<u8>, entries: &[FwdOptionEntry]) {
    debug_assert!(entries.len() <= u16::MAX as usize);
    let entries = &entries[..entries.len().min(u16::MAX as usize)];
    b.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for e in entries {
        b.push(proto_byte(e.proto));
        b.extend_from_slice(&e.port.to_be_bytes());
        // Flags byte: bit0 = proxy; the remaining bits are reserved and must
        // stay zero (the decoder rejects them).
        b.push(u8::from(e.proxy));
        b.extend_from_slice(&e.idle_secs.to_be_bytes());
    }
}

/// Decode a forward-option list written by [`put_fwd_entries`]. Every read is
/// length-guarded and the list is grown without preallocating from the
/// untrusted count, so a malformed or truncated body errors rather than
/// panicking or over-allocating.
fn take_fwd_entries(b: &[u8], at: &mut usize) -> Result<Vec<FwdOptionEntry>> {
    if *at + 2 > b.len() {
        return Err("truncated forward options count".into());
    }
    let count = u16::from_be_bytes([b[*at], b[*at + 1]]) as usize;
    *at += 2;
    let mut entries = Vec::new();
    for _ in 0..count {
        if *at + 8 > b.len() {
            return Err("truncated forward option entry".into());
        }
        let proto = proto_from_byte(b[*at])?;
        let port = u16::from_be_bytes([b[*at + 1], b[*at + 2]]);
        let proxy = match b[*at + 3] {
            0 => false,
            1 => true,
            n => return Err(format!("unknown forward option flags byte {n}").into()),
        };
        let idle_secs = u32::from_be_bytes(b[*at + 4..*at + 8].try_into().unwrap());
        *at += 8;
        entries.push(FwdOptionEntry {
            proto,
            port,
            proxy,
            idle_secs,
        });
    }
    Ok(entries)
}

/// Decode the bridge-client trailer that follows the routes in a snapshot: a u16
/// count followed by that many entries. Every multi-byte read is length-guarded
/// first, the count is u16-bounded, and the list is grown without preallocating
/// from the untrusted count, so a malformed or truncated body errors rather than
/// panicking or over-allocating. The caller still rejects any bytes left over.
fn decode_bridge_clients(b: &[u8], at: &mut usize) -> Result<Vec<BridgeEntry>> {
    if *at + 2 > b.len() {
        return Err("truncated bridge count".into());
    }
    let count = u16::from_be_bytes([b[*at], b[*at + 1]]) as usize;
    *at += 2;
    let mut out = Vec::new();
    for _ in 0..count {
        let label = take_str(b, at)?;
        if *at >= b.len() {
            return Err("truncated bridge named flag".into());
        }
        let named = match b[*at] {
            0 => false,
            1 => true,
            n => return Err(format!("unknown bridge named byte {n}").into()),
        };
        *at += 1;
        if *at >= b.len() {
            return Err("truncated bridge transport".into());
        }
        let transport = b[*at];
        *at += 1;
        if transport != 1 && transport != 2 {
            return Err(format!("unknown transport byte {transport}").into());
        }
        let peer = take_str(b, at)?;
        if *at + 2 > b.len() {
            return Err("truncated bridge mac count".into());
        }
        let mac_count = u16::from_be_bytes([b[*at], b[*at + 1]]) as usize;
        *at += 2;
        let mut macs = Vec::new();
        for _ in 0..mac_count {
            if *at + 6 > b.len() {
                return Err("truncated bridge mac".into());
            }
            let mut m = [0u8; 6];
            m.copy_from_slice(&b[*at..*at + 6]);
            *at += 6;
            macs.push(m);
        }
        if *at + 40 > b.len() {
            return Err("truncated bridge counters".into());
        }
        let rx_bytes = u64::from_be_bytes(b[*at..*at + 8].try_into().unwrap());
        *at += 8;
        let rx_frames = u64::from_be_bytes(b[*at..*at + 8].try_into().unwrap());
        *at += 8;
        let tx_bytes = u64::from_be_bytes(b[*at..*at + 8].try_into().unwrap());
        *at += 8;
        let tx_frames = u64::from_be_bytes(b[*at..*at + 8].try_into().unwrap());
        *at += 8;
        let uptime_secs = u32::from_be_bytes(b[*at..*at + 4].try_into().unwrap());
        *at += 4;
        let idle_secs = u32::from_be_bytes(b[*at..*at + 4].try_into().unwrap());
        *at += 4;
        out.push(BridgeEntry {
            label,
            named,
            transport,
            peer,
            macs,
            rx_bytes,
            rx_frames,
            tx_bytes,
            tx_frames,
            uptime_secs,
            idle_secs,
        });
    }
    Ok(out)
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
            Msg::Data { id, name } => {
                let mut b = Vec::with_capacity(9);
                b.push(3);
                b.extend_from_slice(&id.to_be_bytes());
                if let Some(name) = name {
                    put_str(&mut b, name);
                }
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
                    put_fwd_entries(&mut b, &c.fwd);
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
                // Bridge-client trailer: a u16 count then that many entries (the
                // count is 0 when no bridge clients are attached).
                debug_assert!(snap.bridge_clients.len() <= u16::MAX as usize);
                b.extend_from_slice(&(snap.bridge_clients.len() as u16).to_be_bytes());
                for e in &snap.bridge_clients {
                    put_str(&mut b, &e.label);
                    b.push(u8::from(e.named));
                    b.push(e.transport);
                    put_str(&mut b, &e.peer);
                    debug_assert!(e.macs.len() <= u16::MAX as usize);
                    b.extend_from_slice(&(e.macs.len() as u16).to_be_bytes());
                    for m in &e.macs {
                        b.extend_from_slice(m);
                    }
                    b.extend_from_slice(&e.rx_bytes.to_be_bytes());
                    b.extend_from_slice(&e.rx_frames.to_be_bytes());
                    b.extend_from_slice(&e.tx_bytes.to_be_bytes());
                    b.extend_from_slice(&e.tx_frames.to_be_bytes());
                    b.extend_from_slice(&e.uptime_secs.to_be_bytes());
                    b.extend_from_slice(&e.idle_secs.to_be_bytes());
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
            Msg::FwdOptions { entries } => {
                let mut b = Vec::with_capacity(3 + entries.len() * 8);
                b.push(13);
                put_fwd_entries(&mut b, entries);
                b
            }
            Msg::FwdOptionsAck => vec![14],
            Msg::OpenProxy {
                port,
                id,
                peer,
                local,
            } => {
                let mut b = Vec::with_capacity(49);
                b.push(15);
                b.extend_from_slice(&port.to_be_bytes());
                b.extend_from_slice(&id.to_be_bytes());
                put_sockaddr(&mut b, *peer);
                put_sockaddr(&mut b, *local);
                b
            }
            Msg::PeerAnnounce { provides } => vec![16, *provides],
            Msg::PeerAnnounceAck { observed } => {
                let mut b = Vec::with_capacity(20);
                b.push(17);
                put_sockaddr(&mut b, *observed);
                b
            }
            Msg::PeerConnect { peer_id, want } => {
                let mut b = Vec::new();
                b.push(18);
                put_str(&mut b, peer_id);
                b.push(*want);
                b
            }
            Msg::PeerResult {
                peer_id,
                want,
                pair_id,
                status,
            } => {
                let mut b = Vec::new();
                b.push(19);
                put_str(&mut b, peer_id);
                b.push(*want);
                b.extend_from_slice(&pair_id.to_be_bytes());
                b.push(peer_status_byte(*status));
                b
            }
            Msg::PeerProbe {
                pair_id,
                peer_id,
                probe_id,
                provides,
            } => {
                let mut b = Vec::new();
                b.push(20);
                b.extend_from_slice(&pair_id.to_be_bytes());
                put_str(&mut b, peer_id);
                b.extend_from_slice(&probe_id.to_be_bytes());
                b.push(*provides);
                b
            }
            Msg::PeerInfo {
                pair_id,
                candidates,
            } => {
                let mut b = Vec::new();
                b.push(21);
                b.extend_from_slice(&pair_id.to_be_bytes());
                debug_assert!(candidates.len() <= u16::MAX as usize);
                b.extend_from_slice(&(candidates.len() as u16).to_be_bytes());
                for c in candidates {
                    put_sockaddr(&mut b, *c);
                }
                b
            }
            Msg::PeerRelayOpen { pair_id, id } => {
                let mut b = Vec::with_capacity(17);
                b.push(22);
                b.extend_from_slice(&pair_id.to_be_bytes());
                b.extend_from_slice(&id.to_be_bytes());
                b
            }
            Msg::PeerPath { pair_id, status } => {
                let mut b = Vec::with_capacity(10);
                b.push(23);
                b.extend_from_slice(&pair_id.to_be_bytes());
                b.push(path_status_byte(*status));
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
            Some(3) if b.len() >= 9 => {
                let id = u64::from_be_bytes(b[1..9].try_into().unwrap());
                let name = if b.len() == 9 {
                    None
                } else {
                    let mut at = 9;
                    let name = take_str(b, &mut at)?;
                    if at != b.len() {
                        return Err("trailing bytes in data".into());
                    }
                    Some(name)
                };
                Ok(Msg::Data { id, name })
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
                    let fwd = take_fwd_entries(b, &mut at)?;
                    clients.push(ClientEntry {
                        client_id,
                        transport,
                        fwd,
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
                let bridge_clients = decode_bridge_clients(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in snapshot".into());
                }
                Ok(Msg::Snapshot(SnapshotBody {
                    version,
                    server_id,
                    listeners,
                    clients,
                    routes,
                    bridge_clients,
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
            Some(13) => {
                let mut at = 1;
                let entries = take_fwd_entries(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in forward options".into());
                }
                Ok(Msg::FwdOptions { entries })
            }
            Some(14) if b.len() == 1 => Ok(Msg::FwdOptionsAck),
            Some(15) => {
                if b.len() < 11 {
                    return Err("truncated proxy open".into());
                }
                let port = u16::from_be_bytes([b[1], b[2]]);
                let id = u64::from_be_bytes(b[3..11].try_into().unwrap());
                let mut at = 11;
                let peer = take_sockaddr(b, &mut at)?;
                let local = take_sockaddr(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in proxy open".into());
                }
                Ok(Msg::OpenProxy {
                    port,
                    id,
                    peer,
                    local,
                })
            }
            Some(16) if b.len() == 2 => {
                let provides = provides_from_byte(b[1])?;
                Ok(Msg::PeerAnnounce { provides })
            }
            Some(17) => {
                let mut at = 1;
                let observed = take_sockaddr(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in peer announce ack".into());
                }
                Ok(Msg::PeerAnnounceAck { observed })
            }
            Some(18) => {
                let mut at = 1;
                let peer_id = take_str(b, &mut at)?;
                if at >= b.len() {
                    return Err("truncated peer connect".into());
                }
                let want = want_from_byte(b[at])?;
                at += 1;
                if at != b.len() {
                    return Err("trailing bytes in peer connect".into());
                }
                Ok(Msg::PeerConnect { peer_id, want })
            }
            Some(19) => {
                let mut at = 1;
                let peer_id = take_str(b, &mut at)?;
                if at + 10 > b.len() {
                    return Err("truncated peer result".into());
                }
                let want = want_from_byte(b[at])?;
                let pair_id = u64::from_be_bytes(b[at + 1..at + 9].try_into().unwrap());
                let status = peer_status_from_byte(b[at + 9])?;
                at += 10;
                if at != b.len() {
                    return Err("trailing bytes in peer result".into());
                }
                Ok(Msg::PeerResult {
                    peer_id,
                    want,
                    pair_id,
                    status,
                })
            }
            Some(20) => {
                if b.len() < 9 {
                    return Err("truncated peer probe".into());
                }
                let pair_id = u64::from_be_bytes(b[1..9].try_into().unwrap());
                let mut at = 9;
                let peer_id = take_str(b, &mut at)?;
                if at + 9 > b.len() {
                    return Err("truncated peer probe".into());
                }
                let probe_id = u64::from_be_bytes(b[at..at + 8].try_into().unwrap());
                let provides = want_from_byte(b[at + 8])?;
                at += 9;
                if at != b.len() {
                    return Err("trailing bytes in peer probe".into());
                }
                Ok(Msg::PeerProbe {
                    pair_id,
                    peer_id,
                    probe_id,
                    provides,
                })
            }
            Some(21) => {
                if b.len() < 11 {
                    return Err("truncated peer info".into());
                }
                let pair_id = u64::from_be_bytes(b[1..9].try_into().unwrap());
                let count = u16::from_be_bytes([b[9], b[10]]) as usize;
                let mut at = 11;
                let mut candidates = Vec::new();
                for _ in 0..count {
                    candidates.push(take_sockaddr(b, &mut at)?);
                }
                if at != b.len() {
                    return Err("trailing bytes in peer info".into());
                }
                Ok(Msg::PeerInfo {
                    pair_id,
                    candidates,
                })
            }
            Some(22) if b.len() == 17 => {
                let pair_id = u64::from_be_bytes(b[1..9].try_into().unwrap());
                let id = u64::from_be_bytes(b[9..17].try_into().unwrap());
                Ok(Msg::PeerRelayOpen { pair_id, id })
            }
            Some(23) if b.len() == 10 => {
                let pair_id = u64::from_be_bytes(b[1..9].try_into().unwrap());
                let status = path_status_from_byte(b[9])?;
                Ok(Msg::PeerPath { pair_id, status })
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
                    fwd: vec![
                        FwdOptionEntry {
                            proto: Proto::Tcp,
                            port: 443,
                            proxy: true,
                            idle_secs: 600,
                        },
                        FwdOptionEntry {
                            proto: Proto::Udp,
                            port: 51820,
                            proxy: false,
                            idle_secs: 300,
                        },
                    ],
                },
                ClientEntry {
                    client_id: "rpi-2-cd34".into(),
                    transport: 2,
                    fwd: Vec::new(),
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
            bridge_clients: vec![
                BridgeEntry {
                    label: "rpi-3-ef56".into(),
                    named: true,
                    transport: 1,
                    peer: "203.0.113.5:51820".into(),
                    macs: vec![[0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2]],
                    rx_bytes: 18_874_368,
                    rx_frames: 24_010,
                    tx_bytes: 9_437_184,
                    tx_frames: 19_004,
                    uptime_secs: 252,
                    idle_secs: 0,
                },
                BridgeEntry {
                    label: "bridge-7".into(),
                    named: false,
                    transport: 2,
                    peer: String::new(),
                    macs: Vec::new(),
                    rx_bytes: 0,
                    rx_frames: 0,
                    tx_bytes: 0,
                    tx_frames: 0,
                    uptime_secs: 2,
                    idle_secs: 2,
                },
            ],
        };
        match roundtrip(&Msg::Snapshot(body.clone())) {
            Msg::Snapshot(decoded) => assert_eq!(decoded, body),
            other => panic!("expected snapshot, got {other:?}"),
        }

        let empty = SnapshotBody {
            version: 2,
            server_id: "srv".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
            bridge_clients: Vec::new(),
        };
        match roundtrip(&Msg::Snapshot(empty.clone())) {
            Msg::Snapshot(decoded) => assert_eq!(decoded, empty),
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    /// The bridge trailer is mandatory: a snapshot whose bytes end at the routes
    /// (no trailer) is malformed and must error, not decode to an empty fleet.
    #[test]
    fn snapshot_missing_trailer_errors() {
        let body = SnapshotBody {
            version: 1,
            server_id: "srv".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
            bridge_clients: Vec::new(),
        };
        let mut bytes = Msg::Snapshot(body).encode();
        assert_eq!(&bytes[bytes.len() - 2..], &[0, 0]);
        bytes.truncate(bytes.len() - 2);
        assert!(Msg::decode(&bytes).is_err());
    }

    #[test]
    fn data_carries_optional_name() {
        // A forward-data frame carries no label: 9 bytes, decodes to None.
        let bare = Msg::Data { id: 7, name: None };
        let enc = bare.encode();
        assert_eq!(enc.len(), 9);
        match Msg::decode(&enc) {
            Ok(Msg::Data { id, name }) => {
                assert_eq!(id, 7);
                assert!(name.is_none());
            }
            other => panic!("expected data, got {other:?}"),
        }
        // A named frame roundtrips.
        let named = Msg::Data {
            id: u64::MAX,
            name: Some("br-1a2b".into()),
        };
        match roundtrip(&named) {
            Msg::Data { id, name } => {
                assert_eq!(id, u64::MAX);
                assert_eq!(name.as_deref(), Some("br-1a2b"));
            }
            other => panic!("expected data, got {other:?}"),
        }
        // A truncated name length prefix and trailing junk after a valid name both
        // error rather than panic.
        assert!(Msg::decode(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let mut bad = Msg::Data {
            id: 1,
            name: Some("x".into()),
        }
        .encode();
        bad.push(0xAA);
        assert!(Msg::decode(&bad).is_err());
    }

    /// Every malformed bridge trailer must error, never panic (panic=abort).
    #[test]
    fn snapshot_bridge_trailer_rejects_malformed() {
        let entry = BridgeEntry {
            label: "a".into(),
            named: true,
            transport: 1,
            peer: "p".into(),
            macs: vec![[1, 2, 3, 4, 5, 6]],
            rx_bytes: 1,
            rx_frames: 1,
            tx_bytes: 1,
            tx_frames: 1,
            uptime_secs: 1,
            idle_secs: 0,
        };
        let mk = |bridge: Vec<BridgeEntry>| {
            Msg::Snapshot(SnapshotBody {
                version: 2,
                server_id: "s".into(),
                listeners: Vec::new(),
                clients: Vec::new(),
                routes: Vec::new(),
                bridge_clients: bridge,
            })
        };
        let good = mk(vec![entry]).encode();
        // The trailer's bridge-count begins right after the routes: the same body
        // with an empty fleet ends with that 2-byte zero count.
        let trailer_at = mk(Vec::new()).encode().len() - 2;

        // Truncating anywhere inside the populated trailer (past the count
        // boundary) must error, never panic.
        for cut in trailer_at + 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        // Trailing junk after a valid v2 body is rejected.
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // A bridge count larger than the remaining bytes errors, not over-reads.
        let mut big = good.clone();
        big[trailer_at] = 0xff;
        big[trailer_at + 1] = 0xff;
        assert!(Msg::decode(&big).is_err());
        // The transport byte sits after the count, the label (2-byte len + "a"),
        // and the 1-byte named flag. A value outside {1,2} errors.
        let transport_at = trailer_at + 2 + 3 + 1;
        let mut bad_transport = good.clone();
        bad_transport[transport_at] = 9;
        assert!(Msg::decode(&bad_transport).is_err());
        // The named flag (only 0 or 1) is the byte just before transport.
        let mut bad_named = good.clone();
        bad_named[transport_at - 1] = 2;
        assert!(Msg::decode(&bad_named).is_err());
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
                fwd: Vec::new(),
            }],
            routes: Vec::new(),
            bridge_clients: Vec::new(),
        })
        .encode();
        // The trailing six bytes are the zero forward-option, route, and bridge
        // counts; back up past them to the client transport byte and corrupt it.
        let n = snap.len();
        snap[n - 7] = 3;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a bad listener source byte (5). A single listener and no
        // clients/routes puts the listener source byte before the three zero
        // counts (client + route + bridge), i.e. seven bytes from the end.
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
            bridge_clients: Vec::new(),
        })
        .encode();
        let n = snap.len();
        snap[n - 7] = 5;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a bad route source byte (7). A single route and no
        // clients/listeners puts the route source byte just before the two zero
        // bridge-count bytes, i.e. three bytes from the end.
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
            bridge_clients: Vec::new(),
        })
        .encode();
        let n = snap.len();
        snap[n - 3] = 7;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a client forward-option flags byte carrying reserved bits
        // (2). A single client with one entry and nothing else puts the flags
        // byte before the entry's idle u32 and the two zero route-count and
        // bridge-count bytes, i.e. nine bytes from the end.
        let mut snap = Msg::Snapshot(SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: Vec::new(),
            clients: vec![ClientEntry {
                client_id: "rpi".into(),
                transport: 1,
                fwd: vec![FwdOptionEntry {
                    proto: Proto::Tcp,
                    port: 443,
                    proxy: true,
                    idle_secs: 0,
                }],
            }],
            routes: Vec::new(),
            bridge_clients: Vec::new(),
        })
        .encode();
        let n = snap.len();
        snap[n - 9] = 2;
        assert!(Msg::decode(&snap).is_err());
    }

    #[test]
    fn fwd_options_roundtrip() {
        let entries = vec![
            FwdOptionEntry {
                proto: Proto::Tcp,
                port: 443,
                proxy: true,
                idle_secs: 0,
            },
            FwdOptionEntry {
                proto: Proto::Tcp,
                port: 8443,
                proxy: true,
                idle_secs: 600,
            },
            FwdOptionEntry {
                proto: Proto::Udp,
                port: 51820,
                proxy: false,
                idle_secs: 300,
            },
        ];
        match roundtrip(&Msg::FwdOptions {
            entries: entries.clone(),
        }) {
            Msg::FwdOptions { entries: got } => assert_eq!(got, entries),
            other => panic!("expected fwd options, got {other:?}"),
        }
        match roundtrip(&Msg::FwdOptions {
            entries: Vec::new(),
        }) {
            Msg::FwdOptions { entries: got } => assert!(got.is_empty()),
            other => panic!("expected fwd options, got {other:?}"),
        }
    }

    #[test]
    fn fwd_options_rejects_malformed() {
        let good = Msg::FwdOptions {
            entries: vec![FwdOptionEntry {
                proto: Proto::Tcp,
                port: 443,
                proxy: true,
                idle_secs: 600,
            }],
        }
        .encode();
        assert_eq!(good.len(), 11);
        // Any truncation errors, never panics.
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        // Trailing junk after a valid body.
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // A count larger than the remaining bytes.
        let mut big = good.clone();
        big[1] = 0xff;
        big[2] = 0xff;
        assert!(Msg::decode(&big).is_err());
        // A flags byte with a reserved bit set.
        let mut bad_flags = good.clone();
        bad_flags[6] = 0x02;
        assert!(Msg::decode(&bad_flags).is_err());
        // An unknown proto byte.
        let mut bad_proto = good.clone();
        bad_proto[3] = 9;
        assert!(Msg::decode(&bad_proto).is_err());
    }

    #[test]
    fn fwd_options_ack_exact() {
        let enc = Msg::FwdOptionsAck.encode();
        assert_eq!(enc, vec![14]);
        assert!(matches!(Msg::decode(&enc), Ok(Msg::FwdOptionsAck)));
        // Any other length is malformed.
        assert!(Msg::decode(&[14, 0]).is_err());
    }

    #[test]
    fn open_proxy_roundtrip() {
        let pairs: [(SocketAddr, SocketAddr); 3] = [
            (
                "203.0.113.5:51820".parse().unwrap(),
                "198.51.100.1:443".parse().unwrap(),
            ),
            (
                "[2001:db8::1]:4000".parse().unwrap(),
                "[2001:db8::2]:8443".parse().unwrap(),
            ),
            (
                "203.0.113.5:51820".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
            ),
        ];
        for (peer, local) in pairs {
            match roundtrip(&Msg::OpenProxy {
                port: 443,
                id: u64::MAX,
                peer,
                local,
            }) {
                Msg::OpenProxy {
                    port,
                    id,
                    peer: p,
                    local: l,
                } => {
                    assert_eq!(port, 443);
                    assert_eq!(id, u64::MAX);
                    assert_eq!(p, peer);
                    assert_eq!(l, local);
                }
                other => panic!("expected open proxy, got {other:?}"),
            }
        }
    }

    #[test]
    fn open_proxy_rejects_malformed() {
        let good = Msg::OpenProxy {
            port: 443,
            id: 7,
            peer: "203.0.113.5:51820".parse().unwrap(),
            local: "[2001:db8::2]:443".parse().unwrap(),
        }
        .encode();
        // 1 tag + 2 port + 8 id + 7 (v4 addr) + 19 (v6 addr).
        assert_eq!(good.len(), 37);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // The peer's family byte sits right after the port and id.
        let mut bad_family = good.clone();
        bad_family[11] = 5;
        assert!(Msg::decode(&bad_family).is_err());
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

        let data = Msg::Data { id: 42, name: None };
        let bytes = data.encode();
        assert_eq!(bytes.len(), 9);
        match Msg::decode(&bytes).unwrap() {
            Msg::Data { id, name } => {
                assert_eq!(id, 42);
                assert!(name.is_none());
            }
            other => panic!("expected data, got {other:?}"),
        }

        // Hello (tag 0) is gone: byte 0 must decode to Err.
        assert!(Msg::decode(&[0]).is_err());
    }

    #[test]
    fn peer_announce_roundtrip() {
        for provides in [0, PROVIDES_EXIT, PROVIDES_SEGMENT, PROVIDES_MASK] {
            let enc = Msg::PeerAnnounce { provides }.encode();
            assert_eq!(enc, vec![16, provides]);
            match Msg::decode(&enc).unwrap() {
                Msg::PeerAnnounce { provides: got } => assert_eq!(got, provides),
                other => panic!("expected peer announce, got {other:?}"),
            }
        }
        // Truncated, trailing, and undefined-bit bodies all error.
        assert!(Msg::decode(&[16]).is_err());
        assert!(Msg::decode(&[16, 0, 0]).is_err());
        assert!(Msg::decode(&[16, 0x04]).is_err());
        assert!(Msg::decode(&[16, 0xff]).is_err());
        // The tag after the peer block is still unknown.
        assert!(Msg::decode(&[24]).is_err());
    }

    #[test]
    fn peer_announce_ack_roundtrip() {
        let addrs: [SocketAddr; 2] = [
            "203.0.113.5:51820".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
        ];
        for observed in addrs {
            match roundtrip(&Msg::PeerAnnounceAck { observed }) {
                Msg::PeerAnnounceAck { observed: got } => assert_eq!(got, observed),
                other => panic!("expected peer announce ack, got {other:?}"),
            }
        }
        let good = Msg::PeerAnnounceAck {
            observed: "203.0.113.5:51820".parse().unwrap(),
        }
        .encode();
        // 1 tag + 7 (v4 addr).
        assert_eq!(good.len(), 8);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // An unknown address family byte.
        let mut bad_family = good.clone();
        bad_family[1] = 5;
        assert!(Msg::decode(&bad_family).is_err());
    }

    #[test]
    fn peer_connect_roundtrip() {
        let max = "x".repeat(u16::MAX as usize);
        for id in ["office-b1c2", "", max.as_str()] {
            for want in [PROVIDES_EXIT, PROVIDES_SEGMENT] {
                let m = Msg::PeerConnect {
                    peer_id: id.into(),
                    want,
                };
                match roundtrip(&m) {
                    Msg::PeerConnect { peer_id, want: got } => {
                        assert_eq!(peer_id, id);
                        assert_eq!(got, want);
                    }
                    other => panic!("expected peer connect, got {other:?}"),
                }
            }
        }
        // Truncated length prefix, truncated body, a missing want byte, and
        // trailing junk all error.
        assert!(Msg::decode(&[18, 0]).is_err());
        assert!(Msg::decode(&[18, 0, 4, b'a', b'b']).is_err());
        assert!(Msg::decode(&[18, 0, 2, b'a', b'b']).is_err());
        let mut junk = Msg::PeerConnect {
            peer_id: "ok".into(),
            want: PROVIDES_EXIT,
        }
        .encode();
        junk.push(0xff);
        assert!(Msg::decode(&junk).is_err());
        // The want byte must be exactly one defined bit: zero bits, both bits,
        // and an undefined bit all error.
        for want in [0x00, PROVIDES_MASK, 0x04] {
            assert!(Msg::decode(&[18, 0, 1, b'a', want]).is_err());
        }
    }

    #[test]
    fn peer_result_roundtrip() {
        for status in [
            PeerStatus::Accepted,
            PeerStatus::UnknownPeer,
            PeerStatus::PeerOffline,
            PeerStatus::NotProvided,
            PeerStatus::PeerBusy,
        ] {
            for want in [PROVIDES_EXIT, PROVIDES_SEGMENT] {
                let m = Msg::PeerResult {
                    peer_id: "office-b1c2".into(),
                    want,
                    pair_id: u64::MAX,
                    status,
                };
                match roundtrip(&m) {
                    Msg::PeerResult {
                        peer_id,
                        want: got_want,
                        pair_id,
                        status: got,
                    } => {
                        assert_eq!(peer_id, "office-b1c2");
                        assert_eq!(got_want, want);
                        assert_eq!(pair_id, u64::MAX);
                        assert_eq!(got, status);
                    }
                    other => panic!("expected peer result, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn peer_result_rejects_malformed() {
        let good = Msg::PeerResult {
            peer_id: "a".into(),
            want: PROVIDES_EXIT,
            pair_id: 7,
            status: PeerStatus::Accepted,
        }
        .encode();
        // 1 tag + 3 (peer_id) + 1 want + 8 pair_id + 1 status.
        assert_eq!(good.len(), 14);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // An unknown status byte (the last byte) errors.
        let mut bad_status = good.clone();
        bad_status[13] = 5;
        assert!(Msg::decode(&bad_status).is_err());
        // The want byte follows the peer_id: zero bits, both bits, and an
        // undefined bit all error.
        for want in [0x00, PROVIDES_MASK, 0x04] {
            let mut bad_want = good.clone();
            bad_want[4] = want;
            assert!(Msg::decode(&bad_want).is_err());
        }
    }

    #[test]
    fn peer_probe_roundtrip() {
        for want in [PROVIDES_EXIT, PROVIDES_SEGMENT] {
            let m = Msg::PeerProbe {
                pair_id: 3,
                peer_id: "office-b1c2".into(),
                probe_id: u64::MAX,
                provides: want,
            };
            match roundtrip(&m) {
                Msg::PeerProbe {
                    pair_id,
                    peer_id,
                    probe_id,
                    provides,
                } => {
                    assert_eq!(pair_id, 3);
                    assert_eq!(peer_id, "office-b1c2");
                    assert_eq!(probe_id, u64::MAX);
                    assert_eq!(provides, want);
                }
                other => panic!("expected peer probe, got {other:?}"),
            }
        }
    }

    #[test]
    fn peer_probe_rejects_malformed() {
        let good = Msg::PeerProbe {
            pair_id: 3,
            peer_id: "a".into(),
            probe_id: 4,
            provides: PROVIDES_EXIT,
        }
        .encode();
        // 1 tag + 8 pair_id + 3 (peer_id) + 8 probe_id + 1 provides.
        assert_eq!(good.len(), 21);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // The pair capability (the last byte) must be exactly one defined bit:
        // zero bits, both bits, and an undefined bit all error.
        for provides in [0x00, PROVIDES_MASK, 0x04] {
            let mut bad_provides = good.clone();
            bad_provides[20] = provides;
            assert!(Msg::decode(&bad_provides).is_err());
        }
    }

    #[test]
    fn peer_info_roundtrip() {
        let candidates: Vec<SocketAddr> = vec![
            "203.0.113.5:51820".parse().unwrap(),
            "192.168.1.20:40000".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
        ];
        match roundtrip(&Msg::PeerInfo {
            pair_id: 9,
            candidates: candidates.clone(),
        }) {
            Msg::PeerInfo {
                pair_id,
                candidates: got,
            } => {
                assert_eq!(pair_id, 9);
                assert_eq!(got, candidates);
            }
            other => panic!("expected peer info, got {other:?}"),
        }
        // A relay-only peer has no candidates.
        match roundtrip(&Msg::PeerInfo {
            pair_id: 9,
            candidates: Vec::new(),
        }) {
            Msg::PeerInfo {
                pair_id,
                candidates: got,
            } => {
                assert_eq!(pair_id, 9);
                assert!(got.is_empty());
            }
            other => panic!("expected peer info, got {other:?}"),
        }
    }

    #[test]
    fn peer_info_rejects_malformed() {
        let good = Msg::PeerInfo {
            pair_id: 9,
            candidates: vec![
                "203.0.113.5:51820".parse().unwrap(),
                "[2001:db8::1]:4000".parse().unwrap(),
            ],
        }
        .encode();
        // 1 tag + 8 pair_id + 2 count + 7 (v4 addr) + 19 (v6 addr).
        assert_eq!(good.len(), 37);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // A count larger than the remaining bytes errors, not over-reads.
        let mut big = good.clone();
        big[9] = 0xff;
        big[10] = 0xff;
        assert!(Msg::decode(&big).is_err());
        // The first candidate's family byte sits right after the count.
        let mut bad_family = good.clone();
        bad_family[11] = 5;
        assert!(Msg::decode(&bad_family).is_err());
    }

    #[test]
    fn peer_relay_open_roundtrip() {
        let m = Msg::PeerRelayOpen {
            pair_id: 9,
            id: u64::MAX,
        };
        let enc = m.encode();
        assert_eq!(enc.len(), 17);
        match Msg::decode(&enc).unwrap() {
            Msg::PeerRelayOpen { pair_id, id } => {
                assert_eq!(pair_id, 9);
                assert_eq!(id, u64::MAX);
            }
            other => panic!("expected peer relay open, got {other:?}"),
        }
        // Any other length is malformed.
        assert!(Msg::decode(&enc[..16]).is_err());
        let mut junk = enc.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
    }

    #[test]
    fn peer_path_roundtrip() {
        for status in [PathStatus::Direct, PathStatus::Relay] {
            let m = Msg::PeerPath { pair_id: 9, status };
            let enc = m.encode();
            assert_eq!(enc.len(), 10);
            match Msg::decode(&enc).unwrap() {
                Msg::PeerPath {
                    pair_id,
                    status: got,
                } => {
                    assert_eq!(pair_id, 9);
                    assert_eq!(got, status);
                }
                other => panic!("expected peer path, got {other:?}"),
            }
        }
        // Any other length is malformed, and an unknown status byte errors.
        let enc = Msg::PeerPath {
            pair_id: 9,
            status: PathStatus::Direct,
        }
        .encode();
        assert!(Msg::decode(&enc[..9]).is_err());
        let mut junk = enc.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        let mut bad_status = enc.clone();
        bad_status[9] = 2;
        assert!(Msg::decode(&bad_status).is_err());
    }

    #[test]
    fn sockaddr_body_roundtrip() {
        for addr in ["203.0.113.9:41641", "0.0.0.0:0", "[2001:db8::7]:9"] {
            let a: SocketAddr = addr.parse().unwrap();
            assert_eq!(decode_sockaddr(&encode_sockaddr(a)).unwrap(), a);
        }
    }

    #[test]
    fn sockaddr_body_rejects_malformed() {
        let good = encode_sockaddr("198.51.100.3:53".parse().unwrap());
        for cut in 0..good.len() {
            assert!(
                decode_sockaddr(&good[..cut]).is_err(),
                "cut {cut} should error"
            );
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(decode_sockaddr(&junk).is_err());
        let mut bad_family = good;
        bad_family[0] = 5;
        assert!(decode_sockaddr(&bad_family).is_err());
    }
}
