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
pub const CAPABILITY_LEN: usize = 32;
pub type Capability = [u8; CAPABILITY_LEN];

/// A peer's public identity: the x25519 public key of its static key. Written
/// as 64 hex characters wherever a peer is named in config or log lines;
/// public, never redacted.
pub const PEER_IDENTITY_LEN: usize = 32;
pub type PeerIdentity = [u8; PEER_IDENTITY_LEN];

/// Outcome of a `PeerConnect`, reported to the consumer in `PeerResult`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Accepted,
    UnknownPeer,
    PeerOffline,
    NotProvided,
    PeerBusy,
    /// The server could not allocate the pair.
    ServerFailure,
}

/// The path a party settled on for a pair, reported in `PeerPath`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStatus {
    Direct,
    Relay,
}

/// Why a peer claim was refused or withdrawn, reported in
/// `PeerAnnounceRefuse`: at the announce exchange, or later when another
/// session's proof displaces a standing claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRefuseReason {
    /// The announced identity is not a usable x25519 public key.
    MalformedIdentity,
    /// The proof did not demonstrate possession of the announced identity.
    FailedProof,
    /// The server could not mint a challenge for the announce.
    ChallengeFailed,
    /// Another session proved possession of the identity, displacing this
    /// claim.
    IdentityClaimed,
}

impl std::fmt::Display for PeerRefuseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PeerRefuseReason::MalformedIdentity => "malformed identity",
            PeerRefuseReason::FailedProof => "failed proof",
            PeerRefuseReason::ChallengeFailed => "challenge failed",
            PeerRefuseReason::IdentityClaimed => "identity claimed by another session",
        })
    }
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

/// An accepted rendezvous pair, as reported in a `Snapshot`. `want` is the
/// capability the pair carries. `path` is the path the two parties settled on:
/// relay once the server opened one, direct once both parties reported a
/// punched session, and `None` while the pair is still pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairEntry {
    pub consumer_id: String,
    pub provider_id: String,
    pub want: u8,
    pub path: Option<PathStatus>,
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
    pub pairs: Vec<PairEntry>,
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
/// Data channel (client -> server, first message): `Data` carrying the protocol
/// version and stream id.
/// Admin channel (admin -> server): `AdminHello` mode 0 -> `Snapshot`; mode 1 ->
/// one mutation message (`AddListener`/`RemoveListener`/`SetRoute`/`ClearRoute`),
/// answered by `MutationResult`.
/// Peer rendezvous (control channel): a peer-capable client sends `PeerAnnounce`
/// after `ClientHello`; the server answers `PeerChallenge`, the client proves
/// possession of the announced identity with `PeerProof`, and the server
/// replies `PeerAnnounceAck` or `PeerAnnounceRefuse` (an old server never
/// answers, so an unanswered announce means no peer support). A consumer sends
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
        capability: Capability,
    },
    Data {
        version: u8,
        id: u64,
        capability: Capability,
    },
    Pong,
    ClientHello {
        version: u8,
        client_id: String,
    },
    ClientHelloAck {
        client_id: String,
        bridge_capability: Capability,
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
        capability: Capability,
        /// The public connection's real source address.
        peer: SocketAddr,
        /// The public listener address the connection arrived on.
        local: SocketAddr,
    },
    PeerAnnounce {
        /// Capability bitset: `PROVIDES_EXIT` and/or `PROVIDES_SEGMENT`; a
        /// consumer announces with no bits set.
        provides: u8,
        /// The announcing client's asserted peer identity.
        identity: PeerIdentity,
    },
    PeerAnnounceAck {
        /// The control socket's source address as the server observed it.
        /// Diagnostic only; never a punch candidate.
        observed: SocketAddr,
    },
    PeerChallenge {
        /// The server's fresh x25519 ephemeral public key, one per announce.
        eph_pub: [u8; 32],
        /// Random per-announce nonce, covered by the proof MAC.
        nonce: [u8; 32],
    },
    PeerProof {
        /// Keyed BLAKE2s MAC over the challenge and the announce, keyed by the
        /// x25519 shared secret between the announced identity and the
        /// challenge ephemeral.
        mac: [u8; 32],
    },
    PeerAnnounceRefuse {
        reason: PeerRefuseReason,
    },
    PeerConnect {
        /// The provider's public peer identity.
        peer_id: PeerIdentity,
        /// The requested capability: exactly one provides bit.
        want: u8,
    },
    PeerResult {
        peer_id: PeerIdentity,
        /// The requested capability echoed back, so concurrent connects to
        /// one peer correlate.
        want: u8,
        pair_id: u64,
        status: PeerStatus,
    },
    PeerProbe {
        pair_id: u64,
        /// The other party's public peer identity.
        peer_id: PeerIdentity,
        /// This party's server-assigned probe id, carried in the punch
        /// probe's handshake app id.
        probe_id: u64,
        probe_capability: Capability,
        /// Server-minted pair challenge, bound into the inner handshake's
        /// prologue by both parties.
        challenge: [u8; 32],
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
        capability: Capability,
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

pub(crate) fn source_byte(s: Source) -> u8 {
    match s {
        Source::File => 0,
        Source::Cli => 1,
        Source::Runtime => 2,
    }
}

fn peer_status_byte(s: PeerStatus) -> u8 {
    match s {
        PeerStatus::Accepted => 0,
        PeerStatus::UnknownPeer => 1,
        PeerStatus::PeerOffline => 2,
        PeerStatus::NotProvided => 3,
        PeerStatus::PeerBusy => 4,
        PeerStatus::ServerFailure => 5,
    }
}

fn refuse_reason_byte(r: PeerRefuseReason) -> u8 {
    match r {
        PeerRefuseReason::MalformedIdentity => 0,
        PeerRefuseReason::FailedProof => 1,
        PeerRefuseReason::ChallengeFailed => 2,
        PeerRefuseReason::IdentityClaimed => 3,
    }
}

fn path_status_byte(s: PathStatus) -> u8 {
    match s {
        PathStatus::Direct => 0,
        PathStatus::Relay => 1,
    }
}

/// A settled path as a snapshot field: a pair that has settled on neither path
/// gets its own value.
pub fn settled_path_byte(p: Option<PathStatus>) -> u8 {
    match p {
        None => 0,
        Some(PathStatus::Direct) => 1,
        Some(PathStatus::Relay) => 2,
    }
}

/// The path a pair settled on, as the admin views name it.
pub fn path_name(p: PathStatus) -> &'static str {
    match p {
        PathStatus::Direct => "direct",
        PathStatus::Relay => "relay",
    }
}

pub fn settled_path_from_byte(n: u8) -> Result<Option<PathStatus>> {
    SETTLED_PATHS
        .get(n as usize)
        .copied()
        .ok_or_else(|| bad_byte("unknown settled path", n))
}

/// Lowercase `PeerStatus` name for logs and refusals.
pub fn status_name(s: PeerStatus) -> &'static str {
    match s {
        PeerStatus::Accepted => "accepted",
        PeerStatus::UnknownPeer => "unknown peer",
        PeerStatus::PeerOffline => "peer offline",
        PeerStatus::NotProvided => "capability not provided",
        PeerStatus::PeerBusy => "peer busy",
        PeerStatus::ServerFailure => "server failure",
    }
}

/// Name of a single capability bit, for admin output and refusals.
pub fn provides_name(bit: u8) -> &'static str {
    match bit {
        PROVIDES_EXIT => "exit",
        PROVIDES_SEGMENT => "segment",
        _ => "peer",
    }
}

/// Lowercase protocol name for logs and admin output.
pub(crate) fn proto_name(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

/// The decode error for a byte that names nothing: `"<what> byte <n>"`.
#[inline(never)]
pub(crate) fn bad_byte(what: &str, n: u8) -> crate::Error {
    errf!("{what} byte {n}")
}

/// Append one byte.
#[inline(never)]
pub(crate) fn put_u8(b: &mut Vec<u8>, v: u8) {
    b.push(v);
}

/// Append a big-endian u16.
#[inline(never)]
pub(crate) fn put_u16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_be_bytes());
}

/// Append a big-endian u32.
#[inline(never)]
pub(crate) fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

/// Append a big-endian u64.
#[inline(never)]
pub(crate) fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_be_bytes());
}

/// Append raw bytes.
#[inline(never)]
pub(crate) fn put_bytes(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(s);
}

/// A fresh body starting with its tag byte.
#[inline(never)]
pub(crate) fn tagged(tag: u8) -> Vec<u8> {
    vec![tag]
}

/// A u16 list count, capped so the count and the encoded entries never
/// disagree; returns the number of entries to encode.
#[inline(never)]
pub(crate) fn put_count(b: &mut Vec<u8>, len: usize) -> usize {
    let count = len.min(u16::MAX as usize);
    put_u16(b, count as u16);
    count
}

/// Append a u16-length-prefixed UTF-8 string. Ids are short, well under
/// u16::MAX; the debug assert guards against a future caller violating that.
#[inline(never)]
pub(crate) fn put_str(b: &mut Vec<u8>, s: &str) {
    debug_assert!(s.len() <= u16::MAX as usize);
    put_u16(b, s.len() as u16);
    b.extend_from_slice(s.as_bytes());
}

/// Read cursor over an untrusted body. The first failure is kept in `err`
/// and every later read yields a zero value without advancing, so a decoder
/// runs straight through its fields and reports the first error at the end.
/// Multi-byte reads are preceded by a `need` check naming the field in the
/// truncation error.
pub(crate) struct Rd<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) at: usize,
    err: Option<crate::Error>,
}

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8], at: usize) -> Self {
        Rd { b, at, err: None }
    }

    /// Whether no read has failed yet.
    #[inline(never)]
    pub(crate) fn ok(&self) -> bool {
        self.err.is_none()
    }

    /// Record the first failure.
    #[inline(never)]
    pub(crate) fn fail(&mut self, e: crate::Error) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }

    /// Record the first failure, given as its message.
    #[inline(never)]
    pub(crate) fn fail_msg(&mut self, what: &'static str) {
        if self.err.is_none() {
            self.err = Some(what.into());
        }
    }

    /// The first failure, if any.
    pub(crate) fn end(&mut self) -> Result<()> {
        match self.err.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// `n` more bytes must be present, else `what` is the error.
    #[inline(never)]
    pub(crate) fn need(&mut self, n: usize, what: &'static str) {
        if self.err.is_none() && self.at + n > self.b.len() {
            self.err = Some(what.into());
        }
    }

    /// The body must end here, else `what` is the error.
    #[inline(never)]
    pub(crate) fn done(&mut self, what: &'static str) {
        if self.err.is_none() && self.at != self.b.len() {
            self.err = Some(what.into());
        }
    }

    /// The next `n` bytes, or an empty slice after a failure. The caller has
    /// checked they are present.
    #[inline(never)]
    fn take(&mut self, n: usize) -> &'a [u8] {
        if self.err.is_some() || self.at + n > self.b.len() {
            return &[];
        }
        let s = &self.b[self.at..self.at + n];
        self.at += n;
        s
    }

    #[inline(never)]
    pub(crate) fn u8(&mut self) -> u8 {
        self.take(1).first().copied().unwrap_or(0)
    }

    #[inline(never)]
    pub(crate) fn u16(&mut self) -> u16 {
        match self.take(2) {
            [a, b] => u16::from_be_bytes([*a, *b]),
            _ => 0,
        }
    }

    #[inline(never)]
    pub(crate) fn u32(&mut self) -> u32 {
        match self.take(4).try_into() {
            Ok(a) => u32::from_be_bytes(a),
            Err(_) => 0,
        }
    }

    #[inline(never)]
    pub(crate) fn u64(&mut self) -> u64 {
        match self.take(8).try_into() {
            Ok(a) => u64::from_be_bytes(a),
            Err(_) => 0,
        }
    }

    /// A u16 count preceding a list; `what` names the count in the truncation
    /// error.
    #[inline(never)]
    pub(crate) fn count(&mut self, what: &'static str) -> usize {
        self.need(2, what);
        self.u16() as usize
    }

    /// A flag byte: 0 or 1, anything else fails with `bad_byte(what, n)`.
    #[inline(never)]
    pub(crate) fn flag(&mut self, what: &'static str) -> bool {
        match self.u8() {
            0 => false,
            1 => true,
            n => {
                self.fail(bad_byte(what, n));
                false
            }
        }
    }

    /// A byte that must be one of two values, else fails with
    /// `bad_byte(what, n)`.
    #[inline(never)]
    pub(crate) fn one_of(&mut self, a: u8, b: u8, what: &'static str) -> u8 {
        let n = self.u8();
        if n != a && n != b {
            self.fail(bad_byte(what, n));
        }
        n
    }

    /// A byte below `limit`, else fails with `bad_byte(what, n)`; the enum
    /// decoders index their variant tables with it.
    #[inline(never)]
    pub(crate) fn index(&mut self, limit: u8, what: &'static str) -> usize {
        let n = self.u8();
        if n >= limit {
            self.fail(bad_byte(what, n));
            return 0;
        }
        n as usize
    }

    #[inline(never)]
    pub(crate) fn proto(&mut self) -> Proto {
        match self.one_of(1, 2, "unknown proto") {
            1 => Proto::Tcp,
            _ => Proto::Udp,
        }
    }

    #[inline(never)]
    pub(crate) fn settled_path(&mut self) -> Option<PathStatus> {
        SETTLED_PATHS[self.index(3, "unknown settled path")]
    }

    /// Read a u16-length-prefixed UTF-8 string. Bounds-checks both the length
    /// prefix and the body, and validates UTF-8.
    #[inline(never)]
    pub(crate) fn str(&mut self) -> String {
        self.need(2, "truncated string length");
        let len = self.u16() as usize;
        self.need(len, "truncated string body");
        match std::str::from_utf8(self.take(len)) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                self.fail_msg("invalid utf-8 in string");
                String::new()
            }
        }
    }

    /// Read 32 bytes. `what` names the field in the truncation error.
    #[inline(never)]
    fn arr32(&mut self, what: &str) -> [u8; 32] {
        if self.err.is_none() && self.at + 32 > self.b.len() {
            self.err = Some(errf!("truncated {what}"));
        }
        self.take(32).try_into().unwrap_or([0; 32])
    }

    /// Read 4 octets as an IPv4 address.
    #[inline(never)]
    fn ip(&mut self) -> Ipv4Addr {
        self.need(4, "truncated ipv4 address");
        Ipv4Addr::from(self.u32())
    }

    /// Read a socket address. Rejects any family byte other than 4 or 6 and
    /// length-guards the octets and port.
    #[inline(never)]
    fn sockaddr(&mut self) -> SocketAddr {
        self.need(1, "truncated address family");
        let ip: IpAddr = match self.u8() {
            4 => {
                self.need(4, "truncated ipv4 socket address");
                IpAddr::from(Ipv4Addr::from(self.u32()))
            }
            6 => {
                self.need(16, "truncated ipv6 socket address");
                let o: [u8; 16] = self.take(16).try_into().unwrap_or([0; 16]);
                IpAddr::from(o)
            }
            n => {
                self.fail(bad_byte("unknown address family", n));
                IpAddr::from([0; 4])
            }
        };
        self.need(2, "truncated socket address port");
        let port = self.u16();
        SocketAddr::new(ip, port)
    }
}

const SETTLED_PATHS: [Option<PathStatus>; 3] =
    [None, Some(PathStatus::Direct), Some(PathStatus::Relay)];
const SOURCES: [Source; 3] = [Source::File, Source::Cli, Source::Runtime];
const PEER_STATUSES: [PeerStatus; 6] = [
    PeerStatus::Accepted,
    PeerStatus::UnknownPeer,
    PeerStatus::PeerOffline,
    PeerStatus::NotProvided,
    PeerStatus::PeerBusy,
    PeerStatus::ServerFailure,
];
const REFUSE_REASONS: [PeerRefuseReason; 4] = [
    PeerRefuseReason::MalformedIdentity,
    PeerRefuseReason::FailedProof,
    PeerRefuseReason::ChallengeFailed,
    PeerRefuseReason::IdentityClaimed,
];
const PATH_STATUSES: [PathStatus; 2] = [PathStatus::Direct, PathStatus::Relay];

/// Append the 4 octets of an IPv4 address.
fn put_ip(b: &mut Vec<u8>, ip: Ipv4Addr) {
    put_u32(b, ip.into());
}

/// Append a socket address: a family byte (4 or 6), the raw ip octets, then the
/// port. Addresses are carried verbatim; collapsing an IPv4-mapped IPv6 address
/// is the consumer's concern, not the codec's.
#[inline(never)]
fn put_sockaddr(b: &mut Vec<u8>, a: SocketAddr) {
    match a.ip() {
        IpAddr::V4(ip) => {
            put_u8(b, 4);
            put_ip(b, ip);
        }
        IpAddr::V6(ip) => {
            put_u8(b, 6);
            put_bytes(b, &ip.octets());
        }
    }
    put_u16(b, a.port());
}

/// Encode a socket address as a standalone body: a family byte, the raw ip
/// octets, then the port. Carried in the probe handshake's message-2 payload
/// (the server-observed public mapping) and in the probe session's first
/// frame (the party's local candidate).
pub fn encode_sockaddr(a: SocketAddr) -> Vec<u8> {
    let mut b = Vec::new();
    put_sockaddr(&mut b, a);
    b
}

/// Decode a standalone socket address body written by [`encode_sockaddr`],
/// rejecting trailing bytes.
pub fn decode_sockaddr(b: &[u8]) -> Result<SocketAddr> {
    let mut r = Rd::new(b, 0);
    let a = r.sockaddr();
    r.done("trailing bytes in socket address");
    r.end()?;
    Ok(a)
}

/// Encode a forward-option list: a u16 count then the fixed 8-byte entries.
/// Shared by the `FwdOptions` body and each snapshot client's announced list;
/// the count is a u16 on the wire, so the encoded entries are capped to match
/// and the count and body never disagree.
#[inline(never)]
fn put_fwd_entries(b: &mut Vec<u8>, entries: &[FwdOptionEntry]) {
    debug_assert!(entries.len() <= u16::MAX as usize);
    let count = put_count(b, entries.len());
    for e in &entries[..count] {
        put_u8(b, proto_byte(e.proto));
        put_u16(b, e.port);
        // Flags byte: bit0 = proxy; the remaining bits are reserved and must
        // stay zero (the decoder rejects them).
        put_u8(b, u8::from(e.proxy));
        put_u32(b, e.idle_secs);
    }
}

/// Decode a forward-option list written by [`put_fwd_entries`]. Every read is
/// length-guarded and the list is grown without preallocating from the
/// untrusted count, so a malformed or truncated body errors rather than
/// panicking or over-allocating.
#[inline(never)]
fn take_fwd_entries(r: &mut Rd) -> Vec<FwdOptionEntry> {
    let count = r.count("truncated forward options count");
    let mut entries = Vec::new();
    for _ in 0..count {
        if !r.ok() {
            break;
        }
        r.need(8, "truncated forward option entry");
        let proto = r.proto();
        let port = r.u16();
        let proxy = r.flag("unknown forward option flags");
        let idle_secs = r.u32();
        entries.push(FwdOptionEntry {
            proto,
            port,
            proxy,
            idle_secs,
        });
    }
    entries
}

/// Decode the bridge-client trailer that follows the routes in a snapshot: a u16
/// count followed by that many entries. Every multi-byte read is length-guarded
/// first, the count is u16-bounded, and the list is grown without preallocating
/// from the untrusted count, so a malformed or truncated body errors rather than
/// panicking or over-allocating. The caller still rejects any bytes left over.
#[inline(never)]
fn decode_bridge_clients(r: &mut Rd) -> Vec<BridgeEntry> {
    let count = r.count("truncated bridge count");
    let mut out = Vec::new();
    for _ in 0..count {
        if !r.ok() {
            break;
        }
        let label = r.str();
        r.need(1, "truncated bridge named flag");
        let named = r.flag("unknown bridge named");
        r.need(1, "truncated bridge transport");
        let transport = r.one_of(1, 2, "unknown transport");
        let peer = r.str();
        let mac_count = r.count("truncated bridge mac count");
        let mut macs = Vec::new();
        for _ in 0..mac_count {
            if !r.ok() {
                break;
            }
            r.need(6, "truncated bridge mac");
            let m: [u8; 6] = r.take(6).try_into().unwrap_or([0; 6]);
            macs.push(m);
        }
        r.need(40, "truncated bridge counters");
        let rx_bytes = r.u64();
        let rx_frames = r.u64();
        let tx_bytes = r.u64();
        let tx_frames = r.u64();
        let uptime_secs = r.u32();
        let idle_secs = r.u32();
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
    out
}

/// Decode the pair trailer that follows the bridge clients in a snapshot: a
/// u16 count then that many entries. Length-guarded like the bridge trailer,
/// with the capability and the settled path validated at decode; the caller
/// still rejects any bytes left over.
#[inline(never)]
fn decode_pairs(r: &mut Rd) -> Vec<PairEntry> {
    let count =
        r.count("truncated pair count: the admin reader and the server are different versions");
    let mut out = Vec::new();
    for _ in 0..count {
        if !r.ok() {
            break;
        }
        let consumer_id = r.str();
        let provider_id = r.str();
        r.need(2, "truncated pair capability");
        let want = want(r);
        let path = r.settled_path();
        out.push(PairEntry {
            consumer_id,
            provider_id,
            want,
            path,
        });
    }
    out
}

#[inline(never)]
fn decode_listeners(r: &mut Rd) -> Vec<Listener> {
    let count = r.count("truncated listener count");
    let mut listeners = Vec::new();
    for _ in 0..count {
        if !r.ok() {
            break;
        }
        let bind_ip = r.ip();
        r.need(4, "truncated listener");
        let proto = r.proto();
        let port = r.u16();
        let source = SOURCES[r.index(3, "unknown source")];
        listeners.push(Listener {
            bind_ip,
            proto,
            port,
            source,
        });
    }
    listeners
}

#[inline(never)]
fn decode_clients(r: &mut Rd) -> Vec<ClientEntry> {
    let count = r.count("truncated client count");
    let mut clients = Vec::new();
    for _ in 0..count {
        if !r.ok() {
            break;
        }
        let client_id = r.str();
        r.need(1, "truncated client transport");
        let transport = r.one_of(1, 2, "unknown transport");
        let fwd = take_fwd_entries(r);
        clients.push(ClientEntry {
            client_id,
            transport,
            fwd,
        });
    }
    clients
}

#[inline(never)]
fn decode_routes(r: &mut Rd) -> Vec<RouteEntry> {
    let count = r.count("truncated route count");
    let mut routes = Vec::new();
    for _ in 0..count {
        if !r.ok() {
            break;
        }
        let bind_ip = r.ip();
        r.need(3, "truncated route");
        let proto = r.proto();
        let port = r.u16();
        let client_id = r.str();
        r.need(2, "truncated route state");
        let state = r.one_of(0, 1, "unknown route state");
        let source = SOURCES[r.index(3, "unknown source")];
        routes.push(RouteEntry {
            bind_ip,
            proto,
            port,
            client_id,
            state,
            source,
        });
    }
    routes
}

/// A `provides` bitset: any bit outside the defined set is rejected.
#[inline(never)]
fn provides(r: &mut Rd) -> u8 {
    let n = r.u8();
    if n & !PROVIDES_MASK != 0 {
        r.fail(bad_byte("unknown provides", n));
    }
    n
}

/// A requested capability: exactly one defined provides bit.
#[inline(never)]
fn want(r: &mut Rd) -> u8 {
    let n = r.u8();
    if n & !PROVIDES_MASK != 0 || n.count_ones() != 1 {
        r.fail(bad_byte("invalid want", n));
    }
    n
}

/// The `(bind_ip, proto, port)` triple the listener and route mutations carry.
#[inline(never)]
fn put_target(b: &mut Vec<u8>, bind_ip: Ipv4Addr, proto: Proto, port: u16) {
    put_ip(b, bind_ip);
    put_u8(b, proto_byte(proto));
    put_u16(b, port);
}

/// Read the triple `put_target` writes.
#[inline(never)]
fn take_target(r: &mut Rd) -> (Ipv4Addr, Proto, u16) {
    let bind_ip = r.ip();
    let proto = r.proto();
    let port = r.u16();
    (bind_ip, proto, port)
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Msg::Ping => tagged(1),
            Msg::Open {
                proto,
                port,
                id,
                capability,
            } => {
                let mut b = tagged(2);
                put_u8(&mut b, proto_byte(*proto));
                put_u16(&mut b, *port);
                put_u64(&mut b, *id);
                put_bytes(&mut b, capability);
                b
            }
            Msg::Data {
                version,
                id,
                capability,
            } => {
                let mut b = tagged(3);
                put_u8(&mut b, *version);
                put_u64(&mut b, *id);
                put_bytes(&mut b, capability);
                b
            }
            Msg::Pong => tagged(4),
            Msg::ClientHello { version, client_id } => {
                let mut b = tagged(5);
                put_u8(&mut b, *version);
                put_str(&mut b, client_id);
                b
            }
            Msg::AdminHello { version, mode } => {
                let mut b = tagged(6);
                put_u8(&mut b, *version);
                put_u8(&mut b, *mode);
                b
            }
            Msg::Snapshot(snap) => {
                let mut b = tagged(7);
                put_u8(&mut b, snap.version);
                put_str(&mut b, &snap.server_id);
                debug_assert!(snap.listeners.len() <= u16::MAX as usize);
                let count = put_count(&mut b, snap.listeners.len());
                for l in &snap.listeners[..count] {
                    put_target(&mut b, l.bind_ip, l.proto, l.port);
                    put_u8(&mut b, source_byte(l.source));
                }
                debug_assert!(snap.clients.len() <= u16::MAX as usize);
                let count = put_count(&mut b, snap.clients.len());
                for c in &snap.clients[..count] {
                    put_str(&mut b, &c.client_id);
                    put_u8(&mut b, c.transport);
                    put_fwd_entries(&mut b, &c.fwd);
                }
                debug_assert!(snap.routes.len() <= u16::MAX as usize);
                let count = put_count(&mut b, snap.routes.len());
                for route in &snap.routes[..count] {
                    put_target(&mut b, route.bind_ip, route.proto, route.port);
                    put_str(&mut b, &route.client_id);
                    put_u8(&mut b, route.state);
                    put_u8(&mut b, source_byte(route.source));
                }
                // Bridge-client trailer: a u16 count then that many entries (the
                // count is 0 when no bridge clients are attached).
                debug_assert!(snap.bridge_clients.len() <= u16::MAX as usize);
                let count = put_count(&mut b, snap.bridge_clients.len());
                for e in &snap.bridge_clients[..count] {
                    put_str(&mut b, &e.label);
                    put_u8(&mut b, u8::from(e.named));
                    put_u8(&mut b, e.transport);
                    put_str(&mut b, &e.peer);
                    debug_assert!(e.macs.len() <= u16::MAX as usize);
                    let count = put_count(&mut b, e.macs.len());
                    for m in &e.macs[..count] {
                        put_bytes(&mut b, m);
                    }
                    put_u64(&mut b, e.rx_bytes);
                    put_u64(&mut b, e.rx_frames);
                    put_u64(&mut b, e.tx_bytes);
                    put_u64(&mut b, e.tx_frames);
                    put_u32(&mut b, e.uptime_secs);
                    put_u32(&mut b, e.idle_secs);
                }
                // Pair trailer: a u16 count then that many entries (the count
                // is 0 when no pairs are up).
                let count = put_count(&mut b, snap.pairs.len());
                for p in &snap.pairs[..count] {
                    put_str(&mut b, &p.consumer_id);
                    put_str(&mut b, &p.provider_id);
                    put_u8(&mut b, p.want);
                    put_u8(&mut b, settled_path_byte(p.path));
                }
                b
            }
            Msg::AddListener {
                bind_ip,
                proto,
                port,
            } => {
                let mut b = tagged(8);
                put_target(&mut b, *bind_ip, *proto, *port);
                b
            }
            Msg::RemoveListener {
                bind_ip,
                proto,
                port,
            } => {
                let mut b = tagged(9);
                put_target(&mut b, *bind_ip, *proto, *port);
                b
            }
            Msg::SetRoute {
                bind_ip,
                proto,
                port,
                client_id,
            } => {
                let mut b = tagged(10);
                put_target(&mut b, *bind_ip, *proto, *port);
                put_str(&mut b, client_id);
                b
            }
            Msg::ClearRoute {
                bind_ip,
                proto,
                port,
            } => {
                let mut b = tagged(11);
                put_target(&mut b, *bind_ip, *proto, *port);
                b
            }
            Msg::MutationResult { ok, msg } => {
                let mut b = tagged(12);
                put_u8(&mut b, u8::from(*ok));
                put_str(&mut b, msg);
                b
            }
            Msg::FwdOptions { entries } => {
                let mut b = tagged(13);
                put_fwd_entries(&mut b, entries);
                b
            }
            Msg::FwdOptionsAck => tagged(14),
            Msg::OpenProxy {
                port,
                id,
                capability,
                peer,
                local,
            } => {
                let mut b = tagged(15);
                put_u16(&mut b, *port);
                put_u64(&mut b, *id);
                put_bytes(&mut b, capability);
                put_sockaddr(&mut b, *peer);
                put_sockaddr(&mut b, *local);
                b
            }
            Msg::PeerAnnounce { provides, identity } => {
                let mut b = tagged(16);
                put_u8(&mut b, *provides);
                put_bytes(&mut b, identity);
                b
            }
            Msg::PeerAnnounceAck { observed } => {
                let mut b = tagged(17);
                put_sockaddr(&mut b, *observed);
                b
            }
            Msg::PeerChallenge { eph_pub, nonce } => {
                let mut b = tagged(25);
                put_bytes(&mut b, eph_pub);
                put_bytes(&mut b, nonce);
                b
            }
            Msg::PeerProof { mac } => {
                let mut b = tagged(26);
                put_bytes(&mut b, mac);
                b
            }
            Msg::PeerAnnounceRefuse { reason } => {
                let mut b = tagged(27);
                put_u8(&mut b, refuse_reason_byte(*reason));
                b
            }
            Msg::PeerConnect { peer_id, want } => {
                let mut b = tagged(18);
                put_bytes(&mut b, peer_id);
                put_u8(&mut b, *want);
                b
            }
            Msg::PeerResult {
                peer_id,
                want,
                pair_id,
                status,
            } => {
                let mut b = tagged(19);
                put_bytes(&mut b, peer_id);
                put_u8(&mut b, *want);
                put_u64(&mut b, *pair_id);
                put_u8(&mut b, peer_status_byte(*status));
                b
            }
            Msg::PeerProbe {
                pair_id,
                peer_id,
                probe_id,
                probe_capability,
                challenge,
                provides,
            } => {
                let mut b = tagged(20);
                put_u64(&mut b, *pair_id);
                put_bytes(&mut b, peer_id);
                put_u64(&mut b, *probe_id);
                put_bytes(&mut b, probe_capability);
                put_bytes(&mut b, challenge);
                put_u8(&mut b, *provides);
                b
            }
            Msg::PeerInfo {
                pair_id,
                candidates,
            } => {
                let mut b = tagged(21);
                put_u64(&mut b, *pair_id);
                debug_assert!(candidates.len() <= u16::MAX as usize);
                let count = put_count(&mut b, candidates.len());
                for c in &candidates[..count] {
                    put_sockaddr(&mut b, *c);
                }
                b
            }
            Msg::PeerRelayOpen {
                pair_id,
                id,
                capability,
            } => {
                let mut b = tagged(22);
                put_u64(&mut b, *pair_id);
                put_u64(&mut b, *id);
                put_bytes(&mut b, capability);
                b
            }
            Msg::PeerPath { pair_id, status } => {
                let mut b = tagged(23);
                put_u64(&mut b, *pair_id);
                put_u8(&mut b, path_status_byte(*status));
                b
            }
            Msg::ClientHelloAck {
                client_id,
                bridge_capability,
            } => {
                let mut b = tagged(24);
                put_str(&mut b, client_id);
                put_bytes(&mut b, bridge_capability);
                b
            }
        }
    }

    pub fn decode(b: &[u8]) -> Result<Msg> {
        let mut r = Rd::new(b, 1);
        let msg = match b.first() {
            Some(1) => Msg::Ping,
            Some(2) if b.len() == 12 + CAPABILITY_LEN => Msg::Open {
                proto: r.proto(),
                port: r.u16(),
                id: r.u64(),
                capability: r.arr32("capability"),
            },
            Some(3) if b.len() == 10 + CAPABILITY_LEN => Msg::Data {
                version: r.u8(),
                id: r.u64(),
                capability: r.arr32("capability"),
            },
            Some(4) => Msg::Pong,
            Some(5) => {
                r.need(1, "truncated client hello");
                let version = r.u8();
                let client_id = r.str();
                r.done("trailing bytes in client hello");
                Msg::ClientHello { version, client_id }
            }
            Some(6) if b.len() == 3 => Msg::AdminHello {
                version: b[1],
                mode: b[2],
            },
            Some(7) => {
                r.need(1, "truncated snapshot");
                let version = r.u8();
                let server_id = r.str();
                let listeners = decode_listeners(&mut r);
                let clients = decode_clients(&mut r);
                let routes = decode_routes(&mut r);
                let bridge_clients = decode_bridge_clients(&mut r);
                let pairs = decode_pairs(&mut r);
                r.done(
                    "trailing bytes in snapshot: the admin reader and the server are different versions",
                );
                Msg::Snapshot(SnapshotBody {
                    version,
                    server_id,
                    listeners,
                    clients,
                    routes,
                    bridge_clients,
                    pairs,
                })
            }
            Some(8) if b.len() == 8 => {
                let (bind_ip, proto, port) = take_target(&mut r);
                Msg::AddListener {
                    bind_ip,
                    proto,
                    port,
                }
            }
            Some(9) if b.len() == 8 => {
                let (bind_ip, proto, port) = take_target(&mut r);
                Msg::RemoveListener {
                    bind_ip,
                    proto,
                    port,
                }
            }
            Some(10) => {
                let bind_ip = r.ip();
                r.need(3, "truncated set route");
                let proto = r.proto();
                let port = r.u16();
                let client_id = r.str();
                r.done("trailing bytes in set route");
                Msg::SetRoute {
                    bind_ip,
                    proto,
                    port,
                    client_id,
                }
            }
            Some(11) if b.len() == 8 => {
                let (bind_ip, proto, port) = take_target(&mut r);
                Msg::ClearRoute {
                    bind_ip,
                    proto,
                    port,
                }
            }
            Some(12) => {
                r.need(1, "truncated mutation result");
                let ok = r.flag("unknown mutation result ok");
                let msg = r.str();
                r.done("trailing bytes in mutation result");
                Msg::MutationResult { ok, msg }
            }
            Some(13) => {
                let entries = take_fwd_entries(&mut r);
                r.done("trailing bytes in forward options");
                Msg::FwdOptions { entries }
            }
            Some(14) if b.len() == 1 => Msg::FwdOptionsAck,
            Some(15) => {
                r.need(10 + CAPABILITY_LEN, "truncated proxy open");
                let port = r.u16();
                let id = r.u64();
                let capability = r.arr32("capability");
                let peer = r.sockaddr();
                let local = r.sockaddr();
                r.done("trailing bytes in proxy open");
                Msg::OpenProxy {
                    port,
                    id,
                    capability,
                    peer,
                    local,
                }
            }
            Some(16) if b.len() == 2 + PEER_IDENTITY_LEN => Msg::PeerAnnounce {
                provides: provides(&mut r),
                identity: r.arr32("peer identity"),
            },
            Some(17) => {
                let observed = r.sockaddr();
                r.done("trailing bytes in peer announce ack");
                Msg::PeerAnnounceAck { observed }
            }
            Some(18) if b.len() == 2 + PEER_IDENTITY_LEN => Msg::PeerConnect {
                peer_id: r.arr32("peer identity"),
                want: want(&mut r),
            },
            Some(19) if b.len() == 11 + PEER_IDENTITY_LEN => Msg::PeerResult {
                peer_id: r.arr32("peer identity"),
                want: want(&mut r),
                pair_id: r.u64(),
                status: PEER_STATUSES[r.index(6, "unknown peer status")],
            },
            Some(20) if b.len() == 18 + PEER_IDENTITY_LEN + CAPABILITY_LEN + 32 => Msg::PeerProbe {
                pair_id: r.u64(),
                peer_id: r.arr32("peer identity"),
                probe_id: r.u64(),
                probe_capability: r.arr32("capability"),
                challenge: r.arr32("pair challenge"),
                provides: want(&mut r),
            },
            Some(21) => {
                r.need(10, "truncated peer info");
                let pair_id = r.u64();
                let count = r.u16() as usize;
                let mut candidates = Vec::new();
                for _ in 0..count {
                    if !r.ok() {
                        break;
                    }
                    candidates.push(r.sockaddr());
                }
                r.done("trailing bytes in peer info");
                Msg::PeerInfo {
                    pair_id,
                    candidates,
                }
            }
            Some(22) if b.len() == 17 + CAPABILITY_LEN => Msg::PeerRelayOpen {
                pair_id: r.u64(),
                id: r.u64(),
                capability: r.arr32("capability"),
            },
            Some(23) if b.len() == 10 => Msg::PeerPath {
                pair_id: r.u64(),
                status: PATH_STATUSES[r.index(2, "unknown path status")],
            },
            Some(24) => {
                let client_id = r.str();
                if r.ok() && r.at + CAPABILITY_LEN != b.len() {
                    r.fail_msg("invalid client hello ack capability");
                }
                let bridge_capability = r.arr32("capability");
                Msg::ClientHelloAck {
                    client_id,
                    bridge_capability,
                }
            }
            Some(25) if b.len() == 65 => Msg::PeerChallenge {
                eph_pub: r.arr32("challenge ephemeral"),
                nonce: r.arr32("challenge nonce"),
            },
            Some(26) if b.len() == 33 => Msg::PeerProof {
                mac: r.arr32("announce proof"),
            },
            Some(27) if b.len() == 2 => Msg::PeerAnnounceRefuse {
                reason: REFUSE_REASONS[r.index(4, "unknown refuse reason")],
            },
            _ => {
                r.fail(errf!("malformed message ({} bytes)", b.len()));
                Msg::Ping
            }
        };
        r.end()?;
        Ok(msg)
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
            pairs: vec![
                PairEntry {
                    consumer_id: "rpi-1-ab12".into(),
                    provider_id: "office-b1c2".into(),
                    want: PROVIDES_EXIT,
                    path: Some(PathStatus::Direct),
                },
                PairEntry {
                    consumer_id: "rpi-2-cd34".into(),
                    provider_id: "office-b1c2".into(),
                    want: PROVIDES_SEGMENT,
                    path: None,
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
            pairs: Vec::new(),
        };
        match roundtrip(&Msg::Snapshot(empty.clone())) {
            Msg::Snapshot(decoded) => assert_eq!(decoded, empty),
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    /// Both trailers are mandatory: a snapshot whose bytes end at the routes or
    /// at the bridge clients is malformed and must error, not decode to an
    /// empty fleet.
    #[test]
    fn snapshot_missing_trailer_errors() {
        let body = SnapshotBody {
            version: 1,
            server_id: "srv".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
            bridge_clients: Vec::new(),
            pairs: Vec::new(),
        };
        let bytes = Msg::Snapshot(body).encode();
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 0]);
        for missing in [2, 4] {
            assert!(Msg::decode(&bytes[..bytes.len() - missing]).is_err());
        }
    }

    #[test]
    fn data_carries_capability() {
        let capability = [7; CAPABILITY_LEN];
        let data = Msg::Data {
            version: 2,
            id: 7,
            capability,
        };
        let enc = data.encode();
        assert_eq!(enc.len(), 10 + CAPABILITY_LEN);
        match Msg::decode(&enc) {
            Ok(Msg::Data {
                version,
                id,
                capability: got,
            }) => {
                assert_eq!(version, 2);
                assert_eq!(id, 7);
                assert_eq!(got, capability);
            }
            other => panic!("expected data, got {other:?}"),
        }
        // A short capability and trailing junk both fail closed.
        assert!(Msg::decode(&[3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let mut bad = enc;
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
                pairs: Vec::new(),
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

    /// Every malformed pair trailer must error, never panic (panic=abort).
    #[test]
    fn snapshot_pair_trailer_rejects_malformed() {
        let mk = |pairs: Vec<PairEntry>| {
            Msg::Snapshot(SnapshotBody {
                version: 1,
                server_id: "s".into(),
                listeners: Vec::new(),
                clients: Vec::new(),
                routes: Vec::new(),
                bridge_clients: Vec::new(),
                pairs,
            })
        };
        let good = mk(vec![PairEntry {
            consumer_id: "c".into(),
            provider_id: "p".into(),
            want: PROVIDES_EXIT,
            path: Some(PathStatus::Relay),
        }])
        .encode();
        // The pair count begins where the same body with no pairs ends.
        let trailer_at = mk(Vec::new()).encode().len() - 2;

        for cut in trailer_at + 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // A pair count larger than the remaining bytes errors, not over-reads.
        let mut big = good.clone();
        big[trailer_at] = 0xff;
        big[trailer_at + 1] = 0xff;
        assert!(Msg::decode(&big).is_err());
        // The capability and settled-path bytes end the entry: a capability
        // that is not exactly one defined bit and an undefined path both error.
        for bad in [0u8, PROVIDES_EXIT | PROVIDES_SEGMENT, 4] {
            let mut corrupt = good.clone();
            corrupt[good.len() - 2] = bad;
            assert!(Msg::decode(&corrupt).is_err(), "want {bad} should error");
        }
        let mut bad_path = good.clone();
        *bad_path.last_mut().unwrap() = 3;
        assert!(Msg::decode(&bad_path).is_err());
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
            pairs: Vec::new(),
        })
        .encode();
        // The trailing eight bytes are the zero forward-option, route, bridge,
        // and pair counts; back up past them to the client transport byte and
        // corrupt it.
        let n = snap.len();
        snap[n - 9] = 3;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a bad listener source byte (5). A single listener and no
        // clients/routes puts the listener source byte before the four zero
        // counts (client + route + bridge + pair), i.e. nine bytes from the end.
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
            pairs: Vec::new(),
        })
        .encode();
        let n = snap.len();
        snap[n - 9] = 5;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a bad route source byte (7). A single route and no
        // clients/listeners puts the route source byte just before the zero
        // bridge-count and pair-count bytes, i.e. five bytes from the end.
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
            pairs: Vec::new(),
        })
        .encode();
        let n = snap.len();
        snap[n - 5] = 7;
        assert!(Msg::decode(&snap).is_err());

        // tag-7 with a client forward-option flags byte carrying reserved bits
        // (2). A single client with one entry and nothing else puts the flags
        // byte before the entry's idle u32 and the zero route, bridge, and pair
        // counts, i.e. eleven bytes from the end.
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
            pairs: Vec::new(),
        })
        .encode();
        let n = snap.len();
        snap[n - 11] = 2;
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
                capability: [5; CAPABILITY_LEN],
                peer,
                local,
            }) {
                Msg::OpenProxy {
                    port,
                    id,
                    capability,
                    peer: p,
                    local: l,
                } => {
                    assert_eq!(port, 443);
                    assert_eq!(id, u64::MAX);
                    assert_eq!(capability, [5; CAPABILITY_LEN]);
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
            capability: [5; CAPABILITY_LEN],
            peer: "203.0.113.5:51820".parse().unwrap(),
            local: "[2001:db8::2]:443".parse().unwrap(),
        }
        .encode();
        // 1 tag + 2 port + 8 id + capability + 7 (v4 addr) + 19 (v6 addr).
        assert_eq!(good.len(), 37 + CAPABILITY_LEN);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // The peer's family byte sits right after the port and id.
        let mut bad_family = good.clone();
        bad_family[11 + CAPABILITY_LEN] = 5;
        assert!(Msg::decode(&bad_family).is_err());
    }

    #[test]
    fn core_tags_roundtrip() {
        assert_eq!(Msg::Ping.encode(), vec![1]);
        assert_eq!(Msg::Pong.encode(), vec![4]);

        let open = Msg::Open {
            proto: Proto::Udp,
            port: 443,
            id: 7,
            capability: [6; CAPABILITY_LEN],
        };
        let bytes = open.encode();
        assert_eq!(bytes.len(), 12 + CAPABILITY_LEN);
        match Msg::decode(&bytes).unwrap() {
            Msg::Open {
                proto,
                port,
                id,
                capability,
            } => {
                assert_eq!(proto, Proto::Udp);
                assert_eq!(port, 443);
                assert_eq!(id, 7);
                assert_eq!(capability, [6; CAPABILITY_LEN]);
            }
            other => panic!("expected open, got {other:?}"),
        }

        // Hello (tag 0) is gone: byte 0 must decode to Err.
        assert!(Msg::decode(&[0]).is_err());
    }

    #[test]
    fn peer_announce_roundtrip() {
        for provides in [0, PROVIDES_EXIT, PROVIDES_SEGMENT, PROVIDES_MASK] {
            let enc = Msg::PeerAnnounce {
                provides,
                identity: [9; PEER_IDENTITY_LEN],
            }
            .encode();
            assert_eq!(enc.len(), 2 + PEER_IDENTITY_LEN);
            match Msg::decode(&enc).unwrap() {
                Msg::PeerAnnounce {
                    provides: got,
                    identity,
                } => {
                    assert_eq!(got, provides);
                    assert_eq!(identity, [9; PEER_IDENTITY_LEN]);
                }
                other => panic!("expected peer announce, got {other:?}"),
            }
        }
        // Truncated, trailing, and undefined-bit bodies all error.
        let good = Msg::PeerAnnounce {
            provides: 0,
            identity: [9; PEER_IDENTITY_LEN],
        }
        .encode();
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        for bad_bits in [0x04, 0xff] {
            let mut bad = good.clone();
            bad[1] = bad_bits;
            assert!(Msg::decode(&bad).is_err());
        }
        // The tag after the peer block is still unknown.
        assert!(Msg::decode(&[28]).is_err());
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
    fn peer_challenge_roundtrip() {
        let good = Msg::PeerChallenge {
            eph_pub: [5; 32],
            nonce: [6; 32],
        }
        .encode();
        assert_eq!(good.len(), 65);
        match Msg::decode(&good).unwrap() {
            Msg::PeerChallenge { eph_pub, nonce } => {
                assert_eq!(eph_pub, [5; 32]);
                assert_eq!(nonce, [6; 32]);
            }
            other => panic!("expected peer challenge, got {other:?}"),
        }
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
    }

    #[test]
    fn peer_proof_roundtrip() {
        let good = Msg::PeerProof { mac: [7; 32] }.encode();
        assert_eq!(good.len(), 33);
        match Msg::decode(&good).unwrap() {
            Msg::PeerProof { mac } => assert_eq!(mac, [7; 32]),
            other => panic!("expected peer proof, got {other:?}"),
        }
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
    }

    #[test]
    fn peer_announce_refuse_roundtrip() {
        for reason in [
            PeerRefuseReason::MalformedIdentity,
            PeerRefuseReason::FailedProof,
            PeerRefuseReason::ChallengeFailed,
            PeerRefuseReason::IdentityClaimed,
        ] {
            match roundtrip(&Msg::PeerAnnounceRefuse { reason }) {
                Msg::PeerAnnounceRefuse { reason: got } => assert_eq!(got, reason),
                other => panic!("expected peer announce refuse, got {other:?}"),
            }
        }
        // Truncated, trailing, and undefined-reason bodies all error.
        assert!(Msg::decode(&[27]).is_err());
        assert!(Msg::decode(&[27, 9]).is_err());
        assert!(Msg::decode(&[27, 0, 0]).is_err());
    }

    #[test]
    fn peer_connect_roundtrip() {
        for want in [PROVIDES_EXIT, PROVIDES_SEGMENT] {
            let m = Msg::PeerConnect {
                peer_id: [7; PEER_IDENTITY_LEN],
                want,
            };
            match roundtrip(&m) {
                Msg::PeerConnect { peer_id, want: got } => {
                    assert_eq!(peer_id, [7; PEER_IDENTITY_LEN]);
                    assert_eq!(got, want);
                }
                other => panic!("expected peer connect, got {other:?}"),
            }
        }
        // Truncated bodies and trailing junk all error.
        let good = Msg::PeerConnect {
            peer_id: [7; PEER_IDENTITY_LEN],
            want: PROVIDES_EXIT,
        }
        .encode();
        assert_eq!(good.len(), 2 + PEER_IDENTITY_LEN);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0xff);
        assert!(Msg::decode(&junk).is_err());
        // The want byte must be exactly one defined bit: zero bits, both bits,
        // and an undefined bit all error.
        for want in [0x00, PROVIDES_MASK, 0x04] {
            let mut bad = good.clone();
            *bad.last_mut().unwrap() = want;
            assert!(Msg::decode(&bad).is_err());
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
            PeerStatus::ServerFailure,
        ] {
            for want in [PROVIDES_EXIT, PROVIDES_SEGMENT] {
                let m = Msg::PeerResult {
                    peer_id: [3; PEER_IDENTITY_LEN],
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
                        assert_eq!(peer_id, [3; PEER_IDENTITY_LEN]);
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
            peer_id: [3; PEER_IDENTITY_LEN],
            want: PROVIDES_EXIT,
            pair_id: 7,
            status: PeerStatus::Accepted,
        }
        .encode();
        // 1 tag + identity + 1 want + 8 pair_id + 1 status.
        assert_eq!(good.len(), 11 + PEER_IDENTITY_LEN);
        for cut in 1..good.len() {
            assert!(Msg::decode(&good[..cut]).is_err(), "cut {cut} should error");
        }
        let mut junk = good.clone();
        junk.push(0x00);
        assert!(Msg::decode(&junk).is_err());
        // An unknown status byte (the last byte) errors.
        let mut bad_status = good.clone();
        *bad_status.last_mut().unwrap() = 6;
        assert!(Msg::decode(&bad_status).is_err());
        // The want byte follows the identity: zero bits, both bits, and an
        // undefined bit all error.
        for want in [0x00, PROVIDES_MASK, 0x04] {
            let mut bad_want = good.clone();
            bad_want[1 + PEER_IDENTITY_LEN] = want;
            assert!(Msg::decode(&bad_want).is_err());
        }
    }

    #[test]
    fn peer_probe_roundtrip() {
        for want in [PROVIDES_EXIT, PROVIDES_SEGMENT] {
            let m = Msg::PeerProbe {
                pair_id: 3,
                peer_id: [8; PEER_IDENTITY_LEN],
                probe_id: u64::MAX,
                probe_capability: [5; CAPABILITY_LEN],
                challenge: [6; 32],
                provides: want,
            };
            match roundtrip(&m) {
                Msg::PeerProbe {
                    pair_id,
                    peer_id,
                    probe_id,
                    probe_capability,
                    challenge,
                    provides,
                } => {
                    assert_eq!(pair_id, 3);
                    assert_eq!(peer_id, [8; PEER_IDENTITY_LEN]);
                    assert_eq!(probe_id, u64::MAX);
                    assert_eq!(probe_capability, [5; CAPABILITY_LEN]);
                    assert_eq!(challenge, [6; 32]);
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
            peer_id: [8; PEER_IDENTITY_LEN],
            probe_id: 4,
            probe_capability: [5; CAPABILITY_LEN],
            challenge: [6; 32],
            provides: PROVIDES_EXIT,
        }
        .encode();
        // 1 tag + 8 pair_id + identity + 8 probe_id + capability + challenge
        // + 1 provides.
        assert_eq!(good.len(), 18 + PEER_IDENTITY_LEN + CAPABILITY_LEN + 32);
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
            *bad_provides.last_mut().unwrap() = provides;
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
            capability: [6; CAPABILITY_LEN],
        };
        let enc = m.encode();
        assert_eq!(enc.len(), 17 + CAPABILITY_LEN);
        match Msg::decode(&enc).unwrap() {
            Msg::PeerRelayOpen {
                pair_id,
                id,
                capability,
            } => {
                assert_eq!(pair_id, 9);
                assert_eq!(id, u64::MAX);
                assert_eq!(capability, [6; CAPABILITY_LEN]);
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
