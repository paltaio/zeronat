//! Messages for a running client's local admin socket.
//!
//! A tag space of its own, fully separate from the server protocol in
//! [`crate::proto`]: the two enums never share a stream, so their tags may
//! overlap freely. Bodies follow the same encoding conventions (big-endian
//! integers, u16-length-prefixed UTF-8 strings, exact-length validation) and
//! ride the Noise framing unchanged.

use crate::client::Transport;
use crate::proto::{
    proto_byte, proto_from_byte, put_str, settled_path_byte, settled_path_from_byte, take_str,
    PathStatus, Proto, PROVIDES_EXIT, PROVIDES_SEGMENT,
};
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
    /// Parked by `Disconnect`: nothing is dialed until `Connect`.
    Offline,
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
        SessionMode::Offline => 4,
    }
}

fn mode_from_byte(n: u8) -> Result<SessionMode> {
    match n {
        0 => Ok(SessionMode::Idle),
        1 => Ok(SessionMode::Forwards),
        2 => Ok(SessionMode::Device),
        3 => Ok(SessionMode::Pppoe),
        4 => Ok(SessionMode::Offline),
        n => Err(format!("unknown session mode byte {n}").into()),
    }
}

fn transport_byte(t: Transport) -> u8 {
    match t {
        Transport::Auto => 0,
        Transport::Udp => 1,
        Transport::Tcp => 2,
    }
}

fn transport_from_byte(n: u8) -> Result<Transport> {
    match n {
        0 => Ok(Transport::Auto),
        1 => Ok(Transport::Udp),
        2 => Ok(Transport::Tcp),
        n => Err(format!("unknown transport byte {n}").into()),
    }
}

/// A peer slot's capability: exactly one defined provides bit. Zero, several,
/// or an undefined bit names no slot, so the decoder refuses it.
fn want_from_byte(n: u8) -> Result<u8> {
    match n {
        PROVIDES_EXIT | PROVIDES_SEGMENT => Ok(n),
        n => Err(format!("unknown peer capability byte {n}").into()),
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

/// Live PPP phase of the active session, written by the PPPoE datapath shell
/// and read by snapshot handlers. A single byte cell so the per-frame datapath
/// update never takes a lock.
#[derive(Clone, Default)]
pub struct PppStatus(std::sync::Arc<std::sync::atomic::AtomicU8>);

impl PppStatus {
    pub fn set(&self, phase: PppPhase) {
        self.0
            .store(phase_byte(phase), std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get(&self) -> PppPhase {
        // Only `set` writes the cell, so the byte is always a valid phase.
        phase_from_byte(self.0.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(PppPhase::None)
    }
}

/// Link state toward the active server, as reported in a `ClientSnapshot`.
/// Distinct from [`PppPhase`], which describes the PPP layer of a pppoe body;
/// this is the tunnel dial itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkStatus {
    Offline,
    Dialing,
    Connected,
    Backoff,
}

fn link_byte(l: LinkStatus) -> u8 {
    match l {
        LinkStatus::Offline => 0,
        LinkStatus::Dialing => 1,
        LinkStatus::Connected => 2,
        LinkStatus::Backoff => 3,
    }
}

fn link_from_byte(n: u8) -> Result<LinkStatus> {
    match n {
        0 => Ok(LinkStatus::Offline),
        1 => Ok(LinkStatus::Dialing),
        2 => Ok(LinkStatus::Connected),
        3 => Ok(LinkStatus::Backoff),
        n => Err(format!("unknown link status byte {n}").into()),
    }
}

/// Shared [`LinkStatus`] cell, the same shape as [`PppStatus`]: a single byte
/// written without a lock. Starts at `Offline`.
#[derive(Clone, Default)]
pub struct LinkCell(std::sync::Arc<std::sync::atomic::AtomicU8>);

impl LinkCell {
    pub fn set(&self, status: LinkStatus) {
        self.0
            .store(link_byte(status), std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get(&self) -> LinkStatus {
        // Only `set` writes the cell, so the byte is always a valid status.
        link_from_byte(self.0.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(LinkStatus::Offline)
    }
}

/// Shared per-slot status cell: the four link states every slot reports plus,
/// on a consumer, the path its pair settled on. Two bytes written without a
/// lock, the shape [`LinkCell`] uses. A running slot holds the cell through
/// [`PeerSlotCell::hold`], so a slot the loop tore down reads offline rather
/// than whatever it last wrote.
#[derive(Clone, Default)]
pub struct PeerSlotCell {
    link: LinkCell,
    path: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl PeerSlotCell {
    /// Report the slot's state. The path belongs to a connected consumer; a
    /// provider and any other state carry none.
    pub fn set(&self, link: LinkStatus, path: Option<PathStatus>) {
        self.link.set(link);
        self.path.store(
            settled_path_byte(path),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn get(&self) -> (LinkStatus, Option<PathStatus>) {
        // Only `set` writes the cell, so the byte is always a valid path. The
        // path belongs to a connected slot and is reported under no other link
        // state: the two bytes are read one at a time, so a reader landing
        // between a slot's two stores would otherwise see a settled path on a
        // slot that is already backing off.
        let link = self.link.get();
        let path = settled_path_from_byte(self.path.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(None)
            .filter(|_| link == LinkStatus::Connected);
        (link, path)
    }

    /// Take the cell for a running slot: it reads offline again when the slot
    /// that held it ends, aborted by a profile switch included.
    pub fn hold(&self) -> PeerSlotHold {
        PeerSlotHold(self.clone())
    }
}

/// Resets its slot's cell to offline on drop.
pub struct PeerSlotHold(PeerSlotCell);

impl Drop for PeerSlotHold {
    fn drop(&mut self) {
        self.0.set(LinkStatus::Offline, None);
    }
}

/// A configured peer slot as reported in a `ClientSnapshot`: what the slot
/// asks for, what it opens, and where its loop stands. `peer_id` is empty on a
/// provider, which is identified by its capability alone; `iface` is the
/// device or bridge the slot's adapter opens, empty when it opens none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPeerSlotEntry {
    pub peer_id: String,
    pub want: u8,
    pub iface: String,
    pub link: LinkStatus,
    /// The path a connected consumer's pair settled on.
    pub path: Option<PathStatus>,
}

impl ClientPeerSlotEntry {
    /// The peer a consumer slot asks; `None` on a provider, which the empty
    /// `peer_id` marks and which its capability names alone.
    pub fn peer(&self) -> Option<&str> {
        (!self.peer_id.is_empty()).then_some(self.peer_id.as_str())
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
    pub enabled: bool,
}

/// A configured server profile as reported in a `ClientSnapshot`: the
/// dialable config fields only. The per-server secret never leaves the
/// client; redaction is structural.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientServerEntry {
    pub name: String,
    /// `"dht"` or `host:port`.
    pub addr: String,
    pub transport: Transport,
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
    /// Configured server profiles `SelectServer` may name.
    pub servers: Vec<ClientServerEntry>,
    /// Configured pppoe session names `SpawnPppoe` may name.
    pub pppoe: Vec<String>,
    /// Name of the live pppoe session body; empty in any other mode.
    pub session: String,
    /// Link state toward the active server.
    pub link: LinkStatus,
    /// The peer slots this client runs beside the server slot, each with its
    /// own link state.
    pub peers: Vec<ClientPeerSlotEntry>,
}

/// Server secret carried by `AddServer` and held by the parsed client config;
/// `Debug` prints a placeholder so a logged frame or a debug-printed config
/// never exposes the value.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerSecret(pub String);

impl std::fmt::Debug for ServerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Messages exchanged over a client's admin socket.
///
/// Admin -> client: `ClientAdminHello` mode 0 requests one `ClientSnapshot`;
/// mode 1 is followed by exactly one mutation message, answered by
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
        enabled: bool,
        proxy: bool,
        idle_secs: u32,
    },
    SpawnPppoe {
        name: String,
    },
    StopSession {
        name: String,
    },
    /// Append a server profile. The secret rides the Noise-encrypted local
    /// socket and never appears in any snapshot.
    AddServer {
        name: String,
        addr: String,
        secret: ServerSecret,
        transport: Transport,
    },
    RemoveServer {
        name: String,
    },
    /// Leave the offline park and bring up the boot-derived session body.
    /// An empty `name` means the current active target; server names are
    /// never empty, so the empty string is free to mean "absent".
    Connect {
        name: String,
    },
    /// Tear the session body down and park offline; nothing is dialed until
    /// `Connect`.
    Disconnect,
    /// Append a forward, fields in the snapshot entry's order. An empty
    /// `target` means the config default `127.0.0.1:PORT`, resolved by the
    /// daemon; a real target is never empty, so the sentinel is free.
    /// `idle_secs` 0 means no idle override.
    AddForward {
        proto: Proto,
        port: u16,
        target: String,
        proxy: bool,
        idle_secs: u32,
        enabled: bool,
    },
    /// Remove the `(proto, port)` forward.
    RemoveForward {
        proto: Proto,
        port: u16,
    },
    /// Add a peer slot. A `peer_id` names the peer whose capability the slot
    /// consumes; empty, the slot provides that capability, and peer ids are
    /// never empty so the sentinel is free. The remaining fields mirror the
    /// config records: `dev`, `exit`, and `exit_strict` are the consumer's
    /// `[tun]` keys, with an empty `dev` meaning the default device name, and
    /// `iface` is `[peer] exit_iface` for an exit provider and `[peer]
    /// segment` for a segment provider.
    AttachPeer {
        peer_id: String,
        want: u8,
        dev: String,
        exit: bool,
        exit_strict: bool,
        iface: String,
    },
    /// Remove the peer slot `peer_id` and `want` name: a consumer by the peer
    /// and capability it asks for, or, with an empty `peer_id`, the provider
    /// of that capability.
    DetachPeer {
        peer_id: String,
        want: u8,
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
                    b.push(u8::from(f.enabled));
                }
                let count = snap.servers.len().min(u16::MAX as usize);
                b.extend_from_slice(&(count as u16).to_be_bytes());
                for s in &snap.servers[..count] {
                    put_str(&mut b, &s.name);
                    put_str(&mut b, &s.addr);
                    b.push(transport_byte(s.transport));
                }
                let count = snap.pppoe.len().min(u16::MAX as usize);
                b.extend_from_slice(&(count as u16).to_be_bytes());
                for name in &snap.pppoe[..count] {
                    put_str(&mut b, name);
                }
                put_str(&mut b, &snap.session);
                b.push(link_byte(snap.link));
                let count = snap.peers.len().min(u16::MAX as usize);
                b.extend_from_slice(&(count as u16).to_be_bytes());
                for slot in &snap.peers[..count] {
                    put_str(&mut b, &slot.peer_id);
                    b.push(slot.want);
                    put_str(&mut b, &slot.iface);
                    b.push(link_byte(slot.link));
                    b.push(settled_path_byte(slot.path));
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
                enabled,
                proxy,
                idle_secs,
            } => {
                let mut b = Vec::with_capacity(10);
                b.push(5);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                b.push(u8::from(*enabled));
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
            ClientMsg::AddServer {
                name,
                addr,
                secret,
                transport,
            } => {
                let mut b = Vec::new();
                b.push(8);
                put_str(&mut b, name);
                put_str(&mut b, addr);
                put_str(&mut b, &secret.0);
                b.push(transport_byte(*transport));
                b
            }
            ClientMsg::RemoveServer { name } => {
                let mut b = Vec::new();
                b.push(9);
                put_str(&mut b, name);
                b
            }
            ClientMsg::Connect { name } => {
                let mut b = Vec::new();
                b.push(10);
                put_str(&mut b, name);
                b
            }
            ClientMsg::Disconnect => vec![11],
            ClientMsg::AddForward {
                proto,
                port,
                target,
                proxy,
                idle_secs,
                enabled,
            } => {
                let mut b = Vec::new();
                b.push(12);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                put_str(&mut b, target);
                b.push(u8::from(*proxy));
                b.extend_from_slice(&idle_secs.to_be_bytes());
                b.push(u8::from(*enabled));
                b
            }
            ClientMsg::RemoveForward { proto, port } => {
                let mut b = Vec::with_capacity(4);
                b.push(13);
                b.push(proto_byte(*proto));
                b.extend_from_slice(&port.to_be_bytes());
                b
            }
            ClientMsg::AttachPeer {
                peer_id,
                want,
                dev,
                exit,
                exit_strict,
                iface,
            } => {
                let mut b = Vec::new();
                b.push(14);
                put_str(&mut b, peer_id);
                b.push(*want);
                put_str(&mut b, dev);
                b.push(u8::from(*exit));
                b.push(u8::from(*exit_strict));
                put_str(&mut b, iface);
                b
            }
            ClientMsg::DetachPeer { peer_id, want } => {
                let mut b = Vec::new();
                b.push(15);
                put_str(&mut b, peer_id);
                b.push(*want);
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
                    if at + 6 > b.len() {
                        return Err("truncated forward entry options".into());
                    }
                    let proxy = match b[at] {
                        0 => false,
                        1 => true,
                        n => return Err(format!("unknown forward proxy byte {n}").into()),
                    };
                    let idle_secs = u32::from_be_bytes(b[at + 1..at + 5].try_into().unwrap());
                    let enabled = match b[at + 5] {
                        0 => false,
                        1 => true,
                        n => return Err(format!("unknown forward enabled byte {n}").into()),
                    };
                    at += 6;
                    forwards.push(ClientForwardEntry {
                        proto,
                        port,
                        target,
                        proxy,
                        idle_secs,
                        enabled,
                    });
                }
                if at + 2 > b.len() {
                    return Err("truncated client snapshot server list".into());
                }
                let count = u16::from_be_bytes([b[at], b[at + 1]]) as usize;
                at += 2;
                let mut servers = Vec::new();
                for _ in 0..count {
                    let name = take_str(b, &mut at)?;
                    let addr = take_str(b, &mut at)?;
                    if at >= b.len() {
                        return Err("truncated server entry".into());
                    }
                    let transport = transport_from_byte(b[at])?;
                    at += 1;
                    servers.push(ClientServerEntry {
                        name,
                        addr,
                        transport,
                    });
                }
                if at + 2 > b.len() {
                    return Err("truncated client snapshot pppoe list".into());
                }
                let count = u16::from_be_bytes([b[at], b[at + 1]]) as usize;
                at += 2;
                let mut pppoe = Vec::new();
                for _ in 0..count {
                    pppoe.push(take_str(b, &mut at)?);
                }
                let session = take_str(b, &mut at)?;
                if at >= b.len() {
                    return Err("truncated client snapshot link".into());
                }
                let link = link_from_byte(b[at])?;
                at += 1;
                if at + 2 > b.len() {
                    return Err("truncated client snapshot peer list".into());
                }
                let count = u16::from_be_bytes([b[at], b[at + 1]]) as usize;
                at += 2;
                let mut peers = Vec::new();
                for _ in 0..count {
                    let peer_id = take_str(b, &mut at)?;
                    if at >= b.len() {
                        return Err("truncated peer slot capability".into());
                    }
                    let want = want_from_byte(b[at])?;
                    at += 1;
                    let iface = take_str(b, &mut at)?;
                    if at + 2 > b.len() {
                        return Err("truncated peer slot status".into());
                    }
                    let link = link_from_byte(b[at])?;
                    let path = settled_path_from_byte(b[at + 1])?;
                    at += 2;
                    peers.push(ClientPeerSlotEntry {
                        peer_id,
                        want,
                        iface,
                        link,
                        path,
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
                    servers,
                    pppoe,
                    session,
                    link,
                    peers,
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
            Some(5) if b.len() == 10 => {
                let proto = proto_from_byte(b[1])?;
                let port = u16::from_be_bytes([b[2], b[3]]);
                let enabled = match b[4] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown forward enabled byte {n}").into()),
                };
                let proxy = match b[5] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown forward proxy byte {n}").into()),
                };
                let idle_secs = u32::from_be_bytes(b[6..10].try_into().unwrap());
                Ok(ClientMsg::SetForwardOptions {
                    proto,
                    port,
                    enabled,
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
            Some(8) => {
                let mut at = 1;
                let name = take_str(b, &mut at)?;
                let addr = take_str(b, &mut at)?;
                let secret = ServerSecret(take_str(b, &mut at)?);
                if at >= b.len() {
                    return Err("truncated add server".into());
                }
                let transport = transport_from_byte(b[at])?;
                at += 1;
                if at != b.len() {
                    return Err("trailing bytes in add server".into());
                }
                Ok(ClientMsg::AddServer {
                    name,
                    addr,
                    secret,
                    transport,
                })
            }
            Some(9) => {
                let mut at = 1;
                let name = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in remove server".into());
                }
                Ok(ClientMsg::RemoveServer { name })
            }
            Some(10) => {
                let mut at = 1;
                let name = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in connect".into());
                }
                Ok(ClientMsg::Connect { name })
            }
            Some(11) if b.len() == 1 => Ok(ClientMsg::Disconnect),
            Some(12) => {
                if b.len() < 4 {
                    return Err("truncated add forward".into());
                }
                let proto = proto_from_byte(b[1])?;
                let port = u16::from_be_bytes([b[2], b[3]]);
                let mut at = 4;
                let target = take_str(b, &mut at)?;
                if at + 6 > b.len() {
                    return Err("truncated add forward options".into());
                }
                let proxy = match b[at] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown forward proxy byte {n}").into()),
                };
                let idle_secs = u32::from_be_bytes(b[at + 1..at + 5].try_into().unwrap());
                let enabled = match b[at + 5] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown forward enabled byte {n}").into()),
                };
                at += 6;
                if at != b.len() {
                    return Err("trailing bytes in add forward".into());
                }
                Ok(ClientMsg::AddForward {
                    proto,
                    port,
                    target,
                    proxy,
                    idle_secs,
                    enabled,
                })
            }
            Some(13) if b.len() == 4 => Ok(ClientMsg::RemoveForward {
                proto: proto_from_byte(b[1])?,
                port: u16::from_be_bytes([b[2], b[3]]),
            }),
            Some(14) => {
                let mut at = 1;
                let peer_id = take_str(b, &mut at)?;
                if at >= b.len() {
                    return Err("truncated attach peer".into());
                }
                let want = want_from_byte(b[at])?;
                at += 1;
                let dev = take_str(b, &mut at)?;
                if at + 2 > b.len() {
                    return Err("truncated attach peer options".into());
                }
                let exit = match b[at] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown peer exit byte {n}").into()),
                };
                let exit_strict = match b[at + 1] {
                    0 => false,
                    1 => true,
                    n => return Err(format!("unknown peer exit_strict byte {n}").into()),
                };
                at += 2;
                let iface = take_str(b, &mut at)?;
                if at != b.len() {
                    return Err("trailing bytes in attach peer".into());
                }
                Ok(ClientMsg::AttachPeer {
                    peer_id,
                    want,
                    dev,
                    exit,
                    exit_strict,
                    iface,
                })
            }
            Some(15) => {
                let mut at = 1;
                let peer_id = take_str(b, &mut at)?;
                if at >= b.len() {
                    return Err("truncated detach peer".into());
                }
                let want = want_from_byte(b[at])?;
                at += 1;
                if at != b.len() {
                    return Err("trailing bytes in detach peer".into());
                }
                Ok(ClientMsg::DetachPeer { peer_id, want })
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
                    enabled: true,
                },
                ClientForwardEntry {
                    proto: Proto::Udp,
                    port: 51820,
                    target: "10.0.0.5:51820".into(),
                    proxy: false,
                    idle_secs: 0,
                    enabled: false,
                },
            ],
            servers: vec![
                ClientServerEntry {
                    name: "home".into(),
                    addr: "dht".into(),
                    transport: Transport::Auto,
                },
                ClientServerEntry {
                    name: "away".into(),
                    addr: "198.51.100.7:9000".into(),
                    transport: Transport::Tcp,
                },
            ],
            pppoe: vec!["wan".into(), "dsl".into()],
            session: String::new(),
            link: LinkStatus::Connected,
            peers: vec![
                ClientPeerSlotEntry {
                    peer_id: "office-b1c2".into(),
                    want: PROVIDES_EXIT,
                    iface: "zn0".into(),
                    link: LinkStatus::Connected,
                    path: Some(PathStatus::Direct),
                },
                ClientPeerSlotEntry {
                    peer_id: String::new(),
                    want: PROVIDES_SEGMENT,
                    iface: "br0".into(),
                    link: LinkStatus::Dialing,
                    path: None,
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
            servers: Vec::new(),
            pppoe: Vec::new(),
            session: "wan".into(),
            link: LinkStatus::Offline,
            peers: Vec::new(),
        };
        match roundtrip(&ClientMsg::ClientSnapshot(empty.clone())) {
            ClientMsg::ClientSnapshot(decoded) => assert_eq!(decoded, empty),
            other => panic!("expected client snapshot, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_every_mode_phase_and_link_roundtrips() {
        for mode in [
            SessionMode::Idle,
            SessionMode::Forwards,
            SessionMode::Device,
            SessionMode::Pppoe,
            SessionMode::Offline,
        ] {
            for phase in [
                PppPhase::None,
                PppPhase::Discovery,
                PppPhase::Negotiating,
                PppPhase::Established,
                PppPhase::LinkDown,
                PppPhase::Dead,
            ] {
                for link in [
                    LinkStatus::Offline,
                    LinkStatus::Dialing,
                    LinkStatus::Connected,
                    LinkStatus::Backoff,
                ] {
                    let body = ClientSnapshotBody {
                        version: 1,
                        active: "a".into(),
                        mode,
                        phase,
                        forwards: Vec::new(),
                        servers: Vec::new(),
                        pppoe: Vec::new(),
                        session: String::new(),
                        link,
                        peers: Vec::new(),
                    };
                    match roundtrip(&ClientMsg::ClientSnapshot(body.clone())) {
                        ClientMsg::ClientSnapshot(decoded) => assert_eq!(decoded, body),
                        other => panic!("expected client snapshot, got {other:?}"),
                    }
                }
            }
        }
    }

    /// Every malformed snapshot must error, never panic (panic=abort).
    #[test]
    fn snapshot_rejects_malformed() {
        // One single-char string each, so the byte offsets below are fixed:
        // 0 tag, 1 version, 2-4 active ("a"), 5 mode, 6 phase, 7-8 fwd count,
        // 9 proto, 10-11 port, 12-14 target ("t"), 15 proxy, 16-19 idle,
        // 20 enabled, 21-22 server count, 23-25 name ("s"), 26-28 addr ("d"),
        // 29 transport, 30-31 pppoe count, 32-34 name ("w"),
        // 35-37 session ("x"), 38 link, 39-40 peer count, 41-43 peer ("p"),
        // 44 want, 45-47 iface ("i"), 48 slot link, 49 slot path.
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
                enabled: false,
            }],
            servers: vec![ClientServerEntry {
                name: "s".into(),
                addr: "d".into(),
                transport: Transport::Tcp,
            }],
            pppoe: vec!["w".into()],
            session: "x".into(),
            link: LinkStatus::Connected,
            peers: vec![ClientPeerSlotEntry {
                peer_id: "p".into(),
                want: PROVIDES_EXIT,
                iface: "i".into(),
                link: LinkStatus::Backoff,
                path: Some(PathStatus::Relay),
            }],
        })
        .encode();
        assert_eq!(good.len(), 50);
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
        // Forward, server, and peer counts larger than the remaining bytes.
        for at in [7usize, 21, 39] {
            let mut big = good.clone();
            big[at] = 0xff;
            big[at + 1] = 0xff;
            assert!(
                ClientMsg::decode(&big).is_err(),
                "count at {at} should error"
            );
        }
        // Unknown mode, phase, proto, proxy, enabled, transport, and link
        // bytes, and a peer slot naming no capability, an unknown link state,
        // or an unknown path.
        for (at, bad) in [
            (5, 5u8),
            (6, 6u8),
            (9, 9u8),
            (15, 2u8),
            (20, 2u8),
            (29, 3u8),
            (38, 4u8),
            (44, 0u8),
            (44, PROVIDES_EXIT | PROVIDES_SEGMENT),
            (48, 4u8),
            (49, 3u8),
        ] {
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
            enabled: true,
            proxy: true,
            idle_secs: 600,
        };
        match roundtrip(&set) {
            ClientMsg::SetForwardOptions {
                proto,
                port,
                enabled,
                proxy,
                idle_secs,
            } => {
                assert_eq!(proto, Proto::Tcp);
                assert_eq!(port, 8443);
                assert!(enabled);
                assert!(proxy);
                assert_eq!(idle_secs, 600);
            }
            other => panic!("expected set forward options, got {other:?}"),
        }
        match roundtrip(&ClientMsg::SetForwardOptions {
            proto: Proto::Udp,
            port: 51820,
            enabled: false,
            proxy: false,
            idle_secs: 0,
        }) {
            ClientMsg::SetForwardOptions {
                proto,
                port,
                enabled,
                proxy,
                idle_secs,
            } => {
                assert_eq!(proto, Proto::Udp);
                assert_eq!(port, 51820);
                assert!(!enabled);
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

        for transport in [Transport::Auto, Transport::Udp, Transport::Tcp] {
            let m = ClientMsg::AddServer {
                name: "away".into(),
                addr: "198.51.100.7:9000".into(),
                secret: ServerSecret("hunter2".into()),
                transport,
            };
            match roundtrip(&m) {
                ClientMsg::AddServer {
                    name,
                    addr,
                    secret,
                    transport: got,
                } => {
                    assert_eq!(name, "away");
                    assert_eq!(addr, "198.51.100.7:9000");
                    assert_eq!(secret.0, "hunter2");
                    assert_eq!(got, transport);
                }
                other => panic!("expected add server, got {other:?}"),
            }
        }
        match roundtrip(&ClientMsg::RemoveServer {
            name: "away".into(),
        }) {
            ClientMsg::RemoveServer { name } => assert_eq!(name, "away"),
            other => panic!("expected remove server, got {other:?}"),
        }
        // Connect: a named target and the empty name meaning "the current
        // active target".
        for name in ["home", ""] {
            let m = ClientMsg::Connect { name: name.into() };
            match roundtrip(&m) {
                ClientMsg::Connect { name: got } => assert_eq!(got, name),
                other => panic!("expected connect, got {other:?}"),
            }
        }
        match roundtrip(&ClientMsg::Disconnect) {
            ClientMsg::Disconnect => {}
            other => panic!("expected disconnect, got {other:?}"),
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
        // SetForwardOptions with the wrong length, including the 9-byte frame
        // of the enabled-less shape.
        assert!(ClientMsg::decode(&[5, 1, 0, 1, 1]).is_err());
        assert!(ClientMsg::decode(&[5, 1, 0, 1, 1, 0, 0, 0, 0]).is_err());
        let mut long = ClientMsg::SetForwardOptions {
            proto: Proto::Tcp,
            port: 1,
            enabled: true,
            proxy: false,
            idle_secs: 0,
        }
        .encode();
        long.push(0x00);
        assert!(ClientMsg::decode(&long).is_err());
        // SetForwardOptions with a bad proto, enabled, or proxy byte.
        assert!(ClientMsg::decode(&[5, 9, 0, 1, 1, 0, 0, 0, 0, 0]).is_err());
        assert!(ClientMsg::decode(&[5, 1, 0, 1, 2, 0, 0, 0, 0, 0]).is_err());
        assert!(ClientMsg::decode(&[5, 1, 0, 1, 1, 2, 0, 0, 0, 0]).is_err());
        // Name-carrying mutations: truncated length prefix and trailing junk.
        for tag in [4u8, 6, 7, 9, 10] {
            assert!(ClientMsg::decode(&[tag, 0]).is_err());
            assert!(ClientMsg::decode(&[tag, 0, 8, b'x']).is_err());
            let mut junk = vec![tag, 0, 1, b'x'];
            junk.push(0xff);
            assert!(ClientMsg::decode(&junk).is_err());
        }
        // AddServer: any truncation errors, trailing junk errors, and an
        // unknown transport byte errors.
        let add = ClientMsg::AddServer {
            name: "a".into(),
            addr: "d".into(),
            secret: ServerSecret("s".into()),
            transport: Transport::Auto,
        }
        .encode();
        for cut in 1..add.len() {
            assert!(
                ClientMsg::decode(&add[..cut]).is_err(),
                "cut {cut} should error"
            );
        }
        let mut junk = add.clone();
        junk.push(0x00);
        assert!(ClientMsg::decode(&junk).is_err());
        let mut corrupt = add.clone();
        *corrupt.last_mut().unwrap() = 3;
        assert!(ClientMsg::decode(&corrupt).is_err());
        // Disconnect carries no body.
        assert!(ClientMsg::decode(&[11, 0]).is_err());
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
        assert!(ClientMsg::decode(&[16]).is_err());
    }

    #[test]
    fn peer_slot_mutation_roundtrips() {
        // An exit consumer with every field set, one taking the default
        // device, an exit provider naming its egress, and a segment provider
        // naming its bridge.
        let cases = [
            ("office-b1c2", PROVIDES_EXIT, "zn1", true, true, ""),
            ("office-b1c2", PROVIDES_EXIT, "", false, false, ""),
            ("", PROVIDES_EXIT, "", false, false, "wan0"),
            ("", PROVIDES_EXIT, "", false, false, ""),
            ("", PROVIDES_SEGMENT, "", false, false, "br0"),
        ];
        for (peer_id, want, dev, exit, exit_strict, iface) in cases {
            let m = ClientMsg::AttachPeer {
                peer_id: peer_id.into(),
                want,
                dev: dev.into(),
                exit,
                exit_strict,
                iface: iface.into(),
            };
            match roundtrip(&m) {
                ClientMsg::AttachPeer {
                    peer_id: p,
                    want: w,
                    dev: d,
                    exit: e,
                    exit_strict: s,
                    iface: i,
                } => {
                    assert_eq!(p, peer_id);
                    assert_eq!(w, want);
                    assert_eq!(d, dev);
                    assert_eq!(e, exit);
                    assert_eq!(s, exit_strict);
                    assert_eq!(i, iface);
                }
                other => panic!("expected attach peer, got {other:?}"),
            }
        }

        for (peer_id, want) in [
            ("office-b1c2", PROVIDES_EXIT),
            ("", PROVIDES_EXIT),
            ("", PROVIDES_SEGMENT),
        ] {
            let m = ClientMsg::DetachPeer {
                peer_id: peer_id.into(),
                want,
            };
            match roundtrip(&m) {
                ClientMsg::DetachPeer {
                    peer_id: p,
                    want: w,
                } => {
                    assert_eq!(p, peer_id);
                    assert_eq!(w, want);
                }
                other => panic!("expected detach peer, got {other:?}"),
            }
        }
    }

    #[test]
    fn peer_slot_mutations_reject_malformed() {
        // Byte offsets with one-char strings: 0 tag, 1-3 peer_id ("p"),
        // 4 want, 5-7 dev ("d"), 8 exit, 9 exit_strict, 10-12 iface ("i").
        let attach = ClientMsg::AttachPeer {
            peer_id: "p".into(),
            want: PROVIDES_EXIT,
            dev: "d".into(),
            exit: true,
            exit_strict: false,
            iface: "i".into(),
        }
        .encode();
        assert_eq!(attach.len(), 13);
        for cut in 1..attach.len() {
            assert!(
                ClientMsg::decode(&attach[..cut]).is_err(),
                "cut {cut} should error"
            );
        }
        let mut junk = attach.clone();
        junk.push(0x00);
        assert!(ClientMsg::decode(&junk).is_err());
        // A capability that is not exactly one defined bit names no slot, and
        // the flags take 0 or 1 only.
        for (at, bad) in [
            (4, 0u8),
            (4, PROVIDES_EXIT | PROVIDES_SEGMENT),
            (4, 4),
            (8, 2),
            (9, 2),
        ] {
            let mut corrupt = attach.clone();
            corrupt[at] = bad;
            assert!(
                ClientMsg::decode(&corrupt).is_err(),
                "byte {at} = {bad} should error"
            );
        }

        // Detach: truncation, trailing junk, and the same capability rule.
        let detach = ClientMsg::DetachPeer {
            peer_id: "p".into(),
            want: PROVIDES_SEGMENT,
        }
        .encode();
        assert_eq!(detach.len(), 5);
        for cut in 1..detach.len() {
            assert!(
                ClientMsg::decode(&detach[..cut]).is_err(),
                "cut {cut} should error"
            );
        }
        let mut junk = detach.clone();
        junk.push(0x00);
        assert!(ClientMsg::decode(&junk).is_err());
        let mut corrupt = detach.clone();
        *corrupt.last_mut().unwrap() = 0;
        assert!(ClientMsg::decode(&corrupt).is_err());
    }

    #[test]
    fn forward_mutation_roundtrips() {
        // Every field set, the empty-target sentinel, and a disabled udp
        // entry with no overrides.
        let cases = [
            (Proto::Tcp, 8443u16, "10.0.0.5:443", true, 600u32, true),
            (Proto::Tcp, 443, "", false, 0, true),
            (Proto::Udp, 51820, "127.0.0.1:51820", false, 0, false),
        ];
        for (proto, port, target, proxy, idle_secs, enabled) in cases {
            let m = ClientMsg::AddForward {
                proto,
                port,
                target: target.into(),
                proxy,
                idle_secs,
                enabled,
            };
            match roundtrip(&m) {
                ClientMsg::AddForward {
                    proto: p,
                    port: pt,
                    target: t,
                    proxy: px,
                    idle_secs: i,
                    enabled: e,
                } => {
                    assert_eq!(p, proto);
                    assert_eq!(pt, port);
                    assert_eq!(t, target);
                    assert_eq!(px, proxy);
                    assert_eq!(i, idle_secs);
                    assert_eq!(e, enabled);
                }
                other => panic!("expected add forward, got {other:?}"),
            }
        }

        for proto in [Proto::Tcp, Proto::Udp] {
            match roundtrip(&ClientMsg::RemoveForward { proto, port: 443 }) {
                ClientMsg::RemoveForward { proto: p, port } => {
                    assert_eq!(p, proto);
                    assert_eq!(port, 443);
                }
                other => panic!("expected remove forward, got {other:?}"),
            }
        }
    }

    #[test]
    fn forward_mutations_reject_malformed() {
        // Byte offsets with the one-char target "t": 0 tag, 1 proto, 2-3
        // port, 4-6 target, 7 proxy, 8-11 idle, 12 enabled.
        let add = ClientMsg::AddForward {
            proto: Proto::Tcp,
            port: 443,
            target: "t".into(),
            proxy: true,
            idle_secs: 600,
            enabled: false,
        }
        .encode();
        assert_eq!(add.len(), 13);
        for cut in 1..add.len() {
            assert!(
                ClientMsg::decode(&add[..cut]).is_err(),
                "cut {cut} should error"
            );
        }
        let mut junk = add.clone();
        junk.push(0x00);
        assert!(ClientMsg::decode(&junk).is_err());
        // Unknown proto, proxy, and enabled bytes.
        for (at, bad) in [(1, 9u8), (7, 2u8), (12, 2u8)] {
            let mut corrupt = add.clone();
            corrupt[at] = bad;
            assert!(
                ClientMsg::decode(&corrupt).is_err(),
                "byte {at} = {bad} should error"
            );
        }

        // RemoveForward is a fixed 4-byte frame with a valid proto byte.
        assert!(ClientMsg::decode(&[13]).is_err());
        assert!(ClientMsg::decode(&[13, 0, 1]).is_err());
        assert!(ClientMsg::decode(&[13, 0, 1, 187, 0]).is_err());
        assert!(ClientMsg::decode(&[13, 9, 1, 187]).is_err());
    }

    // The dispatcher formats unexpected messages into logged error strings,
    // so a debug-printed `AddServer` must not carry the secret.
    #[test]
    fn add_server_debug_redacts_the_secret() {
        let m = ClientMsg::AddServer {
            name: "away".into(),
            addr: "198.51.100.7:9000".into(),
            secret: ServerSecret("hunter2".into()),
            transport: Transport::Tcp,
        };
        let s = format!("{m:?}");
        assert!(!s.contains("hunter2"), "{s}");
        assert!(s.contains("away"));
    }
}
