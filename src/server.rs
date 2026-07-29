use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Result;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::{timeout, Instant};

use crate::bridge;
use crate::config;
use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::kcp::{route, session_from, Accepted, ConvGuard, Session};
#[cfg(target_os = "linux")]
use crate::kcp::{BRIDGE_CONV, BRIDGE_ID};
#[cfg(target_os = "linux")]
use crate::netfilter;
use crate::noise::{
    server_handshake, server_handshake_stateless, Noise, NoiseReader, NoiseWriter, StatelessNoise,
};
#[cfg(target_os = "linux")]
use crate::proto::BridgeEntry;
use crate::proto::{
    proto_name, ClientEntry, FwdOptionEntry, Listener, Msg, PairEntry, PathStatus, PeerStatus,
    Proto, RouteEntry, SnapshotBody, Source, PROVIDES_EXIT,
};
#[cfg(target_os = "linux")]
use crate::tap::TapDevice;
use crate::tap::{TapConfig, TunConfig};

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Window for both parties of an accepted pair to report their punch
/// candidates, measured from the `PeerProbe` send; a party whose
/// local-candidate frame has not arrived when it lapses is reported
/// relay-only.
const PAIR_PROBE_DEADLINE: Duration = OPEN_TIMEOUT;
/// Window for both parties to claim the relay legs they were handed, measured
/// from the open. A pair whose second leg never arrives carries nothing and
/// would hold an exclusive provider's slot until a control session bounced, so
/// it is torn down here like a splice that ended. It clears the client's
/// `OPEN_HANDSHAKE_TIMEOUT`, which is what a party spends connecting and
/// handshaking a leg, plus the flight of the frame that told it to, so a leg
/// still inside its own open is never reaped out from under it.
const RELAY_CLAIM_DEADLINE: Duration = Duration::from_secs(20);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Liveness window for the control channel. The client pings every 25s, so no
/// inbound control frame for this long means the link is a black hole (no
/// FIN/RST on a NAT rebind, WAN re-dial, or silent firewall drop). Sized to a
/// few ping intervals to tolerate a missed ping without falsely tearing down a
/// healthy idle link.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_INFLIGHT_HANDSHAKES: usize = 256;
/// Pause after a transient accept/recv error so a persistent failure (e.g. EMFILE
/// under fd pressure) does not spin the listener loop at 100% CPU.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Idle window for a per-source UDP control session. A real client sends KCP ACKs
/// and 25s control pings, so a session silent this long is dead (NAT rebind, churn,
/// or stray probe traffic). The sweep evicts it, bounding the session map on a
/// public port. Sized above the control ping interval so a healthy link survives.
const UDP_SESSION_TTL: Duration = Duration::from_secs(90);
/// How often the control loop sweeps idle/empty sessions.
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Cap on concurrent per-source sessions the public UDP control port retains. A
/// single operator runs one client (one session), so this sits far above real
/// usage; it exists only so a flood of distinct source addresses on the public
/// port cannot grow the session map (and its socket_writer tasks) without bound.
/// With `kcp::MAX_CONVS_PER_SESSION`, the worst-case conv-driver-buffer ceiling
/// is MAX_UDP_SESSIONS * MAX_CONVS_PER_SESSION * ~64KB ~= 512 * 256 * 64KB ~= 8GB.
const MAX_UDP_SESSIONS: usize = 512;

/// Admission test for a datagram from an unknown source at the control port: a
/// new source is admitted only while the session map is below the cap. Known
/// sources bypass this (they already hold a slot), so a flood of fresh sources
/// cannot evict or starve an established session.
fn admit_new_udp_session(session_count: usize) -> bool {
    session_count < MAX_UDP_SESSIONS
}
/// Backstop TTL for a per-source data-listener entry. The bridge self-reaps at
/// `bridge::UDP_IDLE` (120s), closing its channel, which is the precise reclaim
/// signal; this is sized above that so the sweep never evicts a live bridge and
/// only bounds an entry whose channel somehow lingers.
const UDP_DATA_TTL: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, PartialEq)]
pub enum ActiveTransport {
    Tcp,
    Udp,
}

/// Wire byte for an observed transport in a snapshot or switch port: 1 = tcp, 2 = udp.
fn transport_byte(t: ActiveTransport) -> u8 {
    match t {
        ActiveTransport::Tcp => 1,
        ActiveTransport::Udp => 2,
    }
}

/// A public listener keyed by its bind IP, protocol, and port. The same tuple
/// keys the route table, so a public connection maps directly to a route.
type RouteKey = (Ipv4Addr, Proto, u16);

/// A connected client's control channel, the transport it arrived on, and its
/// announced per-forward options (empty until a `FwdOptions` arrives). Cloned
/// out of the registry per public connection so a `try_send` never holds a lock;
/// the options ride an `Arc` so the clone stays cheap.
#[derive(Clone)]
struct ClientHandle {
    tx: mpsc::Sender<Vec<u8>>,
    transport: ActiveTransport,
    fwd: Arc<HashMap<(Proto, u16), FwdOpt>>,
    /// The control socket's source address as observed at registration.
    /// Diagnostic only; never a punch candidate.
    observed: Option<SocketAddr>,
    /// The capability bitset from this client's `PeerAnnounce`, or `None` while
    /// it has not announced. The server sends peer tags only to a client whose
    /// entry holds `Some`, so an old client never sees an undecodable frame.
    peer_provides: Option<u8>,
}

/// One forward's client-announced options: send `OpenProxy` for TCP opens, and
/// the relay idle window (`None` = proto default).
#[derive(Clone, Copy)]
struct FwdOpt {
    proxy: bool,
    idle: Option<Duration>,
}

/// A running listener's teardown handles: `cancel` stops the accept/recv loop,
/// `bridges` collects active TCP bridge tasks so they can be aborted on removal,
/// and `flush` tells a UDP recv loop to drop its per-source sessions so live
/// sources re-resolve the route table. `source` records where the listener came
/// from; `cli_locked` marks a listener pinned by a CLI arg, which admin may not
/// remove and which persists as `File` only when it is also declared in the
/// config file.
struct ListenerHandle {
    cancel: Arc<Notify>,
    bridges: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    flush: Arc<Notify>,
    source: Source,
    cli_locked: bool,
}

/// A route's target client and where the route came from. Bundled so a mutation
/// updates the target and its source atomically under one `routes` lock.
#[derive(Clone)]
struct Route {
    client_id: String,
    source: Source,
}

/// One accepted rendezvous pair: the two parties, the capability it carries,
/// and each party's candidate-discovery progress. Removed when either party's
/// control session ends or is superseded.
struct Pair {
    consumer_id: String,
    provider_id: String,
    /// The pair's capability: the consumer's validated `want` bit.
    want: u8,
    consumer: PartyProbe,
    provider: PartyProbe,
    /// Set once the `PeerInfo` frames go out, so a completing probe and the
    /// pairing deadline cannot both send them.
    info_sent: bool,
    /// The relay, from the first `relay` report onward; `None` while the pair
    /// is still punching.
    relay: Option<Relay>,
}

/// A pair's relay: the leg id handed to each party, and how far the two legs
/// have got.
struct Relay {
    legs: [u64; 2],
    state: RelayState,
}

/// The relay's progress, one state at a time: a parked leg and a running
/// splice cannot coexist.
enum RelayState {
    /// Both leg ids are out; neither has been claimed.
    Open,
    /// The first leg to arrive, held until the second does.
    Parked(RelayLeg),
    /// Both legs are in and the splice is running. Dropping the sender stops
    /// it, which closes both legs, so invalidating the pair tears the relay
    /// down with it.
    Spliced { _stop: oneshot::Sender<()> },
}

/// One party's claimed relay leg. A stream leg carries one inner frame per
/// Noise record and a dgram leg one per datagram, so splicing the two kinds
/// together preserves frame boundaries. Nothing else about delivery survives
/// the splice: a pair whose legs differ gets the weaker of the two, so the
/// pipe is lossy and unordered whatever a party's own leg promises. The dgram
/// guard holds the session's tag registered for the leg's life.
enum RelayLeg {
    Stream(NoiseReader, NoiseWriter),
    Dgram(DgramRx, DgramTx, ConvGuard),
}

impl RelayLeg {
    fn split(self) -> (LegRead, LegWrite) {
        match self {
            RelayLeg::Stream(r, w) => (LegRead::Stream(r), LegWrite::Stream(w)),
            RelayLeg::Dgram(rx, tx, guard) => {
                (LegRead::Dgram(rx), LegWrite::Dgram { tx, _guard: guard })
            }
        }
    }
}

enum LegRead {
    Stream(NoiseReader),
    Dgram(DgramRx),
}

enum LegWrite {
    Stream(NoiseWriter),
    Dgram { tx: DgramTx, _guard: ConvGuard },
}

impl LegRead {
    /// The next inner frame, or `None` once the leg dies. A dgram keepalive
    /// belongs to the hop, and an empty frame is a keepalive on a stream leg
    /// and vanishes when written to one, so both leg kinds drop them and the
    /// pipe carries the same frames on every path. Everything else crosses
    /// opaque.
    async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            match self {
                LegRead::Stream(r) => match r.recv().await {
                    Ok(frame) if frame.is_empty() => continue,
                    Ok(frame) => return Some(frame),
                    Err(_) => return None,
                },
                LegRead::Dgram(rx) => match rx.recv().await? {
                    Frame::Data(body) if !body.is_empty() => return Some(body),
                    _ => continue,
                },
            }
        }
    }
}

impl LegWrite {
    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        match self {
            LegWrite::Stream(w) => w.send(frame).await,
            LegWrite::Dgram { tx, .. } => tx.send(frame).await,
        }
    }
}

/// Move inner frames between two claimed legs until either dies or `stop`
/// resolves, then drop both. A dgram leg carries no EOF of its own, so closing
/// the pair's other leg here is the only way its party learns the relay is
/// gone.
async fn splice_relay(a: RelayLeg, b: RelayLeg, stop: oneshot::Receiver<()>) {
    let (mut a_read, mut a_write) = a.split();
    let (mut b_read, mut b_write) = b.split();
    tokio::select! {
        _ = pump_leg(&mut a_read, &mut b_write) => {}
        _ = pump_leg(&mut b_read, &mut a_write) => {}
        _ = stop => {}
    }
}

async fn pump_leg(from: &mut LegRead, to: &mut LegWrite) {
    while let Some(frame) = from.recv().await {
        if to.send(&frame).await.is_err() {
            break;
        }
    }
}

/// One party's probe progress and settled path. `probe_id` is assigned when
/// the party can probe (udp control transport). `candidates` is `None` until
/// the party settles: the server-observed public mapping plus the party's
/// reported local candidate, or empty for a relay-only party. `path` holds
/// the party's `PeerPath` report, the only signal the server gets about a
/// punch that never touches it.
#[derive(Default)]
struct PartyProbe {
    probe_id: Option<u64>,
    candidates: Option<Vec<SocketAddr>>,
    path: Option<PathStatus>,
}

/// A parked public UDP source, the public socket its replies must go out on and
/// the local address they must leave from, the channel carrying its inbound
/// datagrams, and the relay's idle window, awaiting the matching UDP-forward
/// setup conv.
type UdpPending = (
    Arc<UdpSocket>,
    SocketAddr,
    Option<crate::pktinfo::LocalAddr>,
    mpsc::Receiver<Vec<u8>>,
    Duration,
);

pub(crate) struct Server {
    psk: [u8; 32],
    server_id: String,
    next_id: Mutex<u64>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Noise>>>,
    udp_pending: Mutex<HashMap<u64, UdpPending>>,
    clients: Mutex<HashMap<String, ClientHandle>>,
    /// Every client id that has ever registered on this server, kept across
    /// disconnects so `PeerConnect` can tell an offline peer from an unknown one.
    known_clients: Mutex<HashSet<String>>,
    /// Accepted rendezvous pairs by `pair_id`.
    pairs: Mutex<HashMap<u64, Pair>>,
    /// Outstanding probe ids to their owning `pair_id`, letting the udp
    /// control listener classify a stateless-handshake app id as a probe.
    /// Taken after `pairs` when both are held; entries die with their pair.
    probes: Mutex<HashMap<u64, u64>>,
    /// Outstanding relay leg ids to their owning `pair_id`, letting a claimed
    /// data channel find the pair to splice it into. Same lock rules as
    /// `probes`; a leg id is single-use and removed when it is claimed.
    relay_legs: Mutex<HashMap<u64, u64>>,
    routes: Mutex<HashMap<RouteKey, Route>>,
    listeners: Mutex<HashMap<RouteKey, ListenerHandle>>,
    handshakes: Arc<Semaphore>,
    /// Config file backing this server, or `None` for a runtime-only node that
    /// never writes. The `file_*` fields preserve the loaded `[server]` table
    /// verbatim so an auto-save never bakes CLI-sourced settings into the file.
    config_path: Option<PathBuf>,
    file_id: Option<String>,
    file_control: Option<String>,
    file_exit: Option<bool>,
    file_exit_iface: Option<String>,
    /// Serializes config writes so two concurrent admin sessions never interleave
    /// a save.
    save_lock: tokio::sync::Mutex<()>,
    /// Software learning switch between the one server device and its client
    /// port(s). Built once in `run()` when a `--tap`/`--tun` device is opened;
    /// absent on a runtime-only node with no device. A `--tap` switch gives each
    /// client its own port; a `--tun` switch serves one client.
    #[cfg(target_os = "linux")]
    switch: Option<Arc<bridge::TapSwitch>>,
}

impl Server {
    fn next_id(&self) -> u64 {
        let mut id = self.next_id.lock().unwrap();
        let next = *id;
        *id += 1;
        next
    }

    /// Resolve a public listener key to the id of the client that should serve
    /// it. An explicit route wins; with no route and exactly one connected
    /// client, that client is the implicit target (single-client deployments
    /// need no route). Locks are taken and dropped one at a time.
    fn serving_client_id(&self, key: RouteKey) -> Option<String> {
        let routed_id = self
            .routes
            .lock()
            .unwrap()
            .get(&key)
            .map(|r| r.client_id.clone());
        routed_id.or_else(|| {
            let clients = self.clients.lock().unwrap();
            if clients.len() == 1 {
                clients.keys().next().cloned()
            } else {
                None
            }
        })
    }

    /// The connected client's handle for the target `serving_client_id`
    /// resolves. Locks are never held across a `try_send`.
    fn route_to(&self, key: RouteKey) -> Option<ClientHandle> {
        let id = self.serving_client_id(key)?;
        self.clients.lock().unwrap().get(&id).cloned()
    }

    /// Register a new public stream against the routed client, notify it, and
    /// return the channel that will receive the matching data connection plus
    /// the relay's idle window (the client's per-forward option or the proto
    /// default). `addrs` is a TCP accept's `(peer, local)` pair; when the routed
    /// client flagged this TCP port for PROXY headers, the open is sent as
    /// `OpenProxy` carrying them. `None` if no client serves this key. The
    /// `try_send` runs outside every lock.
    fn open(
        &self,
        bind_ip: Ipv4Addr,
        proto: Proto,
        port: u16,
        addrs: Option<(SocketAddr, SocketAddr)>,
    ) -> Option<(u64, oneshot::Receiver<Noise>, Duration)> {
        let handle = self.route_to((bind_ip, proto, port))?;
        let opt = handle.fwd.get(&(proto, port)).copied();
        let idle = opt.and_then(|o| o.idle).unwrap_or(match proto {
            Proto::Tcp => bridge::TCP_IDLE,
            Proto::Udp => bridge::UDP_IDLE,
        });
        let id = self.next_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let msg = match addrs {
            Some((peer, local)) if proto == Proto::Tcp && opt.is_some_and(|o| o.proxy) => {
                Msg::OpenProxy {
                    port,
                    id,
                    peer,
                    local,
                }
                .encode()
            }
            _ => Msg::Open { proto, port, id }.encode(),
        };
        if handle.tx.try_send(msg).is_err() {
            self.pending.lock().unwrap().remove(&id);
            return None;
        }
        Some((id, rx, idle))
    }

    /// Resolve a consumer's `PeerConnect` into a `PeerResult` status, inserting
    /// a pair on acceptance. `None` means drop the frame without a reply: the
    /// sending session never announced or lost its registry slot. The clients
    /// guard spans the ownership check, the provider check, and the insert, so
    /// a pair only lands while both parties' entries are live and owned; a
    /// teardown or supersession swaps the registry before invalidating pairs,
    /// so a racing insert is either refused here or cleared by that
    /// invalidation. The busy check and the insert share the pair-table lock,
    /// so two consumers racing for an exclusive provider cannot both pair, and
    /// the same lock hold drops this consumer's own prior pair for the peer and
    /// capability it is asking for again. Lock order is clients before pairs. A
    /// failure status carries pair_id 0.
    fn peer_connect(
        &self,
        consumer_id: &str,
        consumer_tx: &mpsc::Sender<Vec<u8>>,
        provider_id: &str,
        want: u8,
    ) -> Option<(u64, PeerStatus)> {
        let clients = self.clients.lock().unwrap();
        let owned = clients
            .get(consumer_id)
            .is_some_and(|h| h.tx.same_channel(consumer_tx) && h.peer_provides.is_some());
        if !owned {
            return None;
        }
        // A party never pairs with itself. The punch elects its roles by
        // comparing the two client ids, so equal ids leave both ends
        // responders: neither can send handshake message one, the pair burns
        // its deadline, and an exclusive provider's one slot is held by a
        // pair that carries nothing.
        if provider_id == consumer_id {
            return Some((0, PeerStatus::UnknownPeer));
        }
        let Some(handle) = clients.get(provider_id) else {
            drop(clients);
            // An id that has registered before but holds no live session is
            // offline; one this server has never seen is unknown.
            if self.known_clients.lock().unwrap().contains(provider_id) {
                return Some((0, PeerStatus::PeerOffline));
            }
            return Some((0, PeerStatus::UnknownPeer));
        };
        if handle.tx.is_closed() {
            return Some((0, PeerStatus::PeerOffline));
        }
        // A provider that never announced provides nothing, same as one whose
        // announced bitset lacks the requested bit.
        if handle.peer_provides.is_none_or(|p| p & want == 0) {
            return Some((0, PeerStatus::NotProvided));
        }
        let mut pairs = self.pairs.lock().unwrap();
        // A consumer holds one pair per peer and capability: that triple is the
        // consumer slot's identity, and a slot asks again only after it has
        // dropped whatever its last cycle left. The server sees a direct pair
        // die only through the control session that carries no part of it, so
        // a pair the consumer abandoned would otherwise answer that consumer's
        // own retry with `peer_busy` for as long as the session stayed up.
        // Dropping the replaced pair stops the splice it carried, which closes
        // both relay legs.
        for (id, pair) in pairs
            .extract_if(|_, p| {
                p.consumer_id == consumer_id && p.provider_id == provider_id && p.want == want
            })
            .collect::<Vec<_>>()
        {
            self.forget_pair_ids(&pair);
            crate::elog!("peer pair {id}: replaced by a fresh request");
        }
        // Exit is exclusive: a tun provider serves one consumer. Segment is
        // multi-consumer, so it is never busy here.
        if want == PROVIDES_EXIT
            && pairs
                .values()
                .any(|p| p.provider_id == provider_id && p.want == want)
        {
            return Some((0, PeerStatus::PeerBusy));
        }
        let pair_id = self.next_id();
        pairs.insert(
            pair_id,
            Pair {
                consumer_id: consumer_id.to_string(),
                provider_id: provider_id.to_string(),
                want,
                consumer: PartyProbe::default(),
                provider: PartyProbe::default(),
                info_sent: false,
                relay: None,
            },
        );
        crate::elog!("peer pair {pair_id}: {consumer_id} -> {provider_id}");
        Some((pair_id, PeerStatus::Accepted))
    }

    /// Remove and return every pair `client_id` is a party to, dropping any
    /// outstanding probe and relay leg ids with them. A pair must not outlive
    /// either party's control session, so this runs when a session ends and
    /// when a reconnect supersedes it. The caller drops the returned pairs,
    /// which tears down any relay they carry.
    fn invalidate_pairs(&self, client_id: &str) -> Vec<(u64, Pair)> {
        let removed: Vec<(u64, Pair)> = self
            .pairs
            .lock()
            .unwrap()
            .extract_if(|_, p| p.consumer_id == client_id || p.provider_id == client_id)
            .collect();
        for (_, p) in &removed {
            self.forget_pair_ids(p);
        }
        removed
    }

    /// Drop the rendezvous ids a removed pair owned: its outstanding probe
    /// ids and any relay leg id still unclaimed. Both maps are taken after
    /// `pairs` and never together.
    fn forget_pair_ids(&self, pair: &Pair) {
        {
            let mut probes = self.probes.lock().unwrap();
            for id in [pair.consumer.probe_id, pair.provider.probe_id]
                .into_iter()
                .flatten()
            {
                probes.remove(&id);
            }
        }
        let mut relay_legs = self.relay_legs.lock().unwrap();
        for id in pair.relay.iter().flat_map(|r| r.legs) {
            relay_legs.remove(&id);
        }
    }

    /// Start candidate discovery for a freshly accepted pair: send both
    /// parties a `PeerProbe` naming the peer and the pair's capability, and arm
    /// the pairing deadline. Only a udp-transport party's probe id is mapped,
    /// so only that party can present it; a tcp-transport party never probes,
    /// takes the frame as the pair notification alone, and settles as
    /// relay-only at once, so a pair of tcp clients is finished before the
    /// deadline task even arms. Every party hears of a pair through a frame
    /// naming its capability, which is what lets a node announcing both bits
    /// place the pair. The sends run outside every lock; lock order is clients,
    /// pairs, probes, with `next_id` a leaf.
    fn start_pair_probes(self: &Arc<Self>, pair_id: u64) {
        let mut sends: Vec<(mpsc::Sender<Vec<u8>>, Vec<u8>)> = Vec::new();
        let settled = {
            let clients = self.clients.lock().unwrap();
            let mut pairs = self.pairs.lock().unwrap();
            let Some(pair) = pairs.get_mut(&pair_id) else {
                return;
            };
            let consumer_id = pair.consumer_id.clone();
            let provider_id = pair.provider_id.clone();
            let want = pair.want;
            let mut probes = self.probes.lock().unwrap();
            for (id, peer_id, party) in [
                (&consumer_id, &provider_id, &mut pair.consumer),
                (&provider_id, &consumer_id, &mut pair.provider),
            ] {
                // An entry gone or swapped mid-teardown is left unsettled: the
                // pending invalidation clears this pair, and a probe must not
                // ride a session that never announced.
                let Some(h) = clients.get(id).filter(|h| h.peer_provides.is_some()) else {
                    continue;
                };
                let probe_id = self.next_id();
                match h.transport {
                    // The id stays out of the map, so a probe presented under
                    // it is refused like any unknown app id.
                    ActiveTransport::Tcp => party.candidates = Some(Vec::new()),
                    ActiveTransport::Udp => {
                        party.probe_id = Some(probe_id);
                        probes.insert(probe_id, pair_id);
                    }
                }
                sends.push((
                    h.tx.clone(),
                    Msg::PeerProbe {
                        pair_id,
                        peer_id: peer_id.clone(),
                        probe_id,
                        provides: want,
                    }
                    .encode(),
                ));
            }
            pair.consumer.candidates.is_some() && pair.provider.candidates.is_some()
        };
        for (tx, msg) in sends {
            tx.try_send(msg).ok();
        }
        if settled {
            self.finish_pair(pair_id);
            return;
        }
        let srv = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(PAIR_PROBE_DEADLINE).await;
            srv.finish_pair(pair_id);
        });
    }

    /// Record a probing party's settled candidate list. Returns the pair id
    /// when the report completes the pair (both parties settled, info frames
    /// still unsent), telling the caller to finish it; a duplicate or
    /// orphaned report settles nothing. The probes guard is released before
    /// the pairs lock is taken.
    fn settle_probe(&self, probe_id: u64, candidates: Vec<SocketAddr>) -> Option<u64> {
        let pair_id = self.probes.lock().unwrap().get(&probe_id).copied()?;
        let mut pairs = self.pairs.lock().unwrap();
        let pair = pairs.get_mut(&pair_id)?;
        let party = if pair.consumer.probe_id == Some(probe_id) {
            &mut pair.consumer
        } else if pair.provider.probe_id == Some(probe_id) {
            &mut pair.provider
        } else {
            return None;
        };
        if party.candidates.is_some() {
            return None;
        }
        party.candidates = Some(candidates);
        (!pair.info_sent
            && pair.consumer.candidates.is_some()
            && pair.provider.candidates.is_some())
        .then_some(pair_id)
    }

    /// Send both parties their `PeerInfo`, each carrying the other party's
    /// candidates; a party that never settled contributes an empty
    /// (relay-only) list. Idempotent: the first call marks the pair reported
    /// and clears its probe ids. Frames go only to sessions that announced,
    /// and the sends run outside every lock.
    fn finish_pair(&self, pair_id: u64) {
        let (consumer_id, provider_id, consumer_c, provider_c) = {
            let mut pairs = self.pairs.lock().unwrap();
            let Some(pair) = pairs.get_mut(&pair_id) else {
                return;
            };
            if pair.info_sent {
                return;
            }
            pair.info_sent = true;
            let mut probes = self.probes.lock().unwrap();
            for id in [pair.consumer.probe_id, pair.provider.probe_id]
                .into_iter()
                .flatten()
            {
                probes.remove(&id);
            }
            drop(probes);
            (
                pair.consumer_id.clone(),
                pair.provider_id.clone(),
                pair.consumer.candidates.clone().unwrap_or_default(),
                pair.provider.candidates.clone().unwrap_or_default(),
            )
        };
        let (consumer_tx, provider_tx) = {
            let clients = self.clients.lock().unwrap();
            let announced = |id: &str| {
                clients
                    .get(id)
                    .filter(|h| h.peer_provides.is_some())
                    .map(|h| h.tx.clone())
            };
            (announced(&consumer_id), announced(&provider_id))
        };
        for (tx, candidates) in [(consumer_tx, provider_c), (provider_tx, consumer_c)] {
            if let Some(tx) = tx {
                tx.try_send(
                    Msg::PeerInfo {
                        pair_id,
                        candidates,
                    }
                    .encode(),
                )
                .ok();
            }
        }
    }

    /// Record a party's punch outcome against its pair, and open the relay on
    /// the first `relay` report. The sender must own its registry slot, have
    /// announced peer support, and be a party of a live pair; anything else is
    /// dropped. The first report per party wins, so a repeat cannot rewrite a
    /// settled path, and the second party's report (or a `direct` from the
    /// other side) opens no second relay. Each party gets its own leg id: two
    /// parties cannot both claim one id through a oneshot pending entry. Lock
    /// order is clients, pairs, relay legs, with `next_id` a leaf; the sends
    /// run outside every lock. Opening the relay arms the claim deadline, so a
    /// leg that never arrives cannot pin the pair.
    fn peer_path(
        self: &Arc<Self>,
        client_id: &str,
        tx: &mpsc::Sender<Vec<u8>>,
        pair_id: u64,
        status: PathStatus,
    ) {
        let mut sends: Vec<(mpsc::Sender<Vec<u8>>, Vec<u8>)> = Vec::new();
        let mut opened = false;
        {
            let clients = self.clients.lock().unwrap();
            let owned = clients
                .get(client_id)
                .is_some_and(|h| h.tx.same_channel(tx) && h.peer_provides.is_some());
            if !owned {
                return;
            }
            let mut pairs = self.pairs.lock().unwrap();
            let Some(pair) = pairs.get_mut(&pair_id) else {
                return;
            };
            let party = if pair.consumer_id == client_id {
                &mut pair.consumer
            } else if pair.provider_id == client_id {
                &mut pair.provider
            } else {
                return;
            };
            if party.path.is_some() {
                return;
            }
            party.path = Some(status);
            if status == PathStatus::Relay && pair.relay.is_none() {
                let legs = [self.next_id(), self.next_id()];
                let mut relay_legs = self.relay_legs.lock().unwrap();
                for (&id, party_id) in legs.iter().zip([&pair.consumer_id, &pair.provider_id]) {
                    relay_legs.insert(id, pair_id);
                    if let Some(h) = clients.get(party_id).filter(|h| h.peer_provides.is_some()) {
                        sends.push((h.tx.clone(), Msg::PeerRelayOpen { pair_id, id }.encode()));
                    }
                }
                drop(relay_legs);
                pair.relay = Some(Relay {
                    legs,
                    state: RelayState::Open,
                });
                opened = true;
            }
        }
        for (tx, msg) in sends {
            tx.try_send(msg).ok();
        }
        let name = crate::proto::path_name(status);
        crate::elog!("peer pair {pair_id}: {client_id} reports the {name} path");
        if opened {
            crate::elog!("peer pair {pair_id}: opening the relay");
            let srv = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(RELAY_CLAIM_DEADLINE).await;
                srv.reap_unclaimed_relay(pair_id);
            });
        }
    }

    /// Drop a pair whose relay opened but never spliced: neither party claimed
    /// its leg, or only one did and the other never arrived. Such a pair
    /// carries nothing, so it goes the way a finished splice goes, leaving a
    /// fresh `PeerConnect` as the recovery. A pair already spliced is left to
    /// `end_relay`.
    fn reap_unclaimed_relay(&self, pair_id: u64) {
        let removed = {
            let mut pairs = self.pairs.lock().unwrap();
            let unclaimed = pairs
                .get(&pair_id)
                .and_then(|p| p.relay.as_ref())
                .is_some_and(|r| !matches!(r.state, RelayState::Spliced { .. }));
            unclaimed.then(|| pairs.remove(&pair_id)).flatten()
        };
        let Some(pair) = removed else {
            return;
        };
        self.forget_pair_ids(&pair);
        crate::elog!("peer pair {pair_id}: the relay legs were never claimed");
    }

    /// Claim a relay leg id and return the pair it belongs to. A leg id is
    /// single-use, so a second claim of the same id finds nothing. Callers
    /// claim before they build the leg, so a duplicate claim never registers
    /// transport state the winner then loses.
    fn take_relay_leg(&self, id: u64) -> Option<u64> {
        self.relay_legs.lock().unwrap().remove(&id)
    }

    /// Park a claimed leg against its pair, splicing the two once both are in.
    /// A leg whose pair died between the claim and here is dropped, which
    /// closes it. The splice removes the pair when it ends: a relayed pair
    /// whose legs are gone carries nothing, and holding it would keep an
    /// exclusive provider busy for a session that never times out.
    fn park_relay_leg(self: &Arc<Self>, pair_id: u64, leg: RelayLeg) {
        let mut pairs = self.pairs.lock().unwrap();
        let Some(relay) = pairs.get_mut(&pair_id).and_then(|p| p.relay.as_mut()) else {
            return;
        };
        match std::mem::replace(&mut relay.state, RelayState::Open) {
            RelayState::Open => relay.state = RelayState::Parked(leg),
            RelayState::Parked(first) => {
                let (stop_tx, stop_rx) = oneshot::channel();
                let srv = self.clone();
                tokio::spawn(async move {
                    splice_relay(first, leg, stop_rx).await;
                    srv.end_relay(pair_id);
                });
                relay.state = RelayState::Spliced { _stop: stop_tx };
            }
            // A pair that is already spliced holds both its legs, so this one
            // is dropped.
            state @ RelayState::Spliced { .. } => relay.state = state,
        }
    }

    /// Remove a pair whose splice has ended, with any rendezvous ids it still
    /// owns. A fresh `PeerConnect` is the only recovery, matching every other
    /// path change.
    fn end_relay(&self, pair_id: u64) {
        let removed = self.pairs.lock().unwrap().remove(&pair_id);
        let Some(pair) = removed else {
            return;
        };
        self.forget_pair_ids(&pair);
        crate::elog!("peer pair {pair_id}: relay closed");
    }
}

/// DHT announce settings. An unset IP is auto-detected via the DHT; an unset port
/// defaults to the control port.
pub struct DhtAnnounce {
    pub ip: Option<Ipv4Addr>,
    pub port: Option<u16>,
}

/// One public listener the server starts at boot, with its config source. A
/// `cli_locked` listener is pinned by a CLI arg: admin may not remove it, and it
/// is persisted only when it is also a file-declared listener (`source == File`).
pub struct ListenerSpec {
    pub bind_ip: Ipv4Addr,
    pub proto: Proto,
    pub port: u16,
    pub source: Source,
    pub cli_locked: bool,
}

/// One route the server seeds at boot, with its config source.
pub struct RouteSpec {
    pub bind_ip: Ipv4Addr,
    pub proto: Proto,
    pub port: u16,
    pub client_id: String,
    pub source: Source,
}

/// TUN all-ports mode. The server forwards every inbound port (except the
/// control port and `except`) plus ICMP to one client over an L3 tunnel.
/// `device` is the server's tunnel endpoint (address `.1`); `client_ip` (`.2`)
/// is the NAT target. `subnet` is the tunnel network base. `exit` masquerades
/// the client's outbound traffic out `exit_iface`, or out the default-route
/// interface when `exit_iface` is unset.
pub struct ServerTun {
    pub device: TunConfig,
    pub subnet: Ipv4Addr,
    pub client_ip: Ipv4Addr,
    pub except: Vec<u16>,
    pub exit: bool,
    pub exit_iface: Option<String>,
}

/// Everything the server needs to boot. `config_path` is the file to auto-save
/// mutations into, or `None` for a runtime-only node. The `file_*` fields
/// carry the loaded `[server]` table so a save preserves it verbatim.
pub struct ServerSettings {
    pub bind: Ipv4Addr,
    pub control_port: u16,
    pub secret: String,
    pub server_id: String,
    pub tap: Option<TapConfig>,
    pub tun: Option<ServerTun>,
    pub dht: Option<DhtAnnounce>,
    pub listeners: Vec<ListenerSpec>,
    pub routes: Vec<RouteSpec>,
    pub config_path: Option<PathBuf>,
    pub file_id: Option<String>,
    pub file_control: Option<String>,
    pub file_exit: Option<bool>,
    pub file_exit_iface: Option<String>,
}

/// The netfilter plan for the TUN device. With `exit` on, the egress interface
/// is `exit_iface` when set, else the default-route interface parsed from
/// `route_table` (`/proc/net/route` contents).
#[cfg(target_os = "linux")]
fn tun_nat_plan(
    st: &ServerTun,
    control_port: u16,
    route_table: &str,
) -> Result<netfilter::NatPlan> {
    let egress = match (st.exit, &st.exit_iface) {
        (false, _) => None,
        (true, Some(iface)) => Some(iface.clone()),
        (true, None) => Some(
            crate::route::default_route_iface(route_table, &st.device.name)
                .ok_or("--exit could not detect the egress interface; pass --exit-iface")?,
        ),
    };
    Ok(netfilter::NatPlan {
        iface: st.device.name.clone(),
        subnet: st.subnet,
        prefix_len: st.device.prefix_len,
        server_ip: st.device.addr,
        mtu: st.device.mtu,
        dnat: Some(netfilter::DnatPlan {
            client_ip: st.client_ip,
            control_port,
            except: st.except.clone(),
        }),
        egress,
    })
}

pub async fn run(settings: ServerSettings) -> Result<()> {
    let ServerSettings {
        bind,
        control_port,
        secret,
        server_id,
        tap,
        tun,
        dht,
        listeners,
        routes,
        config_path,
        file_id,
        file_control,
        file_exit,
        file_exit_iface,
    } = settings;

    // The TUN NAT guard tears the rules down when this future is dropped: on the
    // SIGTERM/SIGINT cancel in main, or on an early-return error (the accept loop
    // never returns normally). Held in the frame for the process lifetime; a bare
    // `_` binding would drop it immediately.
    #[cfg(target_os = "linux")]
    let mut _nat_guard: Option<netfilter::NatGuard> = None;
    // Carries the opened device with whether it is L2 (TAP/Ethernet) or L3 (TUN).
    // The switch needs that distinction: an L2 device MAC-learns across many
    // ports, an L3 device serves exactly one client.
    #[cfg(target_os = "linux")]
    let tap: Option<(Arc<TapDevice>, bool)> = if let Some(st) = &tun {
        let route_table = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
        let plan = tun_nat_plan(st, control_port, &route_table)?;
        let dev = Arc::new(TapDevice::open_tun(&st.device)?);
        match netfilter::install(&plan) {
            netfilter::Outcome::Installed(g) => {
                let extra = if st.except.is_empty() {
                    String::new()
                } else {
                    format!(" + {} excluded", st.except.len())
                };
                crate::elog!(
                    "tun {}: forwarding all ports (except control{extra}) to {} via {}",
                    st.device.name,
                    st.client_ip,
                    g.backend_name(),
                );
                if control_port != 22 && !st.except.contains(&22) {
                    crate::elog!(
                        "warning: port 22 (SSH) now routes to the client; pass --except 22 to keep \
                         administering this server over SSH"
                    );
                }
                if let Some(egress) = &plan.egress {
                    crate::elog!(
                        "tun {}: masquerading client traffic out {egress}",
                        st.device.name
                    );
                }
                _nat_guard = Some(g);
            }
            netfilter::Outcome::Degraded(msg) => eprint!("{msg}"),
        }
        Some((dev, false))
    } else if let Some(cfg) = &tap {
        Some((Arc::new(TapDevice::open(cfg)?), true))
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    if tap.is_some() || tun.is_some() {
        return Err("L2/L3 tunnel modes (--tap/--tun) are only supported on Linux".into());
    }

    // Wrap the one opened device in the software switch so its client port(s)
    // share it; the switch owns the device and spawns the sole reader. Built once
    // here, carrying the L2/L3 distinction so a TUN switch admits one client.
    #[cfg(target_os = "linux")]
    let switch = tap.map(|(dev, is_l2)| bridge::TapSwitch::new(dev, is_l2));

    let bind_ip = bind;

    if let Some(ann) = dht {
        #[cfg(feature = "dht")]
        {
            let secret = secret.clone();
            let ip = ann.ip;
            let port = ann.port.unwrap_or(control_port);
            tokio::spawn(async move {
                crate::dht::announce_loop(&secret, ip, port).await;
            });
        }
        #[cfg(not(feature = "dht"))]
        {
            let _ = ann;
            return Err("this build has no dht support".into());
        }
    }

    let srv = Arc::new(Server {
        psk: crate::noise::derive_psk(&secret),
        server_id,
        next_id: Mutex::new(1),
        pending: Mutex::new(HashMap::new()),
        udp_pending: Mutex::new(HashMap::new()),
        clients: Mutex::new(HashMap::new()),
        known_clients: Mutex::new(HashSet::new()),
        pairs: Mutex::new(HashMap::new()),
        probes: Mutex::new(HashMap::new()),
        relay_legs: Mutex::new(HashMap::new()),
        routes: Mutex::new(
            routes
                .into_iter()
                .map(|r| {
                    (
                        (r.bind_ip, r.proto, r.port),
                        Route {
                            client_id: r.client_id,
                            source: r.source,
                        },
                    )
                })
                .collect(),
        ),
        listeners: Mutex::new(HashMap::new()),
        handshakes: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES)),
        config_path,
        file_id,
        file_control,
        file_exit,
        file_exit_iface,
        save_lock: tokio::sync::Mutex::new(()),
        #[cfg(target_os = "linux")]
        switch,
    });

    // A configured forwarded port that is already in use must not kill the server:
    // log it and keep the others serving, as the single-listener path did.
    for spec in listeners {
        if let Err(e) = spawn_listener(
            &srv,
            spec.bind_ip,
            spec.proto,
            spec.port,
            spec.source,
            spec.cli_locked,
        )
        .await
        {
            crate::elog!("{e}");
        }
    }

    let bind = bind_ip.to_string();
    let (udp_control, l) = bind_control_sockets(&bind, control_port).await?;
    crate::elog!("udp control listening on {bind}:{control_port}");
    {
        let srv = srv.clone();
        let udp_control = udp_control.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_control_listener(srv, udp_control).await {
                crate::elog!("udp control listener stopped: {e}");
            }
        });
    }

    crate::elog!("control listening on {bind}:{control_port}");
    loop {
        // A transient accept error (EMFILE, ECONNABORTED, ...) must not kill the
        // control loop or the process; log it, back off briefly, and keep serving.
        let (sock, peer) = match l.accept().await {
            Ok(v) => v,
            Err(e) => {
                crate::elog!("control accept error: {e}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let srv = srv.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(srv, sock, peer).await {
                crate::elog!("connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle_incoming(srv: Arc<Server>, sock: TcpStream, peer: SocketAddr) -> Result<()> {
    sock.set_nodelay(true).ok();
    let (r, w) = {
        let _permit = srv.handshakes.clone().acquire_owned().await?;
        match timeout(HANDSHAKE_TIMEOUT, server_handshake(sock, &srv.psk)).await {
            Ok(res) => res?,
            Err(_) => return Err("handshake timed out".into()),
        }
    };
    serve_stream(srv, r, w, ActiveTransport::Tcp, Some(peer)).await
}

/// Dispatch a freshly handshaked stream (control, admin, or data),
/// transport-agnostic. The first message decides the role.
pub(crate) async fn serve_stream(
    srv: Arc<Server>,
    mut r: crate::noise::NoiseReader,
    w: crate::noise::NoiseWriter,
    transport: ActiveTransport,
    peer: Option<SocketAddr>,
) -> Result<()> {
    // Guard the first role frame: a peer can finish the handshake then never send
    // its role, parking this task and its fd forever (half-death, NAT rebind,
    // buggy reconnect). Bound it so the task and fd are released, mirroring the
    // post-ClientHello control loop.
    let first = match timeout(CONTROL_TIMEOUT, r.recv()).await {
        Ok(res) => res?,
        Err(_) => return Err("timed out waiting for role frame".into()),
    };
    match Msg::decode(&first)? {
        Msg::ClientHello { version, client_id } => {
            if version != crate::identity::PROTO_VERSION {
                return Err("unsupported protocol version".into());
            }
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
            // Register this session under its client_id. A reconnect with the same
            // id supersedes the previous handle in one lock acquisition, so the
            // routing slot is reclaimed immediately; the old reader self-reaps.
            let superseded = {
                let mut clients = srv.clients.lock().unwrap();
                clients.insert(
                    client_id.clone(),
                    ClientHandle {
                        tx: tx.clone(),
                        transport,
                        fwd: Arc::new(HashMap::new()),
                        observed: peer,
                        peer_provides: None,
                    },
                )
            };
            srv.known_clients.lock().unwrap().insert(client_id.clone());
            if superseded.is_some() {
                crate::elog!("client {client_id} reconnected, superseding previous session");
                // The superseded session's pairs would point at a dead handle;
                // the new session holds none yet, so this only drops stale ones.
                srv.invalidate_pairs(&client_id);
            }
            crate::elog!("client {client_id} connected");
            let mut w = w;
            let writer = tokio::spawn(async move {
                while let Some(bytes) = rx.recv().await {
                    if w.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
            // Drain inbound control frames. Any frame (Ping, ...) resets the
            // liveness deadline; reply to Ping with Pong so the client's own
            // deadline also keeps resetting. A timeout (no inbound frame for the
            // whole window) or a recv error breaks the loop and tears down: a
            // black-holed link delivers no FIN/RST, so only the deadline catches it.
            while let Ok(Ok(bytes)) = timeout(CONTROL_TIMEOUT, r.recv()).await {
                match Msg::decode(&bytes) {
                    Ok(Msg::Ping) => {
                        tx.try_send(Msg::Pong.encode()).ok();
                    }
                    Ok(Msg::FwdOptions { entries }) => {
                        let map: HashMap<(Proto, u16), FwdOpt> = entries
                            .iter()
                            .map(|e| {
                                (
                                    (e.proto, e.port),
                                    FwdOpt {
                                        // PROXY headers are a TCP framing; a udp
                                        // entry claiming one is never honored.
                                        proxy: e.proxy && e.proto == Proto::Tcp,
                                        idle: (e.idle_secs > 0)
                                            .then(|| Duration::from_secs(e.idle_secs.into())),
                                    },
                                )
                            })
                            .collect();
                        // Swap the options into the registry only while this
                        // session still owns its slot (same guard as the
                        // teardown below), so a superseding session's options
                        // are never clobbered by a stale reader.
                        {
                            let mut clients = srv.clients.lock().unwrap();
                            if let Some(h) = clients.get_mut(&client_id) {
                                if h.tx.same_channel(&tx) {
                                    h.fwd = Arc::new(map);
                                }
                            }
                        }
                        // The ack tells the client its options (PROXY headers
                        // included) are honored; it is only ever sent in reply,
                        // so an old client never sees an undecodable frame.
                        tx.try_send(Msg::FwdOptionsAck.encode()).ok();
                    }
                    Ok(Msg::PeerAnnounce { provides }) => {
                        // Record peer support only while this session still owns
                        // its slot (same guard as FwdOptions); the recorded
                        // entry gates every later peer tag to this client.
                        let observed = {
                            let mut clients = srv.clients.lock().unwrap();
                            match clients.get_mut(&client_id) {
                                Some(h) if h.tx.same_channel(&tx) => {
                                    h.peer_provides = Some(provides);
                                    h.observed
                                }
                                _ => None,
                            }
                        };
                        // The ack echoes the control address recorded at
                        // registration; like FwdOptionsAck it is only ever sent
                        // in reply.
                        if let Some(observed) = observed {
                            tx.try_send(Msg::PeerAnnounceAck { observed }.encode()).ok();
                        }
                    }
                    Ok(Msg::PeerConnect { peer_id, want }) => {
                        // `None` marks a sender that never announced or lost
                        // its slot; the frame is dropped like any unknown
                        // frame, since replying would send a peer tag through
                        // an unannounced session.
                        if let Some((pair_id, status)) =
                            srv.peer_connect(&client_id, &tx, &peer_id, want)
                        {
                            tx.try_send(
                                Msg::PeerResult {
                                    peer_id,
                                    want,
                                    pair_id,
                                    status,
                                }
                                .encode(),
                            )
                            .ok();
                            if status == PeerStatus::Accepted {
                                srv.start_pair_probes(pair_id);
                            }
                        }
                    }
                    Ok(Msg::PeerPath { pair_id, status }) => {
                        srv.peer_path(&client_id, &tx, pair_id, status);
                    }
                    _ => {}
                }
            }
            // Remove this client only if the registry still points at this
            // session's channel. A superseding session overwrote the entry, so its
            // tx no longer matches and this teardown is a no-op; the new session's
            // slot is preserved. A superseded reader runs this same no-op once it
            // times out, which is why the stale reader is left to self-reap.
            let removed = {
                let mut clients = srv.clients.lock().unwrap();
                let owned = clients
                    .get(&client_id)
                    .is_some_and(|h| h.tx.same_channel(&tx));
                if owned {
                    clients.remove(&client_id);
                }
                owned
            };
            // Gated on the real removal so a stale reader's no-op teardown
            // cannot drop pairs the superseding session created, nor log a
            // disconnect for a client the registry still holds a session for.
            if removed {
                srv.invalidate_pairs(&client_id);
                crate::elog!("client {client_id} disconnected");
            }
            writer.abort();
            Ok(())
        }
        Msg::AdminHello { version, mode } => {
            if version != crate::identity::PROTO_VERSION {
                return Err("unsupported protocol version".into());
            }
            match mode {
                0 => {
                    // No log line: the console polls this every second, which would flood the log.
                    let mut w = w;
                    w.send(&Msg::Snapshot(srv.snapshot()).encode()).await?;
                    Ok(())
                }
                1 => {
                    crate::elog!("admin connected (mutate)");
                    // Same guard as the first role frame: an admin that says it
                    // will mutate but never sends the request must not park here.
                    let bytes = match timeout(CONTROL_TIMEOUT, r.recv()).await {
                        Ok(res) => res?,
                        Err(_) => return Err("timed out waiting for admin request".into()),
                    };
                    let req = Msg::decode(&bytes)?;
                    let (ok, msg) = apply_mutation(&srv, req).await;
                    crate::elog!("admin mutation: ok={ok} {msg}");
                    let mut w = w;
                    w.send(&Msg::MutationResult { ok, msg }.encode()).await?;
                    Ok(())
                }
                other => Err(format!("unsupported admin mode {other}").into()),
            }
        }
        Msg::Data { id, name } => {
            #[cfg(target_os = "linux")]
            if id == BRIDGE_ID {
                if let Some(switch) = srv.switch.clone() {
                    match switch.add_port(transport_byte(transport), peer) {
                        Ok(handle) => {
                            if let Some(name) = name.as_deref().filter(|n| !n.is_empty()) {
                                handle.set_name(name);
                            }
                            bridge::switch_port_stream(handle, r, w).await
                        }
                        Err(e) => crate::elog!("rejecting bridge stream: {e}"),
                    }
                }
                return Ok(());
            }
            // The bridge name and peer address are only consumed by the
            // linux-only switch above.
            #[cfg(not(target_os = "linux"))]
            let _ = (&name, &peer);
            let claimed = srv.pending.lock().unwrap().remove(&id);
            match claimed {
                Some(tx) => {
                    let _ = tx.send((r, w));
                }
                // Forward opens and relay legs draw ids from one counter, so
                // an id no forward parked can only be a relay leg's.
                None => {
                    if let Some(pair_id) = srv.take_relay_leg(id) {
                        srv.park_relay_leg(pair_id, RelayLeg::Stream(r, w));
                    }
                }
            }
            Ok(())
        }
        other => Err(format!("unexpected first message: {other:?}").into()),
    }
}

impl Server {
    /// Build a point-in-time snapshot of this server's topology. Each lock is held
    /// only long enough to copy its contents; the connected client ids are snapped
    /// into a local set so route states are computed without re-locking `clients`.
    fn snapshot(&self) -> SnapshotBody {
        let (connected, clients): (HashSet<String>, Vec<ClientEntry>) = {
            let map = self.clients.lock().unwrap();
            let connected = map.keys().cloned().collect();
            let clients = map
                .iter()
                .map(|(id, h)| {
                    let mut fwd: Vec<FwdOptionEntry> = h
                        .fwd
                        .iter()
                        .map(|(&(proto, port), o)| FwdOptionEntry {
                            proto,
                            port,
                            proxy: o.proxy,
                            idle_secs: o
                                .idle
                                .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
                                .unwrap_or(0),
                        })
                        .collect();
                    fwd.sort_unstable_by_key(|e| (e.port, e.proto == Proto::Udp));
                    ClientEntry {
                        client_id: id.clone(),
                        transport: transport_byte(h.transport),
                        fwd,
                    }
                })
                .collect();
            (connected, clients)
        };
        let listeners = self
            .listeners
            .lock()
            .unwrap()
            .iter()
            .map(|(&(bind_ip, proto, port), h)| Listener {
                bind_ip,
                proto,
                port,
                // A CLI-locked listener displays as `cli` so admin sees it cannot
                // be removed, even when it is also a file-declared listener.
                source: if h.cli_locked { Source::Cli } else { h.source },
            })
            .collect();
        let routes = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .map(|(&(bind_ip, proto, port), route)| RouteEntry {
                bind_ip,
                proto,
                port,
                client_id: route.client_id.clone(),
                state: if connected.contains(&route.client_id) {
                    0
                } else {
                    1
                },
                source: route.source,
            })
            .collect();
        // L2 bridge clients attach to the switch, not the forward client registry,
        // so the fleet view reads them from the switch's port table. The switch is
        // linux-only; other platforms report no bridge clients.
        #[cfg(target_os = "linux")]
        let bridge_clients =
            self.switch
                .as_ref()
                .map(|sw| {
                    sw.ports_snapshot()
                        .into_iter()
                        .map(|p| {
                            let named = p.name.as_ref().is_some_and(|s| !s.is_empty());
                            let label = p.name.filter(|s| !s.is_empty()).unwrap_or_else(|| match p
                                .peer
                            {
                                Some(a) => a.to_string(),
                                None => format!("bridge-{}", p.port_id),
                            });
                            BridgeEntry {
                                label,
                                named,
                                transport: p.transport,
                                peer: p.peer.map(|a| a.to_string()).unwrap_or_default(),
                                macs: p.macs,
                                rx_bytes: p.rx_bytes,
                                rx_frames: p.rx_frames,
                                tx_bytes: p.tx_bytes,
                                tx_frames: p.tx_frames,
                                uptime_secs: p.uptime_secs,
                                idle_secs: p.idle_secs,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
        #[cfg(not(target_os = "linux"))]
        let bridge_clients = Vec::new();
        // Accepted pairs, each with the path its two parties settled on. The
        // relay is the server's own fact and outranks a stale `direct` report;
        // a punched pair needs both reports, since one party reporting direct
        // while the other has not says nothing about a path that carries
        // traffic. Everything else is a pair still pairing.
        let mut pairs: Vec<PairEntry> = self
            .pairs
            .lock()
            .unwrap()
            .values()
            .map(|p| PairEntry {
                consumer_id: p.consumer_id.clone(),
                provider_id: p.provider_id.clone(),
                want: p.want,
                path: if p.relay.is_some() {
                    Some(PathStatus::Relay)
                } else if p.consumer.path == Some(PathStatus::Direct)
                    && p.provider.path == Some(PathStatus::Direct)
                {
                    Some(PathStatus::Direct)
                } else {
                    None
                },
            })
            .collect();
        pairs.sort_unstable_by(|a, b| {
            (&a.consumer_id, &a.provider_id, a.want).cmp(&(&b.consumer_id, &b.provider_id, b.want))
        });

        SnapshotBody {
            version: crate::identity::PROTO_VERSION,
            server_id: self.server_id.clone(),
            listeners,
            clients,
            routes,
            bridge_clients,
            pairs,
        }
    }

    /// Serialize the file-owned topology and write it crash-safely to the backing
    /// config. A runtime-only node (no `config_path`) never writes. The write runs
    /// under `save_lock` so two concurrent admin saves cannot interleave, and the
    /// blocking fsync+rename runs on a blocking thread so no tokio worker stalls.
    ///
    /// Only `Source::File` listeners and routes are serialized: CLI- and runtime-
    /// owned entries stay live in memory and are merely excluded from the file. The
    /// `[server]` table is preserved verbatim from the loaded file, so a CLI
    /// override of id/control is never baked into the saved config.
    async fn persist(&self) -> Result<()> {
        let Some(path) = self.config_path.clone() else {
            return Ok(());
        };
        let _guard = self.save_lock.lock().await;

        // Snapshot each map independently, releasing one lock before taking the
        // next, so persist never holds two of the maps at once.
        let listeners: Vec<config::CfgListener> = self
            .listeners
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, h)| h.source == Source::File)
            .map(|(&(bind_ip, proto, port), _)| config::CfgListener {
                bind_ip,
                proto,
                port,
            })
            .collect();
        let routes: Vec<config::CfgRoute> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, r)| r.source == Source::File)
            .map(|(&(bind_ip, proto, port), r)| config::CfgRoute {
                bind_ip,
                proto,
                port,
                client: r.client_id.clone(),
            })
            .collect();
        let cfg = config::ServerConfig {
            id: self.file_id.clone(),
            control: self.file_control.clone(),
            exit: self.file_exit,
            exit_iface: self.file_exit_iface.clone(),
            listeners,
            routes,
        };

        let text = config::serialize(&cfg);
        match tokio::task::spawn_blocking(move || config::save_atomic(&path, &text)).await {
            Ok(res) => res,
            Err(e) => Err(format!("config save task failed: {e}").into()),
        }
    }
}

/// Apply one admin mutation against the running server, persisting to the config
/// file when the node is config-backed. Returns `(ok, msg)`: `(true, "")` on a
/// success that also persisted (or needed no save), `(false, reason)` on a
/// bind/registry/lock error or on a save failure. A save failure returns `false`
/// even though the mutation already applied in memory, so a scripted admin detects
/// that the on-disk config did not change.
async fn apply_mutation(srv: &Arc<Server>, req: Msg) -> (bool, String) {
    // File-owned on a config-backed node, runtime-owned otherwise.
    let mutation_source = if srv.config_path.is_some() {
        Source::File
    } else {
        Source::Runtime
    };
    match req {
        Msg::AddListener {
            bind_ip,
            proto,
            port,
        } => match spawn_listener(srv, bind_ip, proto, port, mutation_source, false).await {
            Ok(()) => save_after_mutation(srv).await,
            Err(e) => (false, e.to_string()),
        },
        Msg::RemoveListener {
            bind_ip,
            proto,
            port,
        } => {
            // A CLI-locked listener is owned by the process args; refuse to remove
            // it so the operator does not silently lose a pinned forward.
            if srv
                .listeners
                .lock()
                .unwrap()
                .get(&(bind_ip, proto, port))
                .is_some_and(|h| h.cli_locked)
            {
                return (
                    false,
                    format!(
                        "listener {bind_ip} {} {port} is controlled by CLI args",
                        proto_name(proto)
                    ),
                );
            }
            match remove_listener(srv, (bind_ip, proto, port)) {
                Ok(()) => save_after_mutation(srv).await,
                Err(e) => (false, e.to_string()),
            }
        }
        Msg::SetRoute {
            bind_ip,
            proto,
            port,
            client_id,
        } => {
            let key = (bind_ip, proto, port);
            // Compared against the new target so re-pointing a route at the
            // client already serving it does not cut its traffic.
            let prev = srv.serving_client_id(key);
            srv.routes.lock().unwrap().insert(
                key,
                Route {
                    client_id: client_id.clone(),
                    source: mutation_source,
                },
            );
            if prev.as_deref() != Some(client_id.as_str()) {
                cut_established(srv, key);
            }
            save_after_mutation(srv).await
        }
        Msg::ClearRoute {
            bind_ip,
            proto,
            port,
        } => {
            let key = (bind_ip, proto, port);
            let prev = srv.serving_client_id(key);
            srv.routes.lock().unwrap().remove(&key);
            // Clearing an explicit route can hand the key to the single-client
            // fallback; only a change in the resolved target cuts traffic.
            if prev != srv.serving_client_id(key) {
                cut_established(srv, key);
            }
            save_after_mutation(srv).await
        }
        other => (false, format!("unexpected mutation message: {other:?}")),
    }
}

/// Persist after an applied mutation and map the outcome to an admin `(ok, msg)`.
/// A runtime-only node never writes, so this is `(true, "")` there too.
async fn save_after_mutation(srv: &Arc<Server>) -> (bool, String) {
    match srv.persist().await {
        Ok(()) => (true, String::new()),
        Err(e) => (
            false,
            format!("server {} rejected config save: {e}", srv.server_id),
        ),
    }
}

/// Bind the requested public port synchronously, register a cancellable listener,
/// and spawn its accept/recv loop. The bind happens before the registry insert so
/// an in-use port reports its error to the caller instead of failing in a task.
async fn spawn_listener(
    srv: &Arc<Server>,
    bind_ip: Ipv4Addr,
    proto: Proto,
    port: u16,
    source: Source,
    cli_locked: bool,
) -> Result<()> {
    let key = (bind_ip, proto, port);
    if srv.listeners.lock().unwrap().contains_key(&key) {
        return Err(format!(
            "listener {bind_ip} {} {port} already exists",
            proto_name(proto)
        )
        .into());
    }

    let cancel = Arc::new(Notify::new());
    let bridges = Arc::new(Mutex::new(Vec::new()));
    let flush = Arc::new(Notify::new());

    match proto {
        Proto::Tcp => {
            let l = TcpListener::bind((bind_ip, port))
                .await
                .map_err(|e| -> crate::Error {
                    format!("cannot bind {bind_ip}:{port}: {e}").into()
                })?;
            srv.listeners.lock().unwrap().insert(
                key,
                ListenerHandle {
                    cancel: cancel.clone(),
                    bridges: bridges.clone(),
                    flush,
                    source,
                    cli_locked,
                },
            );
            let srv = srv.clone();
            tokio::spawn(async move {
                tcp_listener(srv, l, bind_ip, port, cancel, bridges).await;
            });
        }
        Proto::Udp => {
            let socket = Arc::new(UdpSocket::bind((bind_ip, port)).await.map_err(
                |e| -> crate::Error { format!("cannot bind {bind_ip}:{port}: {e}").into() },
            )?);
            // A bind covering more than one local address must answer each source
            // from the address that source sent to; a forwarded client whose
            // socket is connected to the dialed address drops every other reply,
            // and UDP has no fallback path to fail over to.
            crate::pktinfo::record_local_addr(&socket).map_err(|e| -> crate::Error {
                format!("cannot record local addresses on {bind_ip}:{port}: {e}").into()
            })?;
            srv.listeners.lock().unwrap().insert(
                key,
                ListenerHandle {
                    cancel: cancel.clone(),
                    bridges,
                    flush: flush.clone(),
                    source,
                    cli_locked,
                },
            );
            let srv = srv.clone();
            tokio::spawn(async move {
                udp_listener(srv, socket, bind_ip, port, cancel, flush).await;
            });
        }
    }
    crate::elog!("listener added: {bind_ip} {} {port}", proto_name(proto));
    Ok(())
}

/// Cut every established flow on a listener so traffic re-resolves the route
/// table: abort the active TCP bridges (the peer sees a reset and reconnects)
/// and flush the UDP loop's per-source sessions, which closes each inbound
/// channel and ends the matching bridge. The listener itself stays bound, so
/// new connections and datagrams are served throughout. A connection accepted
/// concurrently with the cut can register its bridge after the drain and keep
/// the old target; the window is microseconds and accepted.
fn cut_established(srv: &Server, key: RouteKey) {
    let handles = srv
        .listeners
        .lock()
        .unwrap()
        .get(&key)
        .map(|h| (h.bridges.clone(), h.flush.clone()));
    let Some((bridges, flush)) = handles else {
        return;
    };
    for bridge in bridges.lock().unwrap().drain(..) {
        bridge.abort();
    }
    flush.notify_one();
    let (bind_ip, proto, port) = key;
    crate::elog!(
        "route changed: cutting established flows on {bind_ip} {} {port}",
        proto_name(proto)
    );
}

/// Remove a listener: cancel its accept/recv loop, then abort any active TCP
/// bridges it spawned. Cancelling the loop releases the bound socket so the port
/// stops accepting; for UDP the loop also drops its per-source sessions map, which
/// closes every inbound channel and tears down active UDP sources.
fn remove_listener(srv: &Server, key: RouteKey) -> Result<()> {
    let handle = srv.listeners.lock().unwrap().remove(&key);
    match handle {
        Some(h) => {
            h.cancel.notify_one();
            for bridge in h.bridges.lock().unwrap().drain(..) {
                bridge.abort();
            }
            let (bind_ip, proto, port) = key;
            crate::elog!("listener removed: {bind_ip} {} {port}", proto_name(proto));
            Ok(())
        }
        None => {
            let (bind_ip, proto, port) = key;
            Err(format!("no such listener {bind_ip} {} {port}", proto_name(proto)).into())
        }
    }
}

/// Removes a `pending` open entry when dropped. Held by a bridge task across
/// its open window so an abort (route cut, listener removal) cannot strand the
/// entry; once the client's data connection claims it, the remove is a no-op.
struct PendingReclaim {
    srv: Arc<Server>,
    id: u64,
}

impl Drop for PendingReclaim {
    fn drop(&mut self) {
        self.srv.pending.lock().unwrap().remove(&self.id);
    }
}

/// Accept public TCP connections on a pre-bound listener and bridge each to the
/// routed client, until `cancel` fires. Active bridge tasks are pushed into the
/// shared `bridges` vector so `remove_listener` can abort them on teardown.
async fn tcp_listener(
    srv: Arc<Server>,
    l: TcpListener,
    bind_ip: Ipv4Addr,
    port: u16,
    cancel: Arc<Notify>,
    bridges: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
) {
    loop {
        let (public, peer) = tokio::select! {
            _ = cancel.notified() => break,
            r = l.accept() => match r {
                Ok(v) => v,
                // Keep the forwarded port alive across transient accept errors so
                // fd pressure does not silently and permanently kill this listener.
                Err(e) => {
                    crate::elog!("tcp listener {bind_ip}:{port} accept error: {e}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
        };
        let srv = srv.clone();
        let handle = tokio::spawn(async move {
            // The accept's peer and local addresses feed a PROXY header when the
            // routed client asked for one; the bound tuple stands in if the
            // kernel cannot report the local side.
            let local = public
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from((bind_ip, port)));
            let Some((id, rx, idle)) = srv.open(bind_ip, Proto::Tcp, port, Some((peer, local)))
            else {
                return;
            };
            let _reclaim = PendingReclaim {
                srv: srv.clone(),
                id,
            };
            if let Ok(Ok((nr, nw))) = timeout(OPEN_TIMEOUT, rx).await {
                bridge::tcp(public, nr, nw, idle).await;
            }
        });
        let mut active = bridges.lock().unwrap();
        active.push(handle);
        // Bound the tracking vector over a long-lived listener.
        active.retain(|h| !h.is_finished());
    }
}

/// Accept public UDP datagrams on a pre-bound socket, demux per source, and bridge
/// each source to the routed client, until `cancel` fires. On cancel the task
/// returns, dropping `sessions`; that closes every per-source `dtx`, which ends the
/// matching `bridge::udp_server` / `udp_server_stateless` and tears down active UDP
/// sources (see `accept_udp_forward`'s teardown comment). A `flush` clears the
/// sessions map the same way but keeps the loop serving, so each live source is
/// torn down and its next datagram re-resolves the route table.
async fn udp_listener(
    srv: Arc<Server>,
    socket: Arc<UdpSocket>,
    bind_ip: Ipv4Addr,
    port: u16,
    cancel: Arc<Notify>,
    flush: Arc<Notify>,
) {
    // Each entry holds the bridge's inbound channel, the last time a datagram
    // reached it, and its eviction TTL (UDP_DATA_TTL, widened when the forward
    // carries a custom idle so the sweep never undercuts a longer-lived bridge).
    // A closed channel (bridge ended) or a stale TTL evicts the entry, so a
    // source that sends once and vanishes cannot pin a dead Sender slot forever.
    let mut sessions: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant, Duration)> =
        HashMap::new();
    let mut buf = [0u8; 65535];
    let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // A transient recv error must not kill the forwarded UDP port; log, back
        // off briefly, and keep serving. The sweep runs between recvs.
        let (n, src, local) = tokio::select! {
            _ = cancel.notified() => break,
            _ = flush.notified() => {
                sessions.clear();
                continue;
            }
            r = crate::pktinfo::recv_from(&socket, &mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    crate::elog!("udp listener {bind_ip}:{port} recv error: {e}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
            _ = sweep.tick() => {
                let now = Instant::now();
                sessions.retain(|_, (tx, last, ttl)| {
                    !tx.is_closed() && now.duration_since(*last) < *ttl
                });
                continue;
            }
        };
        let data = buf[..n].to_vec();

        // Route to an existing session; recover the datagram if it is dead.
        let data = if let Some((tx, last, _)) = sessions.get_mut(&src) {
            match tx.try_send(data) {
                Ok(()) => {
                    *last = Instant::now();
                    continue;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    *last = Instant::now();
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(v)) => {
                    sessions.remove(&src);
                    v
                }
            }
        } else {
            data
        };

        // Resolve the client serving this listener before parking the source. A
        // source with no route (and no single-client fallback) is dropped.
        let Some(handle) = srv.route_to((bind_ip, Proto::Udp, port)) else {
            continue;
        };

        // A custom per-forward idle widens the entry's TTL so the sweep cannot
        // evict a source whose bridge is deliberately allowed to idle longer.
        let fwd_idle = handle.fwd.get(&(Proto::Udp, port)).and_then(|o| o.idle);
        let ttl = match fwd_idle {
            Some(idle) => UDP_DATA_TTL.max(idle + Duration::from_secs(60)),
            None => UDP_DATA_TTL,
        };
        let (dtx, drx) = mpsc::channel::<Vec<u8>>(64);
        dtx.try_send(data).ok();
        sessions.insert(src, (dtx, Instant::now(), ttl));

        match handle.transport {
            ActiveTransport::Tcp => {
                let Some((id, rx, idle)) = srv.open(bind_ip, Proto::Udp, port, None) else {
                    sessions.remove(&src);
                    continue;
                };
                let socket = socket.clone();
                let srv = srv.clone();
                tokio::spawn(async move {
                    match timeout(OPEN_TIMEOUT, rx).await {
                        Ok(Ok((nr, nw))) => {
                            bridge::udp_server(socket, src, local, drx, nr, nw, idle).await
                        }
                        _ => {
                            srv.pending.lock().unwrap().remove(&id);
                        }
                    }
                });
            }
            ActiveTransport::Udp => {
                let id = srv.next_id();
                let idle = fwd_idle.unwrap_or(bridge::UDP_IDLE);
                srv.udp_pending
                    .lock()
                    .unwrap()
                    .insert(id, (socket.clone(), src, local, drx, idle));
                if handle
                    .tx
                    .try_send(
                        Msg::Open {
                            proto: Proto::Udp,
                            port,
                            id,
                        }
                        .encode(),
                    )
                    .is_err()
                {
                    srv.udp_pending.lock().unwrap().remove(&id);
                    sessions.remove(&src);
                } else {
                    // Reclaim the parked entry if the matching setup conv never
                    // arrives (vanished/spoofed source). `remove` by id is a no-op
                    // once `take_udp_pending` claimed it, so this is idempotent.
                    let srv = srv.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(OPEN_TIMEOUT).await;
                        srv.udp_pending.lock().unwrap().remove(&id);
                    });
                }
            }
        }
    }
}

/// Bind a UDP socket on the control port, demux per source address into a session
/// registry, and dispatch accepted convs: stream convs run the streaming server
/// handshake plus `serve_stream`; setup convs run the stateless handshake plus the
/// UDP-forward bridge.
// Bind both control sockets up front so a transient bind failure (EMFILE/
// ENOBUFS/ENOMEM) propagates out of run() and lets the supervisor restart the
// process. The UDP/KCP control transport must not be silently lost while the
// TCP listener keeps the process alive, so both binds are symmetric and fatal.
async fn bind_control_sockets(
    bind: &str,
    control_port: u16,
) -> Result<(Arc<UdpSocket>, TcpListener)> {
    let udp_control = Arc::new(UdpSocket::bind((bind, control_port)).await?);
    // A bind covering more than one local address must answer each client from
    // the address that client dialed, not from the one the route back to it
    // selects, or a client whose socket is connected to the dialed address drops
    // every reply.
    crate::pktinfo::record_local_addr(&udp_control)?;
    let tcp_control = TcpListener::bind((bind, control_port)).await?;
    Ok((udp_control, tcp_control))
}

async fn udp_control_listener(srv: Arc<Server>, socket: Arc<UdpSocket>) -> Result<()> {
    // Each entry holds the session and the last time a datagram reached it. The
    // map only retains a source once a datagram from it routes to a valid conv,
    // and the periodic sweep evicts idle or conv-less entries, so the map cannot
    // grow without bound from stray/unroutable traffic on a public port.
    let mut sessions: HashMap<SocketAddr, (Arc<Session>, Instant)> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // A transient recv error must not kill the control loop or the process;
        // log, back off briefly, and keep serving. The sweep runs between recvs;
        // dropping a session's `Arc` closes its send channel and ends socket_writer.
        let (n, src, local) = tokio::select! {
            r = crate::pktinfo::recv_from(&socket, &mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    crate::elog!("udp control recv error: {e}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
            _ = sweep.tick() => {
                let now = Instant::now();
                sessions.retain(|_, (sess, last)| {
                    now.duration_since(*last) < UDP_SESSION_TTL && !sess.is_idle()
                });
                continue;
            }
        };

        // Route through the existing session for this source, or a fresh candidate.
        // A candidate that yields no valid conv is dropped on this iteration, so
        // stray/unroutable datagrams leave no lasting session or socket_writer task.
        let (sess, known) = match sessions.get(&src) {
            Some((sess, _)) => (sess.clone(), true),
            None => {
                // Unknown source at the session cap: drop the datagram and build
                // no candidate session (so no socket_writer task spawns). A flood
                // of distinct sources cannot grow the map past the cap; existing
                // sessions keep routing. The sweep reclaims idle entries, freeing
                // room for new sources once the flood stops.
                if !admit_new_udp_session(sessions.len()) {
                    continue;
                }
                (session_from(socket.clone(), src, local, 0), false)
            }
        };

        let accepted = route(&sess, &buf[..n]);
        if known {
            // Existing session: refresh its activity deadline.
            if let Some(entry) = sessions.get_mut(&src) {
                entry.1 = Instant::now();
            }
        } else if accepted.is_some() || !sess.is_idle() {
            // First datagram from this source routed to a valid conv: retain it.
            sessions.insert(src, (sess.clone(), Instant::now()));
        }
        // Otherwise `sess` is a candidate that routed nothing; dropping it here
        // closes its send channel and ends its socket_writer task.

        match accepted {
            Some(Accepted::Stream { stream, .. }) => {
                let srv = srv.clone();
                let psk = srv.psk;
                tokio::spawn(async move {
                    let Ok(permit) = srv.handshakes.clone().acquire_owned().await else {
                        return;
                    };
                    let handshake =
                        timeout(HANDSHAKE_TIMEOUT, server_handshake(stream, &psk)).await;
                    drop(permit);
                    if let Ok(Ok((r, w))) = handshake {
                        let _ = serve_stream(srv, r, w, ActiveTransport::Udp, Some(src)).await;
                    }
                });
            }
            Some(Accepted::Setup { conv, stream }) => {
                let srv = srv.clone();
                let sess2 = sess.clone();
                let psk = srv.psk;
                tokio::spawn(async move {
                    let Ok(permit) = srv.handshakes.clone().acquire_owned().await else {
                        return;
                    };
                    // Message 2's payload carries the datagram source address
                    // back to the initiator: a probe reads its public mapping
                    // from it, every other initiator discards it.
                    let reply = crate::proto::encode_sockaddr(src);
                    let handshake = timeout(
                        HANDSHAKE_TIMEOUT,
                        server_handshake_stateless(stream, &psk, &reply),
                    )
                    .await;
                    drop(permit);
                    if let Ok(Ok((id, noise))) = handshake {
                        #[cfg(target_os = "linux")]
                        if conv == BRIDGE_CONV {
                            accept_bridge(srv, sess2, conv, noise, src).await;
                            return;
                        }
                        if srv.probes.lock().unwrap().contains_key(&id) {
                            accept_probe(srv, sess2, conv, id, noise, src).await;
                        } else if srv.relay_legs.lock().unwrap().contains_key(&id) {
                            accept_relay_leg(&srv, &sess2, conv, id, noise);
                        } else {
                            accept_udp_forward(srv, sess2, conv, id, noise).await;
                        }
                    }
                });
            }
            None => {}
        }
    }
}

/// Bridge a UDP-forward setup conv to its parked public source. The matching public
/// `Open` parked `(public socket, public src, inbound datagram channel)` under `id`;
/// the setup conv carries the same id, with `conv` (== `(id as u32) | high bit`) used
/// as the datagram tag. Replies must go out on the parked public socket so the public
/// client sees them from the port it sent to.
///
/// Cross-task UDP-source teardown chain: `udp_listener` owns the per-source sessions
/// map and the receiving end (`dgram_rx`) of each source's channel. When that
/// listener is removed (or torn down), it drops the map, closing every `dgram_rx`;
/// `udp_server_stateless` observes the closed receiver, ends, and drops its
/// `ConvGuard`, releasing the session slot.
async fn accept_udp_forward(
    srv: Arc<Server>,
    sess: Arc<Session>,
    conv: u32,
    id: u64,
    noise: StatelessNoise,
) {
    let Some((public_socket, public_src, public_local, dgram_rx, idle)) =
        take_udp_pending(&srv, id)
    else {
        return;
    };
    let noise = Arc::new(noise);
    // `_guard` keeps the session counted live for the whole bridge.
    let (inbound, _guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    crate::bridge::udp_server_stateless(
        public_socket,
        public_src,
        public_local,
        dgram_rx,
        rx,
        tx,
        idle,
    )
    .await;
}

fn take_udp_pending(srv: &Server, id: u64) -> Option<UdpPending> {
    srv.udp_pending.lock().unwrap().remove(&id)
}

/// Claim a udp-transport party's relay leg: the setup conv's app id is the leg
/// id its `PeerRelayOpen` carried, and the datagram channel under the matching
/// tag carries one inner frame per datagram.
fn accept_relay_leg(srv: &Arc<Server>, sess: &Session, conv: u32, id: u64, noise: StatelessNoise) {
    // Claim the id before registering the tag: two handshakes completing for
    // one leg id would otherwise both register it, and the loser's guard would
    // erase the winner's entry on the way out.
    let Some(pair_id) = srv.take_relay_leg(id) else {
        return;
    };
    let noise = Arc::new(noise);
    // The guard rides the leg, keeping the session counted live for as long as
    // the splice holds it.
    let (inbound, guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    srv.park_relay_leg(pair_id, RelayLeg::Dgram(rx, tx, guard));
}

/// Record a probe session's candidates against its pair: the datagram source
/// is the party's public mapping, and the first frame on the authenticated
/// session carries its local candidate. A probe whose frame never arrives
/// settles nothing; the pairing deadline reports that party relay-only.
async fn accept_probe(
    srv: Arc<Server>,
    sess: Arc<Session>,
    conv: u32,
    probe_id: u64,
    noise: StatelessNoise,
    src: SocketAddr,
) {
    // `_guard` keeps the session counted live while the frame is awaited.
    let (inbound, _guard) = sess.register_dgram(conv);
    let mut rx = DgramRx::new(inbound, Arc::new(noise));
    let local = loop {
        match timeout(PAIR_PROBE_DEADLINE, rx.recv()).await {
            Ok(Some(Frame::Data(body))) => match crate::proto::decode_sockaddr(&body) {
                Ok(a) => break a,
                Err(_) => return,
            },
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return,
        }
    };
    if let Some(pair_id) = srv.settle_probe(probe_id, vec![src, local]) {
        srv.finish_pair(pair_id);
    }
}

/// Attach a client's UDP bridge conv to the software switch. The bridge setup conv
/// carries the fixed `BRIDGE_CONV` (also the datagram tag); each client gets its
/// own switch port, so multiple clients share the one TAP. The idle reaper inside
/// the relay (plus the session's `register_dgram` guard) reclaims a silent port.
#[cfg(target_os = "linux")]
async fn accept_bridge(
    srv: Arc<Server>,
    sess: Arc<Session>,
    conv: u32,
    noise: StatelessNoise,
    src: SocketAddr,
) {
    let Some(switch) = srv.switch.clone() else {
        return;
    };
    // One bridge port per session. A second concurrent bridge attach in the same
    // session is anomalous; refuse it so two ports never learn and ping-pong the
    // same client's MAC. The guard releases on every exit path below.
    let Some(_bridge_guard) = sess.try_attach_bridge() else {
        return;
    };
    // Register the tag before the port exists: the router drops a datagram whose
    // tag is unregistered, and the client's first frame (the one that proves its
    // port) can arrive before the attach returns. `_guard` keeps the session
    // counted live for the whole bridge and drops the registration on every exit
    // path below.
    let (inbound, _guard) = sess.register_dgram(conv);
    let handle = match switch.add_dgram_port(src) {
        Ok(h) => h,
        Err(e) => {
            crate::elog!("rejecting bridge conv: {e}");
            return;
        }
    };
    let noise = Arc::new(noise);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    bridge::switch_port_dgram(handle, rx, tx).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // The UDP control bind must be fatal, exactly like the TCP control bind, so
    // a transient failure propagates out of run() and the supervisor restarts.
    // run() binds both sockets via bind_control_sockets; here we hold the UDP
    // control port first and assert the helper returns Err instead of swallowing
    // it. EADDRINUSE stands in for the EMFILE/ENOBUFS/ENOMEM cases that need root.
    // The session admission gate must enforce MAX_UDP_SESSIONS exactly: admit
    // while below the cap, refuse at and above it. This is the bound that stops a
    // flood of distinct source addresses on the public control port from growing
    // the session map (and its socket_writer tasks) without limit.
    #[test]
    fn admit_new_udp_session_enforces_cap() {
        assert!(admit_new_udp_session(0));
        assert!(admit_new_udp_session(MAX_UDP_SESSIONS - 1));
        assert!(!admit_new_udp_session(MAX_UDP_SESSIONS));
        assert!(!admit_new_udp_session(MAX_UDP_SESSIONS + 10_000));
    }

    // The control loop only gates *unknown* sources on the cap; a known source
    // already holds a slot and routes regardless of map fullness. This mirrors
    // that branch: at the cap, an established session still routes (real traffic
    // is not starved) while a fresh source is refused admission.
    #[test]
    fn established_session_not_starved_by_flood() {
        let mut sessions: HashMap<SocketAddr, ()> = HashMap::new();
        let established: SocketAddr = "127.0.0.1:1".parse().unwrap();
        sessions.insert(established, ());
        while sessions.len() < MAX_UDP_SESSIONS {
            let n = sessions.len() as u32;
            sessions.insert(format!("127.0.0.2:{}", n + 1).parse().unwrap(), ());
        }

        // A fresh source at the cap is refused: no new entry, no socket_writer.
        assert!(!admit_new_udp_session(sessions.len()));
        // The established source is a known key: it routes without re-admission.
        assert!(sessions.contains_key(&established));
    }

    #[tokio::test]
    async fn udp_control_bind_failure_is_fatal() {
        let bind = "127.0.0.1";
        let held = UdpSocket::bind((bind, 0u16)).await.expect("bind probe");
        let port = held.local_addr().expect("local addr").port();

        let err = bind_control_sockets(bind, port).await;
        assert!(
            err.is_err(),
            "occupied udp control port must make bind_control_sockets return Err"
        );
    }

    // A free port binds both control sockets and yields a usable pair.
    #[tokio::test]
    async fn bind_control_sockets_binds_both() {
        let bind = "127.0.0.1";
        let (udp, tcp) = bind_control_sockets(bind, 0)
            .await
            .expect("bind both control sockets");
        assert!(udp.local_addr().is_ok());
        assert!(tcp.local_addr().is_ok());
    }

    #[cfg(target_os = "linux")]
    fn test_tun(exit: bool, exit_iface: Option<&str>) -> ServerTun {
        ServerTun {
            device: TunConfig {
                name: "zn0".into(),
                mtu: 1400,
                addr: Ipv4Addr::new(10, 9, 8, 1),
                prefix_len: 24,
            },
            subnet: Ipv4Addr::new(10, 9, 8, 0),
            client_ip: Ipv4Addr::new(10, 9, 8, 2),
            except: Vec::new(),
            exit,
            exit_iface: exit_iface.map(str::to_string),
        }
    }

    // One default via eth0 plus a connected route, in /proc/net/route layout.
    #[cfg(target_os = "linux")]
    const PROC_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_nat_plan_without_exit_has_no_egress() {
        let plan = tun_nat_plan(&test_tun(false, None), 2222, PROC_ROUTE).unwrap();
        assert!(plan.egress.is_none());
        assert!(plan.dnat.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_nat_plan_exit_iface_wins_over_default_route() {
        let plan = tun_nat_plan(&test_tun(true, Some("wan1")), 2222, PROC_ROUTE).unwrap();
        assert_eq!(plan.egress.as_deref(), Some("wan1"));
        // The inbound DNAT rides along untouched: the two are independent.
        assert!(plan.dnat.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_nat_plan_exit_auto_detects_default_route() {
        let plan = tun_nat_plan(&test_tun(true, None), 2222, PROC_ROUTE).unwrap();
        assert_eq!(plan.egress.as_deref(), Some("eth0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_nat_plan_exit_auto_detects_gatewayless_default() {
        // A point-to-point uplink carries the default with no gateway; it is
        // still the egress interface.
        let ppp_route = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
";
        let plan = tun_nat_plan(&test_tun(true, None), 2222, ppp_route).unwrap();
        assert_eq!(plan.egress.as_deref(), Some("ppp0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_nat_plan_exit_without_default_route_is_fatal() {
        // A default route already on the tun device does not count either.
        let tun_default = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
zn0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        assert!(tun_nat_plan(&test_tun(true, None), 2222, "").is_err());
        assert!(tun_nat_plan(&test_tun(true, None), 2222, tun_default).is_err());
    }

    fn test_server() -> Arc<Server> {
        Arc::new(Server {
            psk: crate::noise::derive_psk("test-secret"),
            server_id: "test".into(),
            next_id: Mutex::new(1),
            pending: Mutex::new(HashMap::new()),
            udp_pending: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
            known_clients: Mutex::new(HashSet::new()),
            pairs: Mutex::new(HashMap::new()),
            probes: Mutex::new(HashMap::new()),
            relay_legs: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            handshakes: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES)),
            config_path: None,
            file_id: None,
            file_control: None,
            file_exit: None,
            file_exit_iface: None,
            save_lock: tokio::sync::Mutex::new(()),
            #[cfg(target_os = "linux")]
            switch: None,
        })
    }

    // A peer that finishes the handshake then never sends its role frame must not
    // park serve_stream forever (the fd/task leak this guard closes). Under paused
    // time the CONTROL_TIMEOUT window elapses with no real wait, and serve_stream
    // returns Err so the task and its half of the duplex are dropped. The client
    // handshake end is held open for the whole window to model a live-but-silent
    // peer (a closed end would fail the read early and hide the timeout path).
    #[tokio::test(start_paused = true)]
    async fn serve_stream_times_out_silent_role_frame() {
        let srv = test_server();
        let (client_io, server_io) = tokio::io::duplex(8192);
        let psk = srv.psk;

        let client = tokio::spawn(async move {
            let (_cr, _cw) = crate::noise::client_handshake(client_io, &psk)
                .await
                .expect("client handshake");
            // Never send a role frame; keep the connection open and idle.
            std::future::pending::<()>().await;
        });

        let (r, w) = crate::noise::server_handshake(server_io, &srv.psk)
            .await
            .expect("server handshake");
        let res = serve_stream(srv, r, w, ActiveTransport::Tcp, None).await;
        assert!(
            res.is_err(),
            "silent role frame must time out and release the task"
        );
        client.abort();
    }

    // The admin mutate path takes a second read after AdminHello. An admin that
    // announces mode 1 then never sends the request must hit the same guard.
    #[tokio::test(start_paused = true)]
    async fn serve_stream_times_out_silent_admin_request() {
        let srv = test_server();
        let (client_io, server_io) = tokio::io::duplex(8192);
        let psk = srv.psk;

        let client = tokio::spawn(async move {
            let (_cr, mut cw) = crate::noise::client_handshake(client_io, &psk)
                .await
                .expect("client handshake");
            let hello = Msg::AdminHello {
                version: crate::identity::PROTO_VERSION,
                mode: 1,
            }
            .encode();
            cw.send(&hello).await.expect("send admin hello");
            // Never send the mutation request; keep the connection open and idle.
            std::future::pending::<()>().await;
        });

        let (r, w) = crate::noise::server_handshake(server_io, &srv.psk)
            .await
            .expect("server handshake");
        let res = serve_stream(srv, r, w, ActiveTransport::Tcp, None).await;
        assert!(
            res.is_err(),
            "silent admin request must time out and release the task"
        );
        client.abort();
    }

    /// Insert a live client handle with the given announced peer bitset,
    /// recording the id as registered like a real `ClientHello` does. Returns
    /// the handle's control sender (the session identity `peer_connect`
    /// checks) and the receiver keeping the channel open; dropping the
    /// receiver models an entry whose control session is no longer live.
    fn register_peer_client(
        srv: &Server,
        id: &str,
        peer_provides: Option<u8>,
    ) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        register_peer_client_with(srv, id, peer_provides, ActiveTransport::Tcp)
    }

    fn register_peer_client_with(
        srv: &Server,
        id: &str,
        peer_provides: Option<u8>,
        transport: ActiveTransport,
    ) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(8);
        srv.clients.lock().unwrap().insert(
            id.into(),
            ClientHandle {
                tx: tx.clone(),
                transport,
                fwd: Arc::new(HashMap::new()),
                observed: None,
                peer_provides,
            },
        );
        srv.known_clients.lock().unwrap().insert(id.into());
        (tx, rx)
    }

    // Every PeerConnect failure names its reason: an id the server has never
    // seen, a registered id with no live session (torn down or mid-teardown),
    // a provider that never announced, and one whose announced bitset lacks
    // the requested bit. None of them may insert a pair.
    #[test]
    fn peer_connect_failure_statuses() {
        use crate::proto::PROVIDES_SEGMENT;
        let srv = test_server();
        let (c_tx, _c_rx) = register_peer_client(&srv, "c", Some(0));

        assert_eq!(
            srv.peer_connect("c", &c_tx, "ghost", PROVIDES_EXIT),
            Some((0, PeerStatus::UnknownPeer))
        );

        // A completed disconnect removes the registry entry; the id stays known.
        drop(register_peer_client(&srv, "left", Some(PROVIDES_EXIT)));
        srv.clients.lock().unwrap().remove("left");
        assert_eq!(
            srv.peer_connect("c", &c_tx, "left", PROVIDES_EXIT),
            Some((0, PeerStatus::PeerOffline))
        );

        // Mid-teardown the entry lingers with a closed channel; still offline.
        drop(register_peer_client(&srv, "gone", Some(PROVIDES_EXIT)));
        assert_eq!(
            srv.peer_connect("c", &c_tx, "gone", PROVIDES_EXIT),
            Some((0, PeerStatus::PeerOffline))
        );

        let _mute = register_peer_client(&srv, "mute", None);
        assert_eq!(
            srv.peer_connect("c", &c_tx, "mute", PROVIDES_EXIT),
            Some((0, PeerStatus::NotProvided))
        );

        let _seg = register_peer_client(&srv, "seg", Some(PROVIDES_SEGMENT));
        assert_eq!(
            srv.peer_connect("c", &c_tx, "seg", PROVIDES_EXIT),
            Some((0, PeerStatus::NotProvided))
        );

        // A party naming itself reads as unknown, whether or not it provides
        // the capability it asks for. The punch elects roles by comparing the
        // two ids, so a self-pair would leave both ends responders while
        // holding the provider's exclusive slot.
        let (self_tx, _self_rx) = register_peer_client(&srv, "solo", Some(PROVIDES_EXIT));
        assert_eq!(
            srv.peer_connect("solo", &self_tx, "solo", PROVIDES_EXIT),
            Some((0, PeerStatus::UnknownPeer))
        );
        assert_eq!(
            srv.peer_connect("c", &c_tx, "c", PROVIDES_EXIT),
            Some((0, PeerStatus::UnknownPeer))
        );

        assert!(srv.pairs.lock().unwrap().is_empty());
    }

    // Busy is per capability (a dual provider's segment side stays open while
    // its exit slot is taken), and invalidating the holding consumer frees the
    // exclusive slot.
    #[test]
    fn exit_pairs_are_exclusive_segment_pairs_are_not() {
        use crate::proto::PROVIDES_SEGMENT;
        let srv = test_server();
        let (_prov_tx, _prov_rx) =
            register_peer_client(&srv, "prov", Some(PROVIDES_EXIT | PROVIDES_SEGMENT));
        let (c1_tx, _c1_rx) = register_peer_client(&srv, "c1", Some(0));
        let (c2_tx, _c2_rx) = register_peer_client(&srv, "c2", Some(0));

        let (exit_pair, status) = srv
            .peer_connect("c1", &c1_tx, "prov", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        assert_ne!(exit_pair, 0);
        assert_eq!(
            srv.peer_connect("c2", &c2_tx, "prov", PROVIDES_EXIT),
            Some((0, PeerStatus::PeerBusy))
        );

        let (seg1, status1) = srv
            .peer_connect("c1", &c1_tx, "prov", PROVIDES_SEGMENT)
            .unwrap();
        let (seg2, status2) = srv
            .peer_connect("c2", &c2_tx, "prov", PROVIDES_SEGMENT)
            .unwrap();
        assert_eq!(status1, PeerStatus::Accepted);
        assert_eq!(status2, PeerStatus::Accepted);
        assert_ne!(seg1, seg2);

        srv.invalidate_pairs("c1");
        let (_, status) = srv
            .peer_connect("c2", &c2_tx, "prov", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
    }

    // A fresh connect replaces the pair its consumer already holds for that
    // peer and capability, and reclaims the rendezvous ids that pair owned.
    // Pairs the same consumer holds for another peer, or for another
    // capability of the same peer, stand.
    #[tokio::test(start_paused = true)]
    async fn consumer_pairs_are_replaced_by_a_fresh_connect() {
        use crate::proto::PROVIDES_SEGMENT;
        let srv = test_server();
        let (_prov_tx, _prov_rx) =
            register_peer_client(&srv, "prov", Some(PROVIDES_EXIT | PROVIDES_SEGMENT));
        let (_prov2_tx, _prov2_rx) = register_peer_client(&srv, "prov2", Some(PROVIDES_EXIT));
        let (c_tx, _c_rx) = register_peer_client(&srv, "c", Some(0));
        let (other_tx, _other_rx) = register_peer_client(&srv, "other", Some(0));

        let (first, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        srv.peer_path("c", &c_tx, first, PathStatus::Relay);
        assert_eq!(srv.relay_legs.lock().unwrap().len(), 2);

        let (second, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        assert_ne!(second, first);
        let pairs = srv.pairs.lock().unwrap();
        assert_eq!(pairs.len(), 1);
        assert!(pairs.contains_key(&second));
        drop(pairs);
        assert!(srv.relay_legs.lock().unwrap().is_empty());

        // The one exclusive slot is held by the live pair, so another consumer
        // still reads busy.
        assert_eq!(
            srv.peer_connect("other", &other_tx, "prov", PROVIDES_EXIT),
            Some((0, PeerStatus::PeerBusy))
        );

        // A connect naming a different peer replaces nothing.
        let (_, status) = srv
            .peer_connect("c", &c_tx, "prov2", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        assert!(
            srv.pairs.lock().unwrap().contains_key(&second),
            "the pair for the other peer stands"
        );

        // Neither does one naming a different capability of the same peer.
        let (_, status) = srv
            .peer_connect("c", &c_tx, "prov", PROVIDES_SEGMENT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        assert!(
            srv.pairs.lock().unwrap().contains_key(&second),
            "the exit pair stands while the segment pair opens"
        );
    }

    /// Let the claim deadline lapse and give the reaper it armed a turn.
    async fn advance_past_claim_deadline() {
        tokio::time::sleep(RELAY_CLAIM_DEADLINE + Duration::from_secs(1)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    // Opening the relay arms a claim deadline. A relay that spliced in time
    // survives it and is left to its own teardown; one whose second leg never
    // arrives is dropped, because the pair carries nothing and holding it
    // would answer the consumer's own retry with peer_busy for as long as
    // both control sessions stayed up.
    #[tokio::test(start_paused = true)]
    async fn unclaimed_relay_legs_free_the_exclusive_provider() {
        let srv = test_server();
        let (_prov_tx, _prov_rx) = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (c1_tx, _c1_rx) = register_peer_client(&srv, "c1", Some(0));
        let (c2_tx, _c2_rx) = register_peer_client(&srv, "c2", Some(0));

        let (spliced, status) = srv
            .peer_connect("c1", &c1_tx, "prov", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        srv.peer_path("c1", &c1_tx, spliced, PathStatus::Relay);
        let (stop, _stop_rx) = oneshot::channel();
        {
            let mut pairs = srv.pairs.lock().unwrap();
            let relay = pairs
                .get_mut(&spliced)
                .and_then(|p| p.relay.as_mut())
                .expect("the report opened the relay");
            relay.state = RelayState::Spliced { _stop: stop };
        }

        advance_past_claim_deadline().await;
        assert!(
            srv.pairs.lock().unwrap().contains_key(&spliced),
            "a spliced relay outlives the claim deadline"
        );
        assert_eq!(
            srv.peer_connect("c2", &c2_tx, "prov", PROVIDES_EXIT),
            Some((0, PeerStatus::PeerBusy))
        );

        // The next pair is handed its legs and neither party ever claims one.
        srv.end_relay(spliced);
        let (unclaimed, status) = srv
            .peer_connect("c2", &c2_tx, "prov", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        srv.peer_path("c2", &c2_tx, unclaimed, PathStatus::Relay);

        advance_past_claim_deadline().await;
        assert!(srv.pairs.lock().unwrap().is_empty());
        assert!(srv.relay_legs.lock().unwrap().is_empty());
        let (next, status) = srv
            .peer_connect("c2", &c2_tx, "prov", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        assert_ne!(next, unclaimed);
    }

    // The liveness check and the pair insert share the clients guard, so a
    // pair only lands while the provider entry is live and the teardown that
    // removes the entry always invalidates it afterwards. The cross-task
    // interleaving itself is not reachable from a test seam; this pins the
    // observable invariant by replaying the teardown order: after removal
    // plus invalidation no stale pair remains, and the provider's reconnect
    // pairs instead of reading busy.
    #[test]
    fn provider_teardown_leaves_no_stale_pair_to_wedge_reconnect() {
        let srv = test_server();
        let live = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (c_tx, _c_rx) = register_peer_client(&srv, "c", Some(0));
        let (first, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);

        drop(live);
        srv.clients.lock().unwrap().remove("prov");
        srv.invalidate_pairs("prov");
        assert_eq!(
            srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT),
            Some((0, PeerStatus::PeerOffline))
        );
        assert!(srv.pairs.lock().unwrap().is_empty());

        let (_prov_tx, _prov_rx) = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (second, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        assert_ne!(second, first);
    }

    // Invalidation removes and returns every pair the client is a party to,
    // consumer and provider roles alike.
    #[test]
    fn invalidate_pairs_covers_both_roles() {
        use crate::proto::PROVIDES_SEGMENT;
        let srv = test_server();
        let (_a_tx, _a_rx) = register_peer_client(&srv, "a", Some(PROVIDES_EXIT));
        let (b_tx, _b_rx) = register_peer_client(&srv, "b", Some(PROVIDES_SEGMENT));
        let (c_tx, _c_rx) = register_peer_client(&srv, "c", Some(0));

        srv.peer_connect("b", &b_tx, "a", PROVIDES_EXIT);
        srv.peer_connect("c", &c_tx, "b", PROVIDES_SEGMENT);
        assert_eq!(srv.pairs.lock().unwrap().len(), 2);

        assert_eq!(srv.invalidate_pairs("b").len(), 2);
        assert!(srv.pairs.lock().unwrap().is_empty());
    }

    // A connect from a session whose registry slot was swapped by a reconnect
    // under the same id inserts nothing and gets no reply, so a stale reader
    // cannot wedge an exclusive provider with a pair no live session owns.
    #[test]
    fn superseded_consumer_connect_is_dropped() {
        let srv = test_server();
        let (_prov_tx, _prov_rx) = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (stale_tx, _stale_rx) = register_peer_client(&srv, "c", Some(0));
        let (new_tx, _new_rx) = register_peer_client(&srv, "c", Some(0));

        assert_eq!(
            srv.peer_connect("c", &stale_tx, "prov", PROVIDES_EXIT),
            None
        );
        assert!(srv.pairs.lock().unwrap().is_empty());

        // The session that owns the slot pairs as usual.
        let (pair_id, status) = srv
            .peer_connect("c", &new_tx, "prov", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        assert_ne!(pair_id, 0);
    }

    // PeerAnnounce is acked with the control address recorded at registration,
    // and the announced bitset lands on the registry entry that gates every
    // later peer tag.
    #[tokio::test]
    async fn peer_announce_acked_with_recorded_address() {
        let srv = test_server();
        let (client_io, server_io) = tokio::io::duplex(8192);
        let psk = srv.psk;
        let observed: SocketAddr = "203.0.113.7:4321".parse().unwrap();

        let srv2 = srv.clone();
        let server = tokio::spawn(async move {
            let (r, w) = crate::noise::server_handshake(server_io, &psk)
                .await
                .expect("server handshake");
            let _ = serve_stream(srv2, r, w, ActiveTransport::Tcp, Some(observed)).await;
        });

        let (mut cr, mut cw) = crate::noise::client_handshake(client_io, &psk)
            .await
            .expect("client handshake");
        cw.send(
            &Msg::ClientHello {
                version: crate::identity::PROTO_VERSION,
                client_id: "prov".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
        cw.send(
            &Msg::PeerAnnounce {
                provides: PROVIDES_EXIT,
            }
            .encode(),
        )
        .await
        .unwrap();

        let bytes = timeout(Duration::from_secs(10), cr.recv())
            .await
            .expect("no announce ack")
            .unwrap();
        match Msg::decode(&bytes).unwrap() {
            Msg::PeerAnnounceAck { observed: got } => assert_eq!(got, observed),
            other => panic!("expected announce ack, got {other:?}"),
        }
        assert_eq!(
            srv.clients
                .lock()
                .unwrap()
                .get("prov")
                .unwrap()
                .peer_provides,
            Some(PROVIDES_EXIT)
        );
        server.abort();
    }

    // A PeerConnect from a client that never announced gets no reply. Control
    // replies are ordered, so the Pong for the ping sent right after the
    // connect proves no PeerResult was queued ahead of it.
    #[tokio::test]
    async fn peer_connect_before_announce_is_dropped() {
        let srv = test_server();
        let (client_io, server_io) = tokio::io::duplex(8192);
        let psk = srv.psk;

        let srv2 = srv.clone();
        let server = tokio::spawn(async move {
            let (r, w) = crate::noise::server_handshake(server_io, &psk)
                .await
                .expect("server handshake");
            let peer = Some("192.0.2.1:1".parse().unwrap());
            let _ = serve_stream(srv2, r, w, ActiveTransport::Tcp, peer).await;
        });

        let (mut cr, mut cw) = crate::noise::client_handshake(client_io, &psk)
            .await
            .expect("client handshake");
        cw.send(
            &Msg::ClientHello {
                version: crate::identity::PROTO_VERSION,
                client_id: "c".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
        cw.send(
            &Msg::PeerConnect {
                peer_id: "prov".into(),
                want: PROVIDES_EXIT,
            }
            .encode(),
        )
        .await
        .unwrap();
        cw.send(&Msg::Ping.encode()).await.unwrap();

        let bytes = timeout(Duration::from_secs(10), cr.recv())
            .await
            .expect("no pong")
            .unwrap();
        assert!(
            matches!(Msg::decode(&bytes), Ok(Msg::Pong)),
            "unannounced PeerConnect must be dropped without a reply"
        );
        assert!(srv.pairs.lock().unwrap().is_empty());
        server.abort();
    }

    /// Decode the next frame queued on a registered client's control channel.
    fn next_msg(rx: &mut mpsc::Receiver<Vec<u8>>) -> Msg {
        Msg::decode(&rx.try_recv().expect("queued control frame")).expect("decodable frame")
    }

    /// Pair two registered udp-transport clients, start their probes, and
    /// return the pair id plus each party's `PeerProbe`-assigned probe id.
    fn paired_udp_probes(
        srv: &Arc<Server>,
        c_tx: &mpsc::Sender<Vec<u8>>,
        c_rx: &mut mpsc::Receiver<Vec<u8>>,
        p_rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> (u64, u64, u64) {
        let (pair_id, status) = srv.peer_connect("c", c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        srv.start_pair_probes(pair_id);
        let probe_of = |rx: &mut mpsc::Receiver<Vec<u8>>, peer: &str| match next_msg(rx) {
            Msg::PeerProbe {
                pair_id: got,
                peer_id,
                probe_id,
                provides,
            } => {
                assert_eq!(got, pair_id);
                assert_eq!(peer_id, peer);
                assert_eq!(provides, PROVIDES_EXIT);
                probe_id
            }
            other => panic!("expected peer probe, got {other:?}"),
        };
        let c_probe = probe_of(c_rx, "prov");
        let p_probe = probe_of(p_rx, "c");
        assert_ne!(c_probe, p_probe);
        (pair_id, c_probe, p_probe)
    }

    // Each udp party gets its own probe id, mapped for app-id classification,
    // and a party that never reports is announced relay-only at the deadline
    // while the reporting party's candidates still reach the other side.
    #[tokio::test(start_paused = true)]
    async fn pair_probe_deadline_reports_silent_party_relay_only() {
        let srv = test_server();
        let (_p_tx, mut p_rx) =
            register_peer_client_with(&srv, "prov", Some(PROVIDES_EXIT), ActiveTransport::Udp);
        let (c_tx, mut c_rx) = register_peer_client_with(&srv, "c", Some(0), ActiveTransport::Udp);
        let (pair_id, c_probe, p_probe) = paired_udp_probes(&srv, &c_tx, &mut c_rx, &mut p_rx);
        {
            let probes = srv.probes.lock().unwrap();
            assert_eq!(probes.get(&c_probe), Some(&pair_id));
            assert_eq!(probes.get(&p_probe), Some(&pair_id));
        }

        // The provider reports; the consumer stays silent past the deadline.
        let public: SocketAddr = "203.0.113.9:41641".parse().unwrap();
        let local: SocketAddr = "192.168.1.9:41641".parse().unwrap();
        assert_eq!(srv.settle_probe(p_probe, vec![public, local]), None);

        let bytes = timeout(Duration::from_secs(60), c_rx.recv())
            .await
            .expect("no peer info at the deadline")
            .unwrap();
        match Msg::decode(&bytes).unwrap() {
            Msg::PeerInfo {
                pair_id: got,
                candidates,
            } => {
                assert_eq!(got, pair_id);
                assert_eq!(candidates, vec![public, local]);
            }
            other => panic!("expected peer info, got {other:?}"),
        }
        match next_msg(&mut p_rx) {
            Msg::PeerInfo { candidates, .. } => assert!(candidates.is_empty()),
            other => panic!("expected peer info, got {other:?}"),
        }
        // A reported pair holds no probe ids, and a late report settles nothing.
        assert!(srv.probes.lock().unwrap().is_empty());
        assert_eq!(srv.settle_probe(c_probe, vec![public]), None);
    }

    // Both parties reporting completes the pair before the deadline: each
    // side's `PeerInfo` carries the other's candidates, duplicate and late
    // reports are ignored, and the lapsed deadline sends nothing further.
    #[tokio::test(start_paused = true)]
    async fn pair_probe_completion_sends_info_before_deadline() {
        let srv = test_server();
        let (_p_tx, mut p_rx) =
            register_peer_client_with(&srv, "prov", Some(PROVIDES_EXIT), ActiveTransport::Udp);
        let (c_tx, mut c_rx) = register_peer_client_with(&srv, "c", Some(0), ActiveTransport::Udp);
        let (pair_id, c_probe, p_probe) = paired_udp_probes(&srv, &c_tx, &mut c_rx, &mut p_rx);

        let c_cand: Vec<SocketAddr> = vec![
            "198.51.100.1:1000".parse().unwrap(),
            "10.0.0.1:1000".parse().unwrap(),
        ];
        let p_cand: Vec<SocketAddr> = vec![
            "198.51.100.2:2000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
        ];
        assert_eq!(srv.settle_probe(c_probe, c_cand.clone()), None);
        assert_eq!(srv.settle_probe(p_probe, p_cand.clone()), Some(pair_id));
        srv.finish_pair(pair_id);

        match next_msg(&mut c_rx) {
            Msg::PeerInfo { candidates, .. } => assert_eq!(candidates, p_cand),
            other => panic!("expected peer info, got {other:?}"),
        }
        match next_msg(&mut p_rx) {
            Msg::PeerInfo { candidates, .. } => assert_eq!(candidates, c_cand),
            other => panic!("expected peer info, got {other:?}"),
        }
        assert!(srv.probes.lock().unwrap().is_empty());
        assert_eq!(srv.settle_probe(c_probe, c_cand), None);

        tokio::time::sleep(PAIR_PROBE_DEADLINE * 2).await;
        assert!(c_rx.try_recv().is_err());
        assert!(p_rx.try_recv().is_err());
    }

    // A tcp-transport party takes its `PeerProbe` as the pair notification
    // alone: the frame names the peer and the capability, its probe id is
    // mapped nowhere, and the party settles relay-only at once, so the
    // `PeerInfo` follows immediately with an empty candidate list.
    #[tokio::test]
    async fn tcp_transport_parties_settle_relay_only_immediately() {
        let srv = test_server();
        let (_p_tx, mut p_rx) = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (c_tx, mut c_rx) = register_peer_client(&srv, "c", Some(0));
        let (pair_id, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        srv.start_pair_probes(pair_id);

        for (rx, peer) in [(&mut c_rx, "prov"), (&mut p_rx, "c")] {
            let probe_id = match next_msg(rx) {
                Msg::PeerProbe {
                    pair_id: got,
                    peer_id,
                    probe_id,
                    provides,
                } => {
                    assert_eq!(got, pair_id);
                    assert_eq!(peer_id, peer);
                    assert_eq!(provides, PROVIDES_EXIT);
                    probe_id
                }
                other => panic!("expected peer probe, got {other:?}"),
            };
            // The id is inert: nothing can be settled under it.
            assert_eq!(srv.settle_probe(probe_id, vec![]), None);
            match next_msg(rx) {
                Msg::PeerInfo {
                    pair_id: got,
                    candidates,
                } => {
                    assert_eq!(got, pair_id);
                    assert!(candidates.is_empty());
                }
                other => panic!("expected immediate peer info, got {other:?}"),
            }
        }
        assert!(srv.probes.lock().unwrap().is_empty());
    }

    // A punch outcome lands on the pair only when the reporting session owns
    // its registry slot and is a party to it. A stranger's report, one naming
    // an unknown pair, a repeat after the first, and one from a session a
    // reconnect superseded are all dropped.
    #[tokio::test]
    async fn peer_path_records_only_a_live_party() {
        let srv = test_server();
        let (p_tx, _p_rx) = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (c_tx, _c_rx) = register_peer_client(&srv, "c", Some(0));
        let (o_tx, _o_rx) = register_peer_client(&srv, "other", Some(0));
        let (pair_id, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);

        // Both slots are still empty, so a stranger's report has somewhere to
        // land if the membership check regresses. A report for a pair id that
        // does not exist must return rather than panic.
        srv.peer_path("other", &o_tx, pair_id, PathStatus::Relay);
        srv.peer_path("c", &c_tx, pair_id + 1000, PathStatus::Relay);
        {
            let pairs = srv.pairs.lock().unwrap();
            let pair = pairs.get(&pair_id).unwrap();
            assert_eq!(pair.consumer.path, None);
            assert_eq!(pair.provider.path, None);
        }

        // Each party's own report lands, and the repeat that follows does not
        // rewrite it.
        srv.peer_path("c", &c_tx, pair_id, PathStatus::Direct);
        srv.peer_path("prov", &p_tx, pair_id, PathStatus::Relay);
        srv.peer_path("c", &c_tx, pair_id, PathStatus::Relay);
        {
            let pairs = srv.pairs.lock().unwrap();
            let pair = pairs.get(&pair_id).unwrap();
            assert_eq!(pair.consumer.path, Some(PathStatus::Direct));
            assert_eq!(pair.provider.path, Some(PathStatus::Relay));
        }

        // A reconnect under the same id swaps the registry entry, so the
        // stale session's report lands nowhere.
        srv.invalidate_pairs("c");
        let (new_tx, _new_rx) = register_peer_client(&srv, "c", Some(0));
        let (pair2, status) = srv
            .peer_connect("c", &new_tx, "prov", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        srv.peer_path("c", &c_tx, pair2, PathStatus::Direct);
        assert_eq!(
            srv.pairs.lock().unwrap().get(&pair2).unwrap().consumer.path,
            None
        );
    }

    // The path a snapshot shows is the pair's, not a party's: a punched path
    // needs both reports, the relay is the server's own fact and outranks a
    // party still reporting direct, and anything short of that is pairing.
    #[tokio::test]
    async fn snapshot_pairs_settle_on_both_reports() {
        let srv = test_server();
        // Exit is exclusive, so the two pairs take a provider each.
        let (p_tx, _p_rx) = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (q_tx, _q_rx) = register_peer_client(&srv, "prov2", Some(PROVIDES_EXIT));
        let (c_tx, _c_rx) = register_peer_client(&srv, "c", Some(0));
        let (d_tx, _d_rx) = register_peer_client(&srv, "d", Some(0));
        let (punched, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        let (relayed, status) = srv
            .peer_connect("d", &d_tx, "prov2", PROVIDES_EXIT)
            .unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        let path = |consumer: &str| {
            srv.snapshot()
                .pairs
                .into_iter()
                .find(|p| p.consumer_id == consumer)
                .expect("pair in the snapshot")
                .path
        };

        // Neither party has reported yet.
        assert_eq!(path("c"), None);

        // One direct report says nothing about a path that carries traffic.
        srv.peer_path("c", &c_tx, punched, PathStatus::Direct);
        assert_eq!(path("c"), None);
        srv.peer_path("prov", &p_tx, punched, PathStatus::Direct);
        assert_eq!(path("c"), Some(PathStatus::Direct));

        // The relay the server opened outranks the direct report the other
        // party filed before it.
        srv.peer_path("d", &d_tx, relayed, PathStatus::Direct);
        srv.peer_path("prov2", &q_tx, relayed, PathStatus::Relay);
        assert_eq!(path("d"), Some(PathStatus::Relay));
    }

    // Probe state dies with the pair: invalidation drops the outstanding
    // probe ids, so a report for a dead pair settles nothing.
    #[tokio::test(start_paused = true)]
    async fn invalidate_pairs_clears_probe_state() {
        let srv = test_server();
        let (_p_tx, mut p_rx) =
            register_peer_client_with(&srv, "prov", Some(PROVIDES_EXIT), ActiveTransport::Udp);
        let (c_tx, mut c_rx) = register_peer_client_with(&srv, "c", Some(0), ActiveTransport::Udp);
        let (_pair_id, c_probe, _p_probe) = paired_udp_probes(&srv, &c_tx, &mut c_rx, &mut p_rx);

        assert_eq!(srv.invalidate_pairs("c").len(), 1);
        assert!(srv.probes.lock().unwrap().is_empty());
        assert_eq!(
            srv.settle_probe(c_probe, vec!["203.0.113.9:41641".parse().unwrap()]),
            None
        );
    }
}
