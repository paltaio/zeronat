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
use crate::kcp::{route, session, Accepted, Session};
#[cfg(target_os = "linux")]
use crate::kcp::{BRIDGE_CONV, BRIDGE_ID};
#[cfg(target_os = "linux")]
use crate::netfilter;
use crate::noise::{server_handshake, server_handshake_stateless, Noise, StatelessNoise};
#[cfg(target_os = "linux")]
use crate::proto::BridgeEntry;
use crate::proto::{
    proto_name, ClientEntry, FwdOptionEntry, Listener, Msg, PeerStatus, Proto, RouteEntry,
    SnapshotBody, Source, PROVIDES_EXIT,
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
}

/// One party's probe progress. `probe_id` is assigned when the party can
/// probe (udp control transport). `candidates` is `None` until the party
/// settles: the server-observed public mapping plus the party's reported
/// local candidate, or empty for a relay-only party.
#[derive(Default)]
struct PartyProbe {
    probe_id: Option<u64>,
    candidates: Option<Vec<SocketAddr>>,
}

/// A parked public UDP source, the public socket its replies must go out on, the
/// channel carrying its inbound datagrams, and the relay's idle window, awaiting
/// the matching UDP-forward setup conv.
type UdpPending = (
    Arc<UdpSocket>,
    SocketAddr,
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
    /// so two consumers racing for an exclusive provider cannot both pair.
    /// Lock order is clients before pairs. A failure status carries pair_id 0.
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
            },
        );
        crate::elog!("peer pair {pair_id}: {consumer_id} -> {provider_id}");
        Some((pair_id, PeerStatus::Accepted))
    }

    /// Remove and return every pair `client_id` is a party to, dropping any
    /// outstanding probe ids with them. A pair must not outlive either
    /// party's control session, so this runs when a session ends and when a
    /// reconnect supersedes it.
    fn invalidate_pairs(&self, client_id: &str) -> Vec<(u64, Pair)> {
        let removed: Vec<(u64, Pair)> = self
            .pairs
            .lock()
            .unwrap()
            .extract_if(|_, p| p.consumer_id == client_id || p.provider_id == client_id)
            .collect();
        if !removed.is_empty() {
            let mut probes = self.probes.lock().unwrap();
            for (_, p) in &removed {
                for id in [p.consumer.probe_id, p.provider.probe_id]
                    .into_iter()
                    .flatten()
                {
                    probes.remove(&id);
                }
            }
        }
        removed
    }

    /// Start candidate discovery for a freshly accepted pair: assign each
    /// udp-transport party a probe id from the shared counter, send it a
    /// `PeerProbe`, and arm the pairing deadline. A tcp-transport party never
    /// probes and settles as relay-only at once, so a pair of tcp clients is
    /// finished before the deadline task even arms. The sends run outside
    /// every lock; lock order is clients, pairs, probes, with `next_id` a leaf.
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
                match h.transport {
                    ActiveTransport::Tcp => party.candidates = Some(Vec::new()),
                    ActiveTransport::Udp => {
                        let probe_id = self.next_id();
                        party.probe_id = Some(probe_id);
                        probes.insert(probe_id, pair_id);
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
                }
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
            // cannot drop pairs the superseding session created.
            if removed {
                srv.invalidate_pairs(&client_id);
            }
            writer.abort();
            crate::elog!("client {client_id} disconnected");
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
            if let Some(tx) = srv.pending.lock().unwrap().remove(&id) {
                let _ = tx.send((r, w));
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

        SnapshotBody {
            version: crate::identity::PROTO_VERSION,
            server_id: self.server_id.clone(),
            listeners,
            clients,
            routes,
            bridge_clients,
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
        let (n, src) = tokio::select! {
            _ = cancel.notified() => break,
            _ = flush.notified() => {
                sessions.clear();
                continue;
            }
            r = socket.recv_from(&mut buf) => match r {
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
                            bridge::udp_server(socket, src, drx, nr, nw, idle).await
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
                    .insert(id, (socket.clone(), src, drx, idle));
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
        let (n, src) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
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
                (session(socket.clone(), src, 0), false)
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
    let Some((public_socket, public_src, dgram_rx, idle)) = take_udp_pending(&srv, id) else {
        return;
    };
    let noise = Arc::new(noise);
    // `_guard` keeps the session counted live for the whole bridge.
    let (inbound, _guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    crate::bridge::udp_server_stateless(public_socket, public_src, dgram_rx, rx, tx, idle).await;
}

fn take_udp_pending(srv: &Server, id: u64) -> Option<UdpPending> {
    srv.udp_pending.lock().unwrap().remove(&id)
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
    let handle = match switch.add_port(2, Some(src)) {
        Ok(h) => h,
        Err(e) => {
            crate::elog!("rejecting bridge conv: {e}");
            return;
        }
    };
    let noise = Arc::new(noise);
    // `_guard` keeps the session counted live for the whole bridge.
    let (inbound, _guard) = sess.register_dgram(conv);
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

    // Tcp-transport parties never probe: no `PeerProbe` is sent, and both
    // sides get an immediate `PeerInfo` with an empty (relay-only) list.
    #[tokio::test]
    async fn tcp_transport_parties_settle_relay_only_immediately() {
        let srv = test_server();
        let (_p_tx, mut p_rx) = register_peer_client(&srv, "prov", Some(PROVIDES_EXIT));
        let (c_tx, mut c_rx) = register_peer_client(&srv, "c", Some(0));
        let (pair_id, status) = srv.peer_connect("c", &c_tx, "prov", PROVIDES_EXIT).unwrap();
        assert_eq!(status, PeerStatus::Accepted);
        srv.start_pair_probes(pair_id);

        for rx in [&mut c_rx, &mut p_rx] {
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
