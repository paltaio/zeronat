use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::time::timeout as tokio_timeout;
use tokio::time::{interval, sleep};

use crate::bridge;
use crate::clientcfg::ClientConfig;
use crate::clientctl::{ControlPath, ControlState, Persist};
use crate::clientproto::{
    ClientForwardEntry, ClientServerEntry, LinkCell, LinkStatus, PppPhase, PppStatus, SessionMode,
};
use crate::dgram::{DgramRx, DgramTx};
#[cfg(target_os = "linux")]
use crate::exitroute::ExitRoutes;
use crate::kcp::{
    route, session as kcp_session, ConvGuard, Session, CLASS_KCP, CLASS_SETUP, SETUP_CONV_BIT,
};
#[cfg(target_os = "linux")]
use crate::kcp::{BRIDGE_CONV, BRIDGE_ID};
use crate::noise::{
    client_handshake, client_handshake_stateless, client_handshake_stateless_reply,
};
use crate::peerslot;
use crate::peerslot::PeerControl;
pub use crate::peerslot::{PeerExit, PeerSlotSession, PeerSlotSpec, SessionSink};
use crate::proto::{decode_sockaddr, encode_sockaddr, FwdOptionEntry, Msg, Proto};
use crate::tap::TapConfig;
#[cfg(target_os = "linux")]
use crate::tap::TapDevice;

pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(25);
/// Liveness window for the control channel. The server replies Pong to every
/// Ping, so no inbound frame for a few ping intervals means the link is a black
/// hole (no FIN/RST on a NAT rebind, WAN re-dial, or silent firewall drop).
const CONTROL_TIMEOUT: Duration = Duration::from_secs(90);
const RETRY_DELAY: Duration = Duration::from_secs(3);
/// Cap for the reconnect backoff. A server that stays down (especially in DHT
/// mode, where each cycle runs a full lookup) must not redial every RETRY_DELAY
/// forever; the delay doubles per failed cycle up to this ceiling.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(60);
const UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1500);
/// Pause after a transient recv error on the RX pump so a persistent ready-error
/// (e.g. HostUnreachable/NetworkUnreachable on a connected UDP socket) does not
/// spin the loop at 100% CPU or flood logs.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// Bound for a per-forward connect plus Noise handshake back to the server. The
/// server abandons a half-open forward at its own OPEN_TIMEOUT, so a black-holed
/// TCP handshake (kernel retransmits for ~15 min) or stalled KCP conv must not
/// keep the fd and task alive long after the server has moved on.
const OPEN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// A control session over UDP that lives at least this long is treated as a
/// healthy path; a shorter one counts as a flap (handshake succeeds but the KCP
/// link cannot be sustained over a lossy/MTU-broken UDP route).
const UDP_MIN_HEALTHY: Duration = Duration::from_secs(30);
/// Consecutive flapping/failed UDP attempts before Auto stops probing UDP.
const UDP_QUICK_FAILS: u32 = 2;
/// How long Auto prefers TCP after UDP flaps, before it re-probes UDP again.
const UDP_COOLDOWN: Duration = Duration::from_secs(120);
/// How long after sending `FwdOptions` to wait for the server's ack before
/// warning that proxy-enabled forwards will refuse connections. Sized well past
/// a control round-trip; an old server never acks (it ignores the frame), so
/// this fires exactly once per control session against such a server.
const FWD_OPTIONS_ACK_TIMEOUT: Duration = Duration::from_secs(15);

/// UDP-health memory carried across reconnects in Auto mode. Owned by the
/// reconnect loop (not the Arc<Client>, not global) so each running client keeps
/// its own monotonic view of whether the UDP path is currently usable.
#[derive(Default)]
struct UdpHealth {
    fails: u32,
    cooldown_until: Option<Instant>,
}

/// Auto-mode transport decision: probe UDP unless a flap cooldown is still active.
/// Forced Udp/Tcp callers never consult this (their path is fixed upstream).
fn choose_udp(state: &UdpHealth, now: Instant) -> bool {
    match state.cooldown_until {
        Some(until) => now >= until,
        None => true,
    }
}

/// Fold one UDP attempt's outcome into the cooldown memory. A healthy session
/// clears the cooldown; UDP_QUICK_FAILS flaps in a row arms it for UDP_COOLDOWN.
fn record(state: &mut UdpHealth, healthy: bool, now: Instant) {
    if healthy {
        state.fails = 0;
        state.cooldown_until = None;
    } else {
        state.fails += 1;
        if state.fails >= UDP_QUICK_FAILS {
            state.cooldown_until = Some(now + UDP_COOLDOWN);
            state.fails = 0;
        }
    }
}

/// Exponential backoff for one slot's cycle. Owned by the slot (like
/// `UdpHealth` is owned by the server slot) so each keeps its own cadence.
/// Starts at RETRY_DELAY, doubles after every failed cycle, and is capped at
/// RETRY_DELAY_MAX; a cycle that established resets it.
pub(crate) struct Backoff(Duration);

impl Default for Backoff {
    fn default() -> Self {
        Backoff(RETRY_DELAY)
    }
}

impl Backoff {
    pub(crate) fn delay(&self) -> Duration {
        self.0
    }

    pub(crate) fn fail(&mut self) {
        self.0 = (self.0 * 2).min(RETRY_DELAY_MAX);
    }

    pub(crate) fn reset(&mut self) {
        self.0 = RETRY_DELAY;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Auto,
    Udp,
    Tcp,
}

/// Resolved `--pppoe` configuration. Owns the credential bytes for the whole
/// reconnect-loop lifetime; the per-attempt `PppoeDatapath` borrows them.
#[derive(Clone)]
pub struct PppoeRunConfig {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    /// PPPoE Service-Name selector (empty = any).
    pub service_name: Vec<u8>,
    /// Preferred AC name. Stored and logged; PADO filtering is not yet active.
    pub ac_name: Option<Vec<u8>>,
    pub tun_name: String,
    /// Effective MTU/MRU (`min(--pppoe-mtu, tunnel MTU - 8)`, floored).
    pub effective_mtu: u16,
    /// Replace the host default route with zppp0 and pin the tunnel to the WAN.
    pub default_route: bool,
    /// MSS to clamp forwarded SYNs to, or `None` to leave forwarded packets alone.
    pub clamp_mss: Option<u16>,
    /// Request the IPCP DNS servers and apply them to `/etc/resolv.conf`.
    pub request_dns: bool,
}

/// What an Auto-mode connection attempt did with UDP, so the reconnect loop can
/// update its cooldown memory. `Skipped` means the attempt never touched UDP
/// (forced TCP, or cooldown active), so it leaves the memory unchanged.
#[derive(Clone, Copy, PartialEq)]
enum UdpOutcome {
    Skipped,
    Healthy,
    Unhealthy,
}

/// One parsed `--tcp`/`--udp` forward: the public port, the local target it
/// dials, and the per-forward options. `proxy` (TCP only) prefixes every local
/// connection with a PROXY protocol v2 header carrying the real public peer;
/// `idle` overrides the proto-default relay idle window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub port: u16,
    pub target: String,
    pub proxy: bool,
    pub idle: Option<Duration>,
    /// Whether the forward is served; a disabled entry keeps its
    /// configuration but stays out of the per-attempt maps.
    pub enabled: bool,
}

/// A forward as the control loop consults it on each open, keyed by port.
#[derive(Clone)]
struct ForwardTarget {
    target: String,
    proxy: bool,
    idle: Option<Duration>,
    enabled: bool,
}

/// The live forward set, shared between the reconnect loop (each connection
/// attempt snapshots it) and the admin dispatcher (option edits and snapshot
/// views). Lock-only: no holder ever awaits with the lock taken.
#[derive(Clone)]
pub struct SharedForwards {
    inner: Arc<std::sync::Mutex<ForwardMaps>>,
}

struct ForwardMaps {
    tcp: HashMap<u16, ForwardTarget>,
    udp: HashMap<u16, ForwardTarget>,
}

impl SharedForwards {
    pub(crate) fn new(tcp: Vec<Forward>, udp: Vec<Forward>) -> Self {
        let by_port = |fwds: Vec<Forward>| -> HashMap<u16, ForwardTarget> {
            fwds.into_iter()
                .map(|f| {
                    (
                        f.port,
                        ForwardTarget {
                            target: f.target,
                            proxy: f.proxy,
                            idle: f.idle,
                            enabled: f.enabled,
                        },
                    )
                })
                .collect()
        };
        SharedForwards {
            inner: Arc::new(std::sync::Mutex::new(ForwardMaps {
                tcp: by_port(tcp),
                udp: by_port(udp),
            })),
        }
    }

    /// Whether any forward is declared, enabled or not: disabled entries
    /// still shape the session mode, exactly as they shape a boot.
    pub(crate) fn any_declared(&self) -> bool {
        let m = self.inner.lock().unwrap();
        !m.tcp.is_empty() || !m.udp.is_empty()
    }

    /// Append the `(proto, port)` forward. The duplicate check and the insert
    /// are one locked step; `false` (and no change) when the key is taken.
    pub(crate) fn add(&self, proto: Proto, fwd: Forward) -> bool {
        let mut m = self.inner.lock().unwrap();
        let map = match proto {
            Proto::Tcp => &mut m.tcp,
            Proto::Udp => &mut m.udp,
        };
        match map.entry(fwd.port) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(ForwardTarget {
                    target: fwd.target,
                    proxy: fwd.proxy,
                    idle: fwd.idle,
                    enabled: fwd.enabled,
                });
                true
            }
        }
    }

    /// Remove the `(proto, port)` forward; `false` when no such forward
    /// exists.
    pub(crate) fn remove(&self, proto: Proto, port: u16) -> bool {
        let mut m = self.inner.lock().unwrap();
        let map = match proto {
            Proto::Tcp => &mut m.tcp,
            Proto::Udp => &mut m.udp,
        };
        map.remove(&port).is_some()
    }

    /// Per-attempt copy for a `Client`, disabled forwards left out; an edit
    /// after this lands on the next connection attempt.
    fn maps(&self) -> (HashMap<u16, ForwardTarget>, HashMap<u16, ForwardTarget>) {
        let serving = |map: &HashMap<u16, ForwardTarget>| -> HashMap<u16, ForwardTarget> {
            map.iter()
                .filter(|(_, f)| f.enabled)
                .map(|(&port, f)| (port, f.clone()))
                .collect()
        };
        let m = self.inner.lock().unwrap();
        (serving(&m.tcp), serving(&m.udp))
    }

    /// Replace the full option state of the `(proto, port)` forward. `false`
    /// (and no change at all) when no such forward exists.
    pub(crate) fn set_options(
        &self,
        proto: Proto,
        port: u16,
        enabled: bool,
        proxy: bool,
        idle: Option<Duration>,
    ) -> bool {
        let mut m = self.inner.lock().unwrap();
        let map = match proto {
            Proto::Tcp => &mut m.tcp,
            Proto::Udp => &mut m.udp,
        };
        match map.get_mut(&port) {
            Some(f) => {
                f.enabled = enabled;
                f.proxy = proxy;
                f.idle = idle;
                true
            }
            None => false,
        }
    }

    /// Snapshot view of every forward: tcp before udp, sorted by port.
    pub(crate) fn entries(&self) -> Vec<ClientForwardEntry> {
        let m = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for (proto, map) in [(Proto::Tcp, &m.tcp), (Proto::Udp, &m.udp)] {
            for (&port, f) in map {
                out.push(ClientForwardEntry {
                    proto,
                    port,
                    target: f.target.clone(),
                    proxy: f.proxy,
                    idle_secs: f.idle.map(|d| d.as_secs() as u32).unwrap_or(0),
                    enabled: f.enabled,
                });
            }
        }
        out.sort_by_key(|e| (e.proto == Proto::Udp, e.port));
        out
    }
}

struct Client {
    server: String,
    psk: [u8; 32],
    client_id: String,
    tcp: HashMap<u16, ForwardTarget>,
    udp: HashMap<u16, ForwardTarget>,
    transport: Transport,
    /// The capability bits to announce once this control session is up, or
    /// `None` when no peer slot is configured and nothing is announced.
    peer_announce: Option<u8>,
}

/// Aborts its task when dropped. Ties a spawned task's lifetime to the scope
/// that owns this guard, so the task cannot outlive the connection it serves.
pub(crate) struct AbortOnDrop<T = ()>(pub(crate) tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How the control loop opens data connections back to the server.
enum Link {
    Tcp, // data conns dial new TcpStreams
    // data conns open KCP convs on the shared UDP session; the guard aborts the
    // session's RX pump when this Link drops at control teardown (held for Drop).
    // The Notify fires when that pump sees the peer vanish, so the control loop can
    // tear down at once instead of waiting out CONTROL_TIMEOUT.
    Udp(Arc<Session>, #[allow(dead_code)] AbortOnDrop, Arc<Notify>),
}

/// How the server's control address is found: a fixed `host:port`, or looked up
/// on the DHT by a secret-derived key.
enum Discovery {
    Static(String),
    #[cfg(feature = "dht")]
    Dht(Arc<crate::dht::Identity>),
}

impl Discovery {
    fn new(server: &str, secret: &str) -> Result<Self> {
        if server == "dht" {
            #[cfg(feature = "dht")]
            return Ok(Discovery::Dht(Arc::new(crate::dht::Identity::derive(
                secret,
            ))));
            #[cfg(not(feature = "dht"))]
            {
                let _ = secret;
                return Err("this build has no dht support; pass --server host:port".into());
            }
        }
        Ok(Discovery::Static(server.to_string()))
    }

    /// Resolve to a concrete `host:port`. The DHT path serves the cached address
    /// first so a reconnect stays off the network.
    async fn resolve(&self) -> Result<String> {
        match self {
            Discovery::Static(s) => Ok(s.clone()),
            #[cfg(feature = "dht")]
            Discovery::Dht(id) => {
                if let Some(addr) = crate::dht::read_cache(id) {
                    return Ok(addr.to_string());
                }
                crate::elog!("resolving server address via dht...");
                let addr = crate::dht::resolve(id).await?;
                crate::elog!("dht: resolved server to {addr}");
                crate::dht::write_cache(id, addr);
                Ok(addr.to_string())
            }
        }
    }

    /// Drop a cached address after it failed to connect, so the next resolve
    /// consults the DHT (the server's IP may have changed).
    fn invalidate(&self) {
        #[cfg(feature = "dht")]
        if let Discovery::Dht(id) = self {
            crate::dht::clear_cache(id);
        }
    }
}

/// One dialable server profile: address (`"dht"` or `host:port`), the secret
/// that authenticates it, and the transport policy.
#[derive(Clone)]
pub struct ServerTarget {
    pub name: String,
    pub addr: String,
    pub secret: String,
    pub transport: Transport,
}

/// The selectable server profiles, shared between the admin dispatcher (which
/// resolves, appends, and removes them) and snapshot views. Lock-only, like
/// [`SharedForwards`]: no holder ever awaits with the lock taken.
#[derive(Clone)]
pub struct SharedServers {
    inner: Arc<std::sync::Mutex<Vec<ServerTarget>>>,
}

impl SharedServers {
    pub(crate) fn new(servers: Vec<ServerTarget>) -> Self {
        SharedServers {
            inner: Arc::new(std::sync::Mutex::new(servers)),
        }
    }

    /// The named profile, cloned out so the caller holds no lock.
    pub(crate) fn get(&self, name: &str) -> Option<ServerTarget> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.name == name)
            .cloned()
    }

    /// Append a profile; `false` (and no change) when the name is taken.
    pub(crate) fn add(&self, target: ServerTarget) -> bool {
        let mut list = self.inner.lock().unwrap();
        if list.iter().any(|s| s.name == target.name) {
            return false;
        }
        list.push(target);
        true
    }

    /// Remove the named profile; `false` when no such profile exists.
    pub(crate) fn remove(&self, name: &str) -> bool {
        let mut list = self.inner.lock().unwrap();
        let before = list.len();
        list.retain(|s| s.name != name);
        list.len() != before
    }

    /// Whether a profile with exactly these fields is configured.
    fn contains(&self, name: &str, addr: &str, secret: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.name == name && s.addr == addr && s.secret == secret)
    }

    /// Snapshot view: config fields only, the per-server secret stays behind.
    pub(crate) fn entries(&self) -> Vec<ClientServerEntry> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .map(|s| ClientServerEntry {
                name: s.name.clone(),
                addr: s.addr.clone(),
                transport: s.transport,
            })
            .collect()
    }
}

/// Per-server dial state: the derived PSK and the discovery, whose DHT
/// identity carries the resolver cache.
struct DialState {
    psk: [u8; 32],
    discovery: Discovery,
}

/// Dial state kept across switches, keyed by the whole `(name, addr, secret)`
/// triple: returning to an unchanged profile reuses its PSK and discovery,
/// while a remove-then-add under the same name with a new secret or address
/// derives fresh state instead of hitting a stale memo. `prune` drops entries
/// for removed profiles, so the memo stays bounded by the configured set.
#[derive(Default)]
struct DialMemo(HashMap<(String, String, String), DialState>);

impl DialMemo {
    /// Drop entries whose profile is gone, keeping the active target's, so
    /// remove/add cycles cannot grow the memo past the configured set.
    fn prune(&mut self, servers: &SharedServers, active: &ServerTarget) {
        self.0.retain(|(name, addr, secret), _| {
            (*name == active.name && *addr == active.addr && *secret == active.secret)
                || servers.contains(name, addr, secret)
        });
    }

    fn state(&mut self, target: &ServerTarget) -> Result<&mut DialState> {
        let key = (
            target.name.clone(),
            target.addr.clone(),
            target.secret.clone(),
        );
        match self.0.entry(key) {
            std::collections::hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(e) => Ok(e.insert(DialState {
                psk: crate::noise::derive_psk(&target.secret),
                discovery: Discovery::new(&target.addr, &target.secret)?,
            })),
        }
    }
}

/// L3 tunnel shape as the client carries it between bringups. The address is
/// resolved against the active server's secret each time the device opens, so
/// a server switch moves the device onto the new server's subnet unless the
/// operator pinned an explicit address.
#[derive(Clone)]
pub struct ClientTun {
    pub name: String,
    pub mtu: usize,
    /// Explicitly configured `addr/prefix`, or `None` to derive the client
    /// `.2` on the active secret's `/24` at bringup.
    pub address: Option<(Ipv4Addr, u8)>,
    /// Route the host's IPv4 traffic through the tunnel: pin the server over
    /// the uplink and point `0.0.0.0/1`/`128.0.0.0/1` at the device while
    /// the tun profile is active.
    pub exit: bool,
    /// Exit with no fallback: every original default route is deleted and
    /// IPv6 blackholed while the routes are up, both restored on clean
    /// teardown.
    pub exit_strict: bool,
}

impl ClientTun {
    /// The concrete device config for a bringup against `secret`'s server.
    #[cfg(any(test, target_os = "linux"))]
    fn resolve(&self, secret: &str) -> crate::tap::TunConfig {
        let (addr, prefix_len) = self.address.unwrap_or_else(|| {
            let base = crate::identity::derive_tun_subnet(secret);
            (Ipv4Addr::new(base[0], base[1], base[2], 2), 24)
        });
        crate::tap::TunConfig {
            name: self.name.clone(),
            mtu: self.mtu,
            addr,
            prefix_len,
        }
    }
}

/// Which OS device a `RunMode::Device` body opens.
#[derive(Clone)]
pub enum DeviceConfig {
    Tap(TapConfig),
    Tun(ClientTun),
}

/// The session body the reconnect loop runs for the active profile: exactly
/// one at any instant, or none in `Idle`, where only the admin socket is up.
#[derive(Clone)]
pub enum RunMode {
    Idle,
    Forwards,
    Device(DeviceConfig),
    /// One named pppoe session; carries its resolved config so bringup needs
    /// no lookup.
    Pppoe {
        name: String,
        config: Arc<PppoeRunConfig>,
    },
    /// Parked by `Disconnect`: nothing is dialed until `Connect`. Runtime-only;
    /// boot never derives it and it is never persisted.
    Offline,
}

/// The session body the declared forward set selects: `Forwards` when any
/// forward is declared (enabled or not), else `fallback`. Boot, `Connect`,
/// and `StopSession` all derive through here at use, so the body each
/// installs tracks runtime forward edits.
pub(crate) fn derive_mode(forwards: &SharedForwards, fallback: &RunMode) -> RunMode {
    if forwards.any_declared() {
        RunMode::Forwards
    } else {
        fallback.clone()
    }
}

/// An exclusive resource a slot holds while it runs: one OS network device by
/// name, or the host's default routing. Two slots naming one interface is the
/// conflict whichever slots they are, and at most one slot programs the host's
/// defaults.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Claim {
    Device(String),
    DefaultRoute,
}

impl Claim {
    /// How a refusal names the contended resource.
    fn describe(&self) -> String {
        match self {
            Claim::Device(name) => format!("device `{name}`"),
            Claim::DefaultRoute => "the default route".to_string(),
        }
    }
}

/// What the peer slots hold and which slot holds each. One server-slot body
/// runs at a time, so an incoming body is admitted against these alone.
#[derive(Default, Debug)]
struct SlotClaims(Vec<(Claim, String)>);

impl SlotClaims {
    /// The claims of a configured peer slot set, refusing a set that contends
    /// with itself.
    fn new(peers: Vec<(Claim, String)>) -> std::result::Result<Self, String> {
        for (i, (claim, holder)) in peers.iter().enumerate() {
            if let Some((_, first)) = peers[..i].iter().find(|(c, _)| c == claim) {
                return Err(format!(
                    "{} is claimed by both {first} and {holder}",
                    claim.describe()
                ));
            }
        }
        Ok(SlotClaims(peers))
    }

    /// Admit an incoming session body, refusing a claim a peer slot holds and
    /// leaving the running slots alone.
    fn admit_body(&self, body: Vec<(Claim, String)>) -> std::result::Result<(), String> {
        for (claim, holder) in &body {
            if let Some((_, first)) = self.0.iter().find(|(c, _)| c == claim) {
                return Err(format!(
                    "{} is claimed by {first}, so {holder} cannot open it",
                    claim.describe()
                ));
            }
        }
        Ok(())
    }
}

/// The claims a configured peer slot set holds, in declaration order.
fn peer_claims(specs: &[PeerSlotSpec]) -> Vec<(Claim, String)> {
    let mut out = Vec::new();
    for spec in specs {
        let holder = spec.label();
        if let Some(dev) = spec.device() {
            out.push((Claim::Device(dev.to_string()), holder.clone()));
        }
        if spec.default_route() {
            out.push((Claim::DefaultRoute, holder));
        }
    }
    out
}

/// Refuse a slot set whose identities collide. A consumer is identified by the
/// peer and capability its `PeerConnect` carries and a provider by its
/// capability alone, and those are the keys inbound frames fan out by, so a
/// duplicate is unroutable rather than merely redundant.
fn check_slot_identities(specs: &[PeerSlotSpec]) -> std::result::Result<(), String> {
    for (i, spec) in specs.iter().enumerate() {
        let clash =
            specs[..i]
                .iter()
                .any(|other| match (spec.consumer_key(), other.consumer_key()) {
                    (Some(a), Some(b)) => a == b,
                    (None, None) => spec.provides() == other.provides(),
                    _ => false,
                });
        if clash {
            return Err(format!("{} is configured twice", spec.label()));
        }
    }
    Ok(())
}

impl RunMode {
    /// What the server slot claims while this body runs. Forwards claim
    /// nothing; a device body claims its interface, and the bodies that
    /// program the host's defaults claim the route as well.
    fn claims(&self) -> Vec<(Claim, String)> {
        let holder = "the server session body".to_string();
        match self {
            RunMode::Idle | RunMode::Forwards | RunMode::Offline => Vec::new(),
            RunMode::Device(DeviceConfig::Tun(cfg)) => {
                let mut out = vec![(Claim::Device(cfg.name.clone()), holder.clone())];
                if cfg.exit {
                    out.push((Claim::DefaultRoute, holder));
                }
                out
            }
            RunMode::Device(DeviceConfig::Tap(cfg)) => {
                let mut out = vec![(Claim::Device(cfg.name.clone()), holder.clone())];
                if let Some(nic) = &cfg.bridge {
                    out.push((Claim::Device(nic.clone()), holder));
                }
                out
            }
            RunMode::Pppoe { config, .. } => {
                let mut out = vec![(Claim::Device(config.tun_name.clone()), holder.clone())];
                if config.default_route {
                    out.push((Claim::DefaultRoute, holder));
                }
                out
            }
        }
    }

    pub fn session_mode(&self) -> SessionMode {
        match self {
            RunMode::Idle => SessionMode::Idle,
            RunMode::Forwards => SessionMode::Forwards,
            RunMode::Device(_) => SessionMode::Device,
            RunMode::Pppoe { .. } => SessionMode::Pppoe,
            RunMode::Offline => SessionMode::Offline,
        }
    }
}

/// The server and session body the reconnect loop should be running, shared
/// between the loop and whoever drives a switch. Also holds the cancel scoped
/// to the profile currently up: every mutator fires that cancel; the loop
/// installs a fresh one each time it brings a profile up.
#[derive(Clone)]
pub struct ActiveTarget {
    state: Arc<std::sync::Mutex<ActiveState>>,
}

struct ActiveState {
    target: ServerTarget,
    mode: RunMode,
    // Fired with notify_one, which hands out exactly one permit. The
    // run_switchable loop must stay the sole waiter on this Notify: a second
    // waiter could consume the permit, the loop would never see the cancel,
    // and it would redial the old target, silently dropping the switch.
    cancel: Arc<Notify>,
    // Read under the same lock that swaps the body, so a mutation installing a
    // device body is answered as a refusal before anything is torn down.
    claims: SlotClaims,
}

impl ActiveTarget {
    pub fn new(target: ServerTarget) -> Self {
        ActiveTarget {
            state: Arc::new(std::sync::Mutex::new(ActiveState {
                target,
                mode: RunMode::Idle,
                cancel: Arc::new(Notify::new()),
                claims: SlotClaims::default(),
            })),
        }
    }

    /// Install a session body with no peer slots to admit it against.
    #[cfg(test)]
    fn init_mode(&self, mode: RunMode) {
        self.state.lock().unwrap().mode = mode;
    }

    /// Install the configured peer slots' claims and the boot-derived session
    /// body. Every slot's interface is named in config, so the whole set is
    /// decidable before anything opens and a conflicting file is refused here.
    fn init_slots(
        &self,
        peers: Vec<(Claim, String)>,
        mode: RunMode,
    ) -> std::result::Result<(), String> {
        let mut s = self.state.lock().unwrap();
        s.claims = SlotClaims::new(peers)?;
        s.claims.admit_body(mode.claims())?;
        s.mode = mode;
        Ok(())
    }

    /// Retarget the client: replace the shared target and fire the current
    /// profile's cancel, preserving the session body. The loop aborts the
    /// in-flight session task, awaits its teardown, and brings the same body up
    /// against the new target; the brief link drop is inherent to the
    /// teardown-then-bringup.
    pub fn switch(&self, target: ServerTarget) {
        let mut s = self.state.lock().unwrap();
        s.target = target;
        s.cancel.notify_one();
    }

    /// Replace the session body and fire the cancel: the loop tears the
    /// running body down and brings the new one up against the same target. A
    /// body whose device or default route a peer slot holds is refused and
    /// nothing is torn down.
    pub fn set_mode(&self, mode: RunMode) -> std::result::Result<(), String> {
        let mut s = self.state.lock().unwrap();
        s.claims.admit_body(mode.claims())?;
        s.mode = mode;
        s.cancel.notify_one();
        Ok(())
    }

    /// Park the client offline: replace the session body with the offline
    /// park and fire the cancel so the loop tears the running body down.
    /// `false` (and no cancel) when already offline.
    pub fn disconnect(&self) -> bool {
        let mut s = self.state.lock().unwrap();
        if matches!(s.mode, RunMode::Offline) {
            return false;
        }
        s.mode = RunMode::Offline;
        s.cancel.notify_one();
        true
    }

    /// Leave the park and install `boot`, retargeting first when `target` is
    /// set. `Ok(false)` (and no change) while a session body is up: connecting
    /// is the park's exit, never a retarget of a live session.
    pub fn connect(
        &self,
        target: Option<ServerTarget>,
        boot: RunMode,
    ) -> std::result::Result<bool, String> {
        let mut s = self.state.lock().unwrap();
        if !matches!(s.mode, RunMode::Idle | RunMode::Offline) {
            return Ok(false);
        }
        s.claims.admit_body(boot.claims())?;
        if let Some(t) = target {
            s.target = t;
        }
        s.mode = boot;
        s.cancel.notify_one();
        Ok(true)
    }

    /// Stop the named pppoe session, falling back to `base`. Fires the cancel
    /// only when that session is the active body; returns whether it did.
    pub fn stop_pppoe(&self, name: &str, base: RunMode) -> bool {
        let mut s = self.state.lock().unwrap();
        match &s.mode {
            RunMode::Pppoe { name: active, .. } if active == name => {
                s.mode = base;
                s.cancel.notify_one();
                true
            }
            _ => false,
        }
    }

    /// Apply an added forward to the running body. An idle client promotes to
    /// the forwards body and fires the cancel: its boot derivation now says
    /// `Forwards`, and a client that accepted the add must serve it rather
    /// than sit silent until a reconnect. A live forwards body is kicked so
    /// the redial re-announces the new entry. Any other body, the offline
    /// park included, is left untouched; the forward lands at the next
    /// forwards bringup.
    pub fn serve_forwards(&self) {
        let mut s = self.state.lock().unwrap();
        match s.mode {
            RunMode::Idle => {
                s.mode = RunMode::Forwards;
                s.cancel.notify_one();
            }
            RunMode::Forwards => s.cancel.notify_one(),
            _ => {}
        }
    }

    /// Redial the forwards session so the reconnect re-announces per-forward
    /// options. A no-op in any other mode: an option edit must not drop an
    /// unrelated pppoe or device body, and the next forwards bringup reads the
    /// updated set anyway.
    pub fn kick_if_forwards(&self) {
        let s = self.state.lock().unwrap();
        if matches!(s.mode, RunMode::Forwards) {
            s.cancel.notify_one();
        }
    }

    /// Snapshot the target and body to bring up and install a fresh cancel
    /// scoped to them. A mutation racing this call lands its permit on the
    /// fresh cancel, so a switch is never lost between profiles.
    fn begin(&self) -> (ServerTarget, RunMode, Arc<Notify>) {
        let mut s = self.state.lock().unwrap();
        s.cancel = Arc::new(Notify::new());
        (s.target.clone(), s.mode.clone(), s.cancel.clone())
    }

    /// Name of the profile the reconnect loop is running (or about to bring
    /// up), its session mode, and the live pppoe session's name (empty in any
    /// other mode). Read-only: takes the lock briefly and never touches the
    /// cancel.
    pub fn admin_view(&self) -> (String, SessionMode, String) {
        let s = self.state.lock().unwrap();
        let session = match &s.mode {
            RunMode::Pppoe { name, .. } => name.clone(),
            _ => String::new(),
        };
        (s.target.name.clone(), s.mode.session_mode(), session)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    server: String,
    secret: String,
    tcp: Vec<Forward>,
    udp: Vec<Forward>,
    transport: Transport,
    tap: Option<TapConfig>,
    tun: Option<ClientTun>,
    pppoe: Option<PppoeRunConfig>,
    id_prefix: Option<String>,
    control: Option<ControlPath>,
) -> Result<()> {
    let target = ServerTarget {
        name: server.clone(),
        addr: server,
        secret,
        transport,
    };
    // A CLI-declared pppoe session gets a fixed handle so admin can name it.
    let autostart = pppoe.as_ref().map(|_| "cli".to_string());
    let settings = ClientSettings {
        servers: vec![target.clone()],
        tcp,
        udp,
        tap,
        tun,
        pppoe: pppoe
            .map(|config| PppoeSession {
                name: "cli".into(),
                config,
            })
            .into_iter()
            .collect(),
        autostart,
        id_prefix,
        control,
        config: None,
        peers: Vec::new(),
        peer_sessions: None,
    };
    run_switchable(ActiveTarget::new(target), settings).await
}

/// One named pppoe session the admin can spawn at runtime.
pub struct PppoeSession {
    pub name: String,
    pub config: PppoeRunConfig,
}

/// Everything `run_switchable` runs from besides the active target: the
/// selectable server profiles, the session bodies the client can run, and the
/// persistence target for admin mutations.
pub struct ClientSettings {
    /// Profiles `SelectServer` may switch to. The boot profile is the one the
    /// caller put into the `ActiveTarget`.
    pub servers: Vec<ServerTarget>,
    pub tcp: Vec<Forward>,
    pub udp: Vec<Forward>,
    pub tap: Option<TapConfig>,
    pub tun: Option<ClientTun>,
    /// Spawnable pppoe sessions, keyed by name.
    pub pppoe: Vec<PppoeSession>,
    /// Name of the pppoe session to boot when no forwards are declared.
    pub autostart: Option<String>,
    pub id_prefix: Option<String>,
    pub control: Option<ControlPath>,
    /// Admin-mutation persistence: the config file and its parsed contents.
    /// `None` on a runtime-only client, whose mutations stay in memory.
    pub config: Option<(PathBuf, ClientConfig)>,
    /// The peer slots this client runs beside the server slot.
    pub peers: Vec<PeerSlotSpec>,
    /// Where a live peer slot hands its frames, or `None` while nothing rides
    /// a peer session.
    pub peer_sessions: SessionSink,
}

/// The concrete session body brought up for the active profile, holding what
/// the per-attempt task needs: the opened device for `Device`, the credentials
/// for `Pppoe`.
#[cfg(target_os = "linux")]
#[derive(Clone)]
enum Body {
    Forwards,
    Device(Arc<TapDevice>),
    Pppoe(Arc<PppoeRunConfig>),
}

/// Like `run`, but dialing whatever `active` currently points at and running
/// whatever session body it names. A switch or mode change tears the in-flight
/// session down and brings the next body up against the (possibly new) target,
/// with per-server backoff and UDP-health state starting fresh. When
/// `settings.control` is set and its path binds (see [`ControlPath::bind`] for
/// the failure policy), an admin socket serves snapshots and mutations for as
/// long as this future runs.
pub async fn run_switchable(active: ActiveTarget, settings: ClientSettings) -> Result<()> {
    let ClientSettings {
        servers,
        tcp,
        udp,
        tap,
        tun,
        pppoe,
        autostart,
        id_prefix,
        control,
        config,
        peers,
        peer_sessions,
    } = settings;
    let client_id = crate::identity::derive_client_id(id_prefix.as_deref());
    #[cfg(not(target_os = "linux"))]
    if tap.is_some() || tun.is_some() {
        return Err("L2/L3 tunnel modes (--tap/--tun) are only supported on Linux".into());
    }
    #[cfg(not(target_os = "linux"))]
    if !pppoe.is_empty() {
        return Err("pppoe is only supported on Linux".into());
    }
    #[cfg(not(target_os = "linux"))]
    if let Some(spec) = peers.iter().find(|s| s.device().is_some()) {
        return Err(format!(
            "{} opens a network device, which is only supported on Linux",
            spec.label()
        )
        .into());
    }

    let forwards = SharedForwards::new(tcp, udp);
    // Held for the loop's lifetime: a pppoe attempt's datapath borrows the
    // credential bytes across the await, so every session's config must
    // outlive every attempt.
    let pppoe: Vec<(String, Arc<PppoeRunConfig>)> = pppoe
        .into_iter()
        .map(|p| (p.name, Arc::new(p.config)))
        .collect();
    let device = match (tun, tap) {
        (Some(cfg), _) => Some(DeviceConfig::Tun(cfg)),
        (None, Some(cfg)) => Some(DeviceConfig::Tap(cfg)),
        (None, None) => None,
    };

    // The boot chain minus its forwards arm, fixed for the loop's lifetime:
    // the autostart pppoe, else the device, else idle with only the admin
    // socket up. The boot body itself is derived from this plus the declared
    // forward set, through the same helper `Connect` and `StopSession` use.
    let fallback_mode = if let Some(name) = autostart {
        let config = pppoe
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, c)| c.clone())
            .ok_or_else(|| -> crate::Error {
                format!("autostart pppoe `{name}` is not a configured session").into()
            })?;
        RunMode::Pppoe { name, config }
    } else if let Some(device) = device {
        RunMode::Device(device)
    } else {
        RunMode::Idle
    };
    check_slot_identities(&peers)?;
    active.init_slots(peer_claims(&peers), derive_mode(&forwards, &fallback_mode))?;
    // The union of the provider bits, or none at all when this client runs no
    // peer slot and announces nothing.
    let announce =
        (!peers.is_empty()).then(|| peers.iter().fold(0u8, |bits, s| bits | s.provides()));
    let peer_control = PeerControl::default();

    let ppp = PppStatus::default();
    // Written by this loop (park, dial, backoff) and by the session bodies
    // (connected); snapshots report it verbatim.
    let link = LinkCell::default();
    let servers = SharedServers::new(servers);

    // The admin socket lives exactly as long as this future: the guard aborts
    // the accept loop when the future is dropped, and dropping the listener
    // inside it removes the socket file.
    let listener = match control {
        Some(ctl) => ctl.bind()?,
        None => None,
    };
    let _control = match listener {
        Some(listener) => {
            crate::elog!("admin socket at {}", listener.path().display());
            let state = ControlState {
                active: active.clone(),
                forwards: forwards.clone(),
                ppp: ppp.clone(),
                link: link.clone(),
                servers: servers.clone(),
                pppoe,
                fallback_mode,
                persist: config.map(|(path, cfg)| Persist::new(path, cfg)),
            };
            Some(AbortOnDrop(tokio::spawn(listener.serve(state))))
        }
        None => None,
    };

    let mut dial = DialMemo::default();

    // One iteration per active profile/body; only a mutation moves to the
    // next one.
    loop {
        let (target, mode, cancel) = active.begin();
        if !matches!(mode, RunMode::Pppoe { .. }) {
            // Only a live pppoe body reports a phase.
            ppp.set(PppPhase::None);
        }
        // Idle and offline profiles run no session body; the admin socket
        // stays up and a mutation fires the cancel to bring the next body up.
        // An idle client with peer slots still dials: the body is what has
        // nothing to run, while the control session under it is what every
        // pairing goes through. The offline park keeps its whole-client
        // meaning, punched pairs included.
        let park = match mode {
            RunMode::Offline => true,
            RunMode::Idle => peers.is_empty(),
            _ => false,
        };
        if park {
            link.set(LinkStatus::Offline);
            cancel.notified().await;
            continue;
        }
        dial.prune(&servers, &target);
        let state = dial.state(&target)?;
        // TAP and TUN share the same device I/O and tunnel datapath; only the
        // open (L2 bridge vs L3 address) differs. Either becomes the single
        // bridge device. Opened per profile: the binding is iteration-local
        // and device release is synchronous in Drop, so the previous profile's
        // device is closed before this open runs.
        #[cfg(target_os = "linux")]
        let body = match &mode {
            RunMode::Device(DeviceConfig::Tun(cfg)) => {
                Body::Device(Arc::new(TapDevice::open_tun(&cfg.resolve(&target.secret))?))
            }
            RunMode::Device(DeviceConfig::Tap(cfg)) => {
                Body::Device(Arc::new(TapDevice::open(cfg)?))
            }
            RunMode::Pppoe { config, .. } => Body::Pppoe(config.clone()),
            RunMode::Forwards | RunMode::Idle | RunMode::Offline => Body::Forwards,
        };
        // Exit routes for a tun body that asked for them. The guard is filled
        // on the first successful dial preparation and held across redials, so
        // its lifetime matches the device: both drop when a switch or teardown
        // ends this iteration, routes first.
        #[cfg(target_os = "linux")]
        let exit_tun: Option<(String, bool)> = match &mode {
            RunMode::Device(DeviceConfig::Tun(cfg)) if cfg.exit => {
                Some((cfg.name.clone(), cfg.exit_strict))
            }
            _ => None,
        };
        #[cfg(target_os = "linux")]
        let mut exit_routes: Option<ExitRoutes> = None;

        // The psk that pairs a slot, authenticates its probe, and keys its
        // inner handshake is the active profile's, so the slots live exactly
        // as long as this profile does and the switch below awaits them.
        // Pairing rides the control session the forwards body opens; a device
        // or pppoe body opens none, so the slots wait for a body that does.
        if !peers.is_empty() && !matches!(mode, RunMode::Forwards | RunMode::Idle) {
            crate::elog!(
                "the active tap/tun/pppoe session opens no control channel, so no peer session \
                 can pair; peer slots pair while this client runs forwards or sits idle"
            );
        }
        let peer_slots = peerslot::spawn(
            &peers,
            &client_id,
            &target.secret,
            &peer_control,
            &peer_sessions,
        );

        let mut udp_health = UdpHealth::default();
        let mut backoff = Backoff::default();
        // Last address we successfully resolved to. A transient DHT gap (the server
        // republishes on an interval) must not knock a working client offline, so an
        // empty or failed lookup falls back to this until the DHT yields a new value.
        let mut last_addr: Option<String> = None;

        loop {
            link.set(LinkStatus::Dialing);
            let resolved = tokio::select! {
                _ = cancel.notified() => break,
                r = state.discovery.resolve() => r,
            };
            let addr = match resolved {
                Ok(a) => {
                    last_addr = Some(a.clone());
                    a
                }
                Err(e) => match &last_addr {
                    Some(a) => {
                        crate::elog!("server discovery failed: {e}; keeping last known server {a}");
                        a.clone()
                    }
                    None => {
                        crate::elog!("server discovery failed: {e}");
                        link.set(LinkStatus::Backoff);
                        tokio::select! {
                            _ = cancel.notified() => break,
                            _ = sleep(backoff.delay()) => {}
                        }
                        backoff.fail();
                        continue;
                    }
                },
            };
            // A failed exit-route bringup or pin assert keeps the dial from
            // running (traffic must not fall onto a half-programmed route
            // set) and backs off like a failed connect.
            #[cfg(target_os = "linux")]
            let addr = match &exit_tun {
                Some((tun_name, strict)) => {
                    match ensure_exit_routes(&mut exit_routes, &addr, tun_name, *strict).await {
                        Ok(target) => target,
                        Err(e) => {
                            crate::elog!("exit routes for {addr}: {e}");
                            link.set(LinkStatus::Backoff);
                            tokio::select! {
                                _ = cancel.notified() => break,
                                _ = sleep(backoff.delay()) => {}
                            }
                            backoff.fail();
                            continue;
                        }
                    }
                }
                None => addr,
            };
            // The forward maps are re-read per attempt, so an option edit made
            // while another body ran is live on the next forwards bringup.
            let (tcp, udp) = forwards.maps();
            let client = Arc::new(Client {
                server: addr,
                psk: state.psk,
                client_id: client_id.clone(),
                tcp,
                udp,
                transport: target.transport,
                peer_announce: announce,
            });
            // Auto only: skip the UDP probe while a flap cooldown is active. Forced
            // Udp/Tcp ignore `try_udp` and keep their fixed path.
            let try_udp =
                target.transport != Transport::Auto || choose_udp(&udp_health, Instant::now());
            // The session body runs in its own task so a switch can abort it
            // mid-flight. The guard covers the other direction: a caller
            // dropping this future takes the session down with it instead of
            // detaching it (a detached pppoe session would keep the hijacked
            // default route and rewritten resolv.conf applied).
            #[cfg(target_os = "linux")]
            let mut session_task = {
                let body = body.clone();
                let ppp = ppp.clone();
                let link = link.clone();
                let peer_control = peer_control.clone();
                AbortOnDrop(tokio::spawn(async move {
                    match body {
                        Body::Device(tap) => bridge_session(client, tap, try_udp, link).await,
                        Body::Pppoe(pp) => pppoe_session(client, pp, ppp, try_udp, link).await,
                        Body::Forwards => session(client, try_udp, link, peer_control).await,
                    }
                }))
            };
            #[cfg(not(target_os = "linux"))]
            let mut session_task = AbortOnDrop(tokio::spawn(session(
                client,
                try_udp,
                link.clone(),
                peer_control.clone(),
            )));
            let joined = tokio::select! {
                _ = cancel.notified() => None,
                r = &mut session_task.0 => Some(r),
            };
            let (result, outcome, established) = match joined {
                None => {
                    // Teardown half of the switch: abort the session and await its
                    // exit so every handle it holds (the device included) is gone
                    // before the next profile's bringup opens its own.
                    session_task.0.abort();
                    let _ = (&mut session_task.0).await;
                    break;
                }
                Some(Ok(v)) => v,
                // The only aborts are the switch arm above (which takes the
                // None branch) and the guard's drop (which means this future is
                // gone), so a join error here is a panic in the session body;
                // surface it exactly as the inline await it replaced would have.
                Some(Err(e)) => std::panic::resume_unwind(e.into_panic()),
            };
            // The pppoe datapath stops writing its phase once the session task
            // exits; mark the link dead so snapshots during the redial backoff
            // do not keep serving the last live phase.
            if matches!(mode, RunMode::Pppoe { .. }) {
                ppp.set(PppPhase::Dead);
            }
            if target.transport == Transport::Auto && outcome != UdpOutcome::Skipped {
                record(
                    &mut udp_health,
                    outcome == UdpOutcome::Healthy,
                    Instant::now(),
                );
            }
            if let Err(e) = result {
                crate::elog!("connection lost: {e}");
                // Only a failure to establish against the cached address invalidates
                // it; a long-lived session dying from a transient blip keeps the cache
                // so the redial stays off the DHT. If the IP truly moved, the next
                // redial fails to establish and that clears it.
                if !established {
                    state.discovery.invalidate();
                }
            }
            // A cycle that brought the control channel up is a fresh start; one that
            // never established (down server, failed handshake) widens the redial gap.
            if established {
                backoff.reset();
            } else {
                backoff.fail();
            }
            link.set(LinkStatus::Backoff);
            tokio::select! {
                _ = cancel.notified() => break,
                _ = sleep(backoff.delay()) => {}
            }
        }
        // A profile switch is a barrier: the incoming set claims what the
        // outgoing one holds, so every slot's teardown completes before the
        // next iteration admits anything.
        for mut slot in peer_slots {
            slot.0.abort();
            let _ = (&mut slot.0).await;
        }
    }
}

/// Bring up the L2 bridge: UDP first for Auto/Udp, TCP otherwise or as fallback.
/// Mirrors `session`: returns the UDP verdict so the reconnect loop can damp
/// flapping in Auto mode. `bridge_udp` runs the data loop inline, so its return
/// timing is the session lifetime used to judge health.
#[cfg(target_os = "linux")]
async fn bridge_session(
    client: Arc<Client>,
    tap: Arc<TapDevice>,
    try_udp: bool,
    link: LinkCell,
) -> (Result<()>, UdpOutcome, bool) {
    let mode = client.transport;
    if mode == Transport::Tcp || (mode == Transport::Auto && !try_udp) {
        let (result, established) = bridge_tcp(client, tap, &link).await;
        return (result, UdpOutcome::Skipped, established);
    }
    let started = Instant::now();
    match bridge_udp(client.clone(), tap.clone(), &link).await {
        (Ok(()), established) => {
            let healthy = started.elapsed() >= UDP_MIN_HEALTHY;
            let outcome = if healthy {
                UdpOutcome::Healthy
            } else {
                UdpOutcome::Unhealthy
            };
            (Ok(()), outcome, established)
        }
        (Err(e), established) => {
            if mode == Transport::Udp {
                return (Err(e), UdpOutcome::Skipped, established);
            }
            // A short-lived bridge_udp returns Err with the handshake never even
            // reached on some paths; treat any UDP failure here as a flap signal.
            crate::elog!("udp transport unavailable ({e}); falling back to tcp");
            let (result, tcp_established) = bridge_tcp(client, tap, &link).await;
            (
                result,
                UdpOutcome::Unhealthy,
                established || tcp_established,
            )
        }
    }
}

/// Bind a local UDP socket, connect it to the server, start the KCP session, and
/// spawn the inbound RX pump. Shared by the control and bridge UDP paths.
async fn udp_connect(client: &Client) -> Result<(Arc<Session>, AbortOnDrop, Arc<Notify>)> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let server: SocketAddr = client
        .server
        .parse()
        .map_err(|_| -> crate::Error { "server must be host:port for UDP".into() })?;
    socket.connect(server).await?;
    let sess = kcp_session(socket.clone(), server, 1);
    // A connected UDP socket whose peer black-holes never errors on recv, so this
    // pump must be aborted on teardown; the returned guard ties it to the caller's
    // connection scope and fires on both handshake-failure and control-death paths.
    // A peer that vanishes without closing (server restart) does surface an ICMP
    // port-unreachable as ConnectionRefused/ConnectionReset; firing `cancel` then
    // makes the owner tear down in seconds instead of waiting out CONTROL_TIMEOUT.
    let cancel = Arc::new(Notify::new());
    let pump = {
        let sess = sess.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv(&mut buf).await {
                    Ok(n) => {
                        route(&sess, &buf[..n]);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        cancel.notify_one();
                        return;
                    }
                    Err(e) => {
                        crate::elog!("udp recv error: {e}");
                        sleep(RECV_ERROR_BACKOFF).await;
                    }
                }
            }
        })
    };
    Ok((sess, AbortOnDrop(pump), cancel))
}

/// Bound on datagrams queued from non-server sources on a probe socket. The
/// queue carries the punch handshake and, once the punch lands, the direct
/// session's own traffic, so it is sized to the KCP window. When it is full,
/// new datagrams are dropped so a flood cannot grow it.
const PROBE_PEER_QUEUE: usize = 256;

/// Resend cadence for the local-candidate frame. It rides the unreliable
/// dgram channel, where one lost copy would leave this party relay-only for
/// the pair's whole life, so it repeats until `PeerInfo` arrives; the server
/// ignores every copy after the first.
const LOCAL_CANDIDATE_RESEND: Duration = Duration::from_secs(2);

/// A live punch-probe socket and the candidates learned through it. The
/// socket stays wildcard-bound and unconnected, and the rx pump owns every
/// read on it: server datagrams feed the probe session, and datagrams from
/// any other source are queued for [`recv_peer`](Self::recv_peer), so a punch
/// consumer never races the pump. Dropping the value aborts the pump and
/// releases the socket, so it must outlive the punch that uses it.
pub struct ProbeSession {
    /// The socket to punch from.
    pub socket: Arc<UdpSocket>,
    /// This socket's public mapping as the server observed it.
    pub public: SocketAddr,
    /// The local candidate: the route-source address toward the server,
    /// paired with the socket's bound port.
    pub local: SocketAddr,
    peer_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    resend: Option<AbortOnDrop>,
    _sess: Arc<Session>,
    _pump: AbortOnDrop,
}

impl ProbeSession {
    /// The next datagram the probe socket received from a non-server source,
    /// with the address it came from.
    pub async fn recv_peer(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.peer_rx.recv().await
    }

    /// Stop repeating this party's local candidate to the server. The repeats
    /// wait on the pair's `PeerInfo`; a punch stops them itself, so this is
    /// for a caller that abandons the pair without punching.
    pub fn stop_candidate_resend(&mut self) {
        self.resend = None;
    }
}

/// Run one candidate-discovery probe against the server's udp control port:
/// bind a fresh wildcard socket, handshake a setup conv carrying the
/// server-assigned `probe_id`, read this socket's public mapping from the
/// handshake reply, and report the local candidate as the first frame on the
/// authenticated session.
pub async fn probe_candidates(
    server: SocketAddr,
    psk: &[u8; 32],
    probe_id: u64,
) -> Result<ProbeSession> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    // The route-source address toward the server: the wildcard-bound probe
    // socket reports 0.0.0.0 as its own address, so a throwaway connected
    // socket learns the ip the kernel picks for that route.
    let local = {
        let throwaway = UdpSocket::bind("0.0.0.0:0").await?;
        throwaway.connect(server).await?;
        SocketAddr::new(throwaway.local_addr()?.ip(), socket.local_addr()?.port())
    };
    let sess = kcp_session(socket.clone(), server, 1);
    // The probe socket is never connected, so it can receive from the peer as
    // well as the server; the pump routes server datagrams into the session
    // and queues everything else for the punch.
    let (peer_tx, peer_rx) = mpsc::channel(PROBE_PEER_QUEUE);
    let pump = {
        let sess = sess.clone();
        let socket = socket.clone();
        AbortOnDrop(tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, src)) if src == server => {
                        route(&sess, &buf[..n]);
                    }
                    Ok((n, src)) => {
                        peer_tx.try_send((src, buf[..n].to_vec())).ok();
                    }
                    Err(e) => {
                        crate::elog!("probe recv error: {e}");
                        sleep(RECV_ERROR_BACKOFF).await;
                    }
                }
            }
        }))
    };
    let conv = (probe_id as u32) | SETUP_CONV_BIT;
    let stream = sess.open_conv_with(CLASS_SETUP, conv);
    let (noise, reply) = tokio_timeout(
        UDP_HANDSHAKE_TIMEOUT,
        client_handshake_stateless_reply(stream, psk, probe_id),
    )
    .await
    .map_err(|_| -> crate::Error { "probe handshake timed out".into() })??;
    let public = decode_sockaddr(&reply)?;
    let tx = DgramTx::new(sess.send_tx(), conv, Arc::new(noise));
    let body = encode_sockaddr(local);
    tx.send(&body).await?;
    let resend = AbortOnDrop(tokio::spawn(async move {
        loop {
            sleep(LOCAL_CANDIDATE_RESEND).await;
            if tx.send(&body).await.is_err() {
                break;
            }
        }
    }));
    Ok(ProbeSession {
        socket,
        public,
        local,
        peer_rx,
        resend: Some(resend),
        _sess: sess,
        _pump: pump,
    })
}

/// A relay leg on the datagram channel: the framed pipe the server splices to
/// the other party's leg, one inner frame per datagram. The guard holds the
/// session's tag registered for the leg's life.
pub struct RelayDgramLeg {
    pub rx: DgramRx,
    pub tx: DgramTx,
    guard: ConvGuard,
}

impl RelayDgramLeg {
    /// Split into the two frame halves and the tag registration they need held
    /// for the leg's life.
    pub fn split(self) -> (DgramTx, DgramRx, ConvGuard) {
        (self.tx, self.rx, self.guard)
    }
}

/// Open this party's relay leg over the tcp transport: a fresh data connection
/// claiming the leg `id` a `PeerRelayOpen` carried, the same claim a forward
/// data channel makes. The server parks the leg until the other party's
/// arrives, then splices the two; each Noise record carries one inner frame.
pub async fn relay_leg_stream(
    server: &str,
    psk: &[u8; 32],
    id: u64,
) -> Result<crate::noise::Noise> {
    let (nr, mut nw) = tokio_timeout(OPEN_HANDSHAKE_TIMEOUT, async {
        let sock = TcpStream::connect(server).await?;
        sock.set_nodelay(true).ok();
        client_handshake(sock, psk).await
    })
    .await
    .map_err(|_| -> crate::Error { "relay leg connect+handshake timed out".into() })??;
    nw.send(&Msg::Data { id, name: None }.encode()).await?;
    Ok((nr, nw))
}

/// Open this party's relay leg over the udp transport: a setup conv carrying
/// the leg `id`, then the datagram channel under the matching tag, following
/// the UDP-forward rule for both. One datagram carries one inner frame, so the
/// server's splice keeps frame boundaries against a stream leg.
pub async fn relay_leg_dgram(sess: &Session, psk: &[u8; 32], id: u64) -> Result<RelayDgramLeg> {
    let conv = (id as u32) | SETUP_CONV_BIT;
    let stream = sess.open_conv_with(CLASS_SETUP, conv);
    let noise = Arc::new(
        tokio_timeout(
            OPEN_HANDSHAKE_TIMEOUT,
            client_handshake_stateless(stream, psk, id),
        )
        .await
        .map_err(|_| -> crate::Error { "relay leg handshake timed out".into() })??,
    );
    let (inbound, guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    Ok(RelayDgramLeg { rx, tx, guard })
}

/// L2 bridge over the UDP transport: frames ride the unreliable datagram channel.
/// The bool is whether the handshake established before the bridge ran or failed,
/// so the reconnect loop can tell a failed connect from an established-then-dead
/// session.
#[cfg(target_os = "linux")]
async fn bridge_udp(
    client: Arc<Client>,
    tap: Arc<TapDevice>,
    link: &LinkCell,
) -> (Result<()>, bool) {
    // `_pump` aborts the session RX pump when this scope ends (handshake failure
    // or bridge teardown), so a reconnect cannot leave the old pump running.
    let (sess, _pump, cancel) = match udp_connect(&client).await {
        Ok(v) => v,
        Err(e) => return (Err(e), false),
    };
    let stream = sess.open_conv_with(CLASS_SETUP, BRIDGE_CONV);
    let noise = match tokio_timeout(
        UDP_HANDSHAKE_TIMEOUT,
        client_handshake_stateless(stream, &client.psk, BRIDGE_ID),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return (Err(e), false),
        Err(_) => return (Err("udp handshake timed out".into()), false),
    };
    crate::elog!("bridge connected to {} over udp", client.server);
    link.set(LinkStatus::Connected);

    let noise = Arc::new(noise);
    let (inbound, _guard) = sess.register_dgram(BRIDGE_CONV);
    let tx = DgramTx::new(sess.send_tx(), BRIDGE_CONV, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    // Announce this client's label so the server's fleet view names the port.
    let _ = tx.send_name(&client.client_id).await;
    // `cancel` fires only when the RX pump sees the peer vanish (server restart),
    // tearing the bridge down at once instead of stalling until the next reconnect.
    bridge::tap_dgram(tap, rx, tx, cancel, &client.client_id).await;
    (Ok(()), true)
}

/// L2 bridge over the TCP fallback: frames ride a reliable Noise stream. The bool
/// is whether the handshake established before the bridge ran or failed.
#[cfg(target_os = "linux")]
async fn bridge_tcp(
    client: Arc<Client>,
    tap: Arc<TapDevice>,
    link: &LinkCell,
) -> (Result<()>, bool) {
    let ((nr, mut nw), _peer) =
        match connect_and_handshake(&client.server, &client.psk, OPEN_HANDSHAKE_TIMEOUT).await {
            Ok(v) => v,
            Err(e) => return (Err(e), false),
        };
    if let Err(e) = nw
        .send(
            &Msg::Data {
                id: BRIDGE_ID,
                name: Some(client.client_id.clone()),
            }
            .encode(),
        )
        .await
    {
        return (Err(e), true);
    }
    crate::elog!("bridge connected to {} over tcp", client.server);
    link.set(LinkStatus::Connected);
    bridge::tap_stream(tap, nr, nw, Arc::new(Notify::new())).await;
    (Ok(()), true)
}

/// Discovery resend budget for the in-process PPPoE client, expressed in
/// `NEGO_TICK` (1s) units: resend PADI/PADR after 3s of no progress, up to 5
/// attempts before declaring the line dead.
#[cfg(target_os = "linux")]
const PPPOE_RETRANSMIT_TICKS: u32 = 3;
#[cfg(target_os = "linux")]
const PPPOE_MAX_ATTEMPTS: u32 = 5;

/// Bring up the in-process PPPoE client: UDP first for Auto/Udp, TCP otherwise or
/// as fallback. Mirrors `bridge_session`'s reconnect contract; the only structural
/// delta is that `pppoe_udp`/`pppoe_tcp` return the datapath's `Result<()>` (a TUN
/// open failure or discovery death) instead of always `Ok(())`.
#[cfg(target_os = "linux")]
async fn pppoe_session(
    client: Arc<Client>,
    pp: Arc<PppoeRunConfig>,
    status: PppStatus,
    try_udp: bool,
    link: LinkCell,
) -> (Result<()>, UdpOutcome, bool) {
    let mode = client.transport;
    if mode == Transport::Tcp || (mode == Transport::Auto && !try_udp) {
        let (result, established) = pppoe_tcp(client, pp, status, &link).await;
        return (result, UdpOutcome::Skipped, established);
    }
    let started = Instant::now();
    match pppoe_udp(client.clone(), pp.clone(), status.clone(), &link).await {
        (Ok(()), established) => {
            let healthy = started.elapsed() >= UDP_MIN_HEALTHY;
            let outcome = if healthy {
                UdpOutcome::Healthy
            } else {
                UdpOutcome::Unhealthy
            };
            (Ok(()), outcome, established)
        }
        (Err(e), established) => {
            if mode == Transport::Udp {
                return (Err(e), UdpOutcome::Skipped, established);
            }
            crate::elog!("udp transport unavailable ({e}); falling back to tcp");
            let (result, tcp_established) = pppoe_tcp(client, pp, status, &link).await;
            (
                result,
                UdpOutcome::Unhealthy,
                established || tcp_established,
            )
        }
    }
}

/// Build a `PppoeDatapath` borrowing `pp`'s credential bytes. The caller holds
/// `pp` (an `Arc`) across the whole datapath run, so the borrow stays valid.
#[cfg(target_os = "linux")]
fn build_datapath(pp: &PppoeRunConfig) -> Result<crate::pppoe::datapath::PppoeDatapath<'_>> {
    let mut dp = crate::pppoe::datapath::PppoeDatapath::new(
        &pp.username,
        &pp.password,
        pp.service_name.clone(),
        pp.effective_mtu,
        PPPOE_RETRANSMIT_TICKS,
        PPPOE_MAX_ATTEMPTS,
    )
    .map_err(|e| -> crate::Error { e.into() })?;
    if let Some(c) = pp.clamp_mss {
        dp.set_clamp_mss(c);
    }
    dp.set_request_dns(pp.request_dns);
    Ok(dp)
}

/// The IPv4 half of a socket address, or `None` for IPv6. Used to target the
/// PPPoE WAN pin; an IPv6-reached control link cannot be stranded by a v4
/// default-route swap, so `None` correctly skips the pin there.
#[cfg(target_os = "linux")]
fn peer_v4(addr: SocketAddr) -> Option<std::net::Ipv4Addr> {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(_) => None,
    }
}

/// The server's IPv4 address parsed from a literal `host:port`. Valid for the UDP
/// path, where `--server` is already a resolved `ip:port`; the TCP path uses the
/// connected `peer_addr` instead so a hostname `--server` is still pinned.
#[cfg(target_os = "linux")]
fn server_v4(server: &str) -> Option<std::net::Ipv4Addr> {
    server.parse::<SocketAddr>().ok().and_then(peer_v4)
}

/// The server's IPv4 address for the exit pin: a literal `ip:port` parses
/// directly, a hostname is resolved and its first IPv4 answer taken. Exit
/// mode is IPv4-only, so a server with no IPv4 address is refused.
#[cfg(target_os = "linux")]
async fn exit_server_v4(addr: &str) -> Result<Ipv4Addr> {
    if let Some(ip) = server_v4(addr) {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| -> crate::Error { format!("resolving {addr}: {e}").into() })?;
    addrs
        .find_map(peer_v4)
        .ok_or_else(|| format!("exit mode needs an IPv4 server address; {addr} has none").into())
}

/// Program or refresh the exit routes ahead of a dial against `addr`, and
/// return the literal target the dial must use. The first call pins the
/// resolved server over the uplink and installs the half-defaults via
/// `tun_name` (in strict mode also the v6 blackholes and the deletion of
/// every default route, captured from the same table read as the pin); every
/// later call re-asserts the /32 pin, moving it when the resolved address
/// changed.
#[cfg(target_os = "linux")]
async fn ensure_exit_routes(
    guard: &mut Option<ExitRoutes>,
    addr: &str,
    tun_name: &str,
    strict: bool,
) -> Result<String> {
    let server = exit_server_v4(addr).await?;
    match guard {
        Some(g) => g.assert_pin(server)?,
        None => {
            let table = std::fs::read_to_string("/proc/net/route")
                .map_err(|e| -> crate::Error { format!("reading /proc/net/route: {e}").into() })?;
            let pin = crate::exitroute::plan_server_pin(&table, tun_name, server)?;
            let original = if strict {
                let defaults = crate::route::parse_all_defaults(&table, tun_name);
                if defaults.is_empty() {
                    return Err("no default route to capture for strict exit".into());
                }
                Some(defaults)
            } else {
                None
            };
            *guard = Some(ExitRoutes::bring_up(pin, tun_name, original)?);
        }
    }
    exit_dial_target(server, addr)
}

/// The exit-mode dial target: the pinned server address plus `addr`'s port.
/// One resolution feeds both the pin and the dial, so a round-robin or
/// dual-stack DNS answer cannot put the dial on an address the pin does not
/// cover.
#[cfg(target_os = "linux")]
fn exit_dial_target(server: Ipv4Addr, addr: &str) -> Result<String> {
    let (_, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| -> crate::Error { format!("no port in server address {addr}").into() })?;
    Ok(format!("{server}:{port}"))
}

#[cfg(target_os = "linux")]
fn bringup<'a>(
    server_ip: Option<std::net::Ipv4Addr>,
    pp: &'a PppoeRunConfig,
    status: PppStatus,
) -> crate::pppoe::tunnel::ZpppBringup<'a> {
    crate::pppoe::tunnel::ZpppBringup {
        tun_name: &pp.tun_name,
        mtu: pp.effective_mtu,
        ac_name: pp.ac_name.as_deref(),
        netcfg: crate::pppoe::netcfg::NetCfgOpts {
            default_route: pp.default_route,
            dns: pp.request_dns,
        },
        server_ip,
        status,
    }
}

/// In-process PPPoE over the UDP transport: PPPoE frames ride the unreliable
/// datagram channel. The bool is whether the handshake established before the
/// datapath ran or failed.
#[cfg(target_os = "linux")]
async fn pppoe_udp(
    client: Arc<Client>,
    pp: Arc<PppoeRunConfig>,
    status: PppStatus,
    link: &LinkCell,
) -> (Result<()>, bool) {
    let dp = match build_datapath(&pp) {
        Ok(dp) => dp,
        Err(e) => return (Err(e), false),
    };
    let (sess, _pump, cancel) = match udp_connect(&client).await {
        Ok(v) => v,
        Err(e) => return (Err(e), false),
    };
    let stream = sess.open_conv_with(CLASS_SETUP, BRIDGE_CONV);
    let noise = match tokio_timeout(
        UDP_HANDSHAKE_TIMEOUT,
        client_handshake_stateless(stream, &client.psk, BRIDGE_ID),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return (Err(e), false),
        Err(_) => return (Err("udp handshake timed out".into()), false),
    };
    crate::elog!("pppoe connected to {} over udp", client.server);
    link.set(LinkStatus::Connected);

    let noise = Arc::new(noise);
    let (inbound, _guard) = sess.register_dgram(BRIDGE_CONV);
    let tx = DgramTx::new(sess.send_tx(), BRIDGE_CONV, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    // Announce this client's label so the server's fleet view names the port.
    let _ = tx.send_name(&client.client_id).await;
    // UDP requires a literal ip:port, so the configured server is the real peer.
    let server_ip = server_v4(&client.server);
    let result = crate::pppoe::tunnel::run_dgram(
        dp,
        bringup(server_ip, &pp, status),
        rx,
        tx,
        cancel,
        &client.client_id,
    )
    .await;
    (result, true)
}

/// In-process PPPoE over the TCP fallback: PPPoE frames ride a reliable Noise
/// stream. The bool is whether the handshake established before the datapath ran.
#[cfg(target_os = "linux")]
async fn pppoe_tcp(
    client: Arc<Client>,
    pp: Arc<PppoeRunConfig>,
    status: PppStatus,
    link: &LinkCell,
) -> (Result<()>, bool) {
    let dp = match build_datapath(&pp) {
        Ok(dp) => dp,
        Err(e) => return (Err(e), false),
    };
    let ((nr, mut nw), peer) =
        match connect_and_handshake(&client.server, &client.psk, OPEN_HANDSHAKE_TIMEOUT).await {
            Ok(v) => v,
            Err(e) => return (Err(e), false),
        };
    if let Err(e) = nw
        .send(
            &Msg::Data {
                id: BRIDGE_ID,
                name: Some(client.client_id.clone()),
            }
            .encode(),
        )
        .await
    {
        return (Err(e), true);
    }
    crate::elog!("pppoe connected to {} over tcp", client.server);
    link.set(LinkStatus::Connected);
    // Pin the IP the tunnel actually connected to (handles a hostname --server).
    let server_ip = peer.and_then(peer_v4);
    let result = crate::pppoe::tunnel::run_stream(
        dp,
        bringup(server_ip, &pp, status),
        nr,
        nw,
        Arc::new(Notify::new()),
    )
    .await;
    (result, true)
}

/// Establish the control channel over UDP/KCP. Returns the session and the
/// handshaked control reader/writer, or an error to trigger TCP fallback.
async fn udp_session(
    client: Arc<Client>,
) -> Result<(Arc<Session>, AbortOnDrop, Arc<Notify>, crate::noise::Noise)> {
    // On handshake failure the `?` below drops `pump`, aborting the RX pump before
    // this scope returns Err; on success it is handed to the Link for the control
    // session's lifetime so control death aborts it too.
    let (sess, pump, cancel) = udp_connect(&client).await?;
    let (_conv, stream) = sess.open_conv(CLASS_KCP);
    let noise = tokio_timeout(UDP_HANDSHAKE_TIMEOUT, client_handshake(stream, &client.psk))
        .await
        .map_err(|_| -> crate::Error { "udp handshake timed out".into() })??;
    Ok((sess, pump, cancel, noise))
}

/// Establish the control connection and dispatch `Open` requests until it drops.
/// Returns the loop result, how UDP behaved this attempt (so the reconnect loop
/// can damp UDP flapping; Auto only, see `UdpHealth`), and whether the control
/// channel ever established (reaching `control_loop` means connect and handshake
/// both succeeded; a later death is not a failure to establish).
async fn session(
    client: Arc<Client>,
    try_udp: bool,
    link: LinkCell,
    peer: PeerControl,
) -> (Result<()>, UdpOutcome, bool) {
    let mode = client.transport;

    // Try UDP first for Auto/Udp (unless cooldown skipped it); fall back to TCP
    // for Auto/Tcp.
    let probe_udp = mode != Transport::Tcp && (mode == Transport::Udp || try_udp);
    let (via, r, w, started) = if probe_udp {
        match udp_session(client.clone()).await {
            Ok((sess, pump, cancel, (r, w))) => {
                crate::elog!("connected to {} over udp", client.server);
                link.set(LinkStatus::Connected);
                (Link::Udp(sess, pump, cancel), r, w, Some(Instant::now()))
            }
            Err(e) => {
                if mode == Transport::Udp {
                    // Forced UDP never falls back; a failed connect is just an error.
                    return (Err(e), UdpOutcome::Skipped, false);
                }
                // A failed UDP connect is itself a flap signal for the cooldown,
                // independent of how the TCP fallback session fares afterwards.
                crate::elog!("udp transport unavailable ({e}); falling back to tcp");
                match tcp_control(client.clone()).await {
                    Ok((r, w)) => {
                        link.set(LinkStatus::Connected);
                        return (
                            control_loop(client, Link::Tcp, r, w, peer).await,
                            UdpOutcome::Unhealthy,
                            true,
                        );
                    }
                    Err(e) => return (Err(e), UdpOutcome::Unhealthy, false),
                }
            }
        }
    } else {
        match tcp_control(client.clone()).await {
            Ok((r, w)) => {
                link.set(LinkStatus::Connected);
                (Link::Tcp, r, w, None)
            }
            Err(e) => return (Err(e), UdpOutcome::Skipped, false),
        }
    };

    let result = control_loop(client, via, r, w, peer).await;
    // Health is measured from when the UDP control channel came up to when it
    // returned; a short-lived UDP session is a flap. TCP-fallback paths report
    // their UDP verdict above, so `started` here is always the UDP case.
    let outcome = match started {
        Some(t) if t.elapsed() >= UDP_MIN_HEALTHY => UdpOutcome::Healthy,
        Some(_) => UdpOutcome::Unhealthy,
        None => UdpOutcome::Skipped,
    };
    (result, outcome, true)
}

/// Dial `addr`, disable Nagle, run the Noise handshake, and report the connected
/// peer address, bounding the whole connect-plus-handshake under `timeout`.
///
/// A path that black-holes mid-handshake (msg1 ACKed but msg2 never arrives on a
/// NAT remap, WAN re-dial, or silent firewall drop) would otherwise park on the
/// kernel read for the retransmit window (~15 min, or forever with keepalive off);
/// the timeout turns that into an Err so the caller can back off and redial in
/// seconds. The peer is the IP the socket actually reached (after DNS resolution of
/// a hostname `--server`), which is what the PPPoE WAN pin must target; a re-parse
/// of the config string misses the hostname case.
async fn connect_and_handshake(
    addr: &str,
    psk: &[u8; 32],
    timeout: Duration,
) -> Result<(crate::noise::Noise, Option<SocketAddr>)> {
    tokio_timeout(timeout, async {
        let sock = TcpStream::connect(addr)
            .await
            .map_err(|e| -> crate::Error { format!("connecting to {addr}: {e}").into() })?;
        sock.set_nodelay(true).ok();
        let peer = sock.peer_addr().ok();
        let noise = client_handshake(sock, psk).await?;
        Ok((noise, peer))
    })
    .await
    .map_err(|_| -> crate::Error { format!("tcp handshake to {addr} timed out").into() })?
}

/// Dial the TCP control connection and run the Noise handshake.
async fn tcp_control(client: Arc<Client>) -> Result<crate::noise::Noise> {
    let (noise, _peer) =
        connect_and_handshake(&client.server, &client.psk, OPEN_HANDSHAKE_TIMEOUT).await?;
    crate::elog!("connected to {}", client.server);
    Ok(noise)
}

/// Run the control loop over an established Noise control channel, dispatching
/// `Open` requests via `link` until the channel drops.
async fn control_loop(
    client: Arc<Client>,
    link: Link,
    mut r: crate::noise::NoiseReader,
    w: crate::noise::NoiseWriter,
    peer: PeerControl,
) -> Result<()> {
    let link = Arc::new(link);
    let cancel = match link.as_ref() {
        Link::Udp(_, _, cancel) => Some(cancel.clone()),
        Link::Tcp => None,
    };

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    tx.try_send(
        Msg::ClientHello {
            version: crate::identity::PROTO_VERSION,
            client_id: client.client_id.clone(),
        }
        .encode(),
    )
    .ok();
    // Announce per-forward options right after the hello, but only when at
    // least one forward carries a non-default option: an all-default client
    // stays byte-identical on the wire to older releases.
    let options = fwd_options(&client);
    let ack = Arc::new(AtomicBool::new(false));
    if !options.is_empty() {
        tx.try_send(Msg::FwdOptions { entries: options }.encode())
            .ok();
    }
    // Peer support is announced once per control session, alongside the
    // forward options, carrying the union of the provider bits. The slots pair
    // through the session only once the ack comes back.
    let peer_ack = Arc::new(AtomicBool::new(false));
    if let Some(provides) = client.peer_announce {
        tx.try_send(Msg::PeerAnnounce { provides }.encode()).ok();
    }
    // Filled when the ack arrives; dropping it at teardown bumps the
    // generation, which fails every peer cycle that has not settled on a
    // punched path.
    let mut peer_live: Option<crate::peerslot::ControlGuard> = None;

    // Every task this session spawns is held through an AbortOnDrop guard, so
    // both a normal teardown and a server switch aborting the whole session
    // task reap them instead of leaving them running against a dead server.
    let mut w = w;
    let _writer = AbortOnDrop(tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if w.send(&bytes).await.is_err() {
                break;
            }
        }
    }));

    let ping_tx = tx.clone();
    let _pinger = AbortOnDrop(tokio::spawn(async move {
        let mut tick = interval(PING_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            if ping_tx.try_send(Msg::Ping.encode()).is_err() {
                break;
            }
        }
    }));

    // Fail loud at setup for proxy-enabled forwards: they never fall back to a
    // headerless relay, so a server that does not ack the options (an older
    // release ignores the frame) leaves those ports refusing every connection.
    // Say so once, loudly, instead of letting each open fail quietly.
    let _watchdog = {
        let mut proxied: Vec<u16> = client
            .tcp
            .iter()
            .filter(|(_, f)| f.proxy)
            .map(|(&p, _)| p)
            .collect();
        if proxied.is_empty() {
            None
        } else {
            proxied.sort_unstable();
            let ports = proxied
                .iter()
                .map(|p| format!(":{p}"))
                .collect::<Vec<_>>()
                .join(", ");
            let ack = ack.clone();
            Some(AbortOnDrop(tokio::spawn(async move {
                sleep(FWD_OPTIONS_ACK_TIMEOUT).await;
                if !ack.load(Ordering::Relaxed) {
                    crate::elog!(
                        "server did not acknowledge PROXY protocol support; tcp forward(s) {ports} \
                         will refuse connections rather than relay without the header; upgrade the \
                         server to a release that supports +proxy"
                    );
                }
            })))
        }
    };

    // A server that does not answer the announce has no peer support, which
    // fails every peer slot for this control session. The next one announces
    // again and re-decides, so the verdict never outlives a server upgrade.
    let _peer_watchdog = client.peer_announce.map(|_| {
        let acked = peer_ack.clone();
        AbortOnDrop(tokio::spawn(async move {
            sleep(FWD_OPTIONS_ACK_TIMEOUT).await;
            if !acked.load(Ordering::Relaxed) {
                crate::elog!(
                    "server did not acknowledge peer support; no peer session can pair over \
                     this control session; upgrade the server to a release that supports peers"
                );
            }
        }))
    });

    // Guards for in-flight forward tasks spawned for this control session, so a
    // teardown aborts black-holed forwards instead of leaking them.
    let mut forwards: Vec<AbortOnDrop> = Vec::new();

    loop {
        // Any inbound frame (Pong from our ping, or an Open) resets the deadline.
        // No frame for the whole window means the link is a black hole with no
        // FIN/RST; return Err so the outer reconnect loop re-resolves and redials.
        let recv = tokio_timeout(CONTROL_TIMEOUT, r.recv());
        let died = async {
            match &cancel {
                Some(c) => c.notified().await,
                None => std::future::pending().await,
            }
        };
        let msg = tokio::select! {
            // The RX pump saw the peer vanish (ICMP unreachable on UDP); tear down
            // now rather than waiting out CONTROL_TIMEOUT for the deadline to lapse.
            _ = died => break Err("udp peer unreachable (link dead)".into()),
            res = recv => match res {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => break Err(e),
                Err(_) => break Err("control channel timed out (link dead)".into()),
            },
        };
        let open = match Msg::decode(&msg) {
            Ok(Msg::Open { proto, port, id }) => Some((proto, port, id, None)),
            // TCP-only by construction: the server sends OpenProxy exclusively
            // for TCP ports this client flagged proxy.
            Ok(Msg::OpenProxy {
                port,
                id,
                peer,
                local,
            }) => Some((Proto::Tcp, port, id, Some((peer, local)))),
            Ok(Msg::FwdOptionsAck) => {
                ack.store(true, Ordering::Relaxed);
                None
            }
            Ok(Msg::PeerAnnounceAck { observed }) => {
                peer_ack.store(true, Ordering::Relaxed);
                if peer_live.is_none() {
                    crate::elog!("peer support acknowledged; control address {observed}");
                    peer_live = Some(peer.install(crate::peerslot::ControlSession {
                        tx: tx.clone(),
                        server: client.server.clone(),
                        psk: client.psk,
                        sess: match link.as_ref() {
                            Link::Udp(sess, _, _) => Some(sess.clone()),
                            Link::Tcp => None,
                        },
                    }));
                }
                None
            }
            Ok(
                m @ (Msg::PeerResult { .. }
                | Msg::PeerProbe { .. }
                | Msg::PeerInfo { .. }
                | Msg::PeerRelayOpen { .. }),
            ) => {
                peer.route(m);
                None
            }
            Ok(_) => None,
            Err(e) => break Err(e),
        };
        if let Some((proto, port, id, proxy_addrs)) = open {
            let client = client.clone();
            let link = link.clone();
            // Drop guards of forwards that already finished so the tracking
            // vector stays bounded over a long healthy session.
            forwards.retain(|h| !h.0.is_finished());
            forwards.push(AbortOnDrop(tokio::spawn(async move {
                if let Err(e) = handle_open(client, link, proto, port, id, proxy_addrs).await {
                    crate::elog!("stream {id} ({proto:?} :{port}) failed: {e}");
                }
            })));
        }
    }
}

/// Wire entries for every forward carrying a non-default option; empty when the
/// whole config is default, in which case no `FwdOptions` frame is sent.
fn fwd_options(client: &Client) -> Vec<FwdOptionEntry> {
    let mut entries = Vec::new();
    for (proto, map) in [(Proto::Tcp, &client.tcp), (Proto::Udp, &client.udp)] {
        for (&port, f) in map {
            if f.proxy || f.idle.is_some() {
                entries.push(FwdOptionEntry {
                    proto,
                    port,
                    proxy: f.proxy,
                    idle_secs: f.idle.map(|d| d.as_secs() as u32).unwrap_or(0),
                });
            }
        }
    }
    entries
}

/// Connect the local TCP target and, on a proxy-enabled open, write the PROXY
/// v2 header ahead of any tunneled payload so it is the very first bytes the
/// target sees.
async fn connect_local_tcp(
    target: &str,
    proxy_addrs: Option<(SocketAddr, SocketAddr)>,
) -> Result<TcpStream> {
    let mut local = TcpStream::connect(target)
        .await
        .map_err(|e| -> crate::Error { format!("connecting to local {target}: {e}").into() })?;
    if let Some((peer, listener)) = proxy_addrs {
        local
            .write_all(&crate::proxyproto::encode_v2(peer, listener))
            .await?;
    }
    Ok(local)
}

/// Open a data connection back to the server and bridge it to the local target.
/// `proxy_addrs` is the public `(peer, listener)` pair from an `OpenProxy`. A
/// proxy-enabled forward has no headerless mode: a plain `Open` for it is
/// refused before anything is dialed, and an `OpenProxy` for a forward that
/// never asked for one is refused the same way.
async fn handle_open(
    client: Arc<Client>,
    link: Arc<Link>,
    proto: Proto,
    port: u16,
    id: u64,
    proxy_addrs: Option<(SocketAddr, SocketAddr)>,
) -> Result<()> {
    let fwd = match proto {
        Proto::Tcp => client.tcp.get(&port),
        Proto::Udp => client.udp.get(&port),
    }
    .ok_or_else(|| -> crate::Error {
        format!("no local target configured for {proto:?} :{port}").into()
    })?
    .clone();
    if fwd.proxy && proxy_addrs.is_none() {
        return Err(format!(
            "forward :{port} requires a PROXY header but the server sent no peer addresses \
             (it does not support +proxy); refusing to relay without the header"
        )
        .into());
    }
    if !fwd.proxy && proxy_addrs.is_some() {
        return Err(format!("unexpected proxy open for {proto:?} :{port}").into());
    }
    let target = fwd.target;
    let idle = fwd.idle.unwrap_or(match proto {
        Proto::Tcp => bridge::TCP_IDLE,
        Proto::Udp => bridge::UDP_IDLE,
    });

    match (link.as_ref(), proto) {
        // --- TCP transport (unchanged behavior) ---
        (Link::Tcp, Proto::Tcp) => {
            let (nr, mut nw) = tokio_timeout(OPEN_HANDSHAKE_TIMEOUT, async {
                let sock = TcpStream::connect(&client.server).await?;
                sock.set_nodelay(true).ok();
                client_handshake(sock, &client.psk).await
            })
            .await
            .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??;
            nw.send(&Msg::Data { id, name: None }.encode()).await?;
            let local = connect_local_tcp(&target, proxy_addrs).await?;
            bridge::tcp(local, nr, nw, idle).await;
        }
        (Link::Tcp, Proto::Udp) => {
            let (nr, mut nw) = tokio_timeout(OPEN_HANDSHAKE_TIMEOUT, async {
                let sock = TcpStream::connect(&client.server).await?;
                sock.set_nodelay(true).ok();
                client_handshake(sock, &client.psk).await
            })
            .await
            .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??;
            nw.send(&Msg::Data { id, name: None }.encode()).await?;
            let local = UdpSocket::bind("0.0.0.0:0").await?;
            local.connect(&target).await.map_err(|e| -> crate::Error {
                format!("connecting to local {target}: {e}").into()
            })?;
            bridge::udp_client(local, nr, nw, idle).await;
        }
        // --- UDP transport ---
        (Link::Udp(sess, _, _), Proto::Tcp) => {
            let (_conv, stream) = sess.open_conv(CLASS_KCP);
            let (nr, mut nw) = tokio_timeout(
                OPEN_HANDSHAKE_TIMEOUT,
                client_handshake(stream, &client.psk),
            )
            .await
            .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??;
            nw.send(&Msg::Data { id, name: None }.encode()).await?;
            let local = connect_local_tcp(&target, proxy_addrs).await?;
            bridge::tcp(local, nr, nw, idle).await;
        }
        (Link::Udp(sess, _, _), Proto::Udp) => {
            let conv = (id as u32) | SETUP_CONV_BIT;
            let stream = sess.open_conv_with(CLASS_SETUP, conv);
            let noise = Arc::new(
                tokio_timeout(
                    OPEN_HANDSHAKE_TIMEOUT,
                    client_handshake_stateless(stream, &client.psk, id),
                )
                .await
                .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??,
            );
            let local = UdpSocket::bind("0.0.0.0:0").await?;
            local.connect(&target).await.map_err(|e| -> crate::Error {
                format!("connecting to local {target}: {e}").into()
            })?;
            let (inbound, _guard) = sess.register_dgram(conv);
            let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
            let rx = DgramRx::new(inbound, noise);
            bridge::udp_client_stateless(local, rx, tx, idle).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_fails_arm_cooldown_then_tcp_is_chosen() {
        let mut s = UdpHealth::default();
        let t0 = Instant::now();
        // First flap: still probe UDP next time.
        record(&mut s, false, t0);
        assert!(choose_udp(&s, t0));
        // Second consecutive flap reaches UDP_QUICK_FAILS and arms the cooldown.
        record(&mut s, false, t0);
        assert!(!choose_udp(&s, t0));
        // Mid-cooldown still skips UDP; after it expires UDP is re-probed.
        assert!(!choose_udp(&s, t0 + UDP_COOLDOWN - Duration::from_secs(1)));
        assert!(choose_udp(&s, t0 + UDP_COOLDOWN));
    }

    #[test]
    fn healthy_clears_cooldown_and_counter() {
        let mut s = UdpHealth::default();
        let t0 = Instant::now();
        record(&mut s, false, t0);
        record(&mut s, false, t0);
        assert!(s.cooldown_until.is_some());
        record(&mut s, true, t0);
        assert_eq!(s.fails, 0);
        assert!(s.cooldown_until.is_none());
        assert!(choose_udp(&s, t0));
    }

    #[test]
    fn isolated_flaps_never_arm_cooldown() {
        let mut s = UdpHealth::default();
        let t0 = Instant::now();
        // A flap followed by a healthy session must not accumulate toward cooldown.
        record(&mut s, false, t0);
        record(&mut s, true, t0);
        record(&mut s, false, t0);
        assert!(s.cooldown_until.is_none());
        assert!(choose_udp(&s, t0));
    }

    fn target(name: &str) -> ServerTarget {
        ServerTarget {
            name: name.into(),
            addr: "127.0.0.1:1".into(),
            secret: "s".into(),
            transport: Transport::Tcp,
        }
    }

    // A switch must never be lost, wherever it lands relative to a profile
    // bringup: before `begin` the snapshot already carries the new target, and
    // after `begin` the permit sits on that profile's own cancel.
    #[tokio::test]
    async fn switch_is_never_lost_across_begin() {
        let active = ActiveTarget::new(target("a"));
        active.switch(target("b"));
        let (t, _mode, cancel) = active.begin();
        assert_eq!(t.name, "b");

        active.switch(target("c"));
        tokio_timeout(Duration::from_secs(1), cancel.notified())
            .await
            .expect("switch did not fire the profile cancel");
        let (t, _mode, _cancel) = active.begin();
        assert_eq!(t.name, "c");
    }

    /// A `[tun]` without an explicit address follows the active server's
    /// secret; a pinned address never moves.
    #[test]
    fn tun_address_follows_the_secret_unless_pinned() {
        let derived = ClientTun {
            name: "zn0".into(),
            mtu: 1400,
            address: None,
            exit: false,
            exit_strict: false,
        };
        let a = derived.resolve("secret-a");
        let b = derived.resolve("secret-b");
        assert_eq!(a.prefix_len, 24);
        let base = crate::identity::derive_tun_subnet("secret-a");
        assert_eq!(a.addr, Ipv4Addr::new(base[0], base[1], base[2], 2));
        assert_ne!(a.addr, b.addr, "distinct secrets derive distinct subnets");

        let pinned = ClientTun {
            name: "zn0".into(),
            mtu: 1400,
            address: Some((Ipv4Addr::new(192, 168, 7, 1), 30)),
            exit: false,
            exit_strict: false,
        };
        let p = pinned.resolve("secret-a");
        assert_eq!(p.addr, Ipv4Addr::new(192, 168, 7, 1));
        assert_eq!(p.prefix_len, 30);
        assert_eq!(pinned.resolve("secret-b").addr, p.addr);
    }

    /// Exit mode is IPv4-only: a literal v4 target pins directly, a target
    /// with only an IPv6 address is refused before bringup.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exit_pin_requires_an_ipv4_server() {
        assert_eq!(
            exit_server_v4("203.0.113.9:7000").await.unwrap(),
            Ipv4Addr::new(203, 0, 113, 9)
        );
        let err = exit_server_v4("[2001:db8::1]:7000").await.unwrap_err();
        assert!(err.to_string().contains("IPv4"), "unexpected error: {err}");
    }

    /// An exit-mode dial goes to the pinned literal with the target's port,
    /// never back through the resolver.
    #[cfg(target_os = "linux")]
    #[test]
    fn exit_dial_targets_the_pinned_literal() {
        let pin = Ipv4Addr::new(203, 0, 113, 9);
        assert_eq!(
            exit_dial_target(pin, "example.com:7000").unwrap(),
            "203.0.113.9:7000"
        );
        assert_eq!(
            exit_dial_target(pin, "198.51.100.4:9000").unwrap(),
            "203.0.113.9:9000"
        );
        assert!(exit_dial_target(pin, "noport").is_err());
    }

    fn pppoe_mode(name: &str) -> RunMode {
        RunMode::Pppoe {
            name: name.into(),
            config: Arc::new(PppoeRunConfig {
                username: b"u".to_vec(),
                password: b"p".to_vec(),
                service_name: Vec::new(),
                ac_name: None,
                tun_name: "zppp0".into(),
                effective_mtu: 1400,
                default_route: false,
                clamp_mss: None,
                request_dns: false,
            }),
        }
    }

    #[test]
    fn stop_pppoe_matches_only_the_active_session() {
        let active = ActiveTarget::new(target("a"));
        active.init_mode(RunMode::Forwards);
        // Not a pppoe body: nothing to stop.
        assert!(!active.stop_pppoe("wan", RunMode::Forwards));
        assert_eq!(active.admin_view().1, SessionMode::Forwards);

        active.set_mode(pppoe_mode("wan")).unwrap();
        assert_eq!(active.admin_view().1, SessionMode::Pppoe);
        // Wrong name: the running session stays.
        assert!(!active.stop_pppoe("dsl", RunMode::Forwards));
        assert_eq!(active.admin_view().1, SessionMode::Pppoe);
        // Right name: back to the base mode.
        assert!(active.stop_pppoe("wan", RunMode::Forwards));
        assert_eq!(active.admin_view().1, SessionMode::Forwards);
    }

    // A stale memo would keep the old PSK and discovery after a
    // remove-then-add under the same name; the triple key must miss instead.
    #[test]
    fn dial_memo_rekeys_on_addr_or_secret_change() {
        let mut memo = DialMemo::default();
        let mut t = target("a");
        let psk = memo.state(&t).unwrap().psk;
        // The same triple hits the memo.
        memo.state(&t).unwrap();
        assert_eq!(memo.0.len(), 1);
        // Same name, new secret: a fresh entry with a fresh PSK.
        t.secret = "s2".into();
        let rekeyed = memo.state(&t).unwrap().psk;
        assert_eq!(memo.0.len(), 2);
        assert_ne!(psk, rekeyed);
        // Same name and secret, new address: its own entry too.
        t.addr = "127.0.0.1:2".into();
        memo.state(&t).unwrap();
        assert_eq!(memo.0.len(), 3);
    }

    // A removed profile must not pin its dial state for the process
    // lifetime; the prune keeps the configured set plus the active target.
    #[test]
    fn dial_memo_prunes_unconfigured_entries() {
        let mut memo = DialMemo::default();
        let a = target("a");
        let mut b = target("b");
        memo.state(&a).unwrap();
        memo.state(&b).unwrap();
        // b removed and re-added with a new secret: the stale entry lingers
        // until the next prune.
        b.secret = "s2".into();
        memo.state(&b).unwrap();
        assert_eq!(memo.0.len(), 3);
        let servers = SharedServers::new(vec![b.clone()]);
        memo.prune(&servers, &a);
        // a survives as the active target, b's stale entry is gone.
        let keys: Vec<&(String, String, String)> = memo.0.keys().collect();
        assert_eq!(memo.0.len(), 2, "{keys:?}");
        assert!(memo
            .0
            .contains_key(&(b.name.clone(), b.addr.clone(), b.secret.clone())));
        assert!(memo
            .0
            .contains_key(&(a.name.clone(), a.addr.clone(), a.secret.clone())));
    }

    // Disconnect parks any body (and only refuses a repeat); connect leaves
    // the park with the caller's boot body and never touches a live one.
    #[test]
    fn disconnect_and_connect_gate_on_the_park() {
        let active = ActiveTarget::new(target("a"));
        active.init_mode(RunMode::Forwards);
        assert!(active.disconnect());
        assert_eq!(active.admin_view().1, SessionMode::Offline);
        assert!(!active.disconnect(), "already offline must be refused");

        // A named connect retargets and installs the boot body.
        assert!(active
            .connect(Some(target("b")), RunMode::Forwards)
            .unwrap());
        let (t, mode, _cancel) = active.begin();
        assert_eq!(t.name, "b");
        assert_eq!(mode.session_mode(), SessionMode::Forwards);

        // With a session body up, connect changes nothing.
        assert!(!active
            .connect(Some(target("c")), RunMode::Forwards)
            .unwrap());
        assert_eq!(active.admin_view().0, "b");
        assert_eq!(active.admin_view().1, SessionMode::Forwards);
    }

    #[test]
    fn shared_servers_add_remove_and_resolve() {
        let servers = SharedServers::new(vec![target("a")]);
        assert!(servers.get("a").is_some());
        assert!(servers.get("b").is_none());
        assert!(!servers.add(target("a")), "duplicate names must be refused");
        assert!(servers.add(target("b")));
        let names: Vec<String> = servers.entries().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["a", "b"]);
        assert!(!servers.remove("c"));
        assert!(servers.remove("a"));
        assert!(servers.get("a").is_none());
        assert_eq!(servers.entries().len(), 1);
    }

    // A switch keeps the session body; only set_mode/stop_pppoe change it.
    #[test]
    fn switch_preserves_the_session_mode() {
        let active = ActiveTarget::new(target("a"));
        active.init_mode(pppoe_mode("wan"));
        active.switch(target("b"));
        let (t, mode, _cancel) = active.begin();
        assert_eq!(t.name, "b");
        assert_eq!(mode.session_mode(), SessionMode::Pppoe);
    }

    #[tokio::test(start_paused = true)]
    async fn kick_fires_only_in_forwards_mode() {
        let active = ActiveTarget::new(target("a"));
        active.init_mode(RunMode::Forwards);
        let (_t, _m, cancel) = active.begin();
        active.kick_if_forwards();
        tokio_timeout(Duration::from_secs(1), cancel.notified())
            .await
            .expect("kick must fire the cancel in forwards mode");

        active.set_mode(pppoe_mode("wan")).unwrap();
        let (_t, _m, cancel) = active.begin();
        active.kick_if_forwards();
        assert!(
            tokio_timeout(Duration::from_secs(1), cancel.notified())
                .await
                .is_err(),
            "kick must not drop a non-forwards body"
        );
    }

    fn one_tcp_forward(enabled: bool) -> SharedForwards {
        SharedForwards::new(
            vec![Forward {
                port: 443,
                target: "127.0.0.1:8443".into(),
                proxy: false,
                idle: None,
                enabled,
            }],
            vec![],
        )
    }

    // The derived body keys on declared forwards, enabled or not; only an
    // empty declared set falls through to the fallback.
    #[test]
    fn derive_mode_keys_on_declared_forwards() {
        let empty = SharedForwards::new(vec![], vec![]);
        for fallback in [RunMode::Idle, pppoe_mode("wan")] {
            assert_eq!(
                derive_mode(&empty, &fallback).session_mode(),
                fallback.session_mode()
            );
            assert_eq!(
                derive_mode(&one_tcp_forward(true), &fallback).session_mode(),
                SessionMode::Forwards
            );
            // A disabled entry still shapes the mode, as it shapes a boot.
            assert_eq!(
                derive_mode(&one_tcp_forward(false), &fallback).session_mode(),
                SessionMode::Forwards
            );
        }
        // Adding then removing the only forward moves the derivation with the
        // declared set: what Connect installs and what StopSession falls back
        // to track the current set, not the boot-time one.
        let fwds = SharedForwards::new(vec![], vec![]);
        let fallback = pppoe_mode("wan");
        assert_eq!(
            derive_mode(&fwds, &fallback).session_mode(),
            SessionMode::Pppoe
        );
        assert!(fwds.add(
            Proto::Udp,
            Forward {
                port: 53,
                target: "127.0.0.1:5353".into(),
                proxy: false,
                idle: None,
                enabled: false,
            }
        ));
        assert_eq!(
            derive_mode(&fwds, &fallback).session_mode(),
            SessionMode::Forwards
        );
        assert_eq!(
            derive_mode(&fwds, &RunMode::Idle).session_mode(),
            SessionMode::Forwards
        );
        assert!(fwds.remove(Proto::Udp, 53));
        assert_eq!(
            derive_mode(&fwds, &fallback).session_mode(),
            SessionMode::Pppoe
        );
        assert_eq!(
            derive_mode(&fwds, &RunMode::Idle).session_mode(),
            SessionMode::Idle
        );
    }

    #[test]
    fn add_and_remove_edit_the_forward_maps() {
        let fwds = one_tcp_forward(true);
        assert!(fwds.any_declared());
        // A duplicate (proto, port) is refused without touching the entry.
        assert!(!fwds.add(
            Proto::Tcp,
            Forward {
                port: 443,
                target: "10.0.0.9:1".into(),
                proxy: true,
                idle: None,
                enabled: true,
            }
        ));
        assert_eq!(fwds.entries()[0].target, "127.0.0.1:8443");
        // The same port on the other proto is its own key.
        assert!(fwds.add(
            Proto::Udp,
            Forward {
                port: 443,
                target: "127.0.0.1:5353".into(),
                proxy: false,
                idle: Some(Duration::from_secs(300)),
                enabled: false,
            }
        ));
        let entries = fwds.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].proto, Proto::Udp);
        assert_eq!(entries[1].idle_secs, 300);
        assert!(!entries[1].enabled);

        assert!(!fwds.remove(Proto::Tcp, 80));
        assert!(fwds.remove(Proto::Tcp, 443));
        assert!(fwds.remove(Proto::Udp, 443));
        assert!(!fwds.remove(Proto::Udp, 443));
        assert!(!fwds.any_declared());
        assert!(fwds.entries().is_empty());
    }

    // The idle-promotion contract: idle installs the forwards body and fires,
    // a live forwards body is kicked, everything else is left alone.
    #[tokio::test(start_paused = true)]
    async fn serve_forwards_promotes_idle_and_kicks_forwards_only() {
        let active = ActiveTarget::new(target("a"));
        active.init_mode(RunMode::Idle);
        let (_t, _m, cancel) = active.begin();
        active.serve_forwards();
        tokio_timeout(Duration::from_secs(1), cancel.notified())
            .await
            .expect("promotion from idle must fire the cancel");
        assert_eq!(active.admin_view().1, SessionMode::Forwards);

        let (_t, _m, cancel) = active.begin();
        active.serve_forwards();
        tokio_timeout(Duration::from_secs(1), cancel.notified())
            .await
            .expect("a live forwards body must be kicked");
        assert_eq!(active.admin_view().1, SessionMode::Forwards);

        for parked in [pppoe_mode("wan"), RunMode::Offline] {
            let mode = parked.session_mode();
            active.set_mode(parked).unwrap();
            let (_t, _m, cancel) = active.begin();
            active.serve_forwards();
            assert!(
                tokio_timeout(Duration::from_secs(1), cancel.notified())
                    .await
                    .is_err(),
                "serve_forwards must not touch a {mode:?} body"
            );
            assert_eq!(active.admin_view().1, mode);
        }
    }

    #[test]
    fn set_options_edits_existing_forwards_only() {
        let fwds = SharedForwards::new(
            vec![Forward {
                port: 443,
                target: "127.0.0.1:8443".into(),
                proxy: false,
                idle: None,
                enabled: true,
            }],
            vec![Forward {
                port: 53,
                target: "127.0.0.1:5353".into(),
                proxy: false,
                idle: Some(Duration::from_secs(9)),
                enabled: true,
            }],
        );
        assert!(!fwds.set_options(Proto::Tcp, 80, true, true, None));
        assert!(!fwds.set_options(Proto::Udp, 443, true, false, None));

        assert!(fwds.set_options(Proto::Tcp, 443, false, true, Some(Duration::from_secs(600))));
        assert!(fwds.set_options(Proto::Udp, 53, true, false, None)); // clears the idle window

        let entries = fwds.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].proto, Proto::Tcp);
        assert!(entries[0].proxy);
        assert_eq!(entries[0].idle_secs, 600);
        assert!(!entries[0].enabled);
        assert_eq!(entries[1].proto, Proto::Udp);
        assert_eq!(entries[1].idle_secs, 0);
        assert!(entries[1].enabled);
    }

    // A disabled forward is invisible to the per-attempt maps but keeps its
    // slot in the snapshot view, and a toggle moves it on the next read.
    #[test]
    fn maps_leave_out_disabled_forwards() {
        let fwds = SharedForwards::new(
            vec![
                Forward {
                    port: 443,
                    target: "127.0.0.1:8443".into(),
                    proxy: false,
                    idle: None,
                    enabled: true,
                },
                Forward {
                    port: 80,
                    target: "127.0.0.1:8080".into(),
                    proxy: false,
                    idle: None,
                    enabled: false,
                },
            ],
            vec![Forward {
                port: 53,
                target: "127.0.0.1:5353".into(),
                proxy: false,
                idle: None,
                enabled: false,
            }],
        );

        let (tcp, udp) = fwds.maps();
        assert_eq!(tcp.keys().copied().collect::<Vec<_>>(), [443]);
        assert!(udp.is_empty());
        let entries = fwds.entries();
        assert_eq!(entries.len(), 3);
        assert!(!entries.iter().find(|e| e.port == 80).unwrap().enabled);
        assert!(!entries.iter().find(|e| e.port == 53).unwrap().enabled);

        assert!(fwds.set_options(Proto::Tcp, 80, true, false, None));
        assert!(fwds.set_options(Proto::Tcp, 443, false, false, None));
        let (tcp, _) = fwds.maps();
        assert_eq!(tcp.keys().copied().collect::<Vec<_>>(), [80]);
        assert_eq!(fwds.entries().len(), 3);
    }

    fn provider_slot(bit: u8, device: Option<&str>) -> PeerSlotSpec {
        PeerSlotSpec::Provider {
            provides: bit,
            device: device.map(Into::into),
            exit: None,
        }
    }

    /// An exit provider, which claims the tun its adapter opens.
    fn exit_provider_slot(device: &str) -> PeerSlotSpec {
        PeerSlotSpec::Provider {
            provides: crate::proto::PROVIDES_EXIT,
            device: None,
            exit: Some(PeerExit {
                device: device.into(),
                mtu: 1400,
                iface: None,
            }),
        }
    }

    fn consumer_slot(peer: &str, device: Option<&str>, default_route: bool) -> PeerSlotSpec {
        PeerSlotSpec::Consumer {
            peer_id: peer.into(),
            want: crate::proto::PROVIDES_EXIT,
            device: device.map(Into::into),
            default_route,
        }
    }

    fn tap_body(name: &str) -> RunMode {
        RunMode::Device(DeviceConfig::Tap(TapConfig {
            name: name.into(),
            mtu: 1400,
            bridge: None,
        }))
    }

    // A device a peer slot holds refuses the body that would open it, naming
    // both, and leaves the running slots alone.
    #[test]
    fn a_body_cannot_take_a_device_a_peer_slot_holds() {
        let peers = peer_claims(&[provider_slot(crate::proto::PROVIDES_SEGMENT, Some("eth1"))]);
        let claims = SlotClaims::new(peers).unwrap();
        let err = claims.admit_body(tap_body("eth1").claims()).unwrap_err();
        assert!(err.contains("eth1"), "{err}");
        assert!(err.contains("segment provider"), "{err}");
        // An unrelated device is admitted.
        claims.admit_body(tap_body("ztap0").claims()).unwrap();
    }

    // Default-route programming is its own claim: a consumer installing the
    // half-defaults and a pppoe session swapping the default cannot both own
    // the host's routing, whatever devices they open.
    #[test]
    fn the_default_route_takes_one_holder() {
        let peers = peer_claims(&[consumer_slot("office", Some("zn0"), true)]);
        let claims = SlotClaims::new(peers).unwrap();
        let RunMode::Pppoe { name, config } = pppoe_mode("wan") else {
            unreachable!("pppoe_mode builds a pppoe body")
        };
        let mut swapping = (*config).clone();
        swapping.default_route = true;
        let err = claims
            .admit_body(
                RunMode::Pppoe {
                    name,
                    config: Arc::new(swapping),
                }
                .claims(),
            )
            .unwrap_err();
        assert!(err.contains("default route"), "{err}");
        // The same session without the default swap runs beside the consumer.
        claims.admit_body(pppoe_mode("wan").claims()).unwrap();
    }

    // An exit provider claims the tun its adapter opens, so a body naming that
    // device is refused the same way a segment provider's NIC refuses one.
    #[test]
    fn an_exit_provider_claims_the_tun_it_opens() {
        let claims = SlotClaims::new(peer_claims(&[exit_provider_slot("znx0")])).unwrap();
        let err = claims.admit_body(tap_body("znx0").claims()).unwrap_err();
        assert!(err.contains("znx0"), "{err}");
        assert!(err.contains("exit provider"), "{err}");
        claims.admit_body(tap_body("zn0").claims()).unwrap();
        // The host's routing stays free: the adapter masquerades rather than
        // programming default routes.
        assert!(!exit_provider_slot("znx0").default_route());
    }

    // Two peer slots naming one interface contend with each other, and the
    // refusal names both holders.
    #[test]
    fn two_peer_slots_cannot_name_one_interface() {
        let err = SlotClaims::new(peer_claims(&[
            consumer_slot("office", Some("eth1"), false),
            provider_slot(crate::proto::PROVIDES_SEGMENT, Some("eth1")),
        ]))
        .unwrap_err();
        assert!(err.contains("eth1"), "{err}");
        assert!(err.contains("consumer for office"), "{err}");
        assert!(err.contains("segment provider"), "{err}");
    }

    // Inbound frames fan out by slot identity: a consumer by the peer and
    // capability it asks for, a provider by its capability. A set holding the
    // same identity twice is unroutable, so it is refused.
    #[test]
    fn duplicate_slot_identities_are_refused() {
        let err = check_slot_identities(&[
            consumer_slot("office", None, false),
            consumer_slot("office", None, false),
        ])
        .unwrap_err();
        assert!(err.contains("office"), "{err}");
        check_slot_identities(&[
            consumer_slot("office", None, false),
            consumer_slot("depot", None, false),
        ])
        .unwrap();

        assert!(check_slot_identities(&[
            provider_slot(crate::proto::PROVIDES_EXIT, None),
            provider_slot(crate::proto::PROVIDES_EXIT, None),
        ])
        .is_err());
        check_slot_identities(&[
            provider_slot(crate::proto::PROVIDES_EXIT, None),
            provider_slot(crate::proto::PROVIDES_SEGMENT, Some("eth1")),
        ])
        .unwrap();
    }

    // Every slot's interface is named in config, so a contended set is
    // decidable before anything opens: startup fails instead of running with
    // a slot silently missing.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn boot_refuses_a_contended_slot_set() {
        let settings = ClientSettings {
            servers: vec![target("a")],
            tcp: vec![],
            udp: vec![],
            tap: Some(TapConfig {
                name: "eth1".into(),
                mtu: 1400,
                bridge: None,
            }),
            tun: None,
            pppoe: vec![],
            autostart: None,
            id_prefix: Some("t".into()),
            control: None,
            config: None,
            peers: vec![provider_slot(crate::proto::PROVIDES_SEGMENT, Some("eth1"))],
            peer_sessions: None,
        };
        let err = run_switchable(ActiveTarget::new(target("a")), settings)
            .await
            .expect_err("a contended slot set must fail startup")
            .to_string();
        assert!(err.contains("eth1"), "{err}");
    }

    // A path that completes the TCP handshake but never sends Noise msg2 must
    // not park the initiator on the kernel read; connect_and_handshake has to
    // give up at its timeout, not the multi-minute retransmit window.
    #[tokio::test(start_paused = true)]
    async fn handshake_blackhole_times_out() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Accept and hold the connection open without ever writing msg2.
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(sock);
        });

        let res = connect_and_handshake(&addr, &[0u8; 32], OPEN_HANDSHAKE_TIMEOUT).await;
        assert!(res.is_err(), "expected timeout error, got Ok");
    }
}
