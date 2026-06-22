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
use crate::dgram::{DgramRx, DgramTx};
use crate::kcp::{route, session, Accepted, Session};
#[cfg(target_os = "linux")]
use crate::kcp::{BRIDGE_CONV, BRIDGE_ID};
#[cfg(target_os = "linux")]
use crate::netfilter;
use crate::noise::{server_handshake, server_handshake_stateless, Noise, StatelessNoise};
#[cfg(target_os = "linux")]
use crate::proto::BridgeEntry;
use crate::proto::{
    proto_name, ClientEntry, Listener, Msg, Proto, RouteEntry, SnapshotBody, Source,
};
use crate::tap::{TapConfig, TunConfig};
#[cfg(target_os = "linux")]
use crate::tap::TapDevice;

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
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

/// A connected client's control channel and the transport it arrived on. Cloned
/// out of the registry per public connection so a `try_send` never holds a lock.
#[derive(Clone)]
struct ClientHandle {
    tx: mpsc::Sender<Vec<u8>>,
    transport: ActiveTransport,
}

/// A running listener's teardown handles: `cancel` stops the accept/recv loop and
/// `bridges` collects active TCP bridge tasks so they can be aborted on removal.
/// `source` records where the listener came from; `cli_locked` marks a listener
/// pinned by a CLI arg, which admin may not remove and which persists as `File`
/// only when it is also declared in the config file.
struct ListenerHandle {
    cancel: Arc<Notify>,
    bridges: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
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

/// A parked public UDP source, the public socket its replies must go out on, and
/// the channel carrying its inbound datagrams, awaiting the matching UDP-forward
/// setup conv.
type UdpPending = (Arc<UdpSocket>, SocketAddr, mpsc::Receiver<Vec<u8>>);

pub(crate) struct Server {
    psk: [u8; 32],
    server_id: String,
    next_id: Mutex<u64>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Noise>>>,
    udp_pending: Mutex<HashMap<u64, UdpPending>>,
    clients: Mutex<HashMap<String, ClientHandle>>,
    routes: Mutex<HashMap<RouteKey, Route>>,
    listeners: Mutex<HashMap<RouteKey, ListenerHandle>>,
    handshakes: Arc<Semaphore>,
    /// Config file backing this server, or `None` for a runtime-only node that
    /// never writes. `file_id`/`file_control` preserve the loaded `[server]`
    /// verbatim so an auto-save never bakes CLI-sourced identity into the file.
    config_path: Option<PathBuf>,
    file_id: Option<String>,
    file_control: Option<String>,
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

    /// Resolve a public listener key to the client that should serve it. An
    /// explicit route wins; with no route and exactly one connected client, that
    /// client is the implicit target (single-client deployments need no route).
    /// Locks are taken and dropped one at a time, never across a `try_send`.
    fn route_to(&self, key: RouteKey) -> Option<ClientHandle> {
        let routed_id = self
            .routes
            .lock()
            .unwrap()
            .get(&key)
            .map(|r| r.client_id.clone());
        if let Some(id) = routed_id {
            return self.clients.lock().unwrap().get(&id).cloned();
        }
        let clients = self.clients.lock().unwrap();
        if clients.len() == 1 {
            clients.values().next().cloned()
        } else {
            None
        }
    }

    /// Register a new public stream against the routed client, notify it, and
    /// return the channel that will receive the matching data connection. `None`
    /// if no client serves this key. The `try_send` runs outside every lock.
    fn open(
        &self,
        bind_ip: Ipv4Addr,
        proto: Proto,
        port: u16,
    ) -> Option<(u64, oneshot::Receiver<Noise>)> {
        let handle = self.route_to((bind_ip, proto, port))?;
        let id = self.next_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let msg = Msg::Open { proto, port, id }.encode();
        if handle.tx.try_send(msg).is_err() {
            self.pending.lock().unwrap().remove(&id);
            return None;
        }
        Some((id, rx))
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
/// is the NAT target. `subnet` is the tunnel network base.
pub struct ServerTun {
    pub device: TunConfig,
    pub subnet: Ipv4Addr,
    pub client_ip: Ipv4Addr,
    pub except: Vec<u16>,
}

/// Everything the server needs to boot. `config_path` is the file to auto-save
/// mutations into, or `None` for a runtime-only node. `file_id`/`file_control`
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
        let dev = Arc::new(TapDevice::open_tun(&st.device)?);
        let plan = netfilter::NatPlan {
            iface: st.device.name.clone(),
            subnet: st.subnet,
            prefix_len: st.device.prefix_len,
            server_ip: st.device.addr,
            client_ip: st.client_ip,
            control_port,
            mtu: st.device.mtu,
            except: st.except.clone(),
        };
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
                    },
                )
            };
            if superseded.is_some() {
                crate::elog!("client {client_id} reconnected, superseding previous session");
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
                if let Ok(Msg::Ping) = Msg::decode(&bytes) {
                    tx.try_send(Msg::Pong.encode()).ok();
                }
            }
            // Remove this client only if the registry still points at this
            // session's channel. A superseding session overwrote the entry, so its
            // tx no longer matches and this teardown is a no-op; the new session's
            // slot is preserved. A superseded reader runs this same no-op once it
            // times out, which is why the stale reader is left to self-reap.
            {
                let mut clients = srv.clients.lock().unwrap();
                if clients
                    .get(&client_id)
                    .is_some_and(|h| h.tx.same_channel(&tx))
                {
                    clients.remove(&client_id);
                }
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
                    crate::elog!("admin connected (snapshot)");
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
                .map(|(id, h)| ClientEntry {
                    client_id: id.clone(),
                    transport: transport_byte(h.transport),
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
        let bridge_clients = self
            .switch
            .as_ref()
            .map(|sw| {
                sw.ports_snapshot()
                    .into_iter()
                    .map(|p| {
                        let named = p.name.as_ref().is_some_and(|s| !s.is_empty());
                        let label = p.name.filter(|s| !s.is_empty()).unwrap_or_else(|| match p.peer
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
            srv.routes.lock().unwrap().insert(
                (bind_ip, proto, port),
                Route {
                    client_id,
                    source: mutation_source,
                },
            );
            save_after_mutation(srv).await
        }
        Msg::ClearRoute {
            bind_ip,
            proto,
            port,
        } => {
            srv.routes.lock().unwrap().remove(&(bind_ip, proto, port));
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
                    source,
                    cli_locked,
                },
            );
            let srv = srv.clone();
            tokio::spawn(async move {
                udp_listener(srv, socket, bind_ip, port, cancel).await;
            });
        }
    }
    crate::elog!("listener added: {bind_ip} {} {port}", proto_name(proto));
    Ok(())
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
        let public = tokio::select! {
            _ = cancel.notified() => break,
            r = l.accept() => match r {
                Ok((public, _)) => public,
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
            let Some((id, rx)) = srv.open(bind_ip, Proto::Tcp, port) else {
                return;
            };
            match timeout(OPEN_TIMEOUT, rx).await {
                Ok(Ok((nr, nw))) => bridge::tcp(public, nr, nw).await,
                _ => {
                    srv.pending.lock().unwrap().remove(&id);
                }
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
/// sources (see `accept_udp_forward`'s teardown comment).
async fn udp_listener(
    srv: Arc<Server>,
    socket: Arc<UdpSocket>,
    bind_ip: Ipv4Addr,
    port: u16,
    cancel: Arc<Notify>,
) {
    // Each entry holds the bridge's inbound channel and the last time a datagram
    // reached it. A closed channel (bridge ended) or a stale TTL evicts the entry,
    // so a one-shot/vanished source cannot pin a dead Sender slot forever.
    let mut sessions: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
    let mut buf = [0u8; 65535];
    let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // A transient recv error must not kill the forwarded UDP port; log, back
        // off briefly, and keep serving. The sweep runs between recvs.
        let (n, src) = tokio::select! {
            _ = cancel.notified() => break,
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
                sessions.retain(|_, (tx, last)| {
                    !tx.is_closed() && now.duration_since(*last) < UDP_DATA_TTL
                });
                continue;
            }
        };
        let data = buf[..n].to_vec();

        // Route to an existing session; recover the datagram if it is dead.
        let data = if let Some((tx, last)) = sessions.get_mut(&src) {
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

        let (dtx, drx) = mpsc::channel::<Vec<u8>>(64);
        dtx.try_send(data).ok();
        sessions.insert(src, (dtx, Instant::now()));

        match handle.transport {
            ActiveTransport::Tcp => {
                let Some((id, rx)) = srv.open(bind_ip, Proto::Udp, port) else {
                    sessions.remove(&src);
                    continue;
                };
                let socket = socket.clone();
                let srv = srv.clone();
                tokio::spawn(async move {
                    match timeout(OPEN_TIMEOUT, rx).await {
                        Ok(Ok((nr, nw))) => bridge::udp_server(socket, src, drx, nr, nw).await,
                        _ => {
                            srv.pending.lock().unwrap().remove(&id);
                        }
                    }
                });
            }
            ActiveTransport::Udp => {
                let id = srv.next_id();
                srv.udp_pending
                    .lock()
                    .unwrap()
                    .insert(id, (socket.clone(), src, drx));
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
                    let handshake =
                        timeout(HANDSHAKE_TIMEOUT, server_handshake_stateless(stream, &psk)).await;
                    drop(permit);
                    if let Ok(Ok((id, noise))) = handshake {
                        #[cfg(target_os = "linux")]
                        if conv == BRIDGE_CONV {
                            accept_bridge(srv, sess2, conv, noise, src).await;
                        } else {
                            accept_udp_forward(srv, sess2, conv, id, noise).await;
                        }
                        #[cfg(not(target_os = "linux"))]
                        accept_udp_forward(srv, sess2, conv, id, noise).await;
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
    let Some((public_socket, public_src, dgram_rx)) = take_udp_pending(&srv, id) else {
        return;
    };
    let noise = Arc::new(noise);
    // `_guard` keeps the session counted live for the whole bridge.
    let (inbound, _guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    crate::bridge::udp_server_stateless(public_socket, public_src, dgram_rx, rx, tx).await;
}

fn take_udp_pending(srv: &Server, id: u64) -> Option<UdpPending> {
    srv.udp_pending.lock().unwrap().remove(&id)
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

    fn test_server() -> Arc<Server> {
        Arc::new(Server {
            psk: crate::noise::derive_psk("test-secret"),
            server_id: "test".into(),
            next_id: Mutex::new(1),
            pending: Mutex::new(HashMap::new()),
            udp_pending: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            handshakes: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES)),
            config_path: None,
            file_id: None,
            file_control: None,
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
}
