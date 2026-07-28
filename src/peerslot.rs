//! Peer session slots: the consumer and provider loops that run beside the
//! server slot, and the per-client control handle they pair through.
//!
//! A consumer slot asks the server for a session to one peer and capability
//! and drives the pairing it answers with; a provider slot never initiates and
//! serves whatever pairs the server forms against its announced bit. Both end
//! at an inner session over the path the pair settled on, direct or relayed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};

use crate::client::{
    probe_candidates, relay_leg_dgram, relay_leg_stream, AbortOnDrop, Backoff, ProbeSession,
};
use crate::kcp::Session;
use crate::peer::{PeerPath, PeerSession};
use crate::proto::{Msg, PathStatus, PeerStatus, PROVIDES_EXIT, PROVIDES_SEGMENT};
use crate::punch::{punch, PunchOutcome};
use crate::Result;

/// Bound on one cycle, from the `PeerConnect` or the `PeerProbe` that starts it
/// to the completed inner handshake. The server stops sending a pair's frames
/// the moment it invalidates the pair, and no message says so, so a slot whose
/// counterpart vanishes mid-pairing would otherwise wait forever. It exceeds
/// the sum of the four stages a cycle waits on, which a relayed pairing can
/// spend in full: the server's pairing deadline, the punch deadline, the relay
/// leg's connect and handshake, and the inner handshake. So it fires only when
/// a stage stalls with nothing behind it.
pub const CYCLE_DEADLINE: Duration = Duration::from_secs(50);

/// Control frames one slot queues before a further arrival is dropped. A cycle
/// has at most a handful in flight, and a dropped frame stalls that cycle until
/// the deadline rather than corrupting anything.
const SLOT_QUEUE: usize = 16;

/// Frames queued in each direction between a live slot and its owner.
const FRAME_QUEUE: usize = 64;

/// What a provider seals into message two when its exclusive slot already
/// serves a pair.
const REFUSE_BUSY: &[u8] = b"already serving a pair";

/// How long a refused pair holds its path open after sealing the answer. The
/// refusal rides message two, and dropping the path as that frame is written
/// takes the frame down with it on a relayed pair, where the splice ends the
/// moment either leg does. Holding lets the answer land, and lets a consumer
/// that lost it repeat its message one and be answered again.
const REFUSAL_LINGER: Duration = Duration::from_secs(2);

/// The live control session as a peer slot sees it: the frame sender, what a
/// probe socket and a relay leg need to reach the server, and the psk of the
/// profile the pairing is keyed by.
#[derive(Clone)]
pub struct ControlSession {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub server: String,
    pub psk: [u8; 32],
    /// The KCP session under a udp control channel. `None` on tcp, where the
    /// party never probes and opens its relay leg as a fresh connection.
    pub sess: Option<Arc<Session>>,
}

#[derive(Clone, Default)]
struct Live {
    generation: u64,
    session: Option<ControlSession>,
}

/// Inbound peer frames by the id they name: `PeerResult` by the peer and
/// capability its `PeerConnect` asked for, everything else by `pair_id`. A
/// `pair_id` nothing has claimed belongs to the provider slot the `PeerProbe`
/// naming it announces for.
#[derive(Default)]
struct Routes {
    results: HashMap<(String, u8), mpsc::Sender<Msg>>,
    providers: HashMap<u8, mpsc::Sender<Msg>>,
    pairs: HashMap<u64, mpsc::Sender<Msg>>,
}

struct Inner {
    live: watch::Sender<Live>,
    routes: Mutex<Routes>,
}

/// The one handle peer slots reach the server through. The control session is
/// built inside the session body task and dies with it while the slot loops
/// outlive it, so the live session sits here behind a generation the loop
/// bumps at every bringup and teardown: a slot scopes its cycle to the
/// generation its `PeerConnect` went out on, and a slot with no live session
/// waits on the cell.
#[derive(Clone)]
pub struct PeerControl {
    inner: Arc<Inner>,
}

impl Default for PeerControl {
    fn default() -> Self {
        PeerControl {
            inner: Arc::new(Inner {
                live: watch::Sender::new(Live::default()),
                routes: Mutex::new(Routes::default()),
            }),
        }
    }
}

impl PeerControl {
    /// Publish `session` as the live control session and bump the generation.
    /// Dropping the returned guard bumps it again with no session, which is a
    /// cycle failure for every slot that has not settled on a punched path.
    pub fn install(&self, session: ControlSession) -> ControlGuard {
        self.inner.routes.lock().unwrap().pairs.clear();
        self.inner.live.send_modify(|l| {
            l.generation += 1;
            l.session = Some(session);
        });
        ControlGuard {
            control: self.clone(),
        }
    }

    /// The live control session and its generation, waiting until one exists.
    async fn wait_live(&self) -> (u64, ControlSession) {
        let mut rx = self.inner.live.subscribe();
        loop {
            {
                let live = rx.borrow_and_update();
                if let Some(session) = &live.session {
                    return (live.generation, session.clone());
                }
            }
            // The sender lives in the same `Inner` this receiver holds, so
            // the wait only ends on a real change.
            let _ = rx.changed().await;
        }
    }

    /// The live control session and its generation, or `None` while none is up.
    fn live(&self) -> Option<(u64, ControlSession)> {
        let live = self.inner.live.borrow();
        live.session.clone().map(|s| (live.generation, s))
    }

    /// Resolves once the control session is no longer the one `generation`
    /// names.
    async fn wait_gone(&self, generation: u64) {
        let mut rx = self.inner.live.subscribe();
        loop {
            let now = rx.borrow_and_update().generation;
            if now != generation {
                return;
            }
            let _ = rx.changed().await;
        }
    }

    /// Deliver one inbound peer frame to the slot it names.
    pub fn route(&self, msg: Msg) {
        let target = {
            let mut routes = self.inner.routes.lock().unwrap();
            match &msg {
                Msg::PeerResult {
                    peer_id,
                    want,
                    pair_id,
                    status,
                } => {
                    let tx = routes.results.get(&(peer_id.clone(), *want)).cloned();
                    // Binding the pair here rather than in the slot leaves no
                    // window for the pair's own frames to arrive first.
                    if let Some(tx) = &tx {
                        if *status == PeerStatus::Accepted && *pair_id != 0 {
                            routes.pairs.insert(*pair_id, tx.clone());
                        }
                    }
                    tx
                }
                Msg::PeerProbe {
                    pair_id, provides, ..
                } => match routes.pairs.get(pair_id).cloned() {
                    Some(tx) => Some(tx),
                    None => {
                        let tx = routes.providers.get(provides).cloned();
                        if let Some(tx) = &tx {
                            routes.pairs.insert(*pair_id, tx.clone());
                        }
                        tx
                    }
                },
                Msg::PeerInfo { pair_id, .. } | Msg::PeerRelayOpen { pair_id, .. } => {
                    routes.pairs.get(pair_id).cloned()
                }
                _ => None,
            }
        };
        if let Some(tx) = target {
            tx.try_send(msg).ok();
        }
    }

    fn register_consumer(&self, peer_id: &str, want: u8) -> (mpsc::Receiver<Msg>, RouteGuard) {
        let (tx, rx) = mpsc::channel(SLOT_QUEUE);
        self.inner
            .routes
            .lock()
            .unwrap()
            .results
            .insert((peer_id.to_string(), want), tx);
        (
            rx,
            RouteGuard {
                control: self.clone(),
                key: RouteKey::Result(peer_id.to_string(), want),
            },
        )
    }

    fn register_provider(&self, provides: u8) -> (mpsc::Receiver<Msg>, RouteGuard) {
        let (tx, rx) = mpsc::channel(SLOT_QUEUE);
        self.inner
            .routes
            .lock()
            .unwrap()
            .providers
            .insert(provides, tx);
        (
            rx,
            RouteGuard {
                control: self.clone(),
                key: RouteKey::Provider(provides),
            },
        )
    }

    /// Hold the pair binding the router installed for as long as the cycle
    /// that owns the pair runs.
    fn pair_guard(&self, pair_id: u64) -> RouteGuard {
        RouteGuard {
            control: self.clone(),
            key: RouteKey::Pair(pair_id),
        }
    }
}

/// Publishes the live control session for as long as it is up.
pub struct ControlGuard {
    control: PeerControl,
}

impl Drop for ControlGuard {
    fn drop(&mut self) {
        self.control.inner.routes.lock().unwrap().pairs.clear();
        self.control.inner.live.send_modify(|l| {
            l.generation += 1;
            l.session = None;
        });
    }
}

enum RouteKey {
    Result(String, u8),
    Provider(u8),
    Pair(u64),
}

/// Removes one registry entry when the slot or cycle owning it ends.
struct RouteGuard {
    control: PeerControl,
    key: RouteKey,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        let mut routes = self.control.inner.routes.lock().unwrap();
        match &self.key {
            RouteKey::Result(peer_id, want) => {
                routes.results.remove(&(peer_id.clone(), *want));
            }
            RouteKey::Provider(provides) => {
                routes.providers.remove(provides);
            }
            RouteKey::Pair(pair_id) => {
                routes.pairs.remove(pair_id);
            }
        }
    }
}

/// One configured peer slot: a consumer naming the peer and capability it
/// asks for, or a provider serving one capability to whatever pairs the
/// server forms.
#[derive(Clone)]
pub enum PeerSlotSpec {
    Consumer {
        peer_id: String,
        want: u8,
        /// The device the adapter riding this slot opens, when it opens one.
        device: Option<String>,
        /// Whether the slot programs the host's default routing.
        default_route: bool,
    },
    Provider {
        provides: u8,
        /// What this provider opens for the pairs it serves. Unset leaves the
        /// pairs to the frame seam, which is what the slot set's owner takes
        /// when it drives the sessions itself.
        adapter: Option<ProviderAdapter>,
    },
}

/// The device a provider opens for the pairs it serves, one per capability.
#[derive(Clone)]
pub enum ProviderAdapter {
    /// The tun and masquerade an exit provider runs for its one pair.
    Exit(PeerExit),
    /// The bridged TAP a segment provider attaches every consumer to.
    Segment(PeerSegment),
}

/// What an exit provider opens for the pair it serves.
#[derive(Clone)]
pub struct PeerExit {
    /// The tun device brought up on the provider's end of the pair's subnet.
    pub device: String,
    pub mtu: usize,
    /// Interface the pair's traffic masquerades out of; the host's
    /// default-route interface when unset.
    pub iface: Option<String>,
}

/// What a segment provider opens for the consumers it serves.
#[derive(Clone)]
pub struct PeerSegment {
    /// The TAP device the provider's switch reads and writes.
    pub device: String,
    pub mtu: usize,
    /// The bridge the TAP joins, which carries this node's L2 segment.
    pub bridge: String,
}

impl ProviderAdapter {
    /// What this provider can decide about its bringup with no pair in hand.
    fn precheck(&self) -> Result<()> {
        match self {
            ProviderAdapter::Exit(exit) => exit_precheck(exit),
            ProviderAdapter::Segment(segment) => segment_precheck(segment),
        }
    }

    /// The interfaces this adapter opens, which are the claims its slot holds.
    fn devices(&self) -> Vec<&str> {
        match self {
            ProviderAdapter::Exit(exit) => vec![&exit.device],
            ProviderAdapter::Segment(segment) => vec![&segment.device, &segment.bridge],
        }
    }

    /// How this adapter names itself in a log line.
    fn kind(&self) -> &'static str {
        match self {
            ProviderAdapter::Exit(_) => "exit",
            ProviderAdapter::Segment(_) => "segment",
        }
    }
}

impl PeerSlotSpec {
    /// How a claim refusal names this slot.
    pub fn label(&self) -> String {
        match self {
            PeerSlotSpec::Consumer { peer_id, want, .. } => {
                format!("the {} consumer for {peer_id}", provides_name(*want))
            }
            PeerSlotSpec::Provider { provides, .. } => {
                format!("the {} provider", provides_name(*provides))
            }
        }
    }

    /// The interfaces this slot opens, which are the claims it holds: a
    /// consumer's tun, an exit provider's tun, or a segment provider's TAP and
    /// the bridge it joins.
    pub fn devices(&self) -> Vec<&str> {
        match self {
            PeerSlotSpec::Consumer { device, .. } => device.as_deref().into_iter().collect(),
            PeerSlotSpec::Provider { adapter, .. } => adapter
                .as_ref()
                .map(ProviderAdapter::devices)
                .unwrap_or_default(),
        }
    }

    pub fn default_route(&self) -> bool {
        match self {
            PeerSlotSpec::Consumer { default_route, .. } => *default_route,
            PeerSlotSpec::Provider { .. } => false,
        }
    }

    /// The peer and capability that identify a consumer slot; `None` for a
    /// provider, which is identified by its capability alone.
    pub fn consumer_key(&self) -> Option<(&str, u8)> {
        match self {
            PeerSlotSpec::Consumer { peer_id, want, .. } => Some((peer_id, *want)),
            PeerSlotSpec::Provider { .. } => None,
        }
    }

    /// The provider bits this slot announces.
    pub fn provides(&self) -> u8 {
        match self {
            PeerSlotSpec::Consumer { .. } => 0,
            PeerSlotSpec::Provider { provides, .. } => *provides,
        }
    }
}

fn provides_name(bit: u8) -> &'static str {
    match bit {
        PROVIDES_EXIT => "exit",
        PROVIDES_SEGMENT => "segment",
        _ => "peer",
    }
}

/// A live slot's frames, handed to whoever owns the slot set: whole frames
/// from the peer out, whole frames to the peer in. The adapters that ride a
/// peer session take this seam; until then the frames are the owner's to move.
pub struct PeerSlotSession {
    /// The peer on the other end of the pair.
    pub peer_id: String,
    /// The capability the pair carries.
    pub want: u8,
    pub inbound: mpsc::Receiver<Vec<u8>>,
    pub outbound: mpsc::Sender<Vec<u8>>,
}

/// Where a slot hands its live session, or `None` when nothing rides it yet.
pub type SessionSink = Option<mpsc::Sender<PeerSlotSession>>;

/// Start every configured slot against `control`. The guards are the caller's
/// to abort and await: a profile switch ends every slot before the next set is
/// admitted, since the psk that pairs a slot belongs to the active profile, and
/// a slot never outlives the loop that started it.
pub(crate) fn spawn(
    specs: &[PeerSlotSpec],
    client_id: &str,
    secret: &str,
    control: &PeerControl,
    sink: &SessionSink,
) -> Vec<AbortOnDrop> {
    specs
        .iter()
        .map(|spec| {
            let client_id = client_id.to_string();
            let secret = secret.to_string();
            let control = control.clone();
            let sink = sink.clone();
            AbortOnDrop(match spec.clone() {
                PeerSlotSpec::Consumer { peer_id, want, .. } => {
                    tokio::spawn(consumer_slot(peer_id, want, client_id, control, sink))
                }
                PeerSlotSpec::Provider { provides, adapter } => tokio::spawn(provider_slot(
                    provides, adapter, secret, client_id, control, sink,
                )),
            })
        })
        .collect()
}

/// One consumer slot: ask for the peer and capability, follow the pair the
/// server forms, and hold the inner session until it dies. Every cycle short
/// of a completed inner handshake re-arms the backoff, and so does the pair
/// dying afterwards; there is no recovery inside a pair.
async fn consumer_slot(
    peer_id: String,
    want: u8,
    client_id: String,
    control: PeerControl,
    sink: SessionSink,
) {
    let (mut rx, _route) = control.register_consumer(&peer_id, want);
    let mut backoff = Backoff::default();
    loop {
        let (generation, session) = control.wait_live().await;
        let paired = {
            let cycle = pair_as_consumer(&peer_id, want, &client_id, &session, &mut rx, &control);
            tokio::select! {
                _ = control.wait_gone(generation) => Err("the control session ended".into()),
                r = timeout(CYCLE_DEADLINE, cycle) => match r {
                    Ok(r) => r,
                    Err(_) => Err("the pairing deadline lapsed".into()),
                },
            }
        };
        match paired {
            Ok(peer) => {
                backoff.reset();
                crate::elog!("peer {peer_id}: session up");
                run_session(peer, &peer_id, want, &sink).await;
                crate::elog!("peer {peer_id}: session ended");
            }
            Err(e) => {
                crate::elog!("peer {peer_id}: {e}");
                backoff.fail();
            }
        }
        sleep(backoff.delay()).await;
    }
}

/// Drive one consumer pairing to a live inner session: `PeerConnect`, the
/// `PeerResult` that answers it, the probe, the punch or the relay leg, and
/// the inner handshake as the initiator.
async fn pair_as_consumer(
    peer_id: &str,
    want: u8,
    client_id: &str,
    session: &ControlSession,
    rx: &mut mpsc::Receiver<Msg>,
    control: &PeerControl,
) -> Result<PeerSession> {
    // A frame the last cycle left behind names a pair the server has already
    // dropped, and reading it as this cycle's would follow a dead pair to the
    // deadline.
    while rx.try_recv().is_ok() {}
    session
        .tx
        .send(
            Msg::PeerConnect {
                peer_id: peer_id.to_string(),
                want,
            }
            .encode(),
        )
        .await
        .map_err(|_| -> crate::Error { "the control session ended".into() })?;

    let pair_id = loop {
        match next_frame(rx).await? {
            Msg::PeerResult {
                pair_id, status, ..
            } => match status {
                PeerStatus::Accepted => break pair_id,
                other => return Err(format!("the server refused the pair: {other:?}").into()),
            },
            _ => continue,
        }
    };
    // The binding lives as long as the cycle: the relay open stays
    // authoritative until the inner handshake completes.
    let _pair = control.pair_guard(pair_id);
    let settled = settle_path(pair_id, peer_id, client_id, session, rx).await?;
    let (peer, answer) =
        handshake_under_relay_authority(settled, Side::Consumer, pair_id, session, rx).await?;
    if !answer.is_empty() {
        return Err(format!(
            "the provider refused the pair: {}",
            String::from_utf8_lossy(&answer)
        )
        .into());
    }
    Ok(peer)
}

/// One provider slot: it never initiates. A pair reaches it as the
/// `PeerProbe` naming the peer and the capability, and every later frame for
/// that pair follows the binding the probe installed. A pair that dies takes
/// its own session down and, on an exit provider, the adapter this task was
/// running for it; on a segment provider, one switch port. Every other pair is
/// untouched.
///
/// A provider's adapter runs in this task rather than in the pair task that
/// handshaked it, so the devices it opens and the rules it installs are
/// released when this task ends. That is what a profile switch awaits before
/// the incoming slot set claims anything.
async fn provider_slot(
    provides: u8,
    adapter: Option<ProviderAdapter>,
    secret: String,
    client_id: String,
    control: PeerControl,
    sink: SessionSink,
) {
    let (mut rx, _route) = control.register_provider(provides);
    // Exit is exclusive: the slot serves one pair at a time and refuses a
    // second in its handshake answer, which is the only enforcement left once
    // a punched pair outlives the server-side state that fast-fails it. A
    // segment serves every pair at once and is never busy.
    let busy = Arc::new(AtomicBool::new(false));
    let mut pairs: HashMap<u64, mpsc::Sender<Msg>> = HashMap::new();
    let mut running: Vec<(u64, AbortOnDrop)> = Vec::new();
    // Where a pair hands its session over once the handshake settles. An
    // exclusive slot sees one at a time: the hold rides along, so a second is
    // refused before it has a session to hand over.
    let (served_tx, mut served_rx) = mpsc::channel::<ServedPair>(1);
    let owner = adapter.map(|adapter| AdapterOwner {
        served: served_tx,
        health: Arc::new(AdapterHealth::new(adapter.kind())),
        adapter,
        secret,
    });
    let mut exit_adapter: Option<ExitAdapter> = None;
    let mut segment = SegmentPorts::default();
    loop {
        let step = tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => SlotStep::Control(msg),
                None => break,
            },
            // The sender lives in `owner`, so a slot with no adapter has
            // nothing to listen for and a slot with one never sees the channel
            // close.
            served = served_rx.recv(), if owner.is_some() && exit_adapter.is_none() => match served {
                Some(served) => SlotStep::Serve(served),
                None => break,
            },
            _ = drive(&mut exit_adapter) => SlotStep::AdapterEnded,
            ended = segment.drive() => ended,
        };
        let msg = match step {
            SlotStep::Serve(served) => {
                if let Some(owner) = &owner {
                    serve_pair(owner, &mut exit_adapter, &mut segment, served);
                }
                continue;
            }
            SlotStep::AdapterEnded => {
                if let Some(done) = exit_adapter.take() {
                    crate::elog!("peer {}: exit pair ended", done.peer_id);
                }
                continue;
            }
            SlotStep::PortEnded(peer_id) => {
                crate::elog!("peer {peer_id}: segment port closed");
                continue;
            }
            SlotStep::DeviceEnded => {
                // The reader ends when the device stops reading, which is the
                // device dying and every port on it with it. Closing here
                // leaves the next pair to open a fresh one.
                crate::elog!("peer segment: the device stopped; its consumers are detached");
                segment.close();
                continue;
            }
            SlotStep::Control(msg) => msg,
        };
        running.retain(|(id, task)| {
            let live = !task.0.is_finished();
            if !live {
                pairs.remove(id);
            }
            live
        });
        match msg {
            Msg::PeerProbe {
                pair_id,
                ref peer_id,
                provides,
                ..
            } => {
                let Some((generation, session)) = control.live() else {
                    continue;
                };
                let (tx, pair_rx) = mpsc::channel(SLOT_QUEUE);
                let task = provider_pair(
                    PairStart {
                        pair_id,
                        peer_id: peer_id.clone(),
                        provides,
                        generation,
                    },
                    client_id.clone(),
                    session,
                    pair_rx,
                    control.pair_guard(pair_id),
                    control.clone(),
                    PairOwner {
                        sink: sink.clone(),
                        adapter: owner.clone(),
                    },
                    busy.clone(),
                );
                running.push((pair_id, AbortOnDrop(tokio::spawn(task))));
                // The probe frame starts the pair's own cycle, which binds its
                // socket and reports the candidates under the id it carries.
                tx.try_send(msg).ok();
                pairs.insert(pair_id, tx);
            }
            Msg::PeerInfo { pair_id, .. } | Msg::PeerRelayOpen { pair_id, .. } => {
                if let Some(tx) = pairs.get(&pair_id) {
                    tx.try_send(msg).ok();
                }
            }
            _ => {}
        }
    }
}

/// What moved the provider slot's loop forward.
enum SlotStep {
    Control(Msg),
    Serve(ServedPair),
    AdapterEnded,
    PortEnded(String),
    DeviceEnded,
}

/// A pair whose handshake settled, on its way from the pair task to the slot
/// task that runs its adapter. The exclusive hold rides along, so the slot
/// holds it for as long as it serves the pair.
struct ServedPair {
    peer_id: String,
    session: PeerSession,
    hold: Option<BusyGuard>,
}

/// Hand one settled pair to the adapter its slot runs. A segment that cannot
/// open its device drops the pair and holds the reason against the pairs that
/// follow, which is what the exit adapter's own bringup failure does.
fn serve_pair(
    owner: &AdapterOwner,
    exit_adapter: &mut Option<ExitAdapter>,
    segment: &mut SegmentPorts,
    served: ServedPair,
) {
    match &owner.adapter {
        ProviderAdapter::Exit(exit) => {
            crate::elog!("peer {}: exit pair up", served.peer_id);
            *exit_adapter = Some(ExitAdapter {
                peer_id: served.peer_id,
                run: Box::pin(run_exit(
                    served.session,
                    served.hold,
                    exit.clone(),
                    owner.secret.clone(),
                    owner.health.clone(),
                )),
            });
        }
        ProviderAdapter::Segment(cfg) => {
            match segment.attach(cfg, served.peer_id.clone(), served.session) {
                Ok(()) => crate::elog!("peer {}: segment port up", served.peer_id),
                Err(e) => {
                    owner.health.latch(e.to_string());
                }
            }
        }
    }
}

/// One pair's exit adapter: the peer it serves, and the future holding the
/// device it opened, the rules it installed, and the exclusive hold it took.
/// Run by the slot task, so the slot's own end is what releases all three.
struct ExitAdapter {
    peer_id: String,
    run: BoxedRun,
}

/// A running adapter or port, owned by the slot task that polls it.
type BoxedRun = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Poll the running adapter, or wait forever while the slot has none.
async fn drive(adapter: &mut Option<ExitAdapter>) {
    match adapter {
        Some(a) => a.run.as_mut().await,
        None => std::future::pending().await,
    }
}

/// A segment provider's open device and the port it holds for each pair it
/// serves. All of it lives on the slot task, so the slot's end closes every
/// port, the device, and the bridge port the device holds.
#[derive(Default)]
struct SegmentPorts {
    device: Option<OpenSegment>,
    ports: Vec<SegmentPort>,
}

/// The open device and the reader fanning its frames out to the ports.
struct OpenSegment {
    seg: SegmentDevice,
    reader: BoxedRun,
}

/// One consumer's port on the switch.
struct SegmentPort {
    peer_id: String,
    run: BoxedRun,
}

impl SegmentPorts {
    /// Attach one consumer, opening the device on the first pair that needs
    /// it. The device stays open for the slot's life, so the consumers that
    /// follow share one switch and one MAC table.
    fn attach(&mut self, cfg: &PeerSegment, peer_id: String, session: PeerSession) -> Result<()> {
        if self.device.is_none() {
            let seg = open_segment(cfg)?;
            self.device = Some(OpenSegment {
                reader: segment_reader(&seg),
                seg,
            });
        }
        self.add_port(peer_id, session)
    }

    /// Take one port on the open device for a consumer.
    fn add_port(&mut self, peer_id: String, session: PeerSession) -> Result<()> {
        let open = self.device.as_ref().expect("the device is open");
        self.ports.push(SegmentPort {
            peer_id,
            run: segment_attach(&open.seg, session)?,
        });
        Ok(())
    }

    /// Poll the device reader and every port, yielding whichever ended. A port
    /// that ends is removed and leaves the others running.
    async fn drive(&mut self) -> SlotStep {
        std::future::poll_fn(|cx| {
            if let Some(open) = &mut self.device {
                if open.reader.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(SlotStep::DeviceEnded);
                }
            }
            for i in 0..self.ports.len() {
                if self.ports[i].run.as_mut().poll(cx).is_ready() {
                    let done = self.ports.swap_remove(i);
                    return std::task::Poll::Ready(SlotStep::PortEnded(done.peer_id));
                }
            }
            std::task::Poll::Pending
        })
        .await
    }

    /// Drop every port and the device under them.
    fn close(&mut self) {
        self.ports.clear();
        self.device = None;
    }
}

/// A segment provider's open device. Off Linux there is none to open, so the
/// slot never holds one.
#[cfg(target_os = "linux")]
type SegmentDevice = crate::peersegment::Segment;
#[cfg(not(target_os = "linux"))]
type SegmentDevice = std::convert::Infallible;

/// What a segment provider off Linux answers every pair with.
#[cfg(not(target_os = "linux"))]
const NO_TAP_DEVICE: &str =
    "an l2 segment provider needs a tap device, which is only supported on Linux";

/// Open the TAP and join it to the configured bridge.
fn open_segment(cfg: &PeerSegment) -> Result<SegmentDevice> {
    #[cfg(target_os = "linux")]
    return crate::peersegment::open(cfg);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        Err(NO_TAP_DEVICE.into())
    }
}

/// The device's own half of the switch, which the slot polls for its life.
fn segment_reader(seg: &SegmentDevice) -> BoxedRun {
    #[cfg(target_os = "linux")]
    return Box::pin(seg.reader());
    #[cfg(not(target_os = "linux"))]
    match *seg {}
}

/// One consumer's port on the segment's switch.
fn segment_attach(seg: &SegmentDevice, session: PeerSession) -> Result<BoxedRun> {
    #[cfg(target_os = "linux")]
    return Ok(Box::pin(seg.attach(session)?));
    #[cfg(not(target_os = "linux"))]
    {
        let _ = session;
        match *seg {}
    }
}

/// Run the exit adapter over `session`, holding the exclusive slot for as long
/// as it lives. A bringup this provider cannot do is held against the pairs
/// that follow, so they are refused instead of served nothing.
async fn run_exit(
    session: PeerSession,
    _hold: Option<BusyGuard>,
    exit: PeerExit,
    secret: String,
    health: Arc<AdapterHealth>,
) {
    #[cfg(target_os = "linux")]
    if let Err(e) = crate::peerexit::serve(session, &exit, &secret).await {
        health.latch(e.to_string());
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (session, exit, secret, health);
}

/// Where a served pair goes: the adapter the slot runs, else the frame seam
/// whoever owns the slot set took.
struct PairOwner {
    sink: SessionSink,
    adapter: Option<AdapterOwner>,
}

/// What a pair needs to hand its session to the slot: the channel the slot
/// listens on, what the adapter opens, and the bringup state the slot carries
/// between pairs.
#[derive(Clone)]
struct AdapterOwner {
    served: mpsc::Sender<ServedPair>,
    adapter: ProviderAdapter,
    secret: String,
    health: Arc<AdapterHealth>,
}

/// A provider's bringup state. An adapter that cannot come up refuses the pair
/// rather than accepting it and hanging up: a completed handshake is a served
/// session to the consumer, which resets its backoff and re-pairs on the next
/// cycle for as long as the misconfiguration lasts.
struct AdapterHealth {
    /// How the log names this provider.
    kind: &'static str,
    held: Mutex<Option<String>>,
}

impl AdapterHealth {
    fn new(kind: &'static str) -> Self {
        AdapterHealth {
            kind,
            held: Mutex::new(None),
        }
    }

    /// The refusal this provider owes the pair it is about to answer. What the
    /// adapter can check without a pair decides it; a bringup that failed for a
    /// reason those checks cannot see refuses the next pair and then lets the
    /// one after it try again, so a transient failure recovers on its own.
    fn refusal(&self, adapter: &ProviderAdapter) -> Option<String> {
        match adapter.precheck() {
            Err(e) => Some(self.latch(e.to_string())),
            Ok(()) => self.held.lock().unwrap().take(),
        }
    }

    /// Record a bringup failure, naming the cause the first time it appears so
    /// a misconfiguration says why once rather than once per pair.
    fn latch(&self, reason: String) -> String {
        let mut held = self.held.lock().unwrap();
        if held.as_deref() != Some(reason.as_str()) {
            crate::elog!("peer {}: {reason}", self.kind);
        }
        *held = Some(reason.clone());
        reason
    }
}

/// What an exit provider can decide about its bringup with no pair in hand.
fn exit_precheck(exit: &PeerExit) -> Result<()> {
    #[cfg(target_os = "linux")]
    return crate::peerexit::precheck(exit);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = exit;
        Ok(())
    }
}

/// What a segment provider can decide about its bringup with no pair in hand.
fn segment_precheck(segment: &PeerSegment) -> Result<()> {
    #[cfg(target_os = "linux")]
    return crate::peersegment::precheck(segment);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = segment;
        Err(NO_TAP_DEVICE.into())
    }
}

/// What a `PeerProbe` tells a provider about the pair it starts.
struct PairStart {
    pair_id: u64,
    peer_id: String,
    provides: u8,
    generation: u64,
}

/// Serve one pair on a provider slot: probe, take the path the punch or the
/// relay authority hands it, answer the inner handshake, and hold the session
/// until it dies.
#[allow(clippy::too_many_arguments)]
async fn provider_pair(
    start: PairStart,
    client_id: String,
    session: ControlSession,
    mut rx: mpsc::Receiver<Msg>,
    _pair: RouteGuard,
    control: PeerControl,
    owner: PairOwner,
    busy: Arc<AtomicBool>,
) {
    let PairStart {
        pair_id,
        peer_id,
        provides,
        generation,
    } = start;
    let exclusive = provides == PROVIDES_EXIT;
    let served: Result<Served> = {
        let cycle = async {
            let settled = settle_path(pair_id, &peer_id, &client_id, &session, &mut rx).await?;
            // An adapter that cannot come up refuses before it takes the slot,
            // so a provider stuck on its own config never reads as busy.
            let broken = owner
                .adapter
                .as_ref()
                .and_then(|owner| owner.health.refusal(&owner.adapter))
                .map(String::into_bytes);
            // The slot is taken here rather than at the pair's start, so two
            // pairs settling at once cannot both be served: the loser's
            // refusal rides the message two it is about to seal.
            let hold = if exclusive && broken.is_none() {
                BusyGuard::take(&busy)
            } else {
                None
            };
            let refuse = match broken {
                Some(reason) => reason,
                None if exclusive && hold.is_none() => REFUSE_BUSY.to_vec(),
                None => Vec::new(),
            };
            let (peer, _) = handshake_under_relay_authority(
                settled,
                Side::Provider(&refuse),
                pair_id,
                &session,
                &mut rx,
            )
            .await?;
            Ok(if refuse.is_empty() {
                Served::Taken(peer, hold)
            } else {
                Served::Refused(String::from_utf8_lossy(&refuse).into_owned(), peer)
            })
        };
        tokio::select! {
            _ = control.wait_gone(generation) => Err("the control session ended".into()),
            r = timeout(CYCLE_DEADLINE, cycle) => match r {
                Ok(r) => r,
                Err(_) => Err("the pairing deadline lapsed".into()),
            },
        }
    };
    match served {
        Ok(Served::Taken(peer, hold)) => match &owner.adapter {
            // The adapter runs on the slot task, and the hold rides with it,
            // so this task is done the moment it has handed both over.
            Some(adapter) => {
                adapter
                    .served
                    .send(ServedPair {
                        peer_id,
                        session: peer,
                        hold,
                    })
                    .await
                    .ok();
            }
            None => {
                let bit = provides_name(provides);
                crate::elog!("peer {peer_id}: {bit} pair up");
                run_session(peer, &peer_id, provides, &owner.sink).await;
                crate::elog!("peer {peer_id}: {bit} pair ended");
            }
        },
        Ok(Served::Refused(reason, mut peer)) => {
            crate::elog!("peer pair {pair_id}: refused, {reason}");
            timeout(REFUSAL_LINGER, async {
                while peer.recv().await.is_some() {}
            })
            .await
            .ok();
        }
        Err(e) => crate::elog!("peer pair {pair_id}: {e}"),
    }
}

/// What a provider slot did with one pair.
enum Served {
    /// The pair is served; the hold keeps an exclusive slot taken until the
    /// session ends, however the pair task exits.
    Taken(PeerSession, Option<BusyGuard>),
    /// The slot could not take the pair; the reason rode message two, and the
    /// session is held open long enough for it to land.
    Refused(String, PeerSession),
}

/// Holds an exclusive provider slot for one pair.
struct BusyGuard(Arc<AtomicBool>);

impl BusyGuard {
    /// Take the slot, or `None` when another pair holds it.
    fn take(busy: &Arc<AtomicBool>) -> Option<Self> {
        (!busy.swap(true, Ordering::Relaxed)).then(|| BusyGuard(busy.clone()))
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Take this party from its `PeerProbe` to a path: bind the probe socket and
/// report the local candidate, punch every candidate the pair's `PeerInfo`
/// carried, and settle on the relay leg when the authority arrives. The relay
/// open is authoritative, so its delivery drops the punch future whatever the
/// punch was doing, taking the in-flight handshakes and the probe socket with
/// it.
async fn settle_path(
    pair_id: u64,
    peer_id: &str,
    client_id: &str,
    session: &ControlSession,
    rx: &mut mpsc::Receiver<Msg>,
) -> Result<SettledPath> {
    let mut probe: Option<ProbeSession> = None;
    let candidates = loop {
        match next_frame(rx).await? {
            // A tcp control transport never probes: the frame is the pair
            // notification alone, and the server has already settled this
            // party relay-only.
            Msg::PeerProbe {
                pair_id: got,
                probe_id,
                ..
            } if got == pair_id => {
                if let Some(server) = udp_server(session)? {
                    probe = Some(probe_candidates(server, &session.psk, probe_id).await?);
                }
            }
            Msg::PeerInfo {
                pair_id: got,
                candidates,
            } if got == pair_id => break candidates,
            _ => continue,
        }
    };

    let settled = match probe {
        Some(probe) => {
            let punching = punch(
                probe,
                &candidates,
                pair_id,
                client_id,
                peer_id,
                &session.psk,
                &session.tx,
            );
            tokio::select! {
                outcome = punching => Settled::Punched(outcome),
                id = wait_relay_open(rx, pair_id) => Settled::Relay(id?),
            }
        }
        None => {
            session
                .tx
                .try_send(
                    Msg::PeerPath {
                        pair_id,
                        status: PathStatus::Relay,
                    }
                    .encode(),
                )
                .ok();
            Settled::Relay(wait_relay_open(rx, pair_id).await?)
        }
    };
    let leg_id = match settled {
        Settled::Punched(PunchOutcome::Direct(link)) => {
            return Ok(SettledPath::Direct(PeerPath::direct(link)))
        }
        Settled::Punched(PunchOutcome::Relay) => wait_relay_open(rx, pair_id).await?,
        Settled::Relay(id) => id,
    };
    Ok(SettledPath::Relayed(open_leg(session, leg_id).await?))
}

/// This party's relay leg, on the channel its control transport carries.
async fn open_leg(session: &ControlSession, leg_id: u64) -> Result<PeerPath> {
    match &session.sess {
        Some(sess) => Ok(PeerPath::relay_dgram(
            relay_leg_dgram(sess, &session.psk, leg_id).await?,
        )),
        None => Ok(PeerPath::relay_stream(
            relay_leg_stream(&session.server, &session.psk, leg_id).await?,
        )),
    }
}

/// Run the inner handshake over the settled path, with the pair's relay open
/// still authoritative. The server opens the relay off whichever party reports
/// it first, so a party whose punch authenticated in the last milliseconds
/// before its peer's deadline holds a direct path the peer has already
/// abandoned; the open reaches it here, drops that path, and the handshake
/// runs over the leg instead. A pair already on the relay gets no second open.
async fn handshake_under_relay_authority(
    settled: SettledPath,
    side: Side<'_>,
    pair_id: u64,
    session: &ControlSession,
    rx: &mut mpsc::Receiver<Msg>,
) -> Result<(PeerSession, Vec<u8>)> {
    let direct = match settled {
        SettledPath::Relayed(path) => {
            return inner_handshake(side, path, &session.psk, pair_id).await
        }
        SettledPath::Direct(path) => path,
    };
    let raced = tokio::select! {
        r = inner_handshake(side, direct, &session.psk, pair_id) => Raced::Handshake(r),
        id = wait_relay_open(rx, pair_id) => Raced::Relay(id?),
    };
    match raced {
        Raced::Handshake(r) => r,
        // The direct path went down with the losing future above.
        Raced::Relay(leg_id) => {
            let leg = open_leg(session, leg_id).await?;
            inner_handshake(side, leg, &session.psk, pair_id).await
        }
    }
}

/// The inner handshake for this party's end of the pair, with the provider's
/// message-two payload either read or sealed.
async fn inner_handshake(
    side: Side<'_>,
    path: PeerPath,
    psk: &[u8; 32],
    pair_id: u64,
) -> Result<(PeerSession, Vec<u8>)> {
    match side {
        Side::Consumer => PeerSession::consumer(path, psk, pair_id).await,
        Side::Provider(refuse) => Ok((
            PeerSession::provider(path, psk, pair_id, refuse).await?,
            Vec::new(),
        )),
    }
}

/// Which end of the pair a slot runs, and what a provider answers with.
#[derive(Clone, Copy)]
enum Side<'a> {
    Consumer,
    Provider(&'a [u8]),
}

/// Which way a pair settled before its leg is opened.
enum Settled {
    Punched(PunchOutcome),
    Relay(u64),
}

/// The path a pairing settled on, and whether a relay open can still supersede
/// it.
enum SettledPath {
    Direct(PeerPath),
    Relayed(PeerPath),
}

/// Which of the inner handshake and the relay open landed first.
enum Raced {
    Handshake(Result<(PeerSession, Vec<u8>)>),
    Relay(u64),
}

/// The server's udp control address, or `None` when this party's control
/// session runs over tcp and therefore never probes.
fn udp_server(session: &ControlSession) -> Result<Option<SocketAddr>> {
    if session.sess.is_none() {
        return Ok(None);
    }
    let addr = session
        .server
        .parse()
        .map_err(|_| -> crate::Error { "the udp control address is not an ip:port".into() })?;
    Ok(Some(addr))
}

/// The leg id this party's `PeerRelayOpen` carries for `pair_id`.
async fn wait_relay_open(rx: &mut mpsc::Receiver<Msg>, pair_id: u64) -> Result<u64> {
    loop {
        if let Msg::PeerRelayOpen { pair_id: got, id } = next_frame(rx).await? {
            if got == pair_id {
                return Ok(id);
            }
        }
    }
}

async fn next_frame(rx: &mut mpsc::Receiver<Msg>) -> Result<Msg> {
    rx.recv()
        .await
        .ok_or_else(|| -> crate::Error { "the slot's control route closed".into() })
}

/// Hold a live session, moving frames to and from whoever owns the slot.
/// With no owner the session just runs, which is what a slot whose adapter has
/// not landed does: the pair stays up and its keepalive decides when it dies.
async fn run_session(mut peer: PeerSession, peer_id: &str, want: u8, sink: &SessionSink) {
    let Some(sink) = sink else {
        while peer.recv().await.is_some() {}
        return;
    };
    let (inbound_tx, inbound) = mpsc::channel(FRAME_QUEUE);
    let (outbound, mut outbound_rx) = mpsc::channel(FRAME_QUEUE);
    let handed = sink
        .send(PeerSlotSession {
            peer_id: peer_id.to_string(),
            want,
            inbound,
            outbound,
        })
        .await;
    if handed.is_err() {
        return;
    }
    loop {
        // The borrow of the session ends with this statement, so the send
        // below is free to take it again.
        let step = tokio::select! {
            frame = peer.recv() => Step::Inbound(frame),
            frame = outbound_rx.recv() => Step::Outbound(frame),
        };
        match step {
            Step::Inbound(Some(frame)) => {
                if inbound_tx.send(frame).await.is_err() {
                    break;
                }
            }
            Step::Outbound(Some(frame)) => {
                if peer.send(&frame).await.is_err() {
                    break;
                }
            }
            Step::Inbound(None) | Step::Outbound(None) => break,
        }
    }
}

enum Step {
    Inbound(Option<Vec<u8>>),
    Outbound(Option<Vec<u8>>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_session(tx: mpsc::Sender<Vec<u8>>) -> ControlSession {
        ControlSession {
            tx,
            server: "127.0.0.1:1".into(),
            psk: [7u8; 32],
            sess: None,
        }
    }

    /// The peer named by the next `PeerConnect` the slot sends.
    async fn next_connect(rx: &mut mpsc::Receiver<Vec<u8>>) -> String {
        loop {
            let frame = rx.recv().await.expect("the slot stopped asking");
            if let Ok(Msg::PeerConnect { peer_id, .. }) = Msg::decode(&frame) {
                return peer_id;
            }
        }
    }

    // A counterpart that vanishes mid-pairing leaves the slot waiting on
    // frames the server stopped sending when it invalidated the pair, and no
    // message says so. The cycle deadline ends the wait and the backoff
    // re-arms, so the slot asks again instead of hanging with its pair state
    // held.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_pairing_ends_at_the_cycle_deadline() {
        let control = PeerControl::default();
        let (tx, mut sent) = mpsc::channel(8);
        let _live = control.install(control_session(tx));
        let slot = AbortOnDrop(tokio::spawn(consumer_slot(
            "prov".into(),
            PROVIDES_EXIT,
            "c".into(),
            control.clone(),
            None,
        )));

        let asked = timeout(CYCLE_DEADLINE, next_connect(&mut sent))
            .await
            .expect("the slot never asked");
        assert_eq!(asked, "prov");
        // The server accepts the pair and then goes silent: no `PeerProbe`
        // ever follows.
        control.route(Msg::PeerResult {
            peer_id: "prov".into(),
            want: PROVIDES_EXIT,
            pair_id: 9,
            status: PeerStatus::Accepted,
        });

        let again = timeout(CYCLE_DEADLINE * 2, next_connect(&mut sent))
            .await
            .expect("the slot never re-armed after the deadline");
        assert_eq!(again, "prov");
        drop(slot);
    }

    // An adapter that cannot come up refuses the pair, and the refusal
    // outlives it: every pair that follows reads the same reason off the
    // checks a provider can run without one. A failure those checks cannot
    // see is handed to one pair and then cleared, so the pair after it tries
    // the bringup again.
    #[test]
    fn a_provider_that_cannot_bring_its_adapter_up_refuses_every_pair() {
        let exit = ProviderAdapter::Exit(PeerExit {
            device: "znx0".into(),
            mtu: 1400,
            // Masquerading onto the tun the pair itself rides is a bringup no
            // pair can make work, and it reads the same on every call.
            iface: Some("znx0".into()),
        });
        let health = AdapterHealth::new(exit.kind());
        let first = health.refusal(&exit).expect("a standing failure refuses");
        assert!(first.contains("znx0"), "{first}");
        assert_eq!(health.refusal(&exit), Some(first));

        // A segment provider answers off the same latch, over the bringup its
        // own precheck decides: a bridge no interface answers to.
        #[cfg(target_os = "linux")]
        {
            let segment = ProviderAdapter::Segment(PeerSegment {
                device: "zns0".into(),
                mtu: 1400,
                bridge: "zeronat-no-such-bridge".into(),
            });
            let health = AdapterHealth::new(segment.kind());
            let refused = health
                .refusal(&segment)
                .expect("a standing failure refuses");
            assert!(refused.contains("zeronat-no-such-bridge"), "{refused}");
            assert_eq!(health.refusal(&segment), Some(refused));
        }

        // The held reason is what the log speaks on, so repeating it says
        // nothing new; the next pair takes it and leaves the state clear.
        let health = AdapterHealth::new("exit");
        let busy = "the device is busy".to_string();
        assert_eq!(health.latch(busy.clone()), busy);
        assert_eq!(health.latch(busy.clone()), busy);
        assert_eq!(health.held.lock().unwrap().take(), Some(busy));
        assert!(health.held.lock().unwrap().is_none());
    }

    // A segment provider holds one port per pair on one switch. A pair that
    // dies takes its own port and nothing else, and the slot names the peer
    // whose port went; closing the slot drops the ports and the device under
    // them.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_segment_slot_loses_one_port_per_dead_pair() {
        // The device is injected, so the ports open no kernel tap.
        let (seg, dev_fd) = crate::peersegment::Segment::for_test();
        let mut segment = SegmentPorts {
            device: Some(OpenSegment {
                reader: segment_reader(&seg),
                seg,
            }),
            ports: Vec::new(),
        };
        let (a, a_provider) = crate::peer::duplex_pair("segment slot", 1).await;
        let (b, b_provider) = crate::peer::duplex_pair("segment slot", 2).await;
        segment.add_port("a".into(), a_provider).unwrap();
        segment.add_port("b".into(), b_provider).unwrap();

        drop(a);
        let ended = timeout(Duration::from_secs(20), segment.drive())
            .await
            .expect("the dead pair's port never ended");
        assert!(
            matches!(&ended, SlotStep::PortEnded(peer) if peer == "a"),
            "the slot named the wrong port"
        );
        assert_eq!(segment.ports.len(), 1);
        assert_eq!(segment.ports[0].peer_id, "b");

        segment.close();
        assert!(segment.device.is_none());
        drop(b);
        unsafe { libc::close(dev_fd) };
    }

    // A provider with no adapter hands no session to its slot task, and the
    // slot must not read the silent handoff as its own control route closing:
    // it stays registered and keeps taking pairs.
    #[tokio::test]
    async fn a_provider_without_an_adapter_keeps_its_slot_open() {
        let control = PeerControl::default();
        let (tx, _sent) = mpsc::channel(8);
        let _live = control.install(control_session(tx));
        let slot = AbortOnDrop(tokio::spawn(provider_slot(
            PROVIDES_EXIT,
            None,
            "secret".into(),
            "prov".into(),
            control.clone(),
            None,
        )));

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(!slot.0.is_finished(), "the slot stopped serving");
        assert!(control
            .inner
            .routes
            .lock()
            .unwrap()
            .providers
            .contains_key(&PROVIDES_EXIT));
        drop(slot);
    }

    // A refused status ends the cycle at once rather than at the deadline:
    // every reason describes a peer that can be there on the next attempt.
    #[tokio::test(start_paused = true)]
    async fn a_refused_result_re_arms_the_slot() {
        let control = PeerControl::default();
        let (tx, mut sent) = mpsc::channel(8);
        let _live = control.install(control_session(tx));
        let slot = AbortOnDrop(tokio::spawn(consumer_slot(
            "prov".into(),
            PROVIDES_EXIT,
            "c".into(),
            control.clone(),
            None,
        )));

        for _ in 0..2 {
            let asked = timeout(CYCLE_DEADLINE, next_connect(&mut sent))
                .await
                .expect("the slot never asked");
            assert_eq!(asked, "prov");
            control.route(Msg::PeerResult {
                peer_id: "prov".into(),
                want: PROVIDES_EXIT,
                pair_id: 0,
                status: PeerStatus::PeerBusy,
            });
        }
        drop(slot);
    }
}
