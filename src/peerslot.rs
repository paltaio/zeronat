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
        /// The interface a segment provider bridges.
        device: Option<String>,
    },
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

    pub fn device(&self) -> Option<&str> {
        match self {
            PeerSlotSpec::Consumer { device, .. } | PeerSlotSpec::Provider { device, .. } => {
                device.as_deref()
            }
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
    control: &PeerControl,
    sink: &SessionSink,
) -> Vec<AbortOnDrop> {
    specs
        .iter()
        .map(|spec| {
            let client_id = client_id.to_string();
            let control = control.clone();
            let sink = sink.clone();
            AbortOnDrop(match spec.clone() {
                PeerSlotSpec::Consumer { peer_id, want, .. } => {
                    tokio::spawn(consumer_slot(peer_id, want, client_id, control, sink))
                }
                PeerSlotSpec::Provider { provides, .. } => {
                    tokio::spawn(provider_slot(provides, client_id, control, sink))
                }
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
/// its own session down and nothing else.
async fn provider_slot(provides: u8, client_id: String, control: PeerControl, sink: SessionSink) {
    let (mut rx, _route) = control.register_provider(provides);
    // Exit is exclusive: the slot serves one pair at a time and refuses a
    // second in its handshake answer, which is the only enforcement left once
    // a punched pair outlives the server-side state that fast-fails it.
    let busy = Arc::new(AtomicBool::new(false));
    let mut pairs: HashMap<u64, mpsc::Sender<Msg>> = HashMap::new();
    let mut running: Vec<(u64, AbortOnDrop)> = Vec::new();
    while let Some(msg) = rx.recv().await {
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
                    sink.clone(),
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
    sink: SessionSink,
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
            // The slot is taken here rather than at the pair's start, so two
            // pairs settling at once cannot both be served: the loser's
            // refusal rides the message two it is about to seal.
            let hold = if exclusive {
                BusyGuard::take(&busy)
            } else {
                None
            };
            let refuse: &[u8] = if exclusive && hold.is_none() {
                REFUSE_BUSY
            } else {
                &[]
            };
            let (peer, _) = handshake_under_relay_authority(
                settled,
                Side::Provider(refuse),
                pair_id,
                &session,
                &mut rx,
            )
            .await?;
            Ok(if refuse.is_empty() {
                Served::Taken(peer, hold)
            } else {
                Served::Refused
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
        Ok(Served::Taken(peer, _hold)) => {
            let bit = provides_name(provides);
            crate::elog!("peer {peer_id}: {bit} pair up");
            run_session(peer, &peer_id, provides, &sink).await;
            crate::elog!("peer {peer_id}: {bit} pair ended");
        }
        Ok(Served::Refused) => crate::elog!("peer pair {pair_id}: refused, the slot is busy"),
        Err(e) => crate::elog!("peer pair {pair_id}: {e}"),
    }
}

/// What a provider slot did with one pair.
enum Served {
    /// The pair is served; the hold keeps an exclusive slot taken until the
    /// session ends, however the pair task exits.
    Taken(PeerSession, Option<BusyGuard>),
    /// The slot was already serving a pair, and the refusal rode message two.
    Refused,
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
