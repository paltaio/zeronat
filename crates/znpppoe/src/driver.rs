//! Drives N userspace PPPoE sessions over one shared L2 channel. Each session
//! is a `PppoeDatapath` with its own MAC; inbound L2 frames are demuxed to the
//! right session by destination MAC. The negotiated IP never touches the kernel:
//! decapsulated inbound IP packets are handed to the session's userspace netstack
//! and outbound IP packets come back the same way.
//!
//! The driver owns reconnection: if the channel dies it takes the next one the
//! uplink brings up and renegotiates every session over it, keeping the
//! datapaths and the per-session channels (so the netstacks and SOCKS handles)
//! stable.

use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Notify};
use tokio::time::sleep;

use zeronat::pppoe::datapath::{DpPhase, PppoeDatapath};
use zeronat::pppoe::engine::Established;

use crate::uplink::{Inbound, Link, LinkTx, Uplink, REBRIDGE_GRACE, UDP_IDLE};

const RETRANSMIT_TICKS: u32 = 3;
const MAX_ATTEMPTS: u32 = 5;
const NEGO_TICK: Duration = Duration::from_secs(1);
const KEEPALIVE: Duration = Duration::from_secs(20);
// Depth of the per-session inbound IP queue and the shared outbound queue. A full
// queue drops frames (TCP retransmits recover), so it is sized to hold roughly a
// full TCP window of in-flight segments at the netstack's buffer size; too small
// and a fast download's inbound burst is dropped faster than it is drained.
const IP_QUEUE: usize = 1024;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
// Negotiation ticks a session waits before dialing again after discovery gave
// up. An access concentrator that stops answering usually starts again on its
// own, so a session that gave up keeps dialing at a falling rate.
const REDIAL_TICKS: u32 = 3;
// Ceiling the redial wait doubles up to.
const REDIAL_TICKS_MAX: u32 = 60;

/// PPPoE credentials and link parameters shared by every session in the process.
#[derive(Clone)]
pub struct Creds {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub service: Vec<u8>,
    pub mru: u16,
    pub request_dns: bool,
    pub clamp_mss: Option<u16>,
}

/// The per-session handle handed to a netstack: inbound IP packets to consume,
/// a tagged sink for outbound IP packets, and the negotiated config once IPCP is
/// up (`None` until then, and reset to `None` on a link drop or tunnel drop).
pub struct Session {
    pub idx: usize,
    pub inbound_ip: mpsc::Receiver<Vec<u8>>,
    pub outbound_ip: mpsc::Sender<(usize, Vec<u8>)>,
    pub established: watch::Receiver<Option<Established>>,
}

enum Demux {
    One(usize),
    All,
    Drop,
}

/// What the driver tracks per session over the life of a channel: whether the
/// session is up, and the wait pacing a datapath that gave up on discovery.
#[derive(Default)]
struct SessionState {
    up: bool,
    redial: Redial,
}

/// Paces how often a session that gave up on discovery dials again. The wait
/// runs on negotiation ticks and doubles per failed dial; a session that comes
/// up starts the ladder over.
struct Redial {
    /// Ticks left before the next dial, or `None` when no dial is pending.
    wait: Option<u32>,
    /// Ticks the next wait is armed for.
    next: u32,
}

impl Default for Redial {
    fn default() -> Self {
        Redial {
            wait: None,
            next: REDIAL_TICKS,
        }
    }
}

impl Redial {
    /// Start the wait after a failed dial and report how long it is, or `None`
    /// when a wait is already running.
    fn arm(&mut self) -> Option<u32> {
        if self.wait.is_some() {
            return None;
        }
        let ticks = self.next;
        self.wait = Some(ticks);
        self.next = (self.next * 2).min(REDIAL_TICKS_MAX);
        Some(ticks)
    }

    /// Count one tick off the wait, reporting whether it is time to dial.
    fn due(&mut self) -> bool {
        let Some(left) = self.wait else {
            return false;
        };
        let left = left - 1;
        self.wait = (left > 0).then_some(left);
        left == 0
    }
}

/// Route an inbound L2 frame to a session by destination MAC. A broadcast is
/// delivered to every session; each datapath's discovery FSM filters by its own
/// Host-Uniq, so a frame that is not for it is inert.
fn demux(frame: &[u8], macs: &[[u8; 6]]) -> Demux {
    if frame.len() < 14 {
        return Demux::Drop;
    }
    let dst = &frame[0..6];
    if dst == [0xff; 6] {
        return Demux::All;
    }
    match macs.iter().position(|m| m == dst) {
        Some(i) => Demux::One(i),
        None => Demux::Drop,
    }
}

/// Spawn the driver task and return one `Session` handle per PPPoE connection,
/// with the task's handle. The task ends only when no further channel can come
/// up, which leaves every session dead for good.
pub fn spawn(
    uplink: Uplink,
    count: usize,
    creds: Creds,
) -> (Vec<Session>, tokio::task::JoinHandle<()>) {
    let (out_tx, out_rx) = mpsc::channel::<(usize, Vec<u8>)>(IP_QUEUE);

    let mut sessions = Vec::with_capacity(count);
    let mut inbound_txs = Vec::with_capacity(count);
    let mut est_txs = Vec::with_capacity(count);
    for idx in 0..count {
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(IP_QUEUE);
        let (est_tx, est_rx) = watch::channel::<Option<Established>>(None);
        inbound_txs.push(in_tx);
        est_txs.push(est_tx);
        sessions.push(Session {
            idx,
            inbound_ip: in_rx,
            outbound_ip: out_tx.clone(),
            established: est_rx,
        });
    }
    drop(out_tx);

    let task = crate::spawn(run(uplink, count, creds, out_rx, inbound_txs, est_txs));
    (sessions, task)
}

async fn run(
    mut uplink: Uplink,
    count: usize,
    creds: Creds,
    mut out_rx: mpsc::Receiver<(usize, Vec<u8>)>,
    inbound_txs: Vec<mpsc::Sender<Vec<u8>>>,
    est_txs: Vec<watch::Sender<Option<Established>>>,
) {
    // Built once and reused across reconnects so each session keeps a stable MAC.
    let mut dps: Vec<PppoeDatapath> = Vec::with_capacity(count);
    for _ in 0..count {
        match PppoeDatapath::new(
            &creds.username,
            &creds.password,
            creds.service.clone(),
            creds.mru,
            RETRANSMIT_TICKS,
            MAX_ATTEMPTS,
        ) {
            Ok(mut dp) => {
                if let Some(c) = creds.clamp_mss {
                    dp.set_clamp_mss(c);
                }
                dp.set_request_dns(creds.request_dns);
                dps.push(dp);
            }
            Err(e) => {
                eprintln!("znpppoe: session build failed: {e}");
                return;
            }
        }
    }

    let macs: Vec<[u8; 6]> = dps.iter().map(|d| *d.our_mac().octets()).collect();
    let mut state: Vec<SessionState> = (0..count).map(|_| SessionState::default()).collect();

    loop {
        let Some(mut link) = uplink.connect().await else {
            eprintln!("znpppoe: the uplink is gone; no session can come up");
            return;
        };
        eprintln!("znpppoe: link up; negotiating {count} session(s)");

        // Fresh discovery for every session over this channel, and a redial
        // ladder that starts over with it: a new channel can land on a different
        // segment.
        for i in 0..count {
            let _ = dps[i].reset();
            state[i].redial = Redial::default();
            if state[i].up {
                state[i].up = false;
                est_txs[i].send_replace(None);
            }
        }
        flush_all(&mut dps, link.tx()).await;

        session_loop(
            &mut link,
            count,
            &mut dps,
            &macs,
            &mut state,
            &mut out_rx,
            &inbound_txs,
            &est_txs,
        )
        .await;

        eprintln!("znpppoe: link down; reconnecting");
        for i in 0..count {
            if state[i].up {
                state[i].up = false;
                est_txs[i].send_replace(None);
            }
        }
        sleep(RECONNECT_DELAY).await;
    }
}

/// Resolves when the channel's cancel signal fires, or never when it has none.
async fn cancelled(cancel: Option<&Notify>) {
    match cancel {
        Some(cancel) => cancel.notified().await,
        None => std::future::pending().await,
    }
}

/// Pump one channel until it dies (cancel fired or the receive side closes).
#[allow(clippy::too_many_arguments)]
async fn session_loop(
    link: &mut Link,
    count: usize,
    dps: &mut [PppoeDatapath<'_>],
    macs: &[[u8; 6]],
    state: &mut [SessionState],
    out_rx: &mut mpsc::Receiver<(usize, Vec<u8>)>,
    inbound_txs: &[mpsc::Sender<Vec<u8>>],
    est_txs: &[watch::Sender<Option<Established>>],
) {
    // `idle` bounds how long the channel may stay silent, `grace` how long every
    // session may be down on a channel that is otherwise alive. A peer session
    // has neither: its pair reaps a silent peer on its own, and with no attach
    // to redo a bounce only buys a re-pair onto the same segment.
    let (rx, tx, cancel, idle, grace) = match link {
        Link::Bridge { rx, tx, cancel, .. } => (
            rx,
            &*tx,
            Some(&**cancel),
            Some(UDP_IDLE),
            Some(REBRIDGE_GRACE),
        ),
        Link::Peer { rx, tx } => (rx, &*tx, None, None, None),
    };
    let mut nego = tokio::time::interval(NEGO_TICK);
    nego.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    let mut last_up = Instant::now();

    loop {
        tokio::select! {
            _ = cancelled(cancel) => return,

            m = rx.recv() => match m {
                None => return,
                Some(inbound) => {
                    last_in = Instant::now();
                    if let Inbound::Frame(d) = inbound {
                        match demux(&d, macs) {
                            Demux::One(i) => handle_l2(i, &d, dps, tx, inbound_txs, est_txs, state).await,
                            Demux::All => {
                                for i in 0..count {
                                    handle_l2(i, &d, dps, tx, inbound_txs, est_txs, state).await;
                                }
                            }
                            Demux::Drop => {}
                        }
                    }
                }
            },

            Some((idx, pkt)) = out_rx.recv() => {
                if idx < dps.len() {
                    dps[idx].on_tun_ip(&pkt);
                    flush_one(idx, dps, tx).await;
                }
            }

            _ = nego.tick() => {
                tick_sessions(count, dps, tx, inbound_txs, est_txs, state).await;
                // A live session keeps the timer fresh; if every session has been
                // down past the grace, the channel to the segment is gone and
                // redialing in place cannot recover, so bounce it to re-attach.
                if state.iter().any(|s| s.up) {
                    last_up = Instant::now();
                } else if let Some(window) = grace.filter(|w| last_up.elapsed() >= *w) {
                    eprintln!("znpppoe: all sessions down {window:?}; reattaching");
                    return;
                }
            }

            _ = keepalive.tick() => {
                if idle.is_some_and(|window| last_in.elapsed() >= window) {
                    return;
                }
                tx.keepalive().await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_l2(
    idx: usize,
    frame: &[u8],
    dps: &mut [PppoeDatapath<'_>],
    tx: &LinkTx,
    inbound_txs: &[mpsc::Sender<Vec<u8>>],
    est_txs: &[watch::Sender<Option<Established>>],
    state: &mut [SessionState],
) {
    let phase = dps[idx].on_l2_frame(frame);
    flush_one(idx, dps, tx).await;
    while let Some(ip) = dps[idx].poll_inbound_ip() {
        let _ = inbound_txs[idx].try_send(ip);
    }
    apply_phase(idx, phase, dps, tx, inbound_txs, est_txs, state).await;
}

/// Advance every session by one negotiation tick: pump its timers, act on the
/// phase that comes out, and dial again for a session whose redial wait is up.
///
/// Dialing lives here rather than on the inbound path so a session that gave up
/// spends the wait quiet. A PADI is a broadcast, so a session that answered
/// every frame with a fresh dial would both flood the segment and hand every
/// other station that gave up a frame to answer.
async fn tick_sessions(
    count: usize,
    dps: &mut [PppoeDatapath<'_>],
    tx: &LinkTx,
    inbound_txs: &[mpsc::Sender<Vec<u8>>],
    est_txs: &[watch::Sender<Option<Established>>],
    state: &mut [SessionState],
) {
    for i in 0..count {
        if state[i].redial.due() {
            let _ = dps[i].reset();
            flush_one(i, dps, tx).await;
        }
        let phase = dps[i].on_tick();
        flush_one(i, dps, tx).await;
        apply_phase(i, phase, dps, tx, inbound_txs, est_txs, state).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_phase(
    idx: usize,
    phase: DpPhase,
    dps: &mut [PppoeDatapath<'_>],
    tx: &LinkTx,
    inbound_txs: &[mpsc::Sender<Vec<u8>>],
    est_txs: &[watch::Sender<Option<Established>>],
    state: &mut [SessionState],
) {
    match phase {
        DpPhase::Established(est) => {
            if !state[idx].up {
                state[idx].up = true;
                state[idx].redial = Redial::default();
                eprintln!("znpppoe: session {idx} up, ip={}", est.local_ip);
                est_txs[idx].send_replace(Some(est));
            }
            while let Some(ip) = dps[idx].poll_inbound_ip() {
                let _ = inbound_txs[idx].try_send(ip);
            }
        }
        DpPhase::LinkDown => {
            if state[idx].up {
                state[idx].up = false;
                eprintln!("znpppoe: session {idx} link down, redialing");
                est_txs[idx].send_replace(None);
            }
            let _ = dps[idx].reset();
            // Send the fresh PADI now rather than waiting a tick.
            flush_one(idx, dps, tx).await;
        }
        DpPhase::Dead => {
            if state[idx].up {
                state[idx].up = false;
                est_txs[idx].send_replace(None);
            }
            // The datapath emits nothing while it is dead, so the wait is what
            // dials again; `tick_sessions` runs it down.
            if let Some(ticks) = state[idx].redial.arm() {
                let wait = NEGO_TICK * ticks;
                eprintln!("znpppoe: session {idx} discovery failed, dialing again in {wait:?}");
            }
        }
        DpPhase::Discovery | DpPhase::Ppp => {}
    }
}

async fn flush_one(idx: usize, dps: &mut [PppoeDatapath<'_>], tx: &LinkTx) {
    while let Some(frame) = dps[idx].poll_transmit_frame() {
        tx.send(&frame).await;
    }
}

async fn flush_all(dps: &mut [PppoeDatapath<'_>], tx: &LinkTx) {
    for i in 0..dps.len() {
        flush_one(i, dps, tx).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zeronat::pppoe::discovery::{
        build_padi, parse_discovery_frame, CODE_PADI, CODE_PADO, CODE_PADR, CODE_PADS,
    };
    use zeronat::pppoe::session::put_eth_header;
    use zeronat::pppoe::{MacAddr, ETHERTYPE_DISCOVERY, VER_TYPE};

    fn frame(dst: [u8; 6]) -> Vec<u8> {
        let mut f = dst.to_vec();
        f.extend_from_slice(&[0; 8]); // src(6) + ethertype(2): enough to clear the 14-byte floor
        f
    }

    #[test]
    fn demux_routes_by_destination_mac() {
        let macs = [[1u8; 6], [2u8; 6], [3u8; 6]];
        assert!(matches!(demux(&frame([2; 6]), &macs), Demux::One(1)));
        assert!(matches!(demux(&frame([3; 6]), &macs), Demux::One(2)));
        assert!(matches!(demux(&frame([9; 6]), &macs), Demux::Drop));
        assert!(matches!(demux(&frame([0xff; 6]), &macs), Demux::All));
    }

    #[test]
    fn demux_drops_runt_frames() {
        let macs = [[1u8; 6]];
        assert!(matches!(demux(&[1, 1, 1, 1, 1, 1], &macs), Demux::Drop));
    }

    #[test]
    fn the_redial_wait_doubles_up_to_the_ceiling() {
        let mut redial = Redial::default();
        let mut waits = Vec::new();
        for _ in 0..7 {
            let ticks = redial.arm().expect("a wait is already running");
            waits.push(ticks);
            for left in (0..ticks).rev() {
                assert_eq!(redial.due(), left == 0, "the wait dialed with {left} left");
            }
        }
        assert_eq!(waits, [3, 6, 12, 24, 48, 60, 60]);
    }

    fn creds() -> Creds {
        Creds {
            username: b"user".to_vec(),
            password: b"pass".to_vec(),
            service: Vec::new(),
            mru: 1280,
            request_dns: false,
            clamp_mss: None,
        }
    }

    const USER: &[u8] = b"user";
    const PASS: &[u8] = b"pass";
    /// The access concentrator the bench plays, and another station dialing on
    /// the same segment.
    const AC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const OTHER: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

    /// One session and the channel it sends on, pumped by the same functions
    /// `session_loop` pumps it with: `tick` is the negotiation tick and `feed`
    /// is an inbound frame off the channel.
    struct Bench {
        dps: Vec<PppoeDatapath<'static>>,
        state: Vec<SessionState>,
        tx: LinkTx,
        frames: mpsc::Receiver<Vec<u8>>,
        inbound_txs: Vec<mpsc::Sender<Vec<u8>>>,
        est_txs: Vec<watch::Sender<Option<Established>>>,
    }

    impl Bench {
        /// A session dialing over a fresh channel, as `run` starts one.
        async fn new() -> Bench {
            let (frames_tx, frames) = mpsc::channel::<Vec<u8>>(8192);
            let (in_tx, _in_rx) = mpsc::channel::<Vec<u8>>(IP_QUEUE);
            let (est_tx, _est_rx) = watch::channel::<Option<Established>>(None);
            let dp =
                PppoeDatapath::new(USER, PASS, Vec::new(), 1280, RETRANSMIT_TICKS, MAX_ATTEMPTS)
                    .expect("build the datapath");
            let mut b = Bench {
                dps: vec![dp],
                state: vec![SessionState::default()],
                tx: LinkTx::Peer(frames_tx),
                frames,
                inbound_txs: vec![in_tx],
                est_txs: vec![est_tx],
            };
            let _ = b.dps[0].reset();
            flush_all(&mut b.dps, &b.tx).await;
            b
        }

        async fn tick(&mut self) {
            tick_sessions(
                1,
                &mut self.dps,
                &self.tx,
                &self.inbound_txs,
                &self.est_txs,
                &mut self.state,
            )
            .await;
        }

        async fn feed(&mut self, frame: &[u8]) {
            handle_l2(
                0,
                frame,
                &mut self.dps,
                &self.tx,
                &self.inbound_txs,
                &self.est_txs,
                &mut self.state,
            )
            .await;
        }

        fn phase(&self) -> DpPhase {
            self.dps[0].phase()
        }

        /// Every frame the session has put on the channel since the last call.
        fn sent(&mut self) -> Vec<Vec<u8>> {
            let mut v = Vec::new();
            while let Ok(f) = self.frames.try_recv() {
                v.push(f);
            }
            v
        }

        /// Tick until discovery gives up, returning the frames that took.
        async fn dial_until_dead(&mut self) -> Vec<Vec<u8>> {
            let mut sent = self.sent();
            for _ in 0..100 {
                if self.phase() == DpPhase::Dead {
                    return sent;
                }
                self.tick().await;
                sent.extend(self.sent());
            }
            panic!("discovery never gave up");
        }
    }

    fn code_is(frame: &[u8], code: u8) -> bool {
        parse_discovery_frame(frame).is_ok_and(|p| p.code == code)
    }

    fn count(frames: &[Vec<u8>], code: u8) -> usize {
        frames.iter().filter(|f| code_is(f, code)).count()
    }

    /// A PADI from another station: the broadcast every station on the segment
    /// receives, whatever it is doing itself.
    fn other_station_padi() -> Vec<u8> {
        build_padi(OTHER, &[], Some(&[0xaa, 0xbb, 0xcc, 0xdd]))
    }

    /// A discovery frame as the access concentrator sends it to `station`, with
    /// the station's Host-Uniq echoed so its FSM accepts it.
    fn from_ac(code: u8, station: MacAddr, session_id: u16, host_uniq: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x01, 0x01, 0x00, 0x00]; // Service-Name, empty
        payload.extend_from_slice(&[0x01, 0x03]); // Host-Uniq
        payload.extend_from_slice(&(host_uniq.len() as u16).to_be_bytes());
        payload.extend_from_slice(host_uniq);
        let mut f = Vec::new();
        put_eth_header(&mut f, station, AC, ETHERTYPE_DISCOVERY);
        f.push(VER_TYPE);
        f.push(code);
        f.extend_from_slice(&session_id.to_be_bytes());
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.extend_from_slice(&payload);
        f
    }

    // A station whose discovery gave up stays quiet on the frames the segment
    // delivers to it.
    #[tokio::test]
    async fn a_station_that_gave_up_does_not_dial_on_inbound_frames() {
        let mut b = Bench::new().await;
        let dialed = b.dial_until_dead().await;
        assert_eq!(
            count(&dialed, CODE_PADI),
            MAX_ATTEMPTS as usize,
            "discovery sends its attempt budget and stops"
        );

        const FRAMES: usize = 500;
        for _ in 0..FRAMES {
            b.feed(&other_station_padi()).await;
        }
        let sent = b.sent();
        assert!(
            sent.is_empty(),
            "the station sent {} frames on {FRAMES} inbound frames",
            sent.len()
        );
    }

    // What dials again is the wait, and it widens: over a window carrying a
    // thousand frames the station dials a few times, not once per frame. It also
    // has to keep dialing, since an access concentrator that answers nothing
    // usually starts answering again on its own.
    #[tokio::test]
    async fn a_station_that_gave_up_dials_on_a_widening_wait() {
        let mut b = Bench::new().await;
        const TICKS: usize = 200;
        const PER_TICK: usize = 5;
        let mut sent = Vec::new();
        for _ in 0..TICKS {
            b.tick().await;
            for _ in 0..PER_TICK {
                b.feed(&other_station_padi()).await;
            }
            sent.extend(b.sent());
        }
        let dials = count(&sent, CODE_PADI);
        let frames = TICKS * PER_TICK;
        assert!(
            dials >= 2 * MAX_ATTEMPTS as usize,
            "the station stopped dialing altogether after {dials} PADI"
        );
        assert!(
            dials <= 8 * MAX_ATTEMPTS as usize,
            "{dials} PADI over {frames} inbound frames is not a paced redial"
        );
    }

    // The segment answering again is enough to bring a station that gave up back:
    // the wait dials, and the access concentrator's PADO and PADS latch a session.
    #[tokio::test]
    async fn a_station_that_gave_up_comes_back_when_the_segment_answers() {
        let mut b = Bench::new().await;
        b.dial_until_dead().await;

        // Tick until the wait dials again.
        let mut padi = None;
        for _ in 0..100 {
            b.tick().await;
            padi = b.sent().into_iter().find(|f| code_is(f, CODE_PADI));
            if padi.is_some() {
                break;
            }
        }
        let padi = parse_discovery_frame(&padi.expect("the station never dialed again"))
            .expect("parse the PADI");
        let host_uniq = padi.host_uniq.expect("the PADI carries a Host-Uniq");

        b.feed(&from_ac(CODE_PADO, padi.eth.src, 0, &host_uniq))
            .await;
        assert_eq!(
            count(&b.sent(), CODE_PADR),
            1,
            "the station answers the PADO with a PADR"
        );
        b.feed(&from_ac(CODE_PADS, padi.eth.src, 0x0042, &host_uniq))
            .await;
        assert_eq!(b.phase(), DpPhase::Ppp, "the PADS latches a session");
    }

    fn peer_uplink(sessions: mpsc::Receiver<zeronat::client::PeerSlotSession>) -> Uplink {
        Uplink::Peer {
            sessions,
            _client: crate::bridge::AbortOnDrop(crate::spawn(std::future::pending::<()>())),
        }
    }

    // With `--peer` the sessions ride a switch port on a segment provider
    // instead of a bridge port on the server, so the driver's discovery has to
    // leave on the pair the consumer slot handed it.
    #[tokio::test]
    async fn a_peer_uplink_carries_pppoe_discovery() {
        let (sessions_tx, sessions_rx) = mpsc::channel(1);
        let (_from_provider, inbound) = mpsc::channel(4);
        let (outbound, mut to_provider) = mpsc::channel(4);
        sessions_tx
            .send(zeronat::client::PeerSlotSession {
                peer_id: "prov".into(),
                want: zeronat::proto::PROVIDES_SEGMENT,
                path: zeronat::client::PairPath::Relayed,
                inbound,
                outbound,
            })
            .await
            .unwrap();

        // The provider-side sender and the session handles keep the driver's
        // queues open for as long as the test runs.
        let (_sessions, _driver) = spawn(peer_uplink(sessions_rx), 1, creds());

        let frame = tokio::time::timeout(Duration::from_secs(10), to_provider.recv())
            .await
            .expect("no frame reached the provider")
            .expect("the pair closed");
        let padi = zeronat::pppoe::discovery::parse_discovery_frame(&frame)
            .expect("the first frame is not pppoe discovery");
        assert_eq!(padi.code, zeronat::pppoe::discovery::CODE_PADI);
    }

    // A peer client that stops pairing ends the driver, which is what the
    // process exits on: nothing above it can serve over sessions that can no
    // longer come up.
    #[tokio::test]
    async fn a_gone_peer_uplink_ends_the_driver() {
        let (sessions_tx, sessions_rx) = mpsc::channel(1);
        drop(sessions_tx);

        let (_sessions, driver) = spawn(peer_uplink(sessions_rx), 1, creds());

        tokio::time::timeout(Duration::from_secs(10), driver)
            .await
            .expect("the driver is still running")
            .expect("the driver panicked");
    }
}
