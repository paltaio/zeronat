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

    let task = tokio::spawn(run(uplink, count, creds, out_rx, inbound_txs, est_txs));
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
    let mut seen = vec![false; count];

    loop {
        let Some(mut link) = uplink.connect().await else {
            eprintln!("znpppoe: the uplink is gone; no session can come up");
            return;
        };
        eprintln!("znpppoe: link up; negotiating {count} session(s)");

        // Fresh discovery for every session over this channel.
        for i in 0..count {
            let _ = dps[i].reset();
            if seen[i] {
                seen[i] = false;
                est_txs[i].send_replace(None);
            }
        }
        flush_all(&mut dps, link.tx()).await;

        session_loop(
            &mut link,
            count,
            &mut dps,
            &macs,
            &mut seen,
            &mut out_rx,
            &inbound_txs,
            &est_txs,
        )
        .await;

        eprintln!("znpppoe: link down; reconnecting");
        for i in 0..count {
            if seen[i] {
                seen[i] = false;
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
    seen: &mut [bool],
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
                            Demux::One(i) => handle_l2(i, &d, dps, tx, inbound_txs, est_txs, seen).await,
                            Demux::All => {
                                for i in 0..count {
                                    handle_l2(i, &d, dps, tx, inbound_txs, est_txs, seen).await;
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
                for i in 0..count {
                    let phase = dps[i].on_tick();
                    flush_one(i, dps, tx).await;
                    apply_phase(i, phase, dps, tx, inbound_txs, est_txs, seen).await;
                }
                // A live session keeps the timer fresh; if every session has been
                // down past the grace, the channel to the segment is gone and
                // redialing in place cannot recover, so bounce it to re-attach.
                if seen.iter().any(|&s| s) {
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
    seen: &mut [bool],
) {
    let phase = dps[idx].on_l2_frame(frame);
    flush_one(idx, dps, tx).await;
    while let Some(ip) = dps[idx].poll_inbound_ip() {
        let _ = inbound_txs[idx].try_send(ip);
    }
    apply_phase(idx, phase, dps, tx, inbound_txs, est_txs, seen).await;
}

#[allow(clippy::too_many_arguments)]
async fn apply_phase(
    idx: usize,
    phase: DpPhase,
    dps: &mut [PppoeDatapath<'_>],
    tx: &LinkTx,
    inbound_txs: &[mpsc::Sender<Vec<u8>>],
    est_txs: &[watch::Sender<Option<Established>>],
    seen: &mut [bool],
) {
    match phase {
        DpPhase::Established(est) => {
            if !seen[idx] {
                seen[idx] = true;
                eprintln!("znpppoe: session {idx} up, ip={}", est.local_ip);
                est_txs[idx].send_replace(Some(est));
            }
            while let Some(ip) = dps[idx].poll_inbound_ip() {
                let _ = inbound_txs[idx].try_send(ip);
            }
        }
        DpPhase::LinkDown => {
            if seen[idx] {
                seen[idx] = false;
                eprintln!("znpppoe: session {idx} link down, redialing");
                est_txs[idx].send_replace(None);
            }
            let _ = dps[idx].reset();
            // Send the fresh PADI now rather than waiting a tick.
            flush_one(idx, dps, tx).await;
        }
        DpPhase::Dead => {
            eprintln!("znpppoe: session {idx} discovery failed, retrying");
            if seen[idx] {
                seen[idx] = false;
                est_txs[idx].send_replace(None);
            }
            let _ = dps[idx].reset();
            flush_one(idx, dps, tx).await;
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

    fn peer_uplink(sessions: mpsc::Receiver<zeronat::client::PeerSlotSession>) -> Uplink {
        Uplink::Peer {
            sessions,
            _client: crate::bridge::AbortOnDrop(tokio::spawn(std::future::pending::<()>())),
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
