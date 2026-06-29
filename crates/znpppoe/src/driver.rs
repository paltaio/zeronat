//! Drives N userspace PPPoE sessions over one shared bridge channel. Each session
//! is a `PppoeDatapath` with its own MAC; inbound L2 frames are demuxed to the
//! right session by destination MAC. The negotiated IP never touches the kernel:
//! decapsulated inbound IP packets are handed to the session's userspace netstack
//! and outbound IP packets come back the same way.
//!
//! The driver owns tunnel reconnection: if the bridge dies it redials with backoff
//! and renegotiates every session over the new tunnel, keeping the datapaths and
//! the per-session channels (so the netstacks and SOCKS handles) stable.

use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tokio::time::sleep;

use zeronat::dgram::Frame;
use zeronat::pppoe::datapath::{DpPhase, PppoeDatapath};
use zeronat::pppoe::engine::Established;

use crate::bridge::{self, Bridge, Target};

const RETRANSMIT_TICKS: u32 = 3;
const MAX_ATTEMPTS: u32 = 5;
const NEGO_TICK: Duration = Duration::from_secs(1);
const KEEPALIVE: Duration = Duration::from_secs(20);
// Depth of the per-session inbound IP queue and the shared outbound queue. A full
// queue drops frames (TCP retransmits recover), so it is sized to hold roughly a
// full TCP window of in-flight segments at the netstack's buffer size; too small
// and a fast download's inbound burst is dropped faster than it is drained.
const IP_QUEUE: usize = 1024;
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// No inbound frame for this long means the tunnel is wedged (a silent UDP
/// black-hole or expired NAT mapping yields no error), so bounce and reconnect.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// Every session down for this long after the link was up means the bridge to the
/// server is gone (e.g. the server restarted): the attach happens once per tunnel
/// connect and cannot re-establish in place, so an in-place PPPoE redial loops
/// forever. Bounce the tunnel to re-attach instead of waiting out `UDP_IDLE`.
const REBRIDGE_GRACE: Duration = Duration::from_secs(30);

/// How to reach the zeronat server, so the driver can redial after a tunnel drop.
pub struct Dialer {
    pub target: Target,
    pub secret: String,
    pub client_id: String,
}

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

/// Spawn the driver task and return one `Session` handle per PPPoE connection.
pub fn spawn(dialer: Dialer, count: usize, creds: Creds) -> Vec<Session> {
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

    tokio::spawn(run(dialer, count, creds, out_rx, inbound_txs, est_txs));
    sessions
}

async fn run(
    dialer: Dialer,
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
    let mut backoff = BACKOFF_START;

    loop {
        let addr = match dialer.target.resolve().await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("znpppoe: {e}; retry in {backoff:?}");
                sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        let mut bridge = match bridge::connect(addr, &dialer.secret, &dialer.client_id).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("znpppoe: tunnel connect failed: {e}; retry in {backoff:?}");
                // Drop the cached DHT address so the next attempt re-resolves.
                dialer.target.invalidate();
                sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        backoff = BACKOFF_START;
        eprintln!("znpppoe: tunnel up; negotiating {count} session(s)");

        // Fresh discovery for every session over this tunnel.
        for i in 0..count {
            let _ = dps[i].reset();
            if seen[i] {
                seen[i] = false;
                est_txs[i].send_replace(None);
            }
        }
        flush_all(&mut dps, &bridge).await;

        session_loop(
            &mut bridge,
            count,
            &mut dps,
            &macs,
            &mut seen,
            &mut out_rx,
            &inbound_txs,
            &est_txs,
            &dialer.client_id,
        )
        .await;

        eprintln!("znpppoe: tunnel down; reconnecting");
        for i in 0..count {
            if seen[i] {
                seen[i] = false;
                est_txs[i].send_replace(None);
            }
        }
        sleep(RECONNECT_DELAY).await;
    }
}

/// Pump one tunnel until it dies (cancel fired or the receive side closes).
#[allow(clippy::too_many_arguments)]
async fn session_loop(
    bridge: &mut Bridge,
    count: usize,
    dps: &mut [PppoeDatapath<'_>],
    macs: &[[u8; 6]],
    seen: &mut [bool],
    out_rx: &mut mpsc::Receiver<(usize, Vec<u8>)>,
    inbound_txs: &[mpsc::Sender<Vec<u8>>],
    est_txs: &[watch::Sender<Option<Established>>],
    client_id: &str,
) {
    let cancel = bridge.cancel.clone();
    let mut nego = tokio::time::interval(NEGO_TICK);
    nego.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    let mut last_up = Instant::now();

    loop {
        tokio::select! {
            _ = cancel.notified() => return,

            m = bridge.rx.recv() => match m {
                None => return,
                Some(frame) => {
                    last_in = Instant::now();
                    if let Frame::Data(d) = frame {
                        match demux(&d, macs) {
                            Demux::One(i) => handle_l2(i, &d, dps, bridge, inbound_txs, est_txs, seen).await,
                            Demux::All => {
                                for i in 0..count {
                                    handle_l2(i, &d, dps, bridge, inbound_txs, est_txs, seen).await;
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
                    flush_one(idx, dps, bridge).await;
                }
            }

            _ = nego.tick() => {
                for i in 0..count {
                    let phase = dps[i].on_tick();
                    flush_one(i, dps, bridge).await;
                    apply_phase(i, phase, dps, bridge, inbound_txs, est_txs, seen).await;
                }
                // A live session keeps the timer fresh; if every session has been
                // down past the grace, the bridge is gone and redialing in place
                // cannot recover, so bounce the tunnel to re-attach.
                if seen.iter().any(|&s| s) {
                    last_up = Instant::now();
                } else if last_up.elapsed() >= REBRIDGE_GRACE {
                    eprintln!("znpppoe: all sessions down {REBRIDGE_GRACE:?}; rebridging");
                    return;
                }
            }

            _ = keepalive.tick() => {
                // A wedged tunnel surfaces no error; bounce it on inbound silence.
                if last_in.elapsed() >= UDP_IDLE {
                    return;
                }
                // Re-announce the name so a dropped attach frame self-heals.
                bridge.tx.send_name(client_id).await.ok();
                bridge.tx.probe().await.ok();
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_l2(
    idx: usize,
    frame: &[u8],
    dps: &mut [PppoeDatapath<'_>],
    bridge: &Bridge,
    inbound_txs: &[mpsc::Sender<Vec<u8>>],
    est_txs: &[watch::Sender<Option<Established>>],
    seen: &mut [bool],
) {
    let phase = dps[idx].on_l2_frame(frame);
    flush_one(idx, dps, bridge).await;
    while let Some(ip) = dps[idx].poll_inbound_ip() {
        let _ = inbound_txs[idx].try_send(ip);
    }
    apply_phase(idx, phase, dps, bridge, inbound_txs, est_txs, seen).await;
}

#[allow(clippy::too_many_arguments)]
async fn apply_phase(
    idx: usize,
    phase: DpPhase,
    dps: &mut [PppoeDatapath<'_>],
    bridge: &Bridge,
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
            flush_one(idx, dps, bridge).await;
        }
        DpPhase::Dead => {
            eprintln!("znpppoe: session {idx} discovery failed, retrying");
            if seen[idx] {
                seen[idx] = false;
                est_txs[idx].send_replace(None);
            }
            let _ = dps[idx].reset();
            flush_one(idx, dps, bridge).await;
        }
        DpPhase::Discovery | DpPhase::Ppp => {}
    }
}

async fn flush_one(idx: usize, dps: &mut [PppoeDatapath<'_>], bridge: &Bridge) {
    while let Some(frame) = dps[idx].poll_transmit_frame() {
        bridge.tx.send(&frame).await.ok();
    }
}

async fn flush_all(dps: &mut [PppoeDatapath<'_>], bridge: &Bridge) {
    for i in 0..dps.len() {
        flush_one(i, dps, bridge).await;
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
}
