//! Async shell for the PPPoE-over-tunnel datapath (Linux only).
//!
//! Drives the sans-IO `PppoeDatapath` over the tunnel L2 channel and owns the
//! zppp0 TUN lifecycle. `run_dgram` is the UDP path (unreliable datagram channel);
//! `run_stream` is the TCP fallback (reliable Noise stream). Both share the
//! datapath core and the zppp0 bring-up helper; they differ only in the frame
//! in/out primitives.
//!
//! zppp0 is opened only after PPP reaches Established, because its IPv4 address
//! comes from IPCP and `TapDevice::open_tun` assigns the address at open time.
//! Before Established there is no address and no TUN; the zppp0 read arm stays
//! disabled until the bring-up edge.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::{interval, interval_at, Instant, MissedTickBehavior};

use crate::bridge::UDP_IDLE;
use crate::clientproto::{PppPhase, PppStatus};
use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::noise::{NoiseReader, NoiseWriter};
use crate::pppoe::datapath::{DpPhase, PppoeDatapath};
use crate::pppoe::engine::Established;
use crate::pppoe::netcfg::{self, NetCfgGuard, NetCfgOpts};
use crate::pppoe::redial::{self, Redial};
use crate::tap::{TapDevice, TunConfig};

/// Fast tick that drives discovery PADI/PADR retransmit and PPP phase advance.
/// PPPoE/PPP restart timers are seconds-scale, far below the idle window, so the
/// FSM is stepped on this cadence rather than the slow keepalive tick.
const NEGO_TICK: Duration = Duration::from_secs(1);

/// After the default route is swapped to zppp0, if no inbound tunnel frame arrives
/// for this long the control link is treated as stranded and the host-network
/// helpers are reverted (keeping zppp0 and the process up). Must stay below
/// `UDP_IDLE` (120s) so the revert precedes the idle reap. It keys on raw tunnel
/// inbound silence, refreshed by the BRAS's LCP echo-replies (~25s) on a healthy
/// link; the only other refresh is the 60s tunnel keepalive. So 45s sits above the
/// echo cadence (a healthy link never trips) but below the ~75s PPP echo-dead
/// window, intentionally falling back to the original WAN before PPP itself gives
/// up when the zppp0 path goes quiet.
const PPPOE_STRAND_REVERT: Duration = Duration::from_secs(45);

/// Carried into `run_*`: the zppp0 name and the effective MTU/MRU (used both for
/// the TUN MTU and, already, for the LCP MRU baked into the datapath).
pub struct ZpppBringup<'a> {
    pub tun_name: &'a str,
    pub mtu: u16,
    /// Stored-only AC-name selector (logged, not yet used for PADO filtering).
    pub ac_name: Option<&'a [u8]>,
    /// Which host-network helpers to apply once the link is Established.
    pub netcfg: NetCfgOpts,
    /// Resolved IPv4 server address for the WAN pin, or `None` to skip it.
    pub server_ip: Option<Ipv4Addr>,
    /// Live phase cell the shell updates as the datapath advances, so admin
    /// snapshots report the real link state.
    pub status: PppStatus,
}

/// The snapshot phase for a datapath phase.
fn wire_phase(phase: DpPhase) -> PppPhase {
    match phase {
        DpPhase::Discovery => PppPhase::Discovery,
        DpPhase::Ppp => PppPhase::Negotiating,
        DpPhase::Established(_) => PppPhase::Established,
        DpPhase::LinkDown => PppPhase::LinkDown,
        DpPhase::Dead => PppPhase::Dead,
    }
}

/// Bring up zppp0 once PPP reports Established. Opens the TUN with the IPCP
/// address as a /32 host route, the negotiated effective MTU, and the interface
/// up. The peer address and DNS are logged; no routes or DNS are applied.
fn maybe_bring_up_zppp0(
    tun: Option<Arc<TapDevice>>,
    phase: DpPhase,
    cfg: &ZpppBringup<'_>,
) -> crate::Result<(Option<Arc<TapDevice>>, Option<Established>)> {
    if tun.is_some() {
        return Ok((tun, None)); // already up; no fresh edge
    }
    let est = match phase {
        DpPhase::Established(est) => est,
        _ => return Ok((None, None)),
    };
    let tun_cfg = TunConfig {
        name: cfg.tun_name.to_string(),
        mtu: cfg.mtu as usize,
        addr: est.local_ip,
        prefix_len: 32,
    };
    let dev = Arc::new(TapDevice::open_tun(&tun_cfg)?);
    let ac = cfg
        .ac_name
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .unwrap_or_else(|| "any".to_string());
    crate::elog!(
        "pppoe: zppp0 up ip {}/32 peer {} mtu {} dns {:?}/{:?} ac {}; for a manual test: ip route add {} dev {}",
        est.local_ip,
        est.peer_ip,
        cfg.mtu,
        est.dns[0],
        est.dns[1],
        ac,
        est.peer_ip,
        cfg.tun_name,
    );
    Ok((Some(dev), Some(est)))
}

/// On a fresh Established edge, record when the session came up (the redial wait
/// keys on how long it holds) and apply the opt-in host-network helpers for the
/// new lease. The helpers are a no-op when no host flags are set. Clears the
/// strand latch so the watchdog re-arms for the new default route. The LinkDown
/// path already reverts any prior guard before a re-Established edge can occur,
/// so the `None` reset here is defensive (it would revert a stale guard only if a
/// future change left one).
fn on_established_edge(
    guard: &mut Option<NetCfgGuard>,
    stranded: &mut bool,
    up_since: &mut Option<Instant>,
    est_edge: Option<Established>,
    cfg: &ZpppBringup<'_>,
) {
    let Some(est) = est_edge else { return };
    *up_since = Some(Instant::now());
    if !cfg.netcfg.any() {
        return;
    }
    *guard = None; // defensive: the LinkDown path already reverted any prior guard
    *guard = Some(netcfg::apply(cfg.netcfg, cfg.server_ip, &est, cfg.tun_name));
    *stranded = false;
}

/// Revert the host-network helpers if the control link has been silent for longer
/// than `PPPOE_STRAND_REVERT` since the default route was swapped. Keeps zppp0 and
/// the process up; the swap is not re-applied until a real redial proves recovery
/// (a fresh Established edge clears the latch). Returns whether it just reverted.
fn strand_watchdog(guard: &mut Option<NetCfgGuard>, stranded: &mut bool, last_in: Instant) -> bool {
    if *stranded || !guard.as_ref().is_some_and(|g| g.default_applied()) {
        return false;
    }
    if last_in.elapsed() < PPPOE_STRAND_REVERT {
        return false;
    }
    *guard = None;
    *stranded = true;
    crate::elog!(
        "pppoe: control link silent for {}s; auto-reverted host routing, zppp0 still up",
        PPPOE_STRAND_REVERT.as_secs()
    );
    true
}

/// React to a LinkDown phase: close zppp0 (its address came from the now-dead
/// IPCP lease) and dial again over the same channel, so the select loop keeps
/// running and zppp0 reopens on the next Established edge with the (possibly
/// new) address.
///
/// A session that held is dialed again at once and starts the redial wait over.
/// A session that died before it held is released instead and the wait is armed:
/// the session id is off the wire immediately either way, and only the PADI is
/// deferred, to the negotiation tick where `Redial::due` resets the datapath.
/// The datapath stays in LinkDown for the whole wait, so this is re-entered on
/// every tick and inbound frame meanwhile and does nothing once the wait runs.
///
/// zppp0 removal relies on the shell being the sole `Arc<TapDevice>` holder, so
/// `drop` closes the last fd and the kernel removes the non-persistent TUN. The
/// caller drains the fresh PADI right after this returns. Errors only if the new
/// PPP session cannot be built (system RNG failure), which tears down the tunnel.
fn on_link_down(
    dp: &mut PppoeDatapath<'_>,
    tun: Option<Arc<TapDevice>>,
    redial: &mut Redial,
    up_since: Option<Instant>,
) -> crate::Result<Option<Arc<TapDevice>>> {
    let reason = dp.link_down_reason(); // captured before reset() clears it
    drop(tun); // close zppp0
    if redial::held(up_since) {
        *redial = Redial::default();
        crate::elog!("pppoe: link down ({reason}), re-dialing");
        dp.reset()?;
    } else if let Some(ticks) = redial.arm() {
        dp.release()?;
        let wait = NEGO_TICK * ticks;
        crate::elog!("pppoe: link down ({reason}) before the session held, re-dialing in {wait:?}");
    }
    Ok(None)
}

/// Drain every queued outbound L2 frame to the unreliable datagram channel.
async fn flush_to_dgram(dp: &mut PppoeDatapath<'_>, tx: &DgramTx) -> crate::Result<()> {
    while let Some(frame) = dp.poll_transmit_frame() {
        tx.send(&frame).await?;
    }
    Ok(())
}

/// Drain every queued outbound L2 frame to the reliable Noise stream.
async fn flush_to_stream(dp: &mut PppoeDatapath<'_>, nw: &mut NoiseWriter) -> crate::Result<()> {
    while let Some(frame) = dp.poll_transmit_frame() {
        nw.send(&frame).await?;
    }
    Ok(())
}

/// Drain every queued inbound IP packet to zppp0 (one IP packet per write).
async fn drain_inbound_to_tun(
    dp: &mut PppoeDatapath<'_>,
    tun: &Option<Arc<TapDevice>>,
) -> crate::Result<()> {
    if let Some(t) = tun {
        while let Some(ip) = dp.poll_inbound_ip() {
            t.write_frame(&ip).await?;
        }
    }
    Ok(())
}

/// UDP path: shuttle PPPoE frames between the datapath and the unreliable datagram
/// channel, bring up zppp0 on the Established edge, and pump IP both ways. Returns
/// Ok on a clean idle reap or cancel, Err on a TUN failure or discovery death (so
/// the reconnect loop redials).
pub async fn run_dgram(
    mut dp: PppoeDatapath<'_>,
    cfg: ZpppBringup<'_>,
    mut rx: DgramRx,
    tx: DgramTx,
    cancel: Arc<Notify>,
    name: &str,
) -> crate::Result<()> {
    let half = UDP_IDLE / 2;
    let mut keepalive = interval_at(Instant::now() + half, half);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut nego = interval(NEGO_TICK);
    nego.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    let mut tun: Option<Arc<TapDevice>> = None;
    let mut netcfg: Option<NetCfgGuard> = None;
    let mut stranded = false;
    let mut up_since: Option<Instant> = None;
    let mut redial = Redial::default();

    dp.start();
    cfg.status.set(PppPhase::Discovery);
    flush_to_dgram(&mut dp, &tx).await?;

    loop {
        // The zppp0 read future is only armed once the TUN exists.
        let tun_read = async {
            match &tun {
                Some(t) => t.read_frame().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            _ = cancel.notified() => break Ok(()),

            m = rx.recv() => match m {
                Some(Frame::Keepalive) => last_in = Instant::now(),
                // A name frame is server-bound only; never reaches this datapath.
                Some(Frame::Name(_)) => last_in = Instant::now(),
                Some(Frame::Data(d)) => {
                    last_in = Instant::now();
                    let phase = dp.on_l2_frame(&d);
                    cfg.status.set(wire_phase(phase));
                    flush_to_dgram(&mut dp, &tx).await?;
                    // Bring-up first: a no-op on any non-Established phase, so it is
                    // safe to call before the LinkDown handler that closes zppp0.
                    let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                    tun = t;
                    on_established_edge(&mut netcfg, &mut stranded, &mut up_since, est_edge, &cfg);
                    drain_inbound_to_tun(&mut dp, &tun).await?;
                    match phase {
                        DpPhase::Dead => break Err("pppoe discovery failed".into()),
                        DpPhase::LinkDown => {
                            netcfg = None; // revert host routing before zppp0 goes away
                            stranded = false;
                            tun = on_link_down(&mut dp, tun, &mut redial, up_since.take())?;
                            flush_to_dgram(&mut dp, &tx).await?; // drain the fresh PADI
                        }
                        _ => {}
                    }
                }
                None => break Ok(()),
            },

            ip = tun_read => {
                let ip = ip?;
                dp.on_tun_ip(&ip);
                flush_to_dgram(&mut dp, &tx).await?;
            }

            _ = nego.tick() => {
                // The wait a link-down armed dials here, so a session the segment
                // tears down as fast as it hands it out stays off the segment for
                // the wait rather than redialing at the round trip.
                if redial.due() {
                    dp.reset()?;
                    flush_to_dgram(&mut dp, &tx).await?;
                }
                let phase = dp.on_tick();
                cfg.status.set(wire_phase(phase));
                flush_to_dgram(&mut dp, &tx).await?;
                let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                tun = t;
                on_established_edge(&mut netcfg, &mut stranded, &mut up_since, est_edge, &cfg);
                match phase {
                    DpPhase::Dead => break Err("pppoe discovery failed".into()),
                    DpPhase::LinkDown => {
                        netcfg = None;
                        stranded = false;
                        tun = on_link_down(&mut dp, tun, &mut redial, up_since.take())?;
                        flush_to_dgram(&mut dp, &tx).await?;
                    }
                    _ => {}
                }
                strand_watchdog(&mut netcfg, &mut stranded, last_in);
            }

            _ = keepalive.tick() => {
                if last_in.elapsed() >= UDP_IDLE {
                    break Ok(());
                }
                // Re-announce the name so a lost attach frame self-heals; the
                // server applies it idempotently on every receipt.
                tx.send_name(name).await.ok();
                tx.probe().await.ok();
            }
        }
    }
}

/// TCP fallback: same datapath, frames over a reliable Noise stream. Each Noise
/// record is one Ethernet frame; an empty record is a keepalive.
pub async fn run_stream(
    mut dp: PppoeDatapath<'_>,
    cfg: ZpppBringup<'_>,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
    cancel: Arc<Notify>,
) -> crate::Result<()> {
    let half = UDP_IDLE / 2;
    let mut keepalive = interval_at(Instant::now() + half, half);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut nego = interval(NEGO_TICK);
    nego.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    let mut tun: Option<Arc<TapDevice>> = None;
    let mut netcfg: Option<NetCfgGuard> = None;
    let mut stranded = false;
    let mut up_since: Option<Instant> = None;
    let mut redial = Redial::default();

    dp.start();
    cfg.status.set(PppPhase::Discovery);
    flush_to_stream(&mut dp, &mut nw).await?;

    loop {
        let tun_read = async {
            match &tun {
                Some(t) => t.read_frame().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            _ = cancel.notified() => break Ok(()),

            m = nr.recv() => match m {
                Ok(d) => {
                    last_in = Instant::now();
                    if d.is_empty() {
                        continue; // keepalive record
                    }
                    let phase = dp.on_l2_frame(&d);
                    cfg.status.set(wire_phase(phase));
                    flush_to_stream(&mut dp, &mut nw).await?;
                    // Bring-up first: a no-op on any non-Established phase, so it is
                    // safe to call before the LinkDown handler that closes zppp0.
                    let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                    tun = t;
                    on_established_edge(&mut netcfg, &mut stranded, &mut up_since, est_edge, &cfg);
                    drain_inbound_to_tun(&mut dp, &tun).await?;
                    match phase {
                        DpPhase::Dead => break Err("pppoe discovery failed".into()),
                        DpPhase::LinkDown => {
                            netcfg = None; // revert host routing before zppp0 goes away
                            stranded = false;
                            tun = on_link_down(&mut dp, tun, &mut redial, up_since.take())?;
                            flush_to_stream(&mut dp, &mut nw).await?; // drain the fresh PADI
                        }
                        _ => {}
                    }
                }
                Err(_) => break Ok(()),
            },

            ip = tun_read => {
                let ip = ip?;
                dp.on_tun_ip(&ip);
                flush_to_stream(&mut dp, &mut nw).await?;
            }

            _ = nego.tick() => {
                // The wait a link-down armed dials here, so a session the segment
                // tears down as fast as it hands it out stays off the segment for
                // the wait rather than redialing at the round trip.
                if redial.due() {
                    dp.reset()?;
                    flush_to_stream(&mut dp, &mut nw).await?;
                }
                let phase = dp.on_tick();
                cfg.status.set(wire_phase(phase));
                flush_to_stream(&mut dp, &mut nw).await?;
                let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                tun = t;
                on_established_edge(&mut netcfg, &mut stranded, &mut up_since, est_edge, &cfg);
                match phase {
                    DpPhase::Dead => break Err("pppoe discovery failed".into()),
                    DpPhase::LinkDown => {
                        netcfg = None;
                        stranded = false;
                        tun = on_link_down(&mut dp, tun, &mut redial, up_since.take())?;
                        flush_to_stream(&mut dp, &mut nw).await?;
                    }
                    _ => {}
                }
                strand_watchdog(&mut netcfg, &mut stranded, last_in);
            }

            _ = keepalive.tick() => {
                if last_in.elapsed() >= UDP_IDLE {
                    break Ok(());
                }
                nw.probe().await.ok();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use crate::pppoe::discovery::{
        parse_discovery_frame, DiscoveryPacket, CODE_PADI, CODE_PADO, CODE_PADS, CODE_PADT,
    };
    use crate::pppoe::session::{parse_session_frame, put_eth_header};
    use crate::pppoe::{MacAddr, ETHERTYPE_DISCOVERY, ETHERTYPE_SESSION, VER_TYPE};

    /// The access concentrator the segment plays.
    const AC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    /// Forward tunnel packets the way the router does: the class byte and the
    /// tag are stripped before the body reaches a datagram session.
    async fn strip_tag(mut rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>) {
        while let Some(pkt) = rx.recv().await {
            if pkt.len() < 5 || tx.send(pkt[5..].to_vec()).await.is_err() {
                return;
            }
        }
    }

    /// A datagram channel with the shell on one end and the segment on the
    /// other, keyed by a real Noise handshake over an in-memory stream.
    async fn segment_channel() -> ((DgramRx, DgramTx), (DgramRx, DgramTx)) {
        let psk = crate::noise::derive_psk("pppoe redial test");
        let (a, b) = tokio::io::duplex(4096);
        let (shell, segment) = tokio::join!(
            crate::noise::client_handshake_stateless(a, &psk, 1),
            crate::noise::server_handshake_stateless(b, &psk, &[]),
        );
        let shell = Arc::new(shell.expect("the shell handshake failed"));
        let segment = Arc::new(segment.expect("the segment handshake failed").1);

        let (shell_out, shell_out_rx) = mpsc::channel(4096);
        let (segment_in, segment_in_rx) = mpsc::channel(4096);
        crate::spawn(strip_tag(shell_out_rx, segment_in));
        let (segment_out, segment_out_rx) = mpsc::channel(4096);
        let (shell_in, shell_in_rx) = mpsc::channel(4096);
        crate::spawn(strip_tag(segment_out_rx, shell_in));

        (
            (
                DgramRx::new(shell_in_rx, shell.clone()),
                DgramTx::new(shell_out, 0, shell),
            ),
            (
                DgramRx::new(segment_in_rx, segment.clone()),
                DgramTx::new(segment_out, 0, segment),
            ),
        )
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

    fn bringup() -> ZpppBringup<'static> {
        ZpppBringup {
            tun_name: "zpppt0",
            mtu: 1280,
            ac_name: None,
            netcfg: NetCfgOpts::default(),
            server_ip: None,
            status: PppStatus::default(),
        }
    }

    /// The next dial the shell puts on the channel, or `None` once it stops
    /// sending one inside `window`.
    async fn next_dial(rx: &mut DgramRx, window: Duration) -> Option<DiscoveryPacket> {
        loop {
            let frame = match timeout(window, rx.recv()).await {
                Ok(Some(Frame::Data(f))) => f,
                Ok(Some(_)) => continue, // tunnel keepalive or label
                _ => return None,        // the shell went quiet or gave up
            };
            match parse_discovery_frame(&frame) {
                Ok(p) if p.code == CODE_PADI => return Some(p),
                _ => continue, // a session frame or a PADR, not a fresh dial
            }
        }
    }

    /// The shell's next dial, and how many 0x8864 frames carrying `session_id`
    /// came before it: what the shell keeps addressing to a session id while the
    /// wait runs.
    async fn next_dial_counting_session_frames(
        rx: &mut DgramRx,
        window: Duration,
        session_id: u16,
    ) -> (Option<DiscoveryPacket>, usize) {
        let mut on_that_id = 0;
        loop {
            let frame = match timeout(window, rx.recv()).await {
                Ok(Some(Frame::Data(f))) => f,
                Ok(Some(_)) => continue,
                _ => return (None, on_that_id),
            };
            if parse_session_frame(&frame).is_ok_and(|h| h.session_id == session_id) {
                on_that_id += 1;
            }
            match parse_discovery_frame(&frame) {
                Ok(p) if p.code == CODE_PADI => return (Some(p), on_that_id),
                _ => continue,
            }
        }
    }

    /// How many dials a window of `ticks` negotiation ticks carries at least. The
    /// waits double from `REDIAL_TICKS`, so the cumulative wait before the nth
    /// dial is at most `REDIAL_TICKS * (2^n - 1)` ticks: every rung that fits
    /// inside the window dialed, plus the dial that opened it.
    fn dials_in(ticks: usize) -> usize {
        let mut dials = 1;
        let mut cumulative = redial::REDIAL_TICKS as usize;
        while cumulative < ticks {
            dials += 1;
            cumulative = 2 * cumulative + redial::REDIAL_TICKS as usize;
        }
        dials
    }

    /// Whether the shell sends a PPP session frame inside `window`: proof that a
    /// session latched and negotiation started on it.
    async fn sends_ppp_frame(rx: &mut DgramRx, window: Duration) -> bool {
        loop {
            let frame = match timeout(window, rx.recv()).await {
                Ok(Some(Frame::Data(f))) => f,
                Ok(Some(_)) => continue,
                _ => return false,
            };
            if frame.len() >= 14 && frame[12..14] == ETHERTYPE_SESSION.to_be_bytes() {
                return true;
            }
        }
    }

    /// A running shell dialing over a segment channel: the segment's end of that
    /// channel, the shell's cancel, and its task.
    #[allow(clippy::type_complexity)]
    async fn shell_on_a_segment() -> (
        DgramRx,
        DgramTx,
        Arc<Notify>,
        tokio::task::JoinHandle<crate::Result<()>>,
    ) {
        let ((shell_rx, shell_tx), (segment_rx, segment_tx)) = segment_channel().await;
        // 3 retransmit ticks, 5 discovery attempts, as the client shell builds it.
        let dp = PppoeDatapath::new(b"user", b"pass", Vec::new(), 1280, 3, 5)
            .expect("build the datapath");
        let cancel = Arc::new(Notify::new());
        let shell = crate::spawn(run_dgram(
            dp,
            bringup(),
            shell_rx,
            shell_tx,
            cancel.clone(),
            "test",
        ));
        (segment_rx, segment_tx, cancel, shell)
    }

    // An access concentrator that answers a dial through PADS and tears the fresh
    // session down puts no timer in the loop: it answers the next dial as fast as
    // it arrives, so what bounds the rate is the shell's own wait. Nothing here
    // reaches PPP, so zppp0 is never opened.
    #[tokio::test(start_paused = true)]
    async fn a_tunnel_session_torn_down_before_it_holds_dials_on_a_widening_wait() {
        let (mut segment_rx, segment_tx, cancel, shell) = shell_on_a_segment().await;

        const WINDOW: Duration = Duration::from_secs(200);
        let start = Instant::now();
        let mut dials = 0u64;
        while start.elapsed() < WINDOW {
            let Some(padi) = next_dial(&mut segment_rx, WINDOW).await else {
                break;
            };
            dials += 1;
            assert!(
                dials <= WINDOW.as_secs() / 10,
                "{dials} dials in {:?} is not a paced redial",
                start.elapsed()
            );
            let uniq = padi.host_uniq.expect("the PADI carries a Host-Uniq");
            for code in [CODE_PADO, CODE_PADS, CODE_PADT] {
                segment_tx
                    .send(&from_ac(code, padi.eth.src, 0x0042, &uniq))
                    .await
                    .expect("the segment channel closed");
            }
        }
        assert!(
            dials as usize >= dials_in(WINDOW.as_secs() as usize),
            "the shell stopped dialing altogether after {dials} dials"
        );

        // The wait paces the shell without stranding it: once the segment stops
        // tearing sessions down, the next dial latches a session and PPP starts
        // negotiating on it.
        let padi = next_dial(&mut segment_rx, WINDOW)
            .await
            .expect("the shell never dialed again");
        let uniq = padi.host_uniq.expect("the PADI carries a Host-Uniq");
        for code in [CODE_PADO, CODE_PADS] {
            segment_tx
                .send(&from_ac(code, padi.eth.src, 0x0042, &uniq))
                .await
                .expect("the segment channel closed");
        }
        assert!(
            sends_ppp_frame(&mut segment_rx, WINDOW).await,
            "the latched session never started PPP"
        );

        cancel.notify_waiters();
        timeout(Duration::from_secs(5), shell)
            .await
            .expect("the shell is still running")
            .expect("the shell panicked")
            .expect("the shell failed");
    }

    // A session the access concentrator tears down is off the wire the moment the
    // PADT lands: the wait paces how soon the shell dials again, not how long it
    // keeps addressing an id the concentrator has released and may have handed to
    // another subscriber. Three rungs of the ladder, over which the LCP restart
    // timer would otherwise re-offer the Configure-Request through every wait.
    #[tokio::test(start_paused = true)]
    async fn a_torn_down_session_id_leaves_the_wire_at_once() {
        let (mut segment_rx, segment_tx, cancel, shell) = shell_on_a_segment().await;

        const WINDOW: Duration = Duration::from_secs(200);
        let mut dial = next_dial(&mut segment_rx, WINDOW)
            .await
            .expect("the shell never dialed");
        for rung in 0..3u16 {
            let id = 0x0100 + rung;
            let uniq = dial.host_uniq.expect("the PADI carries a Host-Uniq");
            let station = dial.eth.src;
            for code in [CODE_PADO, CODE_PADS] {
                segment_tx
                    .send(&from_ac(code, station, id, &uniq))
                    .await
                    .expect("the segment channel closed");
            }
            assert!(
                sends_ppp_frame(&mut segment_rx, WINDOW).await,
                "the latched session never started PPP"
            );
            segment_tx
                .send(&from_ac(CODE_PADT, station, id, &uniq))
                .await
                .expect("the segment channel closed");

            let (next, leaked) =
                next_dial_counting_session_frames(&mut segment_rx, WINDOW, id).await;
            assert_eq!(
                leaked, 0,
                "the shell sent {leaked} frames on session {id:#06x} after it was torn down"
            );
            dial = next.expect("the wait never dialed again");
        }

        cancel.notify_waiters();
        timeout(Duration::from_secs(5), shell)
            .await
            .expect("the shell is still running")
            .expect("the shell panicked")
            .expect("the shell failed");
    }
}
