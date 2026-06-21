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
use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::noise::{NoiseReader, NoiseWriter};
use crate::pppoe::datapath::{DpPhase, PppoeDatapath};
use crate::pppoe::engine::Established;
use crate::pppoe::netcfg::{self, NetCfgGuard, NetCfgOpts};
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

/// On a fresh Established edge, apply the opt-in host-network helpers for the new
/// lease. A no-op when no host flags are set. Clears the strand latch so the
/// watchdog re-arms for the new default route. The LinkDown path already reverts
/// any prior guard before a re-Established edge can occur, so the `None` reset here
/// is defensive (it would revert a stale guard only if a future change left one).
fn apply_netcfg_edge(
    guard: &mut Option<NetCfgGuard>,
    stranded: &mut bool,
    est_edge: Option<Established>,
    cfg: &ZpppBringup<'_>,
) {
    let Some(est) = est_edge else { return };
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
fn strand_watchdog(
    guard: &mut Option<NetCfgGuard>,
    stranded: &mut bool,
    last_in: Instant,
) -> bool {
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
/// IPCP lease) and reset the datapath to Discovery in place. The select loop
/// keeps running; discovery re-runs over the same channel and zppp0 reopens on
/// the next Established edge with the (possibly new) address.
///
/// zppp0 removal relies on the shell being the sole `Arc<TapDevice>` holder, so
/// `drop` closes the last fd and the kernel removes the non-persistent TUN. The
/// caller drains the fresh PADI right after this returns. Errors only if the new
/// PPP session cannot be built (system RNG failure), which tears down the tunnel.
fn redial_in_place(
    dp: &mut PppoeDatapath<'_>,
    tun: Option<Arc<TapDevice>>,
) -> crate::Result<Option<Arc<TapDevice>>> {
    let reason = dp.link_down_reason(); // captured before reset() clears it
    drop(tun); // close zppp0
    crate::elog!("pppoe: link down ({reason}), re-dialing");
    dp.reset()?;
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

    dp.start();
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
                Some(Frame::Data(d)) => {
                    last_in = Instant::now();
                    let phase = dp.on_l2_frame(&d);
                    flush_to_dgram(&mut dp, &tx).await?;
                    // Bring-up first: a no-op on any non-Established phase, so it is
                    // safe to call before the LinkDown handler that closes zppp0.
                    let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                    tun = t;
                    apply_netcfg_edge(&mut netcfg, &mut stranded, est_edge, &cfg);
                    drain_inbound_to_tun(&mut dp, &tun).await?;
                    match phase {
                        DpPhase::Dead => break Err("pppoe discovery failed".into()),
                        DpPhase::LinkDown => {
                            netcfg = None; // revert host routing before zppp0 goes away
                            stranded = false;
                            tun = redial_in_place(&mut dp, tun)?;
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
                let phase = dp.on_tick();
                flush_to_dgram(&mut dp, &tx).await?;
                let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                tun = t;
                apply_netcfg_edge(&mut netcfg, &mut stranded, est_edge, &cfg);
                match phase {
                    DpPhase::Dead => break Err("pppoe discovery failed".into()),
                    DpPhase::LinkDown => {
                        netcfg = None;
                        stranded = false;
                        tun = redial_in_place(&mut dp, tun)?;
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

    dp.start();
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
                    flush_to_stream(&mut dp, &mut nw).await?;
                    // Bring-up first: a no-op on any non-Established phase, so it is
                    // safe to call before the LinkDown handler that closes zppp0.
                    let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                    tun = t;
                    apply_netcfg_edge(&mut netcfg, &mut stranded, est_edge, &cfg);
                    drain_inbound_to_tun(&mut dp, &tun).await?;
                    match phase {
                        DpPhase::Dead => break Err("pppoe discovery failed".into()),
                        DpPhase::LinkDown => {
                            netcfg = None; // revert host routing before zppp0 goes away
                            stranded = false;
                            tun = redial_in_place(&mut dp, tun)?;
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
                let phase = dp.on_tick();
                flush_to_stream(&mut dp, &mut nw).await?;
                let (t, est_edge) = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                tun = t;
                apply_netcfg_edge(&mut netcfg, &mut stranded, est_edge, &cfg);
                match phase {
                    DpPhase::Dead => break Err("pppoe discovery failed".into()),
                    DpPhase::LinkDown => {
                        netcfg = None;
                        stranded = false;
                        tun = redial_in_place(&mut dp, tun)?;
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
