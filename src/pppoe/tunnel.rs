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

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::{interval, interval_at, Instant, MissedTickBehavior};

use crate::bridge::UDP_IDLE;
use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::noise::{NoiseReader, NoiseWriter};
use crate::pppoe::datapath::{DpPhase, PppoeDatapath};
use crate::tap::{TapDevice, TunConfig};

/// Fast tick that drives discovery PADI/PADR retransmit and PPP phase advance.
/// PPPoE/PPP restart timers are seconds-scale, far below the idle window, so the
/// FSM is stepped on this cadence rather than the slow keepalive tick.
const NEGO_TICK: Duration = Duration::from_secs(1);

/// Carried into `run_*`: the zppp0 name and the effective MTU/MRU (used both for
/// the TUN MTU and, already, for the LCP MRU baked into the datapath).
pub struct ZpppBringup<'a> {
    pub tun_name: &'a str,
    pub mtu: u16,
    /// Stored-only AC-name selector (logged, not yet used for PADO filtering).
    pub ac_name: Option<&'a [u8]>,
}

/// Bring up zppp0 once PPP reports Established. Opens the TUN with the IPCP
/// address as a /32 host route, the negotiated effective MTU, and the interface
/// up. The peer address and DNS are logged; no routes or DNS are applied.
fn maybe_bring_up_zppp0(
    tun: Option<Arc<TapDevice>>,
    phase: DpPhase,
    cfg: &ZpppBringup<'_>,
) -> crate::Result<Option<Arc<TapDevice>>> {
    if tun.is_some() {
        return Ok(tun); // already up
    }
    let est = match phase {
        DpPhase::Established(est) => est,
        _ => return Ok(None),
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
    eprintln!(
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
    Ok(Some(dev))
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
                    tun = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                    drain_inbound_to_tun(&mut dp, &tun).await?;
                    if matches!(phase, DpPhase::Dead) {
                        break Err("pppoe discovery failed".into());
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
                tun = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                if matches!(phase, DpPhase::Dead) {
                    break Err("pppoe discovery failed".into());
                }
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
                    tun = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                    drain_inbound_to_tun(&mut dp, &tun).await?;
                    if matches!(phase, DpPhase::Dead) {
                        break Err("pppoe discovery failed".into());
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
                tun = maybe_bring_up_zppp0(tun, phase, &cfg)?;
                if matches!(phase, DpPhase::Dead) {
                    break Err("pppoe discovery failed".into());
                }
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
