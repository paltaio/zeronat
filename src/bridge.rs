use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::dgram::{DgramRx, DgramTx};
use crate::noise::{NoiseReader, NoiseWriter};
#[cfg(target_os = "linux")]
use crate::tap::TapDevice;

const TCP_BUF: usize = 16 * 1024;
const UDP_BUF: usize = 65535;
pub const UDP_IDLE: Duration = Duration::from_secs(120);
/// Upper bound on a single reliable-writer send/probe. Without it, an arm parked
/// in `nw.send` against a black-holed peer would starve the idle `tick`, so the
/// last_in reaper could never run. A bounded send fails closed and reaps.
const UDP_SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// A forwarded TCP stream idle in both directions for this long is treated as
/// dead (black-holed by a NAT/firewall with no FIN/RST) and reaped.
pub const TCP_IDLE: Duration = Duration::from_secs(120);

/// Copy bytes both ways between a plaintext TCP stream and the encrypted
/// connection. Returns when either side closes or the peer stops answering
/// liveness probes for TCP_IDLE.
pub async fn tcp(plain: TcpStream, mut nr: NoiseReader, mut nw: NoiseWriter) {
    plain.set_nodelay(true).ok();
    let (mut pr, mut pw) = plain.into_split();

    // Both directions copy concurrently so a write blocked on backpressure in one
    // never stalls the other (serializing them can deadlock a full-duplex stream).
    // Probe-then-reap: the upstream task watches a shared mark of the last inbound
    // frame (any frame, including empty keepalive probes) and emits a probe once
    // the link has been quiet for half the window. A peer that answers probes
    // refreshes the mark, so only a true black hole (no inbound frame for the
    // whole window) trips the reaper. Mark in whole seconds: 32-bit targets (mips)
    // have no AtomicU64, and second resolution is ample for a 120s window.
    let base = Instant::now();
    let last_in = Arc::new(AtomicU32::new(0));
    let win = TCP_IDLE.as_secs();

    let up = async move {
        let mut buf = [0u8; TCP_BUF];
        loop {
            match timeout(Duration::from_secs(win / 2), pr.read(&mut buf)).await {
                Ok(r) => {
                    let n = r?;
                    if n == 0 {
                        break;
                    }
                    nw.send(&buf[..n]).await?;
                }
                // Quiet for half the window: poke the peer. A live peer answers
                // (refreshing last_in via `down`); the independent watchdog below
                // reaps only if the whole window passes with no inbound frame.
                Err(_) => nw.probe().await?,
            }
        }
        Ok::<_, crate::Error>(())
    };
    let watch_in = last_in.clone();
    let down = async move {
        while let Ok(m) = nr.recv().await {
            watch_in.store(base.elapsed().as_secs() as u32, Ordering::Relaxed);
            if m.is_empty() {
                continue; // keepalive probe; nothing to forward
            }
            pw.write_all(&m).await?;
        }
        Ok::<_, crate::Error>(())
    };
    // Independent watchdog so a peer that black-holes outbound traffic (parking
    // both `up` in nw.send and `down` in nr.recv) is still reaped once the probe
    // window elapses with no inbound frame.
    let idle = async {
        loop {
            let idle_for = base
                .elapsed()
                .as_secs()
                .saturating_sub(last_in.load(Ordering::Relaxed) as u64);
            if idle_for >= win {
                break;
            }
            tokio::time::sleep(Duration::from_secs(win - idle_for)).await;
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
        _ = idle => {}
    }
}

/// Client side of a UDP stream: shuttle datagrams between a local UDP socket
/// (connected to the target service) and the encrypted connection.
pub async fn udp_client(local: UdpSocket, mut nr: NoiseReader, mut nw: NoiseWriter) {
    let mut buf = [0u8; UDP_BUF];
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            m = nr.recv() => match m {
                Ok(m) => {
                    last_in = Instant::now();
                    m.is_empty() || local.send(&m).await.is_ok()
                }
                Err(_) => false,
            },
            r = local.recv(&mut buf) => match r {
                Ok(n) => matches!(timeout(UDP_SEND_TIMEOUT, nw.send(&buf[..n])).await, Ok(Ok(()))),
                Err(_) => false,
            },
            _ = tick.tick() => {
                last_in.elapsed() < UDP_IDLE
                    && matches!(timeout(UDP_SEND_TIMEOUT, nw.probe()).await, Ok(Ok(())))
            }
        };
        if !alive {
            break;
        }
    }
}

/// Server side of a UDP stream: forward inbound datagrams (from the public
/// socket, delivered via `dgram_rx`) to the client, and client datagrams back
/// out to the original source address.
pub async fn udp_server(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
) {
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            d = dgram_rx.recv() => match d {
                Some(d) => matches!(timeout(UDP_SEND_TIMEOUT, nw.send(&d)).await, Ok(Ok(()))),
                None => false,
            },
            m = nr.recv() => match m {
                Ok(m) => {
                    last_in = Instant::now();
                    m.is_empty() || socket.send_to(&m, src).await.is_ok()
                }
                Err(_) => false,
            },
            _ = tick.tick() => {
                last_in.elapsed() < UDP_IDLE
                    && matches!(timeout(UDP_SEND_TIMEOUT, nw.probe()).await, Ok(Ok(())))
            }
        };
        if !alive {
            break;
        }
    }
}

/// Relay Ethernet frames between a TAP device and the unreliable datagram
/// channel (UDP transport). Returns when either side fails or `cancel` fires
/// (a newer bridge superseding this one).
#[cfg(target_os = "linux")]
pub async fn tap_dgram(tap: Arc<TapDevice>, mut rx: DgramRx, tx: DgramTx, cancel: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = cancel.notified() => break,
            frame = tap.read_frame() => match frame {
                Ok(f) => { if tx.send(&f).await.is_err() { break; } }
                Err(_) => break,
            },
            m = rx.recv() => match m {
                Some(f) => { if tap.write_frame(&f).await.is_err() { break; } }
                None => break,
            },
        }
    }
}

/// Relay Ethernet frames between a TAP device and a reliable Noise stream (TCP
/// fallback). Each `send`/`recv` is one record, so frame boundaries are
/// preserved. Returns when either side closes or `cancel` fires.
#[cfg(target_os = "linux")]
pub async fn tap_stream(
    tap: Arc<TapDevice>,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
    cancel: Arc<Notify>,
) {
    loop {
        tokio::select! {
            _ = cancel.notified() => break,
            frame = tap.read_frame() => match frame {
                Ok(f) => { if nw.send(&f).await.is_err() { break; } }
                Err(_) => break,
            },
            m = nr.recv() => match m {
                Ok(f) => { if tap.write_frame(&f).await.is_err() { break; } }
                Err(_) => break,
            },
        }
    }
}

/// Client side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_client_stateless(local: UdpSocket, mut rx: DgramRx, tx: DgramTx) {
    let mut buf = [0u8; UDP_BUF];
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                m = rx.recv() => {
                    let m = m.ok_or("transport closed")?;
                    local.send(&m).await?;
                    Ok::<_, crate::Error>(true)
                }
                r = local.recv(&mut buf) => {
                    let n = r?;
                    tx.send(&buf[..n]).await?;
                    Ok::<_, crate::Error>(true)
                }
            }
        })
        .await;
        match step {
            Ok(Ok(true)) => {}
            _ => break,
        }
    }
}

/// Server side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_server_stateless(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    mut rx: DgramRx,
    tx: DgramTx,
) {
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                d = dgram_rx.recv() => match d {
                    Some(d) => { tx.send(&d).await?; Ok::<_, crate::Error>(true) }
                    None => Ok::<_, crate::Error>(false),
                },
                m = rx.recv() => {
                    let m = m.ok_or("transport closed")?;
                    socket.send_to(&m, src).await?;
                    Ok::<_, crate::Error>(true)
                }
            }
        })
        .await;
        match step {
            Ok(Ok(true)) => {}
            _ => break,
        }
    }
}
