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
/// A forwarded TCP stream idle in both directions for this long is treated as
/// dead (black-holed by a NAT/firewall with no FIN/RST) and reaped.
pub const TCP_IDLE: Duration = Duration::from_secs(120);

/// Copy bytes both ways between a plaintext TCP stream and the encrypted
/// connection. Returns when either side closes or both fall idle for TCP_IDLE.
pub async fn tcp(plain: TcpStream, mut nr: NoiseReader, mut nw: NoiseWriter) {
    plain.set_nodelay(true).ok();
    let (mut pr, mut pw) = plain.into_split();

    // Both directions copy concurrently so a write blocked on backpressure in one
    // never stalls the other (serializing them can deadlock a full-duplex stream).
    // A shared monotonic mark records the last byte moved either way; the watchdog
    // reaps the stream only after both directions stay idle for TCP_IDLE, i.e. a
    // black hole with no FIN/RST. Activity always restarts the window.
    // Mark in whole seconds: 32-bit targets (mips) have no AtomicU64, and second
    // resolution is ample for a 120s idle window.
    let base = Instant::now();
    let last = Arc::new(AtomicU32::new(0));

    let up_last = last.clone();
    let up = async move {
        let mut buf = [0u8; TCP_BUF];
        loop {
            let n = pr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            nw.send(&buf[..n]).await?;
            up_last.store(base.elapsed().as_secs() as u32, Ordering::Relaxed);
        }
        Ok::<_, crate::Error>(())
    };
    let down_last = last.clone();
    let down = async move {
        while let Ok(m) = nr.recv().await {
            pw.write_all(&m).await?;
            down_last.store(base.elapsed().as_secs() as u32, Ordering::Relaxed);
        }
        Ok::<_, crate::Error>(())
    };
    let win = TCP_IDLE.as_secs();
    let idle = async {
        loop {
            let idle_for = base
                .elapsed()
                .as_secs()
                .saturating_sub(last.load(Ordering::Relaxed) as u64);
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
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                m = nr.recv() => {
                    local.send(&m?).await?;
                    Ok::<_, crate::Error>(true)
                }
                r = local.recv(&mut buf) => {
                    let n = r?;
                    nw.send(&buf[..n]).await?;
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
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                d = dgram_rx.recv() => match d {
                    Some(d) => { nw.send(&d).await?; Ok::<_, crate::Error>(true) }
                    None => Ok::<_, crate::Error>(false),
                },
                m = nr.recv() => {
                    socket.send_to(&m?, src).await?;
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
