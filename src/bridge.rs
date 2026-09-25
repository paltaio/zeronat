#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::{Duration, Instant};

// Per-port traffic counters use the widest atomic the target supports: a 64-bit
// atomic where one exists, falling back to 32-bit on targets (mips) that lack it.
// The counters are display-only, so a 32-bit wrap on those targets is harmless.
#[cfg(all(target_os = "linux", not(target_has_atomic = "64")))]
use std::sync::atomic::AtomicU32 as AtomicCounter;
#[cfg(all(target_os = "linux", target_has_atomic = "64"))]
use std::sync::atomic::AtomicU64 as AtomicCounter;

// Widen a counter load to the wire's u64. On a 64-bit-atomic target the value is
// already u64; on a 32-bit-atomic target the loaded u32 is widened here so the
// snapshot stays target-independent.
#[cfg(all(target_os = "linux", target_has_atomic = "64"))]
fn widen_counter(v: u64) -> u64 {
    v
}
#[cfg(all(target_os = "linux", not(target_has_atomic = "64")))]
fn widen_counter(v: u32) -> u64 {
    u64::from(v)
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
#[cfg(any(target_os = "linux", test))]
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::kcp::Inbound;
use crate::noise::{NoiseReader, NoiseWriter};
use crate::pktinfo::LocalAddr;
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

/// The local plaintext side of a reliable relay. `read` yields the next chunk
/// (an empty chunk signals a closed local side, e.g. a TCP EOF); `write`
/// delivers a decrypted frame back to it. Both take `&mut self` and are driven
/// from independent halves so the two directions never serialize. Each variant
/// keeps the buffer its chunk lives in, so a relay reads without allocating.
enum LocalRead {
    Tcp(OwnedReadHalf, Vec<u8>),
    /// One whole Ethernet frame per read, never empty, so it never collides
    /// with the empty EOF sentinel the relay uses for TCP.
    #[cfg(target_os = "linux")]
    Tap(Arc<TapDevice>, Vec<u8>),
    /// The next switch-routed inbound frame (TAP -> client). A closed channel
    /// is the empty EOF sentinel, which a switch frame never collides with
    /// (a TAP frame is never empty).
    #[cfg(target_os = "linux")]
    Port {
        rx: mpsc::Receiver<Vec<u8>>,
        switch: Arc<TapSwitch>,
        stats: Arc<PortStats>,
        last: Vec<u8>,
    },
    /// Test-only: blocks on an mpsc the test feeds; `None` is the EOF sentinel.
    #[cfg(test)]
    Chan(mpsc::Receiver<Vec<u8>>, Vec<u8>),
}

enum LocalWrite {
    Tcp(OwnedWriteHalf),
    #[cfg(target_os = "linux")]
    Tap(Arc<TapDevice>),
    /// An egress frame (client -> BRAS) learns its source MAC onto this port,
    /// then writes to the shared TAP.
    #[cfg(target_os = "linux")]
    Port {
        switch: Arc<TapSwitch>,
        port_id: u32,
        stats: Arc<PortStats>,
    },
    /// Test-only: records every forwarded frame so a test can assert what
    /// reached it.
    #[cfg(test)]
    Chan(mpsc::UnboundedSender<Vec<u8>>),
}

impl LocalRead {
    fn tcp(r: OwnedReadHalf) -> Self {
        LocalRead::Tcp(r, vec![0u8; TCP_BUF])
    }

    async fn read(&mut self) -> crate::Result<&[u8]> {
        match self {
            LocalRead::Tcp(r, buf) => {
                let n = AsyncReadExt::read(r, &mut buf[..]).await?;
                Ok(&buf[..n]) // empty == EOF
            }
            #[cfg(target_os = "linux")]
            LocalRead::Tap(tap, last) => {
                tap.read_frame_into(last).await?;
                Ok(last)
            }
            #[cfg(target_os = "linux")]
            LocalRead::Port {
                rx,
                switch,
                stats,
                last,
            } => {
                let next = rx.recv().await.unwrap_or_default();
                switch.reclaim(std::mem::replace(last, next));
                // An empty frame is the channel-closed EOF sentinel, not real traffic.
                if !last.is_empty() {
                    stats.note_tx(last.len());
                }
                Ok(last)
            }
            #[cfg(test)]
            LocalRead::Chan(rx, last) => {
                *last = rx.recv().await.unwrap_or_default();
                Ok(last)
            }
        }
    }
}

impl LocalWrite {
    async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
        match self {
            LocalWrite::Tcp(w) => {
                w.write_all(buf).await?;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            LocalWrite::Tap(tap) => tap.write_frame(buf).await,
            #[cfg(target_os = "linux")]
            LocalWrite::Port {
                switch,
                port_id,
                stats,
            } => {
                stats.note_rx(buf.len());
                switch.learn_and_write_egress(buf, *port_id).await
            }
            #[cfg(test)]
            LocalWrite::Chan(tx) => tx.send(buf.to_vec()).map_err(|_| "closed".into()),
        }
    }
}

/// Copy frames both ways between a reliable local side and the encrypted Noise
/// stream, on a probe-then-reap watchdog. Returns when the local side closes,
/// the encrypted stream errors, the peer stops answering liveness probes for
/// the `idle` window, or `cancel` resolves.
///
/// Both directions run concurrently so a write blocked on backpressure in one
/// never stalls the other (serializing them can deadlock a full-duplex stream).
/// The down half marks a shared timestamp on every inbound frame (including
/// empty keepalive probes) and the up half emits a probe once the link has been
/// quiet for half the window; a live peer answers and refreshes the mark, so the
/// independent watchdog reaps only on a true black hole (no inbound frame for the
/// whole window). The mark is an AtomicU32 in whole seconds: 32-bit targets
/// (mips) have no 64-bit atomics and second resolution is ample for a 120s
/// window.
async fn stream_relay(
    mut local_r: LocalRead,
    mut local_w: LocalWrite,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
    idle: Duration,
    cancel: Option<Arc<Notify>>,
) {
    // tokio's clock so the idle math and the watchdog's sleep share one time
    // source (and so a paused-time test can drive it deterministically).
    let base = tokio::time::Instant::now();
    let last_in = Arc::new(AtomicU32::new(0));
    let win = idle.as_secs();

    let up = async move {
        loop {
            // The probe cadence is half the window, floored at a second so a
            // 1-second window cannot degenerate into a zero-length timeout that
            // spins probes back to back.
            match timeout(Duration::from_secs((win / 2).max(1)), local_r.read()).await {
                Ok(r) => {
                    let m = r?;
                    if m.is_empty() {
                        break;
                    }
                    // Bound the send so a send-side black hole cannot park here
                    // forever and starve the idle watchdog below.
                    match timeout(UDP_SEND_TIMEOUT, nw.send(m)).await {
                        Ok(r) => r?,
                        Err(_) => break,
                    }
                }
                // Quiet for half the window: poke the peer. A live peer answers
                // (refreshing last_in via `down`); the independent watchdog below
                // reaps only if the whole window passes with no inbound frame.
                Err(_) => match timeout(UDP_SEND_TIMEOUT, nw.probe()).await {
                    Ok(r) => r?,
                    Err(_) => break,
                },
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
            local_w.write(m).await?;
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

    let cancel = async {
        match &cancel {
            Some(cancel) => cancel.notified().await,
            None => std::future::pending().await,
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
        _ = idle => {}
        _ = cancel => {}
    }
}

/// Copy bytes both ways between a plaintext TCP stream and the encrypted
/// connection. Returns when either side closes or the peer stops answering
/// liveness probes for the `idle` window.
pub async fn tcp(plain: TcpStream, nr: NoiseReader, nw: NoiseWriter, idle: Duration) {
    plain.set_nodelay(true).ok();
    let (pr, pw) = plain.into_split();
    stream_relay(LocalRead::tcp(pr), LocalWrite::Tcp(pw), nr, nw, idle, None).await;
}

/// Client side of a UDP stream: shuttle datagrams between a local UDP socket
/// (connected to the target service) and the encrypted connection.
pub async fn udp_client(local: UdpSocket, nr: NoiseReader, nw: NoiseWriter, idle: Duration) {
    let local = DgramLocal::Udp {
        socket: local,
        buf: vec![0u8; UDP_BUF],
    };
    stream_dgram_relay(local, nr, nw, idle).await;
}

/// Relay datagrams between a local side and the encrypted connection, one
/// Noise record per datagram, on a probe-then-reap watchdog bounded by `idle`.
async fn stream_dgram_relay(
    mut local: DgramLocal,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
    idle: Duration,
) {
    // Floored at a second: interval_at panics on a zero period.
    let half = (idle / 2).max(Duration::from_secs(1));
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            m = nr.recv() => match m {
                Ok(m) => {
                    last_in = Instant::now();
                    m.is_empty() || local.write(m).await
                }
                Err(_) => false,
            },
            frame = local.read() => match frame {
                Some(frame) => {
                    matches!(timeout(UDP_SEND_TIMEOUT, nw.send(frame)).await, Ok(Ok(())))
                }
                None => false,
            },
            _ = tick.tick() => {
                last_in.elapsed() < idle
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
/// out to the original source address, from the local address that source sent
/// to.
pub async fn udp_server(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    local: Option<LocalAddr>,
    dgram_rx: Inbound,
    nr: NoiseReader,
    nw: NoiseWriter,
    idle: Duration,
) {
    let local = DgramLocal::Server {
        socket,
        src,
        local,
        dgram_rx,
        last: Vec::new(),
    };
    stream_dgram_relay(local, nr, nw, idle).await;
}

/// Relay Ethernet frames between a TAP device and the unreliable datagram
/// channel (UDP transport). Returns when either side fails, the peer stops
/// answering keepalives for UDP_IDLE, or `cancel` fires (the client's RX pump
/// seeing the peer vanish). Used by the client for its point-to-point bridge.
///
/// The tick keeps the CG-NAT UDP mapping warm and, paired with the idle mark,
/// self-heals if the mapping silently expires: with no inbound frame for the
/// whole window the relay reaps and the reconnect loop redials.
#[cfg(target_os = "linux")]
pub async fn tap_dgram(
    tap: Arc<TapDevice>,
    rx: DgramRx,
    tx: DgramTx,
    cancel: Arc<Notify>,
    name: &str,
) {
    let local = DgramLocal::Tap {
        tap,
        last: Vec::new(),
    };
    dgram_relay(local, rx, tx, UDP_IDLE, Some(cancel), Some(name)).await;
}

/// The local side of a datagram relay: where a frame from the channel goes,
/// and what feeds the channel.
enum DgramLocal {
    /// The client's point-to-point bridge device.
    #[cfg(target_os = "linux")]
    Tap { tap: Arc<TapDevice>, last: Vec<u8> },
    /// One port of the server's switch. The handle's drop evicts the port.
    #[cfg(target_os = "linux")]
    Port {
        handle: SwitchHandle,
        out_rx: mpsc::Receiver<Vec<u8>>,
        last: Vec<u8>,
    },
    /// A local UDP socket connected to the forward's target.
    Udp { socket: UdpSocket, buf: Vec<u8> },
    /// The server's public socket: inbound datagrams arrive on `dgram_rx`,
    /// replies leave for `src` from the local address it sent to.
    Server {
        socket: Arc<UdpSocket>,
        src: SocketAddr,
        local: Option<LocalAddr>,
        dgram_rx: Inbound,
        last: Vec<u8>,
    },
}

impl DgramLocal {
    /// The next frame bound for the channel, or `None` once this side is done.
    async fn read(&mut self) -> Option<&[u8]> {
        match self {
            #[cfg(target_os = "linux")]
            DgramLocal::Tap { tap, last } => {
                tap.read_frame_into(last).await.ok()?;
                Some(last)
            }
            #[cfg(target_os = "linux")]
            DgramLocal::Port {
                handle,
                out_rx,
                last,
                ..
            } => {
                let next = out_rx.recv().await?;
                handle.switch.reclaim(std::mem::replace(last, next));
                handle.stats.note_tx(last.len());
                Some(last)
            }
            DgramLocal::Udp { socket, buf } => {
                let n = socket.recv(buf).await.ok()?;
                Some(&buf[..n])
            }
            DgramLocal::Server { dgram_rx, last, .. } => {
                let next = dgram_rx.recv().await?;
                dgram_rx.reclaim(std::mem::replace(last, next));
                Some(last)
            }
        }
    }

    /// Deliver a frame from the channel; false once this side is done.
    async fn write(&mut self, frame: &[u8]) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            DgramLocal::Tap { tap, .. } => tap.write_frame(frame).await.is_ok(),
            #[cfg(target_os = "linux")]
            DgramLocal::Port { handle, .. } => {
                handle.stats.note_rx(frame.len());
                handle
                    .switch
                    .learn_and_write_egress(frame, handle.port_id)
                    .await
                    .is_ok()
            }
            DgramLocal::Udp { socket, .. } => socket.send(frame).await.is_ok(),
            DgramLocal::Server {
                socket, src, local, ..
            } => crate::pktinfo::send_to(socket, frame, *src, *local)
                .await
                .is_ok(),
        }
    }

    /// Any frame from the channel is the peer's proof that it is still there.
    fn heard(&self) {
        #[cfg(target_os = "linux")]
        if let DgramLocal::Port { handle, .. } = self {
            handle.prove();
        }
    }
}

/// Relay frames between a local side and the unreliable datagram channel.
/// Returns when either side fails, the peer stops answering keepalives for
/// `idle`, or `cancel` fires. The tick keeps the CG-NAT UDP mapping warm and,
/// paired with the idle mark, self-heals if the mapping silently expires: with
/// no inbound frame for the whole window the relay reaps and the owner
/// redials. With a `name`, the tick re-announces it so a lost attach frame
/// self-heals; the server applies it idempotently on every receipt.
async fn dgram_relay(
    mut local: DgramLocal,
    mut rx: DgramRx,
    mut tx: DgramTx,
    idle: Duration,
    cancel: Option<Arc<Notify>>,
    name: Option<&str>,
) {
    // Floored at a second: interval_at panics on a zero period.
    let half = (idle / 2).max(Duration::from_secs(1));
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let stop = async {
            match &cancel {
                Some(cancel) => cancel.notified().await,
                None => std::future::pending().await,
            }
        };
        let alive = tokio::select! {
            _ = stop => false,
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    local.heard();
                    match f {
                        Frame::Keepalive => true,
                        // A name frame is server-bound only; ignore it here.
                        Frame::Name(_) => true,
                        Frame::Data(d) => local.write(d).await,
                    }
                }
                None => false,
            },
            frame = local.read() => match frame {
                Some(frame) => tx.send(frame).await.is_ok(),
                None => false,
            },
            _ = tick.tick() => {
                let live = last_in.elapsed() < idle;
                if live {
                    if let Some(name) = name {
                        tx.send_name(name).await.ok();
                    }
                }
                live && tx.probe().await.is_ok()
            }
        };
        if !alive {
            break;
        }
    }
}

/// Relay Ethernet frames between a TAP device and a reliable Noise stream (TCP
/// fallback). Each `send`/`recv` is one record, so frame boundaries are
/// preserved. Returns when either side closes, the peer stops answering probes
/// for TCP_IDLE, or `cancel` fires.
#[cfg(target_os = "linux")]
pub async fn tap_stream(
    tap: Arc<TapDevice>,
    nr: NoiseReader,
    nw: NoiseWriter,
    cancel: Arc<Notify>,
) {
    stream_relay(
        LocalRead::Tap(tap.clone(), Vec::new()),
        LocalWrite::Tap(tap),
        nr,
        nw,
        TCP_IDLE,
        Some(cancel),
    )
    .await;
}

/// Cap on distinct source MACs the learning table holds. Mirrors
/// `kcp::MAX_CONVS_PER_SESSION`: it sits far above a real deployment's host count
/// and exists only so one client flooding spoofed source addresses cannot grow
/// the table without bound. At the cap, new MACs are not learned (so they flood
/// to every port instead of being pinned) while existing entries still update.
#[cfg(target_os = "linux")]
const MAX_MACS_PER_SWITCH: usize = 4096;

/// Bounded per-port egress queue depth toward a client. A slow or stalled client
/// relay drops frames here rather than back-pressuring the single TAP reader (one
/// stalled port must never wedge inbound delivery to every other port).
#[cfg(target_os = "linux")]
const SWITCH_PORT_CAP: usize = 256;

/// Cap on the learned MACs reported per port in the admin fleet view. Bounds a
/// bridge-client row's width; routing still uses the full per-switch MAC table.
#[cfg(target_os = "linux")]
const MAX_DISPLAY_MACS: usize = 16;

/// Bound on frame buffers the ports have handed back for the reader to fill
/// again; anything past it is dropped.
#[cfg(target_os = "linux")]
const SWITCH_RECYCLE_CAP: usize = 32;

/// Live traffic counters for one switch port, shared by `Arc` so a port's relay
/// bumps them with a single atomic add per frame and never touches the `ports`
/// lock on the datapath. `last_activity` is whole seconds since `created`, the
/// same low-resolution mark idiom the relays use for idleness.
#[cfg(target_os = "linux")]
struct PortStats {
    rx_bytes: AtomicCounter,
    rx_frames: AtomicCounter,
    tx_bytes: AtomicCounter,
    tx_frames: AtomicCounter,
    last_activity: AtomicU32,
    created: Instant,
}

#[cfg(target_os = "linux")]
impl PortStats {
    fn new() -> Arc<PortStats> {
        Arc::new(PortStats {
            rx_bytes: AtomicCounter::new(0),
            rx_frames: AtomicCounter::new(0),
            tx_bytes: AtomicCounter::new(0),
            tx_frames: AtomicCounter::new(0),
            last_activity: AtomicU32::new(0),
            created: Instant::now(),
        })
    }

    /// Record one egress frame (client -> server): a single atomic add per field.
    fn note_rx(&self, len: usize) {
        self.rx_bytes.fetch_add(len as _, Ordering::Relaxed);
        self.rx_frames.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Record one inbound frame (server -> client).
    fn note_tx(&self, len: usize) {
        self.tx_bytes.fetch_add(len as _, Ordering::Relaxed);
        self.tx_frames.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    fn touch(&self) {
        self.last_activity.store(
            self.created.elapsed().as_secs().min(u32::MAX as u64) as u32,
            Ordering::Relaxed,
        );
    }
}

/// One attached client on the software switch: a bounded sender that carries
/// inbound (TAP -> client) frames toward that client's relay, the cancel that
/// relay waits on so an evicted/closed port tears its relay down at once, and the
/// metadata and counters the fleet view reports.
#[cfg(target_os = "linux")]
struct SwitchPort {
    out: mpsc::Sender<Vec<u8>>,
    cancel: Arc<Notify>,
    stats: Arc<PortStats>,
    /// Client-announced label, set once if the client sends one; `None` leaves the
    /// fleet view to fall back to the peer address or the port id.
    name: Mutex<Option<String>>,
    /// Observed control transport: 1 = tcp, 2 = udp.
    transport: u8,
    peer: Option<SocketAddr>,
    /// Whether the client behind this port has been heard from since it
    /// attached. A stream port is proven the moment it attaches, since the
    /// stream itself carries the client's liveness; a datagram port starts
    /// unproven and its first inbound frame proves it.
    proven: Arc<AtomicBool>,
}

/// A point-in-time copy of one switch port for the admin fleet view. Plain owned
/// data so `bridge.rs` carries no dependency on the wire `BridgeEntry`.
#[cfg(target_os = "linux")]
pub struct BridgePortInfo {
    pub port_id: u32,
    pub name: Option<String>,
    pub transport: u8,
    pub peer: Option<SocketAddr>,
    pub macs: Vec<[u8; 6]>,
    pub rx_bytes: u64,
    pub rx_frames: u64,
    pub tx_bytes: u64,
    pub tx_frames: u64,
    pub uptime_secs: u32,
    pub idle_secs: u32,
}

/// In-process learning switch between the one server-side device and N attached
/// client ports so multiple clients share one server. A single reader owns
/// `tap.read_frame()` and fans each inbound frame out.
///
/// On an L2 (`--tap`, Ethernet) device it is a MAC-learning switch: each inbound
/// frame is routed by destination MAC (flooding broadcast, multicast, and unknown
/// unicast; delivering learned unicast to the one owning port), and each client
/// relay learns the source MACs it sends and writes them back to the shared
/// device. An L3 (`--tun`) device carries raw IPv4 with no Ethernet header and
/// supports one client at a time: the single-port fast path forwards inbound
/// packets untouched and egress learns nothing.
#[cfg(target_os = "linux")]
pub struct TapSwitch {
    tap: Arc<TapDevice>,
    /// `true` for an L2 (TAP/Ethernet) device that supports MAC learning across
    /// many ports; `false` for an L3 (TUN) device, which serves one client only.
    is_l2: bool,
    /// Whether an egress frame is also routed between the switch's own ports.
    /// The device is one port of a kernel bridge and a bridge never sends a
    /// frame back out the port it arrived on, so with this set the switch is
    /// what carries a frame from one attached port to another.
    port_to_port: bool,
    ports: Mutex<HashMap<u32, SwitchPort>>,
    macs: Mutex<HashMap<[u8; 6], (u32, Instant)>>,
    next_port: AtomicU32,
    /// Frame buffers the ports are done with, for `read_loop` to fill again.
    recycle: mpsc::Sender<Vec<u8>>,
    returns: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

/// Parse an Ethernet frame's destination and source MAC. `None` for a buffer too
/// short to be Ethernet (e.g. a raw L3 packet on a `--tun` device), which the
/// caller forwards via the single-port fast path without inspection.
#[cfg(target_os = "linux")]
fn dst_src(f: &[u8]) -> Option<([u8; 6], [u8; 6])> {
    if f.len() < 14 {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&f[0..6]);
    src.copy_from_slice(&f[6..12]);
    Some((dst, src))
}

/// True for a MAC that must never be learned as a source: the broadcast/multicast
/// group bit (LSB of the first octet) marks a non-unicast address, and an all-zero
/// address is not a real station.
#[cfg(target_os = "linux")]
fn is_group_or_zero(mac: &[u8; 6]) -> bool {
    mac[0] & 1 != 0 || *mac == [0u8; 6]
}

#[cfg(target_os = "linux")]
impl TapSwitch {
    /// Build the switch over an opened device and spawn the sole reader task.
    /// `is_l2` is `true` for a TAP (Ethernet) device and `false` for a TUN (L3)
    /// device; an L3 switch serves exactly one client. The returned `Arc` owns the
    /// device; every attached port shares it.
    pub fn new(tap: Arc<TapDevice>, is_l2: bool) -> Arc<Self> {
        let sw = Self::detached(tap, is_l2);
        let reader = sw.clone();
        crate::spawn(reader.read_loop());
        sw
    }

    /// Build the switch without starting the reader, leaving [`Self::read_loop`]
    /// for the caller to drive. A switch whose device must be closed the moment
    /// its owner goes away drives the loop inside that owner's future, since a
    /// spawned reader keeps its own reference to the device until the runtime
    /// gets around to cancelling it.
    pub fn detached(tap: Arc<TapDevice>, is_l2: bool) -> Arc<Self> {
        Self::build(tap, is_l2, false)
    }

    /// Build a detached L2 switch that carries frames between its own ports as
    /// well as to and from the device. This is the peer segment provider's
    /// switch: its consumers share one TAP port on the node's bridge, so a
    /// frame from one consumer to another never comes back from the kernel.
    pub(crate) fn segment(tap: Arc<TapDevice>) -> Arc<Self> {
        Self::build(tap, true, true)
    }

    fn build(tap: Arc<TapDevice>, is_l2: bool, port_to_port: bool) -> Arc<Self> {
        let (recycle, returns) = mpsc::channel(SWITCH_RECYCLE_CAP);
        Arc::new(TapSwitch {
            tap,
            is_l2,
            port_to_port,
            ports: Mutex::new(HashMap::new()),
            macs: Mutex::new(HashMap::new()),
            next_port: AtomicU32::new(0),
            recycle,
            returns: Mutex::new(Some(returns)),
        })
    }

    /// Hand a frame buffer a port is done with back to the reader.
    fn reclaim(&self, frame: Vec<u8>) {
        if frame.capacity() != 0 {
            let _ = self.recycle.try_send(frame);
        }
    }

    /// Sole owner of `tap.read_frame()`: fan every inbound frame out to the right
    /// port(s). On an unrecoverable read error, cancel every port (so their relays
    /// reap) and exit, ending the switch's inbound path. Each frame is read into
    /// a buffer a port handed back, or the one the last flood left over.
    pub async fn read_loop(self: Arc<Self>) {
        let mut returns = self
            .returns
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| mpsc::channel(1).1);
        let mut spare = Vec::new();
        loop {
            let mut frame = returns
                .try_recv()
                .unwrap_or_else(|_| std::mem::take(&mut spare));
            if self.tap.read_frame_into(&mut frame).await.is_err() {
                for port in self.ports.lock().unwrap().values() {
                    port.cancel.notify_one();
                }
                return;
            }
            // Single-port fast path: with exactly one client attached, forward the
            // frame untouched without parsing. This preserves `--tun` (raw L3, no
            // Ethernet header) and single-client `--tap` byte-for-byte.
            let sole = {
                let ports = self.ports.lock().unwrap();
                if ports.len() == 1 {
                    ports.values().next().map(|p| p.out.clone())
                } else {
                    None
                }
            };
            spare = match sole {
                Some(out) => out
                    .try_send(frame)
                    .err()
                    .map(|e| e.into_inner())
                    .unwrap_or_default(),
                None => match dst_src(&frame) {
                    Some((dst, src)) => self.forward_inbound(dst, src, frame),
                    // No Ethernet header but more than one port: nothing to address
                    // it to, so flood it to every port.
                    None => {
                        self.flood(&frame);
                        frame
                    }
                },
            };
        }
    }

    /// Forward one inbound frame by destination MAC: flood broadcast, multicast,
    /// and unknown unicast to every port; deliver learned unicast to the one
    /// owning port (falling back to a flood if that port has since vanished).
    /// The source transmitted on the device's side of the switch, so whatever
    /// port binding it holds is stale and is dropped. Returns the buffer when
    /// the frame was copied rather than moved to a port.
    fn forward_inbound(&self, dst: [u8; 6], src: [u8; 6], frame: Vec<u8>) -> Vec<u8> {
        self.unlearn(src);
        if dst[0] & 1 != 0 {
            // Broadcast or multicast group bit set.
            self.flood(&frame);
            return frame;
        }
        let owner = self.macs.lock().unwrap().get(&dst).map(|&(p, _)| p);
        let Some(port_id) = owner else {
            self.flood(&frame);
            return frame;
        };
        let target = self
            .ports
            .lock()
            .unwrap()
            .get(&port_id)
            .map(|p| p.out.clone());
        match target {
            Some(out) => match out.try_send(frame) {
                Ok(()) => Vec::new(),
                Err(mpsc::error::TrySendError::Full(frame)) => frame,
                Err(mpsc::error::TrySendError::Closed(frame)) => {
                    self.evict_port(port_id);
                    frame
                }
            },
            // Learned port is gone: flood so the frame is not black-holed.
            None => {
                self.flood(&frame);
                frame
            }
        }
    }

    /// Clone the frame to every attached port. A `Closed` target schedules its own
    /// eviction; a `Full` target drops this frame (one slow client never stalls
    /// the others or the single TAP reader).
    fn flood(&self, frame: &[u8]) {
        self.flood_except(frame, None);
    }

    /// Clone the frame to every attached port but `except`, which is the port
    /// an egress frame arrived on.
    fn flood_except(&self, frame: &[u8], except: Option<u32>) {
        let targets: Vec<(u32, mpsc::Sender<Vec<u8>>)> = self
            .ports
            .lock()
            .unwrap()
            .iter()
            .filter(|(&id, _)| Some(id) != except)
            .map(|(&id, p)| (id, p.out.clone()))
            .collect();
        let mut closed = Vec::new();
        for (id, out) in targets {
            if let Err(mpsc::error::TrySendError::Closed(_)) = out.try_send(frame.to_vec()) {
                closed.push(id);
            }
        }
        for id in closed {
            self.evict_port(id);
        }
    }

    /// Remove a port and purge every MAC it owned. Idempotent: a port already gone
    /// (e.g. dropped by its `SwitchHandle`) leaves the maps untouched.
    fn evict_port(&self, port_id: u32) {
        self.ports.lock().unwrap().remove(&port_id);
        self.macs
            .lock()
            .unwrap()
            .retain(|_, &mut (p, _)| p != port_id);
    }

    /// Learn that `src` lives behind `port`. Skips group/zero sources (never a real
    /// station). Honors `MAX_MACS_PER_SWITCH`: at the cap, an existing MAC still
    /// updates (its port and timestamp move) but a new MAC is refused, so one
    /// client cannot exhaust the table.
    fn learn(&self, src: [u8; 6], port: u32) {
        if is_group_or_zero(&src) {
            return;
        }
        let mut macs = self.macs.lock().unwrap();
        match macs.get_mut(&src) {
            Some(entry) => *entry = (port, Instant::now()),
            None => {
                if macs.len() < MAX_MACS_PER_SWITCH {
                    macs.insert(src, (port, Instant::now()));
                }
            }
        }
    }

    /// Forget whichever port owns `src`. Learning happens on port egress alone,
    /// so a station that moved to the device's side keeps its old binding until
    /// this drops it. Skips group/zero sources.
    fn unlearn(&self, src: [u8; 6]) {
        if is_group_or_zero(&src) {
            return;
        }
        self.macs.lock().unwrap().remove(&src);
    }

    /// Learn one egress frame's source MAC onto `port`, then write it to the shared
    /// device. The single egress idiom both the UDP and TCP port halves use.
    /// Concurrent writes from N port relays are safe: the device is opened
    /// `IFF_NO_PI`, so one `write()` carries exactly one whole frame and the kernel
    /// serializes writes on the fd atomically per frame.
    ///
    /// A `port_to_port` switch routes the frame among its own ports first, and
    /// writes to the device only when the destination is not a station it has
    /// learned behind another port.
    ///
    /// Only an L2 switch learns and routes here: an L3 device's packets have no
    /// Ethernet header, so their leading bytes are an IP header, not addresses.
    async fn learn_and_write_egress(&self, frame: &[u8], port: u32) -> crate::Result<()> {
        let Some((dst, src)) = dst_src(frame).filter(|_| self.is_l2) else {
            return self.tap.write_frame(frame).await;
        };
        self.learn(src, port);
        if self.port_to_port && self.forward_egress(dst, frame, port) {
            return Ok(());
        }
        self.tap.write_frame(frame).await
    }

    /// Route one egress frame among the other ports and report whether it is
    /// delivered. Unicast for a station learned behind another port goes to
    /// that port alone; broadcast and multicast are copied to every other port
    /// and still owed to the device. Unknown unicast is owed to the device
    /// alone: every station behind a port is learned from that port's own
    /// egress, so an unknown one is out on the segment.
    fn forward_egress(&self, dst: [u8; 6], frame: &[u8], from: u32) -> bool {
        if dst[0] & 1 != 0 {
            self.flood_except(frame, Some(from));
            return false;
        }
        let owner = self.macs.lock().unwrap().get(&dst).map(|&(p, _)| p);
        let Some(port_id) = owner.filter(|&p| p != from) else {
            return false;
        };
        let target = self
            .ports
            .lock()
            .unwrap()
            .get(&port_id)
            .map(|p| p.out.clone());
        match target {
            Some(out) => match out.try_send(frame.to_vec()) {
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.evict_port(port_id);
                    false
                }
                // A full port drops this frame rather than stalling the
                // sender, as the inbound path does.
                _ => true,
            },
            None => false,
        }
    }

    /// Attach a new client. Allocates a PortId, a bounded egress queue, and a
    /// cancel; the returned `SwitchHandle` is the relay's view of the port and
    /// detaches it on drop. The client counts as heard from the moment it
    /// attaches, which holds for every transport that carries its own liveness:
    /// a stream, or a peer session with its own keepalive.
    ///
    /// An L3 (`--tun`) switch supports exactly one client: while a client that
    /// has been heard from holds the slot, a second attach is refused with `Err`,
    /// so the caller drops that bridge connection without disturbing the
    /// established one.
    pub fn add_port(
        self: &Arc<Self>,
        transport: u8,
        peer: Option<SocketAddr>,
    ) -> crate::Result<SwitchHandle> {
        self.attach(transport, peer, true)
    }

    /// Attach a client whose bridge rides the datagram channel. The port starts
    /// unproven: the datagram handshake completes on the client's first message,
    /// so a client that gave up waiting for the reply leaves a port behind that
    /// never carries a frame. An unproven port does not hold a tun switch's
    /// single client slot: a fresh attach supersedes it.
    pub fn add_dgram_port(self: &Arc<Self>, peer: SocketAddr) -> crate::Result<SwitchHandle> {
        self.attach(2, Some(peer), false)
    }

    /// Build the port and admit it. The admission test and the insert happen
    /// together under the `ports` lock so two simultaneous attaches cannot both
    /// pass it.
    fn attach(
        self: &Arc<Self>,
        transport: u8,
        peer: Option<SocketAddr>,
        proven: bool,
    ) -> crate::Result<SwitchHandle> {
        let port_id = self.next_port.fetch_add(1, Ordering::Relaxed);
        let (out_tx, out_rx) = mpsc::channel(SWITCH_PORT_CAP);
        let cancel = Arc::new(Notify::new());
        let stats = PortStats::new();
        let proven = Arc::new(AtomicBool::new(proven));
        let mut superseded: Vec<(u32, Arc<Notify>)> = Vec::new();
        {
            let mut ports = self.ports.lock().unwrap();
            if !self.is_l2 {
                if ports.values().any(|p| p.proven.load(Ordering::Acquire)) {
                    return Err(
                        "tun bridge already has a client; a tun server serves one client".into(),
                    );
                }
                superseded = ports.drain().map(|(id, p)| (id, p.cancel)).collect();
            }
            ports.insert(
                port_id,
                SwitchPort {
                    out: out_tx,
                    cancel: cancel.clone(),
                    stats: stats.clone(),
                    name: Mutex::new(None),
                    transport,
                    peer,
                    proven: proven.clone(),
                },
            );
        }
        // End each superseded port's relay outside the `ports` lock.
        for (id, cancel) in superseded {
            cancel.notify_one();
            self.evict_port(id);
        }
        Ok(SwitchHandle {
            switch: self.clone(),
            port_id,
            out_rx: Some(out_rx),
            cancel,
            stats,
            proven,
        })
    }

    /// Record the label a client announced for its port. Sanitizes to printable
    /// characters and caps the length, so a crafted name cannot inject terminal
    /// control sequences or grow without bound; an empty name leaves the port
    /// unnamed so the fleet view keeps its address/port fallback.
    fn set_port_name(&self, port_id: u32, name: &str) {
        let clean: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
        if clean.is_empty() {
            return;
        }
        if let Some(port) = self.ports.lock().unwrap().get(&port_id) {
            *port.name.lock().unwrap() = Some(clean);
        }
    }

    /// The source MACs learned behind `port_id`, capped for display. Locks only the
    /// MAC table, so it never nests with the `ports` lock.
    fn macs_for(&self, port_id: u32) -> Vec<[u8; 6]> {
        self.macs
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, &(p, _))| p == port_id)
            .map(|(mac, _)| *mac)
            .take(MAX_DISPLAY_MACS)
            .collect()
    }

    /// A point-in-time view of every attached port for the admin fleet report.
    /// Copies each port's fields out under the `ports` lock, releases it, then reads
    /// the MAC table, so a port's MAC scan never runs while the `ports` lock is held.
    pub fn ports_snapshot(&self) -> Vec<BridgePortInfo> {
        let rows: Vec<BridgePortInfo> = {
            let ports = self.ports.lock().unwrap();
            ports
                .iter()
                .map(|(&port_id, p)| {
                    let uptime = p.stats.created.elapsed().as_secs().min(u32::MAX as u64) as u32;
                    let last = p.stats.last_activity.load(Ordering::Relaxed);
                    BridgePortInfo {
                        port_id,
                        name: p.name.lock().unwrap().clone(),
                        transport: p.transport,
                        peer: p.peer,
                        macs: Vec::new(),
                        rx_bytes: widen_counter(p.stats.rx_bytes.load(Ordering::Relaxed)),
                        rx_frames: widen_counter(p.stats.rx_frames.load(Ordering::Relaxed)),
                        tx_bytes: widen_counter(p.stats.tx_bytes.load(Ordering::Relaxed)),
                        tx_frames: widen_counter(p.stats.tx_frames.load(Ordering::Relaxed)),
                        uptime_secs: uptime,
                        idle_secs: uptime.saturating_sub(last),
                    }
                })
                .collect()
        };
        rows.into_iter()
            .map(|mut r| {
                r.macs = self.macs_for(r.port_id);
                r
            })
            .collect()
    }
}

/// A client's attachment to the switch. Owns the inbound (TAP -> client) receiver
/// and the port's cancel; on drop it detaches the port and purges the MACs it
/// owned, so a disconnecting client never leaves a dead Sender slot or a stale
/// learned route behind.
#[cfg(target_os = "linux")]
pub struct SwitchHandle {
    switch: Arc<TapSwitch>,
    port_id: u32,
    out_rx: Option<mpsc::Receiver<Vec<u8>>>,
    cancel: Arc<Notify>,
    stats: Arc<PortStats>,
    proven: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl SwitchHandle {
    /// Record a client-announced label for this port. Used by the stream (TCP)
    /// bridge, which carries the name in its first frame; the datagram bridge sets
    /// it from an in-band name frame instead.
    pub fn set_name(&self, name: &str) {
        self.switch.set_port_name(self.port_id, name);
    }

    /// Record that the client behind this port has been heard from, so a later
    /// attach on a tun switch is refused rather than superseding it.
    fn prove(&self) {
        self.proven.store(true, Ordering::Release);
    }
}

#[cfg(target_os = "linux")]
impl Drop for SwitchHandle {
    fn drop(&mut self) {
        self.switch.evict_port(self.port_id);
    }
}

/// Per-client half of the switch over the unreliable datagram channel (UDP
/// transport). Egress frames from the client learn their source MAC onto this
/// port and write to the shared TAP; inbound frames the switch routed to this
/// port go out on `tx`. The relay stops on `handle.cancel` (fired by the TAP
/// reader on device death and by `SwitchHandle`'s drop), on channel close, or on
/// the idle reaper; idle and keepalive semantics match the client's `tap_dgram`.
#[cfg(target_os = "linux")]
pub async fn switch_port_dgram(mut handle: SwitchHandle, rx: DgramRx, tx: DgramTx) {
    let out_rx = handle.out_rx.take().expect("switch port out_rx");
    let cancel = handle.cancel.clone();
    let local = DgramLocal::Port {
        handle,
        out_rx,
        last: Vec::new(),
    };
    dgram_relay(local, rx, tx, UDP_IDLE, Some(cancel), None).await;
}

/// Per-client half of the switch over the reliable Noise stream (TCP fallback).
/// Same routing as `switch_port_dgram`: egress frames learn their source and
/// write to the shared TAP, switch-routed inbound frames go out on the stream,
/// with the `stream_relay` idle/probe watchdog. This port's `cancel` (fired by
/// the TAP reader on device death and by `SwitchHandle`'s drop) is the stop
/// signal handed to the relay.
#[cfg(target_os = "linux")]
pub async fn switch_port_stream(mut handle: SwitchHandle, nr: NoiseReader, nw: NoiseWriter) {
    let out_rx = handle.out_rx.take().expect("switch port out_rx");
    let local_r = LocalRead::Port {
        rx: out_rx,
        switch: handle.switch.clone(),
        stats: handle.stats.clone(),
        last: Vec::new(),
    };
    let local_w = LocalWrite::Port {
        switch: handle.switch.clone(),
        port_id: handle.port_id,
        stats: handle.stats.clone(),
    };
    stream_relay(
        local_r,
        local_w,
        nr,
        nw,
        TCP_IDLE,
        Some(handle.cancel.clone()),
    )
    .await;
}

/// A peer session is neither of the two control transports the switch records
/// for its ports, and direct and relayed are the same thing above it.
#[cfg(target_os = "linux")]
pub(crate) const TRANSPORT_PEER: u8 = 0;

/// Per-pair half of the switch over an inner peer session: the exit provider's
/// side of an L3 pair, or one consumer's port on a segment provider's L2
/// switch. A frame from the peer writes to the shared device; a frame the
/// switch routed to this port goes out to the peer.
/// The session carries its own keepalive and reaps a silent peer at its own
/// deadline, so this half keeps no idle window: it ends when the session dies,
/// when the device write fails, or when the port is cancelled (the device
/// reader on device death, `SwitchHandle`'s drop otherwise).
#[cfg(target_os = "linux")]
pub async fn switch_port_peer(mut handle: SwitchHandle, mut session: crate::peer::PeerSession) {
    let mut out_rx = handle.out_rx.take().expect("switch port out_rx");
    let switch = handle.switch.clone();
    let port_id = handle.port_id;
    let stats = handle.stats.clone();
    let cancel = handle.cancel.clone();
    loop {
        // The borrow of the session ends with this statement, so the send in
        // the outbound arm below is free to take it again.
        let step = tokio::select! {
            _ = cancel.notified() => PeerStep::Cancel,
            frame = session.recv() => PeerStep::FromPeer(frame),
            frame = out_rx.recv() => PeerStep::ToPeer(frame),
        };
        let alive = match step {
            PeerStep::Cancel => false,
            PeerStep::FromPeer(Some(frame)) => {
                stats.note_rx(frame.len());
                match switch.learn_and_write_egress(&frame, port_id).await {
                    Ok(()) => true,
                    Err(e) => {
                        crate::elog!("peer port: the device write failed: {e}");
                        false
                    }
                }
            }
            PeerStep::ToPeer(Some(frame)) => {
                stats.note_tx(frame.len());
                session.send(&frame).await.is_ok()
            }
            PeerStep::FromPeer(None) | PeerStep::ToPeer(None) => false,
        };
        if !alive {
            break;
        }
    }
}

#[cfg(target_os = "linux")]
enum PeerStep {
    Cancel,
    FromPeer(Option<Vec<u8>>),
    ToPeer(Option<Vec<u8>>),
}

/// Client side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_client_stateless(local: UdpSocket, rx: DgramRx, tx: DgramTx, idle: Duration) {
    let local = DgramLocal::Udp {
        socket: local,
        buf: vec![0u8; UDP_BUF],
    };
    dgram_relay(local, rx, tx, idle, None, None).await;
}

/// Server side of a UDP-forward stream over the raw datagram channel. Replies
/// leave from the local address the public source sent to.
pub async fn udp_server_stateless(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    local: Option<LocalAddr>,
    dgram_rx: Inbound,
    rx: DgramRx,
    tx: DgramTx,
    idle: Duration,
) {
    let local = DgramLocal::Server {
        socket,
        src,
        local,
        dgram_rx,
        last: Vec::new(),
    };
    dgram_relay(local, rx, tx, idle, None, None).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{client_handshake, derive_psk, server_handshake};
    use tokio::sync::mpsc;

    async fn noise_pair() -> (NoiseReader, NoiseWriter, NoiseReader, NoiseWriter) {
        let psk = derive_psk("bridge relay test");
        let (a, b) = tokio::io::duplex(1 << 16);
        let srv = crate::spawn(async move { server_handshake(b, &psk).await.unwrap() });
        let (cr, cw) = client_handshake(a, &psk).await.unwrap();
        let (sr, sw) = srv.await.unwrap();
        (cr, cw, sr, sw)
    }

    // (a) A peer that never sends and never reads (so probes pile up unanswered)
    // makes the relay reap within roughly the idle window.
    #[tokio::test(start_paused = true)]
    async fn black_holed_peer_is_reaped() {
        let (cr, cw, _sr, _sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let start = tokio::time::Instant::now();
        // Keep the peer halves alive but inert; dropping them would close the
        // stream and reap via the error path instead of the idle watchdog.
        let relay = crate::spawn(stream_relay(
            LocalRead::Chan(feed_rx, Vec::new()),
            LocalWrite::Chan(out_tx),
            cr,
            cw,
            TCP_IDLE,
            None,
        ));
        relay.await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= TCP_IDLE && elapsed < TCP_IDLE * 2,
            "reaped at {elapsed:?}, expected near {TCP_IDLE:?}"
        );
    }

    // A per-forward idle window narrower than TCP_IDLE reaps a black-holed
    // relay at that window, not at the default.
    #[tokio::test(start_paused = true)]
    async fn custom_idle_window_reaps_early() {
        let idle = Duration::from_secs(10);
        let (cr, cw, _sr, _sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let start = tokio::time::Instant::now();
        let relay = crate::spawn(stream_relay(
            LocalRead::Chan(feed_rx, Vec::new()),
            LocalWrite::Chan(out_tx),
            cr,
            cw,
            idle,
            None,
        ));
        relay.await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= idle && elapsed < TCP_IDLE,
            "reaped at {elapsed:?}, expected near {idle:?}"
        );
    }

    // A zero idle window from a library caller must not panic the probe
    // interval; the floored tick reaps the relay instead.
    #[tokio::test(start_paused = true)]
    async fn zero_idle_udp_relay_reaps_without_panic() {
        let (cr, cw, _sr, _sw) = noise_pair().await;
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        local.connect(local.local_addr().unwrap()).await.unwrap();
        udp_client(local, cr, cw, Duration::ZERO).await;
    }

    // (b) A peer that answers every probe keeps the relay alive well past the
    // idle window.
    #[tokio::test(start_paused = true)]
    async fn answered_probes_keep_relay_alive() {
        let (cr, cw, mut sr, mut sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let peer = crate::spawn(async move {
            // Echo a keepalive back for every inbound frame, refreshing last_in.
            while let Ok(_m) = sr.recv().await {
                if sw.probe().await.is_err() {
                    break;
                }
            }
        });
        let relay = crate::spawn(stream_relay(
            LocalRead::Chan(feed_rx, Vec::new()),
            LocalWrite::Chan(out_tx),
            cr,
            cw,
            TCP_IDLE,
            None,
        ));
        // Far longer than one idle window: a live peer must not be reaped.
        if tokio::time::timeout(TCP_IDLE * 5, relay).await.is_ok() {
            panic!("relay reaped a peer that answered probes");
        }
        peer.abort();
    }

    // (c) Empty keepalive frames from the peer are never forwarded to the local
    // write side; real data frames are.
    #[tokio::test(start_paused = true)]
    async fn empty_keepalives_not_forwarded() {
        let (cr, cw, mut sr, mut sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let relay = crate::spawn(stream_relay(
            LocalRead::Chan(feed_rx, Vec::new()),
            LocalWrite::Chan(out_tx),
            cr,
            cw,
            TCP_IDLE,
            None,
        ));
        // Drain inbound on the peer so the relay's nw.send/probe never blocks.
        let drain = crate::spawn(async move { while sr.recv().await.is_ok() {} });
        sw.probe().await.unwrap(); // empty keepalive: must be dropped
        sw.send(b"real-frame").await.unwrap();
        sw.probe().await.unwrap(); // another keepalive
        let got = out_rx.recv().await.unwrap();
        assert_eq!(got, b"real-frame");
        // Nothing else should arrive: only the single data frame was forwarded.
        assert!(out_rx.try_recv().is_err());
        relay.abort();
        drain.abort();
    }
}

/// One Ethernet frame: 6-byte dst, 6-byte src, 2-byte ethertype, payload.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn frame(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype
    f.extend_from_slice(payload);
    f
}

#[cfg(all(test, target_os = "linux"))]
mod switch_tests {
    use super::*;
    use crate::tap::DeviceFd;

    const M1: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const M2: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
    const BCAST: [u8; 6] = [0xff; 6];
    const MCAST: [u8; 6] = [0x01, 0, 0x5e, 0, 0, 0x01];
    const CLIENT: &str = "198.51.100.7:41000";

    /// An L2 switch with no live reader, plus the dummy TAP backing it (kept alive
    /// by the returned guard fd so the device is not closed mid-test). The backing
    /// socketpair is `SOCK_DGRAM`, so it models per-frame boundaries; it is not the
    /// real TAP `IFF_NO_PI` fd, only a stand-in the switch logic reads and writes.
    fn test_switch() -> (Arc<TapSwitch>, DeviceFd) {
        let (dev, peer) = crate::tap::TapDevice::socketpair_for_test(1500).unwrap();
        let sw = TapSwitch::detached(Arc::new(dev), true);
        (sw, DeviceFd(peer))
    }

    /// A tun switch with no reader running, plus the fd that keeps its dummy
    /// device open for the test.
    fn test_tun_switch() -> (Arc<TapSwitch>, DeviceFd) {
        let (dev, peer) = crate::tap::TapDevice::socketpair_for_test(1500).unwrap();
        (TapSwitch::detached(Arc::new(dev), false), DeviceFd(peer))
    }

    // A learned unicast destination is delivered only to the port that owns it,
    // never flooded to the other ports.
    #[tokio::test]
    async fn learn_then_unicast_delivers_to_owner() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port(1, None).unwrap();
        let mut b = sw.add_port(1, None).unwrap();
        // M1 lives behind port a.
        sw.learn(M1, a.port_id);

        let f = frame(M1, M2, b"hi");
        sw.forward_inbound(M1, M2, f.clone());

        assert_eq!(a.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert!(b.out_rx.as_mut().unwrap().try_recv().is_err());
    }

    // A broadcast destination floods to every attached port.
    #[tokio::test]
    async fn broadcast_floods_all_ports() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port(1, None).unwrap();
        let mut b = sw.add_port(1, None).unwrap();
        let f = frame(BCAST, M1, b"b");
        sw.forward_inbound(BCAST, M1, f.clone());
        assert_eq!(a.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // An unknown unicast (no learned owner) floods to every port.
    #[tokio::test]
    async fn unknown_unicast_floods() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port(1, None).unwrap();
        let mut b = sw.add_port(1, None).unwrap();
        let f = frame(M1, M2, b"u");
        sw.forward_inbound(M1, M2, f.clone());
        assert_eq!(a.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // A multicast destination (group bit set) floods to every port.
    #[tokio::test]
    async fn multicast_floods() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port(1, None).unwrap();
        let mut b = sw.add_port(1, None).unwrap();
        let f = frame(MCAST, M1, b"m");
        sw.forward_inbound(MCAST, M1, f.clone());
        assert_eq!(a.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // With exactly one port, the live reader's fast path forwards any buffer
    // untouched, including a sub-14-byte (non-Ethernet/L3) one. The reader spawns
    // here via `new`, so a frame injected on the TAP peer reaches the sole port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_port_fast_path() {
        let (dev, peer) = crate::tap::TapDevice::socketpair_for_test(1500).unwrap();
        let sw = TapSwitch::new(Arc::new(dev), true);
        let mut p = sw.add_port(1, None).unwrap();

        // A raw L3-ish buffer shorter than an Ethernet header; the fast path must
        // forward it without parsing.
        let raw = vec![0x45u8, 0, 0, 20, 0, 0]; // 6 bytes: too short to be Ethernet
        let n = unsafe { libc::write(peer, raw.as_ptr() as *const libc::c_void, raw.len()) };
        assert_eq!(n, raw.len() as isize);

        let got = tokio::time::timeout(Duration::from_secs(2), p.out_rx.as_mut().unwrap().recv())
            .await
            .expect("fast-path frame not delivered")
            .unwrap();
        assert_eq!(got, raw);
        unsafe { libc::close(peer) };
    }

    // A MAC that moves to a new port (client reconnect on a different port) is
    // relearned, so later inbound unicast follows it to the new owner.
    #[tokio::test]
    async fn relearn_on_reconnect() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port(1, None).unwrap();
        let mut b = sw.add_port(1, None).unwrap();
        sw.learn(M1, a.port_id);
        sw.learn(M1, b.port_id); // M1 moved to port b

        let f = frame(M1, M2, b"x");
        sw.forward_inbound(M1, M2, f.clone());
        assert!(a.out_rx.as_mut().unwrap().try_recv().is_err());
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // A station that transmits from the device's side loses the port binding it
    // held, so the next unicast for it from another port goes to the device
    // instead of the port it left.
    #[tokio::test]
    async fn device_inbound_source_unlearns_its_port() {
        let (dev, peer) = crate::tap::TapDevice::socketpair_for_test(1500).unwrap();
        let _g = DeviceFd(peer);
        let sw = TapSwitch::segment(Arc::new(dev));
        let mut a = sw.add_port(1, None).unwrap();
        let mut b = sw.add_port(1, None).unwrap();
        sw.learn(M1, a.port_id);
        sw.learn(M2, b.port_id);

        // M1 moved: it now transmits on the device's side, addressing M2.
        let moved = frame(M2, M1, b"moved");
        sw.forward_inbound(M2, M1, moved.clone());
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), moved);
        assert!(!sw.macs.lock().unwrap().contains_key(&M1));

        // B's unicast for M1 goes to the device, not to A.
        let after = frame(M1, M2, b"after");
        sw.learn_and_write_egress(&after, b.port_id).await.unwrap();
        assert_eq!(crate::tap::read_device(peer).await, after);
        assert!(a.out_rx.as_mut().unwrap().try_recv().is_err());
    }

    // Dropping a SwitchHandle detaches its port and purges every MAC it owned, so a
    // later frame for that MAC floods (no stale route) and reaches no dead port.
    #[tokio::test]
    async fn handle_drop_evicts_port_and_macs() {
        let (sw, _g) = test_switch();
        let a = sw.add_port(1, None).unwrap();
        let a_id = a.port_id;
        let mut b = sw.add_port(1, None).unwrap();
        sw.learn(M1, a_id);
        assert!(sw.macs.lock().unwrap().contains_key(&M1));

        drop(a);
        assert!(!sw.ports.lock().unwrap().contains_key(&a_id));
        assert!(!sw.macs.lock().unwrap().contains_key(&M1));

        // Now-unknown M1 floods to the surviving port only.
        let f = frame(M1, M2, b"y");
        sw.forward_inbound(M1, M2, f.clone());
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // add_port records its transport and peer; ports_snapshot reports them with
    // zeroed counters and no learned MACs.
    #[tokio::test]
    async fn ports_snapshot_reports_metadata() {
        let (sw, _g) = test_switch();
        let peer: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let _a = sw.add_port(2, Some(peer)).unwrap();
        let snap = sw.ports_snapshot();
        assert_eq!(snap.len(), 1);
        let p = &snap[0];
        assert_eq!(p.transport, 2);
        assert_eq!(p.peer, Some(peer));
        assert!(p.name.is_none());
        assert_eq!(
            (p.rx_bytes, p.rx_frames, p.tx_bytes, p.tx_frames),
            (0, 0, 0, 0)
        );
        assert!(p.macs.is_empty());
    }

    // Counters bumped on a port's stats (as the relays do per frame) surface in the
    // snapshot, and a dropped handle removes the port from it.
    #[tokio::test]
    async fn ports_snapshot_reports_counters_and_eviction() {
        let (sw, _g) = test_switch();
        let a = sw.add_port(1, None).unwrap();
        a.stats.note_rx(100);
        a.stats.note_rx(40);
        a.stats.note_tx(10);
        let p = sw
            .ports_snapshot()
            .into_iter()
            .find(|p| p.port_id == a.port_id)
            .expect("port present");
        assert_eq!((p.rx_bytes, p.rx_frames), (140, 2));
        assert_eq!((p.tx_bytes, p.tx_frames), (10, 1));

        let id = a.port_id;
        drop(a);
        assert!(sw.ports_snapshot().iter().all(|p| p.port_id != id));
    }

    // A client-announced name shows in the snapshot with control characters
    // stripped and the length capped; an empty name never clears an existing one.
    #[tokio::test]
    async fn set_port_name_sanitizes_and_caps() {
        let (sw, _g) = test_switch();
        let a = sw.add_port(1, None).unwrap();
        sw.set_port_name(a.port_id, "rpi\x07-1a2b");
        let name = |sw: &Arc<TapSwitch>, id| {
            sw.ports_snapshot()
                .into_iter()
                .find(|p| p.port_id == id)
                .and_then(|p| p.name)
        };
        assert_eq!(name(&sw, a.port_id).as_deref(), Some("rpi-1a2b"));
        // An empty name leaves the prior name in place.
        sw.set_port_name(a.port_id, "");
        assert_eq!(name(&sw, a.port_id).as_deref(), Some("rpi-1a2b"));
        // An over-long name is capped at 64 characters.
        let b = sw.add_port(1, None).unwrap();
        sw.set_port_name(b.port_id, &"x".repeat(200));
        assert_eq!(name(&sw, b.port_id).map(|s| s.chars().count()), Some(64));
    }

    // macs_for and the snapshot report only the MACs learned behind that port.
    #[tokio::test]
    async fn macs_for_isolates_ports() {
        let (sw, _g) = test_switch();
        let a = sw.add_port(1, None).unwrap();
        let b = sw.add_port(1, None).unwrap();
        sw.learn(M1, a.port_id);
        sw.learn(M2, b.port_id);
        assert_eq!(sw.macs_for(a.port_id), vec![M1]);
        assert_eq!(sw.macs_for(b.port_id), vec![M2]);
        let p = sw
            .ports_snapshot()
            .into_iter()
            .find(|p| p.port_id == a.port_id)
            .expect("port present");
        assert_eq!(p.macs, vec![M1]);
    }

    // Learning stops growing the table at MAX_MACS_PER_SWITCH, but entries already
    // present still update (their port can still move).
    #[tokio::test]
    async fn mac_table_cap() {
        let (sw, _g) = test_switch();
        let p = sw.add_port(1, None).unwrap();

        for i in 0..MAX_MACS_PER_SWITCH as u32 {
            let b = i.to_be_bytes();
            sw.learn([0x02, b[0], b[1], b[2], b[3], 0x00], p.port_id);
        }
        assert_eq!(sw.macs.lock().unwrap().len(), MAX_MACS_PER_SWITCH);

        // A brand-new MAC at the cap is refused.
        sw.learn([0x02, 0xff, 0xff, 0xff, 0xff, 0xff], p.port_id);
        assert_eq!(sw.macs.lock().unwrap().len(), MAX_MACS_PER_SWITCH);

        // An existing MAC still updates (move it to a fresh port id).
        let first = [0x02u8, 0, 0, 0, 0, 0x00];
        assert!(sw.macs.lock().unwrap().contains_key(&first));
        sw.learn(first, 999);
        assert_eq!(sw.macs.lock().unwrap().len(), MAX_MACS_PER_SWITCH);
        assert_eq!(sw.macs.lock().unwrap().get(&first).unwrap().0, 999);
    }

    // A closed (full-then-gone) port never blocks delivery to the others: a flood
    // with one closed receiver still reaches the live port and evicts the dead one.
    #[tokio::test]
    async fn closed_port_does_not_block_others() {
        let (sw, _g) = test_switch();
        let dead = sw.add_port(1, None).unwrap();
        let dead_id = dead.port_id;
        let mut live = sw.add_port(1, None).unwrap();
        // Close the dead port's receiver without going through Drop (model a relay
        // that stopped draining and dropped its rx).
        let mut dead = dead;
        drop(dead.out_rx.take());

        let f = frame(BCAST, M1, b"z");
        sw.flood(&f);

        // The live port still got it; the dead port was evicted from `ports`.
        assert_eq!(live.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert!(!sw.ports.lock().unwrap().contains_key(&dead_id));
    }

    // An L3 (`--tun`) switch serves exactly one client: the first port attaches,
    // the second is refused. Dropping the first frees the slot for a reconnect. An
    // L2 (`--tap`) switch admits many ports.
    #[tokio::test]
    async fn tun_switch_admits_one_port_l2_admits_many() {
        let (tun, _g) = test_tun_switch();

        let first = tun.add_port(1, None).expect("first tun port attaches");
        assert!(
            tun.add_port(1, None).is_err(),
            "second tun port must be refused"
        );
        drop(first);
        let _reattach = tun
            .add_port(1, None)
            .expect("a freed tun slot accepts a reconnect");

        let (sw, _g2) = test_switch(); // is_l2 = true
        let _ports: Vec<_> = (0..8)
            .map(|_| {
                sw.add_port(1, None)
                    .expect("an l2 switch admits many ports")
            })
            .collect();
        assert_eq!(sw.ports.lock().unwrap().len(), 8);
    }

    // A datagram bridge port claims the tun switch's one slot before its client
    // has been heard from, because the datagram handshake completes on the
    // client's first message: a client that gave up waiting for the reply still
    // leaves a port behind. The next client takes the slot from that claim
    // instead of being refused, and the superseded relay is cancelled.
    #[tokio::test]
    async fn an_unheard_dgram_claim_gives_way_to_the_next_client() {
        let (tun, _g) = test_tun_switch();

        let abandoned = tun.add_dgram_port(CLIENT.parse().unwrap()).unwrap();
        let cancelled = abandoned.cancel.clone();
        let fresh = tun
            .add_port(1, None)
            .expect("a claim nobody has been heard on must not hold the slot");
        assert!(!tun.ports.lock().unwrap().contains_key(&abandoned.port_id));
        timeout(Duration::from_secs(5), cancelled.notified())
            .await
            .expect("the superseded port's relay must be told to tear down");

        // The superseded handle's drop must not take the port that replaced it.
        drop(abandoned);
        assert!(tun.ports.lock().unwrap().contains_key(&fresh.port_id));
    }

    // One frame from the client is proof enough: from then on the datagram port
    // holds the tun switch's one slot and a second client is refused.
    #[tokio::test]
    async fn a_dgram_client_that_sends_keeps_the_tun_slot() {
        let (tun, _g) = test_tun_switch();
        let handle = tun.add_dgram_port(CLIENT.parse().unwrap()).unwrap();

        let psk = crate::noise::derive_psk("switch port dgram");
        let (a, b) = tokio::io::duplex(8192);
        let responder =
            crate::spawn(
                async move { crate::noise::server_handshake_stateless(b, &psk, &[]).await },
            );
        let client = Arc::new(
            crate::noise::client_handshake_stateless(a, &psk, 0)
                .await
                .unwrap(),
        );
        let server = Arc::new(responder.await.unwrap().unwrap().1);

        // One keepalive from the client, routed the way the session's router
        // hands a datagram to the port: class byte and tag stripped.
        let (client_out, mut client_pkts) = mpsc::channel(4);
        DgramTx::new(client_out, 0, client).probe().await.unwrap();
        let pkt = client_pkts.recv().await.unwrap().pkt;
        let (inbound_tx, inbound_rx) = mpsc::channel(4);
        inbound_tx.send(pkt[5..].to_vec()).await.unwrap();

        let (out_tx, _out_rx) = mpsc::channel(4);
        let relay = crate::spawn(switch_port_dgram(
            handle,
            DgramRx::new(crate::kcp::Inbound::from(inbound_rx), server.clone()),
            DgramTx::new(out_tx, 0, server),
        ));
        timeout(Duration::from_secs(5), async {
            while !tun
                .ports
                .lock()
                .unwrap()
                .values()
                .any(|p| p.proven.load(Ordering::Acquire))
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a frame from the client must prove the port");

        assert!(
            tun.add_port(1, None).is_err(),
            "a port whose client has been heard from keeps the slot"
        );
        relay.abort();
    }
}
