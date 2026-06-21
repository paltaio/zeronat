use std::future::Future;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::dgram::{DgramRx, DgramTx, Frame};
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

/// The local plaintext side of a reliable relay. `read` yields the next chunk
/// (an empty `Vec` signals a closed local side, e.g. a TCP EOF); `write`
/// delivers a decrypted frame back to it. Both take `&mut self` and are driven
/// from independent halves so the two directions never serialize.
trait LocalRead {
    fn read(&mut self) -> impl Future<Output = crate::Result<Vec<u8>>>;
}
trait LocalWrite {
    fn write(&mut self, buf: &[u8]) -> impl Future<Output = crate::Result<()>>;
}

impl LocalRead for OwnedReadHalf {
    async fn read(&mut self) -> crate::Result<Vec<u8>> {
        let mut buf = [0u8; TCP_BUF];
        let n = AsyncReadExt::read(self, &mut buf).await?;
        Ok(buf[..n].to_vec()) // empty == EOF
    }
}
impl LocalWrite for OwnedWriteHalf {
    async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.write_all(buf).await?;
        Ok(())
    }
}

/// Copy frames both ways between a reliable local side and the encrypted Noise
/// stream, on a probe-then-reap watchdog. Returns when the local side closes,
/// the encrypted stream errors, the peer stops answering liveness probes for
/// TCP_IDLE, or `cancel` resolves.
///
/// Both directions run concurrently so a write blocked on backpressure in one
/// never stalls the other (serializing them can deadlock a full-duplex stream).
/// The down half marks a shared timestamp on every inbound frame (including
/// empty keepalive probes) and the up half emits a probe once the link has been
/// quiet for half the window; a live peer answers and refreshes the mark, so the
/// independent watchdog reaps only on a true black hole (no inbound frame for the
/// whole window). The mark is in whole seconds: 32-bit targets (mips) have no
/// AtomicU64 and second resolution is ample for a 120s window.
async fn stream_relay<R, W, C>(
    mut local_r: R,
    mut local_w: W,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
    cancel: C,
) where
    R: LocalRead,
    W: LocalWrite,
    C: Future<Output = ()>,
{
    // tokio's clock so the idle math and the watchdog's sleep share one time
    // source (and so a paused-time test can drive it deterministically).
    let base = tokio::time::Instant::now();
    let last_in = Arc::new(AtomicU32::new(0));
    let win = TCP_IDLE.as_secs();

    let up = async move {
        loop {
            match timeout(Duration::from_secs(win / 2), local_r.read()).await {
                Ok(r) => {
                    let m = r?;
                    if m.is_empty() {
                        break;
                    }
                    // Bound the send so a send-side black hole cannot park here
                    // forever and starve the idle watchdog below.
                    match timeout(UDP_SEND_TIMEOUT, nw.send(&m)).await {
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
            local_w.write(&m).await?;
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
        _ = cancel => {}
    }
}

/// Copy bytes both ways between a plaintext TCP stream and the encrypted
/// connection. Returns when either side closes or the peer stops answering
/// liveness probes for TCP_IDLE.
pub async fn tcp(plain: TcpStream, nr: NoiseReader, nw: NoiseWriter) {
    plain.set_nodelay(true).ok();
    let (pr, pw) = plain.into_split();
    stream_relay(pr, pw, nr, nw, std::future::pending()).await;
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

/// Local-side adapters for the TAP device: both halves share the device via
/// `Arc` because `read_frame`/`write_frame` take `&self`.
#[cfg(target_os = "linux")]
struct TapRead(Arc<TapDevice>);
#[cfg(target_os = "linux")]
struct TapWrite(Arc<TapDevice>);

#[cfg(target_os = "linux")]
impl LocalRead for TapRead {
    async fn read(&mut self) -> crate::Result<Vec<u8>> {
        // A TAP read is one whole Ethernet frame and never empty, so it never
        // collides with the empty-Vec EOF sentinel the relay uses for TCP.
        self.0.read_frame().await
    }
}
#[cfg(target_os = "linux")]
impl LocalWrite for TapWrite {
    async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.0.write_frame(buf).await
    }
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
pub async fn tap_dgram(tap: Arc<TapDevice>, mut rx: DgramRx, tx: DgramTx, cancel: Arc<Notify>) {
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            _ = cancel.notified() => false,
            frame = tap.read_frame() => match frame {
                Ok(f) => tx.send(&f).await.is_ok(),
                Err(_) => false,
            },
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    match f {
                        Frame::Keepalive => true,
                        Frame::Data(d) => tap.write_frame(&d).await.is_ok(),
                    }
                }
                None => false,
            },
            _ = tick.tick() => last_in.elapsed() < UDP_IDLE && tx.probe().await.is_ok(),
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
        TapRead(tap.clone()),
        TapWrite(tap),
        nr,
        nw,
        cancel.notified(),
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

/// One attached client on the software switch: a bounded sender that carries
/// inbound (TAP -> client) frames toward that client's relay, plus the cancel
/// that relay waits on so an evicted/closed port tears its relay down at once.
#[cfg(target_os = "linux")]
struct SwitchPort {
    out: mpsc::Sender<Vec<u8>>,
    cancel: Arc<Notify>,
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
/// supports exactly one client: `add_port` admits one port and refuses a second,
/// so the single-port fast path forwards L3 packets untouched and the
/// MAC-learning path is never reached.
#[cfg(target_os = "linux")]
pub struct TapSwitch {
    tap: Arc<TapDevice>,
    /// `true` for an L2 (TAP/Ethernet) device that supports MAC learning across
    /// many ports; `false` for an L3 (TUN) device, which serves one client only.
    is_l2: bool,
    ports: Mutex<HashMap<u64, SwitchPort>>,
    macs: Mutex<HashMap<[u8; 6], (u64, Instant)>>,
    next_port: AtomicU64,
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
        let sw = Arc::new(TapSwitch {
            tap,
            is_l2,
            ports: Mutex::new(HashMap::new()),
            macs: Mutex::new(HashMap::new()),
            next_port: AtomicU64::new(0),
        });
        let reader = sw.clone();
        tokio::spawn(async move { reader.tap_read_loop().await });
        sw
    }

    /// Build a switch over `tap` without spawning the reader loop, so a test drives
    /// `forward_inbound`/`flood`/`learn`/`add_port`/Drop deterministically against
    /// the port channels with no live TAP read consuming frames.
    #[cfg(test)]
    fn new_without_reader(tap: Arc<TapDevice>, is_l2: bool) -> Arc<Self> {
        Arc::new(TapSwitch {
            tap,
            is_l2,
            ports: Mutex::new(HashMap::new()),
            macs: Mutex::new(HashMap::new()),
            next_port: AtomicU64::new(0),
        })
    }

    /// Sole owner of `tap.read_frame()`: fan every inbound frame out to the right
    /// port(s). On an unrecoverable read error, cancel every port (so their relays
    /// reap) and exit, ending the switch's inbound path.
    async fn tap_read_loop(self: Arc<Self>) {
        loop {
            let frame = match self.tap.read_frame().await {
                Ok(f) => f,
                Err(_) => {
                    for port in self.ports.lock().unwrap().values() {
                        port.cancel.notify_one();
                    }
                    return;
                }
            };
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
            if let Some(out) = sole {
                let _ = out.try_send(frame);
                continue;
            }
            match dst_src(&frame) {
                Some((dst, _)) => self.forward_inbound(dst, frame),
                // No Ethernet header but more than one port: nothing to address it
                // to, so flood it to every port.
                None => self.flood(frame),
            }
        }
    }

    /// Forward one inbound frame by destination MAC: flood broadcast, multicast,
    /// and unknown unicast to every port; deliver learned unicast to the one
    /// owning port (falling back to a flood if that port has since vanished).
    fn forward_inbound(&self, dst: [u8; 6], frame: Vec<u8>) {
        if dst[0] & 1 != 0 {
            // Broadcast or multicast group bit set.
            self.flood(frame);
            return;
        }
        let owner = self.macs.lock().unwrap().get(&dst).map(|&(p, _)| p);
        let Some(port_id) = owner else {
            self.flood(frame);
            return;
        };
        let target = self
            .ports
            .lock()
            .unwrap()
            .get(&port_id)
            .map(|p| p.out.clone());
        match target {
            Some(out) => {
                if let Err(mpsc::error::TrySendError::Closed(_)) = out.try_send(frame) {
                    self.evict_port(port_id);
                }
            }
            // Learned port is gone: flood so the frame is not black-holed.
            None => self.flood(frame),
        }
    }

    /// Clone the frame to every attached port. A `Closed` target schedules its own
    /// eviction; a `Full` target drops this frame (one slow client never stalls
    /// the others or the single TAP reader).
    fn flood(&self, frame: Vec<u8>) {
        let targets: Vec<(u64, mpsc::Sender<Vec<u8>>)> = self
            .ports
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, p)| (id, p.out.clone()))
            .collect();
        let mut closed = Vec::new();
        for (id, out) in targets {
            if let Err(mpsc::error::TrySendError::Closed(_)) = out.try_send(frame.clone()) {
                closed.push(id);
            }
        }
        for id in closed {
            self.evict_port(id);
        }
    }

    /// Remove a port and purge every MAC it owned. Idempotent: a port already gone
    /// (e.g. dropped by its `SwitchHandle`) leaves the maps untouched.
    fn evict_port(&self, port_id: u64) {
        self.ports.lock().unwrap().remove(&port_id);
        self.macs.lock().unwrap().retain(|_, &mut (p, _)| p != port_id);
    }

    /// Learn that `src` lives behind `port`. Skips group/zero sources (never a real
    /// station). Honors `MAX_MACS_PER_SWITCH`: at the cap, an existing MAC still
    /// updates (its port and timestamp move) but a new MAC is refused, so one
    /// client cannot exhaust the table.
    fn learn(&self, src: [u8; 6], port: u64) {
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

    /// Learn one egress frame's source MAC onto `port`, then write it to the shared
    /// device. The single egress idiom both the UDP and TCP port halves use.
    /// Concurrent writes from N port relays are safe: the device is opened
    /// `IFF_NO_PI`, so one `write()` carries exactly one whole frame and the kernel
    /// serializes writes on the fd atomically per frame.
    async fn learn_and_write_egress(&self, frame: &[u8], port: u64) -> crate::Result<()> {
        if let Some((_, src)) = dst_src(frame) {
            self.learn(src, port);
        }
        self.tap.write_frame(frame).await
    }

    /// Attach a new client. Allocates a PortId, a bounded egress queue, and a
    /// cancel; the returned `SwitchHandle` is the relay's view of the port and
    /// detaches it on drop.
    ///
    /// An L3 (`--tun`) switch supports exactly one client: a second concurrent
    /// attach is refused with `Err`, so the caller drops that bridge connection
    /// without disturbing the established one. The cap check and the insert happen
    /// together under the `ports` lock so two simultaneous attaches cannot both
    /// pass it.
    pub fn add_port(self: &Arc<Self>) -> crate::Result<SwitchHandle> {
        let port_id = self.next_port.fetch_add(1, Ordering::Relaxed);
        let (out_tx, out_rx) = mpsc::channel(SWITCH_PORT_CAP);
        let cancel = Arc::new(Notify::new());
        {
            let mut ports = self.ports.lock().unwrap();
            if !self.is_l2 && !ports.is_empty() {
                return Err("tun bridge already has a client; a tun server serves one client".into());
            }
            ports.insert(
                port_id,
                SwitchPort {
                    out: out_tx,
                    cancel: cancel.clone(),
                },
            );
        }
        Ok(SwitchHandle {
            switch: self.clone(),
            port_id,
            out_rx: Some(out_rx),
            cancel,
        })
    }
}

/// A client's attachment to the switch. Owns the inbound (TAP -> client) receiver
/// and the port's cancel; on drop it detaches the port and purges the MACs it
/// owned, so a disconnecting client never leaves a dead Sender slot or a stale
/// learned route behind.
#[cfg(target_os = "linux")]
pub struct SwitchHandle {
    switch: Arc<TapSwitch>,
    port_id: u64,
    out_rx: Option<mpsc::Receiver<Vec<u8>>>,
    cancel: Arc<Notify>,
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
pub async fn switch_port_dgram(mut handle: SwitchHandle, mut rx: DgramRx, tx: DgramTx) {
    let mut out_rx = handle.out_rx.take().expect("switch port out_rx");
    let switch = handle.switch.clone();
    let port_id = handle.port_id;
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            _ = handle.cancel.notified() => false,
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    match f {
                        Frame::Keepalive => true,
                        Frame::Data(d) => switch.learn_and_write_egress(&d, port_id).await.is_ok(),
                    }
                }
                None => false,
            },
            f = out_rx.recv() => match f {
                Some(f) => tx.send(&f).await.is_ok(),
                None => false,
            },
            _ = tick.tick() => last_in.elapsed() < UDP_IDLE && tx.probe().await.is_ok(),
        };
        if !alive {
            break;
        }
    }
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
    let local_r = PortRead(out_rx);
    let local_w = PortWrite {
        switch: handle.switch.clone(),
        port_id: handle.port_id,
    };
    let port_cancel = handle.cancel.clone();
    let stop = async move { port_cancel.notified().await };
    stream_relay(local_r, local_w, nr, nw, stop).await;
}

/// `stream_relay` local-read half for a switch port: yields the next switch-routed
/// inbound frame (TAP -> client). A closed channel is the empty-Vec EOF sentinel,
/// which a switch frame never collides with (a TAP frame is never empty).
#[cfg(target_os = "linux")]
struct PortRead(mpsc::Receiver<Vec<u8>>);
/// `stream_relay` local-write half for a switch port: an egress frame (client ->
/// BRAS) learns its source MAC onto this port, then writes to the shared TAP.
#[cfg(target_os = "linux")]
struct PortWrite {
    switch: Arc<TapSwitch>,
    port_id: u64,
}

#[cfg(target_os = "linux")]
impl LocalRead for PortRead {
    async fn read(&mut self) -> crate::Result<Vec<u8>> {
        Ok(self.0.recv().await.unwrap_or_default())
    }
}
#[cfg(target_os = "linux")]
impl LocalWrite for PortWrite {
    async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.switch.learn_and_write_egress(buf, self.port_id).await
    }
}

/// Client side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_client_stateless(local: UdpSocket, mut rx: DgramRx, tx: DgramTx) {
    let mut buf = [0u8; UDP_BUF];
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    match f {
                        Frame::Keepalive => true,
                        Frame::Data(d) => local.send(&d).await.is_ok(),
                    }
                }
                None => false,
            },
            r = local.recv(&mut buf) => match r {
                Ok(n) => tx.send(&buf[..n]).await.is_ok(),
                Err(_) => false,
            },
            _ = tick.tick() => last_in.elapsed() < UDP_IDLE && tx.probe().await.is_ok(),
        };
        if !alive {
            break;
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
    let half = UDP_IDLE / 2;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + half, half);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_in = Instant::now();
    loop {
        let alive = tokio::select! {
            d = dgram_rx.recv() => match d {
                Some(d) => tx.send(&d).await.is_ok(),
                None => false,
            },
            m = rx.recv() => match m {
                Some(f) => {
                    last_in = Instant::now();
                    match f {
                        Frame::Keepalive => true,
                        Frame::Data(d) => socket.send_to(&d, src).await.is_ok(),
                    }
                }
                None => false,
            },
            _ = tick.tick() => last_in.elapsed() < UDP_IDLE && tx.probe().await.is_ok(),
        };
        if !alive {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{client_handshake, derive_psk, server_handshake};
    use tokio::sync::mpsc;

    // Test-only local side: `read` blocks on an mpsc the test feeds, `write`
    // records every forwarded frame so a test can assert what reached it.
    struct ChanRead(mpsc::Receiver<Vec<u8>>);
    struct ChanWrite(mpsc::UnboundedSender<Vec<u8>>);

    impl LocalRead for ChanRead {
        async fn read(&mut self) -> crate::Result<Vec<u8>> {
            // None == closed local side, signalled as the empty-Vec EOF sentinel.
            Ok(self.0.recv().await.unwrap_or_default())
        }
    }
    impl LocalWrite for ChanWrite {
        async fn write(&mut self, buf: &[u8]) -> crate::Result<()> {
            self.0.send(buf.to_vec()).map_err(|_| "closed".into())
        }
    }

    async fn noise_pair() -> (NoiseReader, NoiseWriter, NoiseReader, NoiseWriter) {
        let psk = derive_psk("bridge relay test");
        let (a, b) = tokio::io::duplex(1 << 16);
        let srv = tokio::spawn(async move { server_handshake(b, &psk).await.unwrap() });
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
        let relay = tokio::spawn(stream_relay(
            ChanRead(feed_rx),
            ChanWrite(out_tx),
            cr,
            cw,
            std::future::pending(),
        ));
        relay.await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= TCP_IDLE && elapsed < TCP_IDLE * 2,
            "reaped at {elapsed:?}, expected near {TCP_IDLE:?}"
        );
    }

    // (b) A peer that answers every probe keeps the relay alive well past the
    // idle window.
    #[tokio::test(start_paused = true)]
    async fn answered_probes_keep_relay_alive() {
        let (cr, cw, mut sr, mut sw) = noise_pair().await;
        let (_feed_tx, feed_rx) = mpsc::channel::<Vec<u8>>(4);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let peer = tokio::spawn(async move {
            // Echo a keepalive back for every inbound frame, refreshing last_in.
            while let Ok(_m) = sr.recv().await {
                if sw.probe().await.is_err() {
                    break;
                }
            }
        });
        let relay = tokio::spawn(stream_relay(
            ChanRead(feed_rx),
            ChanWrite(out_tx),
            cr,
            cw,
            std::future::pending(),
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
        let relay = tokio::spawn(stream_relay(
            ChanRead(feed_rx),
            ChanWrite(out_tx),
            cr,
            cw,
            std::future::pending(),
        ));
        // Drain inbound on the peer so the relay's nw.send/probe never blocks.
        let drain = tokio::spawn(async move { while sr.recv().await.is_ok() {} });
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

#[cfg(all(test, target_os = "linux"))]
mod switch_tests {
    use super::*;

    const M1: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const M2: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
    const BCAST: [u8; 6] = [0xff; 6];
    const MCAST: [u8; 6] = [0x01, 0, 0x5e, 0, 0, 0x01];

    /// One Ethernet frame: 6-byte dst, 6-byte src, 2-byte ethertype, payload.
    fn frame(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype
        f.extend_from_slice(payload);
        f
    }

    /// An L2 switch with no live reader, plus the dummy TAP backing it (kept alive
    /// by the returned guard fd so the device is not closed mid-test). The backing
    /// socketpair is `SOCK_DGRAM`, so it models per-frame boundaries; it is not the
    /// real TAP `IFF_NO_PI` fd, only a stand-in the switch logic reads and writes.
    fn test_switch() -> (Arc<TapSwitch>, TapFdGuard) {
        let (dev, peer) = crate::tap::TapDevice::socketpair_for_test(1500).unwrap();
        let sw = TapSwitch::new_without_reader(Arc::new(dev), true);
        (sw, TapFdGuard(peer))
    }

    /// Closes the peer socketpair fd when the test ends.
    struct TapFdGuard(std::os::unix::io::RawFd);
    impl Drop for TapFdGuard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    // A learned unicast destination is delivered only to the port that owns it,
    // never flooded to the other ports.
    #[tokio::test]
    async fn learn_then_unicast_delivers_to_owner() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port().unwrap();
        let mut b = sw.add_port().unwrap();
        // M1 lives behind port a.
        sw.learn(M1, a.port_id);

        let f = frame(M1, M2, b"hi");
        sw.forward_inbound(M1, f.clone());

        assert_eq!(a.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert!(b.out_rx.as_mut().unwrap().try_recv().is_err());
    }

    // A broadcast destination floods to every attached port.
    #[tokio::test]
    async fn broadcast_floods_all_ports() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port().unwrap();
        let mut b = sw.add_port().unwrap();
        let f = frame(BCAST, M1, b"b");
        sw.forward_inbound(BCAST, f.clone());
        assert_eq!(a.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // An unknown unicast (no learned owner) floods to every port.
    #[tokio::test]
    async fn unknown_unicast_floods() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port().unwrap();
        let mut b = sw.add_port().unwrap();
        let f = frame(M1, M2, b"u");
        sw.forward_inbound(M1, f.clone());
        assert_eq!(a.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // A multicast destination (group bit set) floods to every port.
    #[tokio::test]
    async fn multicast_floods() {
        let (sw, _g) = test_switch();
        let mut a = sw.add_port().unwrap();
        let mut b = sw.add_port().unwrap();
        let f = frame(MCAST, M1, b"m");
        sw.forward_inbound(MCAST, f.clone());
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
        let mut p = sw.add_port().unwrap();

        // A raw L3-ish buffer shorter than an Ethernet header; the fast path must
        // forward it without parsing.
        let raw = vec![0x45u8, 0, 0, 20, 0, 0]; // 6 bytes: too short to be Ethernet
        let n = unsafe {
            libc::write(peer, raw.as_ptr() as *const libc::c_void, raw.len())
        };
        assert_eq!(n, raw.len() as isize);

        let got = tokio::time::timeout(
            Duration::from_secs(2),
            p.out_rx.as_mut().unwrap().recv(),
        )
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
        let mut a = sw.add_port().unwrap();
        let mut b = sw.add_port().unwrap();
        sw.learn(M1, a.port_id);
        sw.learn(M1, b.port_id); // M1 moved to port b

        let f = frame(M1, M2, b"x");
        sw.forward_inbound(M1, f.clone());
        assert!(a.out_rx.as_mut().unwrap().try_recv().is_err());
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // Dropping a SwitchHandle detaches its port and purges every MAC it owned, so a
    // later frame for that MAC floods (no stale route) and reaches no dead port.
    #[tokio::test]
    async fn handle_drop_evicts_port_and_macs() {
        let (sw, _g) = test_switch();
        let a = sw.add_port().unwrap();
        let a_id = a.port_id;
        let mut b = sw.add_port().unwrap();
        sw.learn(M1, a_id);
        assert!(sw.macs.lock().unwrap().contains_key(&M1));

        drop(a);
        assert!(!sw.ports.lock().unwrap().contains_key(&a_id));
        assert!(!sw.macs.lock().unwrap().contains_key(&M1));

        // Now-unknown M1 floods to the surviving port only.
        let f = frame(M1, M2, b"y");
        sw.forward_inbound(M1, f.clone());
        assert_eq!(b.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
    }

    // Learning stops growing the table at MAX_MACS_PER_SWITCH, but entries already
    // present still update (their port can still move).
    #[tokio::test]
    async fn mac_table_cap() {
        let (sw, _g) = test_switch();
        let p = sw.add_port().unwrap();

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
        let dead = sw.add_port().unwrap();
        let dead_id = dead.port_id;
        let mut live = sw.add_port().unwrap();
        // Close the dead port's receiver without going through Drop (model a relay
        // that stopped draining and dropped its rx).
        let mut dead = dead;
        drop(dead.out_rx.take());

        let f = frame(BCAST, M1, b"z");
        sw.flood(f.clone());

        // The live port still got it; the dead port was evicted from `ports`.
        assert_eq!(live.out_rx.as_mut().unwrap().try_recv().unwrap(), f);
        assert!(!sw.ports.lock().unwrap().contains_key(&dead_id));
    }

    // An L3 (`--tun`) switch serves exactly one client: the first port attaches,
    // the second is refused. Dropping the first frees the slot for a reconnect. An
    // L2 (`--tap`) switch admits many ports.
    #[tokio::test]
    async fn tun_switch_admits_one_port_l2_admits_many() {
        let (dev, peer) = crate::tap::TapDevice::socketpair_for_test(1500).unwrap();
        let _g = TapFdGuard(peer);
        let tun = TapSwitch::new_without_reader(Arc::new(dev), false);

        let first = tun.add_port().expect("first tun port attaches");
        assert!(tun.add_port().is_err(), "second tun port must be refused");
        drop(first);
        let _reattach = tun.add_port().expect("a freed tun slot accepts a reconnect");

        let (sw, _g2) = test_switch(); // is_l2 = true
        let _ports: Vec<_> = (0..8)
            .map(|_| sw.add_port().expect("an l2 switch admits many ports"))
            .collect();
        assert_eq!(sw.ports.lock().unwrap().len(), 8);
    }
}
