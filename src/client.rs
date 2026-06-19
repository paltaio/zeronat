use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Result;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::time::timeout as tokio_timeout;
use tokio::time::{interval, sleep};

use crate::bridge;
use crate::dgram::{DgramRx, DgramTx};
use crate::kcp::{route, session as kcp_session, Session, CLASS_KCP, CLASS_SETUP, SETUP_CONV_BIT};
#[cfg(target_os = "linux")]
use crate::kcp::{BRIDGE_CONV, BRIDGE_ID};
use crate::noise::{client_handshake, client_handshake_stateless};
use crate::proto::{Msg, Proto};
use crate::tap::TapConfig;
#[cfg(target_os = "linux")]
use crate::tap::TapDevice;

const PING_INTERVAL: Duration = Duration::from_secs(25);
/// Liveness window for the control channel. The server replies Pong to every
/// Ping, so no inbound frame for a few ping intervals means the link is a black
/// hole (no FIN/RST on a NAT rebind, WAN re-dial, or silent firewall drop).
const CONTROL_TIMEOUT: Duration = Duration::from_secs(90);
const RETRY_DELAY: Duration = Duration::from_secs(3);
/// Cap for the reconnect backoff. A server that stays down (especially in DHT
/// mode, where each cycle runs a full lookup) must not redial every RETRY_DELAY
/// forever; the delay doubles per failed cycle up to this ceiling.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(60);
const UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1500);
/// Pause after a transient recv error on the RX pump so a persistent ready-error
/// (e.g. HostUnreachable/NetworkUnreachable on a connected UDP socket) does not
/// spin the loop at 100% CPU or flood logs.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// Bound for a per-forward connect plus Noise handshake back to the server. The
/// server abandons a half-open forward at its own OPEN_TIMEOUT, so a black-holed
/// TCP handshake (kernel retransmits for ~15 min) or stalled KCP conv must not
/// keep the fd and task alive long after the server has moved on.
const OPEN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// A control session over UDP that lives at least this long is treated as a
/// healthy path; a shorter one counts as a flap (handshake succeeds but the KCP
/// link cannot be sustained over a lossy/MTU-broken UDP route).
const UDP_MIN_HEALTHY: Duration = Duration::from_secs(30);
/// Consecutive flapping/failed UDP attempts before Auto stops probing UDP.
const UDP_QUICK_FAILS: u32 = 2;
/// How long Auto prefers TCP after UDP flaps, before it re-probes UDP again.
const UDP_COOLDOWN: Duration = Duration::from_secs(120);

/// UDP-health memory carried across reconnects in Auto mode. Owned by the
/// reconnect loop (not the Arc<Client>, not global) so each running client keeps
/// its own monotonic view of whether the UDP path is currently usable.
#[derive(Default)]
struct UdpHealth {
    fails: u32,
    cooldown_until: Option<Instant>,
}

/// Auto-mode transport decision: probe UDP unless a flap cooldown is still active.
/// Forced Udp/Tcp callers never consult this (their path is fixed upstream).
fn choose_udp(state: &UdpHealth, now: Instant) -> bool {
    match state.cooldown_until {
        Some(until) => now >= until,
        None => true,
    }
}

/// Fold one UDP attempt's outcome into the cooldown memory. A healthy session
/// clears the cooldown; UDP_QUICK_FAILS flaps in a row arms it for UDP_COOLDOWN.
fn record(state: &mut UdpHealth, healthy: bool, now: Instant) {
    if healthy {
        state.fails = 0;
        state.cooldown_until = None;
    } else {
        state.fails += 1;
        if state.fails >= UDP_QUICK_FAILS {
            state.cooldown_until = Some(now + UDP_COOLDOWN);
            state.fails = 0;
        }
    }
}

/// Exponential backoff for the reconnect loop. Owned by the loop (like
/// `UdpHealth`) so each running client keeps its own redial cadence. Starts at
/// RETRY_DELAY, doubles after every failed cycle, and is capped at
/// RETRY_DELAY_MAX; a cycle that established a control session resets it.
struct Backoff(Duration);

impl Default for Backoff {
    fn default() -> Self {
        Backoff(RETRY_DELAY)
    }
}

impl Backoff {
    fn delay(&self) -> Duration {
        self.0
    }

    fn fail(&mut self) {
        self.0 = (self.0 * 2).min(RETRY_DELAY_MAX);
    }

    fn reset(&mut self) {
        self.0 = RETRY_DELAY;
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Transport {
    Auto,
    Udp,
    Tcp,
}

/// What an Auto-mode connection attempt did with UDP, so the reconnect loop can
/// update its cooldown memory. `Skipped` means the attempt never touched UDP
/// (forced TCP, or cooldown active), so it leaves the memory unchanged.
#[derive(Clone, Copy, PartialEq)]
enum UdpOutcome {
    Skipped,
    Healthy,
    Unhealthy,
}

struct Client {
    server: String,
    psk: [u8; 32],
    client_id: String,
    tcp: HashMap<u16, String>,
    udp: HashMap<u16, String>,
    transport: Transport,
}

/// Aborts its task when dropped. Ties a detached pump's lifetime to the scope
/// that owns this guard, so the task cannot outlive the connection it serves.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How the control loop opens data connections back to the server.
enum Link {
    Tcp, // data conns dial new TcpStreams
    // data conns open KCP convs on the shared UDP session; the guard aborts the
    // session's RX pump when this Link drops at control teardown (held for Drop).
    // The Notify fires when that pump sees the peer vanish, so the control loop can
    // tear down at once instead of waiting out CONTROL_TIMEOUT.
    Udp(Arc<Session>, #[allow(dead_code)] AbortOnDrop, Arc<Notify>),
}

/// How the server's control address is found: a fixed `host:port`, or looked up
/// on the DHT by a secret-derived key.
enum Discovery {
    Static(String),
    #[cfg(feature = "dht")]
    Dht(Arc<crate::dht::Identity>),
}

impl Discovery {
    fn new(server: &str, secret: &str) -> Result<Self> {
        if server == "dht" {
            #[cfg(feature = "dht")]
            return Ok(Discovery::Dht(Arc::new(crate::dht::Identity::derive(
                secret,
            ))));
            #[cfg(not(feature = "dht"))]
            {
                let _ = secret;
                return Err("this build has no dht support; pass --server host:port".into());
            }
        }
        Ok(Discovery::Static(server.to_string()))
    }

    /// Resolve to a concrete `host:port`. The DHT path serves the cached address
    /// first so a reconnect stays off the network.
    async fn resolve(&self) -> Result<String> {
        match self {
            Discovery::Static(s) => Ok(s.clone()),
            #[cfg(feature = "dht")]
            Discovery::Dht(id) => {
                if let Some(addr) = crate::dht::read_cache(id) {
                    return Ok(addr.to_string());
                }
                eprintln!("resolving server address via dht...");
                let addr = crate::dht::resolve(id).await?;
                eprintln!("dht: resolved server to {addr}");
                crate::dht::write_cache(id, addr);
                Ok(addr.to_string())
            }
        }
    }

    /// Drop a cached address after it failed to connect, so the next resolve
    /// consults the DHT (the server's IP may have changed).
    fn invalidate(&self) {
        #[cfg(feature = "dht")]
        if let Discovery::Dht(id) = self {
            crate::dht::clear_cache(id);
        }
    }
}

pub async fn run(
    server: String,
    secret: String,
    tcp: Vec<(u16, String)>,
    udp: Vec<(u16, String)>,
    transport: Transport,
    tap: Option<TapConfig>,
    id_prefix: Option<String>,
) -> Result<()> {
    let psk = crate::noise::derive_psk(&secret);
    let client_id = crate::identity::derive_client_id(id_prefix.as_deref());
    let tcp: HashMap<u16, String> = tcp.into_iter().collect();
    let udp: HashMap<u16, String> = udp.into_iter().collect();
    let discovery = Discovery::new(&server, &secret)?;
    #[cfg(target_os = "linux")]
    let tap = match tap {
        Some(cfg) => Some(Arc::new(TapDevice::open(&cfg)?)),
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    if tap.is_some() {
        return Err("L2 TAP bridge (--tap) is only supported on Linux".into());
    }

    let mut udp_health = UdpHealth::default();
    let mut backoff = Backoff::default();

    loop {
        let addr = match discovery.resolve().await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("server discovery failed: {e}");
                sleep(backoff.delay()).await;
                backoff.fail();
                continue;
            }
        };
        let client = Arc::new(Client {
            server: addr,
            psk,
            client_id: client_id.clone(),
            tcp: tcp.clone(),
            udp: udp.clone(),
            transport,
        });
        // Auto only: skip the UDP probe while a flap cooldown is active. Forced
        // Udp/Tcp ignore `try_udp` and keep their fixed path.
        let try_udp = transport != Transport::Auto || choose_udp(&udp_health, Instant::now());
        #[cfg(target_os = "linux")]
        let (result, outcome, established) = match &tap {
            Some(tap) => bridge_session(client.clone(), tap.clone(), try_udp).await,
            None => session(client.clone(), try_udp).await,
        };
        #[cfg(not(target_os = "linux"))]
        let (result, outcome, established) = session(client.clone(), try_udp).await;
        if transport == Transport::Auto && outcome != UdpOutcome::Skipped {
            record(
                &mut udp_health,
                outcome == UdpOutcome::Healthy,
                Instant::now(),
            );
        }
        if let Err(e) = result {
            eprintln!("connection lost: {e}");
            // Only a failure to establish against the cached address invalidates
            // it; a long-lived session dying from a transient blip keeps the cache
            // so the redial stays off the DHT. If the IP truly moved, the next
            // redial fails to establish and that clears it.
            if !established {
                discovery.invalidate();
            }
        }
        // A cycle that brought the control channel up is a fresh start; one that
        // never established (down server, failed handshake) widens the redial gap.
        if established {
            backoff.reset();
        } else {
            backoff.fail();
        }
        sleep(backoff.delay()).await;
    }
}

/// Bring up the L2 bridge: UDP first for Auto/Udp, TCP otherwise or as fallback.
/// Mirrors `session`: returns the UDP verdict so the reconnect loop can damp
/// flapping in Auto mode. `bridge_udp` runs the data loop inline, so its return
/// timing is the session lifetime used to judge health.
#[cfg(target_os = "linux")]
async fn bridge_session(
    client: Arc<Client>,
    tap: Arc<TapDevice>,
    try_udp: bool,
) -> (Result<()>, UdpOutcome, bool) {
    let mode = client.transport;
    if mode == Transport::Tcp || (mode == Transport::Auto && !try_udp) {
        let (result, established) = bridge_tcp(client, tap).await;
        return (result, UdpOutcome::Skipped, established);
    }
    let started = Instant::now();
    match bridge_udp(client.clone(), tap.clone()).await {
        (Ok(()), established) => {
            let healthy = started.elapsed() >= UDP_MIN_HEALTHY;
            let outcome = if healthy {
                UdpOutcome::Healthy
            } else {
                UdpOutcome::Unhealthy
            };
            (Ok(()), outcome, established)
        }
        (Err(e), established) => {
            if mode == Transport::Udp {
                return (Err(e), UdpOutcome::Skipped, established);
            }
            // A short-lived bridge_udp returns Err with the handshake never even
            // reached on some paths; treat any UDP failure here as a flap signal.
            eprintln!("udp transport unavailable ({e}); falling back to tcp");
            let (result, tcp_established) = bridge_tcp(client, tap).await;
            (
                result,
                UdpOutcome::Unhealthy,
                established || tcp_established,
            )
        }
    }
}

/// Bind a local UDP socket, connect it to the server, start the KCP session, and
/// spawn the inbound RX pump. Shared by the control and bridge UDP paths.
async fn udp_connect(client: &Client) -> Result<(Arc<Session>, AbortOnDrop, Arc<Notify>)> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let server: SocketAddr = client
        .server
        .parse()
        .map_err(|_| -> crate::Error { "server must be host:port for UDP".into() })?;
    socket.connect(server).await?;
    let sess = kcp_session(socket.clone(), server, 1);
    // A connected UDP socket whose peer black-holes never errors on recv, so this
    // pump must be aborted on teardown; the returned guard ties it to the caller's
    // connection scope and fires on both handshake-failure and control-death paths.
    // A peer that vanishes ungracefully (server restart) does surface an ICMP
    // port-unreachable as ConnectionRefused/ConnectionReset; firing `cancel` then
    // makes the owner tear down in seconds instead of waiting out CONTROL_TIMEOUT.
    let cancel = Arc::new(Notify::new());
    let pump = {
        let sess = sess.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv(&mut buf).await {
                    Ok(n) => {
                        route(&sess, &buf[..n]);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        cancel.notify_one();
                        return;
                    }
                    Err(e) => {
                        eprintln!("udp recv error: {e}");
                        sleep(RECV_ERROR_BACKOFF).await;
                    }
                }
            }
        })
    };
    Ok((sess, AbortOnDrop(pump), cancel))
}

/// L2 bridge over the UDP transport: frames ride the unreliable datagram channel.
/// The bool is whether the handshake established before the bridge ran or failed,
/// so the reconnect loop can tell a failed connect from an established-then-dead
/// session.
#[cfg(target_os = "linux")]
async fn bridge_udp(client: Arc<Client>, tap: Arc<TapDevice>) -> (Result<()>, bool) {
    // `_pump` aborts the session RX pump when this scope ends (handshake failure
    // or bridge teardown), so a reconnect cannot leave the old pump running.
    let (sess, _pump, cancel) = match udp_connect(&client).await {
        Ok(v) => v,
        Err(e) => return (Err(e), false),
    };
    let stream = sess.open_conv_with(CLASS_SETUP, BRIDGE_CONV);
    let noise = match tokio_timeout(
        UDP_HANDSHAKE_TIMEOUT,
        client_handshake_stateless(stream, &client.psk, BRIDGE_ID),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return (Err(e), false),
        Err(_) => return (Err("udp handshake timed out".into()), false),
    };
    eprintln!("bridge connected to {} over udp", client.server);

    let noise = Arc::new(noise);
    let (inbound, _guard) = sess.register_dgram(BRIDGE_CONV);
    let tx = DgramTx::new(sess.send_tx(), BRIDGE_CONV, noise.clone());
    let rx = DgramRx::new(inbound, noise);
    // `cancel` fires only when the RX pump sees the peer vanish (server restart),
    // tearing the bridge down at once instead of stalling until the next reconnect.
    bridge::tap_dgram(tap, rx, tx, cancel).await;
    (Ok(()), true)
}

/// L2 bridge over the TCP fallback: frames ride a reliable Noise stream. The bool
/// is whether the handshake established before the bridge ran or failed.
#[cfg(target_os = "linux")]
async fn bridge_tcp(client: Arc<Client>, tap: Arc<TapDevice>) -> (Result<()>, bool) {
    let (nr, mut nw) =
        match connect_and_handshake(&client.server, &client.psk, OPEN_HANDSHAKE_TIMEOUT).await {
            Ok(v) => v,
            Err(e) => return (Err(e), false),
        };
    if let Err(e) = nw.send(&Msg::Data { id: BRIDGE_ID }.encode()).await {
        return (Err(e), true);
    }
    eprintln!("bridge connected to {} over tcp", client.server);
    bridge::tap_stream(tap, nr, nw, Arc::new(Notify::new())).await;
    (Ok(()), true)
}

/// Establish the control channel over UDP/KCP. Returns the session and the
/// handshaked control reader/writer, or an error to trigger TCP fallback.
async fn udp_session(
    client: Arc<Client>,
) -> Result<(Arc<Session>, AbortOnDrop, Arc<Notify>, crate::noise::Noise)> {
    // On handshake failure the `?` below drops `pump`, aborting the RX pump before
    // this scope returns Err; on success it is handed to the Link for the control
    // session's lifetime so control death aborts it too.
    let (sess, pump, cancel) = udp_connect(&client).await?;
    let (_conv, stream) = sess.open_conv(CLASS_KCP);
    let noise = tokio_timeout(UDP_HANDSHAKE_TIMEOUT, client_handshake(stream, &client.psk))
        .await
        .map_err(|_| -> crate::Error { "udp handshake timed out".into() })??;
    Ok((sess, pump, cancel, noise))
}

/// Establish the control connection and dispatch `Open` requests until it drops.
/// Returns the loop result, how UDP behaved this attempt (so the reconnect loop
/// can damp UDP flapping; Auto only, see `UdpHealth`), and whether the control
/// channel ever established (reaching `control_loop` means connect and handshake
/// both succeeded; a later death is not a failure to establish).
async fn session(client: Arc<Client>, try_udp: bool) -> (Result<()>, UdpOutcome, bool) {
    let mode = client.transport;

    // Try UDP first for Auto/Udp (unless cooldown skipped it); fall back to TCP
    // for Auto/Tcp.
    let probe_udp = mode != Transport::Tcp && (mode == Transport::Udp || try_udp);
    let (link, r, w, started) = if probe_udp {
        match udp_session(client.clone()).await {
            Ok((sess, pump, cancel, (r, w))) => {
                eprintln!("connected to {} over udp", client.server);
                (Link::Udp(sess, pump, cancel), r, w, Some(Instant::now()))
            }
            Err(e) => {
                if mode == Transport::Udp {
                    // Forced UDP never falls back; a failed connect is just an error.
                    return (Err(e), UdpOutcome::Skipped, false);
                }
                // A failed UDP connect is itself a flap signal for the cooldown,
                // independent of how the TCP fallback session fares afterwards.
                eprintln!("udp transport unavailable ({e}); falling back to tcp");
                match tcp_control(client.clone()).await {
                    Ok((r, w)) => {
                        return (
                            control_loop(client, Link::Tcp, r, w).await,
                            UdpOutcome::Unhealthy,
                            true,
                        )
                    }
                    Err(e) => return (Err(e), UdpOutcome::Unhealthy, false),
                }
            }
        }
    } else {
        match tcp_control(client.clone()).await {
            Ok((r, w)) => (Link::Tcp, r, w, None),
            Err(e) => return (Err(e), UdpOutcome::Skipped, false),
        }
    };

    let result = control_loop(client, link, r, w).await;
    // Health is measured from when the UDP control channel came up to when it
    // returned; a short-lived UDP session is a flap. TCP-fallback paths report
    // their UDP verdict above, so `started` here is always the UDP case.
    let outcome = match started {
        Some(t) if t.elapsed() >= UDP_MIN_HEALTHY => UdpOutcome::Healthy,
        Some(_) => UdpOutcome::Unhealthy,
        None => UdpOutcome::Skipped,
    };
    (result, outcome, true)
}

/// Dial `addr`, disable Nagle, and run the Noise handshake, bounding the whole
/// connect-plus-handshake under `timeout`. A path that black-holes mid-handshake
/// (msg1 ACKed but msg2 never arrives on a NAT remap, WAN re-dial, or silent
/// firewall drop) would otherwise park on the kernel read for the retransmit
/// window (~15 min, or forever with keepalive off); the timeout turns that into
/// an Err so the caller can back off and redial in seconds.
async fn connect_and_handshake(
    addr: &str,
    psk: &[u8; 32],
    timeout: Duration,
) -> Result<crate::noise::Noise> {
    tokio_timeout(timeout, async {
        let sock = TcpStream::connect(addr)
            .await
            .map_err(|e| -> crate::Error { format!("connecting to {addr}: {e}").into() })?;
        sock.set_nodelay(true).ok();
        client_handshake(sock, psk).await
    })
    .await
    .map_err(|_| -> crate::Error { format!("tcp handshake to {addr} timed out").into() })?
}

/// Dial the TCP control connection and run the Noise handshake.
async fn tcp_control(client: Arc<Client>) -> Result<crate::noise::Noise> {
    let noise = connect_and_handshake(&client.server, &client.psk, OPEN_HANDSHAKE_TIMEOUT).await?;
    eprintln!("connected to {}", client.server);
    Ok(noise)
}

/// Run the control loop over an established Noise control channel, dispatching
/// `Open` requests via `link` until the channel drops.
async fn control_loop(
    client: Arc<Client>,
    link: Link,
    mut r: crate::noise::NoiseReader,
    w: crate::noise::NoiseWriter,
) -> Result<()> {
    let link = Arc::new(link);
    let cancel = match link.as_ref() {
        Link::Udp(_, _, cancel) => Some(cancel.clone()),
        Link::Tcp => None,
    };

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    tx.try_send(
        Msg::ClientHello {
            version: crate::identity::PROTO_VERSION,
            client_id: client.client_id.clone(),
        }
        .encode(),
    )
    .ok();

    let mut w = w;
    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if w.send(&bytes).await.is_err() {
                break;
            }
        }
    });

    let ping_tx = tx.clone();
    let pinger = tokio::spawn(async move {
        let mut tick = interval(PING_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            if ping_tx.try_send(Msg::Ping.encode()).is_err() {
                break;
            }
        }
    });

    // Handles of in-flight forward tasks spawned for this control session, so a
    // teardown can abort black-holed forwards instead of leaking them.
    let mut forwards: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    let result = loop {
        // Any inbound frame (Pong from our ping, or an Open) resets the deadline.
        // No frame for the whole window means the link is a black hole with no
        // FIN/RST; return Err so the outer reconnect loop re-resolves and redials.
        let recv = tokio_timeout(CONTROL_TIMEOUT, r.recv());
        let died = async {
            match &cancel {
                Some(c) => c.notified().await,
                None => std::future::pending().await,
            }
        };
        let msg = tokio::select! {
            // The RX pump saw the peer vanish (ICMP unreachable on UDP); tear down
            // now rather than waiting out CONTROL_TIMEOUT for the deadline to lapse.
            _ = died => break Err("udp peer unreachable (link dead)".into()),
            res = recv => match res {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => break Err(e),
                Err(_) => break Err("control channel timed out (link dead)".into()),
            },
        };
        match Msg::decode(&msg) {
            Ok(Msg::Open { proto, port, id }) => {
                let client = client.clone();
                let link = link.clone();
                // Drop handles of forwards that already finished so the tracking
                // vector stays bounded over a long healthy session.
                forwards.retain(|h| !h.is_finished());
                forwards.push(tokio::spawn(async move {
                    if let Err(e) = handle_open(client, link, proto, port, id).await {
                        eprintln!("stream {id} ({proto:?} :{port}) failed: {e}");
                    }
                }));
            }
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };

    writer.abort();
    pinger.abort();
    // Tear down forwards tied to this dead control session; abort is a no-op on
    // tasks that already completed, so this never races into a panic.
    for h in forwards {
        h.abort();
    }
    result
}

/// Open a data connection back to the server and bridge it to the local target.
async fn handle_open(
    client: Arc<Client>,
    link: Arc<Link>,
    proto: Proto,
    port: u16,
    id: u64,
) -> Result<()> {
    let target = match proto {
        Proto::Tcp => client.tcp.get(&port),
        Proto::Udp => client.udp.get(&port),
    }
    .ok_or_else(|| -> crate::Error {
        format!("no local target configured for {proto:?} :{port}").into()
    })?
    .clone();

    match (link.as_ref(), proto) {
        // --- TCP transport (unchanged behavior) ---
        (Link::Tcp, Proto::Tcp) => {
            let (nr, mut nw) = tokio_timeout(OPEN_HANDSHAKE_TIMEOUT, async {
                let sock = TcpStream::connect(&client.server).await?;
                sock.set_nodelay(true).ok();
                client_handshake(sock, &client.psk).await
            })
            .await
            .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??;
            nw.send(&Msg::Data { id }.encode()).await?;
            let local = TcpStream::connect(&target)
                .await
                .map_err(|e| -> crate::Error {
                    format!("connecting to local {target}: {e}").into()
                })?;
            bridge::tcp(local, nr, nw).await;
        }
        (Link::Tcp, Proto::Udp) => {
            let (nr, mut nw) = tokio_timeout(OPEN_HANDSHAKE_TIMEOUT, async {
                let sock = TcpStream::connect(&client.server).await?;
                sock.set_nodelay(true).ok();
                client_handshake(sock, &client.psk).await
            })
            .await
            .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??;
            nw.send(&Msg::Data { id }.encode()).await?;
            let local = UdpSocket::bind("0.0.0.0:0").await?;
            local.connect(&target).await.map_err(|e| -> crate::Error {
                format!("connecting to local {target}: {e}").into()
            })?;
            bridge::udp_client(local, nr, nw).await;
        }
        // --- UDP transport ---
        (Link::Udp(sess, _, _), Proto::Tcp) => {
            let (_conv, stream) = sess.open_conv(CLASS_KCP);
            let (nr, mut nw) = tokio_timeout(
                OPEN_HANDSHAKE_TIMEOUT,
                client_handshake(stream, &client.psk),
            )
            .await
            .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??;
            nw.send(&Msg::Data { id }.encode()).await?;
            let local = TcpStream::connect(&target)
                .await
                .map_err(|e| -> crate::Error {
                    format!("connecting to local {target}: {e}").into()
                })?;
            bridge::tcp(local, nr, nw).await;
        }
        (Link::Udp(sess, _, _), Proto::Udp) => {
            let conv = (id as u32) | SETUP_CONV_BIT;
            let stream = sess.open_conv_with(CLASS_SETUP, conv);
            let noise = Arc::new(
                tokio_timeout(
                    OPEN_HANDSHAKE_TIMEOUT,
                    client_handshake_stateless(stream, &client.psk, id),
                )
                .await
                .map_err(|_| -> crate::Error { "forward connect+handshake timed out".into() })??,
            );
            let local = UdpSocket::bind("0.0.0.0:0").await?;
            local.connect(&target).await.map_err(|e| -> crate::Error {
                format!("connecting to local {target}: {e}").into()
            })?;
            let (inbound, _guard) = sess.register_dgram(conv);
            let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
            let rx = DgramRx::new(inbound, noise);
            bridge::udp_client_stateless(local, rx, tx).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_fails_arm_cooldown_then_tcp_is_chosen() {
        let mut s = UdpHealth::default();
        let t0 = Instant::now();
        // First flap: still probe UDP next time.
        record(&mut s, false, t0);
        assert!(choose_udp(&s, t0));
        // Second consecutive flap reaches UDP_QUICK_FAILS and arms the cooldown.
        record(&mut s, false, t0);
        assert!(!choose_udp(&s, t0));
        // Mid-cooldown still skips UDP; after it expires UDP is re-probed.
        assert!(!choose_udp(&s, t0 + UDP_COOLDOWN - Duration::from_secs(1)));
        assert!(choose_udp(&s, t0 + UDP_COOLDOWN));
    }

    #[test]
    fn healthy_clears_cooldown_and_counter() {
        let mut s = UdpHealth::default();
        let t0 = Instant::now();
        record(&mut s, false, t0);
        record(&mut s, false, t0);
        assert!(s.cooldown_until.is_some());
        record(&mut s, true, t0);
        assert_eq!(s.fails, 0);
        assert!(s.cooldown_until.is_none());
        assert!(choose_udp(&s, t0));
    }

    #[test]
    fn isolated_flaps_never_arm_cooldown() {
        let mut s = UdpHealth::default();
        let t0 = Instant::now();
        // A flap followed by a healthy session must not accumulate toward cooldown.
        record(&mut s, false, t0);
        record(&mut s, true, t0);
        record(&mut s, false, t0);
        assert!(s.cooldown_until.is_none());
        assert!(choose_udp(&s, t0));
    }

    // A path that completes the TCP handshake but never sends Noise msg2 must
    // not park the initiator on the kernel read; connect_and_handshake has to
    // give up at its timeout, not the multi-minute retransmit window.
    #[tokio::test(start_paused = true)]
    async fn handshake_blackhole_times_out() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Accept and hold the connection open without ever writing msg2.
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(sock);
        });

        let res = connect_and_handshake(&addr, &[0u8; 32], OPEN_HANDSHAKE_TIMEOUT).await;
        assert!(res.is_err(), "expected timeout error, got Ok");
    }
}
