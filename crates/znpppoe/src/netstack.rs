//! One userspace TCP/IP stack (smoltcp) per PPPoE session. IP packets cross the
//! `ChannelDevice` to and from the session's datapath; no kernel interface and no
//! host routing are involved. SOCKS5 opens connections through `Handle::connect`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use tokio::sync::{mpsc, oneshot, Notify};

use crate::driver::Session;

const CHAN_DEPTH: usize = 64;
const MAX_IDLE: Duration = Duration::from_millis(500);
/// Idle/connect timeout: a black-holed SYN or stalled connection aborts to Closed
/// instead of retransmitting forever, so `service` can reap it.
const SOCK_TIMEOUT: Duration = Duration::from_secs(30);
/// Keep-alive probe interval. Without this, `set_timeout` does not arm on an idle
/// established socket, so a peer that vanishes with no FIN/RST would never be
/// reaped; the probes make the timeout fire on silence.
const SOCK_KEEPALIVE: Duration = Duration::from_secs(10);
/// Cap on bytes staged per connection between the client channel and the socket's
/// transmit buffer. Draining stops at this mark, so when the socket cannot send,
/// the backlog stays in the bounded channel and blocks the client's sender instead
/// of growing memory; `out_buf` never holds more than this plus one channel chunk.
const OUT_BUF_BUDGET: usize = 64 * 1024;

/// A request to open a TCP connection through this session's stack. `to_remote`
/// carries client bytes outbound; `from_remote` carries server bytes back; once
/// the TCP connection establishes (or is refused) `ready` reports the outcome.
pub struct Connect {
    pub target: SocketAddrV4,
    pub to_remote: mpsc::Receiver<Vec<u8>>,
    pub from_remote: mpsc::Sender<Vec<u8>>,
    pub ready: oneshot::Sender<bool>,
}

/// Cloneable handle a SOCKS5 worker uses to open egress connections on this
/// session and to nudge the stack after queueing outbound bytes.
#[derive(Clone)]
pub struct Handle {
    cmd: mpsc::Sender<Connect>,
    wake: Arc<Notify>,
}

impl Handle {
    pub async fn connect(&self, c: Connect) -> bool {
        let ok = self.cmd.send(c).await.is_ok();
        self.wake.notify_one();
        ok
    }

    pub fn wake(&self) {
        self.wake.notify_one();
    }
}

/// `live` reflects whether the session currently has a negotiated address, so the
/// SOCKS selector can rotate over only the sessions that can carry traffic.
pub fn spawn(
    session: Session,
    mtu: usize,
    rx_buf: usize,
    tx_buf: usize,
    live: Arc<AtomicBool>,
) -> Handle {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Connect>(CHAN_DEPTH);
    let wake = Arc::new(Notify::new());
    tokio::spawn(run(
        session,
        mtu,
        rx_buf,
        tx_buf,
        cmd_rx,
        wake.clone(),
        live,
    ));
    Handle { cmd: cmd_tx, wake }
}

struct Conn {
    to_remote: mpsc::Receiver<Vec<u8>>,
    /// Dropped (set to `None`) once the remote half-closes so the SOCKS side sees
    /// EOF; that is the only way a server-closes-first response is propagated.
    from_remote: Option<mpsc::Sender<Vec<u8>>>,
    out_buf: VecDeque<u8>,
    ready: Option<oneshot::Sender<bool>>,
    to_remote_done: bool,
    /// Set once the socket reaches Established. The half-close check keys on this
    /// because a pre-Established socket also reports `!may_recv()`, which would
    /// otherwise drop the sender before the connection ever comes up.
    established: bool,
}

#[allow(clippy::too_many_arguments)]
async fn run(
    mut session: Session,
    mtu: usize,
    rx_buf: usize,
    tx_buf: usize,
    mut cmd_rx: mpsc::Receiver<Connect>,
    wake: Arc<Notify>,
    live: Arc<AtomicBool>,
) {
    let idx = session.idx;
    let mut device = ChannelDevice {
        inbound: VecDeque::new(),
        outbound: session.outbound_ip.clone(),
        idx,
        mtu,
    };
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    let mut sockets = SocketSet::new(Vec::new());
    let mut conns: HashMap<SocketHandle, Conn> = HashMap::new();
    let mut next_port: u16 = 49152;
    let mut configured = false;

    loop {
        if session.established.has_changed().unwrap_or(false) {
            let est = *session.established.borrow_and_update();
            match est {
                Some(e) => {
                    iface.update_ip_addrs(|a| {
                        a.clear();
                        let _ = a.push(IpCidr::new(IpAddress::Ipv4(v4(e.local_ip)), 32));
                    });
                    let _ = iface.routes_mut().add_default_ipv4_route(v4(e.peer_ip));
                    configured = true;
                }
                None => {
                    iface.update_ip_addrs(|a| a.clear());
                    iface.routes_mut().remove_default_ipv4_route();
                    configured = false;
                }
            }
            live.store(configured, Ordering::Relaxed);
        }

        while let Ok(pkt) = session.inbound_ip.try_recv() {
            device.inbound.push_back(pkt);
        }

        let now = SmolInstant::now();
        let _ = iface.poll(now, &mut device, &mut sockets);
        service(&mut sockets, &mut conns);
        let _ = iface.poll(now, &mut device, &mut sockets);

        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(MAX_IDLE)
            .min(MAX_IDLE);

        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => match cmd {
                Some(c) => open(c, &mut iface, &mut sockets, &mut conns, &mut next_port, configured, rx_buf, tx_buf),
                None => return,
            },
            Some(pkt) = session.inbound_ip.recv() => device.inbound.push_back(pkt),
            _ = wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn open(
    c: Connect,
    iface: &mut Interface,
    sockets: &mut SocketSet<'static>,
    conns: &mut HashMap<SocketHandle, Conn>,
    next_port: &mut u16,
    configured: bool,
    rx_buf: usize,
    tx_buf: usize,
) {
    if !configured {
        let _ = c.ready.send(false);
        return;
    }
    let rx = tcp::SocketBuffer::new(vec![0u8; rx_buf]);
    let tx = tcp::SocketBuffer::new(vec![0u8; tx_buf]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_nagle_enabled(false);
    socket.set_timeout(Some(SOCK_TIMEOUT.into()));
    socket.set_keep_alive(Some(SOCK_KEEPALIVE.into()));
    let handle = sockets.add(socket);

    let port = *next_port;
    *next_port = if *next_port == u16::MAX {
        49152
    } else {
        *next_port + 1
    };
    let remote = (IpAddress::Ipv4(v4(*c.target.ip())), c.target.port());

    match sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(iface.context(), remote, port)
    {
        Ok(()) => {
            conns.insert(
                handle,
                Conn {
                    to_remote: c.to_remote,
                    from_remote: Some(c.from_remote),
                    out_buf: VecDeque::new(),
                    ready: Some(c.ready),
                    to_remote_done: false,
                    established: false,
                },
            );
        }
        Err(_) => {
            sockets.remove(handle);
            let _ = c.ready.send(false);
        }
    }
}

fn service(sockets: &mut SocketSet<'static>, conns: &mut HashMap<SocketHandle, Conn>) {
    let mut remove = Vec::new();
    for (&handle, conn) in conns.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(handle);

        match socket.state() {
            tcp::State::Established => {
                conn.established = true;
                if let Some(r) = conn.ready.take() {
                    let _ = r.send(true);
                }
            }
            tcp::State::Closed => {
                if let Some(r) = conn.ready.take() {
                    let _ = r.send(false);
                }
                remove.push(handle);
                continue;
            }
            _ => {}
        }

        // client -> remote
        while conn.out_buf.len() < OUT_BUF_BUDGET {
            match conn.to_remote.try_recv() {
                Ok(chunk) => conn.out_buf.extend(chunk),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    conn.to_remote_done = true;
                    break;
                }
            }
        }
        while socket.may_send() && !conn.out_buf.is_empty() {
            let front = conn.out_buf.as_slices().0;
            match socket.send_slice(front) {
                Ok(0) => break,
                Ok(n) => {
                    conn.out_buf.drain(..n);
                }
                Err(_) => break,
            }
        }
        if conn.to_remote_done && conn.out_buf.is_empty() && socket.may_send() {
            socket.close();
        }

        // remote -> client
        let mut client_gone = false;
        while socket.can_recv() {
            let Some(tx) = &conn.from_remote else { break };
            match tx.try_reserve() {
                Ok(permit) => {
                    let mut chunk = Vec::new();
                    let _ = socket.recv(|data| {
                        chunk.extend_from_slice(data);
                        (data.len(), ())
                    });
                    if chunk.is_empty() {
                        break;
                    }
                    permit.send(chunk);
                }
                Err(mpsc::error::TrySendError::Full(())) => break,
                Err(mpsc::error::TrySendError::Closed(())) => {
                    client_gone = true;
                    break;
                }
            }
        }
        if client_gone {
            // The client receiver is gone, so buffered data can never be
            // delivered; abort instead of holding a zero-window socket open
            // for a peer that keeps answering keep-alives.
            conn.from_remote = None;
            socket.abort();
        }
        // Remote half-closed (after Established) and its buffer is drained: signal
        // EOF to the SOCKS client by dropping the sender, otherwise a
        // server-closes-first response would hang forever. Gated on `established`
        // because a pre-Established socket also reports `!may_recv()`.
        if conn.established
            && conn.from_remote.is_some()
            && !socket.may_recv()
            && !socket.can_recv()
        {
            conn.from_remote = None;
        }
    }
    for h in remove {
        conns.remove(&h);
        sockets.remove(h);
    }
}

fn v4(a: std::net::Ipv4Addr) -> Ipv4Address {
    let o = a.octets();
    Ipv4Address::new(o[0], o[1], o[2], o[3])
}

struct ChannelDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: mpsc::Sender<(usize, Vec<u8>)>,
    idx: usize,
    mtu: usize,
}

impl Device for ChannelDevice {
    type RxToken<'a>
        = RxTok
    where
        Self: 'a;
    type TxToken<'a>
        = TxTok<'a>
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.inbound.pop_front()?;
        Some((
            RxTok(pkt),
            TxTok {
                out: &self.outbound,
                idx: self.idx,
            },
        ))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok {
            out: &self.outbound,
            idx: self.idx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct RxTok(Vec<u8>);
impl RxToken for RxTok {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct TxTok<'a> {
    out: &'a mpsc::Sender<(usize, Vec<u8>)>,
    idx: usize,
}
impl TxToken for TxTok<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.out.try_send((self.idx, buf));
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHUNK: usize = 16 * 1024;
    const SOCK_BUF: usize = 4096;

    /// One interface whose device output is fed back into its own input, so two
    /// sockets on it can talk to each other without a kernel or a peer stack.
    struct Loopback {
        device: ChannelDevice,
        iface: Interface,
        sockets: SocketSet<'static>,
        out_rx: mpsc::Receiver<(usize, Vec<u8>)>,
    }

    impl Loopback {
        fn new() -> Self {
            let (out_tx, out_rx) = mpsc::channel(1024);
            let mut device = ChannelDevice {
                inbound: VecDeque::new(),
                outbound: out_tx,
                idx: 0,
                mtu: 1400,
            };
            let config = Config::new(HardwareAddress::Ip);
            let mut iface = Interface::new(config, &mut device, SmolInstant::now());
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 32));
                let _ = a.push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32));
            });
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1));
            Loopback {
                device,
                iface,
                sockets: SocketSet::new(Vec::new()),
                out_rx,
            }
        }

        /// Poll the stack a few rounds, looping every emitted packet back in.
        fn pump(&mut self) {
            for _ in 0..4 {
                let _ = self
                    .iface
                    .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
                while let Ok((_, pkt)) = self.out_rx.try_recv() {
                    self.device.inbound.push_back(pkt);
                }
            }
        }

        /// Poll once and discard everything emitted, so the peer never sees it
        /// and no ACKs come back: a stalled uplink.
        fn pump_blackhole(&mut self) {
            let _ = self
                .iface
                .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
            while self.out_rx.try_recv().is_ok() {}
        }

        fn tcp(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
            self.sockets.get_mut::<tcp::Socket>(handle)
        }
    }

    fn sock_buf() -> tcp::SocketBuffer<'static> {
        tcp::SocketBuffer::new(vec![0u8; SOCK_BUF])
    }

    /// Set up an established client/server socket pair over the loopback.
    fn establish() -> (Loopback, SocketHandle, SocketHandle) {
        let mut lo = Loopback::new();
        let mut server = tcp::Socket::new(sock_buf(), sock_buf());
        server.listen(80).unwrap();
        let server = lo.sockets.add(server);
        let client = lo.sockets.add(tcp::Socket::new(sock_buf(), sock_buf()));
        let Loopback { iface, sockets, .. } = &mut lo;
        sockets
            .get_mut::<tcp::Socket>(client)
            .connect(iface.context(), (IpAddress::v4(10, 0, 0, 2), 80), 49153)
            .unwrap();
        for _ in 0..10 {
            lo.pump();
            if lo.tcp(client).state() == tcp::State::Established
                && lo.tcp(server).state() == tcp::State::Established
            {
                return (lo, client, server);
            }
        }
        panic!("loopback pair failed to establish");
    }

    fn conn(to_remote: mpsc::Receiver<Vec<u8>>, from_remote: mpsc::Sender<Vec<u8>>) -> Conn {
        Conn {
            to_remote,
            from_remote: Some(from_remote),
            out_buf: VecDeque::new(),
            ready: None,
            to_remote_done: false,
            established: true,
        }
    }

    #[test]
    fn out_buf_stays_within_budget_when_uplink_stalls() {
        let (mut lo, client, _server) = establish();
        let (to_tx, to_rx) = mpsc::channel::<Vec<u8>>(64);
        let (from_tx, _from_rx) = mpsc::channel::<Vec<u8>>(64);
        let mut conns = HashMap::new();
        conns.insert(client, conn(to_rx, from_tx));

        for _ in 0..32 {
            // A fast client keeps the bounded channel topped up while the
            // uplink delivers nothing back.
            while to_tx.try_send(vec![0u8; CHUNK]).is_ok() {}
            service(&mut lo.sockets, &mut conns);
            let staged = conns[&client].out_buf.len();
            assert!(
                staged < OUT_BUF_BUDGET + CHUNK,
                "out_buf grew to {staged} bytes"
            );
            lo.pump_blackhole();
        }
        // The backlog stayed in the channel: the producer is blocked.
        assert!(to_tx.try_send(vec![0u8; CHUNK]).is_err());
    }

    #[test]
    fn upload_drains_fully_under_budget() {
        let (mut lo, client, server) = establish();
        let (to_tx, to_rx) = mpsc::channel::<Vec<u8>>(64);
        let (from_tx, _from_rx) = mpsc::channel::<Vec<u8>>(64);
        let mut conns = HashMap::new();
        conns.insert(client, conn(to_rx, from_tx));

        let total = 8 * OUT_BUF_BUDGET;
        let mut sent = 0;
        let mut received = 0;
        for _ in 0..10_000 {
            while sent < total && to_tx.try_send(vec![0xA5u8; CHUNK]).is_ok() {
                sent += CHUNK;
            }
            service(&mut lo.sockets, &mut conns);
            lo.pump();
            let srv = lo.tcp(server);
            while srv.can_recv() {
                received += srv.recv(|data| (data.len(), data.len())).unwrap();
            }
            if received >= total {
                break;
            }
        }
        assert_eq!(received, total);
    }

    #[test]
    fn closed_client_receiver_aborts_connection() {
        let (mut lo, client, server) = establish();
        lo.tcp(server).send_slice(b"undeliverable").unwrap();
        lo.pump();
        assert!(lo.tcp(client).can_recv());

        let (_to_tx, to_rx) = mpsc::channel::<Vec<u8>>(4);
        let (from_tx, from_rx) = mpsc::channel::<Vec<u8>>(4);
        drop(from_rx);
        let mut conns = HashMap::new();
        conns.insert(client, conn(to_rx, from_tx));

        service(&mut lo.sockets, &mut conns);
        assert_eq!(lo.tcp(client).state(), tcp::State::Closed);
        service(&mut lo.sockets, &mut conns);
        assert!(conns.is_empty());
    }
}
