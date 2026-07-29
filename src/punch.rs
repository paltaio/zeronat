use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{interval, interval_at, sleep, Instant};

use crate::client::{AbortOnDrop, ProbeSession, PING_INTERVAL};
use crate::dgram::{DgramRx, DgramTx};
use crate::kcp::{
    route, session as kcp_session, Accepted, ConvGuard, Session, CLASS_DGRAM, CLASS_PUNCH,
    CLASS_SETUP, SETUP_CONV_BIT,
};
use crate::noise::{client_handshake_stateless, server_handshake_stateless, StatelessNoise};
use crate::proto::{Msg, PathStatus};

/// How long both parties try the punch before settling on the relay. Sized to
/// several KCP retransmits of the handshake and several copies of the
/// nominating keepalive, and far below the transport idle windows so the
/// outcome comes from the punch rather than from a reaper.
pub const PUNCH_DEADLINE: Duration = Duration::from_secs(5);

/// Cadence of the punch's own repeats: the responder's probe to every
/// candidate, which opens its NAT mapping and holds it open until the
/// initiator's handshake arrives, and the initiator's nominating keepalive
/// while the punch is still settling.
const PUNCH_PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// Cap on distinct peer addresses one punch holds a session for. It bounds
/// both the initiator's candidate fan-out and the sources the responder
/// answers on its unconnected probe socket.
const MAX_PUNCH_PEERS: usize = 8;

/// An authenticated direct session over the punched path. It owns the probe
/// socket, the pump feeding the session, and the keepalive holding the NAT
/// mapping open, so dropping it takes the direct path down.
pub struct PeerLink {
    /// The peer address the session is bound to.
    pub peer: SocketAddr,
    pub tx: DgramTx,
    pub rx: DgramRx,
    hold: LinkHold,
}

/// The transport state a punched session needs kept alive: the KCP session and
/// its datagram registration, the keepalive holding the NAT mapping open, and
/// the pump draining the probe socket.
pub struct LinkHold {
    _sess: Arc<Session>,
    _guard: ConvGuard,
    _keepalive: AbortOnDrop,
    _pump: AbortOnDrop,
}

impl PeerLink {
    /// Split into the two frame halves and the transport state they ride on,
    /// so each part can be owned separately for as long as the session lives.
    pub fn split(self) -> (DgramTx, DgramRx, LinkHold) {
        (self.tx, self.rx, self.hold)
    }
}

/// The path a pair settled on.
pub enum PunchOutcome {
    Direct(PeerLink),
    Relay,
}

/// Attempt a direct session to the peer over `candidates`, the addresses this
/// pair's `PeerInfo` carried, and report the outcome to the server on
/// `control`.
///
/// The party with the lower `client_id` is the Noise initiator and sends
/// handshake message one to every candidate; the other cannot send message
/// one, so it opens its own mapping with punch probes and answers the
/// handshake. Everything rides the probe socket, whose pump is the only
/// reader on it.
///
/// The initiator nominates: the first candidate whose handshake completes
/// wins, and it repeats a keepalive on that conv from the moment it wins. A
/// responder handshake completes by writing message two, which says nothing
/// about the reverse path, so the responder holds every source whose
/// handshake finished and settles on the one a keepalive arrives from. Both
/// ends bind the same path that way even when several candidates are
/// reachable. A path that drops every copy of the nomination leaves the
/// responder on the relay while the initiator holds direct, which the
/// server's relay authority settles. When the deadline passes with no
/// winner, the pair falls back to the relay.
pub async fn punch(
    mut probe: ProbeSession,
    candidates: &[SocketAddr],
    pair_id: u64,
    client_id: &str,
    peer_id: &str,
    psk: &[u8; 32],
    control: &mpsc::Sender<Vec<u8>>,
) -> PunchOutcome {
    // Holding this pair's candidates is the proof its `PeerInfo` arrived, and
    // the probe session is consumed here, so nothing else can stop the
    // local-candidate repeats afterwards.
    probe.stop_candidate_resend();
    // Two clients on one LAN report the same address as both their public and
    // their local candidate, so the list can repeat.
    let mut targets: Vec<SocketAddr> = Vec::new();
    for c in candidates {
        if !targets.contains(c) && targets.len() < MAX_PUNCH_PEERS {
            targets.push(*c);
        }
    }
    if targets.is_empty() {
        report(control, pair_id, PathStatus::Relay);
        return PunchOutcome::Relay;
    }

    let initiator = client_id < peer_id;
    // Both parties derive the same setup conv from the pair id, following the
    // UDP-forward rule, so the responder can reject a conv it did not expect.
    let conv = (pair_id as u32) | SETUP_CONV_BIT;
    let socket = probe.socket.clone();

    let (done_tx, mut done_rx) = mpsc::channel::<(SocketAddr, StatelessNoise)>(MAX_PUNCH_PEERS);
    let mut sessions: HashMap<SocketAddr, Arc<Session>> = HashMap::new();
    // Responder only: sources whose handshake finished, awaiting the
    // initiator's nominating keepalive.
    let mut completed: HashMap<SocketAddr, StatelessNoise> = HashMap::new();
    // Guards for the in-flight handshakes; the losers are aborted when this
    // function returns.
    let mut attempts: Vec<AbortOnDrop> = Vec::new();

    if initiator {
        for &cand in &targets {
            let sess = kcp_session(socket.clone(), cand, 1);
            let stream = sess.open_conv_with(CLASS_SETUP, conv);
            sessions.insert(cand, sess);
            let psk = *psk;
            let done = done_tx.clone();
            attempts.push(AbortOnDrop(crate::spawn(async move {
                if let Ok(noise) = client_handshake_stateless(stream, &psk, pair_id).await {
                    done.send((cand, noise)).await.ok();
                }
            })));
        }
    }

    let mut probes = interval(PUNCH_PROBE_INTERVAL);
    let deadline = sleep(PUNCH_DEADLINE);
    tokio::pin!(deadline);

    let landed = loop {
        // Biased so a finished handshake is always recorded before the next
        // datagram is judged: the nominating keepalive can otherwise reach
        // the queue while its own completion still sits in the channel, and
        // the responder would discard the nomination.
        tokio::select! {
            biased;
            _ = &mut deadline => break None,
            done = done_rx.recv() => {
                let Some((addr, noise)) = done else { break None };
                if initiator {
                    // Message two arrived, so this candidate carries traffic
                    // both ways. Nominate it.
                    break sessions.get(&addr).map(|sess| (addr, sess.clone(), noise));
                }
                completed.insert(addr, noise);
            }
            _ = probes.tick(), if !initiator => {
                for cand in &targets {
                    socket.send_to(&[CLASS_PUNCH], cand).await.ok();
                }
            }
            queued = probe.recv_peer() => {
                let Some((src, data)) = queued else { break None };
                // Both roles drop every punch probe: it opens the responder's
                // mapping and carries nothing, and nomination rides the
                // keepalive.
                if data == [CLASS_PUNCH] {
                    continue;
                }
                // The nominating keepalive lands before `register_dgram` has
                // run, so the router would drop its body. Match it on the raw
                // datagram and settle only when it opens under the keys that
                // source's handshake produced.
                if !initiator {
                    if let Some(body) = dgram_body(&data, conv) {
                        if let Some(noise) = completed.remove(&src) {
                            match sessions.get(&src) {
                                Some(sess) if noise.open(body).is_ok() => {
                                    break Some((src, sess.clone(), noise));
                                }
                                // Not the nomination; keep the handshake for a
                                // later keepalive from the same source.
                                _ => {
                                    completed.insert(src, noise);
                                }
                            }
                        }
                        continue;
                    }
                }
                let sess = match sessions.get(&src) {
                    Some(sess) => sess.clone(),
                    // The initiator only ever hears back from a candidate it
                    // sent message one to; the responder learns the peer's
                    // source address from the handshake itself, bounded so an
                    // unconnected socket cannot be flooded into sessions.
                    None if initiator || sessions.len() >= MAX_PUNCH_PEERS => continue,
                    None => {
                        let sess = kcp_session(socket.clone(), src, 1);
                        sessions.insert(src, sess.clone());
                        sess
                    }
                };
                match route(&sess, &data) {
                    // Only the responder answers a handshake, and only on the
                    // conv both sides derive from the pair id.
                    Some(Accepted::Setup { conv: got, stream }) if !initiator && got == conv => {
                        let psk = *psk;
                        let done = done_tx.clone();
                        attempts.push(AbortOnDrop(crate::spawn(async move {
                            if let Ok((id, noise)) =
                                server_handshake_stateless(stream, &psk, &[]).await
                            {
                                if id == pair_id {
                                    done.send((src, noise)).await.ok();
                                }
                            }
                        })));
                    }
                    _ => {}
                }
            }
        }
    };

    // A candidate that lost the race, or all of them when the deadline won,
    // has nobody answering: close it so KCP stops retransmitting the
    // handshake into a black hole for the rest of its idle window.
    let winner = landed.as_ref().map(|(peer, _, _)| *peer);
    for (addr, sess) in &sessions {
        if Some(*addr) != winner {
            sess.close();
        }
    }

    let Some((peer, sess, noise)) = landed else {
        report(control, pair_id, PathStatus::Relay);
        return PunchOutcome::Relay;
    };

    let noise = Arc::new(noise);
    let (inbound, guard) = sess.register_dgram(conv);
    let tx = DgramTx::new(sess.send_tx(), conv, noise.clone());
    let rx = DgramRx::new(inbound, noise.clone());
    let keepalive = {
        let tx = DgramTx::new(sess.send_tx(), conv, noise);
        AbortOnDrop(crate::spawn(async move {
            // Every other punch message is a KCP segment and is retransmitted;
            // the initiator's nomination rides the unreliable datagram channel,
            // so it repeats on the punch cadence until the deadline has passed
            // rather than leaving the responder one copy to lose. After that
            // both roles just hold the NAT mapping open. The first tick of
            // either interval completes at once, so the nomination goes out
            // the moment the candidate wins.
            let start = Instant::now();
            let mut nominating = initiator;
            let mut tick = interval(if nominating {
                PUNCH_PROBE_INTERVAL
            } else {
                PING_INTERVAL
            });
            loop {
                tick.tick().await;
                if tx.probe().await.is_err() {
                    break;
                }
                if nominating && start.elapsed() >= PUNCH_DEADLINE {
                    tick = interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
                    nominating = false;
                }
            }
        }))
    };
    // The probe socket's pump stays the only reader on it, and the punched
    // session's traffic arrives through the same queue, so the link keeps
    // draining it and routing the winner's datagrams for as long as it lives.
    let pump = {
        let sess = sess.clone();
        AbortOnDrop(crate::spawn(async move {
            while let Some((src, data)) = probe.recv_peer().await {
                if src == peer {
                    route(&sess, &data);
                }
            }
        }))
    };
    report(control, pair_id, PathStatus::Direct);
    PunchOutcome::Direct(PeerLink {
        peer,
        tx,
        rx,
        hold: LinkHold {
            _sess: sess,
            _guard: guard,
            _keepalive: keepalive,
            _pump: pump,
        },
    })
}

/// The sealed body of a datagram-channel frame on `conv`, or `None` when the
/// datagram is anything else.
fn dgram_body(datagram: &[u8], conv: u32) -> Option<&[u8]> {
    let (&class, rest) = datagram.split_first()?;
    if class != CLASS_DGRAM || rest.len() < 4 {
        return None;
    }
    let (tag, body) = rest.split_at(4);
    (u32::from_be_bytes(tag.try_into().unwrap()) == conv).then_some(body)
}

/// Tell the server which path this party settled on. The punched flow never
/// reaches the server, so this report is the only way it learns the result.
fn report(control: &mpsc::Sender<Vec<u8>>, pair_id: u64, status: PathStatus) {
    control
        .try_send(Msg::PeerPath { pair_id, status }.encode())
        .ok();
}
