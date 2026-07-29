use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{interval_at, sleep, timeout, Instant};

use crate::client::{AbortOnDrop, RelayDgramLeg, PING_INTERVAL};
use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::kcp::ConvGuard;
use crate::noise::{
    client_handshake_stateless_reply, server_handshake_stateless, Noise, NoiseReader, NoiseWriter,
    StatelessNoise,
};
use crate::punch::{LinkHold, PeerLink};
use crate::{Error, Result};

/// Cadence of the inner session's keepalive.
pub const PEER_KEEPALIVE: Duration = PING_INTERVAL;

/// Missed keepalives before a party declares its peer gone.
const PEER_MISSES: u64 = 3;

/// How long a session goes without hearing anything before it reports itself
/// dead. It waits one interval past the missed keepalives, so the last of them
/// is counted lost rather than racing the boundary it would arrive on. A
/// consumer sends all its traffic into the pair, so the pair owns detecting a
/// dead peer; the transport's idle reap would leave that traffic falling into
/// a hole for far longer.
pub const PEER_DEADLINE: Duration =
    Duration::from_secs(PEER_KEEPALIVE.as_secs() * (PEER_MISSES + 1));

/// How long the inner handshake tries before giving up. Either message can be
/// lost, so neither side trusts one delivery: each repeats its last message on
/// [`HANDSHAKE_RETRY`] until the exchange completes or this passes.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const HANDSHAKE_RETRY: Duration = Duration::from_millis(500);

/// Room for one handshake message in each direction of the duplex the
/// handshake runs over; the messages are under a hundred bytes.
const HANDSHAKE_BUF: usize = 4096;

/// Leading byte of every frame this layer emits, naming what follows: a raw
/// handshake message, or a sealed session frame. A party still handshaking
/// feeds its state machine only handshake messages, since that machine
/// consumes its transcript on the first thing it reads and cannot be
/// restarted. The byte rides outside the seal.
pub const FRAME_HANDSHAKE: u8 = 0x00;
pub const FRAME_SESSION: u8 = 0x01;

/// First byte of a sealed frame's plaintext. It keeps a keepalive apart from
/// an adapter frame, and with the frame byte outside it no frame this layer
/// emits is empty: a zero-length frame is a keepalive on a stream leg and
/// vanishes when written to one.
const KIND_DATA: u8 = 0x00;
const KIND_KEEPALIVE: u8 = 0x01;

/// What one UDP payload holds, the ceiling the dgram leg works down from.
const MAX_DATAGRAM: usize = 65507;
/// What the datagram hop spends on a frame: its class byte, tag and kind byte,
/// and the hop's own nonce and authentication tag.
const HOP_OVERHEAD: usize = 1 + 4 + 1 + 24;
/// What this layer spends: the frame byte, the session seal's nonce and
/// authentication tag, and the sealed plaintext's kind byte.
const FRAME_OVERHEAD: usize = 1 + 24 + 1;

/// Largest payload one frame carries. A dgram leg cannot fit more in one
/// datagram and a stream leg splits more across two Noise records, and neither
/// end reassembles, so a larger frame is refused rather than swallowed.
pub const MAX_FRAME: usize = MAX_DATAGRAM - HOP_OVERHEAD - FRAME_OVERHEAD;

/// Frames a session queues in each direction before its owner blocks.
const SESSION_QUEUE: usize = 256;

/// Which end of the pair this party is: the consumer asked for the session, so
/// it runs the handshake's initiator and the provider answers.
#[derive(Clone, Copy)]
enum Role {
    Consumer,
    Provider,
}

/// The read half of a framed peer path.
enum PathRx {
    Dgram(DgramRx),
    Stream(NoiseReader),
}

/// The write half of a framed peer path.
enum PathTx {
    Dgram(DgramTx),
    Stream(NoiseWriter),
}

/// Transport state a path keeps alive under itself: a punched session's
/// guards, or a relay dgram leg's tag registration. A stream leg holds nothing
/// beyond its two halves.
enum PathHold {
    Link { _hold: LinkHold },
    Leg { _guard: ConvGuard },
    Stream,
}

impl PathRx {
    /// The next inner frame, or `None` once the path dies. A dgram keepalive
    /// belongs to the hop below and an empty frame cannot survive a stream
    /// leg, so both are dropped here exactly as the relay drops them.
    async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            match self {
                PathRx::Dgram(rx) => match rx.recv().await? {
                    Frame::Data(body) if !body.is_empty() => return Some(body),
                    _ => continue,
                },
                PathRx::Stream(r) => match r.recv().await {
                    Ok(frame) if frame.is_empty() => continue,
                    Ok(frame) => return Some(frame),
                    Err(_) => return None,
                },
            }
        }
    }
}

impl PathTx {
    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        match self {
            PathTx::Dgram(tx) => tx.send(frame).await,
            PathTx::Stream(w) => w.send(frame).await,
        }
    }
}

/// A framed channel to the peer: whole frames in, whole frames out, lossy and
/// unordered whichever way the pair settled. The punched session and both
/// relay legs already carry whole frames, so an inner session runs over any of
/// them unchanged.
pub struct PeerPath {
    rx: PathRx,
    tx: PathTx,
    hold: PathHold,
}

impl PeerPath {
    /// The punched direct session.
    pub fn direct(link: PeerLink) -> Self {
        let (tx, rx, hold) = link.split();
        PeerPath {
            rx: PathRx::Dgram(rx),
            tx: PathTx::Dgram(tx),
            hold: PathHold::Link { _hold: hold },
        }
    }

    /// This party's relay leg on the datagram channel.
    pub fn relay_dgram(leg: RelayDgramLeg) -> Self {
        let (tx, rx, guard) = leg.split();
        PeerPath {
            rx: PathRx::Dgram(rx),
            tx: PathTx::Dgram(tx),
            hold: PathHold::Leg { _guard: guard },
        }
    }

    /// This party's relay leg on the stream transport, one inner frame per
    /// Noise record.
    pub fn relay_stream(leg: Noise) -> Self {
        let (r, w) = leg;
        PeerPath {
            rx: PathRx::Stream(r),
            tx: PathTx::Stream(w),
            hold: PathHold::Stream,
        }
    }
}

/// A responder's answer to a message one it already handled: the message it
/// consumed, and the frame to send again if that copy comes back because the
/// first answer was lost.
struct Retransmit {
    seen: Vec<u8>,
    reply: Vec<u8>,
}

/// An encrypted frame session between two peers. Both sides handshake
/// `NNpsk0` with the deployment secret over the path that came up, so a
/// relayed pair moves ciphertext the server holds no key for and direct and
/// relayed are the same thing above this layer.
pub struct PeerSession {
    noise: Arc<StatelessNoise>,
    out: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<Vec<u8>>,
    /// Cleared when the reader reaps the peer, so a write-only owner learns
    /// the session is gone from the send side too.
    alive: Arc<AtomicBool>,
    _hold: PathHold,
    /// The reader owns the writer and the keepalive, so reaping a dead peer
    /// stops this party writing into the path as well, and dropping the
    /// session stops all three.
    _reader: AbortOnDrop,
}

impl PeerSession {
    /// The consumer's side: run the handshake's initiator over `path` and
    /// return the session with the provider's answer, which is empty when it
    /// accepted the pair.
    pub async fn consumer(path: PeerPath, psk: &[u8; 32], pair_id: u64) -> Result<(Self, Vec<u8>)> {
        Self::start(path, Role::Consumer, &[], psk, pair_id).await
    }

    /// The provider's side: answer the handshake, sealing `refuse` into
    /// message two. An empty payload accepts the pair.
    pub async fn provider(
        path: PeerPath,
        psk: &[u8; 32],
        pair_id: u64,
        refuse: &[u8],
    ) -> Result<Self> {
        let (session, _) = Self::start(path, Role::Provider, refuse, psk, pair_id).await?;
        Ok(session)
    }

    /// Handshake over `path` and start the session's keepalive and liveness
    /// watch. `pair_id` rides the handshake payload, so a responder rejects a
    /// party that names another pair.
    async fn start(
        path: PeerPath,
        role: Role,
        refuse: &[u8],
        psk: &[u8; 32],
        pair_id: u64,
    ) -> Result<(Self, Vec<u8>)> {
        let PeerPath {
            mut rx,
            mut tx,
            hold,
        } = path;
        let (noise, answer, retransmit) =
            handshake(role, refuse, &mut rx, &mut tx, psk, pair_id).await?;
        let noise = Arc::new(noise);

        let (out, mut outbox) = mpsc::channel::<Vec<u8>>(SESSION_QUEUE);
        let (deliver, inbound) = mpsc::channel::<Vec<u8>>(SESSION_QUEUE);
        let writer = AbortOnDrop(crate::spawn(async move {
            while let Some(frame) = outbox.recv().await {
                if tx.send(&frame).await.is_err() {
                    break;
                }
            }
        }));
        let keepalive = {
            let noise = noise.clone();
            let out = out.clone();
            AbortOnDrop(crate::spawn(async move {
                // The handshake just proved liveness, so the first keepalive
                // waits a full interval.
                let mut tick = interval_at(Instant::now() + PEER_KEEPALIVE, PEER_KEEPALIVE);
                loop {
                    tick.tick().await;
                    if out
                        .send(session_frame(&noise, KIND_KEEPALIVE, &[]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }))
        };
        let alive = Arc::new(AtomicBool::new(true));
        let reader = {
            let noise = noise.clone();
            let out = out.clone();
            let alive = alive.clone();
            AbortOnDrop(crate::spawn(async move {
                let _writer = writer;
                let _keepalive = keepalive;
                // Anything that opens proves the peer is alive; a frame that
                // does not could be from anyone, so it never refreshes the
                // deadline.
                let mut heard = Instant::now();
                loop {
                    let left = PEER_DEADLINE.saturating_sub(heard.elapsed());
                    let Ok(Some(frame)) = timeout(left, rx.recv()).await else {
                        break;
                    };
                    match frame.split_first() {
                        Some((&FRAME_SESSION, body)) => {
                            let Ok(plaintext) = noise.open(body) else {
                                continue;
                            };
                            heard = Instant::now();
                            if let Some((&KIND_DATA, payload)) = plaintext.split_first() {
                                if deliver.send(payload.to_vec()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        // The peer repeating the message one this party
                        // answered: its message two was lost on the way, so
                        // send that answer again.
                        Some((&FRAME_HANDSHAKE, msg)) => {
                            if let Some(again) = &retransmit {
                                if again.seen == msg {
                                    out.send(again.reply.clone()).await.ok();
                                }
                            }
                        }
                        _ => {}
                    }
                }
                alive.store(false, Ordering::Relaxed);
            }))
        };

        Ok((
            PeerSession {
                noise,
                out,
                inbound,
                alive,
                _hold: hold,
                _reader: reader,
            },
            answer,
        ))
    }

    /// Send one frame to the peer. A frame past [`MAX_FRAME`] is refused: it
    /// crosses neither leg whole, and neither end reassembles.
    pub async fn send(&self, frame: &[u8]) -> Result<()> {
        if !self.alive.load(Ordering::Relaxed) {
            return Err("peer session is dead".into());
        }
        if frame.len() > MAX_FRAME {
            return Err(format!(
                "peer frame of {} bytes is past the {MAX_FRAME}-byte limit",
                frame.len()
            )
            .into());
        }
        self.out
            .send(session_frame(&self.noise, KIND_DATA, frame))
            .await
            .map_err(|_| -> Error { "peer session closed".into() })
    }

    /// The next frame from the peer, or `None` once the session is dead: the
    /// path died, or three keepalives went missing.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }
}

/// Seal one frame for the session: the frame byte, then the kind-tagged
/// plaintext under the session keys.
fn session_frame(noise: &StatelessNoise, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(kind);
    plaintext.extend_from_slice(payload);
    let sealed = noise.seal(&plaintext);
    let mut frame = Vec::with_capacity(1 + sealed.len());
    frame.push(FRAME_SESSION);
    frame.extend_from_slice(&sealed);
    frame
}

/// Run the inner handshake over the path, repeating the last message sent
/// until the exchange completes. The existing stateless `NNpsk0` state machine
/// drives it over a duplex: whatever it writes leaves as one path frame, and
/// the handshake messages the path delivers are fed back in. Returns the
/// transport keys, the responder's message-two payload, and the answer to
/// repeat for a responder.
async fn handshake(
    role: Role,
    refuse: &[u8],
    rx: &mut PathRx,
    tx: &mut PathTx,
    psk: &[u8; 32],
    pair_id: u64,
) -> Result<(StatelessNoise, Vec<u8>, Option<Retransmit>)> {
    let (mine, theirs) = tokio::io::duplex(HANDSHAKE_BUF);
    let (mut mine_rx, mut mine_tx) = tokio::io::split(mine);
    let mut task = {
        let psk = *psk;
        let refuse = refuse.to_vec();
        AbortOnDrop(crate::spawn(async move {
            match role {
                Role::Consumer => client_handshake_stateless_reply(theirs, &psk, pair_id).await,
                Role::Provider => {
                    let (id, noise) = server_handshake_stateless(theirs, &psk, &refuse).await?;
                    if id != pair_id {
                        return Err("inner handshake names another pair".into());
                    }
                    Ok((noise, Vec::new()))
                }
            }
        }))
    };

    let mut written = Vec::new();
    let mut last_sent: Option<Vec<u8>> = None;
    let mut first_seen: Option<Vec<u8>> = None;
    let mut resend = interval_at(Instant::now() + HANDSHAKE_RETRY, HANDSHAKE_RETRY);
    let deadline = sleep(HANDSHAKE_DEADLINE);
    tokio::pin!(deadline);

    let (noise, answer) = loop {
        // Biased so the finished state machine is seen before its side of the
        // duplex is read again: that half closes when it returns, and a closed
        // read is ready forever.
        tokio::select! {
            biased;
            _ = &mut deadline => return Err("inner handshake timed out".into()),
            done = &mut task.0 => break done??,
            read = mine_rx.read_buf(&mut written) => {
                read?;
                for msg in take_messages(&mut written) {
                    last_sent = Some(send_handshake(tx, &msg).await?);
                }
            }
            frame = rx.recv() => {
                let Some(frame) = frame else {
                    return Err("peer path closed during the inner handshake".into());
                };
                // Only a handshake message reaches the state machine: it
                // consumes its transcript on whatever it reads first and
                // cannot start over, so anything else is dropped and the
                // retransmit and the deadline decide the outcome.
                let Some((&FRAME_HANDSHAKE, msg)) = frame.split_first() else {
                    continue;
                };
                match &first_seen {
                    // A repeat of the message already in the transcript:
                    // feeding it in again would break the handshake, so
                    // answer it with the last message instead.
                    Some(seen) if seen == msg => {
                        if let Some(frame) = &last_sent {
                            tx.send(frame).await?;
                        }
                    }
                    // Anything else arriving mid-handshake is reordered or
                    // stale; the pipe promises neither order nor delivery.
                    Some(_) => {}
                    None => {
                        mine_tx.write_all(&(msg.len() as u16).to_be_bytes()).await?;
                        mine_tx.write_all(msg).await?;
                        first_seen = Some(msg.to_vec());
                    }
                }
            }
            _ = resend.tick() => {
                if let Some(frame) = &last_sent {
                    tx.send(frame).await?;
                }
            }
        }
    };

    // The last message can still sit in the duplex when the state machine
    // returns, so drain what is left before the handshake stops driving.
    while mine_rx.read_buf(&mut written).await? > 0 {}
    for msg in take_messages(&mut written) {
        last_sent = Some(send_handshake(tx, &msg).await?);
    }

    // Only the responder has an answer to repeat: the initiator is done the
    // moment message two opens.
    let retransmit = match (role, first_seen, last_sent) {
        (Role::Provider, Some(seen), Some(reply)) => Some(Retransmit { seen, reply }),
        _ => None,
    };
    Ok((noise, answer, retransmit))
}

/// Send one handshake message and return the frame it went out as, for the
/// repeats that follow.
async fn send_handshake(tx: &mut PathTx, msg: &[u8]) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(1 + msg.len());
    frame.push(FRAME_HANDSHAKE);
    frame.extend_from_slice(msg);
    tx.send(&frame).await?;
    Ok(frame)
}

/// Cut the whole length-delimited messages out of what the handshake wrote,
/// leaving any partial one behind.
fn take_messages(written: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0;
    while written.len() >= off + 2 {
        let len = u16::from_be_bytes([written[off], written[off + 1]]) as usize;
        if written.len() < off + 2 + len {
            break;
        }
        out.push(written[off + 2..off + 2 + len].to_vec());
        off += 2 + len;
    }
    written.drain(..off);
    out
}

/// Both ends of one inner session, handshaked over a duplex standing in for a
/// relay leg. The provider answers with an empty payload, so the pair is one
/// an adapter can run over.
#[cfg(test)]
pub(crate) async fn duplex_pair(secret: &str, pair_id: u64) -> (PeerSession, PeerSession) {
    let psk = crate::noise::derive_psk(secret);
    let (a, b) = tokio::io::duplex(1 << 16);
    let responder =
        crate::spawn(async move { crate::noise::server_handshake(b, &psk).await.unwrap() });
    let initiator = crate::noise::client_handshake(a, &psk).await.unwrap();
    let responder = responder.await.unwrap();
    let ((consumer, answer), provider) = tokio::try_join!(
        PeerSession::consumer(PeerPath::relay_stream(initiator), &psk, pair_id),
        PeerSession::provider(PeerPath::relay_stream(responder), &psk, pair_id, &[]),
    )
    .expect("the inner handshake must complete on both sides");
    assert!(answer.is_empty());
    (consumer, provider)
}
