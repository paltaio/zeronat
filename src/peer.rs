use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use snow::{Builder, HandshakeState};
use tokio::sync::mpsc;
use tokio::time::{interval_at, timeout, Instant};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::client::{AbortOnDrop, RelayDgramLeg, PING_INTERVAL};
use crate::dgram::{DgramRx, DgramTx, Frame};
use crate::kcp::ConvGuard;
use crate::noise::{Noise, NoiseReader, NoiseWriter, StatelessNoise};
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

/// Room for one handshake message in each direction of the duplex.
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

impl Role {
    fn initiator(self) -> bool {
        matches!(self, Role::Consumer)
    }
}

#[derive(Clone)]
pub struct PairIdentity {
    static_private: [u8; 32],
    auth: crate::proto::PairAuth,
    context: PairContext,
}

#[derive(Clone)]
pub struct PairContext {
    pub local_id: String,
    pub peer_id: String,
    pub provides: u8,
}

impl PairIdentity {
    pub fn new(
        static_private: [u8; 32],
        auth: crate::proto::PairAuth,
        context: PairContext,
    ) -> Self {
        PairIdentity {
            static_private,
            auth,
            context,
        }
    }
}

pub fn public_identity(static_private: &[u8; 32]) -> [u8; 32] {
    x25519(*static_private, X25519_BASEPOINT_BYTES)
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

/// An encrypted frame session between two peers.
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
    pub async fn consumer(
        path: PeerPath,
        identity: &PairIdentity,
        pair_id: u64,
    ) -> Result<(Self, Vec<u8>)> {
        Self::start(path, Role::Consumer, &[], identity, pair_id).await
    }

    /// The provider's side: answer the handshake, sealing `refuse` into
    /// message two. An empty payload accepts the pair.
    pub async fn provider(
        path: PeerPath,
        identity: &PairIdentity,
        pair_id: u64,
        refuse: &[u8],
    ) -> Result<Self> {
        let (session, _) = Self::start(path, Role::Provider, refuse, identity, pair_id).await?;
        Ok(session)
    }

    /// Handshake over `path` and start the session's keepalive and liveness
    /// watch. `pair_id` rides the handshake payload, so a responder rejects a
    /// party that names another pair.
    async fn start(
        path: PeerPath,
        role: Role,
        refuse: &[u8],
        identity: &PairIdentity,
        pair_id: u64,
    ) -> Result<(Self, Vec<u8>)> {
        let PeerPath {
            mut rx,
            mut tx,
            hold,
        } = path;
        let (noise, answer, retransmit) =
            handshake(role, refuse, &mut rx, &mut tx, identity, pair_id).await?;
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
                    let Ok(frame) = session_frame(&noise, KIND_KEEPALIVE, &[]) else {
                        break;
                    };
                    if out.send(frame).await.is_err() {
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
            .send(session_frame(&self.noise, KIND_DATA, frame)?)
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
fn session_frame(noise: &StatelessNoise, kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(kind);
    plaintext.extend_from_slice(payload);
    let sealed = noise.seal(&plaintext)?;
    let mut frame = Vec::with_capacity(1 + sealed.len());
    frame.push(FRAME_SESSION);
    frame.extend_from_slice(&sealed);
    Ok(frame)
}

const PEER_NOISE: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const SESSION_KEY_BYTES: usize = 64;
const HANDSHAKE_ACK: &[u8] = b"zeronat-peer-ready-v1";

/// Run Noise XX over the selected path and distribute random directional
/// datagram keys inside the authenticated channel.
async fn handshake(
    role: Role,
    refuse: &[u8],
    rx: &mut PathRx,
    tx: &mut PathTx,
    identity: &PairIdentity,
    pair_id: u64,
) -> Result<(StatelessNoise, Vec<u8>, Option<Retransmit>)> {
    timeout(HANDSHAKE_DEADLINE, async {
        if role.initiator() {
            handshake_initiator(refuse, rx, tx, identity, pair_id).await
        } else {
            handshake_responder(refuse, rx, tx, identity, pair_id).await
        }
    })
    .await
    .map_err(|_| -> Error { "inner handshake timed out".into() })?
}

async fn handshake_initiator(
    _refuse: &[u8],
    rx: &mut PathRx,
    tx: &mut PathTx,
    identity: &PairIdentity,
    pair_id: u64,
) -> Result<(StatelessNoise, Vec<u8>, Option<Retransmit>)> {
    let mut state = peer_handshake_state(identity, Role::Consumer, pair_id)?;
    let message_one = noise_write(&mut state, &[])?;
    let frame_one = send_handshake(tx, &message_one).await?;
    let mut retry = interval_at(Instant::now() + HANDSHAKE_RETRY, HANDSHAKE_RETRY);
    let message_two = loop {
        tokio::select! {
            _ = retry.tick() => tx.send(&frame_one).await?,
            message = recv_handshake(rx) => break message?,
        }
    };
    let mut answer = vec![0; HANDSHAKE_BUF];
    let answer_len = state.read_message(&message_two, &mut answer)?;
    answer.truncate(answer_len);
    verify_remote_identity(&state, &identity.context.peer_id)?;

    let mut keys = [0; SESSION_KEY_BYTES];
    getrandom::getrandom(&mut keys)?;
    let message_three = noise_write(&mut state, &keys)?;
    let frame_three = send_handshake(tx, &message_three).await?;
    let mut transport = state.into_transport_mode()?;
    let mut retry = interval_at(Instant::now() + HANDSHAKE_RETRY, HANDSHAKE_RETRY);
    loop {
        tokio::select! {
            _ = retry.tick() => tx.send(&frame_three).await?,
            message = recv_handshake(rx) => {
                let message = message?;
                if message == message_two {
                    tx.send(&frame_three).await?;
                    continue;
                }
                let mut ack = [0; 64];
                let len = transport.read_message(&message, &mut ack)?;
                if &ack[..len] != HANDSHAKE_ACK {
                    return Err("invalid peer handshake acknowledgement".into());
                }
                break;
            }
        }
    }
    Ok((StatelessNoise::from_peer_keys(&keys, true), answer, None))
}

async fn handshake_responder(
    refuse: &[u8],
    rx: &mut PathRx,
    tx: &mut PathTx,
    identity: &PairIdentity,
    pair_id: u64,
) -> Result<(StatelessNoise, Vec<u8>, Option<Retransmit>)> {
    let mut state = peer_handshake_state(identity, Role::Provider, pair_id)?;
    let message_one = recv_handshake(rx).await?;
    let mut empty = [0; 1];
    if state.read_message(&message_one, &mut empty)? != 0 {
        return Err("unexpected peer handshake payload".into());
    }
    let message_two = noise_write(&mut state, refuse)?;
    let frame_two = send_handshake(tx, &message_two).await?;
    let mut retry = interval_at(Instant::now() + HANDSHAKE_RETRY, HANDSHAKE_RETRY);
    let message_three = loop {
        tokio::select! {
            _ = retry.tick() => tx.send(&frame_two).await?,
            message = recv_handshake(rx) => {
                let message = message?;
                if message == message_one {
                    tx.send(&frame_two).await?;
                    continue;
                }
                break message;
            }
        }
    };
    let mut keys = [0; SESSION_KEY_BYTES];
    if state.read_message(&message_three, &mut keys)? != SESSION_KEY_BYTES {
        return Err("invalid peer session key payload".into());
    }
    verify_remote_identity(&state, &identity.context.peer_id)?;
    let mut transport = state.into_transport_mode()?;
    let mut ack = [0; 128];
    let ack_len = transport.write_message(HANDSHAKE_ACK, &mut ack)?;
    let ack_frame = send_handshake(tx, &ack[..ack_len]).await?;
    Ok((
        StatelessNoise::from_peer_keys(&keys, false),
        Vec::new(),
        Some(Retransmit {
            seen: message_three,
            reply: ack_frame,
        }),
    ))
}

fn peer_handshake_state(
    identity: &PairIdentity,
    role: Role,
    pair_id: u64,
) -> Result<HandshakeState> {
    let local_identity = crate::secret::encode(public_identity(&identity.static_private));
    if local_identity != identity.context.local_id {
        return Err("local peer identity does not match its private key".into());
    }
    crate::secret::decode(&identity.context.peer_id)
        .map_err(|_| -> Error { "peer identity must be 64 hexadecimal characters".into() })?;
    let prologue = peer_prologue(identity, role, pair_id);
    let params = PEER_NOISE
        .parse()
        .map_err(|_| -> Error { "invalid peer Noise parameters".into() })?;
    let builder = Builder::new(params)
        .local_private_key(&identity.static_private)
        .prologue(&prologue);
    if role.initiator() {
        Ok(builder.build_initiator()?)
    } else {
        Ok(builder.build_responder()?)
    }
}

fn peer_prologue(identity: &PairIdentity, role: Role, pair_id: u64) -> Vec<u8> {
    let (consumer_id, provider_id) = match role {
        Role::Consumer => (
            identity.context.local_id.as_str(),
            identity.context.peer_id.as_str(),
        ),
        Role::Provider => (
            identity.context.peer_id.as_str(),
            identity.context.local_id.as_str(),
        ),
    };
    let mut prologue = Vec::new();
    prologue.extend_from_slice(b"zeronat-peer-noise-v1");
    prologue.push(crate::identity::PROTO_VERSION);
    prologue.extend_from_slice(&pair_id.to_be_bytes());
    prologue.push(identity.context.provides);
    prologue.extend_from_slice(consumer_id.as_bytes());
    prologue.extend_from_slice(provider_id.as_bytes());
    prologue.extend_from_slice(&identity.auth.challenge);
    prologue
}

fn verify_remote_identity(state: &HandshakeState, expected: &str) -> Result<()> {
    let expected = crate::secret::decode(expected)
        .map_err(|_| -> Error { "peer identity must be 64 hexadecimal characters".into() })?;
    if state.get_remote_static() != Some(expected.as_slice()) {
        return Err("peer identity authentication failed".into());
    }
    Ok(())
}

fn noise_write(state: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>> {
    let mut message = vec![0; HANDSHAKE_BUF];
    let len = state.write_message(payload, &mut message)?;
    message.truncate(len);
    Ok(message)
}

async fn recv_handshake(rx: &mut PathRx) -> Result<Vec<u8>> {
    loop {
        let Some(frame) = rx.recv().await else {
            return Err("peer path closed during the inner handshake".into());
        };
        if let Some((&FRAME_HANDSHAKE, message)) = frame.split_first() {
            return Ok(message.to_vec());
        }
    }
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

/// Both ends of one inner session, handshaked over a duplex standing in for a
/// relay leg. The provider answers with an empty payload, so the pair is one
/// an adapter can run over.
#[cfg(test)]
pub(crate) async fn duplex_pair(secret: &str, pair_id: u64) -> (PeerSession, PeerSession) {
    let consumer_psk = crate::noise::derive_psk(secret);
    let provider_psk = crate::noise::derive_psk(&format!("{secret}-provider"));
    let auth_psk = crate::noise::derive_psk(&format!("{secret}-pair"));
    let consumer_id = crate::secret::encode(public_identity(&consumer_psk));
    let provider_id = crate::secret::encode(public_identity(&provider_psk));
    let consumer_identity = PairIdentity::new(
        consumer_psk,
        crate::proto::PairAuth {
            challenge: auth_psk,
        },
        PairContext {
            local_id: consumer_id.clone(),
            peer_id: provider_id.clone(),
            provides: crate::proto::PROVIDES_EXIT,
        },
    );
    let provider_identity = PairIdentity::new(
        provider_psk,
        crate::proto::PairAuth {
            challenge: auth_psk,
        },
        PairContext {
            local_id: provider_id,
            peer_id: consumer_id,
            provides: crate::proto::PROVIDES_EXIT,
        },
    );
    let (a, b) = tokio::io::duplex(1 << 16);
    let psk = auth_psk;
    let responder =
        crate::spawn(async move { crate::noise::server_handshake(b, &psk).await.unwrap() });
    let initiator = crate::noise::client_handshake(a, &psk).await.unwrap();
    let responder = responder.await.unwrap();
    let ((consumer, answer), provider) = tokio::try_join!(
        PeerSession::consumer(
            PeerPath::relay_stream(initiator),
            &consumer_identity,
            pair_id
        ),
        PeerSession::provider(
            PeerPath::relay_stream(responder),
            &provider_identity,
            pair_id,
            &[],
        ),
    )
    .expect("the inner handshake must complete on both sides");
    assert!(answer.is_empty());
    (consumer, provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn another_clients_peer_secret_cannot_impersonate_the_expected_peer() {
        let consumer_static = crate::noise::derive_psk("consumer private key");
        let provider_static = crate::noise::derive_psk("provider private key");
        let attacker_static = crate::noise::derive_psk("attacker private key");
        let pair_challenge = crate::noise::derive_psk("pair challenge");
        let consumer_id = crate::secret::encode(public_identity(&consumer_static));
        let provider_id = crate::secret::encode(public_identity(&provider_static));
        let consumer_identity = PairIdentity::new(
            consumer_static,
            crate::proto::PairAuth {
                challenge: pair_challenge,
            },
            PairContext {
                local_id: consumer_id.clone(),
                peer_id: provider_id.clone(),
                provides: crate::proto::PROVIDES_EXIT,
            },
        );
        let impostor_identity = PairIdentity::new(
            attacker_static,
            crate::proto::PairAuth {
                challenge: pair_challenge,
            },
            PairContext {
                local_id: provider_id,
                peer_id: consumer_id,
                provides: crate::proto::PROVIDES_EXIT,
            },
        );
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk = pair_challenge;
        let responder =
            crate::spawn(async move { crate::noise::server_handshake(b, &psk).await.unwrap() });
        let initiator = crate::noise::client_handshake(a, &psk).await.unwrap();
        let responder = responder.await.unwrap();
        let (consumer, impostor) = tokio::join!(
            PeerSession::consumer(PeerPath::relay_stream(initiator), &consumer_identity, 41),
            PeerSession::provider(
                PeerPath::relay_stream(responder),
                &impostor_identity,
                41,
                &[],
            ),
        );
        assert!(
            consumer.is_err() || impostor.is_err(),
            "another client's private key must not authenticate as the expected peer"
        );
    }

    #[test]
    fn client_cannot_claim_the_opposite_pair_role() {
        let consumer_static = [1; 32];
        let provider_static = [2; 32];
        let consumer_id = crate::secret::encode(public_identity(&consumer_static));
        let provider_id = crate::secret::encode(public_identity(&provider_static));
        let auth = crate::proto::PairAuth { challenge: [3; 32] };
        let consumer = PairIdentity::new(
            consumer_static,
            auth,
            PairContext {
                local_id: consumer_id.clone(),
                peer_id: provider_id.clone(),
                provides: crate::proto::PROVIDES_EXIT,
            },
        );
        let provider = PairIdentity::new(
            provider_static,
            auth,
            PairContext {
                local_id: provider_id,
                peer_id: consumer_id,
                provides: crate::proto::PROVIDES_EXIT,
            },
        );

        let expected = peer_prologue(&provider, Role::Provider, 41);
        assert_eq!(expected, peer_prologue(&consumer, Role::Consumer, 41));
        assert_ne!(expected, peer_prologue(&consumer, Role::Provider, 41));
    }
}
