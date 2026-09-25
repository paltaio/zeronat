use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{interval_at, timeout, Instant};

use crate::client::{AbortOnDrop, RelayDgramLeg, PING_INTERVAL};
use crate::dgram::{DgramRx, DgramTx};
use crate::kcp::ConvGuard;
use crate::noise::{public_identity, Noise, NoiseReader, NoiseWriter, StatelessNoise, XxHandshake};
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

/// How long the inner handshake tries before giving up. Any message can be
/// lost, so neither side trusts one delivery: each repeats its last message on
/// [`HANDSHAKE_RETRY`] until the exchange completes or this passes.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const HANDSHAKE_RETRY: Duration = Duration::from_millis(500);

/// Leading byte of every frame this layer emits, naming what follows: a raw
/// handshake message (or the transport-sealed verdict that ends the
/// handshake), or a sealed session frame. The byte rides outside the seal.
pub const FRAME_HANDSHAKE: u8 = 0x00;
pub const FRAME_SESSION: u8 = 0x01;

/// First byte of the provider's transport-sealed verdict frame: the pair is
/// served, or refused with the reason in the remaining bytes.
pub const VERDICT_READY: u8 = 0x00;
pub const VERDICT_REFUSED: u8 = 0x01;

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

/// What one party brings to the pair's inner handshake: its static private
/// key, the identity it expects on the other end, and the pair challenge the
/// server minted.
#[derive(Clone)]
pub struct PairIdentity {
    static_private: [u8; 32],
    peer: [u8; 32],
    challenge: [u8; 32],
    provides: u8,
}

impl PairIdentity {
    pub fn new(
        static_private: [u8; 32],
        peer: [u8; 32],
        challenge: [u8; 32],
        provides: u8,
    ) -> Self {
        PairIdentity {
            static_private,
            peer,
            challenge,
            provides,
        }
    }
}

/// The transcript prologue both parties must agree on: a domain tag, the
/// protocol version, the pair and its capability, the two identities in role
/// order, and the pair challenge. A handshake message replayed across
/// pairings or roles hashes a different transcript and authenticates nothing.
pub fn pair_prologue(
    pair_id: u64,
    provides: u8,
    consumer: &[u8; 32],
    provider: &[u8; 32],
    challenge: &[u8; 32],
) -> Vec<u8> {
    let mut prologue = Vec::with_capacity(21 + 1 + 8 + 1 + 32 + 32 + 32);
    prologue.extend_from_slice(b"zeronat-peer-noise-v1");
    prologue.push(crate::identity::PROTO_VERSION);
    prologue.extend_from_slice(&pair_id.to_be_bytes());
    prologue.push(provides);
    prologue.extend_from_slice(consumer);
    prologue.extend_from_slice(provider);
    prologue.extend_from_slice(challenge);
    prologue
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
    async fn recv(&mut self) -> Option<&[u8]> {
        match self {
            PathRx::Dgram(rx) => rx.recv_data().await,
            PathRx::Stream(r) => r.recv_data().await,
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

/// A responder's answer to a message three it already handled: the message it
/// consumed, and the verdict frame to send again if that copy comes back
/// because the first answer was lost.
struct Retransmit {
    seen: Vec<u8>,
    reply: Vec<u8>,
}

/// An encrypted frame session between two peers. Both sides handshake
/// `Noise_XX_25519_ChaChaPoly_BLAKE2s` between their static keys over the
/// path that came up, so a relayed pair moves ciphertext the server holds no
/// key for and direct and relayed are the same thing above this layer.
pub struct PeerSession {
    noise: Arc<StatelessNoise>,
    out: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<Vec<u8>>,
    /// Cleared when the reader reaps the peer, so a write-only owner learns
    /// the session is gone from the send side too.
    alive: Arc<AtomicBool>,
    /// The refusal this provider's verdict carried, `None` on a ready verdict
    /// and on every consumer session. A refused session exists only so the
    /// verdict's retransmits can answer a repeated message three.
    refused: Option<String>,
    _hold: PathHold,
    /// The reader owns the writer and the keepalive, so reaping a dead peer
    /// stops this party writing into the path as well, and dropping the
    /// session stops all three.
    _reader: AbortOnDrop,
}

impl PeerSession {
    /// The consumer's side: run the handshake's initiator over `path`. The
    /// session is not up until the provider's ready verdict arrives; a
    /// refusal or an identity mismatch is an error.
    pub async fn consumer(path: PeerPath, identity: &PairIdentity, pair_id: u64) -> Result<Self> {
        Self::start(path, Role::Consumer, &[], &[], identity, pair_id).await
    }

    /// The provider's side: answer the handshake, sealing `refuse` into
    /// message two. The verdict checks `allow` against the consumer static
    /// message three authenticates: an identity off the list is refused as
    /// unauthorized whatever `refuse` says, an admitted one gets `refuse`
    /// repeated or a ready verdict, and [`refused`](Self::refused) carries
    /// whichever reason went out.
    pub async fn provider(
        path: PeerPath,
        identity: &PairIdentity,
        pair_id: u64,
        refuse: &[u8],
        allow: &[[u8; 32]],
    ) -> Result<Self> {
        Self::start(path, Role::Provider, refuse, allow, identity, pair_id).await
    }

    /// Handshake over `path` and start the session's keepalive and liveness
    /// watch.
    async fn start(
        path: PeerPath,
        role: Role,
        refuse: &[u8],
        allow: &[[u8; 32]],
        identity: &PairIdentity,
        pair_id: u64,
    ) -> Result<Self> {
        let PeerPath {
            mut rx,
            mut tx,
            hold,
        } = path;
        let Handshaked {
            noise,
            retransmit,
            refused,
        } = crate::client::boxed(handshake(
            role, refuse, allow, &mut rx, &mut tx, identity, pair_id,
        ))
        .await?;
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
                        // The peer repeating the message three this party
                        // answered: its verdict was lost on the way, so send
                        // it again.
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

        Ok(PeerSession {
            noise,
            out,
            inbound,
            alive,
            refused,
            _hold: hold,
            _reader: reader,
        })
    }

    /// The refusal this provider answered the pair with, `None` when the
    /// verdict was ready. Nothing may ride a refused session.
    pub fn refused(&self) -> Option<&str> {
        self.refused.as_deref()
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
    let mut frame = Vec::with_capacity(1 + 8 + 1 + payload.len() + 16);
    frame.push(FRAME_SESSION);
    frame.extend_from_slice(&[0u8; 8]);
    frame.push(kind);
    frame.extend_from_slice(payload);
    noise.seal_at(&mut frame, 1)?;
    Ok(frame)
}

/// A completed inner handshake: the transport state, the responder's answer to
/// a repeated message three, and the refusal the responder's verdict carried.
struct Handshaked {
    noise: StatelessNoise,
    retransmit: Option<Retransmit>,
    refused: Option<String>,
}

/// Run the inner XX handshake over the path, repeating the last message sent
/// until the exchange completes. Both parties authenticate their static keys
/// under the pair prologue; transport keys come from the handshake split and
/// feed the same directional datagram state the sessions run on.
async fn handshake(
    role: Role,
    refuse: &[u8],
    allow: &[[u8; 32]],
    rx: &mut PathRx,
    tx: &mut PathTx,
    identity: &PairIdentity,
    pair_id: u64,
) -> Result<Handshaked> {
    timeout(HANDSHAKE_DEADLINE, async {
        match role {
            Role::Consumer => handshake_initiator(rx, tx, identity, pair_id).await,
            Role::Provider => handshake_responder(refuse, allow, rx, tx, identity, pair_id).await,
        }
    })
    .await
    .map_err(|_| -> Error { "inner handshake timed out".into() })?
}

/// The consumer's side: message one, then verify the provider's static key
/// against the identity the config names, then message three and the verdict
/// wait. Not up until the verdict reads ready.
async fn handshake_initiator(
    rx: &mut PathRx,
    tx: &mut PathTx,
    identity: &PairIdentity,
    pair_id: u64,
) -> Result<Handshaked> {
    let local = public_identity(&identity.static_private);
    let prologue = pair_prologue(
        pair_id,
        identity.provides,
        &local,
        &identity.peer,
        &identity.challenge,
    );
    let mut state = XxHandshake::initiator(&identity.static_private, &prologue)?;
    let frame_one = send_handshake(tx, &state.write_message_one(&[])).await?;
    let mut retry = interval_at(Instant::now() + HANDSHAKE_RETRY, HANDSHAKE_RETRY);
    let message_two = exchange(rx, tx, &mut retry, &frame_one, None).await?;
    // Message two's payload carries the refusal a provider can state before
    // it knows who is asking; the verdict repeats it, so only the verdict is
    // acted on.
    state.read_message_two(&message_two)?;
    let presented = state
        .remote_static()
        .ok_or("handshake message 2 carried no static key")?;
    if presented != identity.peer {
        return Err(format!(
            "peer identity mismatch: expected {}, presented {}",
            crate::secret::encode(identity.peer),
            crate::secret::encode(presented),
        )
        .into());
    }
    let frame_three = send_handshake(tx, &state.write_message_three(&[])).await?;
    let noise = state.into_transport();
    let mut retry = interval_at(Instant::now() + HANDSHAKE_RETRY, HANDSHAKE_RETRY);
    loop {
        // A repeat of message two says the provider has not read message
        // three yet; anything else that is not the sealed verdict is
        // reordered or stale, and the retransmits and the deadline decide
        // the outcome.
        let message = exchange(rx, tx, &mut retry, &frame_three, Some(&message_two)).await?;
        let Ok(verdict) = noise.open(&message) else {
            continue;
        };
        return match verdict.split_first() {
            Some((&VERDICT_READY, [])) => Ok(Handshaked {
                noise,
                retransmit: None,
                refused: None,
            }),
            Some((&VERDICT_REFUSED, reason)) => Err(format!(
                "the provider refused the pair: {}",
                String::from_utf8_lossy(reason)
            )
            .into()),
            _ => Err("invalid peer handshake verdict".into()),
        };
    }
}

/// The provider's side. The expected consumer identity in the prologue is the
/// relay-forwarded one, which is routing information: it selects the
/// transcript, it admits no one. The consumer is authenticated at message
/// three, and the verdict is decided there on the static it presented: an
/// identity `allow` does not name is refused as unauthorized, an allowlisted
/// identity the pair was not routed for is refused as a routing conflict, and
/// a non-empty `refuse` refuses the rest.
async fn handshake_responder(
    refuse: &[u8],
    allow: &[[u8; 32]],
    rx: &mut PathRx,
    tx: &mut PathTx,
    identity: &PairIdentity,
    pair_id: u64,
) -> Result<Handshaked> {
    let local = public_identity(&identity.static_private);
    let prologue = pair_prologue(
        pair_id,
        identity.provides,
        &identity.peer,
        &local,
        &identity.challenge,
    );
    let mut state = XxHandshake::responder(&identity.static_private, &prologue)?;
    let message_one = recv_handshake(rx).await?;
    if !state.read_message_one(&message_one)?.is_empty() {
        return Err("unexpected payload in peer handshake message one".into());
    }
    let frame_two = send_handshake(tx, &state.write_message_two(refuse)).await?;
    let mut retry = interval_at(Instant::now() + HANDSHAKE_RETRY, HANDSHAKE_RETRY);
    let message_three = exchange(rx, tx, &mut retry, &frame_two, Some(&message_one)).await?;
    if !state.read_message_three(&message_three)?.is_empty() {
        return Err("unexpected payload in peer handshake message three".into());
    }
    let presented = state
        .remote_static()
        .ok_or("handshake message 3 carried no static key")?;
    // The verdict keys on the static the handshake authenticated, never on
    // the relay-forwarded identity: possession of an allowlisted key is the
    // only thing that admits a consumer. The two identities differ here only
    // for a consumer that ran the transcript under a routed identity it does
    // not hold, which is a conflict worth its own reason.
    let refuse = if !allow.contains(&presented) {
        format!(
            "unauthorized consumer identity {}",
            crate::secret::encode(presented)
        )
        .into_bytes()
    } else if presented != identity.peer {
        format!(
            "consumer identity {} is not the identity the pair was routed for",
            crate::secret::encode(presented)
        )
        .into_bytes()
    } else {
        refuse.to_vec()
    };
    let noise = state.into_transport();
    let mut verdict = Vec::with_capacity(1 + refuse.len());
    if refuse.is_empty() {
        verdict.push(VERDICT_READY);
    } else {
        verdict.push(VERDICT_REFUSED);
        verdict.extend_from_slice(&refuse);
    }
    let sealed = noise.seal(&verdict)?;
    let reply = send_handshake(tx, &sealed).await?;
    Ok(Handshaked {
        noise,
        retransmit: Some(Retransmit {
            seen: message_three,
            reply,
        }),
        refused: (!refuse.is_empty()).then(|| String::from_utf8_lossy(&refuse).into_owned()),
    })
}

/// The peer's next handshake message. `frame` goes out again on every
/// `retry` tick, and whenever the peer repeats `answered`, the message this
/// frame answers, which says the frame was lost on the way.
async fn exchange(
    rx: &mut PathRx,
    tx: &mut PathTx,
    retry: &mut tokio::time::Interval,
    frame: &[u8],
    answered: Option<&[u8]>,
) -> Result<Vec<u8>> {
    loop {
        tokio::select! {
            _ = retry.tick() => tx.send(frame).await?,
            message = recv_handshake(rx) => {
                let message = message?;
                if Some(message.as_slice()) == answered {
                    tx.send(frame).await?;
                    continue;
                }
                return Ok(message);
            }
        }
    }
}

/// The next handshake-class frame the path delivers, stripped of its frame
/// byte. Session frames cannot appear before the handshake completes, so
/// anything else is dropped.
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

/// Both stream legs of one relayed pair, standing in for the relay splice.
#[cfg(test)]
async fn duplex_legs(secret: &str) -> (Noise, Noise) {
    let psk = crate::noise::derive_psk(secret);
    let (a, b) = tokio::io::duplex(1 << 16);
    let responder =
        crate::spawn(async move { crate::noise::server_handshake(b, &psk).await.unwrap() });
    let initiator = crate::noise::client_handshake(a, &psk).await.unwrap();
    (initiator, responder.await.unwrap())
}

/// The two ends of a pair as [`PairIdentity`] values, with static keys and the
/// challenge derived from `secret`.
#[cfg(test)]
fn duplex_identities(secret: &str) -> (PairIdentity, PairIdentity) {
    let consumer_static = crate::noise::derive_psk(&format!("{secret}-consumer-static"));
    let provider_static = crate::noise::derive_psk(&format!("{secret}-provider-static"));
    let challenge = crate::noise::derive_psk(&format!("{secret}-pair-challenge"));
    let consumer = PairIdentity::new(
        consumer_static,
        public_identity(&provider_static),
        challenge,
        crate::proto::PROVIDES_EXIT,
    );
    let provider = PairIdentity::new(
        provider_static,
        public_identity(&consumer_static),
        challenge,
        crate::proto::PROVIDES_EXIT,
    );
    (consumer, provider)
}

/// Both ends of one inner session, handshaked over a duplex standing in for a
/// relay leg. The provider answers with a ready verdict, so the pair is one
/// an adapter can run over.
#[cfg(test)]
pub(crate) async fn duplex_pair(secret: &str, pair_id: u64) -> (PeerSession, PeerSession) {
    let (initiator, responder) = duplex_legs(secret).await;
    let (consumer_identity, provider_identity) = duplex_identities(secret);
    let allow = [provider_identity.peer];
    tokio::try_join!(
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
            &allow,
        ),
    )
    .expect("the inner handshake must complete on both sides")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The core identity check: a party that holds everything the relay and
    // the pairing hand out (the pair challenge, both identities, and the
    // prologue they hash to) but not the expected static key must be rejected
    // with the identity-mismatch error, not served and not timed out. The
    // impostor completes its whole flow up to a ready verdict, so a broken or
    // inverted comparison hands the consumer a live session and fails the
    // assertion below.
    #[tokio::test]
    async fn a_provider_presenting_another_static_key_is_rejected_as_a_mismatch() {
        let consumer_static = crate::noise::derive_psk("mismatch consumer");
        let provider_static = crate::noise::derive_psk("mismatch provider");
        let attacker_static = crate::noise::derive_psk("mismatch attacker");
        let challenge = crate::noise::derive_psk("mismatch challenge");
        let expected = public_identity(&provider_static);
        let presented = public_identity(&attacker_static);
        let pair_id = 41;

        let (initiator, responder) = duplex_legs("mismatch legs").await;
        let impostor = crate::spawn(async move {
            let prologue = pair_prologue(
                pair_id,
                crate::proto::PROVIDES_EXIT,
                &public_identity(&consumer_static),
                &expected,
                &challenge,
            );
            let mut state = XxHandshake::responder(&attacker_static, &prologue).unwrap();
            let (mut leg_rx, mut leg_tx) = responder;
            let msg1 = loop {
                let Ok(frame) = leg_rx.recv().await else {
                    return;
                };
                if let Some((&FRAME_HANDSHAKE, m)) = frame.split_first() {
                    break m.to_vec();
                }
            };
            if state.read_message_one(&msg1).is_err() {
                return;
            }
            let mut frame = vec![FRAME_HANDSHAKE];
            frame.extend_from_slice(&state.write_message_two(&[]));
            if leg_tx.send(&frame).await.is_err() {
                return;
            }
            let msg3 = loop {
                let Ok(frame) = leg_rx.recv().await else {
                    return;
                };
                match frame.split_first() {
                    Some((&FRAME_HANDSHAKE, m)) if m != msg1 => break m.to_vec(),
                    _ => continue,
                }
            };
            if state.read_message_three(&msg3).is_err() {
                return;
            }
            let noise = state.into_transport();
            let Ok(sealed) = noise.seal(&[VERDICT_READY]) else {
                return;
            };
            let mut frame = vec![FRAME_HANDSHAKE];
            frame.extend_from_slice(&sealed);
            leg_tx.send(&frame).await.ok();
        });

        let identity = PairIdentity::new(
            consumer_static,
            expected,
            challenge,
            crate::proto::PROVIDES_EXIT,
        );
        let outcome =
            PeerSession::consumer(PeerPath::relay_stream(initiator), &identity, pair_id).await;
        let error = outcome
            .err()
            .expect("another static key must not authenticate as the expected peer")
            .to_string();
        assert!(error.contains("peer identity mismatch"), "{error}");
        assert!(error.contains(&crate::secret::encode(expected)), "{error}");
        assert!(error.contains(&crate::secret::encode(presented)), "{error}");
        impostor.await.unwrap();
    }

    // A provider that cannot take the pair refuses in the verdict; the
    // consumer surfaces the reason as its own error, distinct from an
    // identity mismatch.
    #[tokio::test]
    async fn a_verdict_refusal_is_an_error_distinct_from_a_mismatch() {
        let (initiator, responder) = duplex_legs("refusal legs").await;
        let (consumer_identity, provider_identity) = duplex_identities("refusal legs");
        let allow = [provider_identity.peer];
        let (consumer, provider) = tokio::join!(
            PeerSession::consumer(PeerPath::relay_stream(initiator), &consumer_identity, 7),
            PeerSession::provider(
                PeerPath::relay_stream(responder),
                &provider_identity,
                7,
                b"already serving a pair",
                &allow,
            ),
        );
        let provider = provider.expect("the refusing provider still completes the handshake");
        assert_eq!(provider.refused(), Some("already serving a pair"));
        let error = consumer.err().expect("a refusal fails the consumer");
        let error = error.to_string();
        assert!(
            error.contains("the provider refused the pair: already serving a pair"),
            "{error}"
        );
        assert!(!error.contains("peer identity mismatch"), "{error}");
    }

    // A completed handshake is not a session: the consumer stays down until
    // the ready verdict arrives, and a provider that never sends one leaves
    // it failing at the handshake deadline.
    #[tokio::test(start_paused = true)]
    async fn the_consumer_is_not_up_until_the_ready_verdict() {
        let (initiator, responder) = duplex_legs("verdictless legs").await;
        let (consumer_identity, provider_identity) = duplex_identities("verdictless legs");
        let silent = crate::spawn(async move {
            let prologue = pair_prologue(
                9,
                crate::proto::PROVIDES_EXIT,
                &provider_identity.peer,
                &public_identity(&provider_identity.static_private),
                &provider_identity.challenge,
            );
            let mut state =
                XxHandshake::responder(&provider_identity.static_private, &prologue).unwrap();
            let (mut leg_rx, mut leg_tx) = responder;
            let msg1 = loop {
                let Ok(frame) = leg_rx.recv().await else {
                    return;
                };
                if let Some((&FRAME_HANDSHAKE, m)) = frame.split_first() {
                    break m.to_vec();
                }
            };
            state.read_message_one(&msg1).unwrap();
            let mut frame = vec![FRAME_HANDSHAKE];
            frame.extend_from_slice(&state.write_message_two(&[]));
            leg_tx.send(&frame).await.unwrap();
            // Read message three and go silent: no verdict ever leaves.
            loop {
                if leg_rx.recv().await.is_err() {
                    return;
                }
            }
        });

        let error = PeerSession::consumer(PeerPath::relay_stream(initiator), &consumer_identity, 9)
            .await
            .err()
            .expect("no verdict must not produce a session")
            .to_string();
        assert!(error.contains("inner handshake timed out"), "{error}");
        drop(silent);
    }

    /// Drive the initiator's frames with `static_private` under a prologue
    /// naming `claimed` as the consumer, and return the provider's verdict
    /// plaintext.
    async fn initiate_claiming(
        leg: Noise,
        static_private: [u8; 32],
        claimed: [u8; 32],
        provider: [u8; 32],
        challenge: [u8; 32],
        pair_id: u64,
    ) -> Vec<u8> {
        let prologue = pair_prologue(
            pair_id,
            crate::proto::PROVIDES_EXIT,
            &claimed,
            &provider,
            &challenge,
        );
        let mut state = XxHandshake::initiator(&static_private, &prologue).unwrap();
        let (mut leg_rx, mut leg_tx) = leg;
        let mut frame = vec![FRAME_HANDSHAKE];
        frame.extend_from_slice(&state.write_message_one(&[]));
        leg_tx.send(&frame).await.unwrap();
        let msg2 = loop {
            let frame = leg_rx.recv().await.unwrap();
            if let Some((&FRAME_HANDSHAKE, m)) = frame.split_first() {
                break m.to_vec();
            }
        };
        state.read_message_two(&msg2).unwrap();
        let mut frame = vec![FRAME_HANDSHAKE];
        frame.extend_from_slice(&state.write_message_three(&[]));
        leg_tx.send(&frame).await.unwrap();
        let noise = state.into_transport();
        loop {
            let frame = leg_rx.recv().await.unwrap();
            let Some((&FRAME_HANDSHAKE, m)) = frame.split_first() else {
                continue;
            };
            if m == msg2 {
                continue;
            }
            if let Ok(verdict) = noise.open(m) {
                return verdict;
            }
        }
    }

    // The verdict keys on the static key the handshake authenticated, so
    // nothing the relay forwards can admit a consumer: the pair is routed for
    // an allowlisted identity, the impostor completes the whole exchange
    // under that routing, and only the party holding the allowlisted key is
    // served.
    #[tokio::test]
    async fn the_routed_identity_admits_no_consumer_without_an_allowlisted_key() {
        let provider_static = crate::noise::derive_psk("allowlist provider");
        let allowed_static = crate::noise::derive_psk("allowlist consumer");
        let impostor_static = crate::noise::derive_psk("allowlist impostor");
        let challenge = crate::noise::derive_psk("allowlist challenge");
        let allowed = public_identity(&allowed_static);
        let provider_pub = public_identity(&provider_static);
        let allow = [allowed];
        let pair_id = 51;
        let identity = PairIdentity::new(
            provider_static,
            allowed,
            challenge,
            crate::proto::PROVIDES_EXIT,
        );

        // The relay routed the pair for the allowlisted identity; the
        // impostor claims it in the transcript but holds only its own key.
        let (initiator, responder) = duplex_legs("allowlist legs").await;
        let impostor = crate::spawn(initiate_claiming(
            initiator,
            impostor_static,
            allowed,
            provider_pub,
            challenge,
            pair_id,
        ));
        let session = PeerSession::provider(
            PeerPath::relay_stream(responder),
            &identity,
            pair_id,
            &[],
            &allow,
        )
        .await
        .unwrap();
        let refused = session
            .refused()
            .expect("a key the allowlist does not name must not be served")
            .to_string();
        let presented = crate::secret::encode(public_identity(&impostor_static));
        assert!(refused.contains("unauthorized"), "{refused}");
        assert!(refused.contains(&presented), "{refused}");
        let verdict = impostor.await.unwrap();
        assert_eq!(verdict.first(), Some(&VERDICT_REFUSED));
        let reason = String::from_utf8_lossy(&verdict[1..]);
        assert!(reason.contains("unauthorized"), "{reason}");
        drop(session);

        // The allowlisted consumer itself is served under the same routing.
        let (initiator, responder) = duplex_legs("allowlist legs served").await;
        let consumer_identity = PairIdentity::new(
            allowed_static,
            provider_pub,
            challenge,
            crate::proto::PROVIDES_EXIT,
        );
        let (consumer, provider) = tokio::try_join!(
            PeerSession::consumer(
                PeerPath::relay_stream(initiator),
                &consumer_identity,
                pair_id
            ),
            PeerSession::provider(
                PeerPath::relay_stream(responder),
                &identity,
                pair_id,
                &[],
                &allow,
            ),
        )
        .expect("the allowlisted key must be served");
        assert!(provider.refused().is_none());
        drop((consumer, provider));
    }

    // An unlisted consumer is refused in the verdict: the provider's session
    // reports the refusal, which is what keeps anything from riding the pair,
    // and the consumer surfaces it as the provider's refusal, distinct from
    // the identity-mismatch error its own check raises.
    #[tokio::test]
    async fn a_consumer_absent_from_the_allowlist_gets_an_unauthorized_refusal() {
        let (initiator, responder) = duplex_legs("unlisted legs").await;
        let (consumer_identity, provider_identity) = duplex_identities("unlisted legs");
        let allow = [[0x5A; 32]];
        let (consumer, provider) = tokio::join!(
            PeerSession::consumer(PeerPath::relay_stream(initiator), &consumer_identity, 13),
            PeerSession::provider(
                PeerPath::relay_stream(responder),
                &provider_identity,
                13,
                &[],
                &allow,
            ),
        );
        let provider = provider.expect("the refusing provider still completes the handshake");
        let refused = provider
            .refused()
            .expect("an unlisted consumer must be refused");
        let presented = crate::secret::encode(provider_identity.peer);
        assert!(refused.contains("unauthorized"), "{refused}");
        assert!(refused.contains(&presented), "{refused}");
        let error = consumer
            .err()
            .expect("an unauthorized refusal fails the consumer")
            .to_string();
        assert!(error.contains("the provider refused the pair"), "{error}");
        assert!(error.contains("unauthorized"), "{error}");
        assert!(!error.contains("peer identity mismatch"), "{error}");
    }

    // An allowlisted key that is not the identity the pair was routed for is
    // still refused: the two disagree only when the relay lied or paired
    // stale state, and the routing must not stand in for the key.
    #[tokio::test]
    async fn an_allowlisted_key_the_pair_was_not_routed_for_is_refused() {
        let provider_static = crate::noise::derive_psk("conflict provider");
        let routed_static = crate::noise::derive_psk("conflict routed");
        let other_static = crate::noise::derive_psk("conflict other");
        let challenge = crate::noise::derive_psk("conflict challenge");
        let routed = public_identity(&routed_static);
        let other = public_identity(&other_static);
        let allow = [routed, other];
        let pair_id = 52;
        let identity = PairIdentity::new(
            provider_static,
            routed,
            challenge,
            crate::proto::PROVIDES_EXIT,
        );

        let (initiator, responder) = duplex_legs("conflict legs").await;
        let byzantine = crate::spawn(initiate_claiming(
            initiator,
            other_static,
            routed,
            public_identity(&provider_static),
            challenge,
            pair_id,
        ));
        let session = PeerSession::provider(
            PeerPath::relay_stream(responder),
            &identity,
            pair_id,
            &[],
            &allow,
        )
        .await
        .unwrap();
        let refused = session
            .refused()
            .expect("an identity the pair was not routed for must be refused")
            .to_string();
        assert!(refused.contains("routed for"), "{refused}");
        assert!(refused.contains(&crate::secret::encode(other)), "{refused}");
        assert!(!refused.contains("unauthorized"), "{refused}");
        let verdict = byzantine.await.unwrap();
        assert_eq!(verdict.first(), Some(&VERDICT_REFUSED));
        drop(session);
    }
}
