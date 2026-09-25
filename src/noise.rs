use std::collections::HashMap;
use std::sync::Mutex;

use crate::hash::{blake2s, ct_eq, hmac_blake2s};
use crate::{Error, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

const PATTERN: &[u8] = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const XX_PATTERN: &[u8] = b"Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_MSG: usize = 65535;
const MAX_PLAINTEXT: usize = MAX_MSG - 16;
const HASHLEN: usize = 32;
const DHLEN: usize = 32;
const TAGLEN: usize = 16;
const REPLAY_WINDOW_LEN: u64 = 128;
const REMOTE_PREFACE_MAGIC: [u8; 2] = *b"ZN";
const CLIENT_SELECTOR_LEN: usize = 16;
const REMOTE_PREFACE_LEN: usize = 4 + CLIENT_SELECTOR_LEN;
// Stateless peers authenticate the protocol version as part of the Noise transcript.
const STATELESS_PROLOGUE: [u8; 1] = [crate::identity::PROTO_VERSION];

/// Credential selected before a remote control-port Noise handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthRole {
    Client = 1,
    Admin = 2,
}

impl AuthRole {
    fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::Admin),
            _ => Err("unsupported remote authentication role".into()),
        }
    }

    fn preface(self, selector: [u8; CLIENT_SELECTOR_LEN]) -> [u8; REMOTE_PREFACE_LEN] {
        let mut preface = [0u8; REMOTE_PREFACE_LEN];
        preface[..2].copy_from_slice(&REMOTE_PREFACE_MAGIC);
        preface[2] = crate::identity::PROTO_VERSION;
        preface[3] = self as u8;
        preface[4..].copy_from_slice(&selector);
        preface
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthIdentity {
    Client(String),
    Admin,
}

pub type ClientCredentials = HashMap<[u8; CLIENT_SELECTOR_LEN], (String, [u8; 32])>;

fn parse_remote_preface(
    preface: &[u8; REMOTE_PREFACE_LEN],
) -> Result<(AuthRole, [u8; CLIENT_SELECTOR_LEN])> {
    if preface[..2] != REMOTE_PREFACE_MAGIC {
        return Err("unsupported remote handshake preface".into());
    }
    if preface[2] != crate::identity::PROTO_VERSION {
        return Err("unsupported protocol version".into());
    }
    let role = AuthRole::from_byte(preface[3])?;
    let selector: [u8; CLIENT_SELECTOR_LEN] = preface[4..]
        .try_into()
        .map_err(|_| -> Error { "invalid client credential selector".into() })?;
    Ok((role, selector))
}

pub fn client_selector(psk: &[u8; 32]) -> [u8; CLIENT_SELECTOR_LEN] {
    let digest = blake2s(&[b"zeronat-client-credential-selector-v1", psk]);
    let mut selector = [0u8; CLIENT_SELECTOR_LEN];
    selector.copy_from_slice(&digest[..CLIENT_SELECTOR_LEN]);
    selector
}

pub type Noise = (NoiseReader, NoiseWriter);

type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// A bidirectional stream erased to a single trait object. The handshake
/// interleaves reads and writes on one stream, so it needs a combined trait;
/// erasing here lets the handshake state machine compile once instead of once
/// per concrete stream type (TcpStream, KcpStream, ...).
trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
type BoxStream = Box<dyn IoStream>;

/// The x25519 public key of a static private key, which is the identity a
/// peer presents in the XX handshake.
pub fn public_identity(private: &[u8; 32]) -> [u8; 32] {
    x25519(*private, X25519_BASEPOINT_BYTES)
}

const ANNOUNCE_PROOF_TAG: &[u8] = b"zeronat-peer-announce-proof-v1";

/// The keyed MAC an announce proof carries: a domain tag, the protocol
/// version, the challenge nonce and ephemeral, the claimed identity, the
/// announced `provides` byte, and the announcing client's id, keyed by the
/// x25519 shared secret between the challenge ephemeral and the identity.
fn announce_mac(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    nonce: &[u8; 32],
    identity: &[u8; 32],
    provides: u8,
    client_id: &str,
) -> [u8; 32] {
    hmac_blake2s(
        shared,
        &[
            ANNOUNCE_PROOF_TAG,
            &[crate::identity::PROTO_VERSION],
            nonce,
            eph_pub,
            identity,
            &[provides],
            client_id.as_bytes(),
        ],
    )
}

/// Answer a `PeerChallenge`: the proof MAC only the announced identity's
/// static private key can compute.
pub fn announce_proof(
    static_private: &[u8; 32],
    eph_pub: &[u8; 32],
    nonce: &[u8; 32],
    provides: u8,
    client_id: &str,
) -> [u8; 32] {
    let shared = x25519(*static_private, *eph_pub);
    let identity = public_identity(static_private);
    announce_mac(&shared, eph_pub, nonce, &identity, provides, client_id)
}

/// One announce's server-side challenge: the ephemeral public key and nonce
/// sent to the client, and the shared secret held to verify the proof. The
/// ephemeral private key is dropped at mint, so the challenge is single-use
/// and dies with the exchange it was minted for.
pub struct AnnounceChallenge {
    pub eph_pub: [u8; 32],
    pub nonce: [u8; 32],
    identity: [u8; 32],
    shared: [u8; 32],
}

impl AnnounceChallenge {
    /// Mint a challenge for a claimed identity. `Ok(None)` marks a malformed
    /// identity: a point whose shared secret is all zeros, which would key
    /// the proof with a value anyone can compute.
    ///
    /// # Errors
    ///
    /// Returns an error when the system random source is unavailable.
    pub fn mint(identity: &[u8; 32]) -> Result<Option<AnnounceChallenge>> {
        let mut eph_priv = [0u8; 32];
        getrandom::getrandom(&mut eph_priv)
            .map_err(|e| -> Error { errf!("generating an ephemeral key: {e}") })?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| -> Error { errf!("generating a challenge nonce: {e}") })?;
        let shared = x25519(eph_priv, *identity);
        if shared == [0u8; 32] {
            return Ok(None);
        }
        Ok(Some(AnnounceChallenge {
            eph_pub: public_identity(&eph_priv),
            nonce,
            identity: *identity,
            shared,
        }))
    }

    /// Whether `mac` proves possession of the identity this challenge was
    /// minted for. The comparison runs in constant time.
    pub fn verify(&self, provides: u8, client_id: &str, mac: &[u8; 32]) -> bool {
        let want = announce_mac(
            &self.shared,
            &self.eph_pub,
            &self.nonce,
            &self.identity,
            provides,
            client_id,
        );
        ct_eq(&want, mac)
    }
}

/// Derive the 32-byte pre-shared key from the user's passphrase.
pub fn derive_psk(secret: &str) -> [u8; 32] {
    blake2s(&[b"tunnel-noise-psk-v1", secret.as_bytes()])
}

/// Noise HKDF over HMAC-BLAKE2s: the first `n` of three 32-byte outputs.
#[inline(never)]
fn hkdf(ck: &[u8; HASHLEN], ikm: &[u8], n: usize) -> [[u8; HASHLEN]; 3] {
    let temp = hmac_blake2s(ck, &[ikm]);
    let mut out = [[0u8; HASHLEN]; 3];
    let mut prev: &[u8] = &[];
    for (i, o) in out.iter_mut().enumerate().take(n) {
        *o = hmac_blake2s(&temp, &[prev, &[i as u8 + 1]]);
        prev = &o[..];
    }
    out
}

/// Encode a Noise 96-bit nonce: 4 zero bytes then the counter in little-endian.
fn aead_nonce(n: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(nonce)
}

fn aead_encrypt(key: &[u8; 32], n: u64, ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &aead_nonce(n),
            chacha20poly1305::aead::Payload { msg: pt, aad: ad },
        )
        .expect("chacha20poly1305 encrypt is infallible for valid sizes")
}

fn aead_decrypt(key: &[u8; 32], n: u64, ad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &aead_nonce(n),
            chacha20poly1305::aead::Payload { msg: ct, aad: ad },
        )
        .map_err(|_| -> Error { "aead authentication failed".into() })
}

struct SymmetricState {
    ck: [u8; HASHLEN],
    h: [u8; HASHLEN],
    k: Option<[u8; 32]>,
    n: u64,
}

impl SymmetricState {
    fn new(protocol: &[u8]) -> Self {
        // InitializeSymmetric: if the protocol name is longer than HASHLEN,
        // h = HASH(name); otherwise zero-pad it to HASHLEN.
        let h = if protocol.len() <= HASHLEN {
            let mut buf = [0u8; HASHLEN];
            buf[..protocol.len()].copy_from_slice(protocol);
            buf
        } else {
            blake2s(&[protocol])
        };
        SymmetricState {
            ck: h,
            h,
            k: None,
            n: 0,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = blake2s(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let [ck, temp_k, _] = hkdf(&self.ck, ikm, 2);
        self.ck = ck;
        self.k = Some(temp_k);
        self.n = 0;
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let [ck, temp_h, temp_k] = hkdf(&self.ck, ikm, 3);
        self.ck = ck;
        self.mix_hash(&temp_h);
        self.k = Some(temp_k);
        self.n = 0;
    }

    fn encrypt_and_hash(&mut self, pt: &[u8]) -> Vec<u8> {
        let out = if let Some(k) = self.k {
            let ct = aead_encrypt(&k, self.n, &self.h, pt);
            self.n += 1;
            ct
        } else {
            pt.to_vec()
        };
        self.mix_hash(&out);
        out
    }

    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let pt = if let Some(k) = self.k {
            let pt = aead_decrypt(&k, self.n, &self.h, ct)?;
            self.n += 1;
            pt
        } else {
            ct.to_vec()
        };
        self.mix_hash(ct);
        Ok(pt)
    }

    /// The transport keys from the handshake split, by role: the initiator
    /// sends under the first output and receives under the second.
    fn keys(&self, initiator: bool) -> Keys {
        let [t1, t2, _] = hkdf(&self.ck, &[], 2);
        if initiator {
            Keys {
                send_key: t1,
                recv_key: t2,
            }
        } else {
            Keys {
                send_key: t2,
                recv_key: t1,
            }
        }
    }
}

/// Finished handshake: directional transport keys plus running counters.
struct Keys {
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

/// One side of a `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake, driven one
/// whole message at a time so a lossy carrier can repeat messages around it.
/// The three messages follow pattern order: the initiator writes one and
/// three, the responder writes two. Each party's static key is authenticated
/// once the message carrying it has been read.
pub struct XxHandshake {
    ss: SymmetricState,
    initiator: bool,
    s_priv: [u8; 32],
    e_priv: [u8; 32],
    e_pub: [u8; 32],
    re: [u8; 32],
    rs: Option<[u8; 32]>,
}

impl XxHandshake {
    pub fn initiator(static_private: &[u8; 32], prologue: &[u8]) -> Result<Self> {
        Self::new(true, static_private, prologue)
    }

    pub fn responder(static_private: &[u8; 32], prologue: &[u8]) -> Result<Self> {
        Self::new(false, static_private, prologue)
    }

    fn new(initiator: bool, static_private: &[u8; 32], prologue: &[u8]) -> Result<Self> {
        let mut e_priv = [0u8; 32];
        getrandom::getrandom(&mut e_priv)
            .map_err(|e| -> Error { errf!("generating an ephemeral key: {e}") })?;
        let mut ss = SymmetricState::new(XX_PATTERN);
        ss.mix_hash(prologue);
        Ok(XxHandshake {
            ss,
            initiator,
            s_priv: *static_private,
            e_pub: public_identity(&e_priv),
            e_priv,
            re: [0u8; DHLEN],
            rs: None,
        })
    }

    /// Message one, initiator to responder: tokens [e].
    pub fn write_message_one(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(DHLEN + payload.len());
        self.ss.mix_hash(&self.e_pub);
        msg.extend_from_slice(&self.e_pub);
        msg.extend_from_slice(&self.ss.encrypt_and_hash(payload));
        msg
    }

    pub fn read_message_one(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() < DHLEN {
            return Err("handshake message 1 too short".into());
        }
        self.re.copy_from_slice(&msg[..DHLEN]);
        self.ss.mix_hash(&self.re);
        self.ss.decrypt_and_hash(&msg[DHLEN..])
    }

    /// Message two, responder to initiator: tokens [e, ee, s, es].
    pub fn write_message_two(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(2 * DHLEN + 2 * TAGLEN + payload.len());
        self.ss.mix_hash(&self.e_pub);
        msg.extend_from_slice(&self.e_pub);
        self.ss.mix_key(&x25519(self.e_priv, self.re));
        let s_pub = public_identity(&self.s_priv);
        msg.extend_from_slice(&self.ss.encrypt_and_hash(&s_pub));
        self.ss.mix_key(&x25519(self.s_priv, self.re));
        msg.extend_from_slice(&self.ss.encrypt_and_hash(payload));
        msg
    }

    pub fn read_message_two(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() < 2 * DHLEN + 2 * TAGLEN {
            return Err("handshake message 2 too short".into());
        }
        self.re.copy_from_slice(&msg[..DHLEN]);
        self.ss.mix_hash(&self.re);
        self.ss.mix_key(&x25519(self.e_priv, self.re));
        let rs = self.read_static(&msg[DHLEN..DHLEN + DHLEN + TAGLEN])?;
        self.ss.mix_key(&x25519(self.e_priv, rs));
        self.rs = Some(rs);
        self.ss.decrypt_and_hash(&msg[DHLEN + DHLEN + TAGLEN..])
    }

    /// Message three, initiator to responder: tokens [s, se].
    pub fn write_message_three(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(DHLEN + 2 * TAGLEN + payload.len());
        let s_pub = public_identity(&self.s_priv);
        msg.extend_from_slice(&self.ss.encrypt_and_hash(&s_pub));
        self.ss.mix_key(&x25519(self.s_priv, self.re));
        msg.extend_from_slice(&self.ss.encrypt_and_hash(payload));
        msg
    }

    pub fn read_message_three(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() < DHLEN + 2 * TAGLEN {
            return Err("handshake message 3 too short".into());
        }
        let rs = self.read_static(&msg[..DHLEN + TAGLEN])?;
        self.ss.mix_key(&x25519(self.e_priv, rs));
        self.rs = Some(rs);
        self.ss.decrypt_and_hash(&msg[DHLEN + TAGLEN..])
    }

    fn read_static(&mut self, ct: &[u8]) -> Result<[u8; DHLEN]> {
        self.ss
            .decrypt_and_hash(ct)?
            .try_into()
            .map_err(|_| -> Error { "invalid static key in handshake".into() })
    }

    /// The peer's authenticated static key, once the message carrying it has
    /// been read: message two for the initiator, message three for the
    /// responder.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.rs
    }

    /// Directional datagram state from the handshake split.
    pub fn into_transport(self) -> StatelessNoise {
        StatelessNoise::from_keys(self.ss.keys(self.initiator))
    }
}

/// The NNpsk0 symmetric state with the prologue and the psk mixed in.
fn nn_start(psk: &[u8; 32], prologue: &[u8]) -> SymmetricState {
    let mut ss = SymmetricState::new(PATTERN);
    ss.mix_hash(prologue);
    ss.mix_key_and_hash(psk);
    ss
}

/// Write the `e` token and, with `re` given, the `ee` token behind it:
/// returns the ephemeral private key and the message carrying the ephemeral
/// public key and the sealed payload.
#[inline(never)]
fn nn_write(ss: &mut SymmetricState, re: Option<&[u8; 32]>, payload: &[u8]) -> ([u8; 32], Vec<u8>) {
    let mut e_priv = [0u8; 32];
    getrandom::getrandom(&mut e_priv).expect("system randomness");
    let e_pub = public_identity(&e_priv);
    ss.mix_hash(&e_pub);
    ss.mix_key(&e_pub);
    if let Some(re) = re {
        ss.mix_key(&x25519(e_priv, *re));
    }
    let ct = ss.encrypt_and_hash(payload);
    let mut msg = Vec::with_capacity(DHLEN + ct.len());
    msg.extend_from_slice(&e_pub);
    msg.extend_from_slice(&ct);
    (e_priv, msg)
}

/// Read the `e` token and, with `e_priv` given, the `ee` token behind it:
/// returns the remote ephemeral and the opened payload.
#[inline(never)]
fn nn_read(
    ss: &mut SymmetricState,
    e_priv: Option<&[u8; 32]>,
    msg: &[u8],
    short: &'static str,
) -> Result<([u8; 32], Vec<u8>)> {
    if msg.len() < DHLEN {
        return Err(short.into());
    }
    let mut re = [0u8; DHLEN];
    re.copy_from_slice(&msg[..DHLEN]);
    ss.mix_hash(&re);
    ss.mix_key(&re);
    if let Some(e_priv) = e_priv {
        ss.mix_key(&x25519(*e_priv, re));
    }
    let payload = ss.decrypt_and_hash(&msg[DHLEN..])?;
    Ok((re, payload))
}

/// Run the NNpsk0 initiator handshake over `stream`, after writing the remote
/// preface when there is one: returns the stream, the transport keys and the
/// responder's message-2 payload.
async fn initiate(
    mut stream: BoxStream,
    psk: &[u8; 32],
    preface: Option<&[u8; REMOTE_PREFACE_LEN]>,
    prologue: &[u8],
    payload1: &[u8],
) -> Result<(BoxStream, Keys, Vec<u8>)> {
    if let Some(preface) = preface {
        stream.write_all(preface).await?;
        stream.flush().await?;
    }
    let mut ss = nn_start(psk, prologue);
    // Message 1: tokens [psk, e]
    let (e_priv, msg1) = nn_write(&mut ss, None, payload1);
    write_frame(&mut stream, &msg1).await?;
    // Message 2: tokens [e, ee]
    let msg2 = read_frame(&mut stream).await?;
    let (_, payload2) = nn_read(
        &mut ss,
        Some(&e_priv),
        &msg2,
        "handshake message 2 too short",
    )?;
    Ok((stream, ss.keys(true), payload2))
}

/// Run the NNpsk0 responder handshake over `stream`, sealing `payload2` into
/// message 2: returns the stream, the keys and the payload from message 1.
async fn respond(
    mut stream: BoxStream,
    psk: &[u8; 32],
    prologue: &[u8],
    payload2: &[u8],
) -> Result<(BoxStream, Keys, Vec<u8>)> {
    let mut ss = nn_start(psk, prologue);
    // Message 1: tokens [psk, e]
    let msg1 = read_frame(&mut stream).await?;
    let (re, payload1) = nn_read(&mut ss, None, &msg1, "handshake message 1 too short")?;
    // Message 2: tokens [e, ee]
    let (_, msg2) = nn_write(&mut ss, Some(&re), payload2);
    write_frame(&mut stream, &msg2).await?;
    Ok((stream, ss.keys(false), payload1))
}

/// Read and parse the remote preface that opens a handshake.
async fn read_preface(
    stream: &mut BoxStream,
) -> Result<(
    AuthRole,
    [u8; CLIENT_SELECTOR_LEN],
    [u8; REMOTE_PREFACE_LEN],
)> {
    let mut preface = [0u8; REMOTE_PREFACE_LEN];
    stream.read_exact(&mut preface).await?;
    let (role, selector) = parse_remote_preface(&preface)?;
    Ok((role, selector, preface))
}

/// The stream initiator handshake, with the remote preface when there is one.
async fn stream_initiator(
    stream: BoxStream,
    psk: &[u8; 32],
    preface: Option<[u8; REMOTE_PREFACE_LEN]>,
) -> Result<Noise> {
    let prologue: &[u8] = preface.as_ref().map_or(&[], |p| p);
    let (stream, keys, _payload2) = initiate(stream, psk, preface.as_ref(), prologue, &[]).await?;
    Ok(finish(stream, keys))
}

async fn stream_responder(stream: BoxStream, psk: &[u8; 32], prologue: &[u8]) -> Result<Noise> {
    let (stream, keys, _payload) = respond(stream, psk, prologue, &[]).await?;
    Ok(finish(stream, keys))
}

/// The stateless initiator handshake: under the remote preface when there is
/// one, else under the stateless prologue.
async fn stateless_initiator(
    stream: BoxStream,
    psk: &[u8; 32],
    preface: Option<[u8; REMOTE_PREFACE_LEN]>,
    payload: &[u8],
) -> Result<(StatelessNoise, Vec<u8>)> {
    let prologue: &[u8] = preface.as_ref().map_or(&STATELESS_PROLOGUE, |p| p);
    let (_, keys, reply) = initiate(stream, psk, preface.as_ref(), prologue, payload).await?;
    Ok((StatelessNoise::from_keys(keys), reply))
}

pub async fn client_handshake<S>(stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::client::boxed(stream_initiator(Box::new(stream), psk, None)).await
}

pub async fn server_handshake<S>(stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::client::boxed(stream_responder(Box::new(stream), psk, &[])).await
}

/// Run a remote control-port initiator handshake under one credential role.
pub async fn client_handshake_remote<S>(stream: S, psk: &[u8; 32], role: AuthRole) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let selector = match role {
        AuthRole::Client => client_selector(psk),
        AuthRole::Admin => [0u8; CLIENT_SELECTOR_LEN],
    };
    let preface = role.preface(selector);
    crate::client::boxed(stream_initiator(Box::new(stream), psk, Some(preface))).await
}

/// Read the role preface and complete the handshake with that role's configured key.
pub async fn server_handshake_remote<S>(
    stream: S,
    clients: &ClientCredentials,
    admin_psk: Option<&[u8; 32]>,
) -> Result<(AuthIdentity, Noise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::client::boxed(remote_responder(Box::new(stream), clients, admin_psk)).await
}

async fn remote_responder(
    mut stream: BoxStream,
    clients: &ClientCredentials,
    admin_psk: Option<&[u8; 32]>,
) -> Result<(AuthIdentity, Noise)> {
    let (role, selector, preface) = read_preface(&mut stream).await?;
    let (identity, psk) = match role {
        AuthRole::Client => {
            let (client_id, psk) = clients.get(&selector).ok_or("unknown client credential")?;
            (AuthIdentity::Client(client_id.clone()), psk)
        }
        AuthRole::Admin => (
            AuthIdentity::Admin,
            admin_psk.ok_or("remote administration is disabled")?,
        ),
    };
    let noise = stream_responder(stream, psk, &preface).await?;
    Ok((identity, noise))
}

fn finish(stream: BoxStream, keys: Keys) -> Noise {
    let (rh, wh) = tokio::io::split(stream);
    (
        NoiseReader {
            rh: Box::new(rh),
            recv_key: keys.recv_key,
            recv_n: 0,
            len: [0u8; 2],
            len_filled: 0,
            have_len: false,
            body: Vec::new(),
            body_filled: 0,
        },
        NoiseWriter {
            wh: Box::new(wh),
            send_key: keys.send_key,
            send_n: 0,
        },
    )
}

/// Receiving half of an encrypted connection. One message in, one message out:
/// a TCP byte chunk or a single UDP datagram per frame.
///
/// Partial-frame progress lives in the struct, not on the `recv` future's stack,
/// so dropping a `recv` future mid-frame (e.g. as the losing branch of a
/// `tokio::select!`) keeps already-read bytes and the next `recv` resumes from
/// where it left off. Without this, a cancelled read would desync the framing.
pub struct NoiseReader {
    rh: BoxRead,
    recv_key: [u8; 32],
    recv_n: u64,
    len: [u8; 2],
    len_filled: usize,
    have_len: bool,
    body: Vec<u8>,
    body_filled: usize,
}

impl NoiseReader {
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        while self.len_filled < 2 {
            let n = self.rh.read(&mut self.len[self.len_filled..]).await?;
            if n == 0 {
                return Err("connection closed".into());
            }
            self.len_filled += n;
        }
        if !self.have_len {
            self.body = vec![0u8; u16::from_be_bytes(self.len) as usize];
            self.body_filled = 0;
            self.have_len = true;
        }
        while self.body_filled < self.body.len() {
            let n = self.rh.read(&mut self.body[self.body_filled..]).await?;
            if n == 0 {
                return Err("connection closed".into());
            }
            self.body_filled += n;
        }

        let ct = std::mem::take(&mut self.body);
        self.len_filled = 0;
        self.have_len = false;
        let pt = aead_decrypt(&self.recv_key, self.recv_n, &[], &ct)
            .map_err(|_| -> Error { "decrypt failed".into() })?;
        self.recv_n += 1;
        Ok(pt)
    }
}

/// Sending half of an encrypted connection.
pub struct NoiseWriter {
    wh: BoxWrite,
    send_key: [u8; 32],
    send_n: u64,
}

impl NoiseWriter {
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        for chunk in plaintext.chunks(MAX_PLAINTEXT) {
            let ct = aead_encrypt(&self.send_key, self.send_n, &[], chunk);
            self.send_n += 1;
            write_frame(&mut self.wh, &ct).await?;
        }
        Ok(())
    }

    /// Send a single empty-plaintext frame as a liveness probe. The receiver
    /// decodes a zero-length payload and treats it as a keepalive without
    /// forwarding it to the target. `send(&[])` would emit nothing, so this is
    /// the explicit one-frame form.
    pub async fn probe(&mut self) -> Result<()> {
        let ct = aead_encrypt(&self.send_key, self.send_n, &[], &[]);
        self.send_n += 1;
        write_frame(&mut self.wh, &ct).await
    }
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, b: &[u8]) -> Result<()> {
    w.write_all(&(b.len() as u16).to_be_bytes()).await?;
    w.write_all(b).await?;
    w.flush().await?;
    Ok(())
}

/// A finished stateless Noise session. `seal`/`open` carry an explicit per-message
/// nonce, so loss and reordering on the underlying datagram channel are tolerated.
pub struct StatelessNoise {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: Mutex<u64>,
    recv_window: Mutex<ReplayWindow>,
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: u128,
}

impl ReplayWindow {
    fn check_and_mark(&mut self, nonce: u64) -> Result<()> {
        let Some(highest) = self.highest else {
            self.highest = Some(nonce);
            self.seen = 1;
            return Ok(());
        };

        if nonce > highest {
            let advance = nonce - highest;
            self.seen = if advance >= REPLAY_WINDOW_LEN {
                1
            } else {
                (self.seen << advance) | 1
            };
            self.highest = Some(nonce);
            return Ok(());
        }

        let age = highest - nonce;
        if age >= REPLAY_WINDOW_LEN {
            return Err("stateless datagram is outside the replay window".into());
        }
        let mask = 1u128 << age;
        if self.seen & mask != 0 {
            return Err("replayed stateless datagram".into());
        }
        self.seen |= mask;
        Ok(())
    }
}

impl StatelessNoise {
    fn from_keys(keys: Keys) -> Self {
        StatelessNoise {
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            send_nonce: Mutex::new(0),
            recv_window: Mutex::new(ReplayWindow::default()),
        }
    }

    /// Encrypt `plaintext` into a `[nonce:8][ciphertext]` datagram body.
    ///
    /// # Errors
    ///
    /// Returns an error after the directional nonce space is exhausted or if
    /// the nonce state is unavailable.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = {
            let mut n = self
                .send_nonce
                .lock()
                .map_err(|_| -> Error { "stateless send nonce lock poisoned".into() })?;
            let v = *n;
            *n = n
                .checked_add(1)
                .ok_or_else(|| -> Error { "stateless send nonce exhausted".into() })?;
            v
        };
        let ct = aead_encrypt(&self.send_key, nonce, &[], plaintext);
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a `[nonce:8][ciphertext]` datagram body.
    pub fn open(&self, datagram: &[u8]) -> Result<Vec<u8>> {
        if datagram.len() < 8 + TAGLEN {
            return Err("short datagram".into());
        }
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&datagram[..8]);
        let nonce = u64::from_be_bytes(nonce_bytes);
        let plaintext = aead_decrypt(&self.recv_key, nonce, &[], &datagram[8..])
            .map_err(|_| -> Error { "stateless decrypt failed".into() })?;
        self.recv_window
            .lock()
            .map_err(|_| -> Error { "stateless replay window lock poisoned".into() })?
            .check_and_mark(nonce)?;
        Ok(plaintext)
    }
}

/// Initiator handshake that converts straight to a stateless transport.
/// The 8-byte `id` rides in the (PSK-encrypted) first handshake message payload.
pub async fn client_handshake_stateless<S>(
    stream: S,
    psk: &[u8; 32],
    id: u64,
) -> Result<StatelessNoise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (noise, _reply) = client_handshake_stateless_reply(stream, psk, id).await?;
    Ok(noise)
}

/// Initiator handshake for a claim over a setup conv: probe, relay leg, UDP
/// forward, or bridge. The credential-selector preface names the client
/// credential the handshake is keyed by, so the responder learns which client
/// is claiming `id` before any claim state is touched.
pub async fn client_handshake_stateless_claim<S>(
    stream: S,
    credential_psk: &[u8; 32],
    id: u64,
    capability: &crate::proto::Capability,
) -> Result<StatelessNoise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (noise, _reply) =
        client_handshake_stateless_claim_reply(stream, credential_psk, id, capability).await?;
    Ok(noise)
}

/// Like [`client_handshake_stateless_claim`], also returning the responder's
/// message-2 payload.
pub async fn client_handshake_stateless_claim_reply<S>(
    stream: S,
    credential_psk: &[u8; 32],
    id: u64,
    capability: &crate::proto::Capability,
) -> Result<(StatelessNoise, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let preface = AuthRole::Client.preface(client_selector(credential_psk));
    let mut payload = Vec::with_capacity(8 + crate::proto::CAPABILITY_LEN);
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(capability);
    crate::client::boxed(stateless_initiator(
        Box::new(stream),
        credential_psk,
        Some(preface),
        &payload,
    ))
    .await
}

/// Like [`client_handshake_stateless`], also returning the responder's
/// message-2 payload.
pub async fn client_handshake_stateless_reply<S>(
    stream: S,
    psk: &[u8; 32],
    id: u64,
) -> Result<(StatelessNoise, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::client::boxed(stateless_initiator(
        Box::new(stream),
        psk,
        None,
        &id.to_be_bytes(),
    ))
    .await
}

/// Responder handshake; returns the peer's `id` and the stateless transport.
/// `reply` is sealed into message 2's payload; an initiator that expects no
/// reply decrypts and discards it.
pub async fn server_handshake_stateless<S>(
    stream: S,
    psk: &[u8; 32],
    reply: &[u8],
) -> Result<(u64, StatelessNoise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::client::boxed(stateless_responder(Box::new(stream), psk, reply)).await
}

async fn stateless_responder(
    stream: BoxStream,
    psk: &[u8; 32],
    reply: &[u8],
) -> Result<(u64, StatelessNoise)> {
    let (_, keys, payload) = respond(stream, psk, &STATELESS_PROLOGUE, reply).await?;
    if payload.len() < 8 {
        return Err("missing stream id in handshake payload".into());
    }
    let id = u64::from_be_bytes(payload[..8].try_into().unwrap());
    Ok((id, StatelessNoise::from_keys(keys)))
}

/// Responder side of a claim handshake: read the credential-selector preface,
/// complete the handshake with that client's credential, and return the
/// authenticated client id with the claimed `id` and capability. The caller
/// admits the claim only for the client the credential names.
pub async fn server_handshake_stateless_claim<S>(
    stream: S,
    clients: &ClientCredentials,
    reply: &[u8],
) -> Result<(String, u64, crate::proto::Capability, StatelessNoise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::client::boxed(claim_responder(Box::new(stream), clients, reply)).await
}

async fn claim_responder(
    mut stream: BoxStream,
    clients: &ClientCredentials,
    reply: &[u8],
) -> Result<(String, u64, crate::proto::Capability, StatelessNoise)> {
    let (role, selector, preface) = read_preface(&mut stream).await?;
    if role != AuthRole::Client {
        return Err("stateless claims require a client credential".into());
    }
    let (client_id, psk) = clients.get(&selector).ok_or("unknown client credential")?;
    let (_, keys, payload) = respond(stream, psk, &preface, reply).await?;
    if payload.len() != 8 + crate::proto::CAPABILITY_LEN {
        return Err("invalid data capability in handshake payload".into());
    }
    let mut id_bytes = [0; 8];
    id_bytes.copy_from_slice(&payload[..8]);
    let id = u64::from_be_bytes(id_bytes);
    let mut capability = [0; crate::proto::CAPABILITY_LEN];
    capability.copy_from_slice(&payload[8..]);
    Ok((
        client_id.clone(),
        id,
        capability,
        StatelessNoise::from_keys(keys),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(id: &str, psk: [u8; 32]) -> ClientCredentials {
        [(client_selector(&psk), (id.to_string(), psk))]
            .into_iter()
            .collect()
    }

    async fn stateless_pair() -> (StatelessNoise, StatelessNoise) {
        let psk = derive_psk("stateless replay fixture");
        let (a, b) = tokio::io::duplex(8192);
        let responder =
            crate::spawn(async move { server_handshake_stateless(b, &psk, &[]).await.unwrap() });
        let initiator = client_handshake_stateless(a, &psk, 7).await.unwrap();
        let (_, responder) = responder.await.unwrap();
        (initiator, responder)
    }

    fn seal_at(noise: &StatelessNoise, nonce: u64, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = aead_encrypt(&noise.send_key, nonce, &[], plaintext);
        let mut datagram = Vec::with_capacity(8 + ciphertext.len());
        datagram.extend_from_slice(&nonce.to_be_bytes());
        datagram.extend_from_slice(&ciphertext);
        datagram
    }

    #[tokio::test]
    async fn stateless_roundtrip_out_of_order() {
        let psk = derive_psk("stateless secret");
        let (a, b) = tokio::io::duplex(8192);

        let srv =
            crate::spawn(async move { server_handshake_stateless(b, &psk, &[]).await.unwrap() });
        let cli = client_handshake_stateless(a, &psk, 0xABCD).await.unwrap();
        let (id, srv) = srv.await.unwrap();
        assert_eq!(id, 0xABCD);

        // Client -> server: two datagrams, delivered out of order.
        let d0 = cli.seal(b"first").unwrap();
        let d1 = cli.seal(b"second").unwrap();
        assert_eq!(srv.open(&d1).unwrap(), b"second");
        assert_eq!(srv.open(&d0).unwrap(), b"first");

        // Server -> client back.
        let r = srv.seal(b"reply").unwrap();
        assert_eq!(cli.open(&r).unwrap(), b"reply");
    }

    #[tokio::test]
    async fn stateless_rejects_duplicate_datagrams() {
        let (initiator, responder) = stateless_pair().await;
        let datagram = initiator.seal(b"once").unwrap();

        assert_eq!(responder.open(&datagram).unwrap(), b"once");
        assert!(responder.open(&datagram).is_err());
    }

    #[tokio::test]
    async fn stateless_replay_window_accepts_reordering_and_rejects_old_datagrams() {
        let (initiator, responder) = stateless_pair().await;
        let first = seal_at(&initiator, 0, b"first");
        let latest = seal_at(&initiator, 128, b"latest");
        let reordered = seal_at(&initiator, 127, b"reordered");

        assert_eq!(responder.open(&latest).unwrap(), b"latest");
        assert_eq!(responder.open(&reordered).unwrap(), b"reordered");
        assert!(responder.open(&first).is_err());
    }

    #[tokio::test]
    async fn stateless_replay_window_does_not_wrap() {
        let (initiator, responder) = stateless_pair().await;
        let last = seal_at(&initiator, u64::MAX, b"last");
        let wrapped = seal_at(&initiator, 0, b"wrapped");

        assert_eq!(responder.open(&last).unwrap(), b"last");
        assert!(responder.open(&wrapped).is_err());
    }

    #[tokio::test]
    async fn stateless_send_nonce_does_not_wrap() {
        let (initiator, _) = stateless_pair().await;
        *initiator.send_nonce.lock().unwrap() = u64::MAX - 1;

        let last = initiator.seal(b"last").unwrap();
        assert_eq!(
            u64::from_be_bytes(last[..8].try_into().unwrap()),
            u64::MAX - 1
        );
        assert!(initiator.seal(b"wrapped").is_err());
        assert!(initiator.seal(b"wrapped again").is_err());
    }

    // The proof binds every transcript field: only the identity's key holder
    // can compute it, and changing the provides byte or the client id fails
    // an otherwise valid MAC.
    #[test]
    fn announce_proof_verifies_only_the_key_holder() {
        let owner = derive_psk("announce owner");
        let impostor = derive_psk("announce impostor");
        let identity = public_identity(&owner);
        let challenge = AnnounceChallenge::mint(&identity).unwrap().unwrap();

        let good = announce_proof(&owner, &challenge.eph_pub, &challenge.nonce, 1, "node-a");
        assert!(challenge.verify(1, "node-a", &good));
        assert!(!challenge.verify(2, "node-a", &good));
        assert!(!challenge.verify(1, "node-b", &good));

        let forged = announce_proof(&impostor, &challenge.eph_pub, &challenge.nonce, 1, "node-a");
        assert!(!challenge.verify(1, "node-a", &forged));

        // A proof answers only the challenge it was computed for.
        let fresh = AnnounceChallenge::mint(&identity).unwrap().unwrap();
        assert!(!fresh.verify(1, "node-a", &good));
    }

    #[test]
    fn announce_challenge_refuses_a_small_order_identity() {
        assert!(AnnounceChallenge::mint(&[0u8; 32]).unwrap().is_none());
        let identity = public_identity(&derive_psk("valid announce identity"));
        assert!(AnnounceChallenge::mint(&identity).unwrap().is_some());
    }

    #[test]
    fn stateless_replay_window_has_fixed_inline_state() {
        assert!(!std::mem::needs_drop::<ReplayWindow>());
        assert_eq!(
            std::mem::size_of::<ReplayWindow>(),
            std::mem::size_of::<Option<u64>>() + std::mem::size_of::<u128>()
        );
    }

    #[tokio::test]
    async fn stateless_mixed_protocol_versions_fail_closed() {
        let psk = derive_psk("stateless version fixture");
        let (legacy, current) = tokio::io::duplex(8192);
        let legacy_initiator = async {
            let stream: BoxStream = Box::new(legacy);
            initiate(stream, &psk, None, &[], &7u64.to_be_bytes()).await
        };
        let current_responder = server_handshake_stateless(current, &psk, &[]);
        let (legacy_result, current_result) = tokio::join!(legacy_initiator, current_responder);
        assert!(legacy_result.is_err());
        assert!(current_result.is_err());

        let (current, legacy) = tokio::io::duplex(8192);
        let current_initiator = client_handshake_stateless(current, &psk, 7);
        let legacy_responder = async {
            let stream: BoxStream = Box::new(legacy);
            respond(stream, &psk, &[], &[]).await
        };
        let (current_result, legacy_result) = tokio::join!(current_initiator, legacy_responder);
        assert!(current_result.is_err());
        assert!(legacy_result.is_err());
    }

    #[tokio::test]
    async fn handshake_and_roundtrip() {
        let psk = derive_psk("correct horse");
        let (a, b) = tokio::io::duplex(2 << 20);

        let srv = crate::spawn(async move { server_handshake(b, &psk).await.unwrap() });
        let (mut cr, mut cw) = client_handshake(a, &psk).await.unwrap();
        let (mut sr, mut sw) = srv.await.unwrap();

        // client -> server, including a large payload that spans multiple frames
        let big = vec![7u8; 200_000];
        cw.send(b"ping").await.unwrap();
        cw.send(&big).await.unwrap();
        assert_eq!(sr.recv().await.unwrap(), b"ping");
        assert_eq!(sr.recv().await.unwrap().len(), 65519); // first chunk
                                                           // server -> client
        sw.send(b"pong").await.unwrap();
        assert_eq!(cr.recv().await.unwrap(), b"pong");
    }

    #[tokio::test]
    async fn remote_handshake_selects_independent_credentials() {
        let client_psk = derive_psk("remote client fixture");
        let admin_psk = derive_psk("remote admin fixture");
        let clients = credentials("client-a", client_psk);

        for (role, psk) in [(AuthRole::Client, client_psk), (AuthRole::Admin, admin_psk)] {
            let (initiator, responder) = tokio::io::duplex(8192);
            let client = client_handshake_remote(initiator, &psk, role);
            let server = server_handshake_remote(responder, &clients, Some(&admin_psk));
            let (client, server) = tokio::join!(client, server);
            assert!(client.is_ok());
            let expected = match role {
                AuthRole::Client => AuthIdentity::Client("client-a".into()),
                AuthRole::Admin => AuthIdentity::Admin,
            };
            assert_eq!(server.unwrap().0, expected);
        }

        for (role, wrong_psk) in [(AuthRole::Client, admin_psk), (AuthRole::Admin, client_psk)] {
            let (initiator, responder) = tokio::io::duplex(8192);
            let client = client_handshake_remote(initiator, &wrong_psk, role);
            let server = server_handshake_remote(responder, &clients, Some(&admin_psk));
            let (client, server) = tokio::join!(client, server);
            assert!(client.is_err());
            assert!(server.is_err());
        }
    }

    #[tokio::test]
    async fn remote_admin_handshake_fails_when_unconfigured() {
        let client_psk = derive_psk("remote client fixture");
        let admin_psk = derive_psk("remote admin fixture");
        let clients = credentials("client-a", client_psk);
        let (initiator, responder) = tokio::io::duplex(8192);
        let client = client_handshake_remote(initiator, &admin_psk, AuthRole::Admin);
        let server = server_handshake_remote(responder, &clients, None);
        let (client, server) = tokio::join!(client, server);
        assert!(client.is_err());
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn remote_mixed_protocol_versions_fail_closed() {
        let psk = derive_psk("remote version fixture");
        let clients = credentials("client-a", psk);
        let (legacy, current) = tokio::io::duplex(8192);
        let legacy_client = client_handshake(legacy, &psk);
        let current_server = server_handshake_remote(current, &clients, None);
        let (legacy_result, current_result) = tokio::join!(legacy_client, current_server);
        assert!(legacy_result.is_err());
        assert!(current_result.is_err());

        let (current, legacy) = tokio::io::duplex(8192);
        let current_client = client_handshake_remote(current, &psk, AuthRole::Client);
        let legacy_server = async {
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                server_handshake(legacy, &psk),
            )
            .await
        };
        let (current_result, legacy_result) = tokio::join!(current_client, legacy_server);
        assert!(current_result.is_err());
        assert!(legacy_result.is_err());

        let (mut prior, current) = tokio::io::duplex(8192);
        let prior_client = async {
            let mut preface = [0u8; REMOTE_PREFACE_LEN];
            preface[..2].copy_from_slice(&REMOTE_PREFACE_MAGIC);
            preface[2] = crate::identity::PROTO_VERSION - 1;
            preface[3] = AuthRole::Client as u8;
            preface[4..].copy_from_slice(&client_selector(&psk));
            prior.write_all(&preface).await?;
            let stream: BoxStream = Box::new(prior);
            initiate(stream, &psk, None, &preface, &[]).await
        };
        let current_server = server_handshake_remote(current, &clients, None);
        let (prior_result, current_result) = tokio::join!(prior_client, current_server);
        assert!(prior_result.is_err());
        assert!(current_result.is_err());
    }

    // The claim handshake names its credential in the preface: the responder
    // resolves the client id from it, keys the handshake with that client's
    // psk, and hands back the claimed id and capability with a live transport.
    #[tokio::test]
    async fn stateless_claim_binds_the_claiming_credential() {
        let a_psk = derive_psk("claim client a");
        let b_psk = derive_psk("claim client b");
        let mut clients = credentials("client-a", a_psk);
        clients.extend(credentials("client-b", b_psk));
        let capability = [9u8; crate::proto::CAPABILITY_LEN];
        let (initiator, responder) = tokio::io::duplex(8192);

        let server = crate::spawn(async move {
            server_handshake_stateless_claim(responder, &clients, b"observed").await
        });
        let (cli, reply) =
            client_handshake_stateless_claim_reply(initiator, &b_psk, 42, &capability)
                .await
                .unwrap();
        assert_eq!(reply, b"observed");
        let (client_id, id, got_capability, srv) = server.await.unwrap().unwrap();
        assert_eq!(client_id, "client-b");
        assert_eq!(id, 42);
        assert_eq!(got_capability, capability);

        let d = cli.seal(b"up").unwrap();
        assert_eq!(srv.open(&d).unwrap(), b"up");
        let d = srv.seal(b"down").unwrap();
        assert_eq!(cli.open(&d).unwrap(), b"down");
    }

    #[tokio::test]
    async fn stateless_claim_unknown_credential_fails_closed() {
        let clients = credentials("client-a", derive_psk("claim known"));
        let stranger = derive_psk("claim stranger");
        let capability = [0u8; crate::proto::CAPABILITY_LEN];
        let (initiator, responder) = tokio::io::duplex(8192);
        let client = client_handshake_stateless_claim(initiator, &stranger, 7, &capability);
        let server = server_handshake_stateless_claim(responder, &clients, &[]);
        let (client, server) = tokio::join!(client, server);
        assert!(client.is_err());
        assert!(server.is_err());
    }

    // The admin credential opens no stateless claims: the role is refused
    // before any psk lookup.
    #[tokio::test]
    async fn stateless_claim_refuses_the_admin_role() {
        let psk = derive_psk("claim admin");
        let clients = credentials("client-a", psk);
        let (mut initiator, responder) = tokio::io::duplex(8192);
        // The selector names a registered credential and the handshake is
        // keyed by it, so the role byte is the only thing left to refuse on.
        let admin = async {
            let preface = AuthRole::Admin.preface(client_selector(&psk));
            initiator.write_all(&preface).await?;
            let stream: BoxStream = Box::new(initiator);
            initiate(stream, &psk, None, &preface, &7u64.to_be_bytes()).await
        };
        let server = server_handshake_stateless_claim(responder, &clients, &[]);
        let (admin, server) = tokio::join!(admin, server);
        assert!(admin.is_err());
        assert!(server.is_err());
    }

    // A claim handshake without the credential preface (the shape prior
    // protocol versions sent) authenticates nothing.
    #[tokio::test]
    async fn stateless_claim_without_preface_fails_closed() {
        let psk = derive_psk("claim prefaceless");
        let clients = credentials("client-a", psk);
        let capability = [0u8; crate::proto::CAPABILITY_LEN];
        let (initiator, responder) = tokio::io::duplex(8192);
        let legacy = async {
            let mut payload = Vec::with_capacity(8 + crate::proto::CAPABILITY_LEN);
            payload.extend_from_slice(&7u64.to_be_bytes());
            payload.extend_from_slice(&capability);
            let stream: BoxStream = Box::new(initiator);
            initiate(stream, &psk, None, &STATELESS_PROLOGUE, &payload).await
        };
        let server = server_handshake_stateless_claim(responder, &clients, &[]);
        let (legacy, server) = tokio::join!(legacy, server);
        assert!(legacy.is_err());
        assert!(server.is_err());
    }

    // The responder's message-2 payload reaches the initiator intact, and the
    // resulting transport still carries datagrams both ways.
    #[tokio::test]
    async fn stateless_reply_payload_roundtrip() {
        let psk = derive_psk("reply payload");
        let (a, b) = tokio::io::duplex(8192);

        let srv = crate::spawn(async move {
            server_handshake_stateless(b, &psk, b"reply bytes")
                .await
                .unwrap()
        });
        let (cli, reply) = client_handshake_stateless_reply(a, &psk, 7).await.unwrap();
        assert_eq!(reply, b"reply bytes");
        let (id, srv) = srv.await.unwrap();
        assert_eq!(id, 7);

        let d = cli.seal(b"up").unwrap();
        assert_eq!(srv.open(&d).unwrap(), b"up");
        let d = srv.seal(b"down").unwrap();
        assert_eq!(cli.open(&d).unwrap(), b"down");
    }

    #[tokio::test]
    async fn wrong_secret_fails() {
        let (a, b) = tokio::io::duplex(8192);
        let good = derive_psk("right");
        let bad = derive_psk("wrong");
        let srv = crate::spawn(async move { server_handshake(b, &bad).await });
        let cli = client_handshake(a, &good).await;
        // At least one side must reject the mismatched PSK.
        assert!(cli.is_err() || srv.await.unwrap().is_err());
    }

    // Interop against snow proves the construction is spec-faithful Noise.
    use snow::{params::NoiseParams, Builder};

    fn snow_params() -> NoiseParams {
        "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
    }

    #[tokio::test]
    async fn interop_our_initiator_snow_responder() {
        let psk = derive_psk("interop one");
        let (a, mut b) = tokio::io::duplex(1 << 16);

        let snow_psk = psk;
        let snow = crate::spawn(async move {
            let mut hs = Builder::new(snow_params())
                .psk(0, &snow_psk)
                .build_responder()
                .unwrap();
            let mut buf = [0u8; MAX_MSG];

            let msg1 = read_frame(&mut b).await.unwrap();
            hs.read_message(&msg1, &mut buf).unwrap();
            let n = hs.write_message(&[], &mut buf).unwrap();
            write_frame(&mut b, &buf[..n]).await.unwrap();
            let mut t = hs.into_transport_mode().unwrap();

            // responder receives one transport message, sends one back
            let m = read_frame(&mut b).await.unwrap();
            let mut pt = [0u8; MAX_MSG];
            let n = t.read_message(&m, &mut pt).unwrap();
            assert_eq!(&pt[..n], b"hello from ours");
            let n = t.write_message(b"hello from snow", &mut buf).unwrap();
            write_frame(&mut b, &buf[..n]).await.unwrap();
        });

        let (mut cr, mut cw) = client_handshake(a, &psk).await.unwrap();
        cw.send(b"hello from ours").await.unwrap();
        assert_eq!(cr.recv().await.unwrap(), b"hello from snow");
        snow.await.unwrap();
    }

    #[tokio::test]
    async fn interop_snow_initiator_our_responder() {
        let psk = derive_psk("interop two");
        let (mut a, b) = tokio::io::duplex(1 << 16);

        let snow_psk = psk;
        let snow = crate::spawn(async move {
            let mut hs = Builder::new(snow_params())
                .psk(0, &snow_psk)
                .build_initiator()
                .unwrap();
            let mut buf = [0u8; MAX_MSG];

            let n = hs.write_message(&[], &mut buf).unwrap();
            write_frame(&mut a, &buf[..n]).await.unwrap();
            let msg2 = read_frame(&mut a).await.unwrap();
            let mut pt = [0u8; MAX_MSG];
            hs.read_message(&msg2, &mut pt).unwrap();
            let mut t = hs.into_transport_mode().unwrap();

            let n = t.write_message(b"snow says hi", &mut buf).unwrap();
            write_frame(&mut a, &buf[..n]).await.unwrap();
            let m = read_frame(&mut a).await.unwrap();
            let n = t.read_message(&m, &mut pt).unwrap();
            assert_eq!(&pt[..n], b"ours replies");
        });

        let (mut sr, mut sw) = server_handshake(b, &psk).await.unwrap();
        assert_eq!(sr.recv().await.unwrap(), b"snow says hi");
        sw.send(b"ours replies").await.unwrap();
        snow.await.unwrap();
    }

    fn snow_xx_params() -> NoiseParams {
        "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
    }

    #[test]
    fn xx_interop_our_initiator_snow_responder() {
        let prologue = b"xx interop prologue one";
        let ours_static = derive_psk("xx ours as initiator");
        let snow_static = derive_psk("xx snow as responder");
        let mut ours = XxHandshake::initiator(&ours_static, prologue).unwrap();
        let mut snow = Builder::new(snow_xx_params())
            .local_private_key(&snow_static)
            .prologue(prologue)
            .build_responder()
            .unwrap();
        let mut buf = [0u8; MAX_MSG];
        let mut pt = [0u8; MAX_MSG];

        let msg1 = ours.write_message_one(b"one");
        let n = snow.read_message(&msg1, &mut pt).unwrap();
        assert_eq!(&pt[..n], b"one");
        let n = snow.write_message(b"two", &mut buf).unwrap();
        assert_eq!(ours.read_message_two(&buf[..n]).unwrap(), b"two");
        assert_eq!(ours.remote_static(), Some(public_identity(&snow_static)));
        let msg3 = ours.write_message_three(b"three");
        let n = snow.read_message(&msg3, &mut pt).unwrap();
        assert_eq!(&pt[..n], b"three");
        assert_eq!(
            snow.get_remote_static(),
            Some(public_identity(&ours_static).as_slice())
        );

        let snow = snow.into_stateless_transport_mode().unwrap();
        let ours = ours.into_transport();
        let dg = ours.seal(b"datagram from ours").unwrap();
        let nonce = u64::from_be_bytes(dg[..8].try_into().unwrap());
        let n = snow.read_message(nonce, &dg[8..], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"datagram from ours");
        let n = snow
            .write_message(0, b"datagram from snow", &mut buf)
            .unwrap();
        let mut dg = 0u64.to_be_bytes().to_vec();
        dg.extend_from_slice(&buf[..n]);
        assert_eq!(ours.open(&dg).unwrap(), b"datagram from snow");
    }

    #[test]
    fn xx_interop_snow_initiator_our_responder() {
        let prologue = b"xx interop prologue two";
        let snow_static = derive_psk("xx snow as initiator");
        let ours_static = derive_psk("xx ours as responder");
        let mut snow = Builder::new(snow_xx_params())
            .local_private_key(&snow_static)
            .prologue(prologue)
            .build_initiator()
            .unwrap();
        let mut ours = XxHandshake::responder(&ours_static, prologue).unwrap();
        let mut buf = [0u8; MAX_MSG];
        let mut pt = [0u8; MAX_MSG];

        let n = snow.write_message(b"one", &mut buf).unwrap();
        assert_eq!(ours.read_message_one(&buf[..n]).unwrap(), b"one");
        let msg2 = ours.write_message_two(b"two");
        let n = snow.read_message(&msg2, &mut pt).unwrap();
        assert_eq!(&pt[..n], b"two");
        assert_eq!(
            snow.get_remote_static(),
            Some(public_identity(&ours_static).as_slice())
        );
        let n = snow.write_message(b"three", &mut buf).unwrap();
        assert_eq!(ours.read_message_three(&buf[..n]).unwrap(), b"three");
        assert_eq!(ours.remote_static(), Some(public_identity(&snow_static)));

        let snow = snow.into_stateless_transport_mode().unwrap();
        let ours = ours.into_transport();
        let n = snow
            .write_message(0, b"datagram from snow", &mut buf)
            .unwrap();
        let mut dg = 0u64.to_be_bytes().to_vec();
        dg.extend_from_slice(&buf[..n]);
        assert_eq!(ours.open(&dg).unwrap(), b"datagram from snow");
        let dg = ours.seal(b"datagram from ours").unwrap();
        let nonce = u64::from_be_bytes(dg[..8].try_into().unwrap());
        let n = snow.read_message(nonce, &dg[8..], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"datagram from ours");
    }

    // Two XX handshakes differing only in prologue must not interoperate: the
    // pair challenge and identities ride there, so a transcript replayed
    // across pairings authenticates nothing.
    #[test]
    fn xx_prologue_mismatch_fails_closed() {
        let ours_static = derive_psk("xx prologue initiator");
        let their_static = derive_psk("xx prologue responder");
        let mut initiator = XxHandshake::initiator(&ours_static, b"pair one").unwrap();
        let mut responder = XxHandshake::responder(&their_static, b"pair two").unwrap();

        let msg1 = initiator.write_message_one(&[]);
        responder.read_message_one(&msg1).unwrap();
        let msg2 = responder.write_message_two(&[]);
        assert!(initiator.read_message_two(&msg2).is_err());
    }

    #[tokio::test]
    async fn interop_stateless_our_initiator_snow_responder() {
        let psk = derive_psk("interop stateless");
        let id: u64 = 0x0123_4567_89AB_CDEF;
        // Channel 1: the handshake. Channel 2: transport datagrams, since the
        // real stateless path carries datagrams over a separate socket.
        let (hs_a, mut hs_b) = tokio::io::duplex(1 << 16);
        let (mut dg_a, mut dg_b) = tokio::io::duplex(1 << 16);

        let snow_psk = psk;
        let snow = crate::spawn(async move {
            let mut hs = Builder::new(snow_params())
                .prologue(&STATELESS_PROLOGUE)
                .psk(0, &snow_psk)
                .build_responder()
                .unwrap();
            let mut buf = [0u8; MAX_MSG];
            let mut pt = [0u8; MAX_MSG];

            let msg1 = read_frame(&mut hs_b).await.unwrap();
            let n = hs.read_message(&msg1, &mut pt).unwrap();
            assert_eq!(n, 8);
            let got_id = u64::from_be_bytes(pt[..8].try_into().unwrap());
            assert_eq!(got_id, id, "carried id must match");
            let n = hs.write_message(b"sealed by snow", &mut buf).unwrap();
            write_frame(&mut hs_b, &buf[..n]).await.unwrap();
            let t = hs.into_stateless_transport_mode().unwrap();

            // open one [nonce:8][ct] datagram our client sealed
            let dg = read_frame(&mut dg_b).await.unwrap();
            let nonce = u64::from_be_bytes(dg[..8].try_into().unwrap());
            let n = t.read_message(nonce, &dg[8..], &mut pt).unwrap();
            assert_eq!(&pt[..n], b"datagram from ours");

            // seal one back in the same [nonce:8][ct] layout
            let reply_nonce: u64 = 0;
            let n = t
                .write_message(reply_nonce, b"datagram from snow", &mut buf)
                .unwrap();
            let mut out = Vec::with_capacity(8 + n);
            out.extend_from_slice(&reply_nonce.to_be_bytes());
            out.extend_from_slice(&buf[..n]);
            write_frame(&mut dg_b, &out).await.unwrap();
        });

        let (cli, reply) = client_handshake_stateless_reply(hs_a, &psk, id)
            .await
            .unwrap();
        assert_eq!(reply, b"sealed by snow");
        let dg = cli.seal(b"datagram from ours").unwrap();
        write_frame(&mut dg_a, &dg).await.unwrap();
        let reply = read_frame(&mut dg_a).await.unwrap();
        assert_eq!(cli.open(&reply).unwrap(), b"datagram from snow");
        snow.await.unwrap();
    }
}
