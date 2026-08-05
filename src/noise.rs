use std::collections::HashMap;
use std::sync::Mutex;

use crate::{Error, Result};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hmac::{Mac, SimpleHmac};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

const PATTERN: &[u8] = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
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

pub fn client_selector(psk: &[u8; 32]) -> [u8; CLIENT_SELECTOR_LEN] {
    let mut h = Blake2s256::new();
    h.update(b"zeronat-client-credential-selector-v1");
    h.update(psk);
    let digest = h.finalize();
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

/// Derive the 32-byte pre-shared key from the user's passphrase.
pub fn derive_psk(secret: &str) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"tunnel-noise-psk-v1");
    h.update(secret.as_bytes());
    h.finalize().into()
}

fn blake2s(data: &[u8]) -> [u8; HASHLEN] {
    let mut h = Blake2s256::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-BLAKE2s over `data` with the given key.
fn hmac(key: &[u8], data: &[u8]) -> [u8; HASHLEN] {
    let mut mac =
        <SimpleHmac<Blake2s256> as Mac>::new_from_slice(key).expect("hmac accepts any key len");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Noise HKDF over HMAC-BLAKE2s. Returns two or three 32-byte outputs.
fn hkdf2(ck: &[u8; HASHLEN], ikm: &[u8]) -> ([u8; HASHLEN], [u8; HASHLEN]) {
    let temp = hmac(ck, ikm);
    let o1 = hmac(&temp, &[0x01]);
    let mut msg2 = [0u8; HASHLEN + 1];
    msg2[..HASHLEN].copy_from_slice(&o1);
    msg2[HASHLEN] = 0x02;
    let o2 = hmac(&temp, &msg2);
    (o1, o2)
}

fn hkdf3(ck: &[u8; HASHLEN], ikm: &[u8]) -> ([u8; HASHLEN], [u8; HASHLEN], [u8; HASHLEN]) {
    let temp = hmac(ck, ikm);
    let o1 = hmac(&temp, &[0x01]);
    let mut msg2 = [0u8; HASHLEN + 1];
    msg2[..HASHLEN].copy_from_slice(&o1);
    msg2[HASHLEN] = 0x02;
    let o2 = hmac(&temp, &msg2);
    let mut msg3 = [0u8; HASHLEN + 1];
    msg3[..HASHLEN].copy_from_slice(&o2);
    msg3[HASHLEN] = 0x03;
    let o3 = hmac(&temp, &msg3);
    (o1, o2, o3)
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
    fn new() -> Self {
        // InitializeSymmetric: if the protocol name is longer than HASHLEN,
        // h = HASH(name); otherwise zero-pad it to HASHLEN. This name is
        // longer than 32 bytes, so it hashes.
        let h = if PATTERN.len() <= HASHLEN {
            let mut buf = [0u8; HASHLEN];
            buf[..PATTERN.len()].copy_from_slice(PATTERN);
            buf
        } else {
            blake2s(PATTERN)
        };
        SymmetricState {
            ck: h,
            h,
            k: None,
            n: 0,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(HASHLEN + data.len());
        buf.extend_from_slice(&self.h);
        buf.extend_from_slice(data);
        self.h = blake2s(&buf);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, temp_k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(temp_k);
        self.n = 0;
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let (ck, temp_h, temp_k) = hkdf3(&self.ck, ikm);
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

    fn split(&self) -> ([u8; 32], [u8; 32]) {
        hkdf2(&self.ck, &[])
    }
}

/// Finished handshake: directional transport keys plus running counters.
struct Keys {
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

/// Run the NNpsk0 initiator handshake to completion over `stream`, returning
/// the transport keys and the responder's message-2 payload.
async fn run_initiator(
    stream: &mut BoxStream,
    psk: &[u8; 32],
    prologue: &[u8],
    payload1: &[u8],
) -> Result<(Keys, Vec<u8>)> {
    let mut ss = SymmetricState::new();
    ss.mix_hash(prologue);

    // Message 1: tokens [psk, e]
    ss.mix_key_and_hash(psk);
    let e_priv = EphemeralSecret::random();
    let e_pub = PublicKey::from(&e_priv);
    ss.mix_hash(e_pub.as_bytes());
    ss.mix_key(e_pub.as_bytes());
    let ct1 = ss.encrypt_and_hash(payload1);
    let mut msg1 = Vec::with_capacity(DHLEN + ct1.len());
    msg1.extend_from_slice(e_pub.as_bytes());
    msg1.extend_from_slice(&ct1);
    write_frame(stream, &msg1).await?;

    // Message 2: tokens [e, ee]
    let msg2 = read_frame(stream).await?;
    if msg2.len() < DHLEN {
        return Err("handshake message 2 too short".into());
    }
    let mut re_bytes = [0u8; DHLEN];
    re_bytes.copy_from_slice(&msg2[..DHLEN]);
    let re = PublicKey::from(re_bytes);
    ss.mix_hash(&re_bytes);
    ss.mix_key(&re_bytes);
    let dh = e_priv.diffie_hellman(&re);
    ss.mix_key(dh.as_bytes());
    let payload2 = ss.decrypt_and_hash(&msg2[DHLEN..])?;

    let (t1, t2) = ss.split();
    Ok((
        Keys {
            send_key: t1,
            recv_key: t2,
        },
        payload2,
    ))
}

/// Run the NNpsk0 responder handshake, sealing `payload2` into message 2;
/// returns the keys and the decrypted payload from message 1.
async fn run_responder(
    stream: &mut BoxStream,
    psk: &[u8; 32],
    prologue: &[u8],
    payload2: &[u8],
) -> Result<(Keys, Vec<u8>)> {
    let mut ss = SymmetricState::new();
    ss.mix_hash(prologue);

    // Message 1: tokens [psk, e]
    let msg1 = read_frame(stream).await?;
    if msg1.len() < DHLEN {
        return Err("handshake message 1 too short".into());
    }
    ss.mix_key_and_hash(psk);
    let mut re_bytes = [0u8; DHLEN];
    re_bytes.copy_from_slice(&msg1[..DHLEN]);
    let re = PublicKey::from(re_bytes);
    ss.mix_hash(&re_bytes);
    ss.mix_key(&re_bytes);
    let payload1 = ss.decrypt_and_hash(&msg1[DHLEN..])?;

    // Message 2: tokens [e, ee]
    let e_priv = EphemeralSecret::random();
    let e_pub = PublicKey::from(&e_priv);
    ss.mix_hash(e_pub.as_bytes());
    ss.mix_key(e_pub.as_bytes());
    let dh = e_priv.diffie_hellman(&re);
    ss.mix_key(dh.as_bytes());
    let ct2 = ss.encrypt_and_hash(payload2);
    let mut msg2 = Vec::with_capacity(DHLEN + ct2.len());
    msg2.extend_from_slice(e_pub.as_bytes());
    msg2.extend_from_slice(&ct2);
    write_frame(stream, &msg2).await?;

    let (t1, t2) = ss.split();
    // Responder: send-cipher = t2, recv-cipher = t1.
    Ok((
        Keys {
            send_key: t2,
            recv_key: t1,
        },
        payload1,
    ))
}

pub async fn client_handshake<S>(stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let (keys, _payload2) = run_initiator(&mut stream, psk, &[], &[]).await?;
    Ok(finish(stream, keys))
}

pub async fn server_handshake<S>(stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let (keys, _payload) = run_responder(&mut stream, psk, &[], &[]).await?;
    Ok(finish(stream, keys))
}

/// Run a remote control-port initiator handshake under one credential role.
pub async fn client_handshake_remote<S>(
    mut stream: S,
    psk: &[u8; 32],
    role: AuthRole,
) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let selector = match role {
        AuthRole::Client => client_selector(psk),
        AuthRole::Admin => [0u8; CLIENT_SELECTOR_LEN],
    };
    let preface = role.preface(selector);
    stream.write_all(&preface).await?;
    stream.flush().await?;
    let mut stream: BoxStream = Box::new(stream);
    let (keys, _payload2) = run_initiator(&mut stream, psk, &preface, &[]).await?;
    Ok(finish(stream, keys))
}

/// Read the role preface and complete the handshake with that role's configured key.
pub async fn server_handshake_remote<S>(
    mut stream: S,
    clients: &ClientCredentials,
    admin_psk: Option<&[u8; 32]>,
) -> Result<(AuthIdentity, Noise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut preface = [0u8; REMOTE_PREFACE_LEN];
    stream.read_exact(&mut preface).await?;
    if preface[..2] != REMOTE_PREFACE_MAGIC {
        return Err("unsupported remote handshake preface".into());
    }
    if preface[2] != crate::identity::PROTO_VERSION {
        return Err("unsupported protocol version".into());
    }
    let role = AuthRole::from_byte(preface[3])?;
    let (identity, psk) = match role {
        AuthRole::Client => {
            let selector: [u8; CLIENT_SELECTOR_LEN] = preface[4..]
                .try_into()
                .map_err(|_| -> Error { "invalid client credential selector".into() })?;
            let (client_id, psk) = clients.get(&selector).ok_or("unknown client credential")?;
            (AuthIdentity::Client(client_id.clone()), psk)
        }
        AuthRole::Admin => (
            AuthIdentity::Admin,
            admin_psk.ok_or("remote administration is disabled")?,
        ),
    };
    let mut stream: BoxStream = Box::new(stream);
    let (keys, _payload) = run_responder(&mut stream, psk, &preface, &[]).await?;
    Ok((identity, finish(stream, keys)))
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
        Self {
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            send_nonce: Mutex::new(0),
            recv_window: Mutex::new(ReplayWindow::default()),
        }
    }

    /// Build datagram traffic state from two random keys carried inside the
    /// authenticated peer handshake.
    pub fn from_peer_keys(keys: &[u8; 64], initiator: bool) -> Self {
        let mut initiator_to_responder = [0; 32];
        initiator_to_responder.copy_from_slice(&keys[..32]);
        let mut responder_to_initiator = [0; 32];
        responder_to_initiator.copy_from_slice(&keys[32..]);
        let keys = if initiator {
            Keys {
                send_key: initiator_to_responder,
                recv_key: responder_to_initiator,
            }
        } else {
            Keys {
                send_key: responder_to_initiator,
                recv_key: initiator_to_responder,
            }
        };
        Self::from_keys(keys)
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

pub async fn client_handshake_stateless_claim<S>(
    stream: S,
    psk: &[u8; 32],
    id: u64,
    capability: &crate::proto::Capability,
) -> Result<StatelessNoise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (noise, _reply) =
        client_handshake_stateless_claim_reply(stream, psk, id, capability).await?;
    Ok(noise)
}

pub async fn client_handshake_stateless_claim_reply<S>(
    stream: S,
    psk: &[u8; 32],
    id: u64,
    capability: &crate::proto::Capability,
) -> Result<(StatelessNoise, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut payload = Vec::with_capacity(8 + crate::proto::CAPABILITY_LEN);
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(capability);
    let mut stream: BoxStream = Box::new(stream);
    let (keys, reply) = run_initiator(&mut stream, psk, &STATELESS_PROLOGUE, &payload).await?;
    Ok((StatelessNoise::from_keys(keys), reply))
}

pub async fn client_handshake_stateless_claim_remote<S>(
    stream: S,
    psk: &[u8; 32],
    id: u64,
    capability: &crate::proto::Capability,
) -> Result<StatelessNoise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (noise, _reply) =
        client_handshake_stateless_claim_remote_reply(stream, psk, id, capability).await?;
    Ok(noise)
}

pub async fn client_handshake_stateless_claim_remote_reply<S>(
    mut stream: S,
    psk: &[u8; 32],
    id: u64,
    capability: &crate::proto::Capability,
) -> Result<(StatelessNoise, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let preface = AuthRole::Client.preface(client_selector(psk));
    stream.write_all(&preface).await?;
    stream.flush().await?;
    let mut payload = Vec::with_capacity(8 + crate::proto::CAPABILITY_LEN);
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(capability);
    let mut prologue = Vec::with_capacity(preface.len() + STATELESS_PROLOGUE.len());
    prologue.extend_from_slice(&preface);
    prologue.extend_from_slice(&STATELESS_PROLOGUE);
    let mut stream: BoxStream = Box::new(stream);
    let (keys, reply) = run_initiator(&mut stream, psk, &prologue, &payload).await?;
    Ok((StatelessNoise::from_keys(keys), reply))
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
    let mut stream: BoxStream = Box::new(stream);
    let (keys, reply) =
        run_initiator(&mut stream, psk, &STATELESS_PROLOGUE, &id.to_be_bytes()).await?;
    Ok((StatelessNoise::from_keys(keys), reply))
}

pub async fn client_handshake_stateless_payload_reply<S>(
    stream: S,
    psk: &[u8; 32],
    payload: &[u8],
) -> Result<(StatelessNoise, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let (keys, reply) = run_initiator(&mut stream, psk, &STATELESS_PROLOGUE, payload).await?;
    Ok((StatelessNoise::from_keys(keys), reply))
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
    let mut stream: BoxStream = Box::new(stream);
    let (keys, payload) = run_responder(&mut stream, psk, &STATELESS_PROLOGUE, reply).await?;
    if payload.len() < 8 {
        return Err("missing stream id in handshake payload".into());
    }
    let mut id_bytes = [0; 8];
    id_bytes.copy_from_slice(&payload[..8]);
    let id = u64::from_be_bytes(id_bytes);
    Ok((id, StatelessNoise::from_keys(keys)))
}

pub async fn server_handshake_stateless_payload<S>(
    stream: S,
    psk: &[u8; 32],
    reply: &[u8],
) -> Result<(Vec<u8>, StatelessNoise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let (keys, payload) = run_responder(&mut stream, psk, &STATELESS_PROLOGUE, reply).await?;
    Ok((payload, StatelessNoise::from_keys(keys)))
}

pub async fn server_handshake_stateless_claim<S>(
    stream: S,
    psk: &[u8; 32],
    reply: &[u8],
) -> Result<(u64, crate::proto::Capability, StatelessNoise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream: BoxStream = Box::new(stream);
    let (keys, payload) = run_responder(&mut stream, psk, &STATELESS_PROLOGUE, reply).await?;
    if payload.len() != 8 + crate::proto::CAPABILITY_LEN {
        return Err("invalid data capability in handshake payload".into());
    }
    let mut id_bytes = [0; 8];
    id_bytes.copy_from_slice(&payload[..8]);
    let id = u64::from_be_bytes(id_bytes);
    let mut capability = [0; crate::proto::CAPABILITY_LEN];
    capability.copy_from_slice(&payload[8..]);
    Ok((id, capability, StatelessNoise::from_keys(keys)))
}

pub async fn server_handshake_stateless_claim_remote<S>(
    mut stream: S,
    clients: &ClientCredentials,
    reply: &[u8],
) -> Result<(String, u64, crate::proto::Capability, StatelessNoise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut preface = [0u8; REMOTE_PREFACE_LEN];
    stream.read_exact(&mut preface).await?;
    if preface[..2] != REMOTE_PREFACE_MAGIC {
        return Err("unsupported remote handshake preface".into());
    }
    if preface[2] != crate::identity::PROTO_VERSION {
        return Err("unsupported protocol version".into());
    }
    if AuthRole::from_byte(preface[3])? != AuthRole::Client {
        return Err("stateless claims require a client credential".into());
    }
    let selector: [u8; CLIENT_SELECTOR_LEN] = preface[4..]
        .try_into()
        .map_err(|_| -> Error { "invalid client credential selector".into() })?;
    let (client_id, psk) = clients.get(&selector).ok_or("unknown client credential")?;
    let mut prologue = Vec::with_capacity(preface.len() + STATELESS_PROLOGUE.len());
    prologue.extend_from_slice(&preface);
    prologue.extend_from_slice(&STATELESS_PROLOGUE);
    let mut stream: BoxStream = Box::new(stream);
    let (keys, payload) = run_responder(&mut stream, psk, &prologue, reply).await?;
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

    #[test]
    fn broker_challenge_cannot_open_peer_session_traffic() {
        let keys = [7; 64];
        let broker_keys = [9; 64];
        let initiator = StatelessNoise::from_peer_keys(&keys, true);
        let responder = StatelessNoise::from_peer_keys(&keys, false);
        let broker = StatelessNoise::from_peer_keys(&broker_keys, false);

        let sealed = initiator.seal(b"peer traffic").unwrap();

        assert_eq!(responder.open(&sealed).unwrap(), b"peer traffic");
        assert!(broker.open(&sealed).is_err());
    }

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
            let mut stream: BoxStream = Box::new(legacy);
            run_initiator(&mut stream, &psk, &[], &7u64.to_be_bytes()).await
        };
        let current_responder = server_handshake_stateless(current, &psk, &[]);
        let (legacy_result, current_result) = tokio::join!(legacy_initiator, current_responder);
        assert!(legacy_result.is_err());
        assert!(current_result.is_err());

        let (current, legacy) = tokio::io::duplex(8192);
        let current_initiator = client_handshake_stateless(current, &psk, 7);
        let legacy_responder = async {
            let mut stream: BoxStream = Box::new(legacy);
            run_responder(&mut stream, &psk, &[], &[]).await
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
            let mut stream: BoxStream = Box::new(prior);
            run_initiator(&mut stream, &psk, &preface, &[]).await
        };
        let current_server = server_handshake_remote(current, &clients, None);
        let (prior_result, current_result) = tokio::join!(prior_client, current_server);
        assert!(prior_result.is_err());
        assert!(current_result.is_err());
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
