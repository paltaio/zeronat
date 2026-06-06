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

pub type Noise = (NoiseReader, NoiseWriter);

type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

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

/// Run the NNpsk0 initiator handshake to completion over `stream`.
async fn run_initiator<S>(stream: &mut S, psk: &[u8; 32], payload1: &[u8]) -> Result<Keys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ss = SymmetricState::new();
    ss.mix_hash(&[]); // MixHash(prologue) with the empty prologue.

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
    ss.decrypt_and_hash(&msg2[DHLEN..])?;

    let (t1, t2) = ss.split();
    Ok(Keys {
        send_key: t1,
        recv_key: t2,
    })
}

/// Run the NNpsk0 responder handshake; returns the keys and the decrypted
/// payload from message 1.
async fn run_responder<S>(stream: &mut S, psk: &[u8; 32]) -> Result<(Keys, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ss = SymmetricState::new();
    ss.mix_hash(&[]); // MixHash(prologue) with the empty prologue.

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
    let ct2 = ss.encrypt_and_hash(&[]);
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

pub async fn client_handshake<S>(mut stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let keys = run_initiator(&mut stream, psk, &[]).await?;
    Ok(finish(stream, keys))
}

pub async fn server_handshake<S>(mut stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (keys, _payload) = run_responder(&mut stream, psk).await?;
    Ok(finish(stream, keys))
}

fn finish<S>(stream: S, keys: Keys) -> Noise
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
}

impl StatelessNoise {
    /// Encrypt `plaintext` into a `[nonce:8][ciphertext]` datagram body.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = {
            let mut n = self.send_nonce.lock().unwrap();
            let v = *n;
            *n = n.wrapping_add(1);
            v
        };
        let ct = aead_encrypt(&self.send_key, nonce, &[], plaintext);
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt a `[nonce:8][ciphertext]` datagram body.
    pub fn open(&self, datagram: &[u8]) -> Result<Vec<u8>> {
        if datagram.len() < 8 + TAGLEN {
            return Err("short datagram".into());
        }
        let nonce = u64::from_be_bytes(datagram[..8].try_into().unwrap());
        aead_decrypt(&self.recv_key, nonce, &[], &datagram[8..])
            .map_err(|_| -> Error { "stateless decrypt failed".into() })
    }
}

/// Initiator handshake that converts straight to a stateless transport.
/// The 8-byte `id` rides in the (PSK-encrypted) first handshake message payload.
pub async fn client_handshake_stateless<S>(
    mut stream: S,
    psk: &[u8; 32],
    id: u64,
) -> Result<StatelessNoise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let keys = run_initiator(&mut stream, psk, &id.to_be_bytes()).await?;
    Ok(StatelessNoise {
        send_key: keys.send_key,
        recv_key: keys.recv_key,
        send_nonce: Mutex::new(0),
    })
}

/// Responder handshake; returns the peer's `id` and the stateless transport.
pub async fn server_handshake_stateless<S>(
    mut stream: S,
    psk: &[u8; 32],
) -> Result<(u64, StatelessNoise)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (keys, payload) = run_responder(&mut stream, psk).await?;
    if payload.len() < 8 {
        return Err("missing stream id in handshake payload".into());
    }
    let id = u64::from_be_bytes(payload[..8].try_into().unwrap());
    Ok((
        id,
        StatelessNoise {
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            send_nonce: Mutex::new(0),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stateless_roundtrip_out_of_order() {
        let psk = derive_psk("stateless secret");
        let (a, b) = tokio::io::duplex(8192);

        let srv = tokio::spawn(async move { server_handshake_stateless(b, &psk).await.unwrap() });
        let cli = client_handshake_stateless(a, &psk, 0xABCD).await.unwrap();
        let (id, srv) = srv.await.unwrap();
        assert_eq!(id, 0xABCD);

        // Client -> server: two datagrams, delivered out of order.
        let d0 = cli.seal(b"first");
        let d1 = cli.seal(b"second");
        assert_eq!(srv.open(&d1).unwrap(), b"second");
        assert_eq!(srv.open(&d0).unwrap(), b"first");

        // Server -> client back.
        let r = srv.seal(b"reply");
        assert_eq!(cli.open(&r).unwrap(), b"reply");
    }

    #[tokio::test]
    async fn handshake_and_roundtrip() {
        let psk = derive_psk("correct horse");
        let (a, b) = tokio::io::duplex(2 << 20);

        let srv = tokio::spawn(async move { server_handshake(b, &psk).await.unwrap() });
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
    async fn wrong_secret_fails() {
        let (a, b) = tokio::io::duplex(8192);
        let good = derive_psk("right");
        let bad = derive_psk("wrong");
        let srv = tokio::spawn(async move { server_handshake(b, &bad).await });
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
        let snow = tokio::spawn(async move {
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
        let snow = tokio::spawn(async move {
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
        let snow = tokio::spawn(async move {
            let mut hs = Builder::new(snow_params())
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
            let n = hs.write_message(&[], &mut buf).unwrap();
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

        let cli = client_handshake_stateless(hs_a, &psk, id).await.unwrap();
        let dg = cli.seal(b"datagram from ours");
        write_frame(&mut dg_a, &dg).await.unwrap();
        let reply = read_frame(&mut dg_a).await.unwrap();
        assert_eq!(cli.open(&reply).unwrap(), b"datagram from snow");
        snow.await.unwrap();
    }
}
