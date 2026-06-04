use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use snow::{Builder, StatelessTransportState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const MAX_MSG: usize = 65535;
const MAX_PLAINTEXT: usize = MAX_MSG - 16;

pub type Noise = (NoiseReader, NoiseWriter);

type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Derive the 32-byte pre-shared key from the user's passphrase.
pub fn derive_psk(secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tunnel-noise-psk-v1");
    h.update(secret.as_bytes());
    h.finalize().into()
}

pub async fn client_handshake<S>(mut stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut hs = Builder::new(PATTERN.parse()?)
        .psk(0, psk)
        .build_initiator()?;
    let mut buf = [0u8; MAX_MSG];

    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;
    let msg = read_frame(&mut stream).await?;
    hs.read_message(&msg, &mut buf)?;

    finish(stream, hs.into_transport_mode()?)
}

pub async fn server_handshake<S>(mut stream: S, psk: &[u8; 32]) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut hs = Builder::new(PATTERN.parse()?)
        .psk(0, psk)
        .build_responder()?;
    let mut buf = [0u8; MAX_MSG];

    let msg = read_frame(&mut stream).await?;
    hs.read_message(&msg, &mut buf)?;
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;

    finish(stream, hs.into_transport_mode()?)
}

fn finish<S>(stream: S, transport: TransportState) -> Result<Noise>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let t = Arc::new(Mutex::new(transport));
    let (rh, wh) = tokio::io::split(stream);
    Ok((
        NoiseReader {
            rh: Box::new(rh),
            t: t.clone(),
            len: [0u8; 2],
            len_filled: 0,
            have_len: false,
            body: Vec::new(),
            body_filled: 0,
        },
        NoiseWriter {
            wh: Box::new(wh),
            t,
        },
    ))
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
    t: Arc<Mutex<TransportState>>,
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
                anyhow::bail!("connection closed");
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
                anyhow::bail!("connection closed");
            }
            self.body_filled += n;
        }

        let ct = std::mem::take(&mut self.body);
        self.len_filled = 0;
        self.have_len = false;
        let mut out = vec![0u8; ct.len()];
        let n = {
            let mut t = self.t.lock().unwrap();
            t.read_message(&ct, &mut out)
                .map_err(|e| anyhow!("decrypt failed: {e}"))?
        };
        out.truncate(n);
        Ok(out)
    }
}

/// Sending half of an encrypted connection.
pub struct NoiseWriter {
    wh: BoxWrite,
    t: Arc<Mutex<TransportState>>,
}

impl NoiseWriter {
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        for chunk in plaintext.chunks(MAX_PLAINTEXT) {
            let ct = {
                let mut t = self.t.lock().unwrap();
                let mut out = vec![0u8; chunk.len() + 16];
                let n = t
                    .write_message(chunk, &mut out)
                    .map_err(|e| anyhow!("encrypt failed: {e}"))?;
                out.truncate(n);
                out
            };
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
    t: StatelessTransportState,
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
        let mut out = vec![0u8; 8 + plaintext.len() + 16];
        out[..8].copy_from_slice(&nonce.to_be_bytes());
        let n = self
            .t
            .write_message(nonce, plaintext, &mut out[8..])
            .expect("stateless encrypt");
        out.truncate(8 + n);
        out
    }

    /// Decrypt a `[nonce:8][ciphertext]` datagram body.
    pub fn open(&self, datagram: &[u8]) -> Result<Vec<u8>> {
        if datagram.len() < 8 {
            anyhow::bail!("short datagram");
        }
        let nonce = u64::from_be_bytes(datagram[..8].try_into().unwrap());
        let mut out = vec![0u8; datagram.len() - 8];
        let n = self
            .t
            .read_message(nonce, &datagram[8..], &mut out)
            .map_err(|e| anyhow!("stateless decrypt failed: {e}"))?;
        out.truncate(n);
        Ok(out)
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
    let mut hs = Builder::new(PATTERN.parse()?).psk(0, psk).build_initiator()?;
    let mut buf = [0u8; MAX_MSG];
    let n = hs.write_message(&id.to_be_bytes(), &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;
    let msg = read_frame(&mut stream).await?;
    hs.read_message(&msg, &mut buf)?;
    Ok(StatelessNoise {
        t: hs.into_stateless_transport_mode()?,
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
    let mut hs = Builder::new(PATTERN.parse()?).psk(0, psk).build_responder()?;
    let mut buf = [0u8; MAX_MSG];
    let msg = read_frame(&mut stream).await?;
    let n = hs.read_message(&msg, &mut buf)?;
    if n < 8 {
        anyhow::bail!("missing stream id in handshake payload");
    }
    let id = u64::from_be_bytes(buf[..8].try_into().unwrap());
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;
    Ok((
        id,
        StatelessNoise {
            t: hs.into_stateless_transport_mode()?,
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
}
