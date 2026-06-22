use std::sync::Arc;

use crate::Result;
use tokio::sync::mpsc;

use crate::kcp::CLASS_DGRAM;
use crate::noise::StatelessNoise;

/// First byte of the sealed plaintext: distinguishes a real inner datagram
/// (which may itself be zero-length) from a liveness keepalive, which carries
/// no inner payload and must not reach the local UDP target. Both tunnel ends
/// run the same zeronat build, so this inner framing needs no negotiation.
const KIND_DATA: u8 = 0x00;
const KIND_KEEPALIVE: u8 = 0x01;
/// Carries a bridge client's label, sent once after a UDP bridge attaches. A
/// control frame on the datagram channel; it never reaches the forwarding path.
const KIND_NAME: u8 = 0x02;

/// Longest accepted label, a guard against a crafted oversized name frame.
const MAX_NAME_LEN: usize = 256;

/// A decrypted datagram frame: an inner datagram to forward, a keepalive that only
/// refreshes the receiver's idle window, or a one-shot bridge client label.
pub enum Frame {
    Data(Vec<u8>),
    Keepalive,
    Name(String),
}

/// Sends UDP-forward datagrams over the shared socket as `0x03` frames.
pub struct DgramTx {
    send_tx: mpsc::Sender<Vec<u8>>,
    tag: u32,
    noise: Arc<StatelessNoise>,
}

impl DgramTx {
    pub fn new(send_tx: mpsc::Sender<Vec<u8>>, tag: u32, noise: Arc<StatelessNoise>) -> Self {
        DgramTx {
            send_tx,
            tag,
            noise,
        }
    }

    pub async fn send(&self, datagram: &[u8]) -> Result<()> {
        let mut plaintext = Vec::with_capacity(1 + datagram.len());
        plaintext.push(KIND_DATA);
        plaintext.extend_from_slice(datagram);
        self.frame(&plaintext)
    }

    /// Emit a liveness keepalive: distinct from any inner datagram, ignored by
    /// the receiver beyond refreshing its idle window.
    pub async fn probe(&self) -> Result<()> {
        self.frame(&[KIND_KEEPALIVE])
    }

    /// Announce this bridge client's label. Best-effort and one-shot; a server
    /// that does not understand the kind simply drops it.
    pub async fn send_name(&self, name: &str) -> Result<()> {
        let mut plaintext = Vec::with_capacity(1 + name.len());
        plaintext.push(KIND_NAME);
        plaintext.extend_from_slice(name.as_bytes());
        self.frame(&plaintext)
    }

    fn frame(&self, plaintext: &[u8]) -> Result<()> {
        let body = self.noise.seal(plaintext); // [nonce:8][ct]
        let mut pkt = Vec::with_capacity(1 + 4 + body.len());
        pkt.push(CLASS_DGRAM);
        pkt.extend_from_slice(&self.tag.to_be_bytes());
        pkt.extend_from_slice(&body);
        match self.send_tx.try_send(pkt) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err("transport closed".into()),
        }
    }
}

/// Receives `[nonce:8][ct]` bodies (tag already stripped by the router) and decrypts.
pub struct DgramRx {
    rx: mpsc::Receiver<Vec<u8>>,
    noise: Arc<StatelessNoise>,
}

impl DgramRx {
    pub fn new(rx: mpsc::Receiver<Vec<u8>>, noise: Arc<StatelessNoise>) -> Self {
        DgramRx { rx, noise }
    }

    /// Returns the next decrypted frame, or `None` when the channel closes.
    pub async fn recv(&mut self) -> Option<Frame> {
        loop {
            let body = self.rx.recv().await?;
            match self.noise.open(&body) {
                Ok(pt) => match pt.split_first() {
                    Some((&KIND_DATA, rest)) => return Some(Frame::Data(rest.to_vec())),
                    Some((&KIND_KEEPALIVE, _)) => return Some(Frame::Keepalive),
                    Some((&KIND_NAME, rest)) => {
                        if rest.len() > MAX_NAME_LEN {
                            continue; // oversized label: drop, keep going
                        }
                        match String::from_utf8(rest.to_vec()) {
                            Ok(name) => return Some(Frame::Name(name)),
                            Err(_) => continue, // non-utf8 label: drop, keep going
                        }
                    }
                    _ => continue, // empty or unknown kind: drop, keep going
                },
                Err(_) => continue, // drop undecryptable datagrams, keep going
            }
        }
    }
}
