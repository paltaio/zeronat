use std::sync::Arc;

use crate::Result;
use tokio::sync::mpsc;

use crate::kcp::CLASS_DGRAM;
use crate::noise::StatelessNoise;

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

    pub async fn send(&self, plaintext: &[u8]) -> Result<()> {
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

    /// Returns the next decrypted datagram, or `None` when the channel closes.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            let body = self.rx.recv().await?;
            match self.noise.open(&body) {
                Ok(pt) => return Some(pt),
                Err(_) => continue, // drop undecryptable datagrams, keep going
            }
        }
    }
}
