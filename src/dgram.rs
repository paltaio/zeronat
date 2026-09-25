use std::sync::Arc;

use crate::Result;
use tokio::sync::mpsc;

use crate::kcp::{Inbound, Outbound, CLASS_DGRAM};
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
/// refreshes the receiver's idle window, or a bridge client label sent once.
pub enum Frame<'a> {
    Data(&'a [u8]),
    Keepalive,
    Name(String),
}

/// Buffers parked on a sender's return lane; the socket writer frees anything
/// past this bound instead.
const LANE_CAP: usize = 256;

/// Sends UDP-forward datagrams over the shared socket as `0x03` frames. Each
/// packet, `[class][tag:4][nonce:8][kind][payload][tag]`, is built and sealed
/// in place in a buffer the socket writer hands back on `lane` once it is
/// sent, so a steady flow cycles a few buffers instead of allocating one per
/// packet.
pub struct DgramTx {
    send_tx: mpsc::Sender<Outbound>,
    tag: u32,
    noise: Arc<StatelessNoise>,
    lane_tx: mpsc::Sender<Vec<u8>>,
    lane: mpsc::Receiver<Vec<u8>>,
}

impl DgramTx {
    pub fn new(send_tx: mpsc::Sender<Outbound>, tag: u32, noise: Arc<StatelessNoise>) -> Self {
        let (lane_tx, lane) = mpsc::channel(LANE_CAP);
        DgramTx {
            send_tx,
            tag,
            noise,
            lane_tx,
            lane,
        }
    }

    pub async fn send(&mut self, datagram: &[u8]) -> Result<()> {
        self.frame(KIND_DATA, datagram)
    }

    /// Emit a liveness keepalive: distinct from any inner datagram, ignored by
    /// the receiver beyond refreshing its idle window.
    pub async fn probe(&mut self) -> Result<()> {
        self.frame(KIND_KEEPALIVE, &[])
    }

    /// Announce this bridge client's label. Best-effort and sent once; a server
    /// that does not understand the kind drops it.
    pub async fn send_name(&mut self, name: &str) -> Result<()> {
        self.frame(KIND_NAME, name.as_bytes())
    }

    /// Queue one sealed packet without waiting. A full socket queue drops the
    /// datagram and keeps its buffer; a closed one is an error.
    fn frame(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        let mut pkt = self.lane.try_recv().unwrap_or_default();
        pkt.clear();
        pkt.push(CLASS_DGRAM);
        pkt.extend_from_slice(&self.tag.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 8]);
        pkt.push(kind);
        pkt.extend_from_slice(payload);
        self.noise.seal_at(&mut pkt, 5)?;
        let back = Some(self.lane_tx.clone());
        match self.send_tx.try_send(Outbound { pkt, back }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(dropped)) => {
                let _ = self.lane_tx.try_send(dropped.pkt);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err("transport closed".into()),
        }
    }
}

/// Receives `[nonce:8][ct]` bodies (tag already stripped by the router) and
/// decrypts them in place. `body` is the datagram last received; a `Frame`
/// borrows from it, and the buffer goes back to the router with the next
/// receive.
pub struct DgramRx {
    inbound: Inbound,
    noise: Arc<StatelessNoise>,
    body: Vec<u8>,
}

impl DgramRx {
    pub fn new(inbound: Inbound, noise: Arc<StatelessNoise>) -> Self {
        DgramRx {
            inbound,
            noise,
            body: Vec::new(),
        }
    }

    /// Returns the next decrypted frame, or `None` when the channel closes.
    pub async fn recv(&mut self) -> Option<Frame<'_>> {
        let n = loop {
            let n = self.next().await?;
            // Drop unknown kinds and bad labels; keep going.
            let rest = &self.body[9..8 + n];
            match self.body[8] {
                KIND_DATA => break n,
                KIND_KEEPALIVE => return Some(Frame::Keepalive),
                KIND_NAME if rest.len() <= MAX_NAME_LEN => {
                    if let Ok(name) = String::from_utf8(rest.to_vec()) {
                        return Some(Frame::Name(name));
                    }
                }
                _ => {}
            }
        };
        Some(Frame::Data(&self.body[9..8 + n]))
    }

    /// The next inner datagram with a body; keepalives, labels and empty
    /// datagrams are skipped. `None` when the channel closes.
    pub async fn recv_data(&mut self) -> Option<&[u8]> {
        let n = loop {
            let n = self.next().await?;
            if self.body[8] == KIND_DATA && n > 1 {
                break n;
            }
        };
        Some(&self.body[9..8 + n])
    }

    /// Receive the next datagram into `body` and decrypt it in place: the
    /// plaintext is `body[8..8 + n]` for the returned `n`. Undecryptable and
    /// empty datagrams are dropped; `None` when the channel closes.
    async fn next(&mut self) -> Option<usize> {
        loop {
            let next = self.inbound.recv().await?;
            self.inbound
                .reclaim(std::mem::replace(&mut self.body, next));
            match self.noise.open_in_place(&mut self.body).map(<[u8]>::len) {
                Ok(0) | Err(_) => continue,
                Ok(n) => return Some(n),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{client_handshake_stateless, derive_psk, server_handshake_stateless};

    async fn stateless_pair() -> (Arc<StatelessNoise>, Arc<StatelessNoise>) {
        let psk = derive_psk("datagram replay fixture");
        let (a, b) = tokio::io::duplex(8192);
        let responder =
            crate::spawn(async move { server_handshake_stateless(b, &psk, &[]).await.unwrap() });
        let initiator = Arc::new(client_handshake_stateless(a, &psk, 7).await.unwrap());
        let (_, responder) = responder.await.unwrap();
        (initiator, Arc::new(responder))
    }

    #[tokio::test]
    async fn receiver_drops_replayed_frames_and_continues() {
        let (initiator, responder) = stateless_pair().await;
        let (wire_tx, mut wire_rx) = mpsc::channel(4);
        let mut sender = DgramTx::new(wire_tx, 9, initiator);
        sender.send(b"first").await.unwrap();
        sender.send(b"second").await.unwrap();
        let first = wire_rx.recv().await.unwrap().pkt;
        let second = wire_rx.recv().await.unwrap().pkt;

        let (inbound_tx, inbound_rx) = mpsc::channel(4);
        inbound_tx.send(first[5..].to_vec()).await.unwrap();
        inbound_tx.send(first[5..].to_vec()).await.unwrap();
        inbound_tx.send(second[5..].to_vec()).await.unwrap();
        let mut receiver = DgramRx::new(Inbound::from(inbound_rx), responder);

        assert!(matches!(receiver.recv().await, Some(Frame::Data(data)) if data == b"first"));
        assert!(matches!(receiver.recv().await, Some(Frame::Data(data)) if data == b"second"));
    }

    // The packet a sender puts on the wire is the class byte, the big-endian
    // tag, then the body `seal` produces for `[kind][payload]`, for every kind
    // and across payload sizes; the receiver classifies each one.
    #[tokio::test]
    async fn sender_packets_match_the_sealed_layout() {
        let (initiator, responder) = stateless_pair().await;
        let (wire_tx, mut wire_rx) = mpsc::channel(64);
        let mut sender = DgramTx::new(wire_tx, 0x0102_0304, initiator);
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        let mut receiver = DgramRx::new(Inbound::from(inbound_rx), responder);
        for len in [0usize, 1, 15, 16, 17, 100, 1200, 1400] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            sender.send(&payload).await.unwrap();
            sender.probe().await.unwrap();
            sender.send_name("port label").await.unwrap();
            for (kind, body) in [
                (KIND_DATA, &payload[..]),
                (KIND_KEEPALIVE, &[][..]),
                (KIND_NAME, b"port label"),
            ] {
                let pkt = wire_rx.recv().await.unwrap().pkt;
                assert_eq!(pkt[0], CLASS_DGRAM);
                assert_eq!(pkt[1..5], [1, 2, 3, 4]);
                let mut plaintext = vec![kind];
                plaintext.extend_from_slice(body);
                assert_eq!(pkt.len(), 5 + 8 + plaintext.len() + 16);
                inbound_tx.send(pkt[5..].to_vec()).await.unwrap();
            }
            assert!(matches!(receiver.recv().await, Some(Frame::Data(d)) if d == payload));
            assert!(matches!(receiver.recv().await, Some(Frame::Keepalive)));
            assert!(matches!(receiver.recv().await, Some(Frame::Name(n)) if n == "port label"));
        }
    }

    // The sender never waits on the socket queue: a full queue drops the
    // datagram and reports success, a closed one fails. A buffer the writer
    // hands back carries the next packet.
    #[tokio::test]
    async fn full_queue_drops_and_closed_queue_fails() {
        let (initiator, _) = stateless_pair().await;
        let (wire_tx, mut wire_rx) = mpsc::channel(2);
        let mut sender = DgramTx::new(wire_tx, 9, initiator);

        sender.send(b"a").await.unwrap();
        let Outbound { pkt, back } = wire_rx.try_recv().unwrap();
        let ptr = pkt.as_ptr();
        back.unwrap().try_send(pkt).unwrap();
        sender.send(b"b").await.unwrap();
        assert_eq!(wire_rx.try_recv().unwrap().pkt.as_ptr(), ptr);

        sender.send(b"c").await.unwrap();
        sender.send(b"d").await.unwrap();
        sender.send(b"e").await.unwrap();
        assert!(wire_rx.try_recv().is_ok());
        assert!(wire_rx.try_recv().is_ok());
        assert!(wire_rx.try_recv().is_err());

        drop(wire_rx);
        let err = sender.send(b"f").await.unwrap_err();
        assert_eq!(err.to_string(), "transport closed");
    }
}
