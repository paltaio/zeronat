use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use kcp::Kcp;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

pub const CLASS_KCP: u8 = 0x01;
pub const CLASS_SETUP: u8 = 0x02;
pub const CLASS_DGRAM: u8 = 0x03;
pub const KCP_MTU: usize = 1350;

const SOCKET_SEND_CAP: usize = 1024;
const APP_CHAN_CAP: usize = 256;

/// `std::io::Write` sink handed to a `Kcp`. Each `write` is one KCP packet; we
/// prefix the class byte and hand it to the socket-sender channel without
/// blocking (KCP retransmits anything dropped under backpressure).
pub struct ChannelWriter {
    tx: mpsc::Sender<Vec<u8>>,
    class: u8,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut pkt = Vec::with_capacity(buf.len() + 1);
        pkt.push(self.class);
        pkt.extend_from_slice(buf);
        let _ = self.tx.try_send(pkt);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn new_kcp(conv: u32, tx: mpsc::Sender<Vec<u8>>, class: u8) -> Kcp<ChannelWriter> {
    let mut k = Kcp::new(conv, ChannelWriter { tx, class });
    k.set_nodelay(true, 10, 2, true);
    k.set_wndsize(256, 256);
    let _ = k.set_mtu(KCP_MTU);
    k
}

/// Drains the socket-sender channel to the single per-session peer address.
async fn socket_writer(socket: Arc<UdpSocket>, peer: std::net::SocketAddr, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(pkt) = rx.recv().await {
        let _ = socket.send_to(&pkt, peer).await;
    }
}
