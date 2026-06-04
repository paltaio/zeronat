use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::dgram::{DgramRx, DgramTx};
use crate::noise::{NoiseReader, NoiseWriter};

const TCP_BUF: usize = 16 * 1024;
const UDP_BUF: usize = 65535;
pub const UDP_IDLE: Duration = Duration::from_secs(120);

/// Copy bytes both ways between a plaintext TCP stream and the encrypted
/// connection. Returns when either side closes.
pub async fn tcp(plain: TcpStream, mut nr: NoiseReader, mut nw: NoiseWriter) {
    plain.set_nodelay(true).ok();
    let (mut pr, mut pw) = plain.into_split();

    let up = async move {
        let mut buf = [0u8; TCP_BUF];
        loop {
            let n = pr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            nw.send(&buf[..n]).await?;
        }
        anyhow::Ok(())
    };
    let down = async move {
        while let Ok(m) = nr.recv().await {
            pw.write_all(&m).await?;
        }
        anyhow::Ok(())
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

/// Client side of a UDP stream: shuttle datagrams between a local UDP socket
/// (connected to the target service) and the encrypted connection.
pub async fn udp_client(local: UdpSocket, mut nr: NoiseReader, mut nw: NoiseWriter) {
    let mut buf = [0u8; UDP_BUF];
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                m = nr.recv() => {
                    local.send(&m?).await?;
                    anyhow::Ok(true)
                }
                r = local.recv(&mut buf) => {
                    let n = r?;
                    nw.send(&buf[..n]).await?;
                    anyhow::Ok(true)
                }
            }
        })
        .await;
        match step {
            Ok(Ok(true)) => {}
            _ => break,
        }
    }
}

/// Server side of a UDP stream: forward inbound datagrams (from the public
/// socket, delivered via `dgram_rx`) to the client, and client datagrams back
/// out to the original source address.
pub async fn udp_server(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    mut nr: NoiseReader,
    mut nw: NoiseWriter,
) {
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                d = dgram_rx.recv() => match d {
                    Some(d) => { nw.send(&d).await?; anyhow::Ok(true) }
                    None => anyhow::Ok(false),
                },
                m = nr.recv() => {
                    socket.send_to(&m?, src).await?;
                    anyhow::Ok(true)
                }
            }
        })
        .await;
        match step {
            Ok(Ok(true)) => {}
            _ => break,
        }
    }
}

/// Client side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_client_stateless(local: UdpSocket, mut rx: DgramRx, tx: DgramTx) {
    let mut buf = [0u8; UDP_BUF];
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                m = rx.recv() => {
                    let m = m.ok_or_else(|| anyhow::anyhow!("transport closed"))?;
                    local.send(&m).await?;
                    anyhow::Ok(true)
                }
                r = local.recv(&mut buf) => {
                    let n = r?;
                    tx.send(&buf[..n]).await?;
                    anyhow::Ok(true)
                }
            }
        })
        .await;
        match step {
            Ok(Ok(true)) => {}
            _ => break,
        }
    }
}

/// Server side of a UDP-forward stream over the raw datagram channel.
pub async fn udp_server_stateless(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    mut rx: DgramRx,
    tx: DgramTx,
) {
    loop {
        let step = timeout(UDP_IDLE, async {
            tokio::select! {
                d = dgram_rx.recv() => match d {
                    Some(d) => { tx.send(&d).await?; anyhow::Ok(true) }
                    None => anyhow::Ok(false),
                },
                m = rx.recv() => {
                    let m = m.ok_or_else(|| anyhow::anyhow!("transport closed"))?;
                    socket.send_to(&m, src).await?;
                    anyhow::Ok(true)
                }
            }
        })
        .await;
        match step {
            Ok(Ok(true)) => {}
            _ => break,
        }
    }
}
