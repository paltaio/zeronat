use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};

use crate::bridge;
use crate::noise::client_handshake;
use crate::proto::{Msg, Proto};

const PING_INTERVAL: Duration = Duration::from_secs(25);
const RETRY_DELAY: Duration = Duration::from_secs(3);

struct Client {
    server: String,
    psk: [u8; 32],
    tcp: HashMap<u16, String>,
    udp: HashMap<u16, String>,
}

pub async fn run(
    server: String,
    secret: String,
    tcp: Vec<(u16, String)>,
    udp: Vec<(u16, String)>,
) -> Result<()> {
    let client = Arc::new(Client {
        server,
        psk: crate::noise::derive_psk(&secret),
        tcp: tcp.into_iter().collect(),
        udp: udp.into_iter().collect(),
    });

    loop {
        if let Err(e) = session(client.clone()).await {
            eprintln!("control connection lost: {e}");
        }
        sleep(RETRY_DELAY).await;
    }
}

/// Establish the control connection and dispatch `Open` requests until it drops.
async fn session(client: Arc<Client>) -> Result<()> {
    let sock = TcpStream::connect(&client.server)
        .await
        .with_context(|| format!("connecting to {}", client.server))?;
    sock.set_nodelay(true).ok();
    let (mut r, w) = client_handshake(sock, &client.psk).await?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    tx.try_send(Msg::Hello.encode()).ok();

    let mut w = w;
    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if w.send(&bytes).await.is_err() {
                break;
            }
        }
    });

    let ping_tx = tx.clone();
    let pinger = tokio::spawn(async move {
        let mut tick = interval(PING_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            if ping_tx.try_send(Msg::Ping.encode()).is_err() {
                break;
            }
        }
    });

    eprintln!("connected to {}", client.server);
    let result = loop {
        let msg = match r.recv().await {
            Ok(m) => m,
            Err(e) => break Err(e),
        };
        match Msg::decode(&msg) {
            Ok(Msg::Open { proto, port, id }) => {
                let client = client.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_open(client, proto, port, id).await {
                        eprintln!("stream {id} ({proto:?} :{port}) failed: {e}");
                    }
                });
            }
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };

    writer.abort();
    pinger.abort();
    result
}

/// Open a data connection back to the server and bridge it to the local target.
async fn handle_open(client: Arc<Client>, proto: Proto, port: u16, id: u64) -> Result<()> {
    let target = match proto {
        Proto::Tcp => client.tcp.get(&port),
        Proto::Udp => client.udp.get(&port),
    }
    .with_context(|| format!("no local target configured for {proto:?} :{port}"))?
    .clone();

    let sock = TcpStream::connect(&client.server).await?;
    sock.set_nodelay(true).ok();
    let (nr, mut nw) = client_handshake(sock, &client.psk).await?;
    nw.send(&Msg::Data { id }.encode()).await?;

    match proto {
        Proto::Tcp => {
            let local = TcpStream::connect(&target)
                .await
                .with_context(|| format!("connecting to local {target}"))?;
            bridge::tcp(local, nr, nw).await;
        }
        Proto::Udp => {
            let local = UdpSocket::bind("0.0.0.0:0").await?;
            local
                .connect(&target)
                .await
                .with_context(|| format!("connecting to local {target}"))?;
            bridge::udp_client(local, nr, nw).await;
        }
    }
    Ok(())
}
