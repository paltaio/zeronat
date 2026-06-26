//! Minimal SOCKS5 (CONNECT) front end. Clients authenticate with the proxy
//! password, and the username `<proxy_user>_pppoe<K>` selects egress session K.
//! These credentials are separate from the PPPoE login.
//!
//! Domain targets are resolved with the container's resolver, then dialed through
//! the chosen session, so only the TCP egress (not the DNS lookup) carries the
//! PPPoE source address.

use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::netstack::{Connect, Handle};

const CHAN_DEPTH: usize = 64;
const CONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(35);
/// Cap the pre-splice handshake so a silent client cannot park a task and fd.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Credentials a SOCKS client must present. The username also carries the egress
/// selector: `<user>_pppoe<K>`.
pub struct Auth {
    pub user: String,
    pub pass: String,
}

pub async fn serve(
    listen: SocketAddr,
    proxy_user: String,
    proxy_pass: String,
    handles: Vec<Handle>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind socks5 {listen}"))?;
    eprintln!(
        "znpppoe: socks5 on {listen}; user '{proxy_user}_pppoe<0..{}>' selects egress",
        handles.len().saturating_sub(1)
    );
    let auth = Arc::new(Auth {
        user: proxy_user,
        pass: proxy_pass,
    });
    let handles = Arc::new(handles);
    loop {
        let (sock, _) = listener.accept().await?;
        let auth = auth.clone();
        let handles = handles.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, &auth, &handles).await {
                eprintln!("znpppoe: socks5 conn: {e}");
            }
        });
    }
}

async fn handle(mut sock: TcpStream, auth: &Auth, handles: &[Handle]) -> Result<()> {
    let (idx, target) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        negotiate_auth(&mut sock).await?;
        let idx = read_userpass(&mut sock, auth, handles.len()).await?;
        let target = read_request(&mut sock).await?;
        Ok::<_, anyhow::Error>((idx, target))
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => bail!("socks5 handshake timed out"),
    };

    let (to_tx, to_rx) = mpsc::channel::<Vec<u8>>(CHAN_DEPTH);
    let (from_tx, mut from_rx) = mpsc::channel::<Vec<u8>>(CHAN_DEPTH);
    let (ready_tx, ready_rx) = oneshot::channel::<bool>();
    let handle = handles[idx].clone();
    handle
        .connect(Connect {
            target,
            to_remote: to_rx,
            from_remote: from_tx,
            ready: ready_tx,
        })
        .await;

    // Backstop the connection wait: even if the stack never replies (cmd dropped),
    // fail fast instead of parking the worker forever.
    let ok = match tokio::time::timeout(CONNECT_WAIT, ready_rx).await {
        Ok(Ok(v)) => v,
        _ => false,
    };
    reply(&mut sock, if ok { 0x00 } else { 0x01 }).await?;
    if !ok {
        bail!("connect to {target} via session {idx} failed");
    }

    let (mut rd, mut wr) = sock.into_split();
    let up = handle.clone();
    let client_to_remote = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                    up.wake();
                }
            }
        }
        // Drop the sender, then nudge so the stack closes the write half promptly.
        drop(to_tx);
        up.wake();
    });
    let down = handle.clone();
    let remote_to_client = tokio::spawn(async move {
        while let Some(chunk) = from_rx.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
            // Nudge the stack so it refills the drained download channel promptly.
            down.wake();
        }
        let _ = wr.shutdown().await;
    });
    let _ = tokio::join!(client_to_remote, remote_to_client);
    Ok(())
}

async fn negotiate_auth(sock: &mut TcpStream) -> Result<()> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("not socks5");
    }
    let mut methods = vec![0u8; head[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0x02) {
        sock.write_all(&[0x05, 0xff]).await?;
        bail!("client offered no username/password auth");
    }
    sock.write_all(&[0x05, 0x02]).await?;
    Ok(())
}

/// Read RFC1929 username/password. The password must equal the configured proxy
/// password, and the username must be `<proxy_user>_pppoe<K>`, which also selects
/// the egress session.
async fn read_userpass(sock: &mut TcpStream, auth: &Auth, count: usize) -> Result<usize> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != 0x01 {
        bail!("bad auth version");
    }
    let mut user = vec![0u8; head[1] as usize];
    sock.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    sock.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; plen[0] as usize];
    sock.read_exact(&mut pass).await?;

    let ok = pass == auth.pass.as_bytes();
    let idx = ok
        .then(|| parse_session(&user, &auth.user, count))
        .flatten();
    sock.write_all(&[0x01, if idx.is_some() { 0x00 } else { 0x01 }])
        .await?;
    idx.context("bad proxy credentials")
}

fn parse_session(user: &[u8], base: &str, count: usize) -> Option<usize> {
    let user = std::str::from_utf8(user).ok()?;
    let suffix = user.strip_prefix(base)?.strip_prefix("_pppoe")?;
    let idx: usize = suffix.parse().ok()?;
    (idx < count).then_some(idx)
}

async fn read_request(sock: &mut TcpStream) -> Result<SocketAddrV4> {
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("bad request version");
    }
    if head[1] != 0x01 {
        bail!("only CONNECT is supported");
    }
    let target = match head[3] {
        0x01 => {
            let mut a = [0u8; 6];
            sock.read_exact(&mut a).await?;
            let port = u16::from_be_bytes([a[4], a[5]]);
            SocketAddrV4::new([a[0], a[1], a[2], a[3]].into(), port)
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            sock.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            sock.read_exact(&mut port).await?;
            let host = String::from_utf8(host).context("domain not utf8")?;
            resolve_v4(&host, u16::from_be_bytes(port)).await?
        }
        0x04 => bail!("IPv6 targets are not supported"),
        other => bail!("unknown address type {other}"),
    };
    Ok(target)
}

async fn resolve_v4(host: &str, port: u16) -> Result<SocketAddrV4> {
    for addr in tokio::net::lookup_host((host, port)).await? {
        if let SocketAddr::V4(v4) = addr {
            return Ok(v4);
        }
    }
    bail!("no IPv4 address for {host}")
}

async fn reply(sock: &mut TcpStream, rep: u8) -> Result<()> {
    sock.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
