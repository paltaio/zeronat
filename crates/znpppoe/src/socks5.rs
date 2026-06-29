//! SOCKS5 (CONNECT) front end. Clients authenticate with the proxy password; the
//! username picks the egress session (see `proxy::Selector`). Domain targets are
//! resolved with the container's resolver, then dialed through the chosen session,
//! so only the TCP egress (not the DNS lookup) carries the PPPoE source address.

use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::netstack::Handle;
use crate::proxy::{self, Selector};

/// Cap the pre-splice handshake so a silent client cannot park a task and fd.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn serve(
    listen: SocketAddr,
    selector: Arc<Selector>,
    handles: Arc<Vec<Handle>>,
    conns: Arc<Semaphore>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind socks5 {listen}"))?;
    eprintln!("znpppoe: socks5 on {listen}");
    loop {
        let (sock, _) = listener.accept().await?;
        // Hold a permit for the connection's lifetime; at the cap, drop the socket.
        let Ok(permit) = conns.clone().try_acquire_owned() else {
            continue;
        };
        let selector = selector.clone();
        let handles = handles.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(sock, &selector, &handles).await {
                eprintln!("znpppoe: socks5 conn: {e}");
            }
        });
    }
}

async fn handle(mut sock: TcpStream, selector: &Selector, handles: &[Handle]) -> Result<()> {
    let (idx, target) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        negotiate_auth(&mut sock).await?;
        let idx = read_userpass(&mut sock, selector).await?;
        let target = read_request(&mut sock).await?;
        Ok::<_, anyhow::Error>((idx, target))
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => bail!("socks5 handshake timed out"),
    };

    match proxy::connect(handles, idx, target).await {
        Ok(conn) => {
            reply(&mut sock, 0x00).await?;
            let (rd, wr) = sock.into_split();
            conn.splice(rd, wr).await;
            Ok(())
        }
        Err(e) => {
            reply(&mut sock, 0x01).await?;
            Err(e)
        }
    }
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

/// Read RFC1929 username/password and resolve the egress session through the
/// selector (password check plus username routing).
async fn read_userpass(sock: &mut TcpStream, selector: &Selector) -> Result<usize> {
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

    let idx = selector.select(&user, &pass);
    sock.write_all(&[0x01, if idx.is_some() { 0x00 } else { 0x01 }])
        .await?;
    idx.context("bad proxy credentials or no live session")
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

/// Resolve a domain to its first IPv4 address.
pub(crate) async fn resolve_v4(host: &str, port: u16) -> Result<SocketAddrV4> {
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
