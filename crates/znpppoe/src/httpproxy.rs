//! HTTP CONNECT proxy front end, for clients that speak an HTTP proxy rather than
//! SOCKS. `Proxy-Authorization: Basic` carries the same credentials as SOCKS: the
//! password gates access and the username picks the egress session.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::netstack::Handle;
use crate::proxy::{self, Selector};
use crate::socks5::resolve_v4;

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_HEAD: usize = 8 * 1024;

pub async fn serve(
    listen: SocketAddr,
    selector: Arc<Selector>,
    handles: Arc<Vec<Handle>>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind http proxy {listen}"))?;
    eprintln!("znpppoe: http connect proxy on {listen}");
    loop {
        let (sock, _) = listener.accept().await?;
        let selector = selector.clone();
        let handles = handles.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, &selector, &handles).await {
                eprintln!("znpppoe: http proxy conn: {e}");
            }
        });
    }
}

async fn handle(mut sock: TcpStream, selector: &Selector, handles: &[Handle]) -> Result<()> {
    let head = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_head(&mut sock)).await {
        Ok(r) => r?,
        Err(_) => bail!("http proxy handshake timed out"),
    };
    let req = Request::parse(&head)?;

    let idx = match req.auth.and_then(|(u, p)| selector.select(&u, &p)) {
        Some(i) => i,
        None => {
            sock.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic\r\nConnection: close\r\n\r\n",
            )
            .await?;
            bail!("http proxy auth rejected");
        }
    };

    let (host, port) = req.target;
    let target = resolve_v4(&host, port).await?;
    match proxy::connect(handles, idx, target).await {
        Ok(conn) => {
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            let (rd, wr) = sock.into_split();
            conn.splice(rd, wr).await;
            Ok(())
        }
        Err(e) => {
            sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            Err(e)
        }
    }
}

/// Read the request head one byte at a time so tunnel bytes that follow the blank
/// line stay in the socket for the splice to pick up.
async fn read_head(sock: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if buf.len() >= MAX_HEAD {
            bail!("http request head too large");
        }
        sock.read_exact(&mut b).await?;
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

struct Request {
    target: (String, u16),
    auth: Option<(Vec<u8>, Vec<u8>)>,
}

impl Request {
    fn parse(head: &[u8]) -> Result<Request> {
        let text = std::str::from_utf8(head).context("non-utf8 request head")?;
        let mut lines = text.split("\r\n");
        let request_line = lines.next().context("empty request")?;
        let mut parts = request_line.split_whitespace();
        if parts.next() != Some("CONNECT") {
            bail!("only CONNECT is supported");
        }
        let authority = parts.next().context("missing CONNECT target")?;
        let (host, port) = authority
            .rsplit_once(':')
            .context("target must be host:port")?;
        let port: u16 = port.parse().context("bad target port")?;

        let auth = lines
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("proxy-authorization")
                    .then_some(value.trim())
            })
            .and_then(decode_basic);

        Ok(Request {
            target: (host.to_string(), port),
            auth,
        })
    }
}

/// Decode a `Basic <base64(user:pass)>` header value into its user and password.
fn decode_basic(value: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let b64 = value.strip_prefix("Basic ").or_else(|| {
        value
            .get(..6)?
            .eq_ignore_ascii_case("basic ")
            .then(|| &value[6..])
    })?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let sep = raw.iter().position(|&b| b == b':')?;
    Some((raw[..sep].to_vec(), raw[sep + 1..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_with_basic_auth() {
        let creds = base64::engine::general_purpose::STANDARD.encode("proxy_s7:pw");
        let head = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
             Proxy-Authorization: Basic {creds}\r\n\r\n"
        );
        let req = Request::parse(head.as_bytes()).unwrap();
        assert_eq!(req.target, ("example.com".into(), 443));
        let (u, p) = req.auth.unwrap();
        assert_eq!(u, b"proxy_s7");
        assert_eq!(p, b"pw");
    }

    #[test]
    fn connect_without_auth_has_none() {
        let head = "CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n";
        let req = Request::parse(head.as_bytes()).unwrap();
        assert_eq!(req.target, ("1.2.3.4".into(), 443));
        assert!(req.auth.is_none());
    }

    #[test]
    fn rejects_non_connect() {
        assert!(Request::parse(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }
}
