//! HTTP proxy front end, for clients that speak an HTTP proxy rather than SOCKS.
//! Handles both `CONNECT host:port` (HTTPS and other TLS tunnels) and absolute-form
//! plain-HTTP requests (`GET http://host/path HTTP/1.1`), which is how browsers and
//! `http_proxy`-aware tools issue `http://` URLs. `Proxy-Authorization: Basic`
//! carries the same credentials as SOCKS: the password gates access and the
//! username picks the egress session.
//!
//! Plain-HTTP requests are rewritten to origin-form and relayed byte-for-byte, so
//! the body-framing headers (`Content-Length`, `Transfer-Encoding`) are forwarded
//! unchanged and the origin frames the body; the connection-management hop-by-hop
//! headers are stripped, `Host` is taken from the request target, and the upstream
//! request is sent with `Connection: close` so the response is delimited by EOF.

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
    let req = match Request::parse(&head) {
        Ok(r) => r,
        Err(e) => {
            sock.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await?;
            return Err(e);
        }
    };

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
    let target = match resolve_v4(&host, port).await {
        Ok(t) => t,
        Err(e) => {
            sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            return Err(e);
        }
    };
    let conn = match proxy::connect(handles, idx, target).await {
        Ok(conn) => conn,
        Err(e) => {
            sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            return Err(e);
        }
    };

    match req.kind {
        // CONNECT: acknowledge, then tunnel the raw client stream both ways.
        Kind::Connect => {
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
        }
        // Plain HTTP: send the rewritten request head upstream first; the client's
        // body (if any) and the origin's response then flow through the splice.
        Kind::Forward(upstream_head) => {
            conn.send(upstream_head).await?;
        }
    }
    let (rd, wr) = sock.into_split();
    conn.splice(rd, wr).await;
    Ok(())
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

/// What the client asked the proxy to do.
enum Kind {
    /// `CONNECT host:port`: tunnel the raw stream both ways.
    Connect,
    /// Plain-HTTP forward request; carries the request head rewritten to origin-form
    /// (hop-by-hop headers stripped, `Host` set, `Connection: close`) ready to send
    /// to the origin ahead of the spliced body.
    Forward(Vec<u8>),
}

struct Request {
    target: (String, u16),
    auth: Option<(Vec<u8>, Vec<u8>)>,
    kind: Kind,
}

/// Header field-names always dropped before forwarding a plain-HTTP request: the
/// connection-management hop-by-hop set (RFC 7230 §6.1), plus `Host` (replaced from
/// the request target). `Content-Length` and `Transfer-Encoding` are deliberately
/// kept so the origin frames the body that is relayed unchanged.
const STRIP_HEADERS: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "host",
];

impl Request {
    fn parse(head: &[u8]) -> Result<Request> {
        let text = std::str::from_utf8(head).context("non-utf8 request head")?;
        let mut lines = text.split("\r\n");
        let request_line = lines.next().context("empty request")?;
        let headers: Vec<&str> = lines.take_while(|l| !l.is_empty()).collect();

        // Reject obsolete line folding: a continuation could slip a hop-by-hop token
        // past the strip set or be re-emitted as a forged header. No current client
        // generates it (RFC 7230 deprecated it).
        if headers
            .iter()
            .any(|l| l.starts_with(' ') || l.starts_with('\t'))
        {
            bail!("obsolete header line folding is not accepted");
        }

        let auth = headers
            .iter()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("proxy-authorization")
                    .then_some(value.trim())
            })
            .and_then(decode_basic);

        let mut parts = request_line.split_whitespace();
        let method = parts.next().context("empty request line")?;
        let target_uri = parts.next().context("missing request target")?;
        let version = parts.next().unwrap_or("HTTP/1.1");

        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) =
                split_host_port(target_uri, None).context("CONNECT target must be host:port")?;
            return Ok(Request {
                target: (host, port),
                auth,
                kind: Kind::Connect,
            });
        }

        // Plain-HTTP forward: the target must be an absolute-form http:// URI.
        let rest = strip_http_scheme(target_uri)
            .context("only CONNECT or absolute-form http:// requests are supported")?;
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        // Drop any userinfo (`user:pass@`) from the authority for both connect and Host.
        let authority = {
            let a = &rest[..auth_end];
            a.rsplit('@').next().unwrap_or(a)
        };
        let tail = &rest[auth_end..];
        let path = if tail.is_empty() {
            "/".to_string()
        } else if tail.starts_with('/') {
            tail.to_string()
        } else {
            format!("/{tail}")
        };
        let (host, port) = split_host_port(authority, Some(80)).context("bad http:// authority")?;

        // Reject ambiguous or malformed request framing before relaying the body
        // verbatim: conflicting Content-Length and Transfer-Encoding (CL.TE),
        // duplicate Content-Length lines, or a non-numeric length would let a
        // downstream pool frame the body differently than the origin (RFC 9112 6.3).
        let lengths: Vec<&str> = headers
            .iter()
            .filter(|l| header_named(l, "content-length"))
            .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim()))
            .collect();
        let has_te = headers.iter().any(|l| header_named(l, "transfer-encoding"));
        if !lengths.is_empty() && has_te {
            bail!("request carries both Content-Length and Transfer-Encoding");
        }
        if lengths.len() > 1 {
            bail!("request carries multiple Content-Length headers");
        }
        if let Some(v) = lengths.first() {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) || v.parse::<u64>().is_err() {
                bail!("request has a malformed Content-Length");
            }
        }

        // Headers named in the Connection field are themselves hop-by-hop; collect
        // them alongside the fixed strip set.
        let mut conn_named: Vec<String> = Vec::new();
        for l in &headers {
            if header_named(l, "connection") {
                if let Some((_, v)) = l.split_once(':') {
                    for name in v.split(',') {
                        let n = name.trim().to_ascii_lowercase();
                        if !n.is_empty() {
                            conn_named.push(n);
                        }
                    }
                }
            }
        }

        let mut out = format!("{method} {path} {version}\r\nHost: {authority}\r\n");
        for l in &headers {
            let name = match l.split_once(':') {
                Some((n, _)) => n.trim().to_ascii_lowercase(),
                None => continue,
            };
            if STRIP_HEADERS.contains(&name.as_str()) || conn_named.iter().any(|n| n == &name) {
                continue;
            }
            out.push_str(l);
            out.push_str("\r\n");
        }
        out.push_str("Connection: close\r\n\r\n");

        Ok(Request {
            target: (host, port),
            auth,
            kind: Kind::Forward(out.into_bytes()),
        })
    }
}

/// True when `line` is a header whose field-name equals `name` (case-insensitive).
fn header_named(line: &str, name: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))
}

/// Strip a leading `http://` scheme (case-insensitive), returning the remainder.
fn strip_http_scheme(uri: &str) -> Option<&str> {
    uri.get(..7)
        .filter(|p| p.eq_ignore_ascii_case("http://"))
        .map(|_| &uri[7..])
}

/// Split an authority into host and port. `default` supplies the port when none is
/// present (`None` means a port is required, as for CONNECT). IPv6 literals keep
/// their brackets stripped for the host.
fn split_host_port(authority: &str, default: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default?,
            None => return None,
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, p)) => (host.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default?),
        }
    };
    (!host.is_empty()).then_some((host, port))
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
    fn rejects_origin_form_without_absolute_uri() {
        // A bare origin-form request is addressed to the proxy itself, not proxied.
        assert!(Request::parse(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }

    fn forward_head(req: &Request) -> String {
        match &req.kind {
            Kind::Forward(b) => String::from_utf8(b.clone()).unwrap(),
            Kind::Connect => panic!("expected Forward"),
        }
    }

    #[test]
    fn forwards_plain_http_in_origin_form() {
        let raw = "GET http://example.com/pub/index.html?q=1 HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   User-Agent: curl/8\r\n\
                   Proxy-Authorization: Basic eA==\r\n\
                   Proxy-Connection: keep-alive\r\n\r\n";
        let req = Request::parse(raw.as_bytes()).unwrap();
        assert_eq!(req.target, ("example.com".into(), 80));
        let head = forward_head(&req);
        // Request line rewritten to origin-form.
        assert!(head.starts_with("GET /pub/index.html?q=1 HTTP/1.1\r\n"));
        // Host derived from the target, kept once.
        assert!(head.contains("Host: example.com\r\n"));
        // End-to-end header preserved.
        assert!(head.contains("User-Agent: curl/8\r\n"));
        // Hop-by-hop and proxy headers stripped.
        assert!(!head.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!head.to_ascii_lowercase().contains("proxy-connection"));
        // Forced close so the response is EOF-delimited.
        assert!(head.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn forward_extracts_proxy_auth() {
        let creds = base64::engine::general_purpose::STANDARD.encode("proxy_pppoe1:pw");
        let raw = format!(
            "GET http://1.2.3.4:8080/ HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
        );
        let req = Request::parse(raw.as_bytes()).unwrap();
        assert_eq!(req.target, ("1.2.3.4".into(), 8080));
        let (u, p) = req.auth.unwrap();
        assert_eq!(u, b"proxy_pppoe1");
        assert_eq!(p, b"pw");
    }

    #[test]
    fn forward_defaults_path_and_keeps_body_framing() {
        let req =
            Request::parse(b"POST http://h.test HTTP/1.1\r\nContent-Length: 5\r\n\r\n").unwrap();
        let head = forward_head(&req);
        assert!(head.starts_with("POST / HTTP/1.1\r\n"));
        // Content-Length is body framing, forwarded unchanged for the origin to read.
        assert!(head.contains("Content-Length: 5\r\n"));
    }

    #[test]
    fn forward_strips_connection_named_headers() {
        let raw = "GET http://h.test/ HTTP/1.1\r\n\
                   Connection: close, X-Hop\r\n\
                   X-Hop: secret\r\n\
                   X-Keep: ok\r\n\r\n";
        let head = forward_head(&Request::parse(raw.as_bytes()).unwrap());
        assert!(!head.contains("X-Hop"));
        assert!(head.contains("X-Keep: ok\r\n"));
    }

    #[test]
    fn rejects_conflicting_length_framing() {
        let raw = "POST http://h.test/ HTTP/1.1\r\n\
                   Content-Length: 5\r\n\
                   Transfer-Encoding: chunked\r\n\r\n";
        assert!(Request::parse(raw.as_bytes()).is_err());
    }

    #[test]
    fn rejects_duplicate_content_length() {
        let raw = "POST http://h.test/ HTTP/1.1\r\n\
                   Content-Length: 5\r\n\
                   Content-Length: 6\r\n\r\n";
        assert!(Request::parse(raw.as_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_content_length() {
        let raw = "POST http://h.test/ HTTP/1.1\r\nContent-Length: 5 \tx\r\n\r\n";
        assert!(Request::parse(raw.as_bytes()).is_err());
    }

    #[test]
    fn rejects_obs_fold_headers() {
        let raw = "GET http://h.test/ HTTP/1.1\r\nX-A: a\r\n\tcontinued\r\n\r\n";
        assert!(Request::parse(raw.as_bytes()).is_err());
    }

    #[test]
    fn rejects_empty_host_authority() {
        assert!(Request::parse(b"GET http://:80/ HTTP/1.1\r\n\r\n").is_err());
        assert!(Request::parse(b"CONNECT :443 HTTP/1.1\r\n\r\n").is_err());
    }
}
