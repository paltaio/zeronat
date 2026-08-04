//! Source-address admission for the UDP control port.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use blake2::digest::consts::U16;
use blake2::digest::Mac;
use blake2::Blake2sMac;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

use crate::Result;

/// Outer datagram classes for the admission exchange, disjoint from the
/// `kcp::CLASS_*` range.
pub const CLASS_HELLO: u8 = 0x05;
pub const CLASS_CHALLENGE: u8 = 0x06;
pub const CLASS_ADMIT: u8 = 0x07;

const TS_LEN: usize = 8;
const MAC_LEN: usize = 16;
/// Cookie body: big-endian issue timestamp then the MAC.
pub const COOKIE_LEN: usize = TS_LEN + MAC_LEN;
const CHALLENGE_LEN: usize = 1 + COOKIE_LEN;
/// A hello must be at least as large as the challenge it elicits, so the
/// exchange cannot amplify traffic toward a spoofed source.
pub const HELLO_LEN: usize = CHALLENGE_LEN;

/// How long an issued cookie verifies. Long enough for the client's admit to
/// cross one round trip with retries, short enough that a captured cookie is
/// soon useless.
const COOKIE_TTL: Duration = Duration::from_secs(30);

const HELLO_RESEND: Duration = Duration::from_millis(300);
const ADMIT_TIMEOUT: Duration = Duration::from_secs(4);

type CookieMac = Blake2sMac<U16>;

/// Server half: issues and verifies source-bound cookies.
pub struct CookieJar {
    key: [u8; 32],
    epoch: Instant,
}

impl CookieJar {
    pub fn new() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| -> crate::Error { e.to_string().into() })?;
        Ok(CookieJar {
            key,
            epoch: Instant::now(),
        })
    }

    fn mac_for(&self, ts: u64, src: SocketAddr) -> CookieMac {
        let mut m = <CookieMac as blake2::digest::KeyInit>::new((&self.key).into());
        m.update(&ts.to_be_bytes());
        match src.ip() {
            IpAddr::V4(ip) => m.update(&ip.octets()),
            IpAddr::V6(ip) => m.update(&ip.octets()),
        }
        m.update(&src.port().to_be_bytes());
        m
    }

    /// The challenge datagram answering a hello from `src`.
    pub fn challenge(&self, src: SocketAddr) -> Vec<u8> {
        let ts = self.epoch.elapsed().as_millis() as u64;
        let mut pkt = Vec::with_capacity(CHALLENGE_LEN);
        pkt.push(CLASS_CHALLENGE);
        pkt.extend_from_slice(&ts.to_be_bytes());
        pkt.extend_from_slice(&self.mac_for(ts, src).finalize().into_bytes());
        pkt
    }

    /// Verify an admit body (the datagram minus its class byte) against `src`.
    /// Returns the cookie's issue timestamp and its matching monotonic instant;
    /// `None` for any malformed, expired, forged, or wrong-tuple cookie.
    pub fn verify(&self, src: SocketAddr, body: &[u8]) -> Option<(u64, Instant)> {
        if body.len() != COOKIE_LEN {
            return None;
        }
        let (ts_bytes, mac) = body.split_at(TS_LEN);
        let mut ts_array = [0u8; TS_LEN];
        ts_array.copy_from_slice(ts_bytes);
        let ts = u64::from_be_bytes(ts_array);
        let now = self.epoch.elapsed().as_millis() as u64;
        if ts > now || now - ts > COOKIE_TTL.as_millis() as u64 {
            return None;
        }
        self.mac_for(ts, src).verify_slice(mac).ok()?;
        let issued_at = self.epoch.checked_add(Duration::from_millis(ts))?;
        Some((ts, issued_at))
    }
}

/// Client half: prove return routability to `server` on `socket` before any
/// KCP traffic. Sends a padded hello until the challenge arrives, echoes its
/// cookie back, and returns; datagrams from other sources are ignored, so an
/// unconnected socket works. The server sends no admit confirmation: the
/// caller's own handshake timeout catches a lost admit.
pub async fn admit(socket: &UdpSocket, server: SocketAddr) -> Result<()> {
    let mut hello = [0u8; HELLO_LEN];
    hello[0] = CLASS_HELLO;
    timeout(ADMIT_TIMEOUT, async {
        let mut buf = [0u8; 128];
        loop {
            socket.send_to(&hello, server).await?;
            let resend = tokio::time::sleep(HELLO_RESEND);
            tokio::pin!(resend);
            loop {
                tokio::select! {
                    r = socket.recv_from(&mut buf) => {
                        let (n, src) = r?;
                        if src != server || n != CHALLENGE_LEN || buf[0] != CLASS_CHALLENGE {
                            continue;
                        }
                        let mut admit = [0u8; 1 + COOKIE_LEN];
                        admit[0] = CLASS_ADMIT;
                        admit[1..].copy_from_slice(&buf[1..CHALLENGE_LEN]);
                        socket.send_to(&admit, server).await?;
                        return Ok(());
                    }
                    _ = &mut resend => break,
                }
            }
        }
    })
    .await
    .map_err(|_| -> crate::Error { "udp admission timed out".into() })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 7], port))
    }

    #[test]
    fn cookie_verifies_for_its_tuple() {
        let jar = CookieJar::new().unwrap();
        let src = addr(4000);
        let pkt = jar.challenge(src);
        assert_eq!(pkt.len(), CHALLENGE_LEN);
        assert_eq!(pkt[0], CLASS_CHALLENGE);
        assert!(jar.verify(src, &pkt[1..]).is_some());
    }

    #[test]
    fn cookie_rejects_other_tuples() {
        let jar = CookieJar::new().unwrap();
        let pkt = jar.challenge(addr(4000));
        assert!(jar.verify(addr(4001), &pkt[1..]).is_none());
        assert!(jar
            .verify(SocketAddr::from(([192, 0, 2, 8], 4000)), &pkt[1..])
            .is_none());
    }

    #[test]
    fn cookie_rejects_tampering() {
        let jar = CookieJar::new().unwrap();
        let src = addr(4000);
        let pkt = jar.challenge(src);
        assert!(jar.verify(src, &pkt[1..COOKIE_LEN]).is_none());
        assert!(jar.verify(src, &[]).is_none());
        let mut flipped = pkt.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(jar.verify(src, &flipped[1..]).is_none());
        let mut future = pkt;
        future[1..=TS_LEN].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(jar.verify(src, &future[1..]).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn cookie_expires() {
        let jar = CookieJar::new().unwrap();
        let src = addr(4000);
        let pkt = jar.challenge(src);
        tokio::time::advance(COOKIE_TTL - Duration::from_secs(1)).await;
        assert!(jar.verify(src, &pkt[1..]).is_some());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(jar.verify(src, &pkt[1..]).is_none());
    }

    #[test]
    fn cookies_are_keyed_per_jar() {
        let a = CookieJar::new().unwrap();
        let b = CookieJar::new().unwrap();
        let src = addr(4000);
        let pkt = a.challenge(src);
        assert!(b.verify(src, &pkt[1..]).is_none());
    }

    // The client exchange completes against a jar-speaking responder, and the
    // hello it sends cannot amplify: it is at least as large as the challenge.
    #[tokio::test]
    async fn client_admit_roundtrip() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let responder = crate::spawn({
            let server = server.clone();
            async move {
                let jar = CookieJar::new().unwrap();
                let mut buf = [0u8; 128];
                loop {
                    let (n, src) = server.recv_from(&mut buf).await.unwrap();
                    match buf[0] {
                        CLASS_HELLO if n >= HELLO_LEN => {
                            server.send_to(&jar.challenge(src), src).await.unwrap();
                        }
                        CLASS_ADMIT => {
                            assert!(jar.verify(src, &buf[1..n]).is_some());
                            return;
                        }
                        _ => panic!("unexpected class {}", buf[0]),
                    }
                }
            }
        });

        admit(&client, server_addr).await.unwrap();
        timeout(Duration::from_secs(5), responder)
            .await
            .unwrap()
            .unwrap();
    }
}
