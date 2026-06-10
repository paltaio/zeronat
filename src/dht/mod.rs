//! Server discovery over the Mainline DHT. The server publishes its reachable
//! address as a signed, encrypted BEP44 mutable item; the client looks it up.
//! Both derive the signing key, salt, and sealing key from the shared secret, so
//! there is no out-of-band key exchange.

mod bencode;
mod bep44;
mod node;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::SigningKey;
use tokio::time::{sleep, Duration};

use crate::Result;
use node::Node;

const REPUBLISH_INTERVAL: Duration = Duration::from_secs(600);
/// Until the first successful publish, retry on this short delay so a server that
/// boots before the network is up gets discovered in seconds, not ~10 minutes.
const COLD_START_BACKOFF: Duration = Duration::from_secs(2);
const COLD_START_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A cached server address older than this is ignored, forcing a fresh DHT
/// resolve so a stale-but-accepting old IP cannot pin the client forever.
const CACHE_TTL: Duration = Duration::from_secs(6 * 3600);
const ADDR_VERSION: u8 = 0x01;

/// Secret-derived DHT identity shared by both peers.
pub struct Identity {
    signing: SigningKey,
    pubkey: [u8; 32],
    salt: Vec<u8>,
    addr_key: [u8; 32],
    target: [u8; 20],
}

impl Identity {
    pub fn derive(secret: &str) -> Self {
        let signing = SigningKey::from_bytes(&blake(b"zeronat-dht-ed25519-v1", secret));
        let pubkey = signing.verifying_key().to_bytes();
        let salt = blake(b"zeronat-dht-salt-v1", secret)[..20].to_vec();
        let addr_key = blake(b"zeronat-dht-addr-key-v1", secret);
        let target = bep44::target(&pubkey, Some(&salt));
        Identity {
            signing,
            pubkey,
            salt,
            addr_key,
            target,
        }
    }
}

fn blake(domain: &[u8], secret: &str) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(domain);
    h.update(secret.as_bytes());
    h.finalize().into()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Strictly increasing BEP44 seq: never below `last + 1`, so a backward wall-clock
/// step can never lower the seq and make a republish un-storable under DHT CAS.
fn next_seq(now: i64, last: i64) -> i64 {
    now.max(last.saturating_add(1))
}

/// Seal `ip:port` into a BEP44 `v` value: `[nonce:8][ciphertext]`, the nonce
/// also serving as the AEAD counter.
fn seal_addr(key: &[u8; 32], ip: Ipv4Addr, port: u16, seq: i64) -> Vec<u8> {
    let mut pt = [0u8; 7];
    pt[0] = ADDR_VERSION;
    pt[1..5].copy_from_slice(&ip.octets());
    pt[5..7].copy_from_slice(&port.to_be_bytes());
    let nonce = seq as u64;
    let ct = ChaCha20Poly1305::new(key.into())
        .encrypt(&aead_nonce(nonce), pt.as_ref())
        .expect("chacha20poly1305 encrypt is infallible for valid sizes");
    let mut out = Vec::with_capacity(8 + ct.len());
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(&ct);
    out
}

fn open_addr(key: &[u8; 32], v: &[u8]) -> Option<(Ipv4Addr, u16)> {
    if v.len() < 8 + 16 {
        return None;
    }
    let nonce = u64::from_be_bytes(v[..8].try_into().ok()?);
    let pt = ChaCha20Poly1305::new(key.into())
        .decrypt(&aead_nonce(nonce), &v[8..])
        .ok()?;
    if pt.len() != 7 || pt[0] != ADDR_VERSION {
        return None;
    }
    let ip = Ipv4Addr::new(pt[1], pt[2], pt[3], pt[4]);
    let port = u16::from_be_bytes([pt[5], pt[6]]);
    Some((ip, port))
}

fn aead_nonce(n: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(nonce)
}

/// Publish the server address once. With `announce_ip` unset, the IP is the one
/// the DHT reports seeing us from (BEP42). Returns the announced IP and the
/// number of nodes that stored the record.
async fn publish(
    id: &Identity,
    announce_ip: Option<Ipv4Addr>,
    port: u16,
) -> Result<(Ipv4Addr, usize)> {
    // Persist the seq before the put so a crash between persist and put still
    // leaves the next boot with a strictly higher seq, never a re-used one.
    let seq = next_seq(now_unix(), read_seq(id));
    write_seq(id, seq);
    let node = Node::new().await?;
    let lookup = node.lookup(id.target).await?;
    let ip = announce_ip
        .or(lookup.external_ip)
        .ok_or("could not determine external IP from the DHT; pass --announce-ip")?;
    let v = seal_addr(&id.addr_key, ip, port, seq);
    let sig = bep44::sign(&id.signing, Some(&id.salt), seq, &v);
    let stored = node
        .put(&id.pubkey, Some(&id.salt), seq, &v, &sig, &lookup.storers)
        .await;
    Ok((ip, stored))
}

/// Resolve the server's current address from the DHT.
pub async fn resolve(id: &Identity) -> Result<SocketAddr> {
    let node = Node::new().await?;
    let mut values = node.lookup(id.target).await?.values;
    values.sort_by_key(|v| std::cmp::Reverse(v.seq));
    for val in values {
        if val.k != id.pubkey {
            continue;
        }
        if !bep44::verify(&val.k, Some(&id.salt), val.seq, &val.v, &val.sig) {
            continue;
        }
        if let Some((ip, port)) = open_addr(&id.addr_key, &val.v) {
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    Err("no valid DHT record found".into())
}

/// Republish the server address forever, refreshing the IP each cycle so a
/// changed WAN address propagates within one interval.
pub async fn announce_loop(secret: &str, announce_ip: Option<Ipv4Addr>, port: u16) {
    let id = Identity::derive(secret);
    // Until the first real publish, retry on a short, growing backoff so a boot
    // that races the network recovers in seconds. After that, settle to the
    // steady interval. A bootstrap/DNS failure returns Err and keeps us in the
    // cold-start path; a put accepted by 0 nodes does not count as success.
    let mut backoff = COLD_START_BACKOFF;
    let mut warm = false;
    loop {
        let delay = match publish(&id, announce_ip, port).await {
            Ok((ip, stored)) => {
                eprintln!("dht: announced {ip}:{port} to {stored} nodes");
                if stored > 0 {
                    warm = true;
                }
                if warm {
                    REPUBLISH_INTERVAL
                } else {
                    backoff
                }
            }
            Err(e) => {
                eprintln!("dht: announce failed: {e}");
                if warm {
                    REPUBLISH_INTERVAL
                } else {
                    backoff
                }
            }
        };
        if !warm {
            backoff = (backoff * 2).min(COLD_START_BACKOFF_MAX);
        }
        sleep(delay).await;
    }
}

pub(super) fn cache_dir() -> Option<PathBuf> {
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    #[cfg(windows)]
    if let Ok(x) = std::env::var("LOCALAPPDATA") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    #[cfg(not(windows))]
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join(".cache"));
        }
    }
    None
}

fn cache_file(id: &Identity) -> Option<PathBuf> {
    let name: String = id.target.iter().map(|b| format!("{b:02x}")).collect();
    Some(cache_dir()?.join("zeronat").join(name))
}

/// Per-identity seq counter, stored alongside the address cache.
fn seq_file(id: &Identity) -> Option<PathBuf> {
    Some(cache_file(id)?.with_extension("seq"))
}

/// Last persisted seq, or 0 if the file is missing or corrupt.
fn read_seq(id: &Identity) -> i64 {
    seq_file(id)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_seq(id: &Identity, seq: i64) {
    let Some(path) = seq_file(id) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, seq.to_string());
}

/// Last-known server address, if cached and fresh. Lets a reconnect skip the DHT.
/// An entry older than `CACHE_TTL` is treated as a miss so a stale-but-accepting
/// old IP cannot keep the client off the DHT forever.
pub fn read_cache(id: &Identity) -> Option<SocketAddr> {
    let path = cache_file(id)?;
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age < CACHE_TTL)
        .unwrap_or(false);
    if !fresh {
        return None;
    }
    let s = std::fs::read_to_string(path).ok()?;
    s.trim().parse().ok()
}

pub fn write_cache(id: &Identity, addr: SocketAddr) {
    let Some(path) = cache_file(id) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, addr.to_string());
}

/// Drop the cached address so the next resolve consults the DHT. Called after a
/// cached address fails to connect, e.g. because the server's IP changed.
pub fn clear_cache(id: &Identity) {
    if let Some(path) = cache_file(id) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_deterministic() {
        let a = Identity::derive("secret");
        let b = Identity::derive("secret");
        let c = Identity::derive("other");
        assert_eq!(a.pubkey, b.pubkey);
        assert_eq!(a.target, b.target);
        assert_eq!(a.salt, b.salt);
        assert_ne!(a.pubkey, c.pubkey);
        assert_ne!(a.target, c.target);
    }

    #[test]
    fn seal_open_roundtrip() {
        let id = Identity::derive("secret");
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let v = seal_addr(&id.addr_key, ip, 2222, 1700000000);
        assert_eq!(open_addr(&id.addr_key, &v), Some((ip, 2222)));
    }

    #[test]
    fn open_rejects_wrong_key() {
        let a = Identity::derive("secret");
        let b = Identity::derive("other");
        let v = seal_addr(&a.addr_key, Ipv4Addr::LOCALHOST, 1, 5);
        assert_eq!(open_addr(&b.addr_key, &v), None);
    }

    #[test]
    fn next_seq_is_strictly_monotonic_under_backward_clock() {
        // Forward clock: seq tracks wall time.
        assert_eq!(next_seq(1000, 0), 1000);
        assert_eq!(next_seq(1001, 1000), 1001);
        // Clock steps backward: seq still advances past the last value.
        assert_eq!(next_seq(500, 1001), 1002);
        assert_eq!(next_seq(0, 1002), 1003);
        // Replay a descending clock from a high last seq; seq only ever climbs.
        let mut last = 1003;
        for now in [900, 800, 0, 42, 1] {
            let s = next_seq(now, last);
            assert!(s > last, "seq {s} must exceed last {last}");
            last = s;
        }
    }

    #[test]
    fn seq_file_roundtrip_defaults_to_zero() {
        let dir = std::env::temp_dir().join(format!("zeronat-seq-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("seq");
        // Missing file reads as 0.
        let read = |p: &std::path::Path| -> i64 {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        };
        let _ = std::fs::remove_file(&path);
        assert_eq!(read(&path), 0);
        std::fs::write(&path, "7").unwrap();
        assert_eq!(read(&path), 7);
        // Corrupt content reads as 0.
        std::fs::write(&path, "not-a-number").unwrap();
        assert_eq!(read(&path), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
