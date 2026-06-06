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
    seq: i64,
) -> Result<(Ipv4Addr, usize)> {
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
    loop {
        let seq = now_unix();
        match publish(&id, announce_ip, port, seq).await {
            Ok((ip, stored)) => eprintln!("dht: announced {ip}:{port} to {stored} nodes"),
            Err(e) => eprintln!("dht: announce failed: {e}"),
        }
        sleep(REPUBLISH_INTERVAL).await;
    }
}

fn cache_file(id: &Identity) -> Option<PathBuf> {
    let dir = match std::env::var("XDG_CACHE_HOME") {
        Ok(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var("HOME").ok()?).join(".cache"),
    };
    let name: String = id.target.iter().map(|b| format!("{b:02x}")).collect();
    Some(dir.join("zeronat").join(name))
}

/// Last-known server address, if cached. Lets a reconnect skip the DHT.
pub fn read_cache(id: &Identity) -> Option<SocketAddr> {
    let s = std::fs::read_to_string(cache_file(id)?).ok()?;
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
}
