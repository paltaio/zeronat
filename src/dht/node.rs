//! A throwaway Mainline DHT client: bootstrap, an iterative `get` lookup that
//! also collects write tokens and our externally-seen IP (BEP42), and a `put`.
//! It keeps no routing table across calls; each lookup starts from the routers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, Instant};

use super::bencode::{decode, Ben};
use crate::Result;

const BOOTSTRAP: &[&str] = &[
    "router.bittorrent.com:6881",
    "dht.transmission.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
];
const K: usize = 8;
const ROUNDS: u8 = 6;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const RECV_BUF: usize = 2048;

/// A DHT contact and, once it has answered a `get`, its write token.
#[derive(Clone)]
pub struct Contact {
    id: [u8; 20],
    addr: SocketAddrV4,
    token: Option<Vec<u8>>,
}

/// A mutable item returned by `get`, pending signature verification by the caller.
pub struct Value {
    pub k: [u8; 32],
    pub seq: i64,
    pub v: Vec<u8>,
    pub sig: [u8; 64],
}

/// Result of an iterative lookup: nodes to store at, any values found, and the
/// IP those nodes reported seeing us from.
pub struct Lookup {
    pub storers: Vec<Contact>,
    pub values: Vec<Value>,
    pub external_ip: Option<Ipv4Addr>,
}

struct Parsed {
    from: SocketAddrV4,
    id: Option<[u8; 20]>,
    token: Option<Vec<u8>>,
    nodes: Vec<Contact>,
    ip: Option<Ipv4Addr>,
    value: Option<Value>,
}

pub struct Node {
    sock: UdpSocket,
    id: [u8; 20],
}

impl Node {
    pub async fn new() -> Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let mut id = [0u8; 20];
        getrandom::getrandom(&mut id).map_err(|e| -> crate::Error { e.to_string().into() })?;
        Ok(Node { sock, id })
    }

    /// Iteratively walk toward `target`, collecting write tokens, stored values,
    /// and BEP42 IP votes.
    pub async fn lookup(&self, target: [u8; 20]) -> Result<Lookup> {
        let boot = resolve_bootstrap().await?;
        let mut shortlist: Vec<Contact> = Vec::new();
        let mut seen: HashSet<SocketAddrV4> = HashSet::new();
        let mut queried: HashSet<SocketAddrV4> = HashSet::new();
        let mut storers: Vec<Contact> = Vec::new();
        let mut values: Vec<Value> = Vec::new();
        let mut ip_votes: HashMap<Ipv4Addr, u32> = HashMap::new();

        let mut current: Vec<Contact> = boot
            .into_iter()
            .map(|addr| Contact {
                id: [0u8; 20],
                addr,
                token: None,
            })
            .collect();

        for round in 0..ROUNDS {
            if current.is_empty() {
                break;
            }
            for c in &current {
                queried.insert(c.addr);
            }
            // Routers reliably answer find_node but may not implement BEP44 get;
            // only switch to get once talking to discovered full nodes.
            let method: &[u8] = if round == 0 { b"find_node" } else { b"get" };
            for p in self.round(&current, round, &target, method).await {
                if let Some(ip) = p.ip {
                    *ip_votes.entry(ip).or_default() += 1;
                }
                if let Some(v) = p.value {
                    values.push(v);
                }
                if let (Some(id), Some(token)) = (p.id, p.token) {
                    storers.push(Contact {
                        id,
                        addr: p.from,
                        token: Some(token),
                    });
                }
                for c in p.nodes {
                    if seen.insert(c.addr) {
                        shortlist.push(c);
                    }
                }
            }
            shortlist.sort_by_key(|c| dist(&c.id, &target));
            current = shortlist
                .iter()
                .filter(|c| !queried.contains(&c.addr))
                .take(K)
                .cloned()
                .collect();
        }

        storers.sort_by_key(|c| dist(&c.id, &target));
        let mut kept = HashSet::new();
        storers.retain(|c| kept.insert(c.addr));
        storers.truncate(K);
        let external_ip = ip_votes
            .into_iter()
            .max_by_key(|&(_, n)| n)
            .map(|(ip, _)| ip);
        Ok(Lookup {
            storers,
            values,
            external_ip,
        })
    }

    /// Store a signed mutable item at the nodes that returned write tokens.
    /// Returns how many acknowledged.
    #[allow(clippy::too_many_arguments)]
    pub async fn put(
        &self,
        pubkey: &[u8; 32],
        salt: Option<&[u8]>,
        seq: i64,
        v: &[u8],
        sig: &[u8; 64],
        storers: &[Contact],
    ) -> usize {
        let mut txmap = HashMap::new();
        for (i, c) in storers.iter().enumerate() {
            let Some(token) = &c.token else {
                continue;
            };
            let tx = 0xF000u16 | (i as u16);
            let q = build_put(&self.id, token, pubkey, salt, seq, v, sig, tx);
            let _ = self.sock.send_to(&q, SocketAddr::V4(c.addr)).await;
            txmap.insert(tx, c.addr);
        }
        self.gather(&txmap).await.len()
    }

    async fn round(
        &self,
        contacts: &[Contact],
        round: u8,
        target: &[u8; 20],
        method: &[u8],
    ) -> Vec<Parsed> {
        let mut txmap = HashMap::new();
        for (i, c) in contacts.iter().enumerate().take(256) {
            let tx = ((round as u16) << 8) | (i as u16);
            let q = build_lookup(method, &self.id, target, tx);
            let _ = self.sock.send_to(&q, SocketAddr::V4(c.addr)).await;
            txmap.insert(tx, c.addr);
        }
        self.gather(&txmap).await
    }

    async fn gather(&self, txmap: &HashMap<u16, SocketAddrV4>) -> Vec<Parsed> {
        let mut out = Vec::new();
        let deadline = Instant::now() + QUERY_TIMEOUT;
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                break;
            }
            match timeout(rem, self.sock.recv_from(&mut buf)).await {
                Ok(Ok((n, SocketAddr::V4(from)))) => {
                    if let Some(p) = parse_response(&buf[..n], txmap, from) {
                        out.push(p);
                    }
                }
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
        out
    }
}

async fn resolve_bootstrap() -> Result<Vec<SocketAddrV4>> {
    let mut out = Vec::new();
    for host in BOOTSTRAP {
        if let Ok(addrs) = tokio::net::lookup_host(host).await {
            for a in addrs {
                if let SocketAddr::V4(v4) = a {
                    out.push(v4);
                }
            }
        }
    }
    if out.is_empty() {
        return Err("dht bootstrap resolution failed".into());
    }
    Ok(out)
}

fn dist(a: &[u8; 20], target: &[u8; 20]) -> [u8; 20] {
    let mut d = [0u8; 20];
    for i in 0..20 {
        d[i] = a[i] ^ target[i];
    }
    d
}

fn build_lookup(method: &[u8], id: &[u8; 20], target: &[u8; 20], tx: u16) -> Vec<u8> {
    let mut a = BTreeMap::new();
    a.insert(b"id".to_vec(), Ben::Bytes(id.to_vec()));
    a.insert(b"target".to_vec(), Ben::Bytes(target.to_vec()));
    krpc_query(method, a, tx)
}

#[allow(clippy::too_many_arguments)]
fn build_put(
    id: &[u8; 20],
    token: &[u8],
    pubkey: &[u8; 32],
    salt: Option<&[u8]>,
    seq: i64,
    v: &[u8],
    sig: &[u8; 64],
    tx: u16,
) -> Vec<u8> {
    let mut a = BTreeMap::new();
    a.insert(b"id".to_vec(), Ben::Bytes(id.to_vec()));
    a.insert(b"k".to_vec(), Ben::Bytes(pubkey.to_vec()));
    if let Some(s) = salt {
        a.insert(b"salt".to_vec(), Ben::Bytes(s.to_vec()));
    }
    a.insert(b"seq".to_vec(), Ben::Int(seq));
    a.insert(b"sig".to_vec(), Ben::Bytes(sig.to_vec()));
    a.insert(b"token".to_vec(), Ben::Bytes(token.to_vec()));
    a.insert(b"v".to_vec(), Ben::Bytes(v.to_vec()));
    krpc_query(b"put", a, tx)
}

fn krpc_query(method: &[u8], args: BTreeMap<Vec<u8>, Ben>, tx: u16) -> Vec<u8> {
    let mut d = BTreeMap::new();
    d.insert(b"a".to_vec(), Ben::Dict(args));
    d.insert(b"q".to_vec(), Ben::Bytes(method.to_vec()));
    d.insert(b"t".to_vec(), Ben::Bytes(tx.to_be_bytes().to_vec()));
    d.insert(b"y".to_vec(), Ben::Bytes(b"q".to_vec()));
    Ben::Dict(d).encode()
}

fn parse_response(
    buf: &[u8],
    txmap: &HashMap<u16, SocketAddrV4>,
    from: SocketAddrV4,
) -> Option<Parsed> {
    let msg = decode(buf)?;
    if msg.get(b"y")?.bytes()? != b"r" {
        return None;
    }
    let t = msg.get(b"t")?.bytes()?;
    if t.len() != 2 {
        return None;
    }
    let tx = u16::from_be_bytes([t[0], t[1]]);
    if txmap.get(&tx) != Some(&from) {
        return None;
    }
    let r = msg.get(b"r")?;
    Some(Parsed {
        from,
        id: r.get(b"id").and_then(|b| b.bytes()).and_then(to_array),
        token: r.get(b"token").and_then(|b| b.bytes()).map(<[u8]>::to_vec),
        nodes: r
            .get(b"nodes")
            .and_then(|b| b.bytes())
            .map(parse_nodes)
            .unwrap_or_default(),
        ip: msg.get(b"ip").and_then(|b| b.bytes()).and_then(parse_ipv4),
        value: parse_value(r),
    })
}

fn parse_value(r: &Ben) -> Option<Value> {
    let k = to_array(r.get(b"k")?.bytes()?)?;
    let sig = to_array(r.get(b"sig")?.bytes()?)?;
    let seq = r.get(b"seq")?.int()?;
    let v = r.get(b"v")?.bytes()?.to_vec();
    Some(Value { k, seq, v, sig })
}

fn parse_nodes(b: &[u8]) -> Vec<Contact> {
    b.chunks_exact(26)
        .filter_map(|c| {
            let id = to_array::<20>(&c[..20])?;
            let addr = parse_sockv4(&c[20..26])?;
            Some(Contact {
                id,
                addr,
                token: None,
            })
        })
        .collect()
}

fn parse_sockv4(b: &[u8]) -> Option<SocketAddrV4> {
    if b.len() != 6 {
        return None;
    }
    let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let port = u16::from_be_bytes([b[4], b[5]]);
    Some(SocketAddrV4::new(ip, port))
}

fn parse_ipv4(b: &[u8]) -> Option<Ipv4Addr> {
    parse_sockv4(b).map(|s| *s.ip())
}

fn to_array<const N: usize>(b: &[u8]) -> Option<[u8; N]> {
    b.try_into().ok()
}
