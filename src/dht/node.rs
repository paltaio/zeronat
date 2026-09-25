//! A throwaway Mainline DHT client: bootstrap, an iterative `get` lookup that
//! also collects write tokens and our externally-seen IP (BEP42), and a `put`.
//! It keeps no in-memory routing table; each lookup warm-starts from a persisted
//! set of recently live nodes and always also seeds the bootstrap routers, with the
//! persisted cache letting the walk proceed when router DNS resolution fails.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, Instant};

use super::bencode::{decode, insert, Ben, Dict};
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
/// Cap on persisted live DHT node addresses (6 bytes each on disk).
const MAX_PERSISTED_NODES: usize = 64;
/// Persisted nodes older than this are ignored, falling back to the routers.
const NODE_CACHE_TTL: StdDuration = StdDuration::from_secs(24 * 3600);

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
        // Seed from previously live nodes and always fold in the bootstrap routers.
        // The routers are the dependable source of BEP42 external-IP votes (which the
        // server's announce needs to learn its own address) and of fresh, reachable
        // nodes to converge on. After a WAN-IP change or a network blip the cached
        // nodes can all be stale, and a cache-only lookup then fails to determine the
        // external IP or to reach the record's storers; the routers recover both.
        // Router DNS failure is tolerated as long as the cache still seeds the walk.
        let mut seed = read_node_cache();
        if let Ok(boot) = resolve_bootstrap().await {
            seed.extend(boot);
        }
        let mut deduped = Vec::new();
        seed.retain(|a| note(&mut deduped, *a));
        if seed.is_empty() {
            return Err("dht bootstrap resolution failed".into());
        }
        let (lookup, live) = self.walk(&target, seed).await;
        write_node_cache(&live);
        Ok(lookup)
    }

    /// The iterative walk from `seed`, then a final `get` over the K closest
    /// contacts still lacking a write token. Returns the lookup result and the
    /// live node addresses to persist for the next warm start.
    async fn walk(
        &self,
        target: &[u8; 20],
        seed: Vec<SocketAddrV4>,
    ) -> (Lookup, Vec<SocketAddrV4>) {
        let mut walk = Walk::default();
        let mut current: Vec<Contact> = seed
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
            // Routers reliably answer find_node but may not implement BEP44 get;
            // only switch to get once talking to discovered full nodes.
            let method: &[u8] = if round == 0 { b"find_node" } else { b"get" };
            let answers = self.round(&current, round, target, method).await;
            current = walk.absorb(&current, answers, target);
        }

        // Round 0 marks the seeds queried after only a find_node, so on a warm
        // cache every closest contact can finish the walk token-less, leaving
        // put() nowhere to store and stored values uncollected. Ask once more
        // with get, over the K closest contacts still worth trying: responders
        // that hold no token yet, plus discovered nodes never queried at all.
        // A walk that already gathered K token holders converged and skips it.
        if walk.storers.len() < K {
            let finalists = walk.finalists(target);
            if !finalists.is_empty() {
                for p in self.round(&finalists, ROUNDS, target, b"get").await {
                    walk.record(p, false);
                }
            }
        }
        walk.finish(target)
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
        let mut txmap = Vec::new();
        for (i, c) in storers.iter().enumerate() {
            let Some(token) = &c.token else {
                continue;
            };
            let tx = 0xF000u16 | (i as u16);
            let q = build_put(&self.id, token, pubkey, salt, seq, v, sig, tx);
            let _ = self.sock.send_to(&q, SocketAddr::V4(c.addr)).await;
            txmap.push((tx, c.addr));
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
        let mut txmap = Vec::new();
        for (i, c) in contacts.iter().enumerate().take(256) {
            let tx = ((round as u16) << 8) | (i as u16);
            let q = build_lookup(method, &self.id, target, tx);
            let _ = self.sock.send_to(&q, SocketAddr::V4(c.addr)).await;
            txmap.push((tx, c.addr));
        }
        self.gather(&txmap).await
    }

    /// Collect the responses to the queries in `txmap`, transaction id to the
    /// address it was sent to, until the query timeout passes.
    async fn gather(&self, txmap: &[(u16, SocketAddrV4)]) -> Vec<Parsed> {
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

/// Shared, target-independent cache of live DHT routing nodes (6 bytes each).
fn node_cache_file() -> Option<PathBuf> {
    Some(super::cache_dir()?.join("zeronat").join("dht-nodes"))
}

/// Read fresh cached node addresses; a missing, stale, or corrupt file is empty.
fn read_node_cache() -> Vec<SocketAddrV4> {
    let Some(path) = node_cache_file() else {
        return Vec::new();
    };
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age < NODE_CACHE_TTL)
        .unwrap_or(false);
    if !fresh {
        return Vec::new();
    }
    match std::fs::read(&path) {
        Ok(bytes) => decode_nodes(&bytes),
        Err(_) => Vec::new(),
    }
}

fn write_node_cache(nodes: &[SocketAddrV4]) {
    let Some(path) = node_cache_file() else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, encode_nodes(nodes));
}

/// Pack addresses as 6 bytes each: 4-byte IPv4 + 2-byte big-endian port.
fn encode_nodes(nodes: &[SocketAddrV4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 6);
    for a in nodes {
        out.extend_from_slice(&a.ip().octets());
        out.extend_from_slice(&a.port().to_be_bytes());
    }
    out
}

/// Parse the 6-byte node format; a trailing partial record is ignored.
fn decode_nodes(b: &[u8]) -> Vec<SocketAddrV4> {
    b.as_chunks::<6>()
        .0
        .iter()
        .map(|c| {
            let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            let port = u16::from_be_bytes([c[4], c[5]]);
            SocketAddrV4::new(ip, port)
        })
        .collect()
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

/// What one lookup has gathered so far.
#[derive(Default)]
struct Walk {
    shortlist: Vec<Contact>,
    seen: Vec<SocketAddrV4>,
    queried: Vec<SocketAddrV4>,
    known: Vec<Contact>,
    storers: Vec<Contact>,
    values: Vec<Value>,
    ip_votes: Vec<(Ipv4Addr, u32)>,
    responders: Vec<SocketAddrV4>,
}

impl Walk {
    /// Take one round's answers to the `queried` contacts and pick the K
    /// closest unqueried contacts for the next round.
    #[inline(never)]
    fn absorb(
        &mut self,
        queried: &[Contact],
        answers: Vec<Parsed>,
        target: &[u8; 20],
    ) -> Vec<Contact> {
        for c in queried {
            note(&mut self.queried, c.addr);
        }
        for p in answers {
            self.record(p, true);
        }
        self.shortlist.sort_by_key(|c| dist(&c.id, target));
        self.shortlist
            .iter()
            .filter(|c| !self.queried.contains(&c.addr))
            .take(K)
            .cloned()
            .collect()
    }

    /// Record one answer: its BEP42 vote, value and write token, and, while
    /// `discover` is set, the responder and the contacts it named.
    #[inline(never)]
    fn record(&mut self, p: Parsed, discover: bool) {
        let Parsed {
            from,
            id,
            token,
            nodes,
            ip,
            value,
        } = p;
        self.responders.push(from);
        if let Some(ip) = ip {
            vote(&mut self.ip_votes, ip);
        }
        if let Some(v) = value {
            self.values.push(v);
        }
        if let (Some(id), Some(token)) = (id, token) {
            self.storers.push(Contact {
                id,
                addr: from,
                token: Some(token),
            });
        }
        if !discover {
            return;
        }
        if let Some(id) = id {
            self.known.push(Contact {
                id,
                addr: from,
                token: None,
            });
        }
        for c in nodes {
            if note(&mut self.seen, c.addr) {
                self.shortlist.push(c);
            }
        }
    }

    /// The K closest contacts still worth a `get`: responders that hold no
    /// token yet, plus discovered nodes never queried at all.
    #[inline(never)]
    fn finalists(&self, target: &[u8; 20]) -> Vec<Contact> {
        let with_token: Vec<SocketAddrV4> = self.storers.iter().map(|c| c.addr).collect();
        let answered: Vec<SocketAddrV4> = self.known.iter().map(|c| c.addr).collect();
        let mut finalists: Vec<Contact> = self
            .known
            .iter()
            .chain(self.shortlist.iter())
            .filter(|c| !with_token.contains(&c.addr))
            .filter(|c| answered.contains(&c.addr) || !self.queried.contains(&c.addr))
            .cloned()
            .collect();
        let mut uniq = Vec::new();
        finalists.retain(|c| note(&mut uniq, c.addr));
        finalists.sort_by_key(|c| dist(&c.id, target));
        finalists.truncate(K);
        finalists
    }

    /// The lookup result and the live node addresses to persist.
    #[inline(never)]
    fn finish(mut self, target: &[u8; 20]) -> (Lookup, Vec<SocketAddrV4>) {
        self.storers.sort_by_key(|c| dist(&c.id, target));
        let mut kept = Vec::new();
        self.storers.retain(|c| note(&mut kept, c.addr));
        self.storers.truncate(K);
        let external_ip = self
            .ip_votes
            .into_iter()
            .max_by_key(|&(_, n)| n)
            .map(|(ip, _)| ip);
        // Collect currently-live nodes for the next lookup's warm start: storers
        // (answered with a token) first, then any other responder seen this walk.
        let mut live: Vec<SocketAddrV4> = Vec::new();
        for c in self.storers.iter().map(|c| c.addr).chain(self.responders) {
            note(&mut live, c);
            if live.len() >= MAX_PERSISTED_NODES {
                break;
            }
        }
        (
            Lookup {
                storers: self.storers,
                values: self.values,
                external_ip,
            },
            live,
        )
    }
}

/// Add `addr` to `set` unless it is there already; whether it was added.
fn note(set: &mut Vec<SocketAddrV4>, addr: SocketAddrV4) -> bool {
    if set.contains(&addr) {
        return false;
    }
    set.push(addr);
    true
}

/// Count one BEP42 vote for `ip`.
fn vote(votes: &mut Vec<(Ipv4Addr, u32)>, ip: Ipv4Addr) {
    match votes.iter_mut().find(|(v, _)| *v == ip) {
        Some((_, n)) => *n += 1,
        None => votes.push((ip, 1)),
    }
}

fn dist(a: &[u8; 20], target: &[u8; 20]) -> [u8; 20] {
    let mut d = [0u8; 20];
    for i in 0..20 {
        d[i] = a[i] ^ target[i];
    }
    d
}

fn build_lookup(method: &[u8], id: &[u8; 20], target: &[u8; 20], tx: u16) -> Vec<u8> {
    let mut a = Dict::new();
    insert(&mut a, b"id", Ben::Bytes(id.to_vec()));
    insert(&mut a, b"target", Ben::Bytes(target.to_vec()));
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
    let mut a = Dict::new();
    insert(&mut a, b"id", Ben::Bytes(id.to_vec()));
    insert(&mut a, b"k", Ben::Bytes(pubkey.to_vec()));
    if let Some(s) = salt {
        insert(&mut a, b"salt", Ben::Bytes(s.to_vec()));
    }
    insert(&mut a, b"seq", Ben::Int(seq));
    insert(&mut a, b"sig", Ben::Bytes(sig.to_vec()));
    insert(&mut a, b"token", Ben::Bytes(token.to_vec()));
    insert(&mut a, b"v", Ben::Bytes(v.to_vec()));
    krpc_query(b"put", a, tx)
}

fn krpc_query(method: &[u8], args: Dict, tx: u16) -> Vec<u8> {
    let mut d = Dict::new();
    insert(&mut d, b"a", Ben::Dict(args));
    insert(&mut d, b"q", Ben::Bytes(method.to_vec()));
    insert(&mut d, b"t", Ben::Bytes(tx.to_be_bytes().to_vec()));
    insert(&mut d, b"y", Ben::Bytes(b"q".to_vec()));
    Ben::Dict(d).encode()
}

fn parse_response(buf: &[u8], txmap: &[(u16, SocketAddrV4)], from: SocketAddrV4) -> Option<Parsed> {
    let msg = decode(buf)?;
    if msg.get(b"y")?.bytes()? != b"r" {
        return None;
    }
    let t = msg.get(b"t")?.bytes()?;
    if t.len() != 2 {
        return None;
    }
    let tx = u16::from_be_bytes([t[0], t[1]]);
    if !txmap.contains(&(tx, from)) {
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
    b.as_chunks::<26>()
        .0
        .iter()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_list_roundtrip() {
        let nodes = vec![
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881),
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 25401),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
        ];
        let encoded = encode_nodes(&nodes);
        assert_eq!(encoded.len(), nodes.len() * 6);
        assert_eq!(decode_nodes(&encoded), nodes);
    }

    /// A responder implementing just enough KRPC for the walk: answers
    /// find_node with its id only, and get with its id, a write token, and
    /// a stored value.
    async fn fake_dht_node(sock: tokio::net::UdpSocket, id: [u8; 20], token: &[u8]) {
        let mut buf = [0u8; RECV_BUF];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Some(msg) = decode(&buf[..n]) else {
                continue;
            };
            let Some(q) = msg.get(b"q").and_then(|b| b.bytes()) else {
                continue;
            };
            let Some(t) = msg.get(b"t").and_then(|b| b.bytes()) else {
                continue;
            };
            let mut r = Dict::new();
            insert(&mut r, b"id", Ben::Bytes(id.to_vec()));
            if q == b"get" {
                insert(&mut r, b"token", Ben::Bytes(token.to_vec()));
                insert(&mut r, b"k", Ben::Bytes(vec![3u8; 32]));
                insert(&mut r, b"seq", Ben::Int(5));
                insert(&mut r, b"sig", Ben::Bytes(vec![4u8; 64]));
                insert(&mut r, b"v", Ben::Bytes(b"payload".to_vec()));
            }
            let mut d = Dict::new();
            insert(&mut d, b"r", Ben::Dict(r));
            insert(&mut d, b"t", Ben::Bytes(t.to_vec()));
            insert(&mut d, b"y", Ben::Bytes(b"r".to_vec()));
            let _ = sock.send_to(&Ben::Dict(d).encode(), from).await;
        }
    }

    #[tokio::test]
    async fn warm_start_seed_yields_write_token_via_final_get() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(seed_addr) = sock.local_addr().unwrap() else {
            unreachable!();
        };
        let seed_id = [9u8; 20];
        let responder = crate::spawn(fake_dht_node(sock, seed_id, b"tok"));

        // The seed answers round 0's find_node with no discoveries, so the walk
        // ends immediately; only the final get can extract its write token and
        // its stored value.
        let node = Node::new().await.unwrap();
        let (lookup, live) = node.walk(&[7u8; 20], vec![seed_addr]).await;
        responder.abort();

        assert_eq!(lookup.storers.len(), 1);
        assert_eq!(lookup.storers[0].addr, seed_addr);
        assert_eq!(lookup.storers[0].id, seed_id);
        assert_eq!(lookup.storers[0].token.as_deref(), Some(&b"tok"[..]));
        assert_eq!(lookup.values.len(), 1);
        assert_eq!(lookup.values[0].v, b"payload".to_vec());
        assert_eq!(lookup.values[0].seq, 5);
        assert!(live.contains(&seed_addr));
    }

    #[test]
    fn node_list_decode_ignores_trailing_partial() {
        let nodes = vec![SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242)];
        let mut buf = encode_nodes(&nodes);
        // A truncated trailing record is dropped, not panicked on.
        buf.extend_from_slice(&[9, 9, 9]);
        assert_eq!(decode_nodes(&buf), nodes);
        // Empty and sub-record buffers decode to nothing.
        assert!(decode_nodes(&[]).is_empty());
        assert!(decode_nodes(&[1, 2, 3, 4, 5]).is_empty());
    }
}
