//! Egress selection and connection splicing shared by the SOCKS5 and HTTP CONNECT
//! front ends. `Selector` authenticates a client and maps its username to a live
//! session; `connect` opens a TCP connection through that session and
//! `Conn::splice` pumps bytes between the client socket and the session.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};

use crate::netstack::{Connect, Handle};

const CHAN_DEPTH: usize = 64;
const CONNECT_WAIT: Duration = Duration::from_secs(35);
/// Cap on remembered sticky tokens so an authenticated client cannot grow the map
/// without bound. On overflow the table is cleared; mappings re-establish on use.
const STICKY_MAX: usize = 4096;

/// Why `Selector::select` picked no session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Wrong password, or a username that names no session.
    Denied,
    /// The credentials are good and every session they can use is down.
    Down,
}

/// Authenticates a client and resolves its egress session. The proxy password
/// gates access; the username chooses the session over those currently live, so
/// no connection is dialed through a down session.
///
/// Username forms (`<user>` is the configured proxy user): `<user>` round-robins,
/// `<user>_pppoe<K>` pins session K, `<user>_s<token>` is sticky per token. A
/// sticky token whose session is down moves to the next live session after it
/// and stays there.
pub struct Selector {
    user: String,
    pass: String,
    live: Vec<Arc<AtomicBool>>,
    rr: AtomicUsize,
    sticky: Mutex<HashMap<String, usize>>,
}

impl Selector {
    pub fn new(user: String, pass: String, live: Vec<Arc<AtomicBool>>) -> Self {
        Selector {
            user,
            pass,
            live,
            rr: AtomicUsize::new(0),
            sticky: Mutex::new(HashMap::new()),
        }
    }

    pub fn select(&self, user: &[u8], pass: &[u8]) -> Result<usize, Refusal> {
        if pass != self.pass.as_bytes() {
            return Err(Refusal::Denied);
        }
        let rest = std::str::from_utf8(user)
            .ok()
            .and_then(|user| user.strip_prefix(&self.user))
            .ok_or(Refusal::Denied)?;
        if rest.is_empty() {
            self.next_live().ok_or(Refusal::Down)
        } else if let Some(k) = rest.strip_prefix("_pppoe") {
            let k: usize = k.parse().map_err(|_| Refusal::Denied)?;
            if k >= self.live.len() {
                return Err(Refusal::Denied);
            }
            if self.is_live(k) {
                Ok(k)
            } else {
                Err(Refusal::Down)
            }
        } else if let Some(token) = rest.strip_prefix("_s") {
            if token.is_empty() {
                return Err(Refusal::Denied);
            }
            self.sticky(token).ok_or(Refusal::Down)
        } else {
            Err(Refusal::Denied)
        }
    }

    /// Whether session `idx` has a negotiated address right now.
    pub fn is_live(&self, idx: usize) -> bool {
        self.live[idx].load(Ordering::Relaxed)
    }

    /// The first live session at or after `start`, wrapping around.
    fn live_from(&self, start: usize) -> Option<usize> {
        let n = self.live.len();
        (0..n).map(|i| (start + i) % n).find(|&i| self.is_live(i))
    }

    fn next_live(&self) -> Option<usize> {
        self.live_from(self.rr.fetch_add(1, Ordering::Relaxed))
    }

    fn sticky(&self, token: &str) -> Option<usize> {
        let mut map = self.sticky.lock().unwrap();
        let i = match map.get(token) {
            Some(&i) if self.is_live(i) => return Some(i),
            Some(&i) => self.live_from(i + 1)?,
            None => self.next_live()?,
        };
        if map.len() >= STICKY_MAX {
            map.clear();
        }
        map.insert(token.to_string(), i);
        Some(i)
    }
}

/// A connected egress session, ready to splice with the client socket.
pub struct Conn {
    to_tx: mpsc::Sender<Vec<u8>>,
    from_rx: mpsc::Receiver<Vec<u8>>,
    handle: Handle,
}

/// Open a TCP connection to `target` through session `idx`, returning once the
/// remote side is established (or erroring if it never connects).
pub async fn connect(handles: &[Handle], idx: usize, target: SocketAddrV4) -> Result<Conn> {
    let (to_tx, to_rx) = mpsc::channel::<Vec<u8>>(CHAN_DEPTH);
    let (from_tx, from_rx) = mpsc::channel::<Vec<u8>>(CHAN_DEPTH);
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
    let ok = matches!(
        tokio::time::timeout(CONNECT_WAIT, ready_rx).await,
        Ok(Ok(true))
    );
    if !ok {
        bail!("connect to {target} via session {idx} failed");
    }
    Ok(Conn {
        to_tx,
        from_rx,
        handle,
    })
}

impl Conn {
    /// Queue bytes to the remote before splicing. The plain-HTTP forward path uses
    /// this to send the rewritten request head ahead of the client's body bytes.
    pub async fn send(&self, bytes: Vec<u8>) -> Result<()> {
        if self.to_tx.send(bytes).await.is_err() {
            bail!("remote closed before request was sent");
        }
        self.handle.wake();
        Ok(())
    }

    /// Pump bytes between the client halves and the session until either side ends.
    pub async fn splice(self, rd: OwnedReadHalf, wr: OwnedWriteHalf) {
        let Conn {
            to_tx,
            mut from_rx,
            handle,
        } = self;
        let up = handle.clone();
        let mut rd = rd;
        let client_to_remote = crate::spawn(async move {
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
            drop(to_tx);
            up.wake();
        });
        let mut wr = wr;
        let remote_to_client = crate::spawn(async move {
            while let Some(chunk) = from_rx.recv().await {
                if wr.write_all(&chunk).await.is_err() {
                    break;
                }
                handle.wake();
            }
            let _ = wr.shutdown().await;
        });
        let _ = tokio::join!(client_to_remote, remote_to_client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector(live: &[bool]) -> Selector {
        Selector::new(
            "proxy".into(),
            "pw".into(),
            live.iter().map(|&b| Arc::new(AtomicBool::new(b))).collect(),
        )
    }

    #[test]
    fn rejects_wrong_password() {
        assert_eq!(
            selector(&[true]).select(b"proxy", b"nope"),
            Err(Refusal::Denied)
        );
    }

    #[test]
    fn round_robin_skips_down_sessions() {
        let s = selector(&[false, true, false, true]);
        let picks: Vec<_> = (0..4).map(|_| s.select(b"proxy", b"pw")).collect();
        assert!(picks.iter().all(|p| matches!(p, Ok(1) | Ok(3))));
        assert!(picks.contains(&Ok(1)) && picks.contains(&Ok(3)));
    }

    #[test]
    fn round_robin_none_when_all_down() {
        assert_eq!(
            selector(&[false, false]).select(b"proxy", b"pw"),
            Err(Refusal::Down)
        );
    }

    #[test]
    fn pin_selects_exact_session() {
        let s = selector(&[true, true, true]);
        assert_eq!(s.select(b"proxy_pppoe2", b"pw"), Ok(2));
        assert_eq!(s.select(b"proxy_pppoe9", b"pw"), Err(Refusal::Denied));
    }

    #[test]
    fn pin_fails_while_its_session_is_down() {
        let s = selector(&[true, false, true]);
        assert_eq!(s.select(b"proxy_pppoe1", b"pw"), Err(Refusal::Down));
        s.live[1].store(true, Ordering::Relaxed);
        assert_eq!(s.select(b"proxy_pppoe1", b"pw"), Ok(1));
    }

    #[test]
    fn sticky_token_keeps_one_session() {
        let s = selector(&[true, true, true, true]);
        let first = s.select(b"proxy_sjobA", b"pw").unwrap();
        for _ in 0..10 {
            assert_eq!(s.select(b"proxy_sjobA", b"pw"), Ok(first));
        }
        let other = s.select(b"proxy_sjobB", b"pw").unwrap();
        assert_eq!(s.select(b"proxy_sjobB", b"pw"), Ok(other));
    }

    #[test]
    fn sticky_token_moves_to_the_next_live_session_and_stays() {
        let s = selector(&[true, true, false, true]);
        let first = s.select(b"proxy_sjobA", b"pw").unwrap();
        s.live[first].store(false, Ordering::Relaxed);
        // The next live session after `first`, skipping session 2.
        let moved = if first == 1 { 3 } else { (first + 1) % 4 };
        assert_eq!(s.select(b"proxy_sjobA", b"pw"), Ok(moved));
        s.live[first].store(true, Ordering::Relaxed);
        assert_eq!(s.select(b"proxy_sjobA", b"pw"), Ok(moved));
    }

    #[test]
    fn sticky_none_when_all_down() {
        let s = selector(&[true, true]);
        s.select(b"proxy_sjobA", b"pw").unwrap();
        for flag in &s.live {
            flag.store(false, Ordering::Relaxed);
        }
        assert_eq!(s.select(b"proxy_sjobA", b"pw"), Err(Refusal::Down));
    }

    #[test]
    fn unknown_username_shape_rejected() {
        let s = selector(&[true]);
        assert_eq!(s.select(b"proxy_bogus", b"pw"), Err(Refusal::Denied));
        assert_eq!(s.select(b"other", b"pw"), Err(Refusal::Denied));
    }
}
