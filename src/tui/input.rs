//! Keyboard input: a blocking stdin reader thread that parses bytes into `Key`
//! events and forwards them over a channel the async event loop can select on.

use tokio::sync::mpsc;

pub use zntui::key::Key;
use zntui::key::parse;

/// Spawn the reader thread and return the receiving end. The thread exits on
/// EOF, a read error, or when the receiver is dropped.
pub fn reader() -> mpsc::UnboundedReceiver<Key> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 64];
        loop {
            let n = match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut i = 0;
            while i < n {
                let (key, adv) = parse(&buf[i..n]);
                if let Some(k) = key {
                    if tx.send(k).is_err() {
                        return;
                    }
                }
                i += adv.max(1);
            }
        }
    });
    rx
}
