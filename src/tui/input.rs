//! Keyboard input: a blocking stdin reader thread that parses bytes into `Key`
//! events and forwards them over a channel the async event loop can select on.

use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Esc,
    Tab,
    Backspace,
    Char(char),
    CtrlC,
}

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

/// Parse one key from the front of `b`, returning the key (if any) and how many
/// bytes it consumed. A lone ESC with no following bytes in the chunk is treated
/// as the Escape key; a recognised CSI arrow becomes a direction; other CSI
/// sequences are consumed and ignored.
fn parse(b: &[u8]) -> (Option<Key>, usize) {
    match b[0] {
        0x1b => {
            if b.len() >= 3 && b[1] == b'[' {
                let arrow = match b[2] {
                    b'A' => Some(Key::Up),
                    b'B' => Some(Key::Down),
                    b'C' => Some(Key::Right),
                    b'D' => Some(Key::Left),
                    _ => None,
                };
                if arrow.is_some() {
                    return (arrow, 3);
                }
                // Unknown CSI: skip to its final byte (0x40..=0x7e).
                let mut j = 2;
                while j < b.len() && !(0x40..=0x7e).contains(&b[j]) {
                    j += 1;
                }
                return (None, (j + 1).min(b.len()));
            }
            (Some(Key::Esc), 1)
        }
        b'\r' | b'\n' => (Some(Key::Enter), 1),
        0x7f | 0x08 => (Some(Key::Backspace), 1),
        b'\t' => (Some(Key::Tab), 1),
        0x03 => (Some(Key::CtrlC), 1),
        c if c < 0x20 => (None, 1),
        c if c < 0x80 => (Some(Key::Char(c as char)), 1),
        c => {
            let len = if c >= 0xf0 {
                4
            } else if c >= 0xe0 {
                3
            } else {
                2
            };
            if b.len() >= len {
                if let Ok(s) = std::str::from_utf8(&b[..len]) {
                    if let Some(ch) = s.chars().next() {
                        return (Some(Key::Char(ch)), len);
                    }
                }
            }
            (None, len.min(b.len()))
        }
    }
}
