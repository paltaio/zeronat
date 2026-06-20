//! Key events and a byte-stream parser, shared by the async (zeronat console)
//! and sync (installer) input loops.

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

/// Parse one key from the front of `b`, returning the key (if any) and how many
/// bytes it consumed. A lone ESC with no following bytes in the chunk is treated
/// as the Escape key; a recognised CSI arrow becomes a direction; other CSI
/// sequences are consumed and ignored.
pub fn parse(b: &[u8]) -> (Option<Key>, usize) {
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
