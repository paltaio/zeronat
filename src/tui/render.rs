//! Flicker-free frame renderer.
//!
//! Each frame is a list of pre-rendered row strings. The renderer keeps the
//! previous frame and rewrites only the rows that changed, so a steady screen
//! emits no output and a single changed row touches one line. A size change
//! forces a full repaint.

use std::io::{self, Write};

pub struct Renderer {
    prev: Vec<String>,
    w: u16,
    h: u16,
}

impl Renderer {
    pub fn new() -> Renderer {
        Renderer {
            prev: Vec::new(),
            w: 0,
            h: 0,
        }
    }

    /// Draw `lines` at the given terminal size, taking ownership so the frame
    /// becomes the next diff baseline without a copy. Rows are 1-based in the
    /// cursor addressing; the cursor is parked just past the last row.
    pub fn draw(&mut self, lines: Vec<String>, w: u16, h: u16) -> io::Result<()> {
        let mut out = String::new();

        if w != self.w || h != self.h {
            self.w = w;
            self.h = h;
            self.prev.clear();
            out.push_str("\x1b[2J");
        }

        for (i, line) in lines.iter().enumerate() {
            let changed = self.prev.get(i) != Some(line);
            if changed {
                out.push_str(&format!("\x1b[{};1H\x1b[2K", i + 1));
                out.push_str(line);
            }
        }
        // Clear rows that existed last frame but not this one.
        for i in lines.len()..self.prev.len() {
            out.push_str(&format!("\x1b[{};1H\x1b[2K", i + 1));
        }

        out.push_str(&format!("\x1b[{};1H", lines.len() + 1));

        self.prev = lines;

        let mut stdout = io::stdout();
        stdout.write_all(out.as_bytes())?;
        stdout.flush()
    }
}
