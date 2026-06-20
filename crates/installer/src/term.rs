//! Terminal I/O against /dev/tty so the installer drives the real terminal even
//! when launched as `curl ... | sh` (where stdin/stdout are the pipe). Holds the
//! raw-mode setup, a blocking key reader, and a flicker-free diff renderer.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use zntui::key::{parse, Key};

pub struct Tty {
    file: File,
    fd: RawFd,
    orig: Option<libc::termios>,
    buf: Vec<u8>,
    bpos: usize,
}

impl Tty {
    pub fn open() -> io::Result<Tty> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        let fd = file.as_raw_fd();
        Ok(Tty {
            file,
            fd,
            orig: None,
            buf: Vec::new(),
            bpos: 0,
        })
    }

    pub fn enter_raw(&mut self) -> io::Result<()> {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(self.fd, &mut t) != 0 {
                return Err(io::Error::last_os_error());
            }
            self.orig = Some(t);
            let mut raw = t;
            raw.c_iflag &= !(libc::IGNBRK
                | libc::BRKINT
                | libc::PARMRK
                | libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL
                | libc::IXON);
            raw.c_oflag &= !libc::OPOST;
            raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_cflag &= !(libc::CSIZE | libc::PARENB);
            raw.c_cflag |= libc::CS8;
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(self.fd, libc::TCSANOW, &raw) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // If the alt-screen write fails, undo the termios change so a partial
        // setup never leaves the shell in raw mode.
        if let Err(e) = self.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H") {
            self.restore();
            return Err(e);
        }
        Ok(())
    }

    /// Restore the saved termios first, then leave the alternate screen and show
    /// the cursor. Safe to call more than once.
    pub fn restore(&mut self) {
        if let Some(t) = self.orig.take() {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &t);
            }
        }
        let _ = self.write_all(b"\x1b[?25h\x1b[?1049l");
    }

    pub fn size(&self) -> (u16, u16) {
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(self.fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
                (ws.ws_col, ws.ws_row.max(1))
            } else {
                (80, 24)
            }
        }
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)?;
        self.file.flush()
    }

    /// Block until one key is available, buffering any extra bytes from the same
    /// read (so escape sequences and pastes are parsed one key at a time).
    pub fn next_key(&mut self) -> io::Result<Key> {
        loop {
            if self.bpos >= self.buf.len() {
                let mut tmp = [0u8; 64];
                let n = self.file.read(&mut tmp)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tty closed"));
                }
                self.buf.clear();
                self.buf.extend_from_slice(&tmp[..n]);
                self.bpos = 0;
            }
            let (key, adv) = parse(&self.buf[self.bpos..]);
            self.bpos += adv.max(1);
            if let Some(k) = key {
                return Ok(k);
            }
        }
    }
}

/// Flicker-free renderer: keeps the previous frame and rewrites only the rows
/// that changed. A size change forces a full repaint.
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

    pub fn draw(&mut self, tty: &mut Tty, lines: Vec<String>, w: u16, h: u16) -> io::Result<()> {
        let mut out = String::new();
        if w != self.w || h != self.h {
            self.w = w;
            self.h = h;
            self.prev.clear();
            out.push_str("\x1b[2J");
        }
        for (i, line) in lines.iter().enumerate() {
            if self.prev.get(i).is_none_or(|p| p != line) {
                out.push_str(&format!("\x1b[{};1H\x1b[2K", i + 1));
                out.push_str(line);
            }
        }
        for i in lines.len()..self.prev.len() {
            out.push_str(&format!("\x1b[{};1H\x1b[2K", i + 1));
        }
        out.push_str(&format!("\x1b[{};1H", lines.len() + 1));
        self.prev = lines;
        tty.write_all(out.as_bytes())
    }
}
