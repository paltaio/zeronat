//! Terminal I/O against /dev/tty so the installer drives the real terminal even
//! when launched as `curl ... | sh` (where stdin/stdout are the pipe). Holds the
//! raw-mode setup, a blocking key reader, and a flicker-free diff renderer.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use zntui::key::{parse, Key};

/// Read one line from the controlling terminal with echo disabled, for
/// credentials that must not land on screen or in scrollback. The terminal
/// stays in canonical mode, so the tty driver handles line editing.
pub fn read_hidden_line(prompt: &str) -> io::Result<String> {
    let mut file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    file.write_all(prompt.as_bytes())?;
    file.flush()?;
    read_line_no_echo(&mut file)
}

fn read_line_no_echo(file: &mut File) -> io::Result<String> {
    let fd = file.as_raw_fd();
    // SAFETY: fd is an open terminal descriptor and the termios out-pointer is
    // valid for the duration of the call.
    let original = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err(io::Error::last_os_error());
        }
        t
    };
    let mut hidden = original;
    // ISIG goes too: Ctrl-C must arrive as input and cancel the read, not kill
    // the process before the guard below restores echo.
    hidden.c_lflag &= !(libc::ECHO | libc::ISIG);
    // SAFETY: fd is the same open terminal and hidden was initialized from its
    // current attributes.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct RestoreEcho {
        fd: RawFd,
        original: libc::termios,
    }
    impl Drop for RestoreEcho {
        fn drop(&mut self) {
            // SAFETY: fd stays open for this guard's lifetime and original came
            // from tcgetattr on the same terminal.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
    let _restore = RestoreEcho { fd, original };

    // A canonical-mode read never returns bytes past the newline, so the line
    // is complete once the accumulated input ends with one. A zero read is the
    // terminal closing (or Ctrl-D); return what arrived and let credential
    // validation reject it.
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0u8; 256];
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.last() == Some(&b'\n') {
            break;
        }
    }
    // Enter was not echoed, so move off the prompt line ourselves.
    file.write_all(b"\n")?;
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.contains(&3) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "prompt cancelled",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input is not UTF-8"))
}

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

    /// Like `next_key` but waits at most `timeout_ms`. Returns `Ok(None)` on
    /// timeout so a caller can drive a countdown. An error (e.g. the tty closing
    /// when an SSH session drops) propagates so the caller can stop waiting.
    pub fn poll_key(&mut self, timeout_ms: i32) -> io::Result<Option<Key>> {
        loop {
            if self.bpos < self.buf.len() {
                let (key, adv) = parse(&self.buf[self.bpos..]);
                self.bpos += adv.max(1);
                if let Some(k) = key {
                    return Ok(Some(k));
                }
                continue;
            }
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            if r == 0 {
                return Ok(None);
            }
            let mut tmp = [0u8; 64];
            let n = self.file.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tty closed"));
            }
            self.buf.clear();
            self.buf.extend_from_slice(&tmp[..n]);
            self.bpos = 0;
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

#[cfg(test)]
mod tests {
    use super::read_line_no_echo;
    use std::fs::File;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};

    fn pty_pair() -> (File, File) {
        let mut master = 0;
        let mut slave = 0;
        // SAFETY: openpty fills the two descriptors; the name, termios, and
        // winsize out-parameters are allowed to be null.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: openpty returned ownership of both descriptors.
        unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
    }

    fn lflag(fd: RawFd) -> libc::tcflag_t {
        // SAFETY: fd is an open pty descriptor and the out-pointer is valid.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut t), 0);
            t.c_lflag
        }
    }

    /// Block until the reader has applied the hidden termios, so bytes written
    /// afterwards are processed under it rather than the pty defaults.
    fn wait_until_hidden(fd: RawFd) {
        for _ in 0..1000 {
            if lflag(fd) & libc::ECHO == 0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!("reader never disabled echo");
    }

    #[test]
    fn correcting_an_overtyped_credential_with_backspace_yields_the_corrected_value() {
        let (mut master, mut slave) = pty_pair();

        let mut typed = vec![b'a'; 64];
        typed.push(b'b'); // one character too many
        typed.push(0x7f); // erased by the pty line discipline
        typed.push(b'\n');
        let writer = std::thread::spawn(move || {
            master.write_all(&typed).unwrap();
            master
        });

        let line = read_line_no_echo(&mut slave).unwrap();
        let _master = writer.join().unwrap();
        assert_eq!(line, "a".repeat(64));
    }

    #[test]
    fn ctrl_c_cancels_the_prompt_and_restores_the_terminal() {
        let (mut master, mut slave) = pty_pair();
        let master_fd = master.as_raw_fd();

        let writer = std::thread::spawn(move || {
            wait_until_hidden(master_fd);
            master.write_all(b"abc\x03\n").unwrap();
            master
        });

        let err = read_line_no_echo(&mut slave).unwrap_err();
        let master = writer.join().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
        let restored = lflag(master.as_raw_fd());
        assert_ne!(restored & libc::ECHO, 0, "echo not restored");
        assert_ne!(restored & libc::ISIG, 0, "isig not restored");
    }
}
