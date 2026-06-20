//! Raw-mode terminal control via termios (unix only).
//!
//! `RawMode::enter` switches the terminal to byte-at-a-time input with echo and
//! line editing off, opens the alternate screen, and hides the cursor; dropping
//! the guard reverses all three. The original termios is also stashed in a
//! process-global so a teardown path that bypasses the guard can still restore.

use std::io::{self, Write};
use std::os::fd::RawFd;
use std::sync::Mutex;

const STDIN: RawFd = libc::STDIN_FILENO;
const STDOUT: RawFd = libc::STDOUT_FILENO;

static ORIGINAL: Mutex<Option<libc::termios>> = Mutex::new(None);

/// True when stdout is a terminal. Used to decide between the interactive
/// console and the scriptable one-shot output.
pub fn stdout_is_tty() -> bool {
    unsafe { libc::isatty(STDOUT) == 1 }
}

/// Current terminal size as (cols, rows), falling back to 80x24 when the size
/// is unavailable (e.g. stdout is not a tty).
pub fn size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(STDOUT, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            (ws.ws_col, ws.ws_row.max(1))
        } else {
            (80, 24)
        }
    }
}

pub struct RawMode {
    _private: (),
}

impl RawMode {
    pub fn enter() -> io::Result<RawMode> {
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(STDIN, &mut orig) != 0 {
                return Err(io::Error::last_os_error());
            }
            *ORIGINAL.lock().unwrap() = Some(orig);

            let mut raw = orig;
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
            if libc::tcsetattr(STDIN, libc::TCSANOW, &raw) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let mut out = io::stdout();
        // Alternate screen, hide cursor, clear, home.
        out.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")?;
        out.flush()?;
        Ok(RawMode { _private: () })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = restore();
    }
}

/// Restore the saved termios, then leave the alternate screen and show the
/// cursor. The termios restore runs first and unconditionally so a broken stdout
/// can never strand stdin in raw mode; the cosmetic escapes are best-effort.
/// Safe to call more than once; the second call is a no-op.
pub fn restore() -> io::Result<()> {
    if let Some(orig) = ORIGINAL.lock().unwrap().take() {
        unsafe {
            libc::tcsetattr(STDIN, libc::TCSANOW, &orig);
        }
    }
    let mut out = io::stdout();
    let _ = out.write_all(b"\x1b[?25h\x1b[?1049l");
    let _ = out.flush();
    Ok(())
}
