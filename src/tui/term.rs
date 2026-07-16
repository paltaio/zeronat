//! Raw-mode terminal control via termios (unix only).
//!
//! `RawMode::enter` switches the terminal to byte-at-a-time input with echo and
//! line editing off, opens the alternate screen, and hides the cursor; dropping
//! the guard reverses all three. The original termios is also stashed in a
//! signal-safe process-global: a teardown path that bypasses the guard can
//! still restore, and fatal-signal handlers restore it on a crash, because the
//! abort-on-panic release build runs neither `Drop` nor panic hooks.

use std::cell::UnsafeCell;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

const STDIN: RawFd = libc::STDIN_FILENO;
const STDOUT: RawFd = libc::STDOUT_FILENO;
/// Show the cursor, leave the alternate screen.
const EXIT_ESCAPES: &[u8] = b"\x1b[?25h\x1b[?1049l";

/// The saved termios. Written only by `RawMode::enter` (the console's single
/// entry) before `RAW_ACTIVE` is set; read only by the claimant of the
/// `RAW_ACTIVE` swap. Not a Mutex: the fatal-signal handler must read it
/// async-signal-safely.
struct Saved(UnsafeCell<MaybeUninit<libc::termios>>);
unsafe impl Sync for Saved {}
static SAVED: Saved = Saved(UnsafeCell::new(MaybeUninit::uninit()));
static RAW_ACTIVE: AtomicBool = AtomicBool::new(false);

/// True when stdout is a terminal. Used to decide between the interactive
/// console and plain scriptable output.
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
            // Stash and arm before switching to raw, so a crash in the window
            // between the flag and tcsetattr restores the (unchanged) settings
            // instead of stranding raw mode.
            (*SAVED.0.get()).write(orig);
            RAW_ACTIVE.store(true, Ordering::Release);
            install_fatal_handlers();
            #[cfg(debug_assertions)]
            install_panic_hook();

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
                RAW_ACTIVE.store(false, Ordering::Release);
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

/// Claim the saved termios and restore it; true when this call did the
/// restore. The swap hands the settings to exactly one claimant, so the guard
/// Drop, an explicit `restore`, and the fatal-signal handler can all race
/// safely and later calls are no-ops. Async-signal-safe: one atomic swap and
/// one `tcsetattr`.
fn take_saved_termios() -> bool {
    if !RAW_ACTIVE.swap(false, Ordering::AcqRel) {
        return false;
    }
    unsafe {
        let orig = (*SAVED.0.get()).assume_init();
        libc::tcsetattr(STDIN, libc::TCSANOW, &orig);
    }
    true
}

/// The release build panics via `-Cpanic=immediate-abort`, which runs neither
/// `Drop` nor panic hooks: a panic traps (SIGILL on x86, SIGTRAP on aarch64)
/// and `abort` raises SIGABRT. These handlers are the only chance to leave the
/// terminal usable. All three are synchronous signals delivered on the crashing
/// thread, so reading `SAVED` here cannot race its writer. SIGSEGV stays with
/// the std runtime, whose sigaltstack handler reports stack overflows.
/// `SA_RESETHAND` already restored the default disposition, so the re-raise
/// terminates with the crash status.
unsafe extern "C" fn on_fatal(sig: libc::c_int) {
    if take_saved_termios() {
        libc::write(STDOUT, EXIT_ESCAPES.as_ptr().cast(), EXIT_ESCAPES.len());
    }
    libc::raise(sig);
}

fn install_fatal_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_fatal as unsafe extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESETHAND;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGILL, libc::SIGTRAP, libc::SIGABRT] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    });
}

/// Dev builds unwind, so `Drop` already restores; the hook exists to restore
/// BEFORE the message prints, which would otherwise vanish with the alternate
/// screen.
#[cfg(debug_assertions)]
fn install_panic_hook() {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if take_saved_termios() {
                let mut out = io::stdout();
                let _ = out.write_all(EXIT_ESCAPES);
                let _ = out.flush();
            }
            prev(info);
        }));
    });
}

/// Restore the saved termios, then leave the alternate screen and show the
/// cursor. The termios restore runs first and unconditionally so a broken stdout
/// can never strand stdin in raw mode; the cosmetic escapes are best-effort.
/// Safe to call more than once; the second call is a no-op.
pub fn restore() -> io::Result<()> {
    take_saved_termios();
    let mut out = io::stdout();
    let _ = out.write_all(EXIT_ESCAPES);
    let _ = out.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_restore_claims_saved_termios_once() {
        // Real settings when stdin is a tty (restoring them is a no-op); zeroed
        // otherwise, where tcsetattr fails and never reaches a terminal.
        let orig = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(STDIN, &mut t);
            t
        };
        unsafe { (*SAVED.0.get()).write(orig) };
        RAW_ACTIVE.store(true, Ordering::Release);

        assert!(take_saved_termios());
        // Claimed: every later restorer (signal handler, hook, Drop) is a no-op.
        assert!(!take_saved_termios());
        assert!(!RAW_ACTIVE.load(Ordering::Acquire));
    }
}
