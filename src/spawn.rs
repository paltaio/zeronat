//! Child processes over `posix_spawnp`, with the same defaults as
//! `std::process::Command`: the environment is inherited, `SIGPIPE` is reset
//! to its default in the child, stdio is inherited unless set, and PATH lookup
//! follows the libc rules.

use std::ffi::{c_char, c_int, CString};
use std::fs::File;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

extern "C" {
    static mut environ: *const *const c_char;
}

/// Where one of the child's standard streams comes from.
pub enum Stdio {
    Inherit,
    Null,
    Piped,
    Fd(File),
}

impl Stdio {
    #[cfg(target_os = "linux")]
    pub fn null() -> Stdio {
        Stdio::Null
    }

    #[cfg(target_os = "linux")]
    pub fn piped() -> Stdio {
        Stdio::Piped
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Stdio {
        Stdio::Fd(file)
    }
}

pub struct Command {
    argv: Vec<CString>,
    saw_nul: bool,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

pub struct Child {
    pid: libc::pid_t,
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}

enum Their {
    Inherit,
    Owned(File),
    Explicit(RawFd),
}

impl Their {
    fn fd(&self) -> Option<RawFd> {
        match self {
            Their::Inherit => None,
            Their::Owned(f) => Some(f.as_raw_fd()),
            Their::Explicit(fd) => Some(*fd),
        }
    }
}

fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn cvt_nz(err: c_int) -> io::Result<()> {
    if err == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(err))
    }
}

/// An owned file for a descriptor this module created.
unsafe fn owned(fd: c_int) -> File {
    File::from_raw_fd(fd)
}

fn set_nonblocking(f: &File, on: bool) -> io::Result<()> {
    let v: c_int = on as c_int;
    // SAFETY: FIONBIO reads one int through the pointer.
    cvt(unsafe { libc::ioctl(f.as_raw_fd(), libc::FIONBIO, &v) }).map(drop)
}

fn to_child(io: &Stdio, readable: bool) -> io::Result<(Their, Option<File>)> {
    // SAFETY: plain descriptor syscalls; every descriptor created here is
    // close-on-exec and owned by a File.
    unsafe {
        match *io {
            Stdio::Inherit => Ok((Their::Inherit, None)),
            Stdio::Fd(ref f) => {
                let fd = f.as_raw_fd();
                if (0..=libc::STDERR_FILENO).contains(&fd) {
                    let dup = cvt(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3))?;
                    Ok((Their::Owned(owned(dup)), None))
                } else {
                    Ok((Their::Explicit(fd), None))
                }
            }
            Stdio::Piped => {
                let mut fds = [0 as c_int; 2];
                cvt(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC))?;
                let (reader, writer) = (owned(fds[0]), owned(fds[1]));
                let (ours, theirs) = if readable {
                    (writer, reader)
                } else {
                    (reader, writer)
                };
                Ok((Their::Owned(theirs), Some(ours)))
            }
            Stdio::Null => {
                let flags = if readable {
                    libc::O_RDONLY
                } else {
                    libc::O_WRONLY
                } | libc::O_CLOEXEC;
                let fd = cvt(libc::open(c"/dev/null".as_ptr(), flags, 0o666))?;
                Ok((Their::Owned(owned(fd)), None))
            }
        }
    }
}

impl Command {
    pub fn new(program: &str) -> Command {
        let mut c = Command {
            argv: Vec::new(),
            saw_nul: false,
            stdin: None,
            stdout: None,
            stderr: None,
        };
        c.arg(program);
        c
    }

    pub fn arg(&mut self, arg: &str) -> &mut Command {
        self.argv.push(CString::new(arg).unwrap_or_else(|_| {
            self.saw_nul = true;
            CString::default()
        }));
        self
    }

    pub fn args(&mut self, args: &[&str]) -> &mut Command {
        for a in args {
            self.arg(a);
        }
        self
    }

    pub fn stdin(&mut self, io: Stdio) -> &mut Command {
        self.stdin = Some(io);
        self
    }

    pub fn stdout(&mut self, io: Stdio) -> &mut Command {
        self.stdout = Some(io);
        self
    }

    #[cfg(target_os = "linux")]
    pub fn stderr(&mut self, io: Stdio) -> &mut Command {
        self.stderr = Some(io);
        self
    }

    #[cfg(target_os = "linux")]
    /// Start the child; unset streams are inherited.
    pub fn spawn(&mut self) -> io::Result<Child> {
        self.spawn_with(&Stdio::Inherit, true)
    }

    /// Run to completion with inherited stdio.
    pub fn status(&mut self) -> io::Result<ExitStatus> {
        self.spawn_with(&Stdio::Inherit, true)?.wait()
    }

    /// Run to completion capturing stdout and stderr; stdin reads EOF.
    pub fn output(&mut self) -> io::Result<Output> {
        self.spawn_with(&Stdio::Piped, false)?.wait_with_output()
    }

    fn spawn_with(&mut self, default: &Stdio, needs_stdin: bool) -> io::Result<Child> {
        if self.saw_nul {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nul byte found in provided data",
            ));
        }
        let null = Stdio::Null;
        let default_stdin = if needs_stdin { default } else { &null };
        let (their_stdin, our_stdin) =
            to_child(self.stdin.as_ref().unwrap_or(default_stdin), true)?;
        let (their_stdout, our_stdout) = to_child(self.stdout.as_ref().unwrap_or(default), false)?;
        let (their_stderr, our_stderr) = to_child(self.stderr.as_ref().unwrap_or(default), false)?;

        let mut argv: Vec<*const c_char> = self.argv.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());

        // SAFETY: the spawn attribute and file action objects are initialised
        // before use and destroyed after posix_spawnp returns; argv and the
        // descriptors it duplicates stay alive across the call.
        let pid = unsafe {
            let mut attrs = MaybeUninit::<libc::posix_spawnattr_t>::uninit();
            cvt_nz(libc::posix_spawnattr_init(attrs.as_mut_ptr()))?;
            let mut actions = MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
            cvt_nz(libc::posix_spawn_file_actions_init(actions.as_mut_ptr()))?;
            let res = (|| -> io::Result<libc::pid_t> {
                for (their, target) in [
                    (&their_stdin, libc::STDIN_FILENO),
                    (&their_stdout, libc::STDOUT_FILENO),
                    (&their_stderr, libc::STDERR_FILENO),
                ] {
                    if let Some(fd) = their.fd() {
                        cvt_nz(libc::posix_spawn_file_actions_adddup2(
                            actions.as_mut_ptr(),
                            fd,
                            target,
                        ))?;
                    }
                }
                let mut default_set = MaybeUninit::<libc::sigset_t>::uninit();
                cvt(libc::sigemptyset(default_set.as_mut_ptr()))?;
                cvt(libc::sigaddset(default_set.as_mut_ptr(), libc::SIGPIPE))?;
                cvt_nz(libc::posix_spawnattr_setsigdefault(
                    attrs.as_mut_ptr(),
                    default_set.as_ptr(),
                ))?;
                cvt_nz(libc::posix_spawnattr_setflags(
                    attrs.as_mut_ptr(),
                    libc::POSIX_SPAWN_SETSIGDEF as _,
                ))?;
                let mut pid: libc::pid_t = 0;
                cvt_nz(libc::posix_spawnp(
                    &mut pid,
                    self.argv[0].as_ptr(),
                    actions.as_ptr(),
                    attrs.as_ptr(),
                    argv.as_ptr() as *const *mut c_char,
                    environ as *const *mut c_char,
                ))?;
                Ok(pid)
            })();
            libc::posix_spawn_file_actions_destroy(actions.as_mut_ptr());
            libc::posix_spawnattr_destroy(attrs.as_mut_ptr());
            res?
        };
        Ok(Child {
            pid,
            stdin: our_stdin,
            stdout: our_stdout,
            stderr: our_stderr,
        })
    }
}

impl Child {
    /// Close stdin, then wait for the child to exit.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        drop(self.stdin.take());
        let mut status: c_int = 0;
        loop {
            // SAFETY: status is a valid out-pointer for the call.
            match cvt(unsafe { libc::waitpid(self.pid, &mut status, 0) }) {
                Ok(_) => return Ok(ExitStatus::from_raw(status)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Close stdin, drain the captured streams, then wait for the child.
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        drop(self.stdin.take());
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        match (self.stdout.take(), self.stderr.take()) {
            (None, None) => {}
            (Some(out), None) => {
                (&out).read_to_end(&mut stdout)?;
            }
            (None, Some(err)) => {
                (&err).read_to_end(&mut stderr)?;
            }
            (Some(out), Some(err)) => read_output(&out, &mut stdout, &err, &mut stderr)?,
        }
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

/// Drain two pipes together so neither fills up while the other is read.
fn read_output(
    out: &File,
    stdout: &mut Vec<u8>,
    err: &File,
    stderr: &mut Vec<u8>,
) -> io::Result<()> {
    set_nonblocking(out, true)?;
    set_nonblocking(err, true)?;
    let mut fds = [
        libc::pollfd {
            fd: out.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: err.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: fds holds two initialised pollfd entries.
        match cvt(unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) }) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        if fds[0].revents != 0 && drain(out, stdout)? {
            set_nonblocking(err, false)?;
            return (&*err).read_to_end(stderr).map(drop);
        }
        if fds[1].revents != 0 && drain(err, stderr)? {
            set_nonblocking(out, false)?;
            return (&*out).read_to_end(stdout).map(drop);
        }
    }
}

/// Read everything currently available; true at end of file.
fn drain(f: &File, dst: &mut Vec<u8>) -> io::Result<bool> {
    match (&*f).read_to_end(dst) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e),
    }
}
