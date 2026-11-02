//! Waits for edits to one file: inotify on its directory on Linux, polling its
//! size and modification time elsewhere or when inotify cannot be set up.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// How often a polled file is checked.
const POLL: Duration = Duration::from_secs(2);
/// Quiet time after the last event before an edit counts as finished, so a
/// save that lands in several writes is read once.
#[cfg(target_os = "linux")]
const SETTLE: Duration = Duration::from_millis(250);

pub(crate) struct FileWatch {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    inotify: Option<inotify::Watch>,
    stamp: Option<(SystemTime, u64)>,
}

fn stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

impl FileWatch {
    pub(crate) fn new(path: &Path) -> Self {
        #[cfg(target_os = "linux")]
        let inotify = inotify::Watch::new(path)
            .map_err(|e| {
                crate::elog!(
                    "cannot watch {}: {e}; checking it every {}s",
                    path.display(),
                    POLL.as_secs()
                );
            })
            .ok();
        FileWatch {
            path: path.to_path_buf(),
            #[cfg(target_os = "linux")]
            inotify,
            stamp: stamp(path),
        }
    }

    /// Return once the file has been written or replaced.
    pub(crate) async fn changed(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(watch) = &self.inotify {
            match watch.changed().await {
                Ok(()) => return,
                Err(e) => {
                    crate::elog!(
                        "watching {} failed: {e}; checking it every {}s",
                        self.path.display(),
                        POLL.as_secs()
                    );
                    self.inotify = None;
                    self.stamp = stamp(&self.path);
                }
            }
        }
        self.poll().await;
    }

    /// Return once the file differs from the last change seen and has looked
    /// the same for one poll.
    async fn poll(&mut self) {
        let mut last = self.stamp;
        loop {
            tokio::time::sleep(POLL).await;
            let now = stamp(&self.path);
            let settled = now == last;
            last = now;
            if settled && now.is_some() && now != self.stamp {
                self.stamp = now;
                return;
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod inotify {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use tokio::io::unix::AsyncFd;

    /// The fixed part of a `struct inotify_event`: wd, mask, cookie, len.
    const HEADER: usize = 16;

    /// An inotify watch on a file's directory, which also sees a save that
    /// replaces the file by rename, reporting events for the file's name.
    pub(super) struct Watch {
        fd: AsyncFd<OwnedFd>,
        name: Vec<u8>,
    }

    impl Watch {
        pub(super) fn new(path: &Path) -> io::Result<Watch> {
            let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
            let name = path.file_name().ok_or_else(invalid)?.as_bytes().to_vec();
            let dir = match path.parent() {
                Some(dir) if !dir.as_os_str().is_empty() => dir,
                _ => Path::new("."),
            };
            let dir = CString::new(dir.as_os_str().as_bytes()).map_err(|_| invalid())?;
            let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let wd = unsafe {
                libc::inotify_add_watch(
                    fd.as_raw_fd(),
                    dir.as_ptr(),
                    libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO,
                )
            };
            if wd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Watch {
                fd: AsyncFd::new(fd)?,
                name,
            })
        }

        /// Return after an event for the file, once events have stopped for
        /// `SETTLE`.
        pub(super) async fn changed(&self) -> io::Result<()> {
            while !self.read().await? {}
            while let Ok(read) = tokio::time::timeout(super::SETTLE, self.read()).await {
                read?;
            }
            Ok(())
        }

        /// Wait for a batch of events and report whether one names the file.
        async fn read(&self) -> io::Result<bool> {
            let mut buf = [0u8; 4096];
            loop {
                let mut guard = self.fd.readable().await?;
                let read = guard.try_io(|fd| {
                    let n =
                        unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                });
                if let Ok(n) = read {
                    return names(&buf[..n?], &self.name);
                }
            }
        }
    }

    /// Whether an event in `buf` names `name`. An overflowed queue counts as a
    /// match, since its events are lost; a removed watch is an error.
    fn names(buf: &[u8], name: &[u8]) -> io::Result<bool> {
        let field =
            |at: usize| u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        let mut hit = false;
        let mut at = 0;
        while at + HEADER <= buf.len() {
            let mask = field(at + 4);
            let len = field(at + 12) as usize;
            let raw = buf.get(at + HEADER..at + HEADER + len).unwrap_or(&[]);
            let event_name = raw.split(|&b| b == 0).next().unwrap_or(&[]);
            if mask & libc::IN_IGNORED != 0 {
                return Err(io::Error::other("the watched directory is gone"));
            }
            hit |= mask & libc::IN_Q_OVERFLOW != 0 || event_name == name;
            at += HEADER + len;
        }
        Ok(hit)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir() -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zeronat-filewatch-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An in-place write and a replace by rename both wake the watch well
    /// inside one poll interval, and a write to another file in the directory
    /// does not.
    #[tokio::test]
    async fn sees_writes_and_renames_of_the_file_only() {
        let dir = temp_dir();
        let path = dir.join("server.toml");
        std::fs::write(&path, "a").unwrap();
        let mut watch = FileWatch::new(&path);
        assert!(watch.inotify.is_some());
        let soon = POLL / 2;

        std::fs::write(dir.join("other.toml"), "x").unwrap();
        assert!(tokio::time::timeout(soon, watch.changed()).await.is_err());

        std::fs::write(&path, "b").unwrap();
        tokio::time::timeout(soon, watch.changed()).await.unwrap();

        let tmp = dir.join("server.toml.tmp");
        std::fs::write(&tmp, "c").unwrap();
        tokio::time::timeout(soon, async {
            // The temp file's own close-write names a different file, so only
            // the rename wakes the watch.
            std::fs::rename(&tmp, &path).unwrap();
            watch.changed().await;
        })
        .await
        .unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
