use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

use super::TapConfig;
use crate::Result;

// `_IOW('T', 202, int)`. MIPS uses a different `_IOC` direction encoding than the
// generic one, so the request number differs there.
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
const TUNSETIFF: u64 = 0x800454ca;
#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
const TUNSETIFF: u64 = 0x400454ca;

// SIOC* request numbers are fixed across architectures.
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCSIFMTU: u64 = 0x8922;
const SIOCGIFINDEX: u64 = 0x8933;
const SIOCBRADDIF: u64 = 0x89a2;

const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;

/// Userspace mirror of `struct ifreq`. The name is 16 bytes; the `ifru` union is
/// sized for the largest 64-bit member (24 bytes). Oversizing relative to the
/// kernel struct is safe: the kernel copies only its own size. Union members are
/// read and written unaligned because the buffer has byte alignment.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    ifru: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> Result<Self> {
        let bytes = name.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(format!("interface name too long: {name}").into());
        }
        let mut name_buf = [0 as libc::c_char; libc::IFNAMSIZ];
        for (i, b) in bytes.iter().enumerate() {
            name_buf[i] = *b as libc::c_char;
        }
        Ok(IfReq {
            name: name_buf,
            ifru: [0u8; 24],
        })
    }
    fn set_flags(&mut self, flags: i16) {
        unsafe { std::ptr::write_unaligned(self.ifru.as_mut_ptr() as *mut i16, flags) }
    }
    fn get_flags(&self) -> i16 {
        unsafe { std::ptr::read_unaligned(self.ifru.as_ptr() as *const i16) }
    }
    fn set_mtu(&mut self, mtu: i32) {
        unsafe { std::ptr::write_unaligned(self.ifru.as_mut_ptr() as *mut i32, mtu) }
    }
    fn set_ifindex(&mut self, idx: i32) {
        unsafe { std::ptr::write_unaligned(self.ifru.as_mut_ptr() as *mut i32, idx) }
    }
    fn get_ifindex(&self) -> i32 {
        unsafe { std::ptr::read_unaligned(self.ifru.as_ptr() as *const i32) }
    }
}

/// Bring the device up, set its MTU, and optionally enslave it to a bridge. Runs
/// on a throwaway `AF_INET` socket; the tun fd cannot carry these ioctls.
fn configure(name: &str, mtu: usize, bridge: Option<&str>) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let res = configure_inner(sock, name, mtu, bridge);
    unsafe { libc::close(sock) };
    res
}

fn configure_inner(sock: RawFd, name: &str, mtu: usize, bridge: Option<&str>) -> Result<()> {
    let mut ifr = IfReq::new(name)?;
    ifr.set_mtu(mtu as i32);
    if unsafe {
        libc::ioctl(
            sock,
            SIOCSIFMTU as _,
            &mut ifr as *mut IfReq as *mut libc::c_void,
        )
    } < 0
    {
        return Err(format!("SIOCSIFMTU {name}: {}", io::Error::last_os_error()).into());
    }

    let mut ifr = IfReq::new(name)?;
    if unsafe {
        libc::ioctl(
            sock,
            SIOCGIFFLAGS as _,
            &mut ifr as *mut IfReq as *mut libc::c_void,
        )
    } < 0
    {
        return Err(format!("SIOCGIFFLAGS {name}: {}", io::Error::last_os_error()).into());
    }
    let flags = ifr.get_flags() | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
    ifr.set_flags(flags);
    if unsafe {
        libc::ioctl(
            sock,
            SIOCSIFFLAGS as _,
            &mut ifr as *mut IfReq as *mut libc::c_void,
        )
    } < 0
    {
        return Err(format!("SIOCSIFFLAGS {name}: {}", io::Error::last_os_error()).into());
    }

    if let Some(br) = bridge {
        let mut ifr = IfReq::new(name)?;
        if unsafe {
            libc::ioctl(
                sock,
                SIOCGIFINDEX as _,
                &mut ifr as *mut IfReq as *mut libc::c_void,
            )
        } < 0
        {
            return Err(format!("SIOCGIFINDEX {name}: {}", io::Error::last_os_error()).into());
        }
        let idx = ifr.get_ifindex();
        let mut brifr = IfReq::new(br)?;
        brifr.set_ifindex(idx);
        if unsafe {
            libc::ioctl(
                sock,
                SIOCBRADDIF as _,
                &mut brifr as *mut IfReq as *mut libc::c_void,
            )
        } < 0
        {
            return Err(
                format!("SIOCBRADDIF {br} <- {name}: {}", io::Error::last_os_error()).into(),
            );
        }
    }
    Ok(())
}

/// Owns the tun fd and closes it on drop.
struct TunFd(RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for TunFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// An attached TAP device. Frames are read and written whole: the device is
/// opened with `IFF_NO_PI`, so one read is one Ethernet frame and one write sends
/// one frame. `read_frame`/`write_frame` take `&self` so a single device can be
/// driven from both arms of a `select!` and shared across reconnects via `Arc`.
pub struct TapDevice {
    fd: AsyncFd<TunFd>,
    mtu: usize,
}

impl TapDevice {
    /// Open `/dev/net/tun`, attach (creating it if absent) the named TAP, bring it
    /// up, set its MTU, and optionally enslave it to an existing bridge.
    pub fn open(cfg: &TapConfig) -> Result<Self> {
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(format!("open /dev/net/tun: {}", io::Error::last_os_error()).into());
        }
        let mut ifr = match IfReq::new(&cfg.name) {
            Ok(r) => r,
            Err(e) => {
                unsafe { libc::close(fd) };
                return Err(e);
            }
        };
        ifr.set_flags(IFF_TAP | IFF_NO_PI);
        if unsafe {
            libc::ioctl(
                fd,
                TUNSETIFF as _,
                &mut ifr as *mut IfReq as *mut libc::c_void,
            )
        } < 0
        {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("TUNSETIFF {}: {e}", cfg.name).into());
        }
        if let Err(e) = configure(&cfg.name, cfg.mtu, cfg.bridge.as_deref()) {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Self::from_raw(fd, cfg.mtu)
    }

    fn from_raw(fd: RawFd, mtu: usize) -> Result<Self> {
        Ok(TapDevice {
            fd: AsyncFd::new(TunFd(fd))?,
            mtu,
        })
    }

    pub async fn read_frame(&self) -> Result<Vec<u8>> {
        loop {
            let mut guard = self.fd.readable().await?;
            let mut buf = vec![0u8; self.mtu + 64];
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_frame(&self, frame: &[u8]) -> Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        frame.as_ptr() as *const libc::c_void,
                        frame.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) if n == frame.len() => return Ok(()),
                Ok(Ok(n)) => return Err(format!("short tap write: {n}/{}", frame.len()).into()),
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunsetiff_constant_for_host_arch() {
        // The build/test host is not MIPS, so the generic encoding applies.
        assert_eq!(TUNSETIFF, 0x400454ca);
    }

    #[test]
    fn ifreq_layout() {
        assert_eq!(std::mem::size_of::<IfReq>(), libc::IFNAMSIZ + 24);
        let mut ifr = IfReq::new("zn0").unwrap();
        assert_eq!(ifr.name[0], b'z' as libc::c_char);
        assert_eq!(ifr.name[1], b'n' as libc::c_char);
        assert_eq!(ifr.name[2], b'0' as libc::c_char);
        assert_eq!(ifr.name[3], 0);
        ifr.set_flags(IFF_TAP | IFF_NO_PI);
        assert_eq!(ifr.get_flags(), IFF_TAP | IFF_NO_PI);
        ifr.set_ifindex(42);
        assert_eq!(ifr.get_ifindex(), 42);
    }

    #[test]
    fn name_too_long_rejected() {
        assert!(IfReq::new("0123456789abcdef").is_err());
    }

    fn nonblocking_dgram_socketpair() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed");
        for fd in fds {
            let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
        }
        (fds[0], fds[1])
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn frame_roundtrip_over_socketpair() {
        let (a, b) = nonblocking_dgram_socketpair();
        let ta = TapDevice::from_raw(a, 1400).unwrap();
        let tb = TapDevice::from_raw(b, 1400).unwrap();
        ta.write_frame(b"hello-frame").await.unwrap();
        let got = tb.read_frame().await.unwrap();
        assert_eq!(got, b"hello-frame");
    }
}
