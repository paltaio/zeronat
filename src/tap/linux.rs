use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

use super::{TapConfig, TunConfig};
use crate::Result;

// `_IOW('T', 202, int)`. MIPS uses a different `_IOC` direction encoding than the
// generic one, so the request number differs there.
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
const TUNSETIFF: u64 = 0x800454ca;
#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
const TUNSETIFF: u64 = 0x400454ca;

// SIOC* request numbers are fixed across architectures.
const SIOCSIFADDR: u64 = 0x8916;
const SIOCSIFNETMASK: u64 = 0x891c;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCSIFMTU: u64 = 0x8922;
const SIOCGIFMTU: u64 = 0x8921;
const SIOCGIFINDEX: u64 = 0x8933;
const SIOCBRADDIF: u64 = 0x89a2;

const IFF_TUN: i16 = 0x0001;
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;

/// The `/24`-style mask for a prefix length, as an address. `prefix_len` is
/// clamped to 32; a prefix of 0 yields `0.0.0.0`.
fn netmask_from_prefix(prefix_len: u8) -> Ipv4Addr {
    let bits = prefix_len.min(32);
    let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Ipv4Addr::from(mask)
}

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
    fn get_mtu(&self) -> i32 {
        unsafe { std::ptr::read_unaligned(self.ifru.as_ptr() as *const i32) }
    }
    fn set_ifindex(&mut self, idx: i32) {
        unsafe { std::ptr::write_unaligned(self.ifru.as_mut_ptr() as *mut i32, idx) }
    }
    fn get_ifindex(&self) -> i32 {
        unsafe { std::ptr::read_unaligned(self.ifru.as_ptr() as *const i32) }
    }
    /// Write a `sockaddr_in` for `addr` into the `ifru` union, for the address and
    /// netmask ioctls. Layout: `sin_family` (u16, host order), `sin_port` (u16,
    /// unused), `sin_addr` (4 octets, network order), then zero padding.
    fn set_sockaddr_in(&mut self, addr: Ipv4Addr) {
        self.ifru = [0u8; 24];
        unsafe {
            std::ptr::write_unaligned(self.ifru.as_mut_ptr() as *mut u16, libc::AF_INET as u16);
        }
        self.ifru[4..8].copy_from_slice(&addr.octets());
    }
}

/// Run one `ifreq` ioctl on `sock`, mapping a kernel error to a labeled `Err`.
fn ioctl_ifr(sock: RawFd, req: u64, ifr: &mut IfReq, label: &str) -> Result<()> {
    if unsafe { libc::ioctl(sock, req as _, ifr as *mut IfReq as *mut libc::c_void) } < 0 {
        return Err(format!("{label}: {}", io::Error::last_os_error()).into());
    }
    Ok(())
}

fn set_mtu_ioctl(sock: RawFd, name: &str, mtu: usize) -> Result<()> {
    let mut ifr = IfReq::new(name)?;
    ifr.set_mtu(mtu as i32);
    ioctl_ifr(sock, SIOCSIFMTU, &mut ifr, &format!("SIOCSIFMTU {name}"))
}

fn get_mtu_ioctl(sock: RawFd, name: &str) -> Result<i32> {
    let mut ifr = IfReq::new(name)?;
    ioctl_ifr(sock, SIOCGIFMTU, &mut ifr, &format!("SIOCGIFMTU {name}"))?;
    Ok(ifr.get_mtu())
}

/// Bring the interface up and mark it running.
fn bring_up(sock: RawFd, name: &str) -> Result<()> {
    let mut ifr = IfReq::new(name)?;
    ioctl_ifr(sock, SIOCGIFFLAGS, &mut ifr, &format!("SIOCGIFFLAGS {name}"))?;
    let flags = ifr.get_flags() | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
    ifr.set_flags(flags);
    ioctl_ifr(sock, SIOCSIFFLAGS, &mut ifr, &format!("SIOCSIFFLAGS {name}"))
}

/// Bring an L2 TAP up, set its MTU, and optionally enslave it to a bridge. Runs
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
    set_mtu_ioctl(sock, name, mtu)?;
    bring_up(sock, name)?;

    if let Some(br) = bridge {
        // Enslaving a smaller-MTU TAP makes the kernel drop the bridge to the
        // minimum member MTU, even when the bridge MTU was set explicitly. Capture
        // the bridge MTU and restore it after the enslave so the host's own traffic
        // on the bridge keeps its full MTU (the smaller TAP port stays at its MTU).
        let br_mtu = get_mtu_ioctl(sock, br).ok();
        let mut ifr = IfReq::new(name)?;
        ioctl_ifr(sock, SIOCGIFINDEX, &mut ifr, &format!("SIOCGIFINDEX {name}"))?;
        let idx = ifr.get_ifindex();
        let mut brifr = IfReq::new(br)?;
        brifr.set_ifindex(idx);
        ioctl_ifr(
            sock,
            SIOCBRADDIF,
            &mut brifr,
            &format!("SIOCBRADDIF {br} <- {name}"),
        )?;
        if let Some(m) = br_mtu {
            let _ = set_mtu_ioctl(sock, br, m as usize);
        }
    }
    Ok(())
}

/// Assign an L3 TUN's address and netmask, set its MTU, and bring it up. Runs on
/// a throwaway `AF_INET` socket; the tun fd cannot carry these ioctls.
fn configure_tun(name: &str, mtu: usize, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let res = (|| {
        let mut ifr = IfReq::new(name)?;
        ifr.set_sockaddr_in(addr);
        ioctl_ifr(sock, SIOCSIFADDR, &mut ifr, &format!("SIOCSIFADDR {name}"))?;
        let mut ifr = IfReq::new(name)?;
        ifr.set_sockaddr_in(netmask);
        ioctl_ifr(
            sock,
            SIOCSIFNETMASK,
            &mut ifr,
            &format!("SIOCSIFNETMASK {name}"),
        )?;
        set_mtu_ioctl(sock, name, mtu)?;
        bring_up(sock, name)
    })();
    unsafe { libc::close(sock) };
    res
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

/// An attached tun/tap device (`open` for L2 TAP, `open_tun` for L3 TUN). Frames
/// are read and written whole: the device is opened with `IFF_NO_PI`, so one read
/// is one Ethernet frame (TAP) or one IP packet (TUN) and one write sends one.
/// `read_frame`/`write_frame` take `&self` so a single device can be driven from
/// both arms of a `select!` and shared across reconnects via `Arc`.
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

    /// Open `/dev/net/tun`, attach (creating it if absent) the named TUN, assign
    /// its address/netmask, set its MTU, and bring it up. A TUN read is one whole
    /// IP packet; the same `read_frame`/`write_frame` path as TAP carries it.
    pub fn open_tun(cfg: &TunConfig) -> Result<Self> {
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
        ifr.set_flags(IFF_TUN | IFF_NO_PI);
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
        let netmask = netmask_from_prefix(cfg.prefix_len);
        if let Err(e) = configure_tun(&cfg.name, cfg.mtu, cfg.addr, netmask) {
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

    /// Build a device backed by one end of a non-blocking `socketpair` for tests
    /// that need a real `read_frame`/`write_frame`-capable device without a kernel
    /// TAP or root. `read_frame` blocks until the peer end is written; `write_frame`
    /// succeeds into the socket buffer. The peer fd is returned so the test can
    /// inject inbound frames and drain egress.
    #[cfg(test)]
    pub(crate) fn socketpair_for_test(mtu: usize) -> Result<(Self, RawFd)> {
        let mut fds = [0 as RawFd; 2];
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error().into());
        }
        match Self::from_raw(fds[0], mtu) {
            Ok(dev) => Ok((dev, fds[1])),
            // `from_raw` owns `fds[0]` (its Drop closes it); close the peer so a
            // device-build failure does not leak the other half.
            Err(e) => {
                unsafe { libc::close(fds[1]) };
                Err(e)
            }
        }
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
        ifr.set_mtu(1400);
        assert_eq!(ifr.get_mtu(), 1400);
    }

    #[test]
    fn name_too_long_rejected() {
        assert!(IfReq::new("0123456789abcdef").is_err());
    }

    #[test]
    fn netmask_from_prefix_values() {
        assert_eq!(netmask_from_prefix(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(netmask_from_prefix(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(netmask_from_prefix(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(netmask_from_prefix(0), Ipv4Addr::new(0, 0, 0, 0));
        // Out-of-range prefixes clamp instead of panicking on the shift.
        assert_eq!(netmask_from_prefix(33), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn sockaddr_in_layout() {
        let mut ifr = IfReq::new("zn0").unwrap();
        ifr.set_sockaddr_in(Ipv4Addr::new(10, 7, 9, 1));
        // sin_family = AF_INET in host byte order at offset 0.
        let fam = unsafe { std::ptr::read_unaligned(ifr.ifru.as_ptr() as *const u16) };
        assert_eq!(fam, libc::AF_INET as u16);
        // sin_port (offset 2) unused; sin_addr (offset 4) holds the octets.
        assert_eq!(&ifr.ifru[2..4], &[0, 0]);
        assert_eq!(&ifr.ifru[4..8], &[10, 7, 9, 1]);
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
