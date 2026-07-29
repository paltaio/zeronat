//! Source pinning for replies on a UDP socket that answers on many local
//! addresses.
//!
//! A socket bound to the wildcard address answers from whatever source the
//! route table picks for the destination, which is not the address the request
//! was sent to whenever the two differ: an anycast or secondary address, a
//! loopback alias, or a public address DNATed to the host. A peer whose socket
//! is connected to the address it dialed drops every reply from another source.
//! Recording the local address each datagram arrived on and sending the reply
//! with it pins the source to the address the peer dialed.
//!
//! The mechanism is `IP_PKTINFO`/`IPV6_RECVPKTINFO`, so it is Linux only. On
//! every other platform the local address is never reported and replies keep the
//! kernel's own source selection.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;

/// The local address a datagram was delivered to, plus the interface it arrived
/// on. [`recv_from`] reports one; handing it back to [`send_to`] pins that
/// reply's source address.
#[derive(Clone, Copy)]
pub struct LocalAddr {
    pub ip: IpAddr,
    pub ifindex: u32,
}

/// Ask the kernel to report the local address of every datagram received on
/// `sock`, which is what makes [`recv_from`] able to report one.
#[cfg(target_os = "linux")]
pub fn record_local_addr(sock: &UdpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let (level, opt) = if sock.local_addr()?.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    };
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            std::ptr::addr_of!(on).cast(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn record_local_addr(_sock: &UdpSocket) -> io::Result<()> {
    Ok(())
}

/// Receive one datagram, reporting the source it came from and the local address
/// it was delivered to.
#[cfg(target_os = "linux")]
pub async fn recv_from(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<LocalAddr>)> {
    loop {
        sock.readable().await?;
        match sock.try_io(tokio::io::Interest::READABLE, || recvmsg(sock, buf)) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            other => return other,
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn recv_from(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<LocalAddr>)> {
    let (n, src) = sock.recv_from(buf).await?;
    Ok((n, src, None))
}

/// Send one datagram to `dst`, from `local` when it is known. A `local` the
/// kernel refuses is dropped for this send and the datagram goes out with the
/// kernel's own source selection.
#[cfg(target_os = "linux")]
pub async fn send_to(
    sock: &UdpSocket,
    buf: &[u8],
    dst: SocketAddr,
    local: Option<LocalAddr>,
) -> io::Result<usize> {
    let Some(local) = local else {
        return sock.send_to(buf, dst).await;
    };
    loop {
        sock.writable().await?;
        match sock.try_io(tokio::io::Interest::WRITABLE, || {
            sendmsg(sock, buf, dst, local)
        }) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if source_refused(&e) => return sock.send_to(buf, dst).await,
            other => return other,
        }
    }
}

/// Whether a `sendmsg` error says the pinned source is no longer an address the
/// host can send from: an anycast or secondary address withdrawn, or the
/// interface holding it taken down. An unpinned send still succeeds, so the
/// caller retries without the pin instead of losing the datagram and leaving the
/// session silent until it is torn down.
#[cfg(target_os = "linux")]
fn source_refused(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENETUNREACH | libc::EINVAL | libc::EADDRNOTAVAIL)
    )
}

#[cfg(not(target_os = "linux"))]
pub async fn send_to(
    sock: &UdpSocket,
    buf: &[u8],
    dst: SocketAddr,
    _local: Option<LocalAddr>,
) -> io::Result<usize> {
    sock.send_to(buf, dst).await
}

/// Room for one pktinfo control message, aligned for `cmsghdr`.
#[cfg(target_os = "linux")]
type ControlBuf = [u64; 8];

#[cfg(target_os = "linux")]
fn recvmsg(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<LocalAddr>)> {
    use std::os::unix::io::AsRawFd;

    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut control: ControlBuf = [0; 8];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = std::ptr::addr_of_mut!(name).cast();
    hdr.msg_namelen = std::mem::size_of_val(&name) as libc::socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr().cast();
    hdr.msg_controllen = std::mem::size_of_val(&control) as _;

    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut hdr, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let src = from_sockaddr(&name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported source address family",
        )
    })?;
    Ok((n as usize, src, unsafe { local_addr(&hdr) }))
}

/// The local address carried in a received message's control data. A multicast
/// or unspecified destination is no usable reply source, so it reports `None`
/// and the reply falls back to the kernel's source selection.
#[cfg(target_os = "linux")]
unsafe fn local_addr(hdr: &libc::msghdr) -> Option<LocalAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut cmsg = libc::CMSG_FIRSTHDR(hdr);
    while !cmsg.is_null() {
        let found = match ((*cmsg).cmsg_level, (*cmsg).cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => read_cmsg_data::<libc::in_pktinfo>(hdr, cmsg)
                .map(|info| LocalAddr {
                    ip: IpAddr::V4(Ipv4Addr::from(info.ipi_spec_dst.s_addr.to_ne_bytes())),
                    ifindex: info.ipi_ifindex as u32,
                }),
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                read_cmsg_data::<libc::in6_pktinfo>(hdr, cmsg).map(|info| LocalAddr {
                    ip: IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                    ifindex: info.ipi6_ifindex,
                })
            }
            _ => None,
        };
        if let Some(local) = found {
            if local.ip.is_multicast() || local.ip.is_unspecified() {
                return None;
            }
            return Some(local);
        }
        cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
    }
    None
}

/// Copy a control message's payload out, or `None` when `cmsg_len` leaves less
/// room after the header than a `T` needs, or when the payload would run past
/// the end of the control buffer: `CMSG_NXTHDR` only vouches for the next
/// header fitting, not for the length that header claims. `CMSG_DATA` has no
/// alignment guarantee of its own, so the payload is read as bytes rather than
/// dereferenced in place.
#[cfg(target_os = "linux")]
unsafe fn read_cmsg_data<T>(hdr: &libc::msghdr, cmsg: *const libc::cmsghdr) -> Option<T> {
    // `cmsg_len` and `msg_controllen` are `size_t` against glibc and `socklen_t`
    // against musl.
    #[allow(clippy::unnecessary_cast)]
    let (cmsg_len, controllen) = ((*cmsg).cmsg_len as usize, hdr.msg_controllen as usize);
    if cmsg_len < libc::CMSG_LEN(std::mem::size_of::<T>() as u32) as usize {
        return None;
    }
    let end = (hdr.msg_control as *const u8).addr() + controllen;
    if libc::CMSG_DATA(cmsg).addr() + std::mem::size_of::<T>() > end {
        return None;
    }
    let mut value = std::mem::MaybeUninit::<T>::zeroed();
    std::ptr::copy_nonoverlapping(
        libc::CMSG_DATA(cmsg),
        value.as_mut_ptr().cast(),
        std::mem::size_of::<T>(),
    );
    Some(value.assume_init())
}

#[cfg(target_os = "linux")]
fn sendmsg(sock: &UdpSocket, buf: &[u8], dst: SocketAddr, local: LocalAddr) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;

    let (mut name, namelen) = to_sockaddr(dst);
    let mut control: ControlBuf = [0; 8];
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = std::ptr::addr_of_mut!(name).cast();
    hdr.msg_namelen = namelen;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr().cast();

    // The source address rides in a pktinfo control message: an interface index
    // of zero on v4 leaves the route lookup to pick the device and pins only the
    // source, while v6 needs the arrival interface to scope a link-local source.
    unsafe {
        match local.ip {
            IpAddr::V4(ip) => {
                let info = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(ip.octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                write_cmsg(&mut hdr, libc::IPPROTO_IP, libc::IP_PKTINFO, &info);
            }
            IpAddr::V6(ip) => {
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: ip.octets(),
                    },
                    ipi6_ifindex: local.ifindex,
                };
                write_cmsg(&mut hdr, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &info);
            }
        }
    }

    let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &hdr, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Write one control message of `value` into `hdr`'s control buffer and set the
/// control length to what it occupies. The caller must have pointed
/// `msg_control` at a buffer of at least `CMSG_SPACE(size_of::<T>())` bytes.
#[cfg(target_os = "linux")]
unsafe fn write_cmsg<T>(hdr: &mut libc::msghdr, level: libc::c_int, ty: libc::c_int, value: &T) {
    hdr.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<T>() as u32) as _;
    let cmsg = libc::CMSG_FIRSTHDR(hdr);
    (*cmsg).cmsg_level = level;
    (*cmsg).cmsg_type = ty;
    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<T>() as u32) as _;
    std::ptr::copy_nonoverlapping(
        std::ptr::addr_of!(*value).cast(),
        libc::CMSG_DATA(cmsg),
        std::mem::size_of::<T>(),
    );
}

#[cfg(target_os = "linux")]
fn to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in>();
            unsafe {
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = a.port().to_be();
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in6>();
            unsafe {
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = a.port().to_be();
                (*sin6).sin6_addr.s6_addr = a.ip().octets();
                (*sin6).sin6_flowinfo = a.flowinfo();
                (*sin6).sin6_scope_id = a.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}

#[cfg(target_os = "linux")]
fn from_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { *std::ptr::addr_of!(*storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { *std::ptr::addr_of!(*storage).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A wildcard-bound socket answers a peer that dialed a secondary loopback
    /// address. The route back to the peer selects 127.0.0.1 as the source, so
    /// without the recorded local address the reply reaches a socket connected
    /// to 127.0.0.2 from the wrong address and the kernel drops it.
    #[tokio::test]
    async fn reply_leaves_from_the_dialed_address() {
        let server = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        record_local_addr(&server).unwrap();
        let port = server.local_addr().unwrap().port();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(("127.0.0.2", port)).await.unwrap();
        client.send(b"ping").await.unwrap();

        let mut buf = [0u8; 64];
        let (n, src, local) = recv_from(&server, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(
            local.map(|l| l.ip),
            Some("127.0.0.2".parse().unwrap()),
            "the local address the datagram arrived on must be reported"
        );

        send_to(&server, b"pong", src, local).await.unwrap();
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("a reply from the dialed address reaches a connected socket")
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    /// A source the host can no longer send from (a withdrawn anycast address, a
    /// downed interface) makes the kernel refuse the pinned send outright. The
    /// datagram still has to go out, so it leaves with the kernel's own source
    /// selection instead of being lost until the session is reaped.
    #[tokio::test]
    async fn a_refused_source_falls_back_to_the_kernel_pick() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gone = LocalAddr {
            ip: "192.0.2.1".parse().unwrap(),
            ifindex: 0,
        };

        let dst = client.local_addr().unwrap();
        send_to(&server, b"pong", dst, Some(gone)).await.unwrap();

        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("a datagram whose pinned source is refused still goes out")
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }
}
