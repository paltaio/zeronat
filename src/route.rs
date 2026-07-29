//! Linux IPv4 route table access: reads routes from `/proc/net/route` and adds
//! or deletes them with `rtentry` + `SIOCADDRT`/`SIOCDELRT` ioctls on a
//! throwaway `AF_INET` socket, so the `FROM scratch` production images need no
//! `ip`/`iptables`/`nft`. The parsing layer is unit-tested without touching the
//! host; the ioctl layer is operator-validated.

use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

/// The original default route captured before any mutation, so revert can put it
/// back exactly. `metric` is kept only to break ties when several defaults exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedDefault {
    pub gateway: Ipv4Addr,
    pub iface: String,
    pub metric: u32,
}

/// Parse `/proc/net/route` and return the active IPv4 default route: the row with
/// a zero destination and mask and the `RTF_GATEWAY` flag, excluding `tun_name`,
/// choosing the lowest metric (ties broken by file order).
///
/// `/proc/net/route` is whitespace-separated with a header line; the address
/// columns are little-endian hex. Fields are indexed only after a row-length
/// guard and parsed with a checked radix parse, so a short or malformed row is
/// skipped rather than panicking (the release profile is panic=abort).
pub fn parse_proc_route(contents: &str, tun_name: &str) -> Option<CapturedDefault> {
    parse_default(contents, tun_name, true)
}

/// The interface carrying the active IPv4 default route, excluding `skip_iface`.
/// Unlike `parse_proc_route` this accepts a gatewayless default too, so a
/// point-to-point uplink (a ppp interface with `RTF_UP` and gateway zero) is
/// found as the egress interface.
pub fn default_route_iface(contents: &str, skip_iface: &str) -> Option<String> {
    parse_default(contents, skip_iface, false).map(|d| d.iface)
}

/// Every active IPv4 default route excluding `skip_iface`, in file order:
/// each dest==0/mask==0 row, gatewayless ones included. Strict exit captures
/// the whole set, so a second default at a worse metric does not survive the
/// delete.
pub fn parse_all_defaults(contents: &str, skip_iface: &str) -> Vec<CapturedDefault> {
    scan_defaults(contents, skip_iface, false)
}

/// The single-row default lookup: the lowest metric wins, ties broken by
/// file order. `require_gateway` keeps the pppoe capture strict (a captured
/// original must be restorable via its gateway) while the interface lookup
/// takes any dest==0/mask==0 row.
fn parse_default(
    contents: &str,
    skip_iface: &str,
    require_gateway: bool,
) -> Option<CapturedDefault> {
    scan_defaults(contents, skip_iface, require_gateway)
        .into_iter()
        .min_by_key(|d| d.metric)
}

/// The shared default-route scan: every dest==0/mask==0 row excluding
/// `skip_iface`, in file order.
fn scan_defaults(contents: &str, skip_iface: &str, require_gateway: bool) -> Vec<CapturedDefault> {
    let mut rows = Vec::new();
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        if f.len() < 11 {
            continue;
        }
        let iface = f[0];
        if iface == skip_iface {
            continue;
        }
        let (dest, flags, metric, mask) = match (
            u32::from_str_radix(f[1], 16),
            u32::from_str_radix(f[3], 16),
            f[6].parse::<u32>(),
            u32::from_str_radix(f[7], 16),
        ) {
            (Ok(d), Ok(fl), Ok(m), Ok(mk)) => (d, fl, m, mk),
            _ => continue,
        };
        if dest != 0 || mask != 0 {
            continue;
        }
        if require_gateway && (flags & RTF_GATEWAY_BITS) == 0 {
            continue;
        }
        let gateway = le_hex_to_ipv4(match u32::from_str_radix(f[2], 16) {
            Ok(g) => g,
            Err(_) => continue,
        });
        rows.push(CapturedDefault {
            gateway,
            iface: iface.to_string(),
            metric,
        });
    }
    rows
}

/// Whether any route in `contents` reaches `addr` more specifically than the
/// `/1` half-defaults do, excluding `skip_iface`. A connected LAN prefix or a
/// host route already wins over a half-default on prefix length, and a `/32`
/// pin through the default gateway would displace it.
pub fn covered_beyond_half(contents: &str, skip_iface: &str, addr: Ipv4Addr) -> bool {
    let target = u32::from_be_bytes(addr.octets());
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        if f.len() < 11 {
            continue;
        }
        if f[0] == skip_iface {
            continue;
        }
        let (dest, mask) = match (u32::from_str_radix(f[1], 16), u32::from_str_radix(f[7], 16)) {
            (Ok(d), Ok(m)) => (
                u32::from_be_bytes(le_hex_to_ipv4(d).octets()),
                u32::from_be_bytes(le_hex_to_ipv4(m).octets()),
            ),
            _ => continue,
        };
        if mask.leading_ones() > 1 && target & mask == dest {
            return true;
        }
    }
    false
}

/// `RTF_GATEWAY` as it appears in the `/proc/net/route` Flags column.
const RTF_GATEWAY_BITS: u32 = 0x0002;

/// Decode a `/proc/net/route` little-endian hex address into an `Ipv4Addr`. The
/// column `0150A8C0` is `192.168.80.1`: byte-reversed network order.
fn le_hex_to_ipv4(le: u32) -> Ipv4Addr {
    let b = le.to_le_bytes();
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

/// Read and parse the host's current IPv4 default route from `/proc/net/route`.
pub fn read_default_route(tun_name: &str) -> Option<CapturedDefault> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_proc_route(&contents, tun_name)
}

// SIOCADDRT/SIOCDELRT and the RTF_* flags are stable across architectures; libc
// exposes them and `rtentry` for both glibc and musl.

/// Build a `sockaddr` carrying an IPv4 address (family + address, port zero).
fn sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    };
    // `sockaddr_in` and `sockaddr` are both 16-byte `repr(C)`; the kernel reads the
    // route addresses as `sockaddr` and dispatches on `sa_family`.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) }
}

/// The netmask address for a prefix length: `/0` -> `0.0.0.0`, `/32` ->
/// `255.255.255.255`.
fn netmask(prefix: u8) -> Ipv4Addr {
    let bits = prefix.min(32);
    let mask: u32 = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Ipv4Addr::from(mask)
}

/// Add or delete one route via `SIOCADDRT`/`SIOCDELRT` on a throwaway `AF_INET`
/// socket. `gw` set adds the `RTF_GATEWAY` flag; `prefix == 32` adds `RTF_HOST`;
/// `dev` scopes the route to an interface (required for a gateway-less
/// device default). `priority` is the route's fib priority (the `/proc/net/route`
/// Metric column), so the original default is deleted and restored at its real
/// metric on a multi-homed host. The interface `CString` is built before the
/// socket (so an interior-NUL error cannot leak the fd) and held until after the
/// ioctl so `rt_dev` stays valid.
pub fn modify_route(
    add: bool,
    dst: Ipv4Addr,
    prefix: u8,
    gw: Option<Ipv4Addr>,
    dev: Option<&str>,
    priority: u32,
) -> crate::Result<()> {
    let dev_c = match dev {
        Some(d) => Some(CString::new(d).map_err(|_| -> crate::Error {
            format!("interface name has interior NUL: {d}").into()
        })?),
        None => None,
    };
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let res = modify_route_inner(sock, add, dst, prefix, gw, dev_c.as_deref(), priority);
    unsafe { libc::close(sock) };
    res
}

fn modify_route_inner(
    sock: RawFd,
    add: bool,
    dst: Ipv4Addr,
    prefix: u8,
    gw: Option<Ipv4Addr>,
    dev: Option<&std::ffi::CStr>,
    priority: u32,
) -> crate::Result<()> {
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = sockaddr_in(dst);
    rt.rt_genmask = sockaddr_in(netmask(prefix));
    // The kernel derives the fib priority as rt_metric - 1 for a nonzero rt_metric,
    // so a route at priority P is addressed with rt_metric = P + 1. Without this the
    // delete of a non-zero-metric original default would not match it (the kernel
    // keys on prefix + priority + gw + oif) and revert would restore it at metric 0.
    rt.rt_metric = priority.saturating_add(1).min(i16::MAX as u32) as libc::c_short;
    let mut flags = libc::RTF_UP as libc::c_ushort;
    if let Some(g) = gw {
        rt.rt_gateway = sockaddr_in(g);
        flags |= libc::RTF_GATEWAY as libc::c_ushort;
    }
    if prefix == 32 {
        flags |= libc::RTF_HOST as libc::c_ushort;
    }
    rt.rt_flags = flags;
    if let Some(d) = dev {
        rt.rt_dev = d.as_ptr() as *mut libc::c_char;
    }
    let req = if add {
        libc::SIOCADDRT
    } else {
        libc::SIOCDELRT
    };
    if unsafe {
        libc::ioctl(
            sock,
            req as _,
            &rt as *const libc::rtentry as *mut libc::c_void,
        )
    } < 0
    {
        let os = io::Error::last_os_error();
        let op = if add { "SIOCADDRT" } else { "SIOCDELRT" };
        // Wrapped as an io::Error so callers can match the kind (an
        // already-present route adds as AlreadyExists).
        return Err(Box::new(io::Error::new(
            os.kind(),
            format!("{op} {dst}/{prefix}: {os}"),
        )));
    }
    Ok(())
}

/// The kernel's `struct in6_rtmsg`, the request `SIOCADDRT`/`SIOCDELRT` reads
/// on an `AF_INET6` socket; declared here because libc keeps its fields
/// private.
#[repr(C)]
struct In6Rtmsg {
    dst: libc::in6_addr,
    _src: libc::in6_addr,
    _gateway: libc::in6_addr,
    _type: u32,
    dst_len: u16,
    _src_len: u16,
    _metric: u32,
    _info: libc::c_ulong,
    flags: u32,
    _ifindex: libc::c_int,
}

/// Whether a failed `AF_INET6` socket open means the host has no IPv6 stack.
fn no_ipv6_stack(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

/// Add or delete an IPv6 route via `SIOCADDRT`/`SIOCDELRT` on a throwaway
/// `AF_INET6` socket. The route is bound to no device and asks for
/// `RTF_REJECT`, which this ioctl cannot express: it lands on loopback, so a
/// send to a covered address fails on the host with `ENETUNREACH` and never
/// reaches the uplink. The zero metric adds at the kernel's default priority
/// and deletes at any. A host without an IPv6 stack has nothing to route
/// away, so `EAFNOSUPPORT` from the socket open is success for add and
/// delete alike.
pub fn modify_route6(add: bool, dst: Ipv6Addr, prefix: u8) -> crate::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        let os = io::Error::last_os_error();
        if no_ipv6_stack(&os) {
            return Ok(());
        }
        return Err(os.into());
    }
    let res = modify_route6_inner(sock, add, dst, prefix);
    unsafe { libc::close(sock) };
    res
}

fn modify_route6_inner(sock: RawFd, add: bool, dst: Ipv6Addr, prefix: u8) -> crate::Result<()> {
    let mut rt: In6Rtmsg = unsafe { std::mem::zeroed() };
    rt.dst = libc::in6_addr {
        s6_addr: dst.octets(),
    };
    rt.dst_len = prefix as u16;
    rt.flags = libc::RTF_UP as u32 | libc::RTF_REJECT as u32;
    let req = if add {
        libc::SIOCADDRT
    } else {
        libc::SIOCDELRT
    };
    if unsafe { libc::ioctl(sock, req as _, &rt as *const In6Rtmsg as *mut libc::c_void) } < 0 {
        let os = io::Error::last_os_error();
        let op = if add { "SIOCADDRT" } else { "SIOCDELRT" };
        return Err(Box::new(io::Error::new(
            os.kind(),
            format!("{op} {dst}/{prefix}: {os}"),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // One header line plus a default via 192.168.80.1 on eth0 and a connected
    // route. Gateway 0150A8C0 is little-endian 192.168.80.1; Flags 0003 is
    // RTF_UP|RTF_GATEWAY; the connected row has gateway 0 and Flags 0001.
    const PROC_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    // A point-to-point uplink: the default sits on ppp0 with RTF_UP only and a
    // zero gateway, plus a connected route on eth0.
    const PPP_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn parses_default_with_le_gateway() {
        let d = parse_proc_route(PROC_ROUTE, "zppp0").unwrap();
        assert_eq!(d.gateway, Ipv4Addr::new(192, 168, 80, 1));
        assert_eq!(d.iface, "eth0");
        assert_eq!(d.metric, 100);
    }

    #[test]
    fn lowest_metric_default_wins() {
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0
wlan0\t00000000\t0250A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0
";
        let d = parse_proc_route(routes, "zppp0").unwrap();
        assert_eq!(d.iface, "wlan0");
        assert_eq!(d.gateway, Ipv4Addr::new(192, 168, 80, 2));
        assert_eq!(d.metric, 50);
    }

    #[test]
    fn skips_tun_own_default() {
        // A default already on the tun must never be captured as the original.
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
zppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
";
        assert!(parse_proc_route(routes, "zppp0").is_none());
    }

    #[test]
    fn ignores_non_gateway_and_non_default_rows() {
        // A connected route (no RTF_GATEWAY) and a host route are not defaults.
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth0\t0150A8C0\t00000000\t0005\t0\t0\t100\tFFFFFFFF\t0\t0\t0
";
        assert!(parse_proc_route(routes, "zppp0").is_none());
    }

    #[test]
    fn gatewayless_default_is_not_captured_but_resolves_iface() {
        // The pppoe capture needs a gateway to restore the route later, so a
        // ppp default is skipped; the egress interface lookup accepts it.
        assert!(parse_proc_route(PPP_ROUTE, "zppp0").is_none());
        assert_eq!(
            default_route_iface(PPP_ROUTE, "zppp0").as_deref(),
            Some("ppp0")
        );
    }

    #[test]
    fn all_defaults_keeps_every_row_and_skips_the_tun() {
        // Two gateway defaults, a gatewayless one, the tun's own default, and
        // a connected route: the capture keeps the three uplink defaults in
        // file order and nothing else.
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0250A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
zn0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        let all = parse_all_defaults(routes, "zn0");
        assert_eq!(
            all,
            [
                CapturedDefault {
                    gateway: Ipv4Addr::new(192, 168, 80, 1),
                    iface: "eth0".into(),
                    metric: 100,
                },
                CapturedDefault {
                    gateway: Ipv4Addr::new(192, 168, 80, 2),
                    iface: "wlan0".into(),
                    metric: 600,
                },
                CapturedDefault {
                    gateway: Ipv4Addr::UNSPECIFIED,
                    iface: "ppp0".into(),
                    metric: 0,
                },
            ]
        );
        assert!(parse_all_defaults("", "zn0").is_empty());
    }

    #[test]
    fn cover_takes_prefixes_longer_than_a_half_default() {
        // A default, a connected /24, a host route and a `128.0.0.0/1`: only
        // the middle two reach an address better than a half-default does.
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth0\t076433C6\t00000000\t0005\t0\t0\t100\tFFFFFFFF\t0\t0\t0
eth0\t00000080\t00000000\t0001\t0\t0\t100\t00000080\t0\t0\t0
";
        assert!(covered_beyond_half(
            routes,
            "zn0",
            Ipv4Addr::new(192, 168, 80, 23)
        ));
        assert!(covered_beyond_half(
            routes,
            "zn0",
            Ipv4Addr::new(198, 51, 100, 7)
        ));
        assert!(!covered_beyond_half(
            routes,
            "zn0",
            Ipv4Addr::new(198, 51, 100, 8)
        ));
        // Rows on the excluded interface do not count, and neither does an
        // empty table.
        assert!(!covered_beyond_half(
            routes,
            "eth0",
            Ipv4Addr::new(192, 168, 80, 23)
        ));
        assert!(!covered_beyond_half("", "zn0", Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn eafnosupport_means_no_ipv6_stack() {
        assert!(no_ipv6_stack(&io::Error::from_raw_os_error(
            libc::EAFNOSUPPORT
        )));
        assert!(!no_ipv6_stack(&io::Error::from_raw_os_error(libc::EPERM)));
        assert!(!no_ipv6_stack(&io::Error::other("no os code")));
    }

    #[test]
    fn default_route_iface_finds_gateway_default() {
        assert_eq!(
            default_route_iface(PROC_ROUTE, "zppp0").as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn default_route_iface_skips_excluded_iface() {
        assert!(default_route_iface(PPP_ROUTE, "ppp0").is_none());
    }

    #[test]
    fn garbage_and_short_rows_never_panic() {
        assert!(parse_proc_route("", "zppp0").is_none());
        assert!(parse_proc_route("only one line header", "zppp0").is_none());
        assert!(parse_proc_route("h\nshort\trow\n", "zppp0").is_none());
        // A row with non-hex address fields is skipped, not parsed.
        let bad = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\tZZZZ\tYYYY\tWWWW\t0\t0\tnan\tMMMM\t0\t0\t0
";
        assert!(parse_proc_route(bad, "zppp0").is_none());
    }

    #[test]
    fn netmask_for_prefix() {
        assert_eq!(netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(netmask(24), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn sockaddr_in_carries_family_and_address() {
        let sa = sockaddr_in(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(sa.sa_family, libc::AF_INET as libc::sa_family_t);
        // The address octets land in network order in the sockaddr_in view.
        let sin: libc::sockaddr_in = unsafe { std::mem::transmute(sa) };
        assert_eq!(sin.sin_addr.s_addr.to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(sin.sin_port, 0);
    }
}
