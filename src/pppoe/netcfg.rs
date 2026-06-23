//! In-process host network config for the `--pppoe` link (Linux only).
//!
//! Opt-in helpers that point the host's default route, a server-pinning host
//! route, and DNS at the zppp0 link, then revert all of it on teardown. The
//! production client image is `FROM scratch` with no `ip`/`iptables`/`nft`, so
//! every change is made directly: routes via `rtentry` + `SIOCADDRT`/`SIOCDELRT`
//! ioctls on a throwaway `AF_INET` socket (the same pattern as `tap::linux`),
//! `/etc/resolv.conf` via a plain file write. The original default route is read
//! from `/proc/net/route`.
//!
//! The pure layer (route parsing, resolv.conf rendering, rtentry building) is
//! unit-tested without touching the host; the apply/revert syscalls are
//! operator-validated. Apply order is strand-safe: the server pin goes in first,
//! then the zppp0 default is ADDED before the captured original is DELETED, so
//! there is never a window with no default route.

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use super::engine::Established;

/// `/etc/resolv.conf`, rewritten when `--pppoe-dns` applies the IPCP servers.
const RESOLV_CONF: &str = "/etc/resolv.conf";

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
/// columns are little-endian hex. Every field is read through `get` and parsed
/// with a checked radix parse, so a short or malformed row is skipped rather than
/// panicking (the release profile is panic=abort).
pub fn parse_proc_route(contents: &str, tun_name: &str) -> Option<CapturedDefault> {
    let mut best: Option<CapturedDefault> = None;
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        if f.len() < 11 {
            continue;
        }
        let iface = f[0];
        if iface == tun_name {
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
        if dest != 0 || mask != 0 || (flags & RTF_GATEWAY_BITS) == 0 {
            continue;
        }
        let gateway = le_hex_to_ipv4(match u32::from_str_radix(f[2], 16) {
            Ok(g) => g,
            Err(_) => continue,
        });
        let better = match &best {
            Some(b) => metric < b.metric,
            None => true,
        };
        if better {
            best = Some(CapturedDefault {
                gateway,
                iface: iface.to_string(),
                metric,
            });
        }
    }
    best
}

/// `RTF_GATEWAY` as it appears in the `/proc/net/route` Flags column.
const RTF_GATEWAY_BITS: u32 = 0x0002;

/// Decode a `/proc/net/route` little-endian hex address into an `Ipv4Addr`. The
/// column `0150A8C0` is `192.168.80.1`: byte-reversed network order.
fn le_hex_to_ipv4(le: u32) -> Ipv4Addr {
    let b = le.to_le_bytes();
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

/// Render `/etc/resolv.conf` content for the IPCP-provided DNS servers: one
/// `nameserver` line per present address, empty when neither is set.
pub fn render_resolv_conf(dns: &[Option<Ipv4Addr>; 2]) -> String {
    let mut s = String::new();
    for d in dns.iter().flatten() {
        s.push_str("nameserver ");
        s.push_str(&d.to_string());
        s.push('\n');
    }
    s
}

/// Which host-network changes the operator asked for. When nothing is set, apply
/// is never called and base behavior (zppp0 up only) is byte-unchanged.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetCfgOpts {
    pub default_route: bool,
    pub dns: bool,
}

impl NetCfgOpts {
    pub fn any(&self) -> bool {
        self.default_route || self.dns
    }
}

/// What `apply` actually mutated, so `revert` undoes exactly that and no more.
struct AppliedState {
    captured: Option<CapturedDefault>,
    tun_name: String,
    default_added: bool,
    server_pin: Option<Ipv4Addr>,
    resolv_written: bool,
    resolv_backup: Option<Vec<u8>>,
}

/// Holds the applied host-network state and reverts it on drop. The clean-exit
/// paths all run Drop: a normal return, an error, a cancel, and a SIGTERM/SIGINT
/// (the signal handler drops the run future, which reverts synchronously). The
/// release profile is panic=abort, so Drop does NOT run on a panic, and a hard
/// SIGKILL also skips it. Because apply deletes the captured original default,
/// a skipped revert while the default is swapped leaves the host with no default
/// route (removing zppp0 only drops the zppp0 default, it does not restore the
/// deleted original) until it is restored by hand or the box reboots. The datapath
/// and codecs are de-panicked so this path is not reached in normal operation, and
/// `docker stop` sends SIGTERM (a clean revert); only a panic or SIGKILL strands it.
pub struct NetCfgGuard {
    applied: Option<AppliedState>,
}

impl NetCfgGuard {
    /// True once the default route was actually swapped to zppp0. The strand
    /// watchdog only arms after this, since only a default swap can cut the box off.
    pub fn default_applied(&self) -> bool {
        self.applied.as_ref().is_some_and(|a| a.default_added)
    }

    /// Revert everything this guard applied. Idempotent: a second call is a no-op,
    /// and every step ignores "already gone" so a partial apply reverts cleanly.
    pub fn revert(&mut self) {
        let Some(a) = self.applied.take() else {
            return;
        };
        // Add-before-delete inverse: restore the captured original default first,
        // then drop the zppp0 default, then the server pin, then DNS.
        if a.default_added {
            if let Some(c) = &a.captured {
                let _ = modify_route(
                    true,
                    Ipv4Addr::UNSPECIFIED,
                    0,
                    Some(c.gateway),
                    Some(&c.iface),
                    c.metric,
                );
            }
            let _ = modify_route(false, Ipv4Addr::UNSPECIFIED, 0, None, Some(&a.tun_name), 0);
        }
        if let (Some(pin), Some(c)) = (a.server_pin, &a.captured) {
            let _ = modify_route(false, pin, 32, Some(c.gateway), Some(&c.iface), 0);
        }
        if a.resolv_written {
            match a.resolv_backup {
                Some(bytes) => {
                    let _ = std::fs::write(RESOLV_CONF, bytes);
                }
                None => {
                    let _ = std::fs::remove_file(RESOLV_CONF);
                }
            }
        }
    }
}

impl Drop for NetCfgGuard {
    fn drop(&mut self) {
        self.revert();
    }
}

/// Apply the requested host-network changes for an established link and return a
/// guard that reverts them. Strand-safe ordering: server pin, then add the zppp0
/// default, then delete the captured original. A failed step is logged and skipped
/// (the link stays up, degraded), never fatal; the guard records only what
/// succeeded. `server_ip` is the resolved IPv4 tunnel endpoint, or `None` when the
/// server was reached over IPv6 or given as a hostname (the pin is then skipped).
pub fn apply(
    opts: NetCfgOpts,
    server_ip: Option<Ipv4Addr>,
    est: &Established,
    tun_name: &str,
) -> NetCfgGuard {
    let mut state = AppliedState {
        captured: None,
        tun_name: tun_name.to_string(),
        default_added: false,
        server_pin: None,
        resolv_written: false,
        resolv_backup: None,
    };

    if opts.default_route {
        match read_default_route(tun_name) {
            Some(captured) => {
                // Pin the tunnel endpoint to the real WAN before moving the default,
                // so packets to the server never loop back through zppp0.
                match server_ip {
                    Some(ip) => {
                        if modify_route(true, ip, 32, Some(captured.gateway), Some(&captured.iface), 0)
                            .is_ok()
                        {
                            state.server_pin = Some(ip);
                        } else {
                            crate::elog!("pppoe: server-pin route for {ip} failed; continuing");
                        }
                    }
                    None => crate::elog!(
                        "pppoe: server-pin skipped (tunnel reached over IPv6); a v4 default swap cannot strand it"
                    ),
                }
                // Add the zppp0 default before deleting the captured original. The
                // delete is best-effort: if it no-ops, the original simply remains as
                // a lower-priority fallback and zppp0 (priority 0) still wins.
                match modify_route(true, Ipv4Addr::UNSPECIFIED, 0, None, Some(tun_name), 0) {
                    Ok(()) => {
                        let _ = modify_route(
                            false,
                            Ipv4Addr::UNSPECIFIED,
                            0,
                            Some(captured.gateway),
                            Some(&captured.iface),
                            captured.metric,
                        );
                        state.default_added = true;
                        crate::elog!(
                            "pppoe: default route via {tun_name} (was via {} dev {})",
                            captured.gateway,
                            captured.iface
                        );
                    }
                    Err(e) => crate::elog!(
                        "pppoe: could not add default via {tun_name} ({e}); host routing unchanged"
                    ),
                }
                state.captured = Some(captured);
            }
            None => {
                crate::elog!("pppoe: no original default route found; default-route swap skipped")
            }
        }
    }

    if opts.dns {
        apply_dns(&est.dns, &mut state);
    }

    NetCfgGuard {
        applied: Some(state),
    }
}

/// Read and parse the host's current IPv4 default route from `/proc/net/route`.
fn read_default_route(tun_name: &str) -> Option<CapturedDefault> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_proc_route(&contents, tun_name)
}

/// Apply IPCP DNS to `/etc/resolv.conf`, backing up the prior content for revert.
/// Always log the servers: under Docker the file is bind-managed and the write may
/// not stick, so the operator can apply them on the host.
fn apply_dns(dns: &[Option<Ipv4Addr>; 2], state: &mut AppliedState) {
    let servers: Vec<Ipv4Addr> = dns.iter().flatten().copied().collect();
    if servers.is_empty() {
        crate::elog!("pppoe: --pppoe-dns set but the peer provided no DNS servers");
        return;
    }
    crate::elog!("pppoe: dns servers {servers:?}");
    let rendered = render_resolv_conf(dns);
    let backup = std::fs::read(RESOLV_CONF).ok();
    match std::fs::write(RESOLV_CONF, rendered.as_bytes()) {
        Ok(()) => {
            state.resolv_written = true;
            state.resolv_backup = backup;
        }
        Err(e) => crate::elog!("pppoe: could not write {RESOLV_CONF} ({e}); apply DNS on the host"),
    }
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
/// `dev` scopes the route to an interface (required for the gateway-less zppp0
/// default). `priority` is the route's fib priority (the `/proc/net/route` Metric
/// column), so the original default is deleted and restored at its real metric on a
/// multi-homed host. The interface `CString` is built before the socket (so an
/// interior-NUL error cannot leak the fd) and held until after the ioctl so
/// `rt_dev` stays valid.
fn modify_route(
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
        let op = if add { "SIOCADDRT" } else { "SIOCDELRT" };
        return Err(format!("{op} {dst}/{prefix}: {}", io::Error::last_os_error()).into());
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
    fn renders_resolv_conf() {
        assert_eq!(
            render_resolv_conf(&[
                Some(Ipv4Addr::new(1, 1, 1, 1)),
                Some(Ipv4Addr::new(8, 8, 8, 8))
            ]),
            "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        );
        assert_eq!(
            render_resolv_conf(&[Some(Ipv4Addr::new(1, 1, 1, 1)), None]),
            "nameserver 1.1.1.1\n"
        );
        assert_eq!(render_resolv_conf(&[None, None]), "");
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

    #[test]
    fn opts_any() {
        assert!(!NetCfgOpts::default().any());
        assert!(NetCfgOpts {
            default_route: true,
            dns: false
        }
        .any());
        assert!(NetCfgOpts {
            default_route: false,
            dns: true
        }
        .any());
    }
}
