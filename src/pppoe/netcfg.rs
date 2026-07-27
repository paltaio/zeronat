//! In-process host network config for the `--pppoe` link (Linux only).
//!
//! Opt-in helpers that point the host's default route, a server-pinning host
//! route, and DNS at the zppp0 link, then revert all of it on teardown. The
//! production client image is `FROM scratch` with no `ip`/`iptables`/`nft`, so
//! every change is made directly: routes via the `crate::route` ioctl helpers,
//! `/etc/resolv.conf` via a plain file write. The original default route is read
//! from `/proc/net/route`.
//!
//! The pure layer (resolv.conf rendering) is unit-tested without touching the
//! host; the apply/revert syscalls are operator-validated. Apply order is
//! strand-safe: the server pin goes in first, then the zppp0 default is ADDED
//! before the captured original is DELETED, so there is never a window with no
//! default route.

use std::net::Ipv4Addr;

use super::engine::Established;
use crate::route::{modify_route, read_default_route, CapturedDefault};

/// `/etc/resolv.conf`, rewritten when `--pppoe-dns` applies the IPCP servers.
const RESOLV_CONF: &str = "/etc/resolv.conf";

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
                // delete is best-effort: if it no-ops, the original remains as
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

#[cfg(test)]
mod tests {
    use super::*;

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
