//! Pure helpers for `--pppoe` config resolution and validation.
//!
//! These take already-resolved inputs (the binary does the file/env/argv IO and
//! passes the results in) so the precedence and validation logic is unit-testable
//! in the lib without touching the filesystem or the process environment.

use super::datapath::{effective_mtu, PPPOE_OVERHEAD};

/// Minimum usable effective PPP MTU. Below this a link is not worth bringing up:
/// MRU 0 is a malformed LCP option the BRAS rejects, and a too-small MTU breaks
/// path MTU for normal traffic. The IPv6 minimum is the floor.
pub const MIN_EFFECTIVE_MTU: u16 = 1280;

/// Resolve the PPPoE password from the three sources in precedence order:
/// file (preferred) > env > flag. The flag is last because it leaks in ps/argv.
///
/// `file` is the file's raw bytes (the binary reads it); `env`/`flag` are the
/// resolved string values. Returns an error naming the accepted sources if none
/// is present. The file content is trimmed of a single trailing line ending
/// (CRLF or LF) so `echo pass > file` works, preserving all other bytes; the
/// password is bytes (PPP CHAP/PAP take `&[u8]`), so no UTF-8 requirement.
pub fn resolve_password(
    file: Option<Vec<u8>>,
    env: Option<String>,
    flag: Option<String>,
) -> super::Result<Vec<u8>> {
    if let Some(bytes) = file {
        return Ok(trim_one_line_ending(bytes));
    }
    if let Some(p) = env {
        return Ok(p.into_bytes());
    }
    if let Some(p) = flag {
        return Ok(p.into_bytes());
    }
    Err(super::Error::MissingPassword)
}

/// Resolve the PPPoE username: flag > env (there is no username file).
pub fn resolve_username(flag: Option<String>, env: Option<String>) -> super::Result<Vec<u8>> {
    flag.or(env)
        .map(String::into_bytes)
        .ok_or(super::Error::MissingUsername)
}

/// Strip at most one trailing line ending: a single `\n`, and a single preceding
/// `\r` if the ending was CRLF. All other trailing bytes are preserved.
fn trim_one_line_ending(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

/// The effective MTU plus whether the requested PPP MTU was capped by the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedMtu {
    pub effective: u16,
    /// True when `pppoe_mtu` exceeded what the tunnel can carry and was clamped.
    pub capped: bool,
}

/// Compute the effective PPP MTU/MRU from the requested PPP MTU and the tunnel L2
/// MTU, enforcing `MIN_EFFECTIVE_MTU`. Returns an error (rather than a silent
/// unusable value) when the tunnel MTU is too small to carry a usable PPP link.
pub fn resolve_effective_mtu(pppoe_mtu: u16, tunnel_tap_mtu: u16) -> super::Result<ResolvedMtu> {
    let effective = effective_mtu(pppoe_mtu, tunnel_tap_mtu);
    if effective < MIN_EFFECTIVE_MTU {
        return Err(super::Error::TunnelMtuTooSmall {
            tunnel: tunnel_tap_mtu,
            min: MIN_EFFECTIVE_MTU + PPPOE_OVERHEAD,
        });
    }
    let capped = effective < pppoe_mtu;
    Ok(ResolvedMtu { effective, capped })
}

/// Reject flag combinations that conflict with `--pppoe` owning the L2 channel.
/// `--transport` is orthogonal (it picks the tunnel carrier `--pppoe` rides) and
/// is intentionally not checked here.
pub fn validate_pppoe_exclusions(
    pppoe: bool,
    tap: bool,
    tun: bool,
    has_forwards: bool,
) -> crate::Result<()> {
    if !pppoe {
        return Ok(());
    }
    if tap {
        return Err("--pppoe cannot be combined with --tap".into());
    }
    if tun {
        return Err("--pppoe cannot be combined with --tun".into());
    }
    if has_forwards {
        return Err("--pppoe cannot be combined with --tcp/--udp forwards".into());
    }
    Ok(())
}

/// Reject invalid `--pppoe-*` host-network flag combinations. The three host flags
/// configure the `--pppoe` link, so each requires `--pppoe`; opting out of the MSS
/// clamp only makes sense alongside the default-route swap that brings it on.
pub fn validate_pppoe_netcfg(
    pppoe: bool,
    default_route: bool,
    no_mss_clamp: bool,
    dns: bool,
) -> crate::Result<()> {
    if !pppoe {
        if default_route {
            return Err("--pppoe-default-route requires --pppoe".into());
        }
        if no_mss_clamp {
            return Err("--pppoe-no-mss-clamp requires --pppoe".into());
        }
        if dns {
            return Err("--pppoe-dns requires --pppoe".into());
        }
    }
    if no_mss_clamp && !default_route {
        return Err("--pppoe-no-mss-clamp requires --pppoe-default-route".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_precedence_file_wins() {
        let p = resolve_password(
            Some(b"fromfile\n".to_vec()),
            Some("fromenv".into()),
            Some("fromflag".into()),
        )
        .unwrap();
        assert_eq!(p, b"fromfile");
    }

    #[test]
    fn password_env_over_flag() {
        let p = resolve_password(None, Some("fromenv".into()), Some("fromflag".into())).unwrap();
        assert_eq!(p, b"fromenv");
    }

    #[test]
    fn password_flag_last() {
        let p = resolve_password(None, None, Some("fromflag".into())).unwrap();
        assert_eq!(p, b"fromflag");
    }

    #[test]
    fn password_none_is_error() {
        assert!(matches!(
            resolve_password(None, None, None),
            Err(super::super::Error::MissingPassword)
        ));
    }

    #[test]
    fn password_file_trims_one_line_ending_only() {
        assert_eq!(trim_one_line_ending(b"abc\n".to_vec()), b"abc");
        assert_eq!(trim_one_line_ending(b"abc\r\n".to_vec()), b"abc");
        // A trailing blank line beyond the single ending is preserved.
        assert_eq!(trim_one_line_ending(b"abc\n\n".to_vec()), b"abc\n");
        // No ending: untouched.
        assert_eq!(trim_one_line_ending(b"abc".to_vec()), b"abc");
        // A lone CR is not a line ending we strip.
        assert_eq!(trim_one_line_ending(b"abc\r".to_vec()), b"abc\r");
    }

    #[test]
    fn password_file_allows_non_utf8() {
        let p = resolve_password(Some(vec![0x00, 0xff, 0xfe, b'\n']), None, None).unwrap();
        assert_eq!(p, vec![0x00, 0xff, 0xfe]);
    }

    #[test]
    fn username_flag_then_env() {
        assert_eq!(
            resolve_username(Some("u".into()), Some("e".into())).unwrap(),
            b"u"
        );
        assert_eq!(resolve_username(None, Some("e".into())).unwrap(), b"e");
        assert!(matches!(
            resolve_username(None, None),
            Err(super::super::Error::MissingUsername)
        ));
    }

    #[test]
    fn mtu_resolves_and_flags_cap() {
        let r = resolve_effective_mtu(1492, 1400).unwrap();
        assert_eq!(r.effective, 1392);
        assert!(r.capped);
        // Requested fits within the tunnel: not capped.
        let r = resolve_effective_mtu(1280, 1400).unwrap();
        assert_eq!(r.effective, 1280);
        assert!(!r.capped);
    }

    #[test]
    fn mtu_rejects_tiny_tunnel() {
        // 1400 -> 1392 OK; a small tunnel falls below MIN_EFFECTIVE_MTU and errors
        // instead of silently using a too-small or zero value.
        assert!(resolve_effective_mtu(1492, 8).is_err());
        assert!(resolve_effective_mtu(1492, 1200).is_err());
        // Exactly at the floor is accepted.
        let r = resolve_effective_mtu(1492, MIN_EFFECTIVE_MTU + PPPOE_OVERHEAD).unwrap();
        assert_eq!(r.effective, MIN_EFFECTIVE_MTU);
    }

    #[test]
    fn exclusions() {
        assert!(validate_pppoe_exclusions(true, false, false, false).is_ok());
        // --transport is orthogonal; not represented here, so a plain --pppoe is OK.
        assert!(validate_pppoe_exclusions(true, true, false, false).is_err());
        assert!(validate_pppoe_exclusions(true, false, true, false).is_err());
        assert!(validate_pppoe_exclusions(true, false, false, true).is_err());
        // Not --pppoe: never errors regardless of the other flags.
        assert!(validate_pppoe_exclusions(false, true, true, true).is_ok());
    }

    #[test]
    fn netcfg_flag_validation() {
        // All host flags require --pppoe.
        assert!(validate_pppoe_netcfg(false, true, false, false).is_err());
        assert!(validate_pppoe_netcfg(false, false, true, false).is_err());
        assert!(validate_pppoe_netcfg(false, false, false, true).is_err());
        // --pppoe-no-mss-clamp requires --pppoe-default-route.
        assert!(validate_pppoe_netcfg(true, false, true, false).is_err());
        // Valid combinations.
        assert!(validate_pppoe_netcfg(true, true, false, false).is_ok());
        assert!(validate_pppoe_netcfg(true, true, true, false).is_ok()); // opt out of the clamp
        assert!(validate_pppoe_netcfg(true, false, false, true).is_ok()); // dns is independent
        assert!(validate_pppoe_netcfg(true, false, false, false).is_ok()); // plain --pppoe
    }
}
