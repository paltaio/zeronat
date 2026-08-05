//! Command-line parsing for the installer. The interactive wizard remains the
//! default; flags pre-seed it (and in headless mode fully drive the install with
//! no prompts). Parsing is split from host probing so it can be unit tested
//! without touching the system: `parse` turns argv into raw overrides, and
//! `build` combines those overrides with probed host state into a final Config,
//! applying the same precedence and validation the flow needs.

use crate::sys;
use crate::ui::{Config, Deploy, Kind, Method, Mode};

/// Raw flag values, before any host probing or derivation. Every field is
/// optional so `build` can tell "the user set this" from "leave the default".
#[derive(Default)]
pub struct Parsed {
    pub mode: Option<Mode>,
    pub method: Option<String>,
    pub deploy: Option<String>,
    pub secret: Option<String>,
    pub admin_secret: Option<String>,
    pub control: Option<String>,
    pub ports: Option<String>,
    pub server_addr: Option<String>,
    pub use_dht: bool,
    pub announce_ip: Option<String>,
    pub announce_port: Option<String>,
    pub tap: Option<String>,
    pub bridge: Option<String>,
    pub bridge_nic: Option<String>,
    pub tap_mtu: Option<String>,
    pub all: bool,
    pub headless: bool,
    pub dry: bool,
    pub help: bool,
}

/// Probed host facts that `build` needs to pick defaults and validate.
pub struct Host {
    pub have_docker: bool,
    pub have_compose: bool,
    pub existing_secret: Option<String>,
    pub existing_admin_secret: Option<String>,
    pub ssh_port: u16,
}

pub fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut p = Parsed::default();
    let mut i = 0;
    // Consume the value following a flag, erroring if it is missing.
    let take = |i: &mut usize, flag: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("missing value for {flag}"))
    };
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--server" => p.mode = Some(Mode::Server),
            "--client" => p.mode = Some(Mode::Client),
            "--method" => p.method = Some(take(&mut i, a)?),
            "--deploy" => p.deploy = Some(take(&mut i, a)?),
            "--secret" => p.secret = Some(take(&mut i, a)?),
            "--admin-secret" => p.admin_secret = Some(take(&mut i, a)?),
            "--control" => p.control = Some(take(&mut i, a)?),
            "--ports" => p.ports = Some(take(&mut i, a)?),
            "--server-addr" | "--addr" => p.server_addr = Some(take(&mut i, a)?),
            "--dht" => p.use_dht = true,
            "--announce-ip" => p.announce_ip = Some(take(&mut i, a)?),
            "--announce-port" => p.announce_port = Some(take(&mut i, a)?),
            "--tap" => p.tap = Some(take(&mut i, a)?),
            "--bridge" => p.bridge = Some(take(&mut i, a)?),
            "--bridge-nic" => p.bridge_nic = Some(take(&mut i, a)?),
            "--tap-mtu" => p.tap_mtu = Some(take(&mut i, a)?),
            "--all" => p.all = true,
            "-y" | "--yes" => p.headless = true,
            "--dry-run" | "-n" => p.dry = true,
            "-h" | "--help" => p.help = true,
            other => return Err(format!("unknown option: {other} (try --help)")),
        }
        i += 1;
    }
    Ok(p)
}

fn valid_ports(spec: &str) -> Result<(), String> {
    let mut count = 0;
    for tok in spec.split_whitespace() {
        let (num, proto) = tok
            .split_once('/')
            .ok_or_else(|| format!("bad port in '{tok}' (use PORT/PROTO)"))?;
        // Reject 0 explicitly: it parses as digits but is not a usable port.
        if num.is_empty() || num == "0" || !num.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("bad port in '{tok}'"));
        }
        if proto != "tcp" && proto != "udp" {
            return Err(format!("bad protocol in '{tok}' (use tcp or udp)"));
        }
        count += 1;
    }
    if count == 0 {
        return Err("no ports given".into());
    }
    Ok(())
}

/// Combine parsed overrides with probed host state into a Config. When
/// `headless` every required value is validated and a missing or invalid one is
/// an error; otherwise the result only pre-seeds the wizard, which fills any
/// gaps, so no value is rejected here. `headless` is the effective decision from
/// the caller (set by `-y` or by the absence of a controlling terminal), not the
/// raw `p.headless` flag, so non-tty runs are validated exactly like `-y`.
pub fn build(p: &Parsed, host: &Host, headless: bool) -> Result<Config, String> {
    // The three carry modes are mutually exclusive: the zeronat binary rejects
    // overlapping --tcp/--udp/--tap/--tun, so reject the conflict here too rather
    // than silently dropping one.
    if (p.tap.is_some() as u8 + p.ports.is_some() as u8 + p.all as u8) > 1 {
        return Err("--ports, --tap, and --all are mutually exclusive".into());
    }
    let mut cfg = Config::new(
        host.have_docker,
        host.have_compose,
        host.existing_secret.clone(),
    );
    cfg.ssh_port = host.ssh_port;

    // mode
    if let Some(m) = p.mode {
        cfg.mode = m;
    } else if headless {
        return Err("choose a side: --server or --client".into());
    }

    // method: default docker if present else systemd.
    cfg.method = if host.have_docker {
        Method::Docker
    } else {
        Method::Systemd
    };
    if let Some(m) = &p.method {
        match m.as_str() {
            "docker" => {
                if !host.have_docker {
                    return Err("docker not installed; use --method systemd".into());
                }
                cfg.method = Method::Docker;
            }
            "systemd" => cfg.method = Method::Systemd,
            other => {
                if headless {
                    return Err(format!("method must be docker or systemd (got '{other}')"));
                }
            }
        }
    }

    // deploy (docker only): default compose, fall back to run if compose missing.
    if cfg.method == Method::Docker {
        cfg.deploy = Deploy::Compose;
        if let Some(d) = &p.deploy {
            match d.as_str() {
                "compose" => cfg.deploy = Deploy::Compose,
                "run" => cfg.deploy = Deploy::Run,
                other => {
                    if headless {
                        return Err(format!("deploy must be compose or run (got '{other}')"));
                    }
                }
            }
        }
        if cfg.deploy == Deploy::Compose && !host.have_compose {
            cfg.deploy = Deploy::Run;
        }
    }

    // control (used below for server-addr derivation).
    if let Some(c) = &p.control {
        cfg.control = c.clone();
    }

    // kind: --all => all traffic, --tap => bridge, --ports => ports.
    if p.all {
        cfg.kind = Kind::All;
    } else if let Some(t) = &p.tap {
        cfg.kind = Kind::Bridge;
        cfg.tap = t.clone();
    } else if p.ports.is_some() {
        cfg.kind = Kind::Ports;
    } else if headless {
        return Err("specify --ports, --tap, or --all".into());
    }
    if let Some(b) = &p.bridge {
        cfg.bridge = b.clone();
    }
    // --bridge-nic asks the installer to build the host bridge (and enslave the
    // NIC) itself, rather than assuming an existing bridge.
    if let Some(n) = &p.bridge_nic {
        cfg.bridge_nic = n.clone();
        cfg.bridge_create = true;
        if cfg.bridge.trim().is_empty() {
            cfg.bridge = "br-zeronat".to_string();
        }
    }
    if cfg.bridge_create && (cfg.mode != Mode::Server || cfg.kind != Kind::Bridge) {
        return Err("--bridge-nic applies to a server in --tap bridge mode".into());
    }
    if let Some(m) = &p.tap_mtu {
        cfg.tap_mtu = m.clone();
    }
    if let Some(ports) = &p.ports {
        cfg.ports = ports.clone();
    }
    // Validate the field the selected kind uses: a TAP name for bridge, ports for
    // forwarding.
    if headless {
        match cfg.kind {
            Kind::Bridge => {
                if cfg.tap.trim().is_empty() {
                    return Err("no TAP device name given".into());
                }
            }
            Kind::Ports => valid_ports(&cfg.ports)?,
            // All-traffic has no field to validate; the SSH port is auto-kept.
            Kind::All => {}
        }
    }

    // discovery / server address.
    cfg.use_dht = p.use_dht;
    if let Some(ip) = &p.announce_ip {
        cfg.announce_ip = ip.clone();
    }
    if let Some(port) = &p.announce_port {
        cfg.announce_port = port.clone();
    }
    if cfg.mode == Mode::Client {
        if let Some(addr) = &p.server_addr {
            // No port => append the control port; then the control port is taken
            // from the address so the client dials and the unit agree.
            let addr = if addr.contains(':') {
                addr.clone()
            } else {
                format!("{addr}:{}", cfg.control)
            };
            if let Some((_, port)) = addr.rsplit_once(':') {
                cfg.control = port.to_string();
            }
            cfg.server_addr = addr;
        } else if !cfg.use_dht && headless {
            return Err("client needs --server-addr HOST[:PORT] or --dht".into());
        }
    }

    // secret: --secret > on-disk > generated.
    let secret = if let Some(s) = &p.secret {
        s.clone()
    } else if let Some(s) = &host.existing_secret {
        s.clone()
    } else {
        sys::gen_secret()?
    };
    cfg.secret = secret;
    finalize_credentials(&mut cfg, p, host)?;

    Ok(cfg)
}

/// Normalize the client secret, then clear the admin secret for clients or
/// resolve it for servers.
pub fn finalize_credentials(cfg: &mut Config, p: &Parsed, host: &Host) -> Result<(), String> {
    cfg.secret = zeronat_secret::normalize(&cfg.secret).map_err(|e| format!("client {e}"))?;
    if cfg.mode != Mode::Server {
        cfg.admin_secret.clear();
        return Ok(());
    }

    let admin_secret = if cfg.admin_secret.is_empty() {
        if let Some(s) = &p.admin_secret {
            s.clone()
        } else if let Some(s) = &host.existing_admin_secret {
            s.clone()
        } else {
            sys::gen_secret()?
        }
    } else {
        cfg.admin_secret.clone()
    };
    cfg.admin_secret =
        zeronat_secret::normalize(&admin_secret).map_err(|e| format!("admin {e}"))?;
    if cfg.admin_secret == cfg.secret {
        return Err("admin secret must differ from the client secret".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAG_SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const DISK_SECRET: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    const ADMIN_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn host() -> Host {
        Host {
            have_docker: false,
            have_compose: false,
            existing_secret: None,
            existing_admin_secret: None,
            ssh_port: 22,
        }
    }

    #[test]
    fn flags_map_to_fields() {
        let p = parse(&s(&[
            "--client",
            "--method",
            "systemd",
            "--secret",
            "abc",
            "--admin-secret",
            ADMIN_SECRET,
            "--control",
            "3333",
            "--ports",
            "443/tcp 80/tcp",
            "--server-addr",
            "host:9000",
            "--dht",
            "--announce-ip",
            "1.2.3.4",
            "--announce-port",
            "7000",
            "--tap",
            "zn0",
            "--bridge",
            "br0",
            "--tap-mtu",
            "1400",
        ]))
        .unwrap();
        assert_eq!(p.mode, Some(Mode::Client));
        assert_eq!(p.method.as_deref(), Some("systemd"));
        assert_eq!(p.secret.as_deref(), Some("abc"));
        assert_eq!(p.admin_secret.as_deref(), Some(ADMIN_SECRET));
        assert_eq!(p.control.as_deref(), Some("3333"));
        assert_eq!(p.ports.as_deref(), Some("443/tcp 80/tcp"));
        assert_eq!(p.server_addr.as_deref(), Some("host:9000"));
        assert!(p.use_dht);
        assert_eq!(p.announce_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(p.announce_port.as_deref(), Some("7000"));
        assert_eq!(p.tap.as_deref(), Some("zn0"));
        assert_eq!(p.bridge.as_deref(), Some("br0"));
        assert_eq!(p.tap_mtu.as_deref(), Some("1400"));
    }

    #[test]
    fn addr_alias() {
        let p = parse(&s(&["--addr", "vps:1234"])).unwrap();
        assert_eq!(p.server_addr.as_deref(), Some("vps:1234"));
    }

    #[test]
    fn all_flag_selects_all_traffic() {
        let p = parse(&s(&["--server", "--all"])).unwrap();
        assert!(p.all);
        let cfg = build(&p, &host(), true).unwrap();
        assert!(cfg.kind == Kind::All);
    }

    #[test]
    fn all_conflicts_with_ports_and_tap() {
        let p = parse(&s(&["--server", "--all", "--ports", "80/tcp"])).unwrap();
        assert!(build(&p, &host(), true).is_err());
        let p = parse(&s(&["--server", "--all", "--tap", "zn0"])).unwrap();
        assert!(build(&p, &host(), true).is_err());
    }

    #[test]
    fn yes_sets_headless() {
        assert!(parse(&s(&["-y"])).unwrap().headless);
        assert!(parse(&s(&["--yes"])).unwrap().headless);
    }

    #[test]
    fn unknown_flag_errs() {
        assert!(parse(&s(&["--nope"])).is_err());
    }

    #[test]
    fn missing_value_errs() {
        assert!(parse(&s(&["--secret"])).is_err());
    }

    #[test]
    fn headless_missing_mode_errs() {
        let p = parse(&s(&["-y", "--ports", "443/tcp"])).unwrap();
        assert!(build(&p, &host(), p.headless).is_err());
    }

    #[test]
    fn no_tty_validates_without_yes_flag() {
        // A bare `curl ... | sh` has no tty and no -y; the caller still treats it
        // as headless, so build must validate (not silently default-install).
        let p = parse(&s(&[])).unwrap();
        assert!(!p.headless);
        assert!(build(&p, &host(), true).is_err());
    }

    #[test]
    fn empty_tap_name_errs() {
        let p = parse(&s(&["-y", "--server", "--tap", ""])).unwrap();
        assert!(build(&p, &host(), true).is_err());
    }

    #[test]
    fn tap_and_ports_conflict() {
        // L2 bridge and port forwarding are mutually exclusive (the binary rejects
        // the combination too); reject it regardless of mode, never silently drop one.
        let p = parse(&s(&["--server", "--tap", "zn0", "--ports", "443/tcp"])).unwrap();
        assert!(build(&p, &host(), true).is_err());
        assert!(build(&p, &host(), false).is_err());
    }

    #[test]
    fn headless_client_needs_addr_or_dht() {
        let p = parse(&s(&["-y", "--client", "--ports", "443/tcp"])).unwrap();
        assert!(build(&p, &host(), p.headless).is_err());
    }

    #[test]
    fn headless_bad_port_errs() {
        let p = parse(&s(&["-y", "--server", "--ports", "443/sctp"])).unwrap();
        assert!(build(&p, &host(), p.headless).is_err());
    }

    #[test]
    fn server_addr_gets_default_port() {
        let p = parse(&s(&[
            "-y",
            "--client",
            "--server-addr",
            "1.2.3.4",
            "--ports",
            "443/tcp",
        ]))
        .unwrap();
        let cfg = build(&p, &host(), p.headless).unwrap();
        assert_eq!(cfg.server_addr, "1.2.3.4:2222");
        assert_eq!(cfg.control, "2222");
    }

    #[test]
    fn server_addr_port_overrides_control() {
        let p = parse(&s(&[
            "-y",
            "--client",
            "--server-addr",
            "1.2.3.4:9000",
            "--ports",
            "443/tcp",
        ]))
        .unwrap();
        let cfg = build(&p, &host(), p.headless).unwrap();
        assert_eq!(cfg.server_addr, "1.2.3.4:9000");
        assert_eq!(cfg.control, "9000");
    }

    #[test]
    fn secret_precedence() {
        // explicit flag wins over disk
        let p = parse(&s(&[
            "-y",
            "--server",
            "--ports",
            "80/tcp",
            "--secret",
            FLAG_SECRET,
        ]))
        .unwrap();
        let mut h = host();
        h.existing_secret = Some(DISK_SECRET.into());
        assert_eq!(build(&p, &h, p.headless).unwrap().secret, FLAG_SECRET);

        // disk wins over generated
        let p = parse(&s(&["-y", "--server", "--ports", "80/tcp"])).unwrap();
        assert_eq!(build(&p, &h, p.headless).unwrap().secret, DISK_SECRET);

        // generated when neither
        let p = parse(&s(&["-y", "--server", "--ports", "80/tcp"])).unwrap();
        let gen = build(&p, &host(), p.headless).unwrap().secret;
        assert_eq!(gen.len(), 64);
    }

    #[test]
    fn server_admin_secret_is_independent_and_optional_for_clients() {
        let p = parse(&s(&[
            "-y",
            "--server",
            "--ports",
            "80/tcp",
            "--secret",
            FLAG_SECRET,
            "--admin-secret",
            ADMIN_SECRET,
        ]))
        .unwrap();
        let cfg = build(&p, &host(), p.headless).unwrap();
        assert_eq!(cfg.admin_secret, ADMIN_SECRET);

        let mut h = host();
        h.existing_admin_secret = Some(DISK_SECRET.into());
        let p = parse(&s(&[
            "-y",
            "--server",
            "--ports",
            "80/tcp",
            "--secret",
            FLAG_SECRET,
        ]))
        .unwrap();
        assert_eq!(build(&p, &h, p.headless).unwrap().admin_secret, DISK_SECRET);

        let p = parse(&s(&[
            "-y",
            "--client",
            "--ports",
            "80/tcp",
            "--server-addr",
            "127.0.0.1:2222",
            "--secret",
            FLAG_SECRET,
        ]))
        .unwrap();
        assert!(build(&p, &h, p.headless).unwrap().admin_secret.is_empty());
    }

    #[test]
    fn server_rejects_invalid_or_shared_admin_secret() {
        for admin in ["short", FLAG_SECRET] {
            let p = parse(&s(&[
                "-y",
                "--server",
                "--ports",
                "80/tcp",
                "--secret",
                FLAG_SECRET,
                "--admin-secret",
                admin,
            ]))
            .unwrap();
            assert!(build(&p, &host(), p.headless).is_err());
        }
    }

    #[test]
    fn client_to_server_wizard_change_resolves_admin_secret() {
        let p = parse(&s(&[
            "--client",
            "--secret",
            FLAG_SECRET,
            "--admin-secret",
            ADMIN_SECRET,
        ]))
        .unwrap();
        let h = host();
        let mut cfg = build(&p, &h, false).unwrap();
        assert!(cfg.admin_secret.is_empty());

        cfg.mode = Mode::Server;
        finalize_credentials(&mut cfg, &p, &h).unwrap();

        assert_eq!(cfg.admin_secret, ADMIN_SECRET);
    }

    #[test]
    fn wizard_secret_change_rejects_matching_admin_secret() {
        let p = parse(&s(&[
            "--server",
            "--secret",
            FLAG_SECRET,
            "--admin-secret",
            ADMIN_SECRET,
        ]))
        .unwrap();
        let h = host();
        let mut cfg = build(&p, &h, false).unwrap();

        cfg.secret = ADMIN_SECRET.into();

        assert_eq!(
            finalize_credentials(&mut cfg, &p, &h).unwrap_err(),
            "admin secret must differ from the client secret"
        );
    }

    #[test]
    fn resolved_secret_format_is_strict() {
        for invalid in [
            "short".to_string(),
            "a".repeat(63),
            "a".repeat(65),
            format!("{}g", "a".repeat(63)),
        ] {
            let p = parse(&s(&[
                "-y", "--server", "--ports", "80/tcp", "--secret", &invalid,
            ]))
            .unwrap();
            assert!(
                build(&p, &host(), p.headless).is_err(),
                "accepted invalid secret {invalid:?}"
            );

            let p = parse(&s(&["-y", "--server", "--ports", "80/tcp"])).unwrap();
            let mut h = host();
            h.existing_secret = Some(invalid.clone());
            assert!(
                build(&p, &h, p.headless).is_err(),
                "accepted invalid on-disk secret {invalid:?}"
            );
        }

        let uppercase = "A".repeat(64);
        let p = parse(&s(&[
            "-y", "--server", "--ports", "80/tcp", "--secret", &uppercase,
        ]))
        .unwrap();
        assert_eq!(
            build(&p, &host(), p.headless).unwrap().secret,
            "a".repeat(64)
        );
    }

    #[test]
    fn headless_docker_missing_errs() {
        let p = parse(&s(&[
            "-y", "--server", "--ports", "80/tcp", "--method", "docker",
        ]))
        .unwrap();
        assert!(build(&p, &host(), p.headless).is_err());
    }

    #[test]
    fn headless_compose_falls_back_to_run() {
        let p = parse(&s(&[
            "-y", "--server", "--ports", "80/tcp", "--deploy", "compose",
        ]))
        .unwrap();
        let mut h = host();
        h.have_docker = true;
        h.have_compose = false;
        let cfg = build(&p, &h, p.headless).unwrap();
        assert_eq!(cfg.method, Method::Docker);
        assert_eq!(cfg.deploy, Deploy::Run);
    }
}
