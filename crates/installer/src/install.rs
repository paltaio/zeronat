//! The execute phase: turns a finished `Config` into a running zeronat, by the
//! same steps the shell installer performs. Each action reports a line so the
//! TUI can show live progress; an error short-circuits with a message.

use std::process::Output;

use crate::bridge;
use crate::sys::{self, errtext, ok};
use crate::ui::{Config, Deploy, Kind, Method, Mode};

/// Seconds the operator has to confirm a risky bridge before it auto-reverts.
const BRIDGE_TIMEOUT: u32 = 30;

// Shown to the user, so it uses the friendly Pages URL.
const INSTALL_URL: &str = "https://paltaio.github.io/zeronat/get.sh";
// Internal fetches (compose templates) hit the repo directly to stay current.
const RAW_BASE: &str = "https://raw.githubusercontent.com/paltaio/zeronat/main";
const RELEASE_BASE: &str = "https://github.com/paltaio/zeronat/releases/latest/download";
const IMAGE: &str = "ghcr.io/paltaio/zeronat:latest";
const ETC_DIR: &str = "/etc/zeronat";
const ENV_FILE: &str = "/etc/zeronat/.env";
const COMPOSE_FILE: &str = "/etc/zeronat/compose.yml";
const BIN_PATH: &str = "/usr/local/bin/zeronat";
const UNIT: &str = "/etc/systemd/system/zeronat.service";

pub enum Lvl {
    Step,
    Info,
}

pub struct Outcome {
    pub manage: String,
    pub headline: String,
    pub peer_intro: String,
    pub peer_cmd: String,
    // The literal start command that was run, with an edit hint. None for dry-run
    // (nothing was actually run).
    pub ran: Option<String>,
    // Command to open the interactive admin console. None when there is no fixed
    // control address to point at (a DHT client).
    pub console: Option<String>,
}

/// Drives the install. Every external command goes through `run` so the UI can
/// animate while it works; `step`/`info` annotate the progress log.
pub trait Runner {
    fn step(&mut self, desc: String);
    fn info(&mut self, msg: String);
    fn run(&mut self, privileged: bool, program: &str, args: &[&str]) -> Result<Output, String>;
    /// Ask the operator to confirm within `secs`, used to keep a risky bridge.
    /// Interactive runners read a key with a countdown; headless runners verify
    /// connectivity instead. Returns true to keep, false to let it revert.
    fn confirm(&mut self, prompt: &str, secs: u32) -> bool;
}

/// Write `content` to `dest` with `mode` as root: stage a temp file and let the
/// runner's `install` set the mode and ownership.
fn place(r: &mut dyn Runner, content: &[u8], mode: &str, dest: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    // The staged file can carry the secret, so create it 0600 up front (O_EXCL,
    // unique name); the 0600 on the final dest does not cover the /tmp window.
    let tmp = std::env::temp_dir().join(format!(
        "zninst-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("temp create: {e}"))?;
    f.write_all(content)
        .map_err(|e| format!("temp write: {e}"))?;
    drop(f);
    let tmps = tmp.to_string_lossy().to_string();
    let out = r.run(true, "install", &["-m", mode, &tmps, dest]);
    let _ = std::fs::remove_file(&tmp);
    let out = out?;
    if ok(&out) {
        Ok(())
    } else {
        Err(format!("install {dest}: {}", errtext(&out)))
    }
}

fn zn_args(cfg: &Config) -> String {
    match cfg.kind {
        Kind::Bridge => {
            let mut s = format!(" --tap {}", cfg.tap);
            if !cfg.bridge.is_empty() {
                s.push_str(&format!(" --bridge {}", cfg.bridge));
            }
            if !cfg.tap_mtu.is_empty() {
                s.push_str(&format!(" --tap-mtu {}", cfg.tap_mtu));
            }
            s
        }
        Kind::Ports => cfg
            .ports
            .split_whitespace()
            .map(|p| {
                let (num, proto) = p.split_once('/').unwrap_or((p, "tcp"));
                if proto == "udp" {
                    format!(" --udp {num}")
                } else {
                    format!(" --tcp {num}")
                }
            })
            .collect(),
        Kind::All => " --tun".to_string(),
    }
}

fn client_addr(cfg: &Config) -> String {
    if cfg.server_addr.contains(':') {
        cfg.server_addr.clone()
    } else {
        format!("{}:{}", cfg.server_addr, cfg.control)
    }
}

/// The zeronat subcommand the service runs (without the binary/image prefix).
pub fn subcmd(cfg: &Config) -> String {
    let a = zn_args(cfg);
    match cfg.mode {
        Mode::Server => {
            let mut s = format!("server --control {}{a}", cfg.control);
            // Keep SSH on the server (it would otherwise route to the client like
            // every other port).
            if cfg.kind == Kind::All && cfg.exclude_ssh {
                s.push_str(&format!(" --except {}", cfg.ssh_port));
            }
            if cfg.use_dht {
                s.push_str(" --server dht");
                if !cfg.announce_ip.is_empty() {
                    s.push_str(&format!(" --announce-ip {}", cfg.announce_ip));
                }
                if !cfg.announce_port.is_empty() {
                    s.push_str(&format!(" --announce-port {}", cfg.announce_port));
                }
            }
            s
        }
        Mode::Client if cfg.use_dht => format!("client --server dht{a}"),
        Mode::Client => format!("client --server {}{a}", client_addr(cfg)),
    }
}

fn forward_flag(cfg: &Config) -> String {
    match cfg.kind {
        Kind::Bridge => format!("--tap {}", cfg.tap),
        Kind::Ports => format!("--ports \"{}\"", cfg.ports),
        Kind::All => "--all".to_string(),
    }
}

fn mode_str(cfg: &Config) -> &'static str {
    match cfg.mode {
        Mode::Server => "server",
        Mode::Client => "client",
    }
}

/// Command to open the interactive admin console for this node. The console
/// connects to a server's control port: local on a server box, the dialed server
/// for a fixed-address client. A DHT client has no fixed control address to point
/// at, so there is no one-line console command (run it on the server instead).
fn console_cmd(cfg: &Config) -> Option<String> {
    let target = match cfg.mode {
        Mode::Server => format!("127.0.0.1:{}", cfg.control),
        Mode::Client if cfg.use_dht => return None,
        Mode::Client => client_addr(cfg),
    };
    Some(match cfg.method {
        // The image is FROM scratch with the binary at /zeronat (not on PATH), and
        // the container already holds ZERONAT_SECRET from its env file.
        Method::Docker => format!("docker exec -it zeronat /zeronat admin --server {target}"),
        Method::Systemd => format!("zeronat admin --server {target} --secret {}", cfg.secret),
    })
}

/// The intro line and the single-line command to run on the *other* machine,
/// mirroring the shell installer. One line so it is easy to copy and paste.
fn peer_steps(cfg: &Config) -> (String, String) {
    let fwd = forward_flag(cfg);
    match cfg.mode {
        Mode::Server => {
            let cmd = if cfg.use_dht {
                format!(
                    "curl -fsSL {INSTALL_URL} | sh -s -- --client --dht --secret {} {fwd} -y",
                    cfg.secret
                )
            } else {
                let host = sys::pub_ip();
                format!(
                    "curl -fsSL {INSTALL_URL} | sh -s -- --client --server-addr {host}:{} --secret {} {fwd} -y",
                    cfg.control, cfg.secret
                )
            };
            (
                "Run this on the client (the machine behind CG-NAT):".into(),
                cmd,
            )
        }
        Mode::Client => {
            let disc = if cfg.use_dht {
                "--dht".to_string()
            } else {
                // The server must listen on the port the client dials, which is
                // the one in the entered address (falling back to the default).
                let ctrl = cfg
                    .server_addr
                    .rsplit_once(':')
                    .map(|(_, p)| p.to_string())
                    .unwrap_or_else(|| cfg.control.clone());
                format!("--control {ctrl}")
            };
            let cmd = format!(
                "curl -fsSL {INSTALL_URL} | sh -s -- --server {disc} --secret {} {fwd} -y",
                cfg.secret
            );
            (
                "Run this on the server (it must use the same secret):".into(),
                cmd,
            )
        }
    }
}

/// Last-line guard before any command is built: the validated paths (headless
/// `valid_ports`, interactive checklist) already enforce this, so reaching here
/// with a forwarding-less config means a path bypassed validation. Catch it
/// rather than silently starting a server/client that forwards nothing.
fn check_forwards(cfg: &Config) -> Result<(), String> {
    match cfg.kind {
        Kind::Bridge => {
            if cfg.tap.trim().is_empty() {
                return Err("no TAP device name given".into());
            }
        }
        Kind::Ports => {
            for tok in cfg.ports.split_whitespace() {
                let proto = tok.split_once('/').map(|(_, p)| p).unwrap_or("");
                if proto != "tcp" && proto != "udp" {
                    return Err(format!("bad protocol in '{tok}' (use tcp or udp)"));
                }
            }
            if cfg.ports.split_whitespace().next().is_none() {
                return Err("no ports given".into());
            }
        }
        Kind::All => {}
    }
    Ok(())
}

pub fn execute(cfg: &Config, dry: bool, r: &mut dyn Runner) -> Result<Outcome, String> {
    check_forwards(cfg)?;
    let sub = subcmd(cfg);
    if dry {
        return dry_run(cfg, &sub, r);
    }

    r.step(format!("preparing {ETC_DIR}"));
    let out = r.run(true, "mkdir", &["-p", ETC_DIR])?;
    if !ok(&out) {
        return Err(format!("mkdir {ETC_DIR}: {}", errtext(&out)));
    }

    r.step("writing env file".into());
    let env = if cfg.method == Method::Docker && cfg.deploy == Deploy::Compose {
        format!("ZERONAT_SECRET={}\nZERONAT_ARGS={}\n", cfg.secret, sub)
    } else {
        format!("ZERONAT_SECRET={}\n", cfg.secret)
    };
    place(r, env.as_bytes(), "0600", ENV_FILE)?;

    // Build the host bridge before starting zeronat, so the TAP has a bridge to
    // join. A no-op unless this is a server in bridge mode asked to create one.
    setup_bridge(cfg, r)?;

    let (manage, ran) = match cfg.method {
        Method::Docker => install_docker(cfg, &sub, r)?,
        Method::Systemd => install_systemd(cfg, &sub, r)?,
    };

    let (peer_intro, peer_cmd) = peer_steps(cfg);
    Ok(Outcome {
        manage,
        headline: format!("zeronat {} is running", mode_str(cfg)),
        peer_intro,
        peer_cmd,
        ran: Some(ran),
        console: console_cmd(cfg),
    })
}

/// Create the host bridge and enslave the chosen NIC, persisting it through the
/// host's network manager. When the NIC carries the operator's connectivity the
/// apply runs under a detached watchdog that reverts unless confirmed in time.
/// A no-op unless this is a server in bridge mode with `bridge_create`.
fn setup_bridge(cfg: &Config, r: &mut dyn Runner) -> Result<(), String> {
    if !(cfg.mode == Mode::Server && cfg.kind == Kind::Bridge && cfg.bridge_create) {
        return Ok(());
    }
    if !sys::have("ip") {
        return Err("the `ip` command (iproute2) is required to create a bridge".into());
    }
    let nics = bridge::list_nics();
    let nic = nics
        .iter()
        .find(|n| n.name == cfg.bridge_nic)
        .cloned()
        .ok_or_else(|| format!("NIC '{}' not found", cfg.bridge_nic))?;
    if nic.wifi {
        return Err(format!("{} is wireless; bridge a wired NIC instead", nic.name));
    }
    if nic.enslaved {
        // A re-run after a successful bridge: the NIC is already a member. If it is
        // already our bridge, the step is done; otherwise it belongs to something else.
        if verify_bridge(&cfg.bridge, &nic.name, r).is_ok() {
            return Ok(());
        }
        return Err(format!("{} is already enslaved to another bridge/bond", nic.name));
    }
    let mgr = bridge::detect_manager();
    if matches!(mgr, bridge::Mgr::Unsupported(_)) {
        return Err(bridge::manual_snippet(&cfg.bridge, &nic));
    }
    let dns = bridge::nameservers();

    if !nic.risky() {
        // A spare NIC with no addressing cannot strand the operator: apply and
        // persist with no rollback window.
        r.step(format!("creating bridge {} on {}", cfg.bridge, nic.name));
        let script = bridge::apply_script(&cfg.bridge, &nic, mgr, &dns, None);
        place(r, script.as_bytes(), "0755", bridge::APPLY_PATH)?;
        let out = r.run(true, "sh", &[bridge::APPLY_PATH])?;
        if !ok(&out) {
            return Err(format!("bridge setup failed: {}", errtext(&out)));
        }
        return verify_bridge(&cfg.bridge, &nic.name, r);
    }

    // Risky: the NIC carries the operator's connectivity. Persisting via netplan's
    // authoritative-file takeover renames every existing netplan file aside, so
    // refuse a multi-NIC host where that would drop another interface's config.
    if mgr == bridge::Mgr::Netplan && nics.iter().filter(|n| n.has_ip()).count() > 1 {
        return Err(format!(
            "this host has more than one active interface; auto-bridging the uplink is \
             only supported on a single-NIC host.\n{}",
            bridge::manual_snippet(&cfg.bridge, &nic)
        ));
    }
    // systemd owns the revert timer, so it must be present.
    if !bridge::have_systemd_run() {
        return Err(format!(
            "systemd-run is required to safely bridge the uplink NIC.\n{}",
            bridge::manual_snippet(&cfg.bridge, &nic)
        ));
    }

    r.step(format!(
        "bridging {} into {} (auto-reverts in ~{BRIDGE_TIMEOUT}s if you lose access)",
        nic.name, cfg.bridge
    ));
    // The apply script arms the systemd revert timer as its first action. The
    // timer's clock starts at surgery time, but the operator's countdown only
    // starts after the apply returns, so the margin must cover a slow apply (e.g.
    // a contended `netplan generate`) plus the full confirm window. The normal
    // keep/decline paths cancel or trigger the timer explicitly; this deadline is
    // only the backstop for the operator-vanished case.
    let apply = bridge::apply_script(&cfg.bridge, &nic, mgr, &dns, Some(BRIDGE_TIMEOUT + 60));
    let undo = bridge::undo_script(&cfg.bridge, &nic, mgr);
    place(r, apply.as_bytes(), "0755", bridge::APPLY_PATH)?;
    place(r, undo.as_bytes(), "0755", bridge::UNDO_PATH)?;

    let undo_timer = format!("{}.timer", bridge::UNDO_UNIT);

    // Run the apply. It arms the timer first, so even if this is interrupted the
    // box still reverts.
    let out = r.run(true, "sh", &[bridge::APPLY_PATH])?;
    if !ok(&out) {
        let undone = matches!(r.run(true, "sh", &[bridge::UNDO_PATH]), Ok(o) if o.status.success());
        if undone {
            let _ = r.run(true, "systemctl", &["stop", &undo_timer]);
        }
        return Err(format!("bridge apply failed: {}", errtext(&out)));
    }

    let keep = r.confirm(
        &format!("Bridge live on {}. Confirm you still have access", nic.name),
        BRIDGE_TIMEOUT,
    );
    if keep {
        let _ = r.run(true, "systemctl", &["stop", &undo_timer]);
        verify_bridge(&cfg.bridge, &nic.name, r)?;
        r.info("bridge kept and persisted".into());
        Ok(())
    } else {
        // Revert synchronously so the box is actually restored before we report it;
        // the systemd timer was only the backstop for our own death. Leave it armed
        // if the synchronous undo did not succeed.
        let undone = matches!(r.run(true, "sh", &[bridge::UNDO_PATH]), Ok(o) if o.status.success());
        if undone {
            let _ = r.run(true, "systemctl", &["stop", &undo_timer]);
        }
        Err("no confirmation; the bridge was reverted".into())
    }
}

/// Confirm the NIC ended up enslaved to the bridge after an apply.
fn verify_bridge(bridge: &str, nic: &str, r: &mut dyn Runner) -> Result<(), String> {
    let out = r.run(false, "ip", &["-o", "link", "show", "master", bridge])?;
    let listed = String::from_utf8_lossy(&out.stdout);
    let enslaved = listed.contains(&format!(" {nic}:")) || listed.contains(&format!(" {nic}@"));
    if !ok(&out) || !enslaved {
        return Err(format!("{nic} is not enslaved to {bridge} after apply"));
    }
    Ok(())
}

/// Preview the steps without touching the system. Used by --dry-run and for
/// safe demos; the progress screen looks the same as a real install.
// The `sleep` is a deliberate no-op that paces the preview through the real
// animated runner path.
fn dstep(r: &mut dyn Runner, desc: &str) {
    r.step(desc.to_string());
    let _ = r.run(false, "sleep", &["0.35"]);
}

fn dry_run(cfg: &Config, _sub: &str, r: &mut dyn Runner) -> Result<Outcome, String> {
    r.info("dry run: no changes will be made".into());
    dstep(r, &format!("would prepare {ETC_DIR} and write {ENV_FILE}"));
    if cfg.mode == Mode::Server && cfg.kind == Kind::Bridge && cfg.bridge_create {
        dstep(
            r,
            &format!("would create bridge {} on {}", cfg.bridge, cfg.bridge_nic),
        );
    }
    let manage = match cfg.method {
        Method::Docker if cfg.deploy == Deploy::Compose => {
            let dc = sys::compose_argv();
            let prog = if dc.is_empty() {
                "docker compose".to_string()
            } else {
                dc.join(" ")
            };
            dstep(r, "would fetch the compose file");
            dstep(r, "would pull the image and start via compose");
            format!("cd {ETC_DIR} && {prog} logs -f    # status: {prog} ps")
        }
        Method::Docker => {
            dstep(r, "would pull the image and start the container");
            "docker logs -f zeronat".into()
        }
        Method::Systemd => {
            let target = sys::arch_target().unwrap_or("this arch");
            r.info(format!("target {target}"));
            dstep(r, "would download the binary and write a systemd unit");
            dstep(r, "would enable the service");
            "systemctl status zeronat".into()
        }
    };
    let (peer_intro, peer_cmd) = peer_steps(cfg);
    Ok(Outcome {
        manage,
        headline: format!("zeronat {} ready (dry run)", mode_str(cfg)),
        peer_intro,
        peer_cmd,
        ran: None,
        console: console_cmd(cfg),
    })
}

fn install_docker(cfg: &Config, sub: &str, r: &mut dyn Runner) -> Result<(String, String), String> {
    let _ = r.run(true, "docker", &["rm", "-f", "zeronat"]);

    if cfg.deploy == Deploy::Compose {
        // TAP and all-traffic (TUN) both need NET_ADMIN and /dev/net/tun.
        let src = if cfg.kind == Kind::Ports {
            "compose.yml"
        } else {
            "compose.bridge.yml"
        };
        r.step(format!("fetching {src}"));
        let url = format!("{RAW_BASE}/{src}");
        let out = r.run(false, "curl", &["-fsSL", &url])?;
        if !ok(&out) {
            return Err(format!("could not fetch {src}"));
        }
        place(r, &out.stdout, "0644", COMPOSE_FILE)?;

        let dc = sys::compose_argv();
        if dc.is_empty() {
            return Err("docker compose not available".into());
        }
        // compose auto-loads .env from the project directory (the compose file's
        // own dir), so -f is the only flag needed and the command works from any
        // cwd; --env-file and --project-directory would be redundant.
        let base: Vec<String> = dc[1..]
            .iter()
            .cloned()
            .chain(["-f".into(), COMPOSE_FILE.into()])
            .collect();

        r.step("pulling image".into());
        compose(r, &dc[0], &base, "pull")?;
        r.step("starting via compose".into());
        compose(r, &dc[0], &base, "up")?;

        let view: Vec<&str> = std::iter::once(dc[0].as_str())
            .chain(base.iter().map(|s| s.as_str()))
            .collect();
        let ran = format!("{} up -d    # edit {ENV_FILE} to change ports/secret", view.join(" "));
        let dcj = dc.join(" ");
        let manage = format!("cd {ETC_DIR} && {dcj} logs -f    # status: {dcj} ps");
        Ok((manage, ran))
    } else {
        r.step("pulling image".into());
        let out = r.run(true, "docker", &["pull", IMAGE])?;
        if !ok(&out) {
            return Err(format!("docker pull: {}", errtext(&out)));
        }
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            "zeronat".into(),
            "--restart".into(),
            "unless-stopped".into(),
            "--network".into(),
            "host".into(),
        ];
        if cfg.kind != Kind::Ports {
            args.extend([
                "--cap-add".into(),
                "NET_ADMIN".into(),
                "--device".into(),
                "/dev/net/tun".into(),
            ]);
        }
        args.extend(["--env-file".into(), ENV_FILE.into(), IMAGE.into()]);
        args.extend(sub.split_whitespace().map(|s| s.to_string()));
        let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        r.step("starting container".into());
        let out = r.run(true, "docker", &aref)?;
        if !ok(&out) {
            return Err(format!("docker run: {}", errtext(&out)));
        }
        let ran = format!(
            "docker {}    # edit {ENV_FILE} to change ports/secret",
            args.join(" ")
        );
        Ok((
            "docker logs -f zeronat    # status: docker ps".into(),
            ran,
        ))
    }
}

fn compose(r: &mut dyn Runner, prog: &str, base: &[String], verb: &str) -> Result<(), String> {
    let mut args: Vec<String> = base.to_vec();
    if verb == "up" {
        args.push("up".into());
        args.push("-d".into());
    } else {
        args.push(verb.into());
    }
    let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = r.run(true, prog, &aref)?;
    if ok(&out) {
        Ok(())
    } else {
        Err(format!("compose {verb}: {}", errtext(&out)))
    }
}

fn install_systemd(cfg: &Config, sub: &str, r: &mut dyn Runner) -> Result<(String, String), String> {
    let target = sys::arch_target()?;
    r.info(format!("target {target}"));
    let url = format!("{RELEASE_BASE}/zeronat-{target}");
    let tmp = std::env::temp_dir().join(format!("zeronat-dl-{}", std::process::id()));
    let tmps = tmp.to_string_lossy().to_string();

    r.step("downloading zeronat binary".into());
    let out = r.run(false, "curl", &["-fsSL", &url, "-o", &tmps])?;
    if !ok(&out) {
        return Err(format!("download failed (no release asset for {target}?)"));
    }
    let inst = r.run(true, "install", &["-m", "0755", &tmps, BIN_PATH]);
    let _ = std::fs::remove_file(&tmp);
    let out = inst?;
    if !ok(&out) {
        return Err(format!("install binary: {}", errtext(&out)));
    }

    r.step("writing systemd unit".into());
    let mode = match cfg.mode {
        Mode::Server => "server",
        Mode::Client => "client",
    };
    let unit = format!(
        "[Unit]\n\
         Description=zeronat {mode}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         EnvironmentFile={ENV_FILE}\n\
         ExecStart={BIN_PATH} {sub}\n\
         Restart=always\n\
         RestartSec=3\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    place(r, unit.as_bytes(), "0644", UNIT)?;

    r.step("enabling service".into());
    let out = r.run(true, "systemctl", &["daemon-reload"])?;
    if !ok(&out) {
        return Err(format!("daemon-reload: {}", errtext(&out)));
    }
    let out = r.run(true, "systemctl", &["enable", "--now", "zeronat"])?;
    if !ok(&out) {
        return Err(format!("enable: {}", errtext(&out)));
    }
    let ran = format!("systemctl enable --now zeronat    # edit {ENV_FILE} and {UNIT} to change ports/secret");
    Ok((
        "systemctl status zeronat    # logs: journalctl -u zeronat -f".into(),
        ran,
    ))
}

#[cfg(test)]
mod tests {
    use super::{check_forwards, console_cmd, peer_steps, subcmd};
    use crate::ui::{Config, Kind, Method, Mode};

    fn cfg() -> Config {
        Config::new(false, false, None)
    }

    #[test]
    fn console_server_targets_localhost() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.control = "2222".into();
        c.method = Method::Docker;
        assert_eq!(
            console_cmd(&c).unwrap(),
            "docker exec -it zeronat /zeronat admin --server 127.0.0.1:2222"
        );
        c.method = Method::Systemd;
        c.secret = "sek".into();
        assert_eq!(
            console_cmd(&c).unwrap(),
            "zeronat admin --server 127.0.0.1:2222 --secret sek"
        );
    }

    #[test]
    fn console_client_targets_the_server() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "vps.example:9000".into();
        c.method = Method::Docker;
        assert_eq!(
            console_cmd(&c).unwrap(),
            "docker exec -it zeronat /zeronat admin --server vps.example:9000"
        );
    }

    #[test]
    fn console_none_for_dht_client() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.use_dht = true;
        assert!(console_cmd(&c).is_none());
    }

    #[test]
    fn check_forwards_rejects_empty_ports() {
        let mut c = cfg();
        c.kind = Kind::Ports;
        c.ports = "  ".into();
        assert!(check_forwards(&c).is_err());
    }

    #[test]
    fn check_forwards_rejects_empty_tap() {
        let mut c = cfg();
        c.kind = Kind::Bridge;
        c.tap = "".into();
        assert!(check_forwards(&c).is_err());
    }

    #[test]
    fn check_forwards_accepts_valid_ports() {
        let mut c = cfg();
        c.kind = Kind::Ports;
        c.ports = "443/tcp 80/udp".into();
        assert!(check_forwards(&c).is_ok());
    }

    #[test]
    fn client_peer_uses_the_server_port() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "vps.example:9000".into();
        c.ports = "443/tcp".into();
        let (_, cmd) = peer_steps(&c);
        assert!(cmd.contains("--server --control 9000"), "{cmd}");
    }

    #[test]
    fn client_peer_defaults_the_port_when_omitted() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "vps.example".into();
        c.ports = "443/tcp".into();
        let (_, cmd) = peer_steps(&c);
        assert!(cmd.contains("--control 2222"), "{cmd}");
    }

    #[test]
    fn server_ports() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.ports = "443/tcp 51820/udp".into();
        assert_eq!(subcmd(&c), "server --control 2222 --tcp 443 --udp 51820");
    }

    #[test]
    fn server_dht_publish() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.use_dht = true;
        c.ports = "80/tcp".into();
        assert_eq!(subcmd(&c), "server --control 2222 --tcp 80 --server dht");
    }

    #[test]
    fn client_address_gets_default_port() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "1.2.3.4".into();
        c.ports = "443/tcp".into();
        assert_eq!(subcmd(&c), "client --server 1.2.3.4:2222 --tcp 443");
    }

    #[test]
    fn client_address_keeps_explicit_port() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "host.example:9000".into();
        c.ports = "443/tcp".into();
        assert_eq!(subcmd(&c), "client --server host.example:9000 --tcp 443");
    }

    #[test]
    fn client_dht() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.use_dht = true;
        c.ports = "443/tcp".into();
        assert_eq!(subcmd(&c), "client --server dht --tcp 443");
    }

    #[test]
    fn bridge_tap() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::Bridge;
        c.tap = "zn0".into();
        assert_eq!(subcmd(&c), "server --control 2222 --tap zn0");
    }

    #[test]
    fn bridge_with_bridge_and_mtu() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::Bridge;
        c.tap = "zn0".into();
        c.bridge = "br0".into();
        c.tap_mtu = "1400".into();
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --tap zn0 --bridge br0 --tap-mtu 1400"
        );
    }

    #[test]
    fn server_dht_announce() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.use_dht = true;
        c.ports = "443/tcp".into();
        c.announce_ip = "203.0.113.1".into();
        c.announce_port = "9000".into();
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --tcp 443 --server dht --announce-ip 203.0.113.1 --announce-port 9000"
        );
    }

    #[test]
    fn server_all_traffic_excepts_ssh_port() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::All;
        c.ssh_port = 2200;
        assert_eq!(subcmd(&c), "server --control 2222 --tun --except 2200");
    }

    #[test]
    fn server_all_traffic_forward_everything() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::All;
        c.exclude_ssh = false;
        assert_eq!(subcmd(&c), "server --control 2222 --tun");
    }

    #[test]
    fn client_all_traffic_has_no_except() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.kind = Kind::All;
        c.server_addr = "1.2.3.4".into();
        assert_eq!(subcmd(&c), "client --server 1.2.3.4:2222 --tun");
    }

    #[test]
    fn all_traffic_peer_uses_all_flag() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::All;
        c.use_dht = true;
        c.secret = "s".into();
        let (_, cmd) = peer_steps(&c);
        assert!(cmd.contains("--client"), "{cmd}");
        assert!(cmd.contains("--all"), "{cmd}");
    }

    #[test]
    fn peer_cmd_uses_get_sh_and_headless() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.use_dht = true;
        c.ports = "443/tcp".into();
        c.secret = "deadbeef".into();
        let (_, cmd) = peer_steps(&c);
        assert!(cmd.contains("get.sh"), "{cmd}");
        assert!(cmd.ends_with(" -y"), "{cmd}");
    }
}
