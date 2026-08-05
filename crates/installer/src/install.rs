//! The execute phase: turns a finished `Config` into a running zeronat, by the
//! same steps the shell installer performs. Each action reports a line so the
//! TUI can show live progress; an error short-circuits with a message.

use std::fs::File;
use std::io::Write as _;
use std::process::Output;
use zeronat_install_support::{
    curl_fetch_command, download_verified_asset_with_keys, DownloadFile, SelectedRelease,
    TrustedKey,
};

#[cfg(not(test))]
use zeronat_install_support::TRUSTED_RELEASE_KEYS;
#[cfg(test)]
const TEST_RELEASE_KEYS: &[TrustedKey] = &[TrustedKey {
    id: "3cafdfbef1bd2ed8",
    public_key: include_str!("../../install-support/tests/fixtures/minisign.pub"),
}];
#[cfg(test)]
const TEST_RELEASE_MANIFEST: &[u8] =
    include_bytes!("../../install-support/tests/fixtures/v0.25.1.manifest");
#[cfg(test)]
const TEST_RELEASE_SIGNATURE: &[u8] =
    include_bytes!("../../install-support/tests/fixtures/v0.25.1.manifest.minisig");
#[cfg(test)]
const TEST_RELEASE_BINARY: &[u8] = b"downloaded binary";

use crate::args::Host;
use crate::bridge;
use crate::sys::{self, errtext, ok};
use crate::ui::{Config, Deploy, Kind, Method, Mode, UpgradeOffer};

/// Seconds the operator has to confirm a risky bridge before it auto-reverts.
const BRIDGE_TIMEOUT: u32 = 30;

// Shown to the user, so it uses the friendly Pages URL.
const INSTALL_URL: &str = "https://paltaio.github.io/zeronat/get.sh";
// Internal fetches (compose templates) hit the repo directly to stay current.
const RAW_BASE: &str = "https://raw.githubusercontent.com/paltaio/zeronat/main";
const IMAGE: &str = "ghcr.io/paltaio/zeronat:protocol-v6";
const BINARY_ASSET_PREFIX: &str = "zeronat-v6";
const ETC_DIR: &str = "/etc/zeronat";
const ENV_FILE: &str = "/etc/zeronat/.env";
const COMPOSE_FILE: &str = "/etc/zeronat/compose.yml";
/// Persisted route/listener state, kept in its own subdir so the container mount
/// excludes the secret-bearing .env and compose file. Only port-forwarding
/// servers have per-port routes worth persisting.
const DATA_DIR: &str = "/etc/zeronat/data";
const CONFIG_FILE: &str = "/etc/zeronat/data/server.toml";
const BIN_PATH: &str = "/usr/local/bin/zeronat";
const UNIT: &str = "/etc/systemd/system/zeronat.service";

pub enum Lvl {
    Step,
    Info,
}

/// One labelled command in the summary. The label is a short muted tag; the
/// command sits alone on the next line so a copy-paste grabs exactly it.
pub struct Cmd {
    pub label: &'static str,
    pub cmd: String,
}

pub struct Outcome {
    pub headline: String,
    /// Labelled commands shown in order (e.g. ran, logs, status, console).
    pub cmds: Vec<Cmd>,
    /// A one-line note with no command, e.g. where to change the config.
    pub note: Option<String>,
    pub peer_intro: String,
    pub peer_cmd: String,
}

/// What a successful install/upgrade run produced, before `execute` adds the
/// console command and peer steps: the command that ran, the follow/status
/// commands, and a config note.
struct Started {
    ran: String,
    cmds: Vec<Cmd>,
    note: Option<String>,
}

/// Drives the install. Every external command goes through `run` so the UI can
/// animate while it works; `step`/`info` annotate the progress log.
pub trait Runner {
    fn step(&mut self, desc: String);
    fn info(&mut self, msg: String);
    fn run(&mut self, privileged: bool, program: &str, args: &[&str]) -> Result<Output, String>;
    fn run_with_stdin(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
        input: &File,
    ) -> Result<Output, String>;
    fn run_with_stdout(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
        output: &File,
    ) -> Result<Output, String>;
    /// Ask the operator to confirm within `secs`, used to keep a risky bridge.
    /// Interactive runners read a key with a countdown; headless runners verify
    /// connectivity instead. Returns true to keep, false to let it revert.
    fn confirm(&mut self, prompt: &str, secs: u32) -> bool;
}

fn download_binary(
    r: &mut dyn Runner,
    release: &SelectedRelease,
    target: &str,
) -> Result<(), String> {
    let asset_name = format!("{BINARY_ASSET_PREFIX}-{target}");
    let mut download = download_verified_asset_with_keys(
        release,
        &asset_name,
        release_keys(),
        |url, max_bytes, output| {
            let (program, args) = curl_fetch_command(url, max_bytes);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let out = r.run_with_stdout(false, program, &args, output)?;
            Ok(ok(&out))
        },
    )?;
    let input = download.prepare_install()?;
    let out = r.run_with_stdin(
        true,
        "install",
        &["-m", "0755", "/dev/stdin", BIN_PATH],
        input,
    )?;
    if !ok(&out) {
        return Err(format!("install binary: {}", errtext(&out)));
    }
    Ok(())
}

#[cfg(not(test))]
fn release_keys() -> &'static [TrustedKey] {
    TRUSTED_RELEASE_KEYS
}

#[cfg(test)]
fn release_keys() -> &'static [TrustedKey] {
    TEST_RELEASE_KEYS
}

#[cfg(not(test))]
fn release_for_install() -> Result<SelectedRelease, String> {
    let latest = sys::latest_version()
        .ok_or_else(|| "could not determine the latest signed release".to_string())?;
    SelectedRelease::from_version(&latest)
}

#[cfg(test)]
fn release_for_install() -> Result<SelectedRelease, String> {
    SelectedRelease::from_version("0.25.1")
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
            // Persist per-port routes across restarts. Only port-forwarding servers
            // have routes; tun/tap own every port and keep no per-port routing.
            if cfg.kind == Kind::Ports {
                s.push_str(&format!(" --config {CONFIG_FILE}"));
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

/// Command to open the server's interactive admin console locally. Client
/// installations do not receive the server's administrative credential.
fn console_cmd(cfg: &Config) -> Option<String> {
    let target = match cfg.mode {
        Mode::Server => format!("127.0.0.1:{}", cfg.control),
        Mode::Client => return None,
    };
    Some(match cfg.method {
        // The image is FROM scratch with the binary at /zeronat, and the
        // container receives ZERONAT_ADMIN_SECRET from its env file.
        Method::Docker => format!("docker exec -it zeronat /zeronat admin --server {target}"),
        // sudo lets admin read the root-owned installer environment file.
        Method::Systemd => format!("sudo {BIN_PATH} admin --server {target}"),
    })
}

fn peer_steps(cfg: &Config) -> (String, String) {
    let fwd = forward_flag(cfg);
    match cfg.mode {
        Mode::Server => {
            let server_public = zeronat_secret::server_public(&cfg.secret)
                .expect("validated server secret must derive a public identity");
            let cmd = if cfg.use_dht {
                format!(
                    "curl -fsSL {INSTALL_URL} | sh -s -- --client --dht --server-public {server_public} --credential-prompt {fwd} -y"
                )
            } else {
                let host = sys::pub_ip();
                format!(
                    "curl -fsSL {INSTALL_URL} | sh -s -- --client --server-addr {host}:{} --server-public {server_public} --credential-prompt {fwd} -y",
                    cfg.control
                )
            };
            (
                "Read ZERONAT_CLIENT_SECRET from /etc/zeronat/.env on the server. Run this on the client and enter that value at the hidden prompt:".into(),
                cmd,
            )
        }
        Mode::Client => (String::new(), String::new()),
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

fn env_file(cfg: &Config, sub: &str) -> Result<String, String> {
    let (runtime_secret, client_credential) = match cfg.mode {
        Mode::Server => (
            cfg.secret.clone(),
            zeronat_secret::client_credential(&cfg.secret)
                .map_err(|e| format!("client credential: {e}"))?,
        ),
        Mode::Client => (cfg.server_public.clone(), cfg.secret.clone()),
    };
    let role = if cfg.mode == Mode::Server {
        format!(
            "ZERONAT_CLIENT_ID=client\nZERONAT_CLIENT_SECRET={}\nZERONAT_ADMIN_SECRET={}\n",
            client_credential, cfg.admin_secret
        )
    } else {
        format!("ZERONAT_CLIENT_SECRET={client_credential}\n")
    };
    if cfg.method == Method::Docker && cfg.deploy == Deploy::Compose {
        Ok(format!(
            "ZERONAT_SECRET={runtime_secret}\n{role}ZERONAT_ARGS={sub}\n"
        ))
    } else {
        Ok(format!("ZERONAT_SECRET={runtime_secret}\n{role}"))
    }
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
    // Port-forwarding servers persist routes into DATA_DIR; the dir must exist so
    // the mount source is present and the server's atomic rewrite has a temp dir.
    if cfg.mode == Mode::Server && cfg.kind == Kind::Ports {
        let out = r.run(true, "mkdir", &["-p", DATA_DIR])?;
        if !ok(&out) {
            return Err(format!("mkdir {DATA_DIR}: {}", errtext(&out)));
        }
    }

    r.step("writing env file".into());
    let env = env_file(cfg, &sub)?;
    place(r, env.as_bytes(), "0600", ENV_FILE)?;

    // Build the host bridge before starting zeronat, so the TAP has a bridge to
    // join. A no-op unless this is a server in bridge mode asked to create one.
    setup_bridge(cfg, r)?;

    let started = match cfg.method {
        Method::Docker => install_docker(cfg, &sub, r)?,
        Method::Systemd => install_systemd(cfg, &sub, r)?,
    };

    let mut cmds = vec![Cmd {
        label: "ran",
        cmd: started.ran,
    }];
    cmds.extend(started.cmds);
    if let Some(console) = console_cmd(cfg) {
        cmds.push(Cmd {
            label: "console",
            cmd: console,
        });
    }

    let (peer_intro, peer_cmd) = peer_steps(cfg);
    Ok(Outcome {
        headline: format!("zeronat {} is running", mode_str(cfg)),
        cmds,
        note: started.note,
        peer_intro,
        peer_cmd,
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
        return Err(format!(
            "{} is wireless; bridge a wired NIC instead",
            nic.name
        ));
    }
    if nic.enslaved {
        // A re-run after a successful bridge: the NIC is already a member. If it is
        // already our bridge, the step is done; otherwise it belongs to something else.
        if verify_bridge(&cfg.bridge, &nic.name, r).is_ok() {
            return Ok(());
        }
        return Err(format!(
            "{} is already enslaved to another bridge/bond",
            nic.name
        ));
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
    let mut cmds = match cfg.method {
        Method::Docker if cfg.deploy == Deploy::Compose => {
            let dc = sys::compose_argv();
            let prog = if dc.is_empty() {
                "docker compose".to_string()
            } else {
                dc.join(" ")
            };
            dstep(r, "would fetch the compose file");
            dstep(r, "would pull the image and start via compose");
            vec![
                Cmd {
                    label: "logs",
                    cmd: format!("cd {ETC_DIR} && {prog} logs -f"),
                },
                Cmd {
                    label: "status",
                    cmd: format!("cd {ETC_DIR} && {prog} ps"),
                },
            ]
        }
        Method::Docker => {
            dstep(r, "would pull the image and start the container");
            vec![
                Cmd {
                    label: "logs",
                    cmd: "docker logs -f zeronat".into(),
                },
                Cmd {
                    label: "status",
                    cmd: "docker ps".into(),
                },
            ]
        }
        Method::Systemd => {
            let target = sys::arch_target().unwrap_or("this arch");
            r.info(format!("target {target}"));
            dstep(r, "would download the binary and write a systemd unit");
            dstep(r, "would enable and restart the service");
            vec![
                Cmd {
                    label: "status",
                    cmd: "systemctl status zeronat".into(),
                },
                Cmd {
                    label: "logs",
                    cmd: "journalctl -u zeronat -f".into(),
                },
            ]
        }
    };
    if let Some(console) = console_cmd(cfg) {
        cmds.push(Cmd {
            label: "console",
            cmd: console,
        });
    }
    let (peer_intro, peer_cmd) = peer_steps(cfg);
    Ok(Outcome {
        headline: format!("zeronat {} ready (dry run)", mode_str(cfg)),
        cmds,
        note: None,
        peer_intro,
        peer_cmd,
    })
}

/// Upgrade the existing install in place: download the latest binary and restart
/// the service, and/or pull the latest image and recreate the container. Config
/// (env file, unit, compose file) is left untouched.
pub fn upgrade(offer: &UpgradeOffer, host: &Host, r: &mut dyn Runner) -> Result<Outcome, String> {
    validate_upgrade_credentials(host)?;
    validate_upgrade_deployments(offer, host)?;
    if offer.systemd.is_some() {
        upgrade_systemd(offer, r)?;
    }
    if offer.docker.is_some() {
        upgrade_docker(offer, r)?;
    }
    Ok(upgrade_outcome(offer))
}

pub fn preflight_upgrade(installed: &sys::Installed, host: &Host) -> Result<(), String> {
    validate_upgrade_credentials(host)?;
    validate_installed_version("systemd", installed.systemd.as_deref())?;
    validate_installed_version("docker", installed.docker.as_deref())?;
    let offer = UpgradeOffer {
        latest: String::new(),
        systemd: installed.systemd.clone(),
        docker: installed.docker.clone(),
        compose: installed.compose,
    };
    validate_upgrade_deployments(&offer, host)
}

fn validate_installed_version(deployment: &str, version: Option<&str>) -> Result<(), String> {
    let Some(version) = version else {
        return Ok(());
    };
    SelectedRelease::from_version(version).map_err(|_| {
        format!(
            "cannot verify the installed {deployment} version '{version}'; reinstall it from a signed release before upgrading"
        )
    })?;
    Ok(())
}

fn validate_upgrade_credentials(host: &Host) -> Result<(), String> {
    let legacy = match (&host.existing_secret, &host.existing_client_secret) {
        (Some(identity), Some(credential)) => {
            identity.trim().eq_ignore_ascii_case(credential.trim())
        }
        _ => false,
    };
    if legacy {
        return Err(
            "legacy shared credentials detected; rerun the installer on the server, run its client enrollment command on each client, then retry the upgrade"
                .into(),
        );
    }
    Ok(())
}

fn validate_upgrade_deployments(offer: &UpgradeOffer, host: &Host) -> Result<(), String> {
    if offer.systemd.is_some() {
        let out = sys::run(true, "cat", &[UNIT])?;
        if !ok(&out) {
            return Err(format!("reading {UNIT} before upgrade: {}", errtext(&out)));
        }
        let unit = String::from_utf8_lossy(&out.stdout);
        let command: Vec<String> = unit
            .lines()
            .find_map(|line| line.trim().strip_prefix("ExecStart="))
            .map(|line| line.split_whitespace().map(str::to_string).collect())
            .ok_or_else(|| format!("cannot determine the zeronat command in {UNIT}"))?;
        validate_upgrade_command(&command, "systemd", host)?;
    }

    if offer.docker.is_some() {
        if !offer.compose && host.existing_secret.is_none() {
            return Err(format!(
                "cannot upgrade the docker deployment without {ENV_FILE}; restore its enrollment values first"
            ));
        }
        let command = if offer.compose {
            rendered_compose_command()?
        } else {
            direct_docker_command()?
        };
        validate_upgrade_command(&command, "docker", host)?;
        if !offer.compose {
            let out = sys::run(true, "cat", &[ENV_FILE])?;
            if !ok(&out) {
                return Err(format!(
                    "reading {ENV_FILE} before upgrade: {}",
                    errtext(&out)
                ));
            }
            let current = inspect_container_env_command()?;
            validate_container_env(&current, &String::from_utf8_lossy(&out.stdout))?;
        }
    }
    Ok(())
}

fn inspect_container_env_command() -> Result<Vec<String>, String> {
    let out = sys::run(
        true,
        "docker",
        &["inspect", "-f", "{{json .Config.Env}}", "zeronat"],
    )?;
    if !ok(&out) {
        return Err(format!(
            "inspecting the docker deployment: {}",
            errtext(&out)
        ));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|error| format!("reading the docker environment snapshot: {error}"))
}

fn validate_container_env(current: &[String], env_file: &str) -> Result<(), String> {
    let configured: std::collections::HashMap<&str, &str> = env_file
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#'))
                .then(|| line.split_once('='))
                .flatten()
                .map(|(key, value)| (key.trim(), value))
        })
        .filter(|(key, _)| !key.is_empty())
        .collect();
    let mut current_env = std::collections::HashMap::new();
    for entry in current {
        let (key, value) = entry
            .split_once('=')
            .ok_or("the running container has a malformed environment entry")?;
        current_env.insert(key, value);
    }
    let mut changed: Vec<&str> = configured
        .keys()
        .copied()
        .filter(|key| current_env.get(key).copied() != configured.get(key).copied())
        .collect();
    changed.sort_unstable();
    changed.dedup();
    if changed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "cannot recreate the container because {ENV_FILE} differs from the running container for: {}",
            changed.join(", ")
        ))
    }
}

fn docker_restart_policy(name: String, retries: String) -> Result<String, String> {
    let retries: u64 = retries
        .parse()
        .map_err(|_| "cannot determine the docker restart retry count")?;
    if name == "on-failure" && retries > 0 {
        Ok(format!("{name}:{retries}"))
    } else {
        Ok(name)
    }
}

fn protected_env_file(entries: &[String]) -> Result<DownloadFile, String> {
    let snapshot = DownloadFile::create()?;
    let mut output = snapshot.output();
    for entry in entries {
        validate_env_file_entry(entry)?;
        writeln!(output, "{entry}")
            .map_err(|error| format!("writing the private environment snapshot: {error}"))?;
    }
    output
        .sync_all()
        .map_err(|error| format!("syncing the private environment snapshot: {error}"))?;
    Ok(snapshot)
}

fn validate_env_file_entry(entry: &str) -> Result<(), String> {
    const MAX_LINE: usize = 64 * 1024 - 1;

    let (key, value) = entry
        .split_once('=')
        .ok_or("the running container has a malformed environment entry")?;
    let valid_key = key
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !valid_key
        || value.contains(['\0', '\n', '\r'])
        || value.trim() != value
        || entry.len() > MAX_LINE
    {
        return Err(
            "the running container environment cannot be represented by a protected env file"
                .into(),
        );
    }
    Ok(())
}

fn validate_image_env(current: &[String], image: &[String]) -> Result<(), String> {
    let current_keys: std::collections::HashSet<&str> = current
        .iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, _)| key)
                .ok_or("the running container has a malformed environment entry")
        })
        .collect::<Result<_, _>>()?;
    let mut added = Vec::new();
    for entry in image {
        let key = entry
            .split_once('=')
            .map(|(key, _)| key)
            .ok_or("the pulled image has a malformed environment entry")?;
        if !current_keys.contains(key) {
            added.push(key);
        }
    }
    added.sort_unstable();
    added.dedup();
    if added.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "cannot recreate the container because the pulled image adds environment keys: {}",
            added.join(", ")
        ))
    }
}

fn direct_docker_command() -> Result<Vec<String>, String> {
    let out = sys::run(
        true,
        "docker",
        &[
            "inspect",
            "-f",
            "{{range .Config.Cmd}}{{println .}}{{end}}",
            "zeronat",
        ],
    )?;
    if !ok(&out) {
        return Err(format!(
            "inspecting the docker deployment before upgrade: {}",
            errtext(&out)
        ));
    }
    let command: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if command.is_empty() {
        return Err("cannot determine the zeronat command for the docker deployment".into());
    }
    Ok(command)
}

fn rendered_compose_command() -> Result<Vec<String>, String> {
    let compose = sys::compose_argv();
    if compose.is_empty() {
        return Err("docker compose not available".into());
    }
    let mut args = vec![format!("ZERONAT_IMAGE={IMAGE}")];
    args.extend(compose);
    args.extend([
        "--env-file".into(),
        ENV_FILE.into(),
        "-f".into(),
        COMPOSE_FILE.into(),
        "config".into(),
        "--format".into(),
        "json".into(),
    ]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = sys::run(true, "env", &refs)?;
    if !ok(&out) {
        return Err(format!(
            "rendering {COMPOSE_FILE} before upgrade: {}",
            errtext(&out)
        ));
    }
    parse_compose_command(&out.stdout)
}

fn parse_compose_command(body: &[u8]) -> Result<Vec<String>, String> {
    let config: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| format!("reading rendered compose configuration: {e}"))?;
    let command = config
        .get("services")
        .and_then(|services| services.get("zeronat"))
        .and_then(|service| service.get("command"))
        .ok_or_else(|| format!("cannot determine the zeronat command in {COMPOSE_FILE}"))?;
    let command = match command {
        serde_json::Value::Array(parts) => parts
            .iter()
            .map(|part| {
                part.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("invalid zeronat command in {COMPOSE_FILE}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        serde_json::Value::String(command) => {
            command.split_whitespace().map(str::to_string).collect()
        }
        _ => return Err(format!("invalid zeronat command in {COMPOSE_FILE}")),
    };
    if command.is_empty() {
        return Err(format!(
            "cannot determine the zeronat command in {COMPOSE_FILE}"
        ));
    }
    Ok(command)
}

fn deployment_role(command: &[String]) -> Option<&str> {
    let role_index = usize::from(
        command
            .first()
            .is_some_and(|arg| arg == "zeronat" || arg.ends_with("/zeronat")),
    );
    command.get(role_index).map(String::as_str)
}

fn command_value<'a>(command: &'a [String], flag: &str) -> Option<&'a str> {
    command
        .iter()
        .position(|arg| arg == flag)
        .and_then(|index| command.get(index + 1))
        .map(String::as_str)
}

fn validate_upgrade_command(command: &[String], source: &str, host: &Host) -> Result<(), String> {
    match deployment_role(command) {
        Some("server") => return Ok(()),
        Some("client") => {}
        _ => {
            return Err(format!(
                "cannot determine whether the {source} deployment is a client"
            ));
        }
    }

    if let Some(index) = command.iter().position(|arg| arg == "--config") {
        let path = command
            .get(index + 1)
            .ok_or_else(|| format!("the {source} client command has --config without a path"))?;
        let out = sys::run(true, "cat", &[path])?;
        if !ok(&out) {
            return Err(format!(
                "reading client config {path} before upgrade: {}",
                errtext(&out)
            ));
        }
        if validate_client_config_layout(path, &String::from_utf8_lossy(&out.stdout))? {
            return Ok(());
        }
    }

    validate_enrollment_values(
        command_value(command, "--secret").or(host.existing_secret.as_deref()),
        command_value(command, "--credential").or(host.existing_client_secret.as_deref()),
        source,
    )
}

fn validate_enrollment_values(
    identity: Option<&str>,
    credential: Option<&str>,
    source: &str,
) -> Result<(), String> {
    let action = "rerun the installer on the server, run its client enrollment command on this client, then retry the upgrade";
    let identity =
        identity.ok_or_else(|| format!("the {source} client has no server identity; {action}"))?;
    let credential = credential
        .ok_or_else(|| format!("the {source} client has no client credential; {action}"))?;
    let identity = zeronat_secret::normalize(identity).map_err(|_| {
        format!(
            "the {source} client's server identity must be exactly 64 hexadecimal characters (32 bytes)"
        )
    })?;
    let credential = zeronat_secret::normalize(credential).map_err(|_| {
        format!(
            "the {source} client's credential must be exactly 64 hexadecimal characters (32 bytes)"
        )
    })?;
    if identity == credential {
        return Err(format!("legacy shared credentials detected; {action}"));
    }
    Ok(())
}

fn validate_client_config_layout(path: &str, body: &str) -> Result<bool, String> {
    let mut in_server = false;
    let mut found_server = false;
    let mut secret: Option<String> = None;
    let mut credential: Option<String> = None;
    let mut section = "";
    let mut peer_secret: Option<String> = None;
    let mut exit_via: Option<String> = None;
    let mut provides_peer_session = false;
    let mut server_material = Vec::new();
    let action = "rerun the installer on the server, run its client enrollment command on this client, then retry the upgrade";

    let finish_server = |secret: &mut Option<String>,
                         credential: &mut Option<String>,
                         server_material: &mut Vec<String>|
     -> Result<(), String> {
        let Some(secret) = secret.take() else {
            return Err(format!(
                "client config {path} has a server without an identity; {action}"
            ));
        };
        let Some(credential) = credential.take() else {
            return Err(format!(
                "client config {path} has a server without a credential; {action}"
            ));
        };
        let secret = zeronat_secret::normalize(&secret).map_err(|_| {
            format!("client config {path} has an invalid server identity; {action}")
        })?;
        let credential = zeronat_secret::normalize(&credential).map_err(|_| {
            format!("client config {path} has an invalid client credential; {action}")
        })?;
        if secret == credential {
            return Err(format!(
                "client config {path} has shared credentials; {action}"
            ));
        }
        server_material.push(secret);
        server_material.push(credential);
        Ok(())
    };

    for line in body.lines() {
        let line = strip_config_comment(line).trim();
        if line == "[[servers]]" {
            if in_server {
                finish_server(&mut secret, &mut credential, &mut server_material)?;
            }
            in_server = true;
            section = "server";
            found_server = true;
            continue;
        }
        if line.starts_with('[') {
            if in_server {
                finish_server(&mut secret, &mut credential, &mut server_material)?;
                in_server = false;
            }
            section = match line {
                "[client]" => "client",
                "[tun]" => "tun",
                "[peer]" => "peer",
                _ => "",
            };
            continue;
        }
        match section {
            "server" => {
                if let Some(value) = config_string(line, "secret")? {
                    secret = Some(value);
                }
                if let Some(value) = config_string(line, "credential")? {
                    credential = Some(value);
                }
            }
            "client" => {
                if let Some(value) = config_string(line, "peer_secret")? {
                    peer_secret = Some(value);
                }
            }
            "tun" => {
                if let Some(value) = config_string(line, "exit_via")? {
                    exit_via = Some(value);
                }
            }
            "peer"
                if config_bool(line, "exit")? == Some(true)
                    || config_string(line, "segment")?.is_some() =>
            {
                provides_peer_session = true;
            }
            "peer" => {}
            _ => {}
        }
    }
    if in_server {
        finish_server(&mut secret, &mut credential, &mut server_material)?;
    }
    if let Some(value) = &peer_secret {
        let peer_secret = zeronat_secret::normalize(value).map_err(|_| {
            format!(
                "client config {path} has an invalid peer_secret; set a client-owned 64-character hexadecimal peer secret before upgrading"
            )
        })?;
        if server_material.iter().any(|value| value == &peer_secret) {
            return Err(format!(
                "client config {path} has a peer_secret known by a configured server; replace it with a client-owned secret before upgrading"
            ));
        }
    }
    if let Some(value) = &exit_via {
        zeronat_secret::normalize(value).map_err(|_| {
            format!(
                "client config {path} has an invalid tun exit_via; set it to the provider's 64-character hexadecimal peer identity before upgrading"
            )
        })?;
    }
    if (exit_via.is_some() || provides_peer_session) && peer_secret.is_none() {
        return Err(format!(
            "client config {path} uses peer sessions without [client] peer_secret; add a client-owned 64-character hexadecimal peer secret before upgrading"
        ));
    }
    Ok(found_server)
}

fn strip_config_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quoted {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if character == '#' && !quoted {
            return &line[..index];
        }
    }
    line
}

fn config_string(line: &str, key: &str) -> Result<Option<String>, String> {
    let Some((found, value)) = line.split_once('=') else {
        return Ok(None);
    };
    if found.trim() != key {
        return Ok(None);
    }
    let value = value.trim();
    let Some(value) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(format!("client config has a malformed `{key}` value"));
    };
    Ok(Some(value.to_string()))
}

fn config_bool(line: &str, key: &str) -> Result<Option<bool>, String> {
    let Some((found, value)) = line.split_once('=') else {
        return Ok(None);
    };
    if found.trim() != key {
        return Ok(None);
    }
    match value.trim() {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(format!("client config has a malformed `{key}` value")),
    }
}

fn upgrade_systemd(offer: &UpgradeOffer, r: &mut dyn Runner) -> Result<(), String> {
    let target = sys::arch_target()?;
    r.info(format!("target {target}"));
    let release = SelectedRelease::from_version(&offer.latest)?;

    r.step("downloading latest binary".into());
    download_binary(r, &release, target)?;

    r.step("restarting service".into());
    let out = r.run(true, "systemctl", &["restart", "zeronat"])?;
    if !ok(&out) {
        return Err(format!("systemctl restart: {}", errtext(&out)));
    }
    Ok(())
}

fn upgrade_docker(offer: &UpgradeOffer, r: &mut dyn Runner) -> Result<(), String> {
    if offer.compose {
        let dc = sys::compose_argv();
        if dc.is_empty() {
            return Err("docker compose not available".into());
        }
        let base: Vec<String> = dc[1..]
            .iter()
            .cloned()
            .chain([
                "--env-file".into(),
                ENV_FILE.into(),
                "-f".into(),
                COMPOSE_FILE.into(),
            ])
            .collect();
        r.step("pulling latest image".into());
        compose(r, &dc[0], &base, "pull")?;
        r.step("recreating container".into());
        compose(r, &dc[0], &base, "up")?;
    } else {
        let snapshot = container_snapshot(r)?;
        r.step("pulling latest image".into());
        let out = r.run(true, "docker", &["pull", IMAGE])?;
        if !ok(&out) {
            return Err(format!("docker pull: {}", errtext(&out)));
        }
        r.step("recreating container".into());
        recreate_container(r, snapshot)?;
    }
    Ok(())
}

/// Configuration captured from a plain `docker run` container for recreation.
struct ContainerSnapshot {
    cmd: Vec<String>,
    env: Vec<String>,
    caps: Vec<String>,
    devices: Vec<String>,
    binds: Vec<String>,
    network: String,
    restart: String,
}

fn container_snapshot(r: &mut dyn Runner) -> Result<ContainerSnapshot, String> {
    if !std::path::Path::new(ENV_FILE).exists() {
        return Err(format!(
            "cannot recreate the container without {ENV_FILE}; restore its enrollment values before upgrading"
        ));
    }
    let cmd = inspect_lines_required(r, "{{range .Config.Cmd}}{{println .}}{{end}}")?;
    if cmd.is_empty() {
        return Err("cannot determine the zeronat command for the docker deployment".into());
    }
    let env = inspect_container_env(r)?;
    let caps = inspect_lines_required(r, "{{range .HostConfig.CapAdd}}{{println .}}{{end}}")?;
    let devices = inspect_lines_required(
        r,
        "{{range .HostConfig.Devices}}{{printf \"%s:%s:%s\\n\" .PathOnHost .PathInContainer .CgroupPermissions}}{{end}}",
    )?;
    let binds = inspect_lines_required(r, "{{range .HostConfig.Binds}}{{println .}}{{end}}")?;
    let network = inspect_lines_required(r, "{{.HostConfig.NetworkMode}}")?
        .into_iter()
        .next()
        .unwrap_or_default();
    let restart_name = inspect_lines_required(r, "{{.HostConfig.RestartPolicy.Name}}")?
        .into_iter()
        .next()
        .unwrap_or_default();
    let restart_retries =
        inspect_lines_required(r, "{{.HostConfig.RestartPolicy.MaximumRetryCount}}")?
            .into_iter()
            .next()
            .unwrap_or_else(|| "0".into());
    let restart = docker_restart_policy(restart_name, restart_retries)?;
    Ok(ContainerSnapshot {
        cmd,
        env,
        caps,
        devices,
        binds,
        network,
        restart,
    })
}

fn recreate_container(r: &mut dyn Runner, snapshot: ContainerSnapshot) -> Result<(), String> {
    let ContainerSnapshot {
        cmd,
        env,
        caps,
        devices,
        binds,
        network,
        restart,
    } = snapshot;

    let image_env = inspect_image_env(r)?;
    validate_image_env(&env, &image_env)?;
    let env_file = protected_env_file(&env)?;
    let env_path = env_file
        .path()
        .to_str()
        .ok_or("the private environment snapshot path is not valid UTF-8")?;

    let out = r.run(true, "docker", &["rm", "-f", "zeronat"])?;
    if !ok(&out) {
        return Err(format!("docker rm: {}", errtext(&out)));
    }

    let mut args: Vec<String> = vec!["run".into(), "-d".into(), "--name".into(), "zeronat".into()];
    if !restart.is_empty() && restart != "no" {
        args.push("--restart".into());
        args.push(restart);
    }
    if !network.is_empty() {
        args.push("--network".into());
        args.push(network);
    }
    for c in &caps {
        args.push("--cap-add".into());
        args.push(c.clone());
    }
    for d in &devices {
        args.push("--device".into());
        args.push(d.clone());
    }
    for b in &binds {
        args.push("-v".into());
        args.push(b.clone());
    }
    args.push("--env-file".into());
    args.push(env_path.into());
    args.push(IMAGE.into());
    args.extend(cmd);

    let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = r.run(true, "docker", &aref)?;
    if !ok(&out) {
        return Err(format!("docker run: {}", errtext(&out)));
    }
    Ok(())
}

fn inspect_lines_required(r: &mut dyn Runner, fmt: &str) -> Result<Vec<String>, String> {
    let out = r.run(true, "docker", &["inspect", "-f", fmt, "zeronat"])?;
    if !ok(&out) {
        return Err(format!(
            "inspecting the docker deployment: {}",
            errtext(&out)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn inspect_container_env(r: &mut dyn Runner) -> Result<Vec<String>, String> {
    let out = r.run(
        true,
        "docker",
        &["inspect", "-f", "{{json .Config.Env}}", "zeronat"],
    )?;
    if !ok(&out) {
        return Err(format!(
            "inspecting the docker deployment: {}",
            errtext(&out)
        ));
    }
    serde_json::from_slice::<Option<Vec<String>>>(&out.stdout)
        .map(Option::unwrap_or_default)
        .map_err(|error| format!("reading the docker environment snapshot: {error}"))
}

fn inspect_image_env(r: &mut dyn Runner) -> Result<Vec<String>, String> {
    let out = r.run(
        true,
        "docker",
        &["image", "inspect", "-f", "{{json .Config.Env}}", IMAGE],
    )?;
    if !ok(&out) {
        return Err(format!(
            "inspecting the pulled docker image: {}",
            errtext(&out)
        ));
    }
    serde_json::from_slice::<Option<Vec<String>>>(&out.stdout)
        .map(Option::unwrap_or_default)
        .map_err(|error| format!("reading the pulled image environment: {error}"))
}

fn upgrade_outcome(offer: &UpgradeOffer) -> Outcome {
    let mut parts = Vec::new();
    if let Some(c) = &offer.systemd {
        parts.push(format!("systemd {c} -> {}", offer.latest));
    }
    if let Some(c) = &offer.docker {
        parts.push(format!("docker {c} -> {}", offer.latest));
    }
    let summary = parts.join(", ");
    let cmds = if offer.docker.is_some() {
        let dc = sys::compose_argv();
        if offer.compose && !dc.is_empty() {
            let dcj = dc.join(" ");
            vec![
                Cmd {
                    label: "logs",
                    cmd: format!("cd {ETC_DIR} && {dcj} logs -f"),
                },
                Cmd {
                    label: "status",
                    cmd: format!("cd {ETC_DIR} && {dcj} ps"),
                },
            ]
        } else {
            vec![
                Cmd {
                    label: "logs",
                    cmd: "docker logs -f zeronat".into(),
                },
                Cmd {
                    label: "status",
                    cmd: "docker ps".into(),
                },
            ]
        }
    } else {
        vec![
            Cmd {
                label: "status",
                cmd: "systemctl status zeronat".into(),
            },
            Cmd {
                label: "logs",
                cmd: "journalctl -u zeronat -f".into(),
            },
        ]
    };
    Outcome {
        headline: format!("zeronat upgraded: {summary}"),
        cmds,
        note: None,
        peer_intro: String::new(),
        peer_cmd: String::new(),
    }
}

fn install_docker(cfg: &Config, sub: &str, r: &mut dyn Runner) -> Result<Started, String> {
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
        let base: Vec<String> = dc[1..]
            .iter()
            .cloned()
            .chain([
                "--env-file".into(),
                ENV_FILE.into(),
                "-f".into(),
                COMPOSE_FILE.into(),
            ])
            .collect();

        r.step("pulling image".into());
        compose(r, &dc[0], &base, "pull")?;
        r.step("starting via compose".into());
        compose(r, &dc[0], &base, "up")?;

        let view: Vec<&str> = std::iter::once(dc[0].as_str())
            .chain(base.iter().map(|s| s.as_str()))
            .collect();
        let dcj = dc.join(" ");
        Ok(Started {
            ran: format!("{} up -d", view.join(" ")),
            cmds: vec![
                Cmd {
                    label: "logs",
                    cmd: format!("cd {ETC_DIR} && {dcj} logs -f"),
                },
                Cmd {
                    label: "status",
                    cmd: format!("cd {ETC_DIR} && {dcj} ps"),
                },
            ],
            note: Some(format!("change deployment settings in {ENV_FILE}")),
        })
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
        // Persist the route config across container recreation. The data subdir
        // (not the file) is mounted: a not-yet-written file would otherwise make
        // docker create a directory in its place, and the subdir keeps the .env
        // secret out of the container.
        if cfg.kind == Kind::Ports {
            args.extend(["-v".into(), format!("{DATA_DIR}:{DATA_DIR}")]);
        }
        args.extend(["--env-file".into(), ENV_FILE.into(), IMAGE.into()]);
        args.extend(sub.split_whitespace().map(|s| s.to_string()));
        let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        r.step("starting container".into());
        let out = r.run(true, "docker", &aref)?;
        if !ok(&out) {
            return Err(format!("docker run: {}", errtext(&out)));
        }
        Ok(Started {
            ran: format!("docker {}", args.join(" ")),
            cmds: vec![
                Cmd {
                    label: "logs",
                    cmd: "docker logs -f zeronat".into(),
                },
                Cmd {
                    label: "status",
                    cmd: "docker ps".into(),
                },
            ],
            note: Some(format!("change deployment settings in {ENV_FILE}")),
        })
    }
}

fn compose(r: &mut dyn Runner, prog: &str, base: &[String], verb: &str) -> Result<(), String> {
    let mut args = vec![format!("ZERONAT_IMAGE={IMAGE}"), prog.to_string()];
    args.extend_from_slice(base);
    if verb == "up" {
        args.push("up".into());
        args.push("-d".into());
    } else {
        args.push(verb.into());
    }
    let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = r.run(true, "env", &aref)?;
    if ok(&out) {
        Ok(())
    } else {
        Err(format!("compose {verb}: {}", errtext(&out)))
    }
}

fn install_systemd(cfg: &Config, sub: &str, r: &mut dyn Runner) -> Result<Started, String> {
    let target = sys::arch_target()?;
    r.info(format!("target {target}"));
    let release = release_for_install()?;

    r.step("downloading zeronat binary".into());
    download_binary(r, &release, target)?;

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
         StateDirectory=zeronat\n\
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
    let out = r.run(true, "systemctl", &["enable", "zeronat"])?;
    if !ok(&out) {
        return Err(format!("enable: {}", errtext(&out)));
    }
    // `enable --now` is a no-op on an already-active unit, so a re-install with
    // a changed env file or unit would keep running the old config. Restart
    // applies it; on a fresh install it is the start.
    let out = r.run(true, "systemctl", &["restart", "zeronat"])?;
    if !ok(&out) {
        return Err(format!("restart: {}", errtext(&out)));
    }
    Ok(Started {
        ran: "systemctl enable zeronat && systemctl restart zeronat".into(),
        cmds: vec![
            Cmd {
                label: "status",
                cmd: "systemctl status zeronat".into(),
            },
            Cmd {
                label: "logs",
                cmd: "journalctl -u zeronat -f".into(),
            },
        ],
        note: Some(format!(
            "change deployment settings in {ENV_FILE} and {UNIT}"
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        check_forwards, compose, console_cmd, deployment_role, env_file, execute, install_systemd,
        parse_compose_command, peer_steps, subcmd, upgrade, validate_client_config_layout,
        validate_container_env, validate_installed_version, Runner, COMPOSE_FILE, IMAGE,
        TEST_RELEASE_BINARY, TEST_RELEASE_MANIFEST, TEST_RELEASE_SIGNATURE,
    };
    use crate::args::Host;
    use crate::ui::{Config, Kind, Method, Mode, UpgradeOffer};
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::path::PathBuf;
    use std::process::Output;

    const TEST_SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const TEST_ADMIN_SECRET: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn cfg() -> Config {
        let mut cfg = Config::new(false, false, None);
        cfg.secret = TEST_SECRET.into();
        cfg.admin_secret = TEST_ADMIN_SECRET.into();
        cfg
    }

    /// Records every command instead of running it; all commands succeed.
    struct FakeRunner {
        cmds: Vec<String>,
    }

    impl Runner for FakeRunner {
        fn step(&mut self, _: String) {}
        fn info(&mut self, _: String) {}
        fn run(&mut self, _: bool, program: &str, args: &[&str]) -> Result<Output, String> {
            use std::os::unix::process::ExitStatusExt;
            self.cmds.push(format!("{program} {}", args.join(" ")));
            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
        fn run_with_stdin(
            &mut self,
            _: bool,
            program: &str,
            args: &[&str],
            input: &std::fs::File,
        ) -> Result<Output, String> {
            let mut input = input.try_clone().unwrap();
            let mut bytes = Vec::new();
            input.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"downloaded binary");
            self.run(false, program, args)
        }
        fn run_with_stdout(
            &mut self,
            _: bool,
            program: &str,
            args: &[&str],
            output: &std::fs::File,
        ) -> Result<Output, String> {
            let url = args
                .iter()
                .find(|arg| arg.starts_with("https://"))
                .copied()
                .unwrap_or_default();
            let bytes = if url.ends_with(".manifest") {
                TEST_RELEASE_MANIFEST
            } else if url.ends_with(".minisig") {
                TEST_RELEASE_SIGNATURE
            } else {
                TEST_RELEASE_BINARY
            };
            output.try_clone().unwrap().write_all(bytes).unwrap();
            self.run(false, program, args)
        }
        fn confirm(&mut self, _: &str, _: u32) -> bool {
            true
        }
    }

    struct FailedDownloadRunner {
        path: Option<PathBuf>,
    }

    impl Runner for FailedDownloadRunner {
        fn step(&mut self, _: String) {}
        fn info(&mut self, _: String) {}
        fn run(&mut self, _: bool, _: &str, _: &[&str]) -> Result<Output, String> {
            use std::os::unix::process::ExitStatusExt;

            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
        fn run_with_stdin(
            &mut self,
            _: bool,
            _: &str,
            _: &[&str],
            _: &std::fs::File,
        ) -> Result<Output, String> {
            panic!("failed download must not be installed")
        }
        fn run_with_stdout(
            &mut self,
            _: bool,
            _: &str,
            _: &[&str],
            output: &std::fs::File,
        ) -> Result<Output, String> {
            use std::os::unix::process::ExitStatusExt;

            let fd_path = format!("/proc/self/fd/{}", output.as_raw_fd());
            self.path = Some(std::fs::read_link(fd_path).unwrap());
            output
                .try_clone()
                .unwrap()
                .write_all(b"partial download")
                .unwrap();
            Ok(Output {
                status: std::process::ExitStatus::from_raw(1 << 8),
                stdout: Vec::new(),
                stderr: b"download failed".to_vec(),
            })
        }
        fn confirm(&mut self, _: &str, _: u32) -> bool {
            true
        }
    }

    #[test]
    fn systemd_install_cleans_failed_download() {
        let mut r = FailedDownloadRunner { path: None };
        let mut c = cfg();
        c.mode = Mode::Server;

        let result = install_systemd(&c, "server", &mut r);
        let path = r.path.expect("curl should receive an output file");
        let remained = path.parent().unwrap().exists();

        assert!(result.is_err());
        assert!(!remained, "failed download directory should be removed");
    }

    #[test]
    fn upgrade_rejects_an_unknown_installed_version() {
        let error = validate_installed_version("systemd", Some("unknown")).unwrap_err();
        assert!(
            error.contains("reinstall it from a signed release"),
            "{error}"
        );
    }

    #[test]
    fn upgrade_refuses_legacy_shared_credentials_before_commands() {
        let offer = UpgradeOffer {
            latest: "0.25.1".into(),
            systemd: Some("0.24.0".into()),
            docker: None,
            compose: false,
        };
        let host = Host {
            have_docker: false,
            have_compose: false,
            existing_secret: Some(TEST_SECRET.into()),
            existing_client_secret: Some(TEST_SECRET.to_ascii_uppercase()),
            existing_admin_secret: Some(TEST_ADMIN_SECRET.into()),
            ssh_port: 22,
        };
        let mut runner = FakeRunner { cmds: Vec::new() };

        let error = match upgrade(&offer, &host, &mut runner) {
            Ok(_) => panic!("legacy credentials must block the upgrade"),
            Err(error) => error,
        };

        assert!(error.contains("legacy shared credentials"), "{error}");
        assert!(error.contains("rerun the installer"), "{error}");
        assert!(runner.cmds.is_empty());
    }

    #[test]
    fn legacy_client_config_layouts_block_upgrade() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let missing =
            format!("[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"{secret}\"\n");
        let error = validate_client_config_layout("client.toml", &missing).unwrap_err();
        assert!(error.contains("without a credential"), "{error}");

        let shared = format!(
            "[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"{secret}\"\ncredential = \"{}\"\n",
            secret.to_ascii_uppercase()
        );
        let error = validate_client_config_layout("client.toml", &shared).unwrap_err();
        assert!(error.contains("shared credentials"), "{error}");
    }

    #[test]
    fn current_client_config_layout_reaches_upgrade() {
        let current = "[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\ncredential = \"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\"\n";
        assert!(validate_client_config_layout("client.toml", current).unwrap());
    }

    #[test]
    fn peer_config_requires_a_peer_key_and_identity_before_upgrade() {
        let server = "[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\ncredential = \"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\"\n";
        let peer_identity = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer_secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let missing = format!("{server}\n[tun]\nexit_via = \"{peer_identity}\"\n");
        let error = validate_client_config_layout("client.toml", &missing).unwrap_err();
        assert!(error.contains("without [client] peer_secret"), "{error}");

        let legacy = format!(
            "[client]\npeer_secret = \"{peer_secret}\"\n\n{server}\n[tun]\nexit_via = \"office\"\n"
        );
        let error = validate_client_config_layout("client.toml", &legacy).unwrap_err();
        assert!(error.contains("invalid tun exit_via"), "{error}");

        let current = format!(
            "[client]\npeer_secret = \"{peer_secret}\"\n\n{server}\n[tun]\nexit_via = \"{peer_identity}\"\n"
        );
        assert!(validate_client_config_layout("client.toml", &current).unwrap());

        let relay_known = format!(
            "[client]\npeer_secret = \"{}\"\n\n{server}[peer]\nexit = true\n",
            "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
        );
        let error = validate_client_config_layout("client.toml", &relay_known).unwrap_err();
        assert!(
            error.contains("peer_secret known by a configured server"),
            "{error}"
        );

        let credential_known = format!(
            "[client]\npeer_secret = \"{}\"\n\n{server}[peer]\nexit = true\n",
            "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100"
        );
        let error = validate_client_config_layout("client.toml", &credential_known).unwrap_err();
        assert!(
            error.contains("peer_secret known by a configured server"),
            "{error}"
        );
    }

    #[test]
    fn container_environment_requires_recreation_values() {
        let current = [
            "ZERONAT_SECRET=current".into(),
            "MODE=client".into(),
            "PATH=/usr/local/bin:/usr/bin".into(),
        ];

        validate_container_env(&current, "ZERONAT_SECRET=current\nMODE=client\n").unwrap();

        let error = validate_container_env(
            &current,
            "ZERONAT_SECRET=replacement\nMODE=client\nEXTRA=value\n",
        )
        .unwrap_err();
        assert!(error.contains("ZERONAT_SECRET"), "{error}");
        assert!(error.contains("EXTRA"), "{error}");
        assert!(!error.contains("PATH"), "{error}");
        assert!(!error.contains("current"), "{error}");
        assert!(!error.contains("replacement"), "{error}");
    }

    #[test]
    fn docker_restart_policy_keeps_failure_retry_limit() {
        assert_eq!(
            super::docker_restart_policy("on-failure".into(), "7".into()).unwrap(),
            "on-failure:7"
        );
        assert_eq!(
            super::docker_restart_policy("always".into(), "0".into()).unwrap(),
            "always"
        );
    }

    #[test]
    fn environment_snapshot_refuses_unrepresentable_entries_and_new_image_keys() {
        assert!(super::validate_env_file_entry(
            "ZERONAT_ARGS=client --config /etc/zeronat/client.toml"
        )
        .is_ok());
        assert!(super::validate_env_file_entry("#SECRET=value").is_err());
        assert!(super::validate_env_file_entry("SECRET= trailing ").is_err());
        assert!(
            super::validate_env_file_entry(&format!("LONG={}", "x".repeat(64 * 1024))).is_err()
        );

        let current = ["PATH=/old".into(), "SECRET=current".into()];
        super::validate_image_env(&current, &["PATH=/new".into()]).unwrap();
        let error = super::validate_image_env(&current, &["NEW=value".into()]).unwrap_err();
        assert!(error.contains("NEW"), "{error}");
        assert!(!error.contains("value"), "{error}");
    }

    #[test]
    fn client_role_is_not_bypassed_by_a_server_argument_value() {
        let command = [
            "client".to_string(),
            "--config".to_string(),
            "server".to_string(),
        ];

        assert_eq!(deployment_role(&command), Some("client"));
    }

    #[test]
    fn client_config_layout_accepts_comments_outside_strings() {
        let current = "[[servers]] # home\nname = \"home#lab\" # label\naddr = \"dht\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\" # identity\ncredential = \"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\" # credential\n";

        assert!(validate_client_config_layout("client.toml", current).unwrap());
    }

    #[test]
    fn compose_pins_the_protocol_v6_image() {
        let mut runner = FakeRunner { cmds: Vec::new() };
        let base = vec![
            "compose".to_string(),
            "-f".to_string(),
            COMPOSE_FILE.to_string(),
        ];

        compose(&mut runner, "docker", &base, "pull").unwrap();

        assert_eq!(
            runner.cmds,
            [format!(
                "env ZERONAT_IMAGE={IMAGE} docker compose -f {COMPOSE_FILE} pull"
            )]
        );
    }

    #[test]
    fn rendered_compose_command_selects_the_zeronat_service() {
        let rendered = br#"{"services":{"other":{"command":["server"]},"zeronat":{"command":["client","--config","/etc/zeronat/client.toml"]}}}"#;

        assert_eq!(
            parse_compose_command(rendered).unwrap(),
            ["client", "--config", "/etc/zeronat/client.toml"]
        );
    }

    #[test]
    fn systemd_install_restarts_after_writing_config() {
        let mut r = FakeRunner { cmds: Vec::new() };
        let mut c = cfg();
        c.mode = Mode::Server;
        install_systemd(&c, "server", &mut r).unwrap();

        let reload = r.cmds.iter().position(|c| c == "systemctl daemon-reload");
        let restart = r.cmds.iter().position(|c| c == "systemctl restart zeronat");
        assert!(r
            .cmds
            .iter()
            .any(|command| command.contains("/zeronat-v6-")));
        assert!(r.cmds.contains(&"systemctl enable zeronat".to_string()));
        assert!(restart.unwrap() > reload.unwrap());
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
        assert_eq!(
            console_cmd(&c).unwrap(),
            "sudo /usr/local/bin/zeronat admin --server 127.0.0.1:2222"
        );
    }

    #[test]
    fn client_install_does_not_receive_an_admin_command() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "vps.example:9000".into();
        c.method = Method::Docker;
        assert!(console_cmd(&c).is_none());
    }

    #[test]
    fn generated_env_authorizes_the_installed_client() {
        let mut c = cfg();
        c.mode = Mode::Server;
        let credential = zeronat_secret::client_credential(TEST_SECRET).unwrap();
        let public = zeronat_secret::server_public(TEST_SECRET).unwrap();
        let server = env_file(&c, "server --control 2222").unwrap();
        assert!(server.contains(&format!("ZERONAT_SECRET={TEST_SECRET}\n")));
        assert!(server.contains("ZERONAT_CLIENT_ID=client\n"));
        assert!(server.contains(&format!("ZERONAT_CLIENT_SECRET={credential}\n")));
        assert!(server.contains(&format!("ZERONAT_ADMIN_SECRET={TEST_ADMIN_SECRET}\n")));

        c.mode = Mode::Client;
        c.secret = credential.clone();
        c.server_public = public.clone();
        let client = env_file(&c, "client --server 127.0.0.1:2222").unwrap();
        assert!(client.contains(&format!("ZERONAT_SECRET={public}\n")));
        assert!(client.contains(&format!("ZERONAT_CLIENT_SECRET={credential}\n")));
        assert!(!client.contains(&format!("ZERONAT_SECRET={TEST_SECRET}\n")));
        assert!(!client.contains("ZERONAT_CLIENT_ID="));
        assert!(!client.contains("ZERONAT_ADMIN_SECRET="));
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
    fn enrolled_client_does_not_generate_a_server_command() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "vps.example:9000".into();
        c.ports = "443/tcp".into();
        let (_, cmd) = peer_steps(&c);
        assert!(cmd.is_empty());
    }

    #[test]
    fn server_ports() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.ports = "443/tcp 51820/udp".into();
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --tcp 443 --udp 51820 --config /etc/zeronat/data/server.toml"
        );
    }

    #[test]
    fn server_dht_publish() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.use_dht = true;
        c.ports = "80/tcp".into();
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --tcp 80 --server dht --config /etc/zeronat/data/server.toml"
        );
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
            "server --control 2222 --tcp 443 --server dht --announce-ip 203.0.113.1 --announce-port 9000 --config /etc/zeronat/data/server.toml"
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
        c.secret = TEST_SECRET.into();
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
        c.secret = TEST_SECRET.into();
        let (_, cmd) = peer_steps(&c);
        assert!(cmd.contains("get.sh"), "{cmd}");
        assert!(cmd.ends_with(" -y"), "{cmd}");
    }

    #[test]
    fn generated_client_enrollment_does_not_disclose_the_server_secret() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.use_dht = true;
        c.secret = TEST_SECRET.into();
        let (_, cmd) = peer_steps(&c);
        let public = zeronat_secret::server_public(TEST_SECRET).unwrap();
        let credential = zeronat_secret::client_credential(TEST_SECRET).unwrap();

        assert!(!cmd.contains(TEST_SECRET), "{cmd}");
        assert!(cmd.contains(&public), "{cmd}");
        assert!(!cmd.contains(&credential), "{cmd}");
        assert!(!cmd.contains("--credential "), "{cmd}");
        assert!(cmd.contains("--credential-prompt"), "{cmd}");
    }

    #[test]
    fn generated_systemd_summary_contains_no_reusable_credential() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.method = Method::Systemd;
        c.use_dht = true;
        c.ports = "443/tcp".into();
        let mut runner = FakeRunner { cmds: Vec::new() };

        let outcome = execute(&c, true, &mut runner).unwrap();
        let mut summary = outcome
            .cmds
            .iter()
            .map(|entry| entry.cmd.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        summary.push('\n');
        summary.push_str(&outcome.peer_intro);
        summary.push('\n');
        summary.push_str(&outcome.peer_cmd);
        let credential = zeronat_secret::client_credential(TEST_SECRET).unwrap();

        assert!(!summary.contains(TEST_SECRET), "{summary}");
        assert!(!summary.contains(TEST_ADMIN_SECRET), "{summary}");
        assert!(!summary.contains(&credential), "{summary}");
        assert!(!summary.contains("--secret "), "{summary}");
    }
}
