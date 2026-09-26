//! The execute phase: turns a finished `Config` into a running zeronat, by the
//! same steps the shell installer performs. Each action reports a line so the
//! TUI can show live progress; an error short-circuits with a message.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::process::Output;
use zeronat_install_support::release::{
    embedded_public_key, ReleaseManifest, MANIFEST_LIMIT, MANIFEST_NAME, SIGNATURE_LIMIT,
    SIGNATURE_NAME,
};
use zeronat_install_support::DownloadFile;

use crate::bridge;
use crate::sys::{self, errtext, ok};
use crate::ui::{Config, Deploy, Kind, Method, Mode, UpgradeOffer};

/// Seconds the operator has to confirm a risky bridge before it auto-reverts.
const BRIDGE_TIMEOUT: u32 = 30;

// Shown to the user, so it uses the friendly Pages URL.
const INSTALL_URL: &str = "https://paltaio.github.io/zeronat/get.sh";
// Internal fetches (compose templates) hit the repo directly to stay current.
const RAW_BASE: &str = "https://raw.githubusercontent.com/paltaio/zeronat/main";
const RELEASE_DOWNLOAD_BASE: &str = "https://github.com/paltaio/zeronat/releases/download";
const LATEST_URL: &str = "https://github.com/paltaio/zeronat/releases/latest";
const IMAGE: &str = "ghcr.io/paltaio/zeronat:latest";
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

fn release_key() -> Result<[u8; 32], String> {
    embedded_public_key()
        .ok_or_else(|| "this build has no release public key and cannot verify downloads".into())
}

/// Fetch a small release file (manifest or signature) into memory, bounded by
/// `limit` so a hostile server cannot balloon the download.
fn fetch_small(r: &mut dyn Runner, url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let out = r.run(
        false,
        "curl",
        &[
            "-fsSL",
            "--max-filesize",
            &limit.to_string(),
            "--max-time",
            "60",
            url,
        ],
    )?;
    if !ok(&out) {
        return Err(format!("download failed for {url}"));
    }
    if out.stdout.len() as u64 > limit {
        return Err(format!("{url} exceeds its size limit"));
    }
    Ok(out.stdout)
}

/// Download the latest release binary and install it to `BIN_PATH`, after
/// verifying the release's signed manifest and the binary's digest against it.
/// Everything is fetched from the resolved tag, not `latest`, so the manifest
/// and the binary cannot straddle a release published mid-install.
fn download_binary(r: &mut dyn Runner, public_key: &[u8; 32], target: &str) -> Result<(), String> {
    let out = r.run(
        false,
        "curl",
        &[
            "-fsSL",
            "-I",
            "-o",
            "/dev/null",
            "-w",
            "%{url_effective}",
            "--max-time",
            "15",
            LATEST_URL,
        ],
    )?;
    if !ok(&out) {
        return Err("could not resolve the latest release".into());
    }
    let version = sys::version_from_url(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| "could not resolve the latest release".to_string())?;
    let base = format!("{RELEASE_DOWNLOAD_BASE}/v{version}");
    let manifest = fetch_small(r, &format!("{base}/{MANIFEST_NAME}"), MANIFEST_LIMIT)?;
    let signature = fetch_small(r, &format!("{base}/{SIGNATURE_NAME}"), SIGNATURE_LIMIT)?;
    let manifest = ReleaseManifest::verify(&manifest, &signature, public_key)?;
    if manifest.version() != version {
        return Err(format!(
            "the signed release manifest is for {} but the release tag is v{version}",
            manifest.version()
        ));
    }

    let name = format!("zeronat-{target}");
    let size = manifest
        .expected_size(&name)
        .ok_or_else(|| format!("the release manifest has no entry for {name}"))?;
    let mut download = DownloadFile::create()?;
    let out = r.run_with_stdout(
        false,
        "curl",
        &[
            "-fsSL",
            "--max-filesize",
            &size.to_string(),
            "--max-time",
            "180",
            &format!("{base}/{name}"),
        ],
        download.output(),
    )?;
    if !ok(&out) {
        return Err(format!("download failed (no release asset for {target}?)"));
    }
    let mut input = download.prepare_install()?;
    manifest.verify_artifact(&name, input)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("failed to read downloaded binary: {e}"))?;
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
/// Under a seed the server authorizes the client id `client` and the client
/// goes by it; an explicit install names both in its env file.
pub fn subcmd(cfg: &Config) -> String {
    let a = zn_args(cfg);
    let id = if cfg.explicit { "" } else { " --id client" };
    match cfg.mode {
        Mode::Server => {
            let mut s = format!("server --control {}", cfg.control);
            if !cfg.explicit {
                s.push_str(" --client client");
            }
            s.push_str(&a);
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
        Mode::Client if cfg.use_dht => format!("client --server dht{id}{a}"),
        Mode::Client => format!("client --server {}{id}{a}", client_addr(cfg)),
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
        // container receives its env file, whose ZERONAT_SEED or
        // ZERONAT_ADMIN_SECRET admin reads.
        Method::Docker => format!("docker exec -it zeronat /zeronat admin --server {target}"),
        // sudo lets admin read the root-owned env file.
        Method::Systemd => format!("sudo {BIN_PATH} admin --server {target}"),
    })
}

/// The intro line and the single-line command to run on the *other* machine,
/// mirroring the shell installer.
fn peer_steps(cfg: &Config) -> (String, String) {
    let fwd = forward_flag(cfg);
    // The one-liner lands in scrollback and shell history on the other machine,
    // so it carries prompt flags instead of the credentials themselves. An
    // explicit install says so, since the other side defaults to a seed.
    let (names, entry, prompts) = match (cfg.explicit, cfg.use_dht) {
        (true, true) => (
            "ZERONAT_SECRET and ZERONAT_DISCOVERY_SECRET",
            "enter each value at its hidden prompt",
            "--explicit-secrets --secret-prompt --discovery-prompt",
        ),
        (true, false) => (
            "ZERONAT_SECRET",
            "enter it at the hidden prompt",
            "--explicit-secrets --secret-prompt",
        ),
        (false, _) => (
            "ZERONAT_SEED",
            "enter it at the hidden prompt",
            "--secret-prompt",
        ),
    };
    match cfg.mode {
        Mode::Server => {
            let cmd = if cfg.use_dht {
                format!("curl -fsSL {INSTALL_URL} | sh -s -- --client --dht {prompts} {fwd} -y")
            } else {
                let host = sys::pub_ip();
                format!(
                    "curl -fsSL {INSTALL_URL} | sh -s -- --client --server-addr {host}:{} {prompts} {fwd} -y",
                    cfg.control
                )
            };
            (
                format!(
                    "Read {names} from {ENV_FILE} on this server. Run this on the client (the machine behind CG-NAT) and {entry}:"
                ),
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
            let cmd =
                format!("curl -fsSL {INSTALL_URL} | sh -s -- --server {disc} {prompts} {fwd} -y");
            (
                format!(
                    "Read {names} from {ENV_FILE} on this machine. Run this on the server and {entry}:"
                ),
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

/// The env file: one `ZERONAT_SEED` plus any credential given on its own, or
/// with `explicit` the network secret, the `client` authorization, and the
/// admin secret spelled out.
fn env_file(cfg: &Config, sub: &str) -> String {
    let mut env = if cfg.explicit {
        let mut env = format!("ZERONAT_SECRET={}\n", cfg.secret);
        if cfg.mode == Mode::Server {
            env.push_str(&format!(
                "ZERONAT_CLIENT_ID=client\nZERONAT_CLIENT_SECRET={}\nZERONAT_ADMIN_SECRET={}\n",
                cfg.secret, cfg.admin_secret
            ));
        } else {
            env.push_str(&format!("ZERONAT_CLIENT_SECRET={}\n", cfg.secret));
        }
        env
    } else {
        let mut env = format!("ZERONAT_SEED={}\n", cfg.secret);
        if cfg.mode == Mode::Server && !cfg.admin_secret.is_empty() {
            env.push_str(&format!("ZERONAT_ADMIN_SECRET={}\n", cfg.admin_secret));
        }
        env
    };
    if cfg.use_dht && !cfg.discovery.is_empty() {
        env.push_str(&format!("ZERONAT_DISCOVERY_SECRET={}\n", cfg.discovery));
    }
    if cfg.method == Method::Docker && cfg.deploy == Deploy::Compose {
        env.push_str(&format!(
            "ZERONAT_USER={}\nZERONAT_ARGS={sub}\n",
            container_user(cfg)
        ));
    }
    env
}

/// Container user for docker deploys. Binding a port below 1024 needs
/// CAP_NET_BIND_SERVICE and tun/tap needs CAP_NET_ADMIN, and capabilities
/// added to a non-root container user never become effective (docker sets no
/// ambient set), so those configurations must run as root with everything
/// else dropped. Only a ports config whose every bound port (forwards, plus
/// the control port on a server) parses unprivileged runs as the nonroot uid.
fn container_user(cfg: &Config) -> &'static str {
    let control_ok =
        cfg.mode != Mode::Server || cfg.control.parse::<u16>().is_ok_and(|port| port >= 1024);
    let unprivileged = cfg.kind == Kind::Ports
        && control_ok
        && cfg.ports.split_whitespace().all(|tok| {
            tok.split_once('/')
                .and_then(|(num, _)| num.parse::<u16>().ok())
                .is_some_and(|port| port >= 1024)
        });
    if unprivileged {
        "65532:65532"
    } else {
        "0:0"
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
        // A nonroot container writes its route config into the mounted dir.
        if cfg.method == Method::Docker && container_user(cfg) != "0:0" {
            let out = r.run(true, "chown", &[container_user(cfg), DATA_DIR])?;
            if !ok(&out) {
                return Err(format!("chown {DATA_DIR}: {}", errtext(&out)));
            }
        }
    }

    r.step("writing env file".into());
    let env = env_file(cfg, &sub);
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
pub fn upgrade(offer: &UpgradeOffer, r: &mut dyn Runner) -> Result<Outcome, String> {
    if offer.systemd.is_some() {
        upgrade_systemd(r)?;
    }
    if offer.docker.is_some() {
        upgrade_docker(offer, r)?;
    }
    Ok(upgrade_outcome(offer))
}

fn upgrade_systemd(r: &mut dyn Runner) -> Result<(), String> {
    let key = release_key()?;
    let target = sys::arch_target()?;
    r.info(format!("target {target}"));

    r.step("downloading latest binary".into());
    download_binary(r, &key, target)?;

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
            .chain(["-f".into(), COMPOSE_FILE.into()])
            .collect();
        r.step("pulling latest image".into());
        compose(r, &dc[0], &base, "pull")?;
        r.step("recreating container".into());
        compose(r, &dc[0], &base, "up")?;
    } else {
        r.step("pulling latest image".into());
        let out = r.run(true, "docker", &["pull", IMAGE])?;
        if !ok(&out) {
            return Err(format!("docker pull: {}", errtext(&out)));
        }
        r.step("recreating container".into());
        recreate_container(r)?;
    }
    Ok(())
}

/// Recreate a plain `docker run` container on the freshly pulled image, carrying
/// over the run config read back from the old container. The secret rides via the
/// installer env file, which a docker-run install always wrote.
fn recreate_container(r: &mut dyn Runner) -> Result<(), String> {
    let cmd = inspect_lines(r, "{{range .Config.Cmd}}{{println .}}{{end}}");
    let user = inspect_lines(r, "{{.Config.User}}")
        .into_iter()
        .next()
        .unwrap_or_default();
    let caps = inspect_lines(r, "{{range .HostConfig.CapAdd}}{{println .}}{{end}}");
    let cap_drops = inspect_lines(r, "{{range .HostConfig.CapDrop}}{{println .}}{{end}}");
    let security_opts = inspect_lines(r, "{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}");
    let devices = inspect_lines(
        r,
        "{{range .HostConfig.Devices}}{{println .PathOnHost}}{{end}}",
    );
    let binds = inspect_lines(r, "{{range .HostConfig.Binds}}{{println .}}{{end}}");
    let network = inspect_lines(r, "{{.HostConfig.NetworkMode}}")
        .into_iter()
        .next()
        .unwrap_or_else(|| "host".into());
    let restart = inspect_lines(r, "{{.HostConfig.RestartPolicy.Name}}")
        .into_iter()
        .next()
        .unwrap_or_else(|| "unless-stopped".into());

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
    if !user.is_empty() {
        args.push("--user".into());
        args.push(user);
    }
    for c in &cap_drops {
        args.push("--cap-drop".into());
        args.push(c.clone());
    }
    for s in &security_opts {
        args.push("--security-opt".into());
        args.push(s.clone());
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
    if std::path::Path::new(ENV_FILE).exists() {
        args.push("--env-file".into());
        args.push(ENV_FILE.into());
    }
    args.push(IMAGE.into());
    args.extend(cmd);

    let aref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = r.run(true, "docker", &aref)?;
    if !ok(&out) {
        return Err(format!("docker run: {}", errtext(&out)));
    }
    Ok(())
}

fn inspect_lines(r: &mut dyn Runner, fmt: &str) -> Vec<String> {
    r.run(true, "docker", &["inspect", "-f", fmt, "zeronat"])
        .ok()
        .filter(ok)
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
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
            note: Some(format!("change ports or the secret by editing {ENV_FILE}")),
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
            "--user".into(),
            container_user(cfg).into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
        ];
        if cfg.kind != Kind::Ports {
            // NET_RAW keeps the legacy-iptables fallback working when nft is
            // unusable on the host kernel; NET_BIND_SERVICE covers a
            // privileged control port.
            args.extend([
                "--cap-add".into(),
                "NET_ADMIN".into(),
                "--cap-add".into(),
                "NET_RAW".into(),
                "--cap-add".into(),
                "NET_BIND_SERVICE".into(),
                "--device".into(),
                "/dev/net/tun".into(),
            ]);
        } else if container_user(cfg) == "0:0" {
            args.extend(["--cap-add".into(), "NET_BIND_SERVICE".into()]);
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
            note: Some(format!("change ports or the secret by editing {ENV_FILE}")),
        })
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

fn install_systemd(cfg: &Config, sub: &str, r: &mut dyn Runner) -> Result<Started, String> {
    install_systemd_with(cfg, sub, &release_key()?, r)
}

fn install_systemd_with(
    cfg: &Config,
    sub: &str,
    public_key: &[u8; 32],
    r: &mut dyn Runner,
) -> Result<Started, String> {
    let target = sys::arch_target()?;
    r.info(format!("target {target}"));

    r.step("downloading zeronat binary".into());
    download_binary(r, public_key, target)?;

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
            "change ports or the secret by editing {ENV_FILE} and {UNIT}"
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        check_forwards, console_cmd, container_user, env_file, execute, install_systemd_with,
        peer_steps, recreate_container, subcmd, Runner, MANIFEST_NAME, SIGNATURE_NAME,
    };
    use crate::ui::{Config, Deploy, Kind, Method, Mode};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Write as _};
    use std::path::PathBuf;
    use std::process::Output;

    const TEST_SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const TEST_ADMIN_SECRET: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TEST_DISCOVERY_SECRET: &str =
        "5555555555555555555555555555555555555555555555555555555555555555";

    fn cfg() -> Config {
        let mut cfg = Config::new(false, false, None);
        cfg.secret = TEST_SECRET.into();
        cfg.admin_secret = TEST_ADMIN_SECRET.into();
        cfg
    }

    fn test_key() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .unwrap();
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    /// A signed release for the running host: the tag redirect, the manifest
    /// listing `content` under this host's target name, and its signature.
    struct TestRelease {
        public: [u8; 32],
        redirect: Vec<u8>,
        manifest: Vec<u8>,
        signature: Vec<u8>,
    }

    fn test_release(content: &[u8]) -> TestRelease {
        let (signing, public) = test_key();
        let name = format!("zeronat-{}", crate::sys::arch_target().unwrap());
        let digest = zeronat_secret::encode(Sha256::digest(content).into());
        let manifest = format!(
            "zeronat-release-v1 v0.25.1\n{digest} {} {name}\n",
            content.len()
        )
        .into_bytes();
        let signature = signing
            .sign(&manifest)
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .into_bytes();
        TestRelease {
            public,
            redirect: b"https://github.com/paltaio/zeronat/releases/tag/v0.25.1".to_vec(),
            manifest,
            signature,
        }
    }

    fn release_response(release: &TestRelease, args: &[&str]) -> Vec<u8> {
        let url = args.last().copied().unwrap_or_default();
        if url.ends_with("/releases/latest") {
            release.redirect.clone()
        } else if url.ends_with(MANIFEST_NAME) {
            release.manifest.clone()
        } else if url.ends_with(SIGNATURE_NAME) {
            release.signature.clone()
        } else {
            Vec::new()
        }
    }

    /// Records every command instead of running it; all commands succeed, and
    /// curl fetches answer from the fake release.
    struct FakeRunner {
        cmds: Vec<String>,
        release: TestRelease,
    }

    impl Runner for FakeRunner {
        fn step(&mut self, _: String) {}
        fn info(&mut self, _: String) {}
        fn run(&mut self, _: bool, program: &str, args: &[&str]) -> Result<Output, String> {
            use std::os::unix::process::ExitStatusExt;
            self.cmds.push(format!("{program} {}", args.join(" ")));
            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: release_response(&self.release, args),
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
            output
                .try_clone()
                .unwrap()
                .write_all(b"downloaded binary")
                .unwrap();
            self.run(false, program, args)
        }
        fn confirm(&mut self, _: &str, _: u32) -> bool {
            true
        }
    }

    struct FailedDownloadRunner {
        path: Option<PathBuf>,
        release: TestRelease,
    }

    impl Runner for FailedDownloadRunner {
        fn step(&mut self, _: String) {}
        fn info(&mut self, _: String) {}
        fn run(&mut self, _: bool, _: &str, args: &[&str]) -> Result<Output, String> {
            use std::os::unix::process::ExitStatusExt;

            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: release_response(&self.release, args),
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
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::process::ExitStatusExt;

            // The download is the `artifact` under the temp dir that is this
            // open file.
            let file = output.metadata().unwrap();
            let path = std::fs::read_dir(std::env::temp_dir())
                .unwrap()
                .filter_map(|entry| Some(entry.ok()?.path().join("artifact")))
                .find(|path| {
                    std::fs::symlink_metadata(path)
                        .is_ok_and(|m| (m.dev(), m.ino()) == (file.dev(), file.ino()))
                })
                .expect("the download file is under the temp dir");
            self.path = Some(path);
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
        let release = test_release(b"downloaded binary");
        let public = release.public;
        let mut r = FailedDownloadRunner {
            path: None,
            release,
        };
        let mut c = cfg();
        c.mode = Mode::Server;

        let result = install_systemd_with(&c, "server", &public, &mut r);
        let path = r.path.expect("curl should receive an output file");
        let remained = path.parent().unwrap().exists();

        assert!(result.is_err());
        assert!(!remained, "failed download directory should be removed");
    }

    #[test]
    fn systemd_install_restarts_after_writing_config() {
        let release = test_release(b"downloaded binary");
        let public = release.public;
        let mut r = FakeRunner {
            cmds: Vec::new(),
            release,
        };
        let mut c = cfg();
        c.mode = Mode::Server;
        install_systemd_with(&c, "server", &public, &mut r).unwrap();

        let reload = r.cmds.iter().position(|c| c == "systemctl daemon-reload");
        let restart = r.cmds.iter().position(|c| c == "systemctl restart zeronat");
        assert!(r.cmds.contains(&"systemctl enable zeronat".to_string()));
        assert!(restart.unwrap() > reload.unwrap());
    }

    // The downloaded bytes disagree with the signed manifest, so the install
    // step must never run; FakeRunner's stdin handler would record it.
    #[test]
    fn systemd_install_refuses_a_download_that_does_not_match_the_manifest() {
        let release = test_release(b"a different binary");
        let public = release.public;
        let mut r = FakeRunner {
            cmds: Vec::new(),
            release,
        };
        let mut c = cfg();
        c.mode = Mode::Server;

        assert!(install_systemd_with(&c, "server", &public, &mut r).is_err());
        assert!(
            !r.cmds.iter().any(|c| c.starts_with("install ")),
            "unverified binary was installed"
        );
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

    // Both sides get the one seed; the server authorizes `client` on the
    // command line and the client goes by that id. An admin secret given on
    // its own rides along.
    #[test]
    fn generated_env_is_one_seed() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.admin_secret.clear();
        assert_eq!(
            env_file(&c, "server --control 2222"),
            format!("ZERONAT_SEED={TEST_SECRET}\n")
        );
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --client client --config /etc/zeronat/data/server.toml"
        );
        c.admin_secret = TEST_ADMIN_SECRET.into();
        assert_eq!(
            env_file(&c, "server --control 2222"),
            format!("ZERONAT_SEED={TEST_SECRET}\nZERONAT_ADMIN_SECRET={TEST_ADMIN_SECRET}\n")
        );

        c.mode = Mode::Client;
        c.server_addr = "1.2.3.4:2222".into();
        assert_eq!(
            env_file(&c, "client --server 1.2.3.4:2222"),
            format!("ZERONAT_SEED={TEST_SECRET}\n")
        );
        assert_eq!(subcmd(&c), "client --server 1.2.3.4:2222 --id client");
    }

    #[test]
    fn explicit_env_authorizes_the_installed_client() {
        let mut c = cfg();
        c.explicit = true;
        c.mode = Mode::Server;
        let server = env_file(&c, "server --control 2222");
        assert!(server.contains(&format!("ZERONAT_SECRET={TEST_SECRET}\n")));
        assert!(server.contains("ZERONAT_CLIENT_ID=client\n"));
        assert!(server.contains(&format!("ZERONAT_CLIENT_SECRET={TEST_SECRET}\n")));
        assert!(server.contains(&format!("ZERONAT_ADMIN_SECRET={TEST_ADMIN_SECRET}\n")));
        assert!(!server.contains("ZERONAT_SEED="));
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --config /etc/zeronat/data/server.toml"
        );

        c.mode = Mode::Client;
        c.server_addr = "1.2.3.4:2222".into();
        let client = env_file(&c, "client --server 127.0.0.1:2222");
        assert!(client.contains(&format!("ZERONAT_SECRET={TEST_SECRET}\n")));
        assert!(client.contains(&format!("ZERONAT_CLIENT_SECRET={TEST_SECRET}\n")));
        assert!(!client.contains("ZERONAT_CLIENT_ID="));
        assert!(!client.contains("ZERONAT_ADMIN_SECRET="));
        assert!(!client.contains("ZERONAT_SEED="));
        assert_eq!(subcmd(&c), "client --server 1.2.3.4:2222");
    }

    // A seeded dht install writes no discovery value and asks the other
    // machine for the seed only.
    #[test]
    fn seeded_dht_install_derives_the_discovery_secret() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.use_dht = true;
        c.ports = "80/tcp".into();
        let env = env_file(&c, "server --control 2222");
        assert!(!env.contains("ZERONAT_DISCOVERY_SECRET"), "{env}");
        let (intro, cmd) = peer_steps(&c);
        assert!(intro.contains("ZERONAT_SEED"), "{intro}");
        assert!(cmd.contains("--secret-prompt"), "{cmd}");
        assert!(!cmd.contains("--discovery"), "{cmd}");
        assert!(!cmd.contains("--explicit-secrets"), "{cmd}");

        c.mode = Mode::Client;
        let (_, cmd) = peer_steps(&c);
        assert!(cmd.contains("--server --dht --secret-prompt"), "{cmd}");
    }

    // An explicit dht install carries the discovery secret in the env file it
    // writes; the one-liner for the other machine prompts for it instead, and
    // a host:port install carries neither.
    #[test]
    fn dht_install_keeps_the_discovery_secret_in_the_env_file() {
        let mut c = cfg();
        c.explicit = true;
        c.mode = Mode::Server;
        c.use_dht = true;
        c.discovery = TEST_DISCOVERY_SECRET.into();
        c.ports = "80/tcp".into();
        let env = env_file(&c, "server --control 2222");
        assert!(env.contains(&format!(
            "ZERONAT_DISCOVERY_SECRET={TEST_DISCOVERY_SECRET}\n"
        )));
        let (_, cmd) = peer_steps(&c);
        assert!(!cmd.contains(TEST_DISCOVERY_SECRET), "{cmd}");
        assert!(cmd.contains("--discovery-prompt"), "{cmd}");

        c.mode = Mode::Client;
        let env = env_file(&c, "client --server dht");
        assert!(env.contains(&format!(
            "ZERONAT_DISCOVERY_SECRET={TEST_DISCOVERY_SECRET}\n"
        )));
        let (_, cmd) = peer_steps(&c);
        assert!(!cmd.contains(TEST_DISCOVERY_SECRET), "{cmd}");
        assert!(cmd.contains("--discovery-prompt"), "{cmd}");

        c.use_dht = false;
        c.server_addr = "vps.example:9000".into();
        let env = env_file(&c, "client --server vps.example:9000");
        assert!(!env.contains("ZERONAT_DISCOVERY_SECRET"));
        let (_, cmd) = peer_steps(&c);
        assert!(!cmd.contains("--discovery"), "{cmd}");
    }

    #[test]
    fn peer_commands_prompt_for_credentials_instead_of_embedding_them() {
        let mut c = cfg();
        c.explicit = true;
        c.mode = Mode::Server;
        c.use_dht = true;
        c.discovery = TEST_DISCOVERY_SECRET.into();
        c.ports = "443/tcp".into();
        let (intro, cmd) = peer_steps(&c);
        assert!(!cmd.contains(TEST_SECRET), "{cmd}");
        assert!(!cmd.contains(TEST_DISCOVERY_SECRET), "{cmd}");
        assert!(cmd.contains("--explicit-secrets"), "{cmd}");
        assert!(cmd.contains("--secret-prompt"), "{cmd}");
        assert!(cmd.contains("--discovery-prompt"), "{cmd}");
        assert!(intro.contains("/etc/zeronat/.env"), "{intro}");

        c.mode = Mode::Client;
        let (intro, cmd) = peer_steps(&c);
        assert!(!cmd.contains(TEST_SECRET), "{cmd}");
        assert!(!cmd.contains(TEST_DISCOVERY_SECRET), "{cmd}");
        assert!(cmd.contains("--explicit-secrets"), "{cmd}");
        assert!(cmd.contains("--secret-prompt"), "{cmd}");
        assert!(cmd.contains("--discovery-prompt"), "{cmd}");
        assert!(intro.contains("/etc/zeronat/.env"), "{intro}");
    }

    // Everything the installer prints back - the ran/console commands, the note,
    // and the one-liner for the other machine - stays free of the three
    // credentials; they belong in the 0600 env file only.
    #[test]
    fn no_summary_output_contains_a_credential() {
        for method in [Method::Systemd, Method::Docker] {
            let mut c = cfg();
            c.mode = Mode::Server;
            c.method = method;
            c.use_dht = true;
            c.discovery = TEST_DISCOVERY_SECRET.into();
            c.ports = "443/tcp".into();
            let mut r = FakeRunner {
                cmds: Vec::new(),
                release: test_release(b"downloaded binary"),
            };
            let outcome = execute(&c, true, &mut r).unwrap();

            let mut text: Vec<String> = outcome.cmds.iter().map(|e| e.cmd.clone()).collect();
            text.push(outcome.headline);
            text.extend(outcome.note);
            text.push(outcome.peer_intro);
            text.push(outcome.peer_cmd);
            text.extend(r.cmds);
            let text = text.join("\n");

            assert!(!text.contains(TEST_SECRET), "{method:?}: {text}");
            assert!(!text.contains(TEST_ADMIN_SECRET), "{method:?}: {text}");
            assert!(!text.contains(TEST_DISCOVERY_SECRET), "{method:?}: {text}");
        }
    }

    #[test]
    fn console_none_for_dht_client() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.use_dht = true;
        assert!(console_cmd(&c).is_none());
    }

    #[test]
    fn container_user_is_nonroot_only_when_every_port_is_unprivileged() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::Ports;
        c.control = "2222".into();
        c.ports = "8443/tcp 51820/udp".into();
        assert_eq!(container_user(&c), "65532:65532");

        c.ports = "443/tcp 8443/tcp".into();
        assert_eq!(container_user(&c), "0:0");

        // Unparseable ports must not end up nonroot and unable to bind.
        c.ports = "bogus".into();
        assert_eq!(container_user(&c), "0:0");

        // The server binds its control port too.
        c.ports = "8443/tcp".into();
        c.control = "443".into();
        assert_eq!(container_user(&c), "0:0");
        // A client dials the control port instead of binding it.
        c.mode = Mode::Client;
        assert_eq!(container_user(&c), "65532:65532");

        c.mode = Mode::Server;
        c.control = "2222".into();
        c.kind = Kind::All;
        assert_eq!(container_user(&c), "0:0");
        c.kind = Kind::Bridge;
        assert_eq!(container_user(&c), "0:0");
    }

    /// Answers `docker inspect` with a hardened container's settings and
    /// records every command, so the recreate path can be checked to carry
    /// them over.
    struct InspectRunner {
        cmds: Vec<String>,
    }

    impl Runner for InspectRunner {
        fn step(&mut self, _: String) {}
        fn info(&mut self, _: String) {}
        fn run(&mut self, _: bool, program: &str, args: &[&str]) -> Result<Output, String> {
            use std::os::unix::process::ExitStatusExt;
            self.cmds.push(format!("{program} {}", args.join(" ")));
            let stdout = if program == "docker" && args.first() == Some(&"inspect") {
                match args[2] {
                    f if f.contains(".Config.User") => b"65532:65532\n".to_vec(),
                    f if f.contains("CapDrop") => b"ALL\n".to_vec(),
                    f if f.contains("SecurityOpt") => b"no-new-privileges\n".to_vec(),
                    f if f.contains(".Config.Cmd") => {
                        b"server\n--control\n2222\n--tcp\n8443\n".to_vec()
                    }
                    f if f.contains("NetworkMode") => b"host\n".to_vec(),
                    f if f.contains("RestartPolicy") => b"unless-stopped\n".to_vec(),
                    _ => Vec::new(),
                }
            } else {
                Vec::new()
            };
            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout,
                stderr: Vec::new(),
            })
        }
        fn run_with_stdin(
            &mut self,
            _: bool,
            program: &str,
            args: &[&str],
            _: &std::fs::File,
        ) -> Result<Output, String> {
            self.run(false, program, args)
        }
        fn run_with_stdout(
            &mut self,
            _: bool,
            program: &str,
            args: &[&str],
            _: &std::fs::File,
        ) -> Result<Output, String> {
            self.run(false, program, args)
        }
        fn confirm(&mut self, _: &str, _: u32) -> bool {
            true
        }
    }

    #[test]
    fn recreated_container_keeps_user_and_capability_flags() {
        let mut r = InspectRunner { cmds: Vec::new() };
        recreate_container(&mut r).unwrap();
        let run = r
            .cmds
            .iter()
            .find(|c| c.starts_with("docker run"))
            .expect("recreate must run the container");
        assert!(run.contains("--user 65532:65532"), "{run}");
        assert!(run.contains("--cap-drop ALL"), "{run}");
        assert!(run.contains("--security-opt no-new-privileges"), "{run}");
    }

    #[test]
    fn compose_env_selects_the_container_user() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.method = Method::Docker;
        c.deploy = Deploy::Compose;
        c.kind = Kind::Ports;
        c.ports = "8443/tcp".into();
        let env = env_file(&c, "server --control 2222");
        assert!(env.contains("ZERONAT_USER=65532:65532\n"), "{env}");

        c.ports = "443/tcp".into();
        let env = env_file(&c, "server --control 2222");
        assert!(env.contains("ZERONAT_USER=0:0\n"), "{env}");
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
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --client client --tcp 443 --udp 51820 --config /etc/zeronat/data/server.toml"
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
            "server --control 2222 --client client --tcp 80 --server dht --config /etc/zeronat/data/server.toml"
        );
    }

    #[test]
    fn client_address_gets_default_port() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "1.2.3.4".into();
        c.ports = "443/tcp".into();
        assert_eq!(
            subcmd(&c),
            "client --server 1.2.3.4:2222 --id client --tcp 443"
        );
    }

    #[test]
    fn client_address_keeps_explicit_port() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.server_addr = "host.example:9000".into();
        c.ports = "443/tcp".into();
        assert_eq!(
            subcmd(&c),
            "client --server host.example:9000 --id client --tcp 443"
        );
    }

    #[test]
    fn client_dht() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.use_dht = true;
        c.ports = "443/tcp".into();
        assert_eq!(subcmd(&c), "client --server dht --id client --tcp 443");
    }

    #[test]
    fn bridge_tap() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::Bridge;
        c.tap = "zn0".into();
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --client client --tap zn0"
        );
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
            "server --control 2222 --client client --tap zn0 --bridge br0 --tap-mtu 1400"
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
            "server --control 2222 --client client --tcp 443 --server dht --announce-ip 203.0.113.1 --announce-port 9000 --config /etc/zeronat/data/server.toml"
        );
    }

    #[test]
    fn server_all_traffic_excepts_ssh_port() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::All;
        c.ssh_port = 2200;
        assert_eq!(
            subcmd(&c),
            "server --control 2222 --client client --tun --except 2200"
        );
    }

    #[test]
    fn server_all_traffic_forward_everything() {
        let mut c = cfg();
        c.mode = Mode::Server;
        c.kind = Kind::All;
        c.exclude_ssh = false;
        assert_eq!(subcmd(&c), "server --control 2222 --client client --tun");
    }

    #[test]
    fn client_all_traffic_has_no_except() {
        let mut c = cfg();
        c.mode = Mode::Client;
        c.kind = Kind::All;
        c.server_addr = "1.2.3.4".into();
        assert_eq!(subcmd(&c), "client --server 1.2.3.4:2222 --id client --tun");
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
}
