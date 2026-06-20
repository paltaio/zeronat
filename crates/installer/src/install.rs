//! The execute phase: turns a finished `Config` into a running zeronat, by the
//! same steps the shell installer performs. Each action reports a line so the
//! TUI can show live progress; an error short-circuits with a message.

use std::process::Output;

use crate::sys::{self, errtext, ok};
use crate::ui::{Config, Deploy, Kind, Method, Mode};

// Shown to the user, so it uses the friendly Pages URL.
const INSTALL_URL: &str = "https://paltaio.github.io/zeronat/install.sh";
// Internal fetches (compose templates) hit the repo directly to stay current.
const RAW_BASE: &str = "https://raw.githubusercontent.com/paltaio/zeronat/main";
const RELEASE_BASE: &str = "https://github.com/paltaio/zeronat/releases/latest/download";
const IMAGE: &str = "ghcr.io/paltaio/zeronat:latest";
const ETC_DIR: &str = "/etc/zeronat";
const ENV_FILE: &str = "/etc/zeronat/zeronat.env";
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
}

/// Drives the install. Every external command goes through `run` so the UI can
/// animate while it works; `step`/`info` annotate the progress log.
pub trait Runner {
    fn step(&mut self, desc: String);
    fn info(&mut self, msg: String);
    fn run(&mut self, privileged: bool, program: &str, args: &[&str]) -> Result<Output, String>;
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
        Kind::Bridge => format!(" --tap {}", cfg.tap),
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
            if cfg.use_dht {
                s.push_str(" --server dht");
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
    }
}

fn mode_str(cfg: &Config) -> &'static str {
    match cfg.mode {
        Mode::Server => "server",
        Mode::Client => "client",
    }
}

/// The intro line and the single-line command to run on the *other* machine,
/// mirroring the shell installer. One line so it is easy to copy and paste.
fn peer_steps(cfg: &Config) -> (String, String) {
    let fwd = forward_flag(cfg);
    match cfg.mode {
        Mode::Server => {
            let cmd = if cfg.use_dht {
                format!(
                    "curl -fsSL {INSTALL_URL} | sh -s -- --client --dht --secret {} {fwd}",
                    cfg.secret
                )
            } else {
                let host = sys::pub_ip();
                format!(
                    "curl -fsSL {INSTALL_URL} | sh -s -- --client --server-addr {host}:{} --secret {} {fwd}",
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
                "curl -fsSL {INSTALL_URL} | sh -s -- --server {disc} --secret {} {fwd}",
                cfg.secret
            );
            (
                "Run this on the server (it must use the same secret):".into(),
                cmd,
            )
        }
    }
}

pub fn execute(cfg: &Config, dry: bool, r: &mut dyn Runner) -> Result<Outcome, String> {
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
    let _ = r.run(true, "rm", &["-f", "/etc/zeronat/.env"]);

    let manage = match cfg.method {
        Method::Docker => install_docker(cfg, &sub, r)?,
        Method::Systemd => install_systemd(cfg, &sub, r)?,
    };

    let (peer_intro, peer_cmd) = peer_steps(cfg);
    Ok(Outcome {
        manage,
        headline: format!("zeronat {} is running", mode_str(cfg)),
        peer_intro,
        peer_cmd,
    })
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
            format!("{prog} ... logs -f")
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
    })
}

fn install_docker(cfg: &Config, sub: &str, r: &mut dyn Runner) -> Result<String, String> {
    let _ = r.run(true, "docker", &["rm", "-f", "zeronat"]);

    if cfg.deploy == Deploy::Compose {
        let src = if cfg.kind == Kind::Bridge {
            "compose.bridge.yml"
        } else {
            "compose.yml"
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
                "--project-directory".into(),
                ETC_DIR.into(),
            ])
            .collect();

        r.step("pulling image".into());
        compose(r, &dc[0], &base, "pull")?;
        r.step("starting via compose".into());
        compose(r, &dc[0], &base, "up")?;

        let view: Vec<&str> = std::iter::once(dc[0].as_str())
            .chain(base.iter().map(|s| s.as_str()))
            .collect();
        Ok(format!(
            "{} logs -f    # status: {} ps",
            view.join(" "),
            view.join(" ")
        ))
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
        if cfg.kind == Kind::Bridge {
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
        Ok("docker logs -f zeronat    # status: docker ps".into())
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

fn install_systemd(cfg: &Config, sub: &str, r: &mut dyn Runner) -> Result<String, String> {
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
    Ok("systemctl status zeronat    # logs: journalctl -u zeronat -f".into())
}

#[cfg(test)]
mod tests {
    use super::{peer_steps, subcmd};
    use crate::ui::{Config, Kind, Mode};

    fn cfg() -> Config {
        Config::new(false, false, None)
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
}
