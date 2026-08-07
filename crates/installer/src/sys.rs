//! Thin wrappers over the host tools the install drives: privilege handling,
//! command execution with captured output, downloads, and small probes. Nothing
//! here touches the terminal, so it is safe to call while the TUI is on screen.

use std::process::{Command, Output};
use zeronat_install_support::{installed_service_manager, SelectedRelease, SERVICE_BINARY_PATH};
pub use zeronat_install_support::{ServiceInstall, ServiceManager};

pub fn is_root() -> bool {
    // SAFETY: geteuid has no failure mode and does not dereference memory.
    (unsafe { libc::geteuid() }) == 0
}

pub fn have(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn have_compose() -> bool {
    Command::new("sh")
        .arg("-c")
        .arg("docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn service_manager() -> Option<ServiceManager> {
    detect_service_manager(|path| std::path::Path::new(path).exists(), have)
}

fn detect_service_manager(
    exists: impl Fn(&str) -> bool,
    command_exists: impl Fn(&str) -> bool,
) -> Option<ServiceManager> {
    if exists("/run/systemd/system") && command_exists("systemctl") {
        Some(ServiceManager::Systemd)
    } else if exists("/etc/rc.common") && exists("/sbin/procd") {
        Some(ServiceManager::Procd)
    } else if exists("/sbin/openrc-run")
        && command_exists("rc-service")
        && command_exists("rc-update")
    {
        Some(ServiceManager::OpenRc)
    } else {
        None
    }
}

/// `docker compose` vs the legacy `docker-compose`; empty if neither is present.
pub fn compose_argv() -> Vec<String> {
    if Command::new("sh")
        .arg("-c")
        .arg("docker compose version >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        vec!["docker".into(), "compose".into()]
    } else if have("docker-compose") {
        vec!["docker-compose".into()]
    } else {
        Vec::new()
    }
}

/// A fresh random 256-bit secret, hex-encoded.
pub fn gen_secret() -> Result<String, String> {
    zeronat_secret::generate().map_err(|e| format!("cannot read the system random source: {e}"))
}

/// Cache sudo credentials up front (prompting on the normal terminal, before the
/// alt screen) so privileged steps later never prompt mid-render.
pub fn ensure_privilege() -> Result<(), String> {
    if is_root() {
        return Ok(());
    }
    if !have("sudo") {
        return Err("need root: run as root or install sudo".into());
    }
    let ok = Command::new("sudo")
        .arg("-v")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err("sudo authentication failed".into());
    }
    // Refresh the timestamp every minute so a slow privileged step never crosses
    // the sudo timeout and re-prompts for a password into the raw-mode terminal.
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        let alive = Command::new("sudo")
            .args(["-n", "-v"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !alive {
            break;
        }
    });
    Ok(())
}

/// Run a command, escalating with sudo when `privileged` and not already root.
pub fn run(privileged: bool, program: &str, args: &[&str]) -> Result<Output, String> {
    let out = command(privileged, program, args).output();
    out.map_err(|e| format!("failed to run {program}: {e}"))
}

pub fn run_with_stdin(
    privileged: bool,
    program: &str,
    args: &[&str],
    input: std::fs::File,
) -> Result<Output, String> {
    let out = command(privileged, program, args)
        .stdin(std::process::Stdio::from(input))
        .output();
    out.map_err(|e| format!("failed to run {program}: {e}"))
}

pub fn run_with_stdout(
    privileged: bool,
    program: &str,
    args: &[&str],
    output: std::fs::File,
) -> Result<Output, String> {
    let out = command(privileged, program, args)
        .stdout(std::process::Stdio::from(output))
        .output();
    out.map_err(|e| format!("failed to run {program}: {e}"))
}

fn command(privileged: bool, program: &str, args: &[&str]) -> Command {
    if privileged && !is_root() {
        let mut command = Command::new("sudo");
        command.arg(program).args(args);
        command
    } else {
        let mut command = Command::new(program);
        command.args(args);
        command
    }
}

pub fn ok(out: &Output) -> bool {
    out.status.success()
}

pub fn errtext(out: &Output) -> String {
    let s = String::from_utf8_lossy(&out.stderr);
    let s = s.trim();
    if s.is_empty() {
        format!("exit {}", out.status.code().unwrap_or(-1))
    } else {
        s.lines().last().unwrap_or(s).to_string()
    }
}

pub fn pub_ip() -> String {
    for u in [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ] {
        if let Ok(o) = Command::new("curl")
            .args(["-fsSL", "--max-time", "5", u])
            .output()
        {
            if o.status.success() {
                let ip = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !ip.is_empty() {
                    return ip;
                }
            }
        }
    }
    "YOUR_SERVER_IP".to_string()
}

pub fn existing_secret() -> Option<String> {
    existing_env_value("ZERONAT_SECRET")
}

/// An administrative secret already on disk, kept across installer re-runs.
pub fn existing_admin_secret() -> Option<String> {
    existing_env_value("ZERONAT_ADMIN_SECRET")
}

/// A client credential already on disk, kept across installer re-runs.
pub fn existing_client_secret() -> Option<String> {
    existing_env_value("ZERONAT_CLIENT_SECRET")
}

fn existing_env_value(key: &str) -> Option<String> {
    let out = run(true, "cat", &["/etc/zeronat/.env"]).ok()?;
    if !out.status.success() {
        return None;
    }
    env_value(&String::from_utf8_lossy(&out.stdout), key)
}

fn env_value(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for line in body.lines() {
        if let Some(v) = line.strip_prefix(&prefix) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// The SSH port to offer to protect in all-traffic mode: the port of the current
/// SSH session when the installer is run over one, else the first `Port` in
/// sshd_config, else 22.
pub fn ssh_port() -> u16 {
    // SSH_CONNECTION is "clientip clientport serverip serverport"; the 4th field
    // is the port the operator is connected through, i.e. the one to keep.
    if let Ok(c) = std::env::var("SSH_CONNECTION") {
        if let Some(p) = c.split_whitespace().nth(3).and_then(|s| s.parse().ok()) {
            return p;
        }
    }
    if let Ok(text) = std::fs::read_to_string("/etc/ssh/sshd_config") {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("Port ") {
                if let Ok(p) = rest.trim().parse::<u16>() {
                    if p != 0 {
                        return p;
                    }
                }
            }
        }
    }
    22
}

/// Versions of any zeronat already installed on this host, used to offer an
/// upgrade before a fresh install.
pub struct Installed {
    pub service: Option<ServiceInstall>,
    pub docker: Option<String>,
    pub compose: bool,
}

pub fn installed() -> Installed {
    Installed {
        service: service_version(),
        docker: docker_version(),
        compose: std::path::Path::new("/etc/zeronat/compose.yml").exists(),
    }
}

fn service_version() -> Option<ServiceInstall> {
    let bin = SERVICE_BINARY_PATH;
    if !std::path::Path::new(bin).exists() {
        return None;
    }
    let systemd_unit_exists = std::path::Path::new(ServiceManager::Systemd.unit_path()).exists();
    let init_script = if systemd_unit_exists {
        None
    } else {
        std::fs::read_to_string(ServiceManager::OpenRc.unit_path()).ok()
    };
    let manager = installed_service_manager(systemd_unit_exists, init_script.as_deref())?;
    Some(ServiceInstall {
        manager,
        version: binary_version(bin),
    })
}

/// "unknown" when the binary predates `--version` or cannot run.
fn binary_version(path: &str) -> String {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| version_token(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_else(|| "unknown".to_string())
}

fn docker_version() -> Option<String> {
    if !have("docker") {
        return None;
    }
    let exists = run(true, "docker", &["inspect", "-f", "{{.Id}}", "zeronat"])
        .map(|o| o.status.success())
        .unwrap_or(false);
    let compose = std::path::Path::new("/etc/zeronat/compose.yml").exists();
    if !exists && !compose {
        return None;
    }
    if !exists {
        return Some("unknown".to_string());
    }
    Some(
        run(
            true,
            "docker",
            &["exec", "zeronat", "/zeronat", "--version"],
        )
        .ok()
        .filter(|o| o.status.success())
        .map(|o| version_token(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_else(|| "unknown".to_string()),
    )
}

/// The newest published release version, via the GitHub `releases/latest`
/// redirect (no API rate limit). None when offline or curl is missing.
pub fn latest_version() -> Option<String> {
    if !have("curl") {
        return None;
    }
    let out = run(
        false,
        "curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "5",
            "-I",
            "-o",
            "/dev/null",
            "-w",
            "%{url_effective}",
            "--max-time",
            "15",
            "https://github.com/paltaio/zeronat/releases/latest",
        ],
    )
    .ok()?;
    if !out.status.success() {
        return None;
    }
    version_from_url(&String::from_utf8_lossy(&out.stdout))
}

/// Version out of a `releases/tag/vX.Y.Z` redirect target; None for the
/// unresolved `releases/latest` URL.
pub fn version_from_url(url: &str) -> Option<String> {
    SelectedRelease::from_latest_url(url)
        .ok()
        .map(|release| release.version().to_string())
}

fn version_token(s: &str) -> String {
    s.split_whitespace().last().unwrap_or("unknown").to_string()
}

pub fn version_newer(latest: &str, current: &str) -> bool {
    SelectedRelease::from_version(latest)
        .and_then(|release| release.is_newer_than(current))
        .unwrap_or(false)
}

pub fn arch_target() -> Result<&'static str, String> {
    let m = Command::new("uname")
        .arg("-m")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    Ok(match m.as_str() {
        "x86_64" | "amd64" => "x86_64-unknown-linux-musl",
        "aarch64" | "arm64" => "aarch64-unknown-linux-musl",
        "armv7l" => "armv7-unknown-linux-musleabihf",
        "armv6l" => "arm-unknown-linux-musleabihf",
        "mips" => "mips-unknown-linux-musl",
        "mipsel" => "mipsel-unknown-linux-musl",
        "mips64" => "mips64-unknown-linux-gnuabi64",
        "mips64el" => "mips64el-unknown-linux-gnuabi64",
        other => return Err(format!("unsupported arch '{other}'")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_url_extracts_tag() {
        assert_eq!(
            version_from_url("https://github.com/paltaio/zeronat/releases/tag/v0.14.0").as_deref(),
            Some("0.14.0")
        );
        assert_eq!(
            version_from_url("https://github.com/x/y/releases/latest"),
            None
        );
    }

    #[test]
    fn gen_secret_yields_random_hex() {
        let a = gen_secret().unwrap();
        let b = gen_secret().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn env_file_keeps_client_and_admin_secrets_separate() {
        let body = "ZERONAT_SECRET=client\nZERONAT_ADMIN_SECRET=admin\n";
        assert_eq!(env_value(body, "ZERONAT_SECRET").as_deref(), Some("client"));
        assert_eq!(
            env_value(body, "ZERONAT_ADMIN_SECRET").as_deref(),
            Some("admin")
        );
        assert_eq!(env_value(body, "MISSING"), None);
    }

    #[test]
    fn version_newer_compares_semver() {
        assert!(version_newer("0.14.0", "0.13.0"));
        assert!(!version_newer("0.14.0", "0.14.0"));
        assert!(!version_newer("0.13.0", "0.14.0"));
        assert!(!version_newer("0.14.0", "unknown"));
        assert!(!version_newer("unknown", "0.14.0"));
        assert!(!version_newer("0.14.0", "0.13"));
        assert!(!version_newer("0.14.0", "0.13.0-rc1"));
    }

    #[test]
    fn service_manager_detection_uses_the_running_init_system() {
        let systemd = detect_service_manager(
            |path| path == "/run/systemd/system",
            |command| command == "systemctl",
        );
        assert_eq!(systemd, Some(ServiceManager::Systemd));

        let procd = detect_service_manager(
            |path| matches!(path, "/etc/rc.common" | "/sbin/procd"),
            |_| false,
        );
        assert_eq!(procd, Some(ServiceManager::Procd));

        let openrc = detect_service_manager(
            |path| path == "/sbin/openrc-run",
            |command| matches!(command, "rc-service" | "rc-update"),
        );
        assert_eq!(openrc, Some(ServiceManager::OpenRc));
    }
}
