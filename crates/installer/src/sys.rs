//! Thin wrappers over the host tools the install drives: privilege handling,
//! command execution with captured output, downloads, and small probes. Nothing
//! here touches the terminal, so it is safe to call while the TUI is on screen.

use std::process::{Command, Output};

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
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

pub fn gen_secret() -> String {
    use std::io::Read;
    let mut b = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
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
    let out = if privileged && !is_root() {
        Command::new("sudo").arg(program).args(args).output()
    } else {
        Command::new(program).args(args).output()
    };
    out.map_err(|e| format!("failed to run {program}: {e}"))
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

/// A secret already on disk, so a re-run does not rotate it and break clients.
pub fn existing_secret() -> Option<String> {
    let out = run(true, "cat", &["/etc/zeronat/.env"]).ok()?;
    if !out.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(v) = line.strip_prefix("ZERONAT_SECRET=") {
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
/// upgrade before a fresh install. `systemd` is the installed binary's version;
/// `docker` is the version the running container reports. Either is None when
/// that deployment is absent.
pub struct Installed {
    pub systemd: Option<String>,
    pub docker: Option<String>,
    pub compose: bool,
}

pub fn installed() -> Installed {
    Installed {
        systemd: systemd_version(),
        docker: docker_version(),
        compose: std::path::Path::new("/etc/zeronat/compose.yml").exists(),
    }
}

fn systemd_version() -> Option<String> {
    let unit = std::path::Path::new("/etc/systemd/system/zeronat.service");
    let bin = "/usr/local/bin/zeronat";
    if unit.exists() && std::path::Path::new(bin).exists() {
        Some(binary_version(bin))
    } else {
        None
    }
}

/// "unknown" when the binary predates `--version` or cannot run, which
/// `version_newer` treats as upgradable.
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
        run(true, "docker", &["exec", "zeronat", "/zeronat", "--version"])
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
            "-fsSL",
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
    let tag = url.trim().trim_end_matches('/').rsplit('/').next()?;
    let ver = tag.strip_prefix('v').unwrap_or(tag);
    if ver.chars().next()?.is_ascii_digit() {
        Some(ver.to_string())
    } else {
        None
    }
}

fn version_token(s: &str) -> String {
    s.split_whitespace().last().unwrap_or("unknown").to_string()
}

pub fn version_newer(latest: &str, current: &str) -> bool {
    let Some(l) = parse_semver(latest) else {
        return false;
    };
    match parse_semver(current) {
        Some(c) => l > c,
        None => true,
    }
}

fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.split(['-', '+']).next().unwrap_or(s);
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
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
        "mips" => "mips-unknown-linux-gnu",
        "mipsel" => "mipsel-unknown-linux-gnu",
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
    fn version_newer_compares_semver() {
        assert!(version_newer("0.14.0", "0.13.0"));
        assert!(!version_newer("0.14.0", "0.14.0"));
        assert!(!version_newer("0.13.0", "0.14.0"));
        assert!(version_newer("0.14.0", "unknown"));
        assert!(!version_newer("unknown", "0.14.0"));
    }
}
