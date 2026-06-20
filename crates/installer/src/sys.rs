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
    for f in ["/etc/zeronat/.env", "/etc/zeronat/zeronat.env"] {
        if let Ok(out) = run(true, "cat", &[f]) {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some(v) = line.strip_prefix("ZERONAT_SECRET=") {
                        if !v.is_empty() {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
    }
    None
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
