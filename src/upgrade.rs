//! `zeronat upgrade`: detect how this host runs zeronat and, when a newer release
//! is published, fetch it and restart in place. It orchestrates the host's own
//! tools (curl, docker, systemctl) the way the installer does, because the
//! scratch container ships nothing it could upgrade itself with. Meant to run on
//! the host, not inside the container.

use crate::Result;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use zeronat_install_support::release::{
    embedded_public_key, ReleaseManifest, MANIFEST_LIMIT, MANIFEST_NAME, SIGNATURE_LIMIT,
    SIGNATURE_NAME,
};
use zeronat_install_support::DownloadFile;

const ENV_FILE: &str = "/etc/zeronat/.env";
const COMPOSE_FILE: &str = "/etc/zeronat/compose.yml";
const BIN_PATH: &str = "/usr/local/bin/zeronat";
const UNIT_FILE: &str = "/etc/systemd/system/zeronat.service";
const CONTAINER: &str = "zeronat";
const IMAGE: &str = "ghcr.io/paltaio/zeronat:latest";
const RELEASE_DOWNLOAD_BASE: &str = "https://github.com/paltaio/zeronat/releases/download";
const LATEST_URL: &str = "https://github.com/paltaio/zeronat/releases/latest";

trait UpgradeRunner {
    fn run(&mut self, privileged: bool, program: &str, args: &[&str]) -> std::io::Result<Output>;
    fn run_with_stdin(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
        input: &File,
    ) -> std::io::Result<Output>;
    fn run_with_stdout(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
        output: &File,
    ) -> std::io::Result<Output>;
}

struct CommandRunner;

impl UpgradeRunner for CommandRunner {
    fn run(&mut self, privileged: bool, program: &str, args: &[&str]) -> std::io::Result<Output> {
        exec(privileged, program, args)
    }

    fn run_with_stdin(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
        input: &File,
    ) -> std::io::Result<Output> {
        exec_with_stdin(privileged, program, args, input)
    }

    fn run_with_stdout(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
        output: &File,
    ) -> std::io::Result<Output> {
        exec_with_stdout(privileged, program, args, output)
    }
}

/// Check for a newer release and, unless `check_only`, upgrade every zeronat
/// deployment found on this host (the systemd binary and/or a docker container).
pub fn run(check_only: bool) -> Result<()> {
    // Probe locally first so a host with nothing to upgrade fails fast, before
    // any network round-trip.
    let systemd = systemd_version();
    let docker = docker_deployment();

    if systemd.is_none() && docker.is_none() {
        return Err(format!(
            "no zeronat deployment found here (looked for {UNIT_FILE} with {BIN_PATH}, \
             and a docker container named {CONTAINER})"
        )
        .into());
    }

    let latest = latest_version()?;
    let mut applied = false;

    if let Some(current) = &systemd {
        let newer = version_newer(&latest, current);
        println!("systemd: {}", status_line(current, &latest, newer));
        if newer && !check_only {
            upgrade_systemd(&latest)?;
            applied = true;
        }
    }

    if let Some(dep) = &docker {
        let newer = version_newer(&latest, &dep.version);
        println!("docker:  {}", status_line(&dep.version, &latest, newer));
        if newer && !check_only {
            upgrade_docker(dep)?;
            applied = true;
        }
    }

    if !check_only {
        if applied {
            println!("upgrade complete (latest {latest})");
        } else {
            println!("already up to date (latest {latest})");
        }
    }
    Ok(())
}

fn status_line(current: &str, latest: &str, newer: bool) -> String {
    if newer {
        format!("{current} -> {latest} available")
    } else {
        format!("up to date ({current})")
    }
}

// ---- discovery -----------------------------------------------------------

fn systemd_version() -> Option<String> {
    if Path::new(UNIT_FILE).exists() && Path::new(BIN_PATH).exists() {
        Some(binary_version(BIN_PATH))
    } else {
        None
    }
}

/// Ask an installed binary its version; "unknown" when it predates `--version`
/// or cannot be run, which `version_newer` treats as upgradable.
fn binary_version(path: &str) -> String {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| version_token(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_else(|| "unknown".to_string())
}

struct DockerDeployment {
    mode: DockerMode,
    compose: bool,
    version: String,
}

#[derive(Clone, Copy)]
enum DockerMode {
    Direct,
    Sudo,
}

fn docker_deployment() -> Option<DockerDeployment> {
    let mode = docker_mode()?;
    let compose = Path::new(COMPOSE_FILE).exists();
    let exists = dk(mode, &["inspect", "-f", "{{.Id}}", CONTAINER])
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !exists && !compose {
        return None;
    }
    let version = if exists {
        dk(mode, &["exec", CONTAINER, "/zeronat", "--version"])
            .ok()
            .filter(|o| o.status.success())
            .map(|o| version_token(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown".to_string()
    };
    Some(DockerDeployment {
        mode,
        compose,
        version,
    })
}

/// How to reach the docker daemon: directly (rootless, or already root) or via
/// sudo (rootful daemon, unprivileged caller). None when docker is absent or the
/// daemon is unreachable either way.
fn docker_mode() -> Option<DockerMode> {
    if !have("docker") {
        return None;
    }
    if cmd_ok(dk_cmd(DockerMode::Direct, &["version"])) {
        return Some(DockerMode::Direct);
    }
    if !is_root() && have("sudo") && cmd_ok(dk_cmd(DockerMode::Sudo, &["version"])) {
        return Some(DockerMode::Sudo);
    }
    None
}

// ---- apply ---------------------------------------------------------------

fn upgrade_systemd(latest: &str) -> Result<()> {
    let key = embedded_public_key()
        .ok_or("this build has no release public key and cannot verify downloads")?;
    upgrade_systemd_with(latest, &key, &mut CommandRunner)
}

fn upgrade_systemd_with(
    latest: &str,
    public_key: &[u8; 32],
    runner: &mut dyn UpgradeRunner,
) -> Result<()> {
    if !have("curl") {
        return Err("curl is required to download the new binary".into());
    }
    let target = arch_target()?;
    // Everything is fetched from the resolved tag, not `latest`, so the signed
    // manifest and the binary cannot straddle a release published mid-upgrade.
    let base = format!("{RELEASE_DOWNLOAD_BASE}/v{latest}");
    let manifest = fetch_small(runner, &format!("{base}/{MANIFEST_NAME}"), MANIFEST_LIMIT)?;
    let signature = fetch_small(runner, &format!("{base}/{SIGNATURE_NAME}"), SIGNATURE_LIMIT)?;
    let manifest = ReleaseManifest::verify(&manifest, &signature, public_key)?;
    if manifest.version() != latest {
        return Err(format!(
            "the signed release manifest is for {} but the release tag is v{latest}",
            manifest.version()
        )
        .into());
    }
    println!("systemd: downloading zeronat-{target} ({latest})");
    let name = format!("zeronat-{target}");
    let size = manifest
        .expected_size(&name)
        .ok_or_else(|| format!("the release manifest has no entry for {name}"))?;
    let url = format!("{base}/{name}");
    let mut download = DownloadFile::create()?;
    let dl = runner
        .run_with_stdout(
            false,
            "curl",
            &[
                "-fsSL",
                "--max-filesize",
                &size.to_string(),
                "--max-time",
                "180",
                &url,
            ],
            download.output(),
        )
        .map_err(|e| format!("running curl: {e}"))?;
    if !dl.status.success() {
        return Err(format!("download failed (no release asset for {target}?)").into());
    }
    let mut input = download.prepare_install()?;
    manifest.verify_artifact(&name, input)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("failed to read downloaded binary: {e}"))?;
    let inst = runner
        .run_with_stdin(
            true,
            "install",
            &["-m", "0755", "/dev/stdin", BIN_PATH],
            input,
        )
        .map_err(|e| format!("running install: {e}"))?;
    if !inst.status.success() {
        return Err(format!("installing {BIN_PATH}: {}", errtext(&inst)).into());
    }
    println!("systemd: restarting service");
    let res = runner
        .run(true, "systemctl", &["restart", "zeronat"])
        .map_err(|e| format!("running systemctl: {e}"))?;
    if !res.status.success() {
        return Err(format!("systemctl restart: {}", errtext(&res)).into());
    }
    Ok(())
}

/// Fetch a small release file (manifest or signature) into memory, bounded by
/// `limit` so a hostile server cannot balloon the download.
fn fetch_small(runner: &mut dyn UpgradeRunner, url: &str, limit: u64) -> Result<Vec<u8>> {
    let out = runner
        .run(
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
        )
        .map_err(|e| format!("running curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("download failed for {url}").into());
    }
    if out.stdout.len() as u64 > limit {
        return Err(format!("{url} exceeds its size limit").into());
    }
    Ok(out.stdout)
}

fn upgrade_docker(dep: &DockerDeployment) -> Result<()> {
    if dep.compose {
        println!("docker:  pulling image via compose");
        compose(dep.mode, &["-f", COMPOSE_FILE, "pull"])?;
        println!("docker:  recreating container");
        compose(dep.mode, &["-f", COMPOSE_FILE, "up", "-d"])?;
    } else {
        println!("docker:  pulling {IMAGE}");
        let pull = dk(dep.mode, &["pull", IMAGE]).map_err(|e| format!("running docker: {e}"))?;
        if !pull.status.success() {
            return Err(format!("docker pull: {}", errtext(&pull)).into());
        }
        println!("docker:  recreating container");
        recreate_run(dep.mode)?;
    }
    Ok(())
}

/// Recreate a plain `docker run` container on the freshly pulled image, carrying
/// over the run config (command, network, restart policy, caps, devices) read
/// back from the old container. The secret rides via the installer env file; if
/// that file is absent we refuse rather than put the secret on argv.
fn recreate_run(mode: DockerMode) -> Result<()> {
    // Fail before touching the running container if there is no env file to carry
    // the secret. Recreating it from the inspected env would expose ZERONAT_SECRET
    // on the new process's argv (ps, /proc/<pid>/cmdline); refuse instead.
    if !Path::new(ENV_FILE).exists() {
        return Err(format!(
            "cannot recreate the container without {ENV_FILE}; create it with the \
             ZERONAT_SECRET line and re-run the upgrade"
        )
        .into());
    }
    let cmd = inspect_lines(mode, "{{range .Config.Cmd}}{{println .}}{{end}}");
    let caps = inspect_lines(mode, "{{range .HostConfig.CapAdd}}{{println .}}{{end}}");
    let devices = inspect_lines(
        mode,
        "{{range .HostConfig.Devices}}{{println .PathOnHost}}{{end}}",
    );
    let network = inspect_one(mode, "{{.HostConfig.NetworkMode}}").unwrap_or_else(|| "host".into());
    let restart = inspect_one(mode, "{{.HostConfig.RestartPolicy.Name}}")
        .unwrap_or_else(|| "unless-stopped".into());

    let rm = dk(mode, &["rm", "-f", CONTAINER]).map_err(|e| format!("running docker: {e}"))?;
    if !rm.status.success() {
        return Err(format!("docker rm: {}", errtext(&rm)).into());
    }

    let mut args: Vec<String> = vec!["run".into(), "-d".into(), "--name".into(), CONTAINER.into()];
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
    args.push("--env-file".into());
    args.push(ENV_FILE.into());
    args.push(IMAGE.into());
    args.extend(cmd);

    let aref: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = dk(mode, &aref).map_err(|e| format!("running docker: {e}"))?;
    if !out.status.success() {
        return Err(format!("docker run: {}", errtext(&out)).into());
    }
    Ok(())
}

fn inspect_lines(mode: DockerMode, fmt: &str) -> Vec<String> {
    dk(mode, &["inspect", "-f", fmt, CONTAINER])
        .ok()
        .filter(|o| o.status.success())
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

fn inspect_one(mode: DockerMode, fmt: &str) -> Option<String> {
    inspect_lines(mode, fmt).into_iter().next()
}

fn compose(mode: DockerMode, args: &[&str]) -> Result<()> {
    let out = if dk(mode, &["compose", "version"])
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let mut full = vec!["compose"];
        full.extend_from_slice(args);
        dk(mode, &full)
    } else if have("docker-compose") {
        match mode {
            DockerMode::Direct => Command::new("docker-compose").args(args).output(),
            DockerMode::Sudo => Command::new("sudo")
                .arg("docker-compose")
                .args(args)
                .output(),
        }
    } else {
        return Err("a compose file exists but docker compose is not available".into());
    };
    let out = out.map_err(|e| format!("running docker compose: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("compose: {}", errtext(&out)).into())
    }
}

// ---- version helpers -----------------------------------------------------

fn latest_version() -> Result<String> {
    if !have("curl") {
        return Err("curl is required to check for the latest release".into());
    }
    let out = exec(
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
            "20",
            LATEST_URL,
        ],
    )
    .map_err(|e| format!("running curl: {e}"))?;
    if !out.status.success() {
        return Err("could not reach the release server to check the latest version".into());
    }
    let url = String::from_utf8_lossy(&out.stdout);
    version_from_url(&url)
        .ok_or_else(|| format!("could not parse the latest release from '{}'", url.trim()).into())
}

/// Pull the version out of a GitHub `releases/latest` redirect target, e.g.
/// `.../releases/tag/v0.14.0` -> `0.14.0`. None for the unresolved
/// `.../releases/latest` URL (no tag yet).
fn version_from_url(url: &str) -> Option<String> {
    let tag = url.trim().trim_end_matches('/').rsplit('/').next()?;
    let ver = tag.strip_prefix('v').unwrap_or(tag);
    if ver.chars().next()?.is_ascii_digit() {
        Some(ver.to_string())
    } else {
        None
    }
}

/// Last whitespace token of a `--version` line, e.g. `zeronat 0.14.0` -> `0.14.0`.
fn version_token(s: &str) -> String {
    s.split_whitespace().last().unwrap_or("unknown").to_string()
}

fn version_newer(latest: &str, current: &str) -> bool {
    let Some(l) = parse_semver(latest) else {
        return false;
    };
    match parse_semver(current) {
        Some(c) => l > c,
        // An unparseable installed version (e.g. a pre-`--version` binary) is
        // treated as upgradable; an unparseable latest is the safe no-op above.
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

fn arch_target() -> Result<&'static str> {
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
        other => return Err(format!("unsupported architecture '{other}'").into()),
    })
}

// ---- process helpers -----------------------------------------------------

fn dk_cmd(mode: DockerMode, args: &[&str]) -> Command {
    let mut c = match mode {
        DockerMode::Direct => Command::new("docker"),
        DockerMode::Sudo => {
            let mut s = Command::new("sudo");
            s.arg("docker");
            s
        }
    };
    c.args(args);
    c
}

fn dk(mode: DockerMode, args: &[&str]) -> std::io::Result<Output> {
    dk_cmd(mode, args).output()
}

fn exec(privileged: bool, program: &str, args: &[&str]) -> std::io::Result<Output> {
    command(privileged, program, args).output()
}

fn exec_with_stdin(
    privileged: bool,
    program: &str,
    args: &[&str],
    input: &File,
) -> std::io::Result<Output> {
    command(privileged, program, args)
        .stdin(Stdio::from(input.try_clone()?))
        .output()
}

fn exec_with_stdout(
    privileged: bool,
    program: &str,
    args: &[&str],
    output: &File,
) -> std::io::Result<Output> {
    command(privileged, program, args)
        .stdout(Stdio::from(output.try_clone()?))
        .output()
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

fn cmd_ok(mut c: Command) -> bool {
    c.output().map(|o| o.status.success()).unwrap_or(false)
}

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn errtext(out: &Output) -> String {
    let s = String::from_utf8_lossy(&out.stderr);
    let s = s.trim();
    if s.is_empty() {
        format!("exit {}", out.status.code().unwrap_or(-1))
    } else {
        s.lines().last().unwrap_or(s).to_string()
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    effective_uid() == 0
}
#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no failure mode and does not dereference memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Write as _};

    struct FakeUpgradeRunner {
        commands: Vec<String>,
        installed: Vec<u8>,
        manifest: Vec<u8>,
        signature: Vec<u8>,
        download: Vec<u8>,
    }

    impl FakeUpgradeRunner {
        fn new(manifest: Vec<u8>, signature: Vec<u8>, download: Vec<u8>) -> Self {
            FakeUpgradeRunner {
                commands: Vec::new(),
                installed: Vec::new(),
                manifest,
                signature,
                download,
            }
        }
    }

    impl UpgradeRunner for FakeUpgradeRunner {
        fn run(&mut self, _: bool, program: &str, args: &[&str]) -> std::io::Result<Output> {
            self.commands.push(format!("{program} {}", args.join(" ")));
            let url = args.last().copied().unwrap_or_default();
            let body = if url.ends_with(MANIFEST_NAME) {
                self.manifest.clone()
            } else if url.ends_with(SIGNATURE_NAME) {
                self.signature.clone()
            } else {
                Vec::new()
            };
            Ok(success(body))
        }

        fn run_with_stdin(
            &mut self,
            _: bool,
            program: &str,
            args: &[&str],
            input: &File,
        ) -> std::io::Result<Output> {
            input.try_clone()?.read_to_end(&mut self.installed)?;
            self.run(false, program, args)
        }

        fn run_with_stdout(
            &mut self,
            _: bool,
            program: &str,
            args: &[&str],
            output: &File,
        ) -> std::io::Result<Output> {
            let body = self.download.clone();
            output.try_clone()?.write_all(&body)?;
            self.run(false, program, args)
        }
    }

    fn success(stdout: Vec<u8>) -> Output {
        use std::os::unix::process::ExitStatusExt;

        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout,
            stderr: Vec::new(),
        }
    }

    fn test_key() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .unwrap();
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    fn signed_manifest(signing: &SigningKey, version: &str, content: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let name = format!("zeronat-{}", arch_target().unwrap());
        let digest = zeronat_secret::encode(Sha256::digest(content).into());
        let manifest = format!(
            "zeronat-release-v1 v{version}\n{digest} {} {name}\n",
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
        (manifest, signature)
    }

    #[test]
    fn systemd_upgrade_installs_the_verified_download() {
        let (signing, public) = test_key();
        let (manifest, signature) = signed_manifest(&signing, "0.25.1", b"downloaded binary");
        let mut runner = FakeUpgradeRunner::new(manifest, signature, b"downloaded binary".to_vec());

        upgrade_systemd_with("0.25.1", &public, &mut runner).unwrap();

        assert_eq!(runner.installed, b"downloaded binary");
        assert!(runner
            .commands
            .iter()
            .any(|command| command.starts_with("curl -fsSL ")
                && command.contains("/releases/download/v0.25.1/")
                && !command.contains(" -o ")));
        assert!(runner
            .commands
            .iter()
            .any(|command| { command == "install -m 0755 /dev/stdin /usr/local/bin/zeronat" }));
        assert!(runner
            .commands
            .contains(&"systemctl restart zeronat".to_string()));
    }

    // Every verification failure must refuse before anything is installed or
    // restarted: a missing signature, a signature by another key, a manifest
    // for a different release, and a download that does not match the signed
    // digest.
    #[test]
    fn systemd_upgrade_refuses_unverified_downloads() {
        let (signing, public) = test_key();
        let (other_signing, _) = test_key();
        let (manifest, signature) = signed_manifest(&signing, "0.25.1", b"downloaded binary");
        let (_, wrong_key) = signed_manifest(&other_signing, "0.25.1", b"downloaded binary");
        let (stale, stale_sig) = signed_manifest(&signing, "0.25.0", b"downloaded binary");

        let cases = [
            (
                "unsigned",
                manifest.clone(),
                Vec::new(),
                b"downloaded binary".to_vec(),
            ),
            (
                "wrong key",
                manifest.clone(),
                wrong_key,
                b"downloaded binary".to_vec(),
            ),
            (
                "wrong release",
                stale,
                stale_sig,
                b"downloaded binary".to_vec(),
            ),
            (
                "tampered download",
                manifest.clone(),
                signature.clone(),
                b"tampered binary!!".to_vec(),
            ),
        ];
        for (case, manifest, signature, download) in cases {
            let mut runner = FakeUpgradeRunner::new(manifest, signature, download);
            assert!(
                upgrade_systemd_with("0.25.1", &public, &mut runner).is_err(),
                "{case}: upgrade accepted"
            );
            assert!(runner.installed.is_empty(), "{case}: binary was installed");
            assert!(
                !runner
                    .commands
                    .iter()
                    .any(|c| c.starts_with("install ") || c.starts_with("systemctl ")),
                "{case}: install or restart ran"
            );
        }
    }

    #[test]
    fn version_from_url_extracts_tag() {
        assert_eq!(
            version_from_url("https://github.com/paltaio/zeronat/releases/tag/v0.14.0").as_deref(),
            Some("0.14.0")
        );
        assert_eq!(
            version_from_url("https://github.com/x/y/releases/tag/v1.2.3\n").as_deref(),
            Some("1.2.3")
        );
        // The unresolved latest URL has no tag.
        assert_eq!(
            version_from_url("https://github.com/x/y/releases/latest"),
            None
        );
    }

    #[test]
    fn version_token_takes_last() {
        assert_eq!(version_token("zeronat 0.14.0"), "0.14.0");
        assert_eq!(version_token("zeronat 0.14.0\n"), "0.14.0");
        assert_eq!(version_token(""), "unknown");
    }

    #[test]
    fn version_newer_compares_semver() {
        assert!(version_newer("0.14.0", "0.13.0"));
        assert!(version_newer("0.14.1", "0.14.0"));
        assert!(version_newer("1.0.0", "0.99.99"));
        assert!(!version_newer("0.14.0", "0.14.0"));
        assert!(!version_newer("0.13.0", "0.14.0"));
        // Unknown installed version -> upgradable; unknown latest -> no-op.
        assert!(version_newer("0.14.0", "unknown"));
        assert!(!version_newer("unknown", "0.14.0"));
    }
}
