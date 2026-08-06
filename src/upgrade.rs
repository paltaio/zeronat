//! `zeronat upgrade`: detect how this host runs zeronat and, when a newer release
//! is published, fetch it and restart in place. It orchestrates the host's own
//! tools (curl, docker, systemctl) the way the installer does, because the
//! scratch container ships nothing it could upgrade itself with. Meant to run on
//! the host, not inside the container.

use crate::Result;
use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use zeronat_install_support::{
    curl_fetch_command, download_verified_asset_with_keys, parse_image_reference,
    replace_image_reference_in_env, DownloadFile, SelectedRelease, TrustedKey, COMPOSE_ASSET,
    COMPOSE_BRIDGE_ASSET, IMAGE_REFERENCE_ASSET,
};

#[cfg(not(test))]
use zeronat_install_support::TRUSTED_RELEASE_KEYS;

#[cfg(test)]
const TEST_RELEASE_KEYS: &[TrustedKey] = &[TrustedKey {
    id: "3cbde1bed2d17057",
    public_key: include_str!("../crates/install-support/tests/fixtures/minisign.pub"),
}];
#[cfg(test)]
const TEST_RELEASE_MANIFEST: &[u8] =
    include_bytes!("../crates/install-support/tests/fixtures/v0.25.1.manifest");
#[cfg(test)]
const TEST_RELEASE_SIGNATURE: &[u8] =
    include_bytes!("../crates/install-support/tests/fixtures/v0.25.1.manifest.minisig");
#[cfg(test)]
const TEST_RELEASE_BINARY: &[u8] =
    include_bytes!("../crates/install-support/tests/fixtures/zeronat-v6-x86_64-unknown-linux-musl");
#[cfg(test)]
const TEST_RELEASE_IMAGE: &[u8] =
    include_bytes!("../crates/install-support/tests/fixtures/zeronat-image-v6.txt");
#[cfg(test)]
const TEST_RELEASE_COMPOSE: &[u8] =
    include_bytes!("../crates/install-support/tests/fixtures/compose.yml");
#[cfg(test)]
const TEST_RELEASE_COMPOSE_BRIDGE: &[u8] =
    include_bytes!("../crates/install-support/tests/fixtures/compose.bridge.yml");

const ENV_FILE: &str = "/etc/zeronat/.env";
const COMPOSE_FILE: &str = "/etc/zeronat/compose.yml";
const BIN_PATH: &str = "/usr/local/bin/zeronat";
const UNIT_FILE: &str = "/etc/systemd/system/zeronat.service";
const CONTAINER: &str = "zeronat";
const IMAGE_REPOSITORY: &str = "ghcr.io/paltaio/zeronat";
const CONTAINER_USER: &str = "65532:65532";
const ROOT_USER: &str = "0:0";
const BINARY_ASSET_PREFIX: &str = "zeronat-v6";
const LATEST_URL: &str = "https://github.com/paltaio/zeronat/releases/latest";

fn image_for_version(version: &str) -> Result<String> {
    SelectedRelease::from_version(version)
        .map(|release| format!("{IMAGE_REPOSITORY}:{}", release.version()))
        .map_err(Into::into)
}

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

    if let Some(version) = &systemd {
        validate_installed_version("systemd", version)?;
    }
    if let Some(deployment) = &docker {
        validate_installed_version("docker", &deployment.version)?;
    }

    if !check_only {
        validate_installed_credentials(systemd.is_some(), docker.as_ref())?;
    }

    let latest = latest_release()?;
    let latest_version = latest.version();
    let systemd_newer = systemd
        .as_ref()
        .is_some_and(|current| version_newer(latest_version, current));
    let docker_newer = docker
        .as_ref()
        .is_some_and(|deployment| version_newer(latest_version, &deployment.version));
    let mut applied = false;

    if let Some(current) = &systemd {
        println!(
            "systemd: {}",
            status_line(current, latest_version, systemd_newer)
        );
        if systemd_newer && !check_only {
            upgrade_systemd(&latest)?;
            applied = true;
        }
    }

    if let Some(dep) = &docker {
        println!(
            "docker:  {}",
            status_line(&dep.version, latest_version, docker_newer)
        );
        if docker_newer && !check_only {
            upgrade_docker(dep, &latest)?;
            applied = true;
        }
    }

    if !check_only {
        if applied {
            println!("upgrade complete (latest {latest_version})");
        } else {
            println!("already up to date (latest {latest_version})");
        }
    }
    Ok(())
}

fn validate_installed_credentials(
    has_systemd: bool,
    docker: Option<&DockerDeployment>,
) -> Result<()> {
    let env = if Path::new(ENV_FILE).exists() {
        std::fs::read_to_string(ENV_FILE)
            .map_err(|e| format!("reading {ENV_FILE} before upgrade: {e}"))?
    } else {
        String::new()
    };
    validate_credential_env(&env)?;

    if has_systemd {
        let unit = std::fs::read_to_string(UNIT_FILE)
            .map_err(|e| format!("reading {UNIT_FILE} before upgrade: {e}"))?;
        let command: Vec<&str> = unit
            .lines()
            .find_map(|line| line.trim().strip_prefix("ExecStart="))
            .map(str::split_whitespace)
            .map(Iterator::collect)
            .ok_or_else(|| format!("cannot determine the zeronat command in {UNIT_FILE}"))?;
        validate_deployment_command(&command, "systemd", &env)?;
    }

    if let Some(deployment) = docker {
        if !deployment.compose && !Path::new(ENV_FILE).exists() {
            return Err(format!(
                "cannot upgrade the docker deployment without {ENV_FILE}; restore its enrollment values first"
            )
            .into());
        }
        let command = if deployment.compose {
            rendered_compose_deployment(deployment.mode, &image_for_version(&deployment.version)?)?
                .command
        } else {
            direct_docker_command(deployment.mode)?
        };
        let command: Vec<&str> = command.iter().map(String::as_str).collect();
        validate_deployment_command(&command, "docker", &env)?;
        if !deployment.compose {
            let current = inspect_container_env(deployment.mode)?;
            validate_container_env(&current, &env)?;
        }
    }
    Ok(())
}

fn validate_container_env(current: &[String], env_file: &str) -> Result<()> {
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
        return Ok(());
    }
    Err(format!(
        "cannot recreate the container because {ENV_FILE} differs from the running container for: {}",
        changed.join(", ")
    )
    .into())
}

fn docker_restart_policy(name: String, retries: String) -> Result<String> {
    let retries: u64 = retries
        .parse()
        .map_err(|_| "cannot determine the docker restart retry count")?;
    if name == "on-failure" && retries > 0 {
        Ok(format!("{name}:{retries}"))
    } else {
        Ok(name)
    }
}

fn protected_env_file(entries: &[String]) -> Result<DownloadFile> {
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

fn validate_env_file_entry(entry: &str) -> Result<()> {
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

fn validate_image_env(current: &[String], image: &[String]) -> Result<()> {
    let current_keys: std::collections::HashSet<&str> = current
        .iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, _)| key)
                .ok_or("the running container has a malformed environment entry")
        })
        .collect::<std::result::Result<_, _>>()?;
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
        )
        .into())
    }
}

fn direct_docker_command(mode: DockerMode) -> Result<Vec<String>> {
    let out = dk(
        mode,
        &[
            "inspect",
            "-f",
            "{{range .Config.Cmd}}{{println .}}{{end}}",
            CONTAINER,
        ],
    )
    .map_err(|e| format!("inspecting the docker deployment before upgrade: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "inspecting the docker deployment before upgrade: {}",
            errtext(&out)
        )
        .into());
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

fn rendered_compose_deployment(mode: DockerMode, image: &str) -> Result<RenderedCompose> {
    let mut command = if dk(mode, &["compose", "version"])
        .map(|out| out.status.success())
        .unwrap_or(false)
    {
        compose_command(
            mode,
            image,
            "docker",
            Some("compose"),
            &[
                "--env-file",
                ENV_FILE,
                "-f",
                COMPOSE_FILE,
                "config",
                "--format",
                "json",
            ],
        )
    } else if have("docker-compose") {
        compose_command(
            mode,
            image,
            "docker-compose",
            None,
            &[
                "--env-file",
                ENV_FILE,
                "-f",
                COMPOSE_FILE,
                "config",
                "--format",
                "json",
            ],
        )
    } else {
        return Err("a compose file exists but docker compose is not available".into());
    };
    let out = command
        .output()
        .map_err(|e| format!("rendering {COMPOSE_FILE} before upgrade: {e}"))?;
    if !out.status.success() {
        return Err(format!("rendering {COMPOSE_FILE} before upgrade: {}", errtext(&out)).into());
    }
    parse_compose_deployment(&out.stdout)
}

struct RenderedCompose {
    command: Vec<String>,
    privileged: bool,
}

fn parse_compose_deployment(body: &[u8]) -> Result<RenderedCompose> {
    let config: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| format!("reading rendered compose configuration: {e}"))?;
    let service = config
        .get("services")
        .and_then(|services| services.get(CONTAINER))
        .ok_or_else(|| format!("cannot determine the zeronat service in {COMPOSE_FILE}"))?;
    let command = service
        .get("command")
        .ok_or_else(|| format!("cannot determine the zeronat command in {COMPOSE_FILE}"))?;
    let command = match command {
        serde_json::Value::Array(parts) => parts
            .iter()
            .map(|part| {
                part.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("invalid zeronat command in {COMPOSE_FILE}"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        serde_json::Value::String(command) => {
            command.split_whitespace().map(str::to_string).collect()
        }
        _ => return Err(format!("invalid zeronat command in {COMPOSE_FILE}").into()),
    };
    if command.is_empty() {
        return Err(format!("cannot determine the zeronat command in {COMPOSE_FILE}").into());
    }
    let privileged = service
        .get("privileged")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        || service
            .get("cap_add")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|caps| caps.iter().any(|cap| cap.as_str() == Some("NET_ADMIN")))
        || service
            .get("devices")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|devices| devices.iter().any(compose_device_maps_tun));
    Ok(RenderedCompose {
        command,
        privileged,
    })
}

fn compose_device_maps_tun(device: &serde_json::Value) -> bool {
    match device {
        serde_json::Value::String(mapping) => mapping
            .split(':')
            .take(2)
            .any(|path| path == "/dev/net/tun"),
        serde_json::Value::Object(mapping) => ["source", "target"].iter().any(|key| {
            mapping.get(*key).and_then(serde_json::Value::as_str) == Some("/dev/net/tun")
        }),
        _ => false,
    }
}

fn compose_asset(privileged: bool) -> &'static str {
    if privileged {
        COMPOSE_BRIDGE_ASSET
    } else {
        COMPOSE_ASSET
    }
}

fn validate_credential_env(body: &str) -> Result<()> {
    let identity = env_value(body, "ZERONAT_SECRET");
    let credential = env_value(body, "ZERONAT_CLIENT_SECRET");
    if matches!(
        (identity, credential),
        (Some(identity), Some(credential))
            if identity.trim().eq_ignore_ascii_case(credential.trim())
    ) {
        return Err(
            "legacy shared credentials detected; rerun the installer on the server with --reinstall and re-enroll each client with a distinct credential before upgrading"
                .into(),
        );
    }
    Ok(())
}

fn env_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    body.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .filter(|value| !value.is_empty())
}

fn validate_deployment_command(args: &[&str], source: &str, env: &str) -> Result<()> {
    let role_index = usize::from(
        args.first()
            .is_some_and(|arg| *arg == "zeronat" || arg.ends_with("/zeronat")),
    );
    match args.get(role_index).copied() {
        Some("server") => return Ok(()),
        Some("client") => {}
        _ => {
            return Err(
                format!("cannot determine whether the {source} deployment is a client").into(),
            );
        }
    }

    if let Some(config_index) = args.iter().position(|arg| *arg == "--config") {
        let path = args
            .get(config_index + 1)
            .ok_or_else(|| format!("the {source} client command has --config without a path"))?;
        let body = std::fs::read_to_string(path)
            .map_err(|e| format!("reading client config {path} before upgrade: {e}"))?;
        if validate_client_config(path, &body)? {
            return Ok(());
        }
    }

    let identity = value_after(args, "--secret").or_else(|| env_value(env, "ZERONAT_SECRET"));
    let credential =
        value_after(args, "--credential").or_else(|| env_value(env, "ZERONAT_CLIENT_SECRET"));
    validate_enrollment_values(identity, credential, source)
}

fn value_after<'a>(args: &'a [&str], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| *arg == flag)
        .and_then(|index| args.get(index + 1).copied())
}

fn validate_enrollment_values(
    identity: Option<&str>,
    credential: Option<&str>,
    source: &str,
) -> Result<()> {
    let action = "rerun the installer on the server with --reinstall, then re-enroll this client with its own credential before upgrading";
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
        return Err(format!("legacy shared credentials detected; {action}").into());
    }
    Ok(())
}

fn validate_client_config(path: &str, body: &str) -> Result<bool> {
    let action = "rerun the installer on the server with --reinstall, then re-enroll this client with its own credential before upgrading";
    let classify = |error: crate::Error| {
        let enrollment_error = crate::clientcfg::is_enrollment_error(&error);
        let error = error.to_string();
        if enrollment_error {
            format!("client config {path} uses legacy enrollment values; {action}")
        } else {
            format!("cannot upgrade with client config {path}: {error}")
        }
    };
    let config = crate::clientcfg::parse_client(body).map_err(classify)?;
    config.validate().map_err(classify)?;
    Ok(!config.servers.is_empty())
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

fn upgrade_systemd(release: &SelectedRelease) -> Result<()> {
    upgrade_systemd_with(release, &mut CommandRunner)
}

fn download_asset_with(
    release: &SelectedRelease,
    asset_name: &str,
    runner: &mut dyn UpgradeRunner,
) -> Result<DownloadFile> {
    download_verified_asset_with_keys(
        release,
        asset_name,
        release_keys(),
        |url, max_bytes, output| {
            let (program, args) = curl_fetch_command(url, max_bytes);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let result = runner
                .run_with_stdout(false, program, &args, output)
                .map_err(|e| format!("running curl: {e}"))?;
            Ok(result.status.success())
        },
    )
    .map_err(Into::into)
}

fn download_image_reference_with(
    release: &SelectedRelease,
    runner: &mut dyn UpgradeRunner,
) -> Result<String> {
    let mut download = download_asset_with(release, IMAGE_REFERENCE_ASSET, runner)?;
    let bytes = download.read_limited(256, "release image reference")?;
    parse_image_reference(&bytes).map_err(Into::into)
}

fn install_download_with(
    download: &mut DownloadFile,
    mode: &str,
    destination: &str,
    runner: &mut dyn UpgradeRunner,
) -> Result<()> {
    let input = download.prepare_install()?;
    let installed = runner
        .run_with_stdin(
            true,
            "install",
            &["-m", mode, "/dev/stdin", destination],
            input,
        )
        .map_err(|e| format!("running install: {e}"))?;
    if installed.status.success() {
        Ok(())
    } else {
        Err(format!("installing {destination}: {}", errtext(&installed)).into())
    }
}

fn upgrade_systemd_with(release: &SelectedRelease, runner: &mut dyn UpgradeRunner) -> Result<()> {
    if !have("curl") {
        return Err("curl is required to download the new binary".into());
    }
    let target = arch_target()?;
    let asset_name = format!("{BINARY_ASSET_PREFIX}-{target}");
    println!("systemd: downloading {asset_name} ({})", release.version());
    let mut download = download_asset_with(release, &asset_name, runner)?;
    install_download_with(&mut download, "0755", BIN_PATH, runner)?;
    println!("systemd: restarting service");
    let res = runner
        .run(true, "systemctl", &["restart", "zeronat"])
        .map_err(|e| format!("running systemctl: {e}"))?;
    if !res.status.success() {
        return Err(format!("systemctl restart: {}", errtext(&res)).into());
    }
    Ok(())
}

fn upgrade_docker(dep: &DockerDeployment, release: &SelectedRelease) -> Result<()> {
    let mut runner = CommandRunner;
    let image = download_image_reference_with(release, &mut runner)?;
    if dep.compose {
        let current_image = image_for_version(&dep.version)?;
        let deployment = rendered_compose_deployment(dep.mode, &current_image)?;
        let asset = compose_asset(deployment.privileged);
        let mut compose_file = download_asset_with(release, asset, &mut runner)?;
        install_download_with(&mut compose_file, "0644", COMPOSE_FILE, &mut runner)?;
        let current_env = std::fs::read(ENV_FILE)
            .map_err(|e| format!("reading {ENV_FILE} before upgrade: {e}"))?;
        let updated_env = replace_image_reference_in_env(&current_env, &image)?;
        let mut env_file = DownloadFile::create()?;
        env_file
            .output()
            .try_clone()
            .and_then(|mut file| file.write_all(&updated_env))
            .map_err(|e| format!("staging {ENV_FILE}: {e}"))?;
        install_download_with(&mut env_file, "0600", ENV_FILE, &mut runner)?;
        println!("docker:  pulling image via compose");
        compose(
            dep.mode,
            &image,
            &["--env-file", ENV_FILE, "-f", COMPOSE_FILE, "pull"],
        )?;
        println!("docker:  recreating container");
        compose(
            dep.mode,
            &image,
            &["--env-file", ENV_FILE, "-f", COMPOSE_FILE, "up", "-d"],
        )?;
    } else {
        let snapshot = run_snapshot(dep.mode)?;
        println!("docker:  pulling {image}");
        let pull = dk(dep.mode, &["pull", &image]).map_err(|e| format!("running docker: {e}"))?;
        if !pull.status.success() {
            return Err(format!("docker pull: {}", errtext(&pull)).into());
        }
        println!("docker:  recreating container");
        recreate_run(dep.mode, snapshot, &image)?;
    }
    Ok(())
}

/// Configuration captured from a plain `docker run` container for recreation.
struct RunSnapshot {
    cmd: Vec<String>,
    env: Vec<String>,
    caps: Vec<String>,
    devices: Vec<String>,
    binds: Vec<String>,
    network: String,
    restart: String,
    user: String,
}

fn run_snapshot(mode: DockerMode) -> Result<RunSnapshot> {
    if !Path::new(ENV_FILE).exists() {
        return Err(format!(
            "cannot recreate the container without {ENV_FILE}; restore the deployment's \
             enrollment values in it and re-run the upgrade"
        )
        .into());
    }
    let cmd = inspect_lines_required(mode, "{{range .Config.Cmd}}{{println .}}{{end}}")?;
    if cmd.is_empty() {
        return Err("cannot determine the zeronat command for the docker deployment".into());
    }
    let env = inspect_container_env(mode)?;
    let caps = inspect_lines_required(mode, "{{range .HostConfig.CapAdd}}{{println .}}{{end}}")?;
    let devices = inspect_lines_required(
        mode,
        "{{range .HostConfig.Devices}}{{printf \"%s:%s:%s\\n\" .PathOnHost .PathInContainer .CgroupPermissions}}{{end}}",
    )?;
    let binds = inspect_lines_required(mode, "{{range .HostConfig.Binds}}{{println .}}{{end}}")?;
    let network = inspect_lines_required(mode, "{{.HostConfig.NetworkMode}}")?
        .into_iter()
        .next()
        .unwrap_or_default();
    let restart_name = inspect_lines_required(mode, "{{.HostConfig.RestartPolicy.Name}}")?
        .into_iter()
        .next()
        .unwrap_or_default();
    let restart_retries =
        inspect_lines_required(mode, "{{.HostConfig.RestartPolicy.MaximumRetryCount}}")?
            .into_iter()
            .next()
            .unwrap_or_else(|| "0".into());
    let restart = docker_restart_policy(restart_name, restart_retries)?;
    let user = inspect_lines_required(mode, "{{.Config.User}}")?
        .into_iter()
        .next()
        .unwrap_or_default();
    Ok(RunSnapshot {
        cmd,
        env,
        caps,
        devices,
        binds,
        network,
        restart,
        user,
    })
}

fn recreate_run(mode: DockerMode, snapshot: RunSnapshot, image: &str) -> Result<()> {
    let RunSnapshot {
        cmd,
        env,
        caps,
        devices,
        binds,
        network,
        restart,
        user,
    } = snapshot;

    let image_env = inspect_image_env(mode, image)?;
    validate_image_env(&env, &image_env)?;
    let env_file = protected_env_file(&env)?;
    let env_path = env_file
        .path()
        .to_str()
        .ok_or("the private environment snapshot path is not valid UTF-8")?;

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
    args.extend([
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--user".into(),
        if user.is_empty() {
            if caps.iter().any(|cap| cap == "NET_ADMIN")
                || devices
                    .iter()
                    .any(|device| device.starts_with("/dev/net/tun:"))
            {
                ROOT_USER.into()
            } else {
                CONTAINER_USER.into()
            }
        } else {
            user
        },
    ]);
    for c in &caps {
        args.push("--cap-add".into());
        args.push(c.clone());
    }
    for d in &devices {
        args.push("--device".into());
        args.push(d.clone());
    }
    for bind in &binds {
        args.push("-v".into());
        args.push(bind.clone());
    }
    args.push("--env-file".into());
    args.push(env_path.into());
    args.push(image.into());
    args.extend(cmd);

    let aref: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = dk(mode, &aref).map_err(|e| format!("running docker: {e}"))?;
    if !out.status.success() {
        return Err(format!("docker run: {}", errtext(&out)).into());
    }
    Ok(())
}

fn inspect_lines_required(mode: DockerMode, fmt: &str) -> Result<Vec<String>> {
    let out = dk(mode, &["inspect", "-f", fmt, CONTAINER])
        .map_err(|error| format!("inspecting the docker deployment: {error}"))?;
    if !out.status.success() {
        return Err(format!("inspecting the docker deployment: {}", errtext(&out)).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn inspect_container_env(mode: DockerMode) -> Result<Vec<String>> {
    let out = dk(mode, &["inspect", "-f", "{{json .Config.Env}}", CONTAINER])
        .map_err(|error| format!("inspecting the docker deployment: {error}"))?;
    if !out.status.success() {
        return Err(format!("inspecting the docker deployment: {}", errtext(&out)).into());
    }
    serde_json::from_slice::<Option<Vec<String>>>(&out.stdout)
        .map(Option::unwrap_or_default)
        .map_err(|error| format!("reading the docker environment snapshot: {error}").into())
}

fn inspect_image_env(mode: DockerMode, image: &str) -> Result<Vec<String>> {
    let out = dk(
        mode,
        &["image", "inspect", "-f", "{{json .Config.Env}}", image],
    )
    .map_err(|error| format!("inspecting the pulled docker image: {error}"))?;
    if !out.status.success() {
        return Err(format!("inspecting the pulled docker image: {}", errtext(&out)).into());
    }
    serde_json::from_slice::<Option<Vec<String>>>(&out.stdout)
        .map(Option::unwrap_or_default)
        .map_err(|error| format!("reading the pulled image environment: {error}").into())
}

fn compose(mode: DockerMode, image: &str, args: &[&str]) -> Result<()> {
    let out = if dk(mode, &["compose", "version"])
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        compose_command(mode, image, "docker", Some("compose"), args).output()
    } else if have("docker-compose") {
        compose_command(mode, image, "docker-compose", None, args).output()
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

fn compose_command(
    mode: DockerMode,
    image: &str,
    program: &str,
    subcommand: Option<&str>,
    args: &[&str],
) -> Command {
    match mode {
        DockerMode::Direct => {
            let mut command = Command::new(program);
            command.env("ZERONAT_IMAGE", image);
            command.args(subcommand).args(args);
            command
        }
        DockerMode::Sudo => {
            let mut command = Command::new("sudo");
            command
                .arg("env")
                .arg(format!("ZERONAT_IMAGE={image}"))
                .arg(program)
                .args(subcommand)
                .args(args);
            command
        }
    }
}

// ---- version helpers -----------------------------------------------------

fn latest_release() -> Result<SelectedRelease> {
    if !have("curl") {
        return Err("curl is required to check for the latest release".into());
    }
    let out = exec(
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
            "20",
            LATEST_URL,
        ],
    )
    .map_err(|e| format!("running curl: {e}"))?;
    if !out.status.success() {
        return Err("could not reach the release server to check the latest version".into());
    }
    let url = String::from_utf8_lossy(&out.stdout);
    SelectedRelease::from_latest_url(&url)
        .map_err(|error| format!("could not parse the latest release: {error}").into())
}

/// Last whitespace token of a `--version` line, e.g. `zeronat 0.14.0` -> `0.14.0`.
fn version_token(s: &str) -> String {
    s.split_whitespace().last().unwrap_or("unknown").to_string()
}

fn version_newer(latest: &str, current: &str) -> bool {
    SelectedRelease::from_version(latest)
        .and_then(|release| release.is_newer_than(current))
        .unwrap_or(false)
}

fn validate_installed_version(deployment: &str, version: &str) -> Result<()> {
    if SelectedRelease::from_version(version).is_err() {
        return Err(format!(
            "cannot verify the installed {deployment} version '{version}'; reinstall it from a signed release before upgrading"
        )
        .into());
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
    use std::io::Read as _;

    struct FakeUpgradeRunner {
        commands: Vec<String>,
        installed: Vec<u8>,
    }

    impl UpgradeRunner for FakeUpgradeRunner {
        fn run(&mut self, _: bool, program: &str, args: &[&str]) -> std::io::Result<Output> {
            self.commands.push(format!("{program} {}", args.join(" ")));
            Ok(success())
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
            let url = args
                .iter()
                .find(|arg| arg.starts_with("https://"))
                .copied()
                .unwrap_or_default();
            let bytes = if url.ends_with(".manifest") {
                TEST_RELEASE_MANIFEST
            } else if url.ends_with(".minisig") {
                TEST_RELEASE_SIGNATURE
            } else if url.ends_with("zeronat-image-v6.txt") {
                TEST_RELEASE_IMAGE
            } else if url.ends_with("compose.bridge.yml") {
                TEST_RELEASE_COMPOSE_BRIDGE
            } else if url.ends_with("compose.yml") {
                TEST_RELEASE_COMPOSE
            } else {
                TEST_RELEASE_BINARY
            };
            output.try_clone()?.write_all(bytes)?;
            self.run(false, program, args)
        }
    }

    fn success() -> Output {
        use std::os::unix::process::ExitStatusExt;

        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn systemd_upgrade_installs_the_held_download() {
        let mut runner = FakeUpgradeRunner {
            commands: Vec::new(),
            installed: Vec::new(),
        };

        let release = SelectedRelease::from_version("0.25.1").unwrap();
        upgrade_systemd_with(&release, &mut runner).unwrap();

        assert_eq!(runner.installed, TEST_RELEASE_BINARY);
        assert!(runner
            .commands
            .iter()
            .any(|command| command.starts_with("sh -c ")
                && command.contains("ulimit -f")
                && command.contains(" curl --fail ")
                && command.contains("/zeronat-v6-")
                && !command.contains(" -o ")));
        assert!(runner
            .commands
            .iter()
            .any(|command| { command == "install -m 0755 /dev/stdin /usr/local/bin/zeronat" }));
        assert!(runner
            .commands
            .contains(&"systemctl restart zeronat".to_string()));
    }

    #[test]
    fn legacy_shared_credentials_block_upgrade() {
        let legacy = "ZERONAT_SECRET=001122\nZERONAT_CLIENT_SECRET=001122\n";
        let error = validate_credential_env(legacy).unwrap_err().to_string();
        assert!(error.contains("legacy shared credentials"), "{error}");
        assert!(error.contains("--reinstall"), "{error}");

        let current = "ZERONAT_SECRET=001122\nZERONAT_CLIENT_SECRET=aabbcc\n";
        validate_credential_env(current).unwrap();
    }

    #[test]
    fn systemd_legacy_client_config_blocks_upgrade() {
        let path = std::env::temp_dir().join(format!(
            "zeronat-upgrade-systemd-config-{}",
            std::process::id()
        ));
        let legacy = "[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n";
        std::fs::write(&path, legacy).unwrap();
        let path_text = path.to_string_lossy();
        let command = ["/usr/local/bin/zeronat", "client", "--config", &path_text];

        let error = validate_deployment_command(&command, "systemd", "")
            .unwrap_err()
            .to_string();

        assert!(error.contains("legacy enrollment values"), "{error}");
        assert!(error.contains("--reinstall"), "{error}");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn docker_shared_client_config_blocks_upgrade() {
        let path = std::env::temp_dir().join(format!(
            "zeronat-upgrade-docker-config-{}",
            std::process::id()
        ));
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let shared = format!(
            "[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"{secret}\"\ncredential = \"{}\"\n",
            secret.to_ascii_uppercase()
        );
        std::fs::write(&path, shared).unwrap();
        let path_text = path.to_string_lossy();
        let command = ["client", "--config", &path_text];

        let error = validate_deployment_command(&command, "docker", "")
            .unwrap_err()
            .to_string();

        assert!(error.contains("legacy enrollment values"), "{error}");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn current_client_config_reaches_upgrade() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let credential = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        let current = format!(
            "[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"{secret}\"\ncredential = \"{credential}\"\n"
        );

        assert!(validate_client_config("client.toml", &current).unwrap());
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
        .unwrap_err()
        .to_string();
        assert!(error.contains("ZERONAT_SECRET"), "{error}");
        assert!(error.contains("EXTRA"), "{error}");
        assert!(!error.contains("PATH"), "{error}");
        assert!(!error.contains("current"), "{error}");
        assert!(!error.contains("replacement"), "{error}");
    }

    #[test]
    fn docker_restart_policy_keeps_failure_retry_limit() {
        assert_eq!(
            docker_restart_policy("on-failure".into(), "7".into()).unwrap(),
            "on-failure:7"
        );
        assert_eq!(
            docker_restart_policy("always".into(), "0".into()).unwrap(),
            "always"
        );
    }

    #[test]
    fn environment_snapshot_refuses_unrepresentable_entries_and_new_image_keys() {
        assert!(
            validate_env_file_entry("ZERONAT_ARGS=client --config /etc/zeronat/client.toml")
                .is_ok()
        );
        assert!(validate_env_file_entry("#SECRET=value").is_err());
        assert!(validate_env_file_entry("SECRET= trailing ").is_err());
        assert!(validate_env_file_entry(&format!("LONG={}", "x".repeat(64 * 1024))).is_err());

        let current = ["PATH=/old".into(), "SECRET=current".into()];
        validate_image_env(&current, &["PATH=/new".into()]).unwrap();
        let error = validate_image_env(&current, &["NEW=value".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("NEW"), "{error}");
        assert!(!error.contains("value"), "{error}");
    }

    #[test]
    fn client_role_is_not_bypassed_by_a_server_argument_value() {
        let path = std::env::temp_dir().join(format!(
            "zeronat-upgrade-role-config-{}",
            std::process::id()
        ));
        std::fs::write(&path, "").unwrap();
        let path_text = path.to_string_lossy();
        let command = ["client", "--config", &path_text, "--name", "server"];

        let error = validate_deployment_command(&command, "systemd", "").unwrap_err();

        assert!(error.to_string().contains("no server identity"), "{error}");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn client_without_config_requires_both_enrollment_values() {
        let command = ["client"];
        let env =
            "ZERONAT_SECRET=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";

        let error = validate_deployment_command(&command, "docker", env).unwrap_err();

        assert!(
            error.to_string().contains("no client credential"),
            "{error}"
        );
    }

    #[test]
    fn rendered_compose_selects_the_zeronat_service() {
        let rendered = br#"{"services":{"other":{"command":["server"]},"zeronat":{"command":["client","--config","/etc/zeronat/client.toml"]}}}"#;

        assert_eq!(
            parse_compose_deployment(rendered).unwrap().command,
            ["client", "--config", "/etc/zeronat/client.toml"]
        );
    }

    #[test]
    fn rendered_compose_preserves_privileges_for_config_driven_device_mode() {
        let rendered = br#"{"services":{"zeronat":{"command":["client","--config","/etc/zeronat/client.toml"],"user":"0:0","cap_add":["NET_ADMIN"],"devices":[{"source":"/dev/net/tun","target":"/dev/net/tun","permissions":"rwm"}]}}}"#;
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let credential = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

        for device in ["[tap]\ndev = \"zn0\"\n", "[tun]\n"] {
            let config = format!(
                "[[servers]]\nname = \"home\"\naddr = \"dht\"\nsecret = \"{secret}\"\ncredential = \"{credential}\"\n{device}"
            );
            assert!(validate_client_config("client.toml", &config).unwrap());
            let deployment = parse_compose_deployment(rendered).unwrap();
            assert_eq!(compose_asset(deployment.privileged), COMPOSE_BRIDGE_ASSET);
        }

        let plain = br#"{"services":{"zeronat":{"command":["client","--config","/etc/zeronat/client.toml"],"user":"65532:65532","cap_drop":["ALL"]}}}"#;
        let deployment = parse_compose_deployment(plain).unwrap();
        assert_eq!(compose_asset(deployment.privileged), COMPOSE_ASSET);
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
        assert!(!version_newer("0.14.0", "unknown"));
        assert!(!version_newer("unknown", "0.14.0"));
        assert!(!version_newer("0.14.0", "0.13"));
        assert!(!version_newer("0.14.0", "0.13.0-rc1"));
        assert!(validate_installed_version("systemd", "unknown")
            .unwrap_err()
            .to_string()
            .contains("reinstall it from a signed release"));
    }

    #[test]
    fn image_reference_comes_from_the_signed_release_manifest() {
        let release = SelectedRelease::from_version("0.25.1").unwrap();
        let mut runner = FakeUpgradeRunner {
            commands: Vec::new(),
            installed: Vec::new(),
        };

        let image = download_image_reference_with(&release, &mut runner).unwrap();

        assert_eq!(
            image,
            std::str::from_utf8(TEST_RELEASE_IMAGE).unwrap().trim()
        );
    }
}
