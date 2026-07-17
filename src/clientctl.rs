//! Local admin socket hosted by a running client.
//!
//! The client listens on a Unix domain socket at `[client].control` (default
//! `/run/zeronat/client.sock`). Each accepted connection runs the Noise
//! handshake under the fixed local-admin PSK, performs one request/response in
//! the [`crate::clientproto`] namespace, and closes. The socket file is 0600
//! inside a 0700 directory: filesystem permissions are the access control; the
//! handshake supplies framing and channel integrity, not admission.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};

use crate::client::{
    derive_mode, ActiveTarget, Forward, PppoeRunConfig, RunMode, ServerTarget, SharedForwards,
    SharedServers,
};
use crate::clientcfg::{serialize_client, CfgForward, CfgServer, ClientConfig};
use crate::clientproto::{ClientMsg, ClientSnapshotBody, LinkCell, PppStatus};
use crate::proto::{proto_name, Proto};
use crate::Result;

/// Directory hosting the default socket when the client can create it.
pub(crate) const PRIMARY_DIR: &str = "/run/zeronat";
/// Socket directory under `$XDG_RUNTIME_DIR` when the primary is unusable.
pub(crate) const RUNTIME_SUBDIR: &str = "zeronat";
pub(crate) const SOCKET_NAME: &str = "client.sock";
/// Bound for one whole admin exchange (handshake, request, response), so a
/// peer that connects and stalls cannot wedge the accept loop.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// PSK for the admin socket's Noise handshake. Deliberately a fixed, public
/// constant: admission is controlled by the socket file mode, not by the key,
/// so connecting needs no secret argument.
pub fn admin_psk() -> [u8; 32] {
    crate::noise::derive_psk("zeronat-client-admin-v1")
}

/// Where the admin socket path came from, which decides how failures to bind
/// it are treated. The socket is auxiliary to the tunnel: a path the operator
/// asked for must work, while the built-in default is best-effort.
pub enum ControlPath {
    /// Set via `[client].control`; a path that cannot be bound is fatal.
    Explicit(PathBuf),
    /// The resolved default location; a path that cannot be bound disables
    /// the admin socket and the client runs without one.
    Default(PathBuf),
}

impl ControlPath {
    /// Bind the admin listener under this path's failure policy: `Explicit`
    /// propagates the error, `Default` logs it and returns no listener.
    pub fn bind(self) -> Result<Option<ControlListener>> {
        match self {
            ControlPath::Explicit(path) => ControlListener::bind(path).map(Some),
            ControlPath::Default(path) => match ControlListener::bind(path) {
                Ok(listener) => Ok(Some(listener)),
                Err(e) => {
                    crate::elog!("no admin socket: {e}; the client runs without one");
                    Ok(None)
                }
            },
        }
    }
}

/// Control-socket path when `[client].control` is unset: `client.sock` under
/// `/run/zeronat`, or under `$XDG_RUNTIME_DIR/zeronat` when the primary
/// directory cannot be created. When neither location can be prepared the
/// client runs without an admin socket; the failure is logged here.
pub fn default_control() -> Option<ControlPath> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    default_control_in(Path::new(PRIMARY_DIR), runtime.as_deref())
}

fn default_control_in(primary: &Path, runtime_dir: Option<&Path>) -> Option<ControlPath> {
    match resolve_control_dir(primary, runtime_dir) {
        Ok(dir) => Some(ControlPath::Default(dir.join(SOCKET_NAME))),
        Err(e) => {
            crate::elog!("no admin socket: {e}; the client runs without one");
            None
        }
    }
}

/// Ensure the directory hosting the default socket exists with mode 0700 and
/// return it. `primary` is preferred; when it cannot be created (typically an
/// unprivileged client under `/run`), the socket moves to a `zeronat`
/// directory under `runtime_dir`.
fn resolve_control_dir(primary: &Path, runtime_dir: Option<&Path>) -> Result<PathBuf> {
    let primary_err = match create_dir_0700(primary) {
        Ok(()) => return Ok(primary.to_path_buf()),
        Err(e) => e,
    };
    let Some(base) = runtime_dir else {
        return Err(format!(
            "creating {}: {primary_err}, and XDG_RUNTIME_DIR is unset",
            primary.display()
        )
        .into());
    };
    let dir = base.join(RUNTIME_SUBDIR);
    create_dir_0700(&dir)
        .map_err(|e| -> crate::Error { format!("creating {}: {e}", dir.display()).into() })?;
    Ok(dir)
}

fn create_dir_0700(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Admin-mutation persistence target: the config file and its parsed
/// contents, present only when the client's shape came from that file. The
/// dispatcher edits the parsed config and rewrites the whole file, so a saved
/// file always passes the client parser and validation.
pub struct Persist {
    path: PathBuf,
    /// The parsed config; the dispatcher applies edits here in mutation order.
    cfg: Arc<std::sync::Mutex<ClientConfig>>,
    /// Gate serializing the disk writes. An exchange timeout abandons a
    /// spawn_blocking save without stopping it, so without the gate an older
    /// abandoned rename could land after a newer one; each save serializes the
    /// config under the gate, so the last rename carries the newest state.
    write: Arc<std::sync::Mutex<()>>,
}

impl Persist {
    pub fn new(path: PathBuf, cfg: ClientConfig) -> Self {
        Persist {
            path,
            cfg: Arc::new(std::sync::Mutex::new(cfg)),
            write: Arc::new(std::sync::Mutex::new(())),
        }
    }
}

/// The client-runtime state the accept loop answers snapshots and mutations
/// from. Snapshot reads and mutation applies are lock-only: the dispatcher
/// never waits on the switch cancel (whose `Notify` has a sole-waiter contract
/// with the reconnect loop) and never awaits a teardown before replying.
pub struct ControlState {
    /// Shared active target and session body; mutations fire its cancel.
    pub active: ActiveTarget,
    /// Live forward set, edited by `SetForwardOptions`.
    pub forwards: SharedForwards,
    /// Live PPP phase, written by the pppoe datapath shell.
    pub ppp: PppStatus,
    /// Link state toward the active server, reported verbatim in snapshots.
    /// The reconnect loop writes the park/dial/backoff transitions; the
    /// session bodies write the connected state.
    pub link: LinkCell,
    /// Profiles `SelectServer` and `Connect` resolve against, edited by
    /// `AddServer`/`RemoveServer`.
    pub servers: SharedServers,
    /// Sessions `SpawnPppoe` may bring up, by name.
    pub pppoe: Vec<(String, Arc<PppoeRunConfig>)>,
    /// The boot chain minus its forwards arm, fixed at boot: the autostart
    /// pppoe, else the device, else idle. The bodies `Connect` and
    /// `StopSession` install are derived at use from the declared forward
    /// set, so runtime forward edits move them; only `Connect` falls through
    /// to this chain.
    pub fallback_mode: RunMode,
    /// `None` on a runtime-only client; mutations then stay in memory.
    pub persist: Option<Persist>,
}

impl ControlState {
    /// The boot-derived body `Connect` installs, so disconnect-then-connect
    /// restores the currently declared boot shape, not whatever ran last.
    fn boot_mode(&self) -> RunMode {
        derive_mode(&self.forwards, &self.fallback_mode)
    }

    /// The body `StopSession` falls back to: forwards when any are declared,
    /// idle otherwise.
    fn base_mode(&self) -> RunMode {
        derive_mode(&self.forwards, &RunMode::Idle)
    }
}

/// The bound admin socket. Dropping it removes the socket file, so an aborted
/// accept-loop task and a normal return both leave the path clean.
pub struct ControlListener {
    listener: UnixListener,
    path: PathBuf,
}

impl ControlListener {
    /// Unlink any stale socket a previous process left at `path`, bind, and
    /// restrict the socket file to its owner. Only a socket is ever unlinked;
    /// anything else occupying the path is somebody's file and refusing to
    /// bind beats deleting it. A stale socket that cannot be unlinked is an
    /// error too: binding over it would fail anyway, and silently serving
    /// nothing is worse than not binding.
    pub fn bind(path: PathBuf) -> Result<Self> {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    return Err(format!(
                        "control socket path {} is occupied by a non-socket; refusing to replace it",
                        path.display()
                    )
                    .into());
                }
                std::fs::remove_file(&path).map_err(|e| -> crate::Error {
                    format!("removing stale control socket {}: {e}", path.display()).into()
                })?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(
                    format!("inspecting control socket path {}: {e}", path.display()).into(),
                )
            }
        }
        let listener = UnixListener::bind(&path).map_err(|e| -> crate::Error {
            format!("binding control socket {}: {e}", path.display()).into()
        })?;
        let bound = ControlListener { listener, path };
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bound.path, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| -> crate::Error {
                format!("restricting control socket {}: {e}", bound.path.display()).into()
            },
        )?;
        Ok(bound)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept connections forever, one request/response each, handled in
    /// sequence under [`EXCHANGE_TIMEOUT`]. Runs until the owning task is
    /// aborted; the listener's `Drop` then removes the socket file.
    pub async fn serve(self, state: ControlState) {
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e) => {
                    crate::elog!("control socket accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let outcome = tokio::time::timeout(EXCHANGE_TIMEOUT, handle(stream, &state))
                .await
                .unwrap_or_else(|_| Err("admin exchange timed out".into()));
            if let Err(e) = outcome {
                crate::elog!("control socket exchange failed: {e}");
            }
        }
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One admin exchange: handshake, hello, then a snapshot (mode 0) or a
/// mutation answered by a `MutationResult` (mode 1).
async fn handle(stream: UnixStream, state: &ControlState) -> Result<()> {
    let (mut r, mut w) = crate::noise::server_handshake(stream, &admin_psk()).await?;
    let frame = r.recv().await?;
    let mode = match ClientMsg::decode(&frame)? {
        ClientMsg::ClientAdminHello { version: _, mode } => mode,
        other => return Err(format!("expected client admin hello, got {other:?}").into()),
    };
    match mode {
        0 => {
            w.send(&ClientMsg::ClientSnapshot(snapshot(state)).encode())
                .await?;
        }
        1 => {
            let frame = r.recv().await?;
            let (ok, msg) = mutate(state, ClientMsg::decode(&frame)?).await;
            w.send(&ClientMsg::MutationResult { ok, msg }.encode())
                .await?;
        }
        n => return Err(format!("unknown admin hello mode {n}").into()),
    }
    Ok(())
}

fn snapshot(state: &ControlState) -> ClientSnapshotBody {
    let (active, mode, session) = state.active.admin_view();
    ClientSnapshotBody {
        version: crate::identity::PROTO_VERSION,
        active,
        mode,
        phase: state.ppp.get(),
        forwards: state.forwards.entries(),
        servers: state.servers.entries(),
        pppoe: state.pppoe.iter().map(|(name, _)| name.clone()).collect(),
        session,
        link: state.link.get(),
    }
}

/// Apply one admin mutation. Every reply is an acceptance reply: validate,
/// update the shared state, persist when file-sourced, fire the switch cancel,
/// and answer without awaiting the teardown or bringup the cancel triggers. A
/// validation failure changes nothing; a save failure returns `false` even
/// though the mutation already applied in memory, so a scripted admin detects
/// that the on-disk config did not change.
async fn mutate(state: &ControlState, msg: ClientMsg) -> (bool, String) {
    match msg {
        ClientMsg::SelectServer { name } => {
            let Some(target) = state.servers.get(&name) else {
                return (false, format!("no configured server named `{name}`"));
            };
            if let Some(msg) = undialable(&target, cfg!(feature = "dht")) {
                return (false, msg);
            }
            // One call updates the target and fires the cancel; the session
            // body is preserved and comes back up against the new server. An
            // offline client just re-parks retargeted, nothing is dialed.
            state.active.switch(target);
            persist(state, move |cfg| cfg.active = Some(name)).await
        }
        ClientMsg::SetForwardOptions {
            proto,
            port,
            enabled,
            proxy,
            idle_secs,
        } => {
            // Mirror the config parser's per-entry rules, so what is applied
            // here is exactly what the persisted file will parse back.
            if proxy && proto == Proto::Udp {
                return (false, "`proxy` is not supported on udp forwards".into());
            }
            // Wire 0 clears the idle override; the config value is therefore
            // never Some(0), which the parser would reject.
            let idle = if idle_secs == 0 {
                None
            } else {
                Some(Duration::from_secs(u64::from(idle_secs)))
            };
            if !state
                .forwards
                .set_options(proto, port, enabled, proxy, idle)
            {
                return (
                    false,
                    format!("no {} forward on port {port}", proto_name(proto)),
                );
            }
            let saved = persist(state, move |cfg| {
                if let Some(f) = cfg
                    .forwards
                    .iter_mut()
                    .find(|f| f.proto == proto && f.port == port)
                {
                    f.enabled = enabled;
                    f.proxy = proxy;
                    f.idle = if idle_secs == 0 {
                        None
                    } else {
                        Some(idle_secs)
                    };
                }
            })
            .await;
            state.active.kick_if_forwards();
            saved
        }
        ClientMsg::SpawnPppoe { name } => {
            let Some((_, config)) = state.pppoe.iter().find(|(n, _)| *n == name) else {
                return (false, format!("no configured pppoe session named `{name}`"));
            };
            // Runtime-only: which session runs is never written back.
            state.active.set_mode(RunMode::Pppoe {
                name,
                config: config.clone(),
            });
            (true, String::new())
        }
        ClientMsg::StopSession { name } => {
            // Runtime-only, valid only against the running pppoe body; the
            // loop falls back to the derived base mode.
            if state.active.stop_pppoe(&name, state.base_mode()) {
                (true, String::new())
            } else {
                (false, format!("no active pppoe session named `{name}`"))
            }
        }
        ClientMsg::AddServer {
            name,
            addr,
            secret,
            transport,
        } => {
            // Mirror the parser and validate plus the checks boot hits at
            // dial time, so the accepted entry is exactly what the persisted
            // file parses back to and what the dial loop can use.
            if name.is_empty() {
                return (false, "server `name` must not be empty".into());
            }
            if secret.0.is_empty() {
                return (false, "server `secret` must not be empty".into());
            }
            // The config lexer rejects control characters in strings, so a
            // value carrying one could never be saved and read back.
            for (field, value) in [
                ("name", name.as_str()),
                ("addr", addr.as_str()),
                ("secret", secret.0.as_str()),
            ] {
                if value.chars().any(char::is_control) {
                    return (
                        false,
                        format!("server `{field}` must not contain control characters"),
                    );
                }
            }
            if addr == "dht" {
                if cfg!(not(feature = "dht")) {
                    return (false, "this build has no dht support; use host:port".into());
                }
            } else if !valid_host_port(&addr) {
                return (
                    false,
                    format!("addr must be \"dht\" or host:port, got `{addr}`"),
                );
            }
            let target = ServerTarget {
                name: name.clone(),
                addr: addr.clone(),
                secret: secret.0.clone(),
                transport,
            };
            // Name uniqueness also protects the empty-name `Connect` sentinel.
            if !state.servers.add(target) {
                return (false, format!("a server named `{name}` already exists"));
            }
            persist(state, move |cfg| {
                cfg.servers.push(CfgServer {
                    name,
                    addr,
                    secret,
                    transport,
                })
            })
            .await
        }
        ClientMsg::RemoveServer { name } => {
            // The active profile is the one the loop is running or about to
            // dial (offline included); removing it would strand the runtime
            // target and, on a file-sourced client, save a config whose
            // `active` names no entry.
            if state.active.admin_view().0 == name {
                return (
                    false,
                    format!("`{name}` is the active server; select another first"),
                );
            }
            if !state.servers.remove(&name) {
                return (false, format!("no configured server named `{name}`"));
            }
            persist(state, move |cfg| cfg.servers.retain(|s| s.name != name)).await
        }
        ClientMsg::Connect { name } => {
            // An empty name means the current active target, resolved before
            // any server-list lookup; a named connect must name a profile.
            let target = if name.is_empty() {
                None
            } else {
                match state.servers.get(&name) {
                    Some(t) => Some(t),
                    None => return (false, format!("no configured server named `{name}`")),
                }
            };
            if let Some(t) = &target {
                if let Some(msg) = undialable(t, cfg!(feature = "dht")) {
                    return (false, msg);
                }
            }
            let named = target.is_some();
            if !state.active.connect(target, state.boot_mode()) {
                return (
                    false,
                    "a session is already up; select-server retargets a running client".into(),
                );
            }
            if named {
                persist(state, move |cfg| cfg.active = Some(name)).await
            } else {
                (true, String::new())
            }
        }
        ClientMsg::Disconnect => {
            // Runtime-only, like SpawnPppoe: the offline park is never
            // persisted, so a reboot comes back serving what the file
            // declares.
            if state.active.disconnect() {
                (true, String::new())
            } else {
                (false, "already offline".into())
            }
        }
        ClientMsg::AddForward {
            proto,
            port,
            target,
            proxy,
            idle_secs,
            enabled,
        } => {
            // The empty target is the wire's config-default sentinel; resolve
            // it before validation and persistence, exactly as the config
            // parser fills a missing `target` key.
            let target = if target.is_empty() {
                format!("127.0.0.1:{port}")
            } else {
                target
            };
            // Mirror the parser and validate, so the applied entry is exactly
            // what the persisted file parses back to.
            if proxy && proto == Proto::Udp {
                return (false, "`proxy` is not supported on udp forwards".into());
            }
            if !valid_host_port(&target) {
                return (false, format!("target must be host:port, got `{target}`"));
            }
            // The config lexer rejects control characters in strings, so a
            // value carrying one could never be saved and read back.
            if target.chars().any(char::is_control) {
                return (
                    false,
                    "forward `target` must not contain control characters".into(),
                );
            }
            // A device-bound client cannot serve forwards, and validate
            // refuses the combination, so persisting it would save a file
            // boot rejects.
            if matches!(state.fallback_mode, RunMode::Device(_)) {
                return (false, "[tap]/[tun] cannot be combined with forwards".into());
            }
            // Wire 0 means no idle override; the config value is therefore
            // never Some(0), which the parser would reject.
            let idle = (idle_secs != 0).then(|| Duration::from_secs(u64::from(idle_secs)));
            let fwd = Forward {
                port,
                target: target.clone(),
                proxy,
                idle,
                enabled,
            };
            if !state.forwards.add(proto, fwd) {
                return (
                    false,
                    format!(
                        "a {} forward on port {port} already exists",
                        proto_name(proto)
                    ),
                );
            }
            let saved = persist(state, move |cfg| {
                cfg.forwards.push(CfgForward {
                    proto,
                    port,
                    target,
                    proxy,
                    idle: (idle_secs != 0).then_some(idle_secs),
                    enabled,
                })
            })
            .await;
            state.active.serve_forwards();
            saved
        }
        ClientMsg::RemoveForward { proto, port } => {
            if !state.forwards.remove(proto, port) {
                return (
                    false,
                    format!("no {} forward on port {port}", proto_name(proto)),
                );
            }
            let saved = persist(state, move |cfg| {
                cfg.forwards
                    .retain(|f| !(f.proto == proto && f.port == port))
            })
            .await;
            // Never demotes the mode: removing the last forward leaves a live
            // forwards body running as the bare control session.
            state.active.kick_if_forwards();
            saved
        }
        other => (false, format!("expected a mutation, got {other:?}")),
    }
}

/// Refusal for a profile this build cannot dial. Dialing a `"dht"` profile
/// without dht support is a fatal discovery error in the reconnect loop, which
/// would kill the daemon after the acceptance reply; refusing the retarget
/// here keeps the loop away from it. Config-declared profiles hit this too:
/// boot only dials the active profile, so the others were never checked.
fn undialable(target: &ServerTarget, dht_supported: bool) -> Option<String> {
    (target.addr == "dht" && !dht_supported).then(|| {
        format!(
            "`{}` is a dht profile and this build has no dht support",
            target.name
        )
    })
}

/// `host:port` with a non-empty host and a non-zero port. Hostnames resolve
/// at dial time, so only the shape is checked here.
fn valid_host_port(addr: &str) -> bool {
    match addr.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0),
        None => false,
    }
}

/// Persist an applied mutation on a file-sourced client: edit the parsed
/// config, then rewrite the file crash-safely off the runtime threads. The
/// blocking task serializes under the write gate, so a save that outlives its
/// exchange can neither reorder renames nor write a stale config. A
/// runtime-only client returns success without touching any file.
async fn persist(state: &ControlState, edit: impl FnOnce(&mut ClientConfig)) -> (bool, String) {
    let Some(p) = &state.persist else {
        return (true, String::new());
    };
    {
        let mut cfg = p.cfg.lock().unwrap();
        edit(&mut cfg);
    }
    let path = p.path.clone();
    let cfg = p.cfg.clone();
    let write = p.write.clone();
    match tokio::task::spawn_blocking(move || {
        let _gate = write.lock().unwrap();
        let text = serialize_client(&cfg.lock().unwrap());
        crate::config::save_atomic(&path, &text)
    })
    .await
    {
        Ok(Ok(())) => (true, String::new()),
        Ok(Err(e)) => (false, format!("client rejected config save: {e}")),
        Err(e) => (false, format!("config save task failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Forward, Transport};
    use crate::clientproto::{LinkStatus, PppPhase, ServerSecret, SessionMode};
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zeronat-clientctl-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn dir_mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn server_target(name: &str, port: u16) -> ServerTarget {
        ServerTarget {
            name: name.into(),
            addr: format!("127.0.0.1:{port}"),
            secret: "s".into(),
            transport: Transport::Tcp,
        }
    }

    fn idle_state(name: &str) -> ControlState {
        ControlState {
            active: ActiveTarget::new(server_target(name, 1)),
            forwards: SharedForwards::new(Vec::new(), Vec::new()),
            ppp: PppStatus::default(),
            link: LinkCell::default(),
            servers: SharedServers::new(Vec::new()),
            pppoe: Vec::new(),
            fallback_mode: RunMode::Idle,
            persist: None,
        }
    }

    fn pppoe_config() -> Arc<PppoeRunConfig> {
        Arc::new(PppoeRunConfig {
            username: b"u".to_vec(),
            password: b"p".to_vec(),
            service_name: Vec::new(),
            ac_name: None,
            tun_name: "zppp0".into(),
            effective_mtu: 1400,
            default_route: false,
            clamp_mss: None,
            request_dns: false,
        })
    }

    fn tcp_fwd(port: u16) -> Forward {
        Forward {
            port,
            target: format!("127.0.0.1:{}", port + 1),
            proxy: false,
            idle: None,
            enabled: true,
        }
    }

    /// The snapshot reports whatever the datapath last wrote into the cell.
    #[test]
    fn snapshot_reports_the_live_ppp_phase() {
        let state = idle_state("home");
        assert_eq!(snapshot(&state).phase, PppPhase::None);
        // No writer holds the link cell, so it reports its default.
        assert_eq!(snapshot(&state).link, LinkStatus::Offline);
        for phase in [
            PppPhase::Discovery,
            PppPhase::Negotiating,
            PppPhase::Established,
            PppPhase::LinkDown,
            PppPhase::Dead,
            PppPhase::None,
        ] {
            state.ppp.set(phase);
            assert_eq!(snapshot(&state).phase, phase);
        }
    }

    #[tokio::test]
    async fn select_server_validates_and_persists() {
        let dir = temp_dir("selsrv");
        let path = dir.join("client.toml");
        let cfg = crate::clientcfg::parse_client(
            "[client]\nactive = \"a\"\n\
             [[servers]]\nname = \"a\"\naddr = \"127.0.0.1:1\"\nsecret = \"s\"\n\
             [[servers]]\nname = \"b\"\naddr = \"127.0.0.1:2\"\nsecret = \"t\"\n",
        )
        .unwrap();
        let mut state = idle_state("a");
        state.servers = SharedServers::new(vec![server_target("a", 1), server_target("b", 2)]);
        state.persist = Some(Persist::new(path.clone(), cfg));

        // The snapshot lists the selectable profiles by their config fields.
        let snap = snapshot(&state);
        let names: Vec<&str> = snap.servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(snap.servers[0].addr, "127.0.0.1:1");
        assert_eq!(snap.servers[0].transport, Transport::Tcp);

        let (ok, msg) = mutate(
            &state,
            ClientMsg::SelectServer {
                name: "nope".into(),
            },
        )
        .await;
        assert!(!ok);
        assert!(!path.exists(), "a rejected mutation must not write: {msg}");
        assert_eq!(state.active.admin_view().0, "a");

        let (ok, msg) = mutate(&state, ClientMsg::SelectServer { name: "b".into() }).await;
        assert!(ok, "{msg}");
        assert_eq!(state.active.admin_view().0, "b");
        // The saved file parses back with the new active profile and passes
        // the same validation boot applies.
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert_eq!(on_disk.active.as_deref(), Some("b"));
        assert_eq!(on_disk.servers.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn set_forward_options_validates_edits_and_persists() {
        let dir = temp_dir("fwdopt");
        let path = dir.join("client.toml");
        let text = "[[servers]]\nname = \"a\"\naddr = \"127.0.0.1:1\"\nsecret = \"s\"\n\
                    [[forwards]]\nproto = \"tcp\"\nport = 443\ntarget = \"127.0.0.1:444\"\n\
                    [[forwards]]\nproto = \"udp\"\nport = 53\ntarget = \"127.0.0.1:54\"\n";
        std::fs::write(&path, text).unwrap();
        let mut state = idle_state("a");
        state.forwards = SharedForwards::new(
            vec![tcp_fwd(443)],
            vec![Forward {
                port: 53,
                target: "127.0.0.1:54".into(),
                proxy: false,
                idle: None,
                enabled: true,
            }],
        );
        state.persist = Some(Persist::new(
            path.clone(),
            crate::clientcfg::parse_client(text).unwrap(),
        ));

        // Failing validation persists and applies nothing: proxy on udp,
        // then a forward that does not exist.
        let before = std::fs::read_to_string(&path).unwrap();
        let entries_before = state.forwards.entries();
        let (ok, _) = mutate(
            &state,
            ClientMsg::SetForwardOptions {
                proto: Proto::Udp,
                port: 53,
                enabled: true,
                proxy: true,
                idle_secs: 0,
            },
        )
        .await;
        assert!(!ok, "proxy on a udp forward must be rejected");
        let (ok, _) = mutate(
            &state,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: 80,
                enabled: true,
                proxy: false,
                idle_secs: 5,
            },
        )
        .await;
        assert!(!ok, "an unknown forward must be rejected");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(state.forwards.entries(), entries_before);

        // A valid edit lands in memory and round-trips through the parser.
        let (ok, msg) = mutate(
            &state,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: 443,
                enabled: false,
                proxy: true,
                idle_secs: 600,
            },
        )
        .await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        assert!(snap.forwards[0].proxy);
        assert_eq!(snap.forwards[0].idle_secs, 600);
        assert!(!snap.forwards[0].enabled);
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert!(on_disk.forwards[0].proxy);
        assert_eq!(on_disk.forwards[0].idle, Some(600));
        assert!(!on_disk.forwards[0].enabled);

        // Wire idle 0 clears the override; the file never carries idle = 0,
        // which the parser would reject.
        let (ok, msg) = mutate(
            &state,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: 443,
                enabled: true,
                proxy: true,
                idle_secs: 0,
            },
        )
        .await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        assert_eq!(snap.forwards[0].idle_secs, 0);
        assert!(snap.forwards[0].enabled);
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert_eq!(on_disk.forwards[0].idle, None);
        assert!(on_disk.forwards[0].enabled);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn add_forward(proto: Proto, port: u16, target: &str) -> ClientMsg {
        ClientMsg::AddForward {
            proto,
            port,
            target: target.into(),
            proxy: false,
            idle_secs: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn add_forward_validates_persists_and_promotes() {
        let dir = temp_dir("addfwd");
        let path = dir.join("client.toml");
        let text = "[[servers]]\nname = \"a\"\naddr = \"127.0.0.1:1\"\nsecret = \"s\"\n\
                    [[forwards]]\nproto = \"tcp\"\nport = 443\ntarget = \"127.0.0.1:444\"\n";
        std::fs::write(&path, text).unwrap();
        let mut state = idle_state("a");
        state.forwards = SharedForwards::new(vec![tcp_fwd(443)], Vec::new());
        state.persist = Some(Persist::new(
            path.clone(),
            crate::clientcfg::parse_client(text).unwrap(),
        ));
        state.active.set_mode(RunMode::Forwards);

        // Each refusal mirrors a parser/validate rule and changes nothing:
        // a duplicate key, proxy on udp, a shapeless target, and a target
        // carrying a control character.
        let before = std::fs::read_to_string(&path).unwrap();
        let entries_before = state.forwards.entries();
        let refused = [
            add_forward(Proto::Tcp, 443, "127.0.0.1:80"),
            ClientMsg::AddForward {
                proto: Proto::Udp,
                port: 53,
                target: String::new(),
                proxy: true,
                idle_secs: 0,
                enabled: true,
            },
            add_forward(Proto::Tcp, 80, "no-port"),
            add_forward(Proto::Tcp, 80, ":80"),
            add_forward(Proto::Tcp, 80, "127.0.0.1:0"),
            add_forward(Proto::Tcp, 80, "10.0.0.5\n:80"),
        ];
        for req in refused {
            let desc = format!("{req:?}");
            let (ok, msg) = mutate(&state, req).await;
            assert!(!ok, "expected a refusal for {desc}: {msg}");
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(state.forwards.entries(), entries_before);

        // The empty target resolves to the config default before persistence,
        // and idle rides the wire in whole seconds.
        let (ok, msg) = mutate(
            &state,
            ClientMsg::AddForward {
                proto: Proto::Udp,
                port: 53,
                target: String::new(),
                proxy: false,
                idle_secs: 300,
                enabled: false,
            },
        )
        .await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Udp && f.port == 53)
            .expect("added forward in the snapshot");
        assert_eq!(f.target, "127.0.0.1:53");
        assert_eq!(f.idle_secs, 300);
        assert!(!f.enabled);
        // Persisted: the file parses back, passes the boot validation, and
        // carries the resolved target.
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        let entry = on_disk
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Udp && f.port == 53)
            .expect("added forward on disk");
        assert_eq!(entry.target, "127.0.0.1:53");
        assert_eq!(entry.idle, Some(300));
        assert!(!entry.enabled);

        // The forwards body was live, so the add kicked rather than moved it.
        assert_eq!(snap.mode, SessionMode::Forwards);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The first add on an idle client installs the forwards body; a
    /// device-bound client refuses the add outright.
    #[tokio::test]
    async fn add_forward_promotes_idle_and_refuses_a_device_client() {
        let state = idle_state("a");
        assert_eq!(snapshot(&state).mode, SessionMode::Idle);
        let (ok, msg) = mutate(&state, add_forward(Proto::Tcp, 443, "")).await;
        assert!(ok, "{msg}");
        assert_eq!(snapshot(&state).mode, SessionMode::Forwards);

        let mut device = idle_state("a");
        device.fallback_mode =
            RunMode::Device(crate::client::DeviceConfig::Tap(crate::tap::TapConfig {
                name: "ztap0".into(),
                mtu: 1400,
                bridge: None,
            }));
        let (ok, msg) = mutate(&device, add_forward(Proto::Tcp, 443, "")).await;
        assert!(!ok);
        assert!(msg.contains("[tap]/[tun]"), "{msg}");
        assert!(snapshot(&device).forwards.is_empty());
    }

    #[tokio::test]
    async fn remove_forward_refuses_unknown_and_persists_the_rest() {
        let dir = temp_dir("rmfwd");
        let path = dir.join("client.toml");
        let text = "[[servers]]\nname = \"a\"\naddr = \"127.0.0.1:1\"\nsecret = \"s\"\n\
                    [[forwards]]\nproto = \"tcp\"\nport = 443\ntarget = \"127.0.0.1:444\"\n\
                    [[forwards]]\nproto = \"udp\"\nport = 53\ntarget = \"127.0.0.1:54\"\n";
        std::fs::write(&path, text).unwrap();
        let mut state = idle_state("a");
        state.forwards = SharedForwards::new(
            vec![tcp_fwd(443)],
            vec![Forward {
                port: 53,
                target: "127.0.0.1:54".into(),
                proxy: false,
                idle: None,
                enabled: true,
            }],
        );
        state.persist = Some(Persist::new(
            path.clone(),
            crate::clientcfg::parse_client(text).unwrap(),
        ));
        state.active.set_mode(RunMode::Forwards);

        // No such key: the port on the wrong proto, and a port never declared.
        let before = std::fs::read_to_string(&path).unwrap();
        for (proto, port) in [(Proto::Udp, 443u16), (Proto::Tcp, 80)] {
            let (ok, msg) = mutate(&state, ClientMsg::RemoveForward { proto, port }).await;
            assert!(!ok, "expected a refusal: {msg}");
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(snapshot(&state).forwards.len(), 2);

        let (ok, msg) = mutate(
            &state,
            ClientMsg::RemoveForward {
                proto: Proto::Tcp,
                port: 443,
            },
        )
        .await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        assert_eq!(snap.forwards.len(), 1);
        assert_eq!(snap.forwards[0].proto, Proto::Udp);
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert_eq!(on_disk.forwards.len(), 1);
        assert_eq!(on_disk.forwards[0].proto, Proto::Udp);

        // Removing the last forward never demotes the live body.
        let (ok, msg) = mutate(
            &state,
            ClientMsg::RemoveForward {
                proto: Proto::Udp,
                port: 53,
            },
        )
        .await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        assert!(snap.forwards.is_empty());
        assert_eq!(snap.mode, SessionMode::Forwards);
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert!(on_disk.forwards.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The derived bodies track the declared set: adding a forward under an
    /// autostart-pppoe fallback moves both `Connect`'s body and
    /// `StopSession`'s fallback to forwards; removing it moves them back.
    #[tokio::test]
    async fn derived_modes_follow_forward_edits() {
        let mut state = idle_state("a");
        state.fallback_mode = RunMode::Pppoe {
            name: "wan".into(),
            config: pppoe_config(),
        };
        assert_eq!(state.boot_mode().session_mode(), SessionMode::Pppoe);
        assert_eq!(state.base_mode().session_mode(), SessionMode::Idle);

        let (ok, msg) = mutate(&state, add_forward(Proto::Tcp, 443, "")).await;
        assert!(ok, "{msg}");
        assert_eq!(state.boot_mode().session_mode(), SessionMode::Forwards);
        assert_eq!(state.base_mode().session_mode(), SessionMode::Forwards);

        let (ok, msg) = mutate(
            &state,
            ClientMsg::RemoveForward {
                proto: Proto::Tcp,
                port: 443,
            },
        )
        .await;
        assert!(ok, "{msg}");
        assert_eq!(state.boot_mode().session_mode(), SessionMode::Pppoe);
        assert_eq!(state.base_mode().session_mode(), SessionMode::Idle);
    }

    fn add_server(name: &str, addr: &str, secret: &str) -> ClientMsg {
        ClientMsg::AddServer {
            name: name.into(),
            addr: addr.into(),
            secret: ServerSecret(secret.into()),
            transport: Transport::Tcp,
        }
    }

    #[tokio::test]
    async fn add_server_validates_and_persists() {
        let dir = temp_dir("addsrv");
        let path = dir.join("client.toml");
        let text = "[[servers]]\nname = \"a\"\naddr = \"127.0.0.1:1\"\nsecret = \"s\"\n";
        std::fs::write(&path, text).unwrap();
        let mut state = idle_state("a");
        state.servers = SharedServers::new(vec![server_target("a", 1)]);
        state.persist = Some(Persist::new(
            path.clone(),
            crate::clientcfg::parse_client(text).unwrap(),
        ));

        // Each refusal mirrors a parser/validate rule and changes nothing.
        let before = std::fs::read_to_string(&path).unwrap();
        let refused = [
            add_server("", "127.0.0.1:2", "t"),
            add_server("b", "127.0.0.1:2", ""),
            add_server("a", "127.0.0.1:2", "t"),
            add_server("b", "no-port", "t"),
            add_server("b", ":1", "t"),
            add_server("b", "127.0.0.1:0", "t"),
            add_server("b", "127.0.0.1:99999", "t"),
        ];
        for req in refused {
            let desc = format!("{req:?}");
            let (ok, msg) = mutate(&state, req).await;
            assert!(!ok, "expected a refusal for {desc}: {msg}");
        }
        // A control character is refused with the offending field named.
        let (ok, msg) = mutate(&state, add_server("b\n", "127.0.0.1:2", "t")).await;
        assert!(!ok);
        assert!(msg.contains("`name`"), "{msg}");
        let (ok, msg) = mutate(&state, add_server("b", "127.0.0.1:2", "se\ncret")).await;
        assert!(!ok);
        assert!(msg.contains("`secret`"), "{msg}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(snapshot(&state).servers.len(), 1);

        let (ok, msg) = mutate(&state, add_server("b", "127.0.0.1:2", "t")).await;
        assert!(ok, "{msg}");
        // Live: listed by config fields only and resolvable by name.
        let snap = snapshot(&state);
        let names: Vec<&str> = snap.servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        // Persisted: the file parses back, passes the boot validation, and
        // carries the appended entry.
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert_eq!(on_disk.servers.len(), 2);
        assert_eq!(on_disk.servers[1].name, "b");
        assert_eq!(on_disk.servers[1].secret.0, "t");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A `"dht"` profile is dialable exactly when the build carries dht
    /// support; the refusal message names the profile.
    #[test]
    fn undialable_keys_on_dht_support() {
        let dht = ServerTarget {
            name: "roam".into(),
            addr: "dht".into(),
            secret: "s".into(),
            transport: Transport::Auto,
        };
        assert!(undialable(&dht, true).is_none());
        let msg = undialable(&dht, false).unwrap();
        assert!(msg.contains("`roam`"), "{msg}");
        assert!(msg.contains("dht"), "{msg}");
        assert!(undialable(&server_target("a", 1), false).is_none());
        assert!(undialable(&server_target("a", 1), true).is_none());
    }

    /// Retargeting to a config-declared dht profile must not reach the
    /// reconnect loop on a build that cannot dial it: the dispatcher refuses
    /// both `SelectServer` and `Connect` and nothing changes.
    #[cfg(not(feature = "dht"))]
    #[tokio::test]
    async fn select_and_connect_refuse_a_dht_profile_without_dht_support() {
        let mut state = idle_state("a");
        let dht = ServerTarget {
            name: "roam".into(),
            addr: "dht".into(),
            secret: "s".into(),
            transport: Transport::Auto,
        };
        state.servers = SharedServers::new(vec![server_target("a", 1), dht]);

        let (ok, msg) = mutate(
            &state,
            ClientMsg::SelectServer {
                name: "roam".into(),
            },
        )
        .await;
        assert!(!ok);
        assert!(msg.contains("dht"), "{msg}");
        assert_eq!(state.active.admin_view().0, "a");

        let (ok, msg) = mutate(
            &state,
            ClientMsg::Connect {
                name: "roam".into(),
            },
        )
        .await;
        assert!(!ok);
        assert!(msg.contains("dht"), "{msg}");
        assert_eq!(snapshot(&state).mode, SessionMode::Idle);
    }

    /// On a dht build the same retargets are accepted.
    #[cfg(feature = "dht")]
    #[tokio::test]
    async fn select_and_connect_accept_a_dht_profile_with_dht_support() {
        let mut state = idle_state("a");
        let dht = ServerTarget {
            name: "roam".into(),
            addr: "dht".into(),
            secret: "s".into(),
            transport: Transport::Auto,
        };
        state.servers = SharedServers::new(vec![server_target("a", 1), dht]);
        state.forwards = SharedForwards::new(vec![tcp_fwd(443)], Vec::new());

        let (ok, msg) = mutate(
            &state,
            ClientMsg::SelectServer {
                name: "roam".into(),
            },
        )
        .await;
        assert!(ok, "{msg}");
        assert_eq!(state.active.admin_view().0, "roam");

        let (ok, _) = mutate(&state, ClientMsg::Disconnect).await;
        assert!(ok);
        let (ok, msg) = mutate(
            &state,
            ClientMsg::Connect {
                name: "roam".into(),
            },
        )
        .await;
        assert!(ok, "{msg}");
        assert_eq!(snapshot(&state).mode, SessionMode::Forwards);
    }

    #[tokio::test]
    async fn remove_server_refuses_the_active_and_persists_the_rest() {
        let dir = temp_dir("rmsrv");
        let path = dir.join("client.toml");
        let text = "[client]\nactive = \"a\"\n\
                    [[servers]]\nname = \"a\"\naddr = \"127.0.0.1:1\"\nsecret = \"s\"\n\
                    [[servers]]\nname = \"b\"\naddr = \"127.0.0.1:2\"\nsecret = \"t\"\n";
        std::fs::write(&path, text).unwrap();
        let mut state = idle_state("a");
        state.servers = SharedServers::new(vec![server_target("a", 1), server_target("b", 2)]);
        state.persist = Some(Persist::new(
            path.clone(),
            crate::clientcfg::parse_client(text).unwrap(),
        ));

        // The profile the loop runs (or would dial next) cannot be removed;
        // neither can one that does not exist. Nothing changes.
        let before = std::fs::read_to_string(&path).unwrap();
        let (ok, msg) = mutate(&state, ClientMsg::RemoveServer { name: "a".into() }).await;
        assert!(!ok);
        assert!(msg.contains("active"), "unexpected refusal: {msg}");
        let (ok, _) = mutate(&state, ClientMsg::RemoveServer { name: "c".into() }).await;
        assert!(!ok);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(snapshot(&state).servers.len(), 2);

        // An inactive profile removes and the file parses back without it.
        let (ok, msg) = mutate(&state, ClientMsg::RemoveServer { name: "b".into() }).await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        assert_eq!(snap.servers.len(), 1);
        assert_eq!(snap.servers[0].name, "a");
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert_eq!(on_disk.servers.len(), 1);
        assert_eq!(on_disk.servers[0].name, "a");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn disconnect_parks_and_connect_restores_the_boot_body() {
        let mut state = idle_state("a");
        state.servers = SharedServers::new(vec![server_target("a", 1), server_target("b", 2)]);
        state.pppoe = vec![("wan".into(), pppoe_config())];
        state.forwards = SharedForwards::new(vec![tcp_fwd(443)], Vec::new());
        // Idle runs no session body, so connect is the park's exit there too:
        // it installs the boot-derived forwards body.
        let (ok, _) = mutate(
            &state,
            ClientMsg::Connect {
                name: String::new(),
            },
        )
        .await;
        assert!(ok);
        assert_eq!(snapshot(&state).mode, SessionMode::Forwards);

        let (ok, _) = mutate(&state, ClientMsg::Disconnect).await;
        assert!(ok);
        assert_eq!(snapshot(&state).mode, SessionMode::Offline);
        let (ok, msg) = mutate(&state, ClientMsg::Disconnect).await;
        assert!(!ok, "disconnect while offline must be refused");
        assert_eq!(msg, "already offline");

        // While offline, SelectServer retargets without leaving the park.
        let (ok, _) = mutate(&state, ClientMsg::SelectServer { name: "b".into() }).await;
        assert!(ok);
        let snap = snapshot(&state);
        assert_eq!(snap.active, "b");
        assert_eq!(snap.mode, SessionMode::Offline);

        // A connect naming no profile is refused before anything moves; a
        // named one retargets and installs the boot-derived body.
        let (ok, _) = mutate(&state, ClientMsg::Connect { name: "c".into() }).await;
        assert!(!ok);
        assert_eq!(snapshot(&state).mode, SessionMode::Offline);
        let (ok, msg) = mutate(&state, ClientMsg::Connect { name: "a".into() }).await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        assert_eq!(snap.active, "a");
        assert_eq!(snap.mode, SessionMode::Forwards);

        // With the body up, connect is refused whatever the name.
        let (ok, msg) = mutate(
            &state,
            ClientMsg::Connect {
                name: String::new(),
            },
        )
        .await;
        assert!(!ok);
        assert!(msg.contains("already up"), "unexpected refusal: {msg}");

        // An explicit spawn outranks the park: pppoe comes up from offline.
        let (ok, _) = mutate(&state, ClientMsg::Disconnect).await;
        assert!(ok);
        let (ok, msg) = mutate(&state, ClientMsg::SpawnPppoe { name: "wan".into() }).await;
        assert!(ok, "{msg}");
        assert_eq!(snapshot(&state).mode, SessionMode::Pppoe);
    }

    #[tokio::test]
    async fn spawn_and_stop_pppoe_move_the_session_mode() {
        let mut state = idle_state("a");
        state.pppoe = vec![("wan".into(), pppoe_config())];

        let (ok, _) = mutate(
            &state,
            ClientMsg::SpawnPppoe {
                name: "nope".into(),
            },
        )
        .await;
        assert!(!ok, "spawning an unknown session must fail");
        let (ok, _) = mutate(&state, ClientMsg::StopSession { name: "wan".into() }).await;
        assert!(!ok, "stopping with a non-pppoe body must fail");

        let (ok, msg) = mutate(&state, ClientMsg::SpawnPppoe { name: "wan".into() }).await;
        assert!(ok, "{msg}");
        assert_eq!(state.active.admin_view().1, SessionMode::Pppoe);
        let snap = snapshot(&state);
        assert_eq!(snap.pppoe, ["wan"]);
        assert_eq!(snap.session, "wan");

        let (ok, _) = mutate(
            &state,
            ClientMsg::StopSession {
                name: "other".into(),
            },
        )
        .await;
        assert!(!ok, "stopping a session that is not running must fail");
        assert_eq!(state.active.admin_view().1, SessionMode::Pppoe);

        let (ok, msg) = mutate(&state, ClientMsg::StopSession { name: "wan".into() }).await;
        assert!(ok, "{msg}");
        assert_eq!(state.active.admin_view().1, SessionMode::Idle);
        assert_eq!(snapshot(&state).session, "");
    }

    #[test]
    fn resolve_prefers_a_creatable_primary() {
        let base = temp_dir("primary");
        let primary = base.join("zeronat");
        let dir = resolve_control_dir(&primary, None).unwrap();
        assert_eq!(dir, primary);
        assert_eq!(dir_mode(&dir), 0o700);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resolve_falls_back_on_permission_denied() {
        let base = temp_dir("fallback");
        let ro = base.join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let runtime = base.join("runtime");
        std::fs::create_dir(&runtime).unwrap();

        let dir = resolve_control_dir(&ro.join("zeronat"), Some(&runtime)).unwrap();
        assert_eq!(dir, runtime.join("zeronat"));
        assert_eq!(dir_mode(&dir), 0o700);

        // Without a runtime dir the same denial is fatal.
        assert!(resolve_control_dir(&ro.join("zeronat"), None).is_err());

        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resolve_falls_back_on_any_primary_failure() {
        let base = temp_dir("anyfail");
        let blocker = base.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let runtime = base.join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        // Creating under a regular file fails with something other than a
        // permission denial; the fallback still applies.
        let dir = resolve_control_dir(&blocker.join("zeronat"), Some(&runtime)).unwrap();
        assert_eq!(dir, runtime.join("zeronat"));
        assert_eq!(dir_mode(&dir), 0o700);
        std::fs::remove_dir_all(&base).ok();
    }

    /// When the primary directory cannot be created and there is no usable
    /// runtime fallback, the default path yields no socket at all instead of
    /// an error: the client keeps tunneling without an admin socket.
    #[test]
    fn default_path_double_failure_disables_the_socket() {
        let base = temp_dir("degrade");
        let blocker = base.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let primary = blocker.join("zeronat");
        assert!(default_control_in(&primary, None).is_none());
        // A runtime dir that is itself unusable degrades the same way.
        assert!(default_control_in(&primary, Some(&blocker)).is_none());
        std::fs::remove_dir_all(&base).ok();
    }

    /// A non-socket file at the socket path is never deleted: binding it is
    /// fatal for an explicit path and disables the socket for the default
    /// path, and the file survives both.
    #[test]
    fn bind_refuses_to_replace_a_non_socket_file() {
        let base = temp_dir("nonsock");
        let path = base.join(SOCKET_NAME);
        std::fs::write(&path, b"keep").unwrap();

        assert!(ControlListener::bind(path.clone()).is_err());
        assert!(ControlPath::Explicit(path.clone()).bind().is_err());
        assert!(ControlPath::Default(path.clone()).bind().unwrap().is_none());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");

        std::fs::remove_dir_all(&base).ok();
    }

    /// The fallback directory hosts a working listener: bind succeeds and the
    /// socket accepts a connection.
    #[tokio::test]
    async fn fallback_dir_hosts_the_listener() {
        let base = temp_dir("listen");
        let ro = base.join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let runtime = base.join("runtime");
        std::fs::create_dir(&runtime).unwrap();

        let dir = resolve_control_dir(&ro.join("zeronat"), Some(&runtime)).unwrap();
        let listener = ControlListener::bind(dir.join(SOCKET_NAME)).unwrap();
        UnixStream::connect(listener.path()).await.unwrap();

        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(listener);
        std::fs::remove_dir_all(&base).ok();
    }

    /// A stale socket file left by a dead process is unlinked and rebound; the
    /// fresh socket is owner-only, serves a snapshot, and is removed when the
    /// serve task is aborted.
    #[tokio::test]
    async fn stale_socket_is_replaced_and_removed_on_shutdown() {
        let base = temp_dir("stale");
        let path = base.join(SOCKET_NAME);
        // Binding leaves the socket file behind on drop: the stale-path case.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists(), "precondition: stale socket file present");

        let listener = ControlListener::bind(path.clone()).unwrap();
        assert_eq!(dir_mode(&path), 0o600);
        let serve = tokio::spawn(listener.serve(idle_state("home")));

        let stream = UnixStream::connect(&path).await.unwrap();
        let (mut r, mut w) = crate::noise::client_handshake(stream, &admin_psk())
            .await
            .unwrap();
        w.send(
            &ClientMsg::ClientAdminHello {
                version: crate::identity::PROTO_VERSION,
                mode: 0,
            }
            .encode(),
        )
        .await
        .unwrap();
        let frame = r.recv().await.unwrap();
        match ClientMsg::decode(&frame).unwrap() {
            ClientMsg::ClientSnapshot(snap) => {
                assert_eq!(snap.active, "home");
                assert_eq!(snap.mode, SessionMode::Idle);
                assert!(snap.forwards.is_empty());
            }
            other => panic!("expected client snapshot, got {other:?}"),
        }

        serve.abort();
        let _ = serve.await;
        assert!(!path.exists(), "socket file must be removed on shutdown");
        std::fs::remove_dir_all(&base).ok();
    }
}
