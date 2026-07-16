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

use crate::client::{ActiveTarget, PppoeRunConfig, RunMode, ServerTarget, SharedForwards};
use crate::clientcfg::{serialize_client, ClientConfig};
use crate::clientproto::{ClientMsg, ClientSnapshotBody, PppStatus};
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
    /// Profiles `SelectServer` may switch to.
    pub servers: Vec<ServerTarget>,
    /// Sessions `SpawnPppoe` may bring up, by name.
    pub pppoe: Vec<(String, Arc<PppoeRunConfig>)>,
    /// The body `StopSession` falls back to: forwards when any are declared,
    /// idle otherwise.
    pub base_mode: RunMode,
    /// `None` on a runtime-only client; mutations then stay in memory.
    pub persist: Option<Persist>,
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
    let (active, mode) = state.active.admin_view();
    ClientSnapshotBody {
        version: crate::identity::PROTO_VERSION,
        active,
        mode,
        phase: state.ppp.get(),
        forwards: state.forwards.entries(),
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
            let Some(target) = state.servers.iter().find(|s| s.name == name) else {
                return (false, format!("no configured server named `{name}`"));
            };
            // One call updates the target and fires the cancel; the session
            // body is preserved and comes back up against the new server.
            state.active.switch(target.clone());
            persist(state, move |cfg| cfg.active = Some(name)).await
        }
        ClientMsg::SetForwardOptions {
            proto,
            port,
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
            if !state.forwards.set_options(proto, port, proxy, idle) {
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
            // loop falls back to the boot-derived base mode.
            if state.active.stop_pppoe(&name, state.base_mode.clone()) {
                (true, String::new())
            } else {
                (false, format!("no active pppoe session named `{name}`"))
            }
        }
        other => (false, format!("expected a mutation, got {other:?}")),
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
    use crate::clientproto::{PppPhase, SessionMode};
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
            servers: Vec::new(),
            pppoe: Vec::new(),
            base_mode: RunMode::Idle,
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
        }
    }

    /// The snapshot reports whatever the datapath last wrote into the cell.
    #[test]
    fn snapshot_reports_the_live_ppp_phase() {
        let state = idle_state("home");
        assert_eq!(snapshot(&state).phase, PppPhase::None);
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
        state.servers = vec![server_target("a", 1), server_target("b", 2)];
        state.persist = Some(Persist::new(path.clone(), cfg));

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
                proxy: true,
                idle_secs: 600,
            },
        )
        .await;
        assert!(ok, "{msg}");
        let snap = snapshot(&state);
        assert!(snap.forwards[0].proxy);
        assert_eq!(snap.forwards[0].idle_secs, 600);
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert!(on_disk.forwards[0].proxy);
        assert_eq!(on_disk.forwards[0].idle, Some(600));

        // Wire idle 0 clears the override; the file never carries idle = 0,
        // which the parser would reject.
        let (ok, msg) = mutate(
            &state,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: 443,
                proxy: true,
                idle_secs: 0,
            },
        )
        .await;
        assert!(ok, "{msg}");
        assert_eq!(snapshot(&state).forwards[0].idle_secs, 0);
        let on_disk = crate::clientcfg::load(&path).unwrap();
        on_disk.validate().unwrap();
        assert_eq!(on_disk.forwards[0].idle, None);

        std::fs::remove_dir_all(&dir).ok();
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
