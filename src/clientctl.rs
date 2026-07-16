//! Local admin socket hosted by a running client.
//!
//! The client listens on a Unix domain socket at `[client].control` (default
//! `/run/zeronat/client.sock`). Each accepted connection runs the Noise
//! handshake under the fixed local-admin PSK, performs one request/response in
//! the [`crate::clientproto`] namespace, and closes. The socket file is 0600
//! inside a 0700 directory: filesystem permissions are the access control; the
//! handshake supplies framing and channel integrity, not admission.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};

use crate::client::ActiveTarget;
use crate::clientproto::{
    ClientForwardEntry, ClientMsg, ClientSnapshotBody, PppPhase, SessionMode,
};
use crate::Result;

/// Directory hosting the default socket when the client can create it.
const PRIMARY_DIR: &str = "/run/zeronat";
const SOCKET_NAME: &str = "client.sock";
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
    let dir = base.join("zeronat");
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

/// The client-runtime state the accept loop answers snapshots from.
pub struct ControlState {
    /// Shared active target. Read for the profile name only, never waited on:
    /// its cancel `Notify` has a sole-waiter contract with the reconnect loop.
    pub active: ActiveTarget,
    pub mode: SessionMode,
    pub forwards: Vec<ClientForwardEntry>,
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
            let msg = match ClientMsg::decode(&frame)? {
                ClientMsg::SelectServer { .. }
                | ClientMsg::SetForwardOptions { .. }
                | ClientMsg::SpawnPppoe { .. }
                | ClientMsg::StopSession { .. } => "not implemented".to_string(),
                other => format!("expected a mutation, got {other:?}"),
            };
            w.send(&ClientMsg::MutationResult { ok: false, msg }.encode())
                .await?;
        }
        n => return Err(format!("unknown admin hello mode {n}").into()),
    }
    Ok(())
}

fn snapshot(state: &ControlState) -> ClientSnapshotBody {
    ClientSnapshotBody {
        version: crate::identity::PROTO_VERSION,
        active: state.active.active_name(),
        mode: state.mode,
        phase: PppPhase::None,
        forwards: state.forwards.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ServerTarget, Transport};
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

    fn idle_state(name: &str) -> ControlState {
        ControlState {
            active: ActiveTarget::new(ServerTarget {
                name: name.into(),
                addr: "127.0.0.1:1".into(),
                secret: "s".into(),
                transport: Transport::Tcp,
            }),
            mode: SessionMode::Idle,
            forwards: Vec::new(),
        }
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
