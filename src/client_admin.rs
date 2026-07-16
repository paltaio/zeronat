//! Admin-side counterpart of [`crate::clientctl`]: drive a running client
//! over its control socket.
//!
//! Each call is a complete connect/handshake/exchange over the Unix stream:
//! hello mode 0 fetches one snapshot, mode 1 carries one mutation and returns
//! the client's verdict. The one-shots (`show`, `select_server`, `spawn_pppoe`,
//! `stop_pppoe`) wrap those exchanges for the CLI; a mutation one-shot returns
//! as soon as the client accepts it, never waiting on the teardown or bringup
//! it triggers.

use std::path::{Path, PathBuf};

use crate::clientproto::{ClientMsg, ClientSnapshotBody, PppPhase, SessionMode};
use crate::proto::proto_name;
use crate::Result;

/// The control socket to talk to: an explicit path is used as given; otherwise
/// the default resolves to the same locations a client binds, in the same
/// order (`/run/zeronat/client.sock`, then `$XDG_RUNTIME_DIR/zeronat/`). The
/// admin side never creates directories: it connects to what exists, and a
/// default that resolves to nothing means no client is running with an admin
/// socket.
pub fn resolve_socket(explicit: Option<&Path>) -> Result<PathBuf> {
    match explicit {
        Some(path) => Ok(path.to_path_buf()),
        None => {
            let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
            default_socket(Path::new(crate::clientctl::PRIMARY_DIR), runtime.as_deref())
        }
    }
}

fn default_socket(primary: &Path, runtime_dir: Option<&Path>) -> Result<PathBuf> {
    let primary = primary.join(crate::clientctl::SOCKET_NAME);
    if primary.exists() {
        return Ok(primary);
    }
    let fallback = runtime_dir.map(|base| {
        base.join(crate::clientctl::RUNTIME_SUBDIR)
            .join(crate::clientctl::SOCKET_NAME)
    });
    if let Some(path) = &fallback {
        if path.exists() {
            return Ok(path.clone());
        }
    }
    let tried = match &fallback {
        Some(path) => format!("{} or {}", primary.display(), path.display()),
        None => format!("{} (XDG_RUNTIME_DIR is unset)", primary.display()),
    };
    Err(format!("no admin socket at {tried}: the client is not running or has none").into())
}

/// Connect to the control socket at `path` and run the admin handshake.
pub async fn connect(path: &Path) -> Result<crate::noise::Noise> {
    let stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| -> crate::Error {
            format!("connecting to admin socket {}: {e}", path.display()).into()
        })?;
    crate::noise::client_handshake(stream, &crate::clientctl::admin_psk()).await
}

/// Request one snapshot and return it. A complete connect/handshake/exchange,
/// so callers hold no long-lived state.
pub async fn snapshot(path: &Path) -> Result<ClientSnapshotBody> {
    let (mut r, mut w) = connect(path).await?;
    w.send(&hello(0)).await?;
    let frame = r.recv().await?;
    match ClientMsg::decode(&frame)? {
        ClientMsg::ClientSnapshot(snap) => Ok(snap),
        other => Err(format!("expected client snapshot, got {other:?}").into()),
    }
}

/// Send one mutation (`SelectServer`/`SetForwardOptions`/`SpawnPppoe`/
/// `StopSession`) and return the client's `(ok, message)` verdict. Transport
/// errors propagate as `Err`; a refused mutation comes back as
/// `Ok((false, reason))`.
pub async fn mutate(path: &Path, req: ClientMsg) -> Result<(bool, String)> {
    let (mut r, mut w) = connect(path).await?;
    w.send(&hello(1)).await?;
    w.send(&req.encode()).await?;
    let frame = r.recv().await?;
    match ClientMsg::decode(&frame)? {
        ClientMsg::MutationResult { ok, msg } => Ok((ok, msg)),
        other => Err(format!("expected mutation result, got {other:?}").into()),
    }
}

fn hello(mode: u8) -> Vec<u8> {
    ClientMsg::ClientAdminHello {
        version: crate::identity::PROTO_VERSION,
        mode,
    }
    .encode()
}

/// Fetch the running client's snapshot, render it, and exit.
pub async fn show(socket: Option<&Path>) -> Result<()> {
    let path = resolve_socket(socket)?;
    let snap = snapshot(&path).await?;
    print!("{}", render(&snap));
    Ok(())
}

/// One-shot `select-server NAME`: switch the active server profile.
pub async fn select_server(socket: Option<&Path>, name: String) -> Result<()> {
    one_shot(socket, ClientMsg::SelectServer { name }).await
}

/// One-shot `spawn-pppoe NAME`: bring up the named PPPoE session.
pub async fn spawn_pppoe(socket: Option<&Path>, name: String) -> Result<()> {
    one_shot(socket, ClientMsg::SpawnPppoe { name }).await
}

/// One-shot `stop-pppoe NAME`: stop the named PPPoE session and fall back to
/// the client's base mode.
pub async fn stop_pppoe(socket: Option<&Path>, name: String) -> Result<()> {
    one_shot(socket, ClientMsg::StopSession { name }).await
}

/// Send one mutation and report the verdict: `ok` on stdout when the client
/// accepts, its refusal message as the error otherwise.
async fn one_shot(socket: Option<&Path>, req: ClientMsg) -> Result<()> {
    let path = resolve_socket(socket)?;
    let (ok, msg) = mutate(&path, req).await?;
    if ok {
        println!("ok");
        Ok(())
    } else {
        Err(msg.into())
    }
}

fn mode_name(mode: SessionMode) -> &'static str {
    match mode {
        SessionMode::Idle => "idle",
        SessionMode::Forwards => "forwards",
        SessionMode::Device => "device",
        SessionMode::Pppoe => "pppoe",
    }
}

fn phase_name(phase: PppPhase) -> &'static str {
    match phase {
        PppPhase::None => "-",
        PppPhase::Discovery => "discovery",
        PppPhase::Negotiating => "negotiating",
        PppPhase::Established => "established",
        PppPhase::LinkDown => "link down",
        PppPhase::Dead => "dead",
    }
}

/// Render a client snapshot to a human-readable report. Pure (no IO) so it is
/// testable. The PPP phase appears only under a pppoe body, where it means
/// something.
pub fn render(snap: &ClientSnapshotBody) -> String {
    let mut out = String::new();

    out.push_str("Client\n");
    out.push_str(&format!("  active  {}\n", snap.active));
    out.push_str(&format!("  mode    {}\n", mode_name(snap.mode)));
    if snap.mode == SessionMode::Pppoe {
        out.push_str(&format!("  phase   {}\n", phase_name(snap.phase)));
    }

    out.push_str("\nForwards\n");
    if snap.forwards.is_empty() {
        out.push_str("  (no forwards)\n");
    } else {
        for f in &snap.forwards {
            out.push_str(&format!(
                "  {}:{} -> {}  {}\n",
                proto_name(f.proto),
                f.port,
                f.target,
                crate::admin::fwd_opts(f.proxy, f.idle_secs),
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clientproto::ClientForwardEntry;
    use crate::proto::Proto;

    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zeronat-clientadmin-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn explicit_socket_path_wins() {
        // As given, even when nothing exists there: the connect error names it.
        let path = Path::new("/nonexistent/client.sock");
        assert_eq!(resolve_socket(Some(path)).unwrap(), path);
    }

    #[test]
    fn default_prefers_an_existing_primary() {
        let base = temp_dir("primary");
        let primary = base.join("run");
        std::fs::create_dir(&primary).unwrap();
        std::fs::write(primary.join(crate::clientctl::SOCKET_NAME), b"").unwrap();
        let runtime = base.join("runtime");
        std::fs::create_dir_all(runtime.join("zeronat")).unwrap();
        std::fs::write(
            runtime.join("zeronat").join(crate::clientctl::SOCKET_NAME),
            b"",
        )
        .unwrap();

        // Both exist: the primary wins, mirroring the client's bind order.
        let found = default_socket(&primary, Some(&runtime)).unwrap();
        assert_eq!(found, primary.join(crate::clientctl::SOCKET_NAME));

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn default_falls_back_to_the_runtime_dir() {
        let base = temp_dir("fallback");
        let primary = base.join("run");
        let runtime = base.join("runtime");
        std::fs::create_dir_all(runtime.join("zeronat")).unwrap();
        let sock = runtime.join("zeronat").join(crate::clientctl::SOCKET_NAME);
        std::fs::write(&sock, b"").unwrap();

        assert_eq!(default_socket(&primary, Some(&runtime)).unwrap(), sock);

        std::fs::remove_dir_all(&base).ok();
    }

    /// Resolution never creates anything: a missing socket is an error naming
    /// every location tried, and the filesystem is left untouched.
    #[test]
    fn default_with_no_socket_errors_and_creates_nothing() {
        let base = temp_dir("nosock");
        let primary = base.join("run");
        let runtime = base.join("runtime");
        std::fs::create_dir(&runtime).unwrap();

        let err = default_socket(&primary, Some(&runtime)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("run/client.sock"), "{text}");
        assert!(text.contains("zeronat/client.sock"), "{text}");
        assert!(!primary.exists(), "resolution must not create the primary");
        assert!(
            !runtime.join("zeronat").exists(),
            "resolution must not create the fallback"
        );

        let err = default_socket(&primary, None).unwrap_err();
        assert!(err.to_string().contains("XDG_RUNTIME_DIR is unset"));

        std::fs::remove_dir_all(&base).ok();
    }

    fn entry(
        proto: Proto,
        port: u16,
        target: &str,
        proxy: bool,
        idle_secs: u32,
    ) -> ClientForwardEntry {
        ClientForwardEntry {
            proto,
            port,
            target: target.into(),
            proxy,
            idle_secs,
        }
    }

    #[test]
    fn render_lists_forwards_with_their_options() {
        let snap = ClientSnapshotBody {
            version: 1,
            active: "home".into(),
            mode: SessionMode::Forwards,
            phase: PppPhase::None,
            forwards: vec![
                entry(Proto::Tcp, 8080, "127.0.0.1:80", true, 600),
                entry(Proto::Udp, 51820, "10.0.0.5:51820", false, 300),
                entry(Proto::Tcp, 443, "127.0.0.1:8443", false, 0),
            ],
            servers: Vec::new(),
            pppoe: Vec::new(),
            session: String::new(),
        };
        let s = render(&snap);
        assert!(s.contains("active  home"));
        assert!(s.contains("mode    forwards"));
        assert!(s.contains("tcp:8080 -> 127.0.0.1:80  +proxy+idle=600"));
        assert!(s.contains("udp:51820 -> 10.0.0.5:51820  +idle=300"));
        assert!(s.contains("tcp:443 -> 127.0.0.1:8443  -"));
        // No pppoe body, no phase line.
        assert!(!s.contains("phase"));
    }

    #[test]
    fn render_shows_the_phase_only_under_a_pppoe_body() {
        let snap = ClientSnapshotBody {
            version: 1,
            active: "home".into(),
            mode: SessionMode::Pppoe,
            phase: PppPhase::Established,
            forwards: Vec::new(),
            servers: Vec::new(),
            pppoe: Vec::new(),
            session: "wan".into(),
        };
        let s = render(&snap);
        assert!(s.contains("mode    pppoe"));
        assert!(s.contains("phase   established"));
        assert!(s.contains("(no forwards)"));
    }
}
