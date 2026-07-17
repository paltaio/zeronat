//! Admin-side counterpart of [`crate::clientctl`]: drive a running client
//! over its control socket.
//!
//! Each call is a complete connect/handshake/exchange over the Unix stream:
//! hello mode 0 fetches one snapshot, mode 1 carries one mutation and returns
//! the client's verdict. The CLI commands wrap those exchanges; a mutation
//! command returns as soon as the client accepts it, never waiting on the
//! teardown or bringup it triggers.

use std::path::{Path, PathBuf};

use crate::client::{Forward, Transport};
use crate::clientproto::{
    ClientMsg, ClientSnapshotBody, LinkStatus, PppPhase, ServerSecret, SessionMode,
};
use crate::proto::{proto_name, Proto};
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
async fn handshake(path: &Path) -> Result<crate::noise::Noise> {
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
    let (mut r, mut w) = handshake(path).await?;
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
    let (mut r, mut w) = handshake(path).await?;
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

/// `select-server NAME`: switch the active server profile.
pub async fn select_server(socket: Option<&Path>, name: String) -> Result<()> {
    command(socket, ClientMsg::SelectServer { name }).await
}

/// `spawn-pppoe NAME`: bring up the named PPPoE session.
pub async fn spawn_pppoe(socket: Option<&Path>, name: String) -> Result<()> {
    command(socket, ClientMsg::SpawnPppoe { name }).await
}

/// `stop-pppoe NAME`: stop the named PPPoE session and fall back to
/// the client's base mode.
pub async fn stop_pppoe(socket: Option<&Path>, name: String) -> Result<()> {
    command(socket, ClientMsg::StopSession { name }).await
}

/// `add-server NAME ADDR [--transport MODE]`: append a server profile. The
/// secret comes from stdin, never from argv, which leaks through the process
/// list.
pub async fn add_server(
    socket: Option<&Path>,
    name: String,
    addr: String,
    transport: Transport,
) -> Result<()> {
    let secret = ServerSecret(read_secret()?);
    command(
        socket,
        ClientMsg::AddServer {
            name,
            addr,
            secret,
            transport,
        },
    )
    .await
}

/// `remove-server NAME`: remove a server profile. The active profile is
/// refused; select another or disconnect first.
pub async fn remove_server(socket: Option<&Path>, name: String) -> Result<()> {
    command(socket, ClientMsg::RemoveServer { name }).await
}

/// `enable-forward PROTO:PORT` / `disable-forward PROTO:PORT`: flip one
/// forward's `enabled` flag. `SetForwardOptions` is full-state, so a snapshot
/// supplies the forward's current `proxy`/`idle` and only the flag changes.
pub async fn set_forward_enabled(socket: Option<&Path>, spec: &str, enabled: bool) -> Result<()> {
    let (proto, port) = parse_proto_port(spec)?;
    let path = resolve_socket(socket)?;
    let snap = snapshot(&path).await?;
    let f = snap
        .forwards
        .iter()
        .find(|f| f.proto == proto && f.port == port)
        .ok_or_else(|| -> crate::Error {
            format!("no {} forward on port {port}", proto_name(proto)).into()
        })?;
    let req = ClientMsg::SetForwardOptions {
        proto,
        port,
        enabled,
        proxy: f.proxy,
        idle_secs: f.idle_secs,
    };
    let (ok, msg) = mutate(&path, req).await?;
    if ok {
        println!("ok");
        Ok(())
    } else {
        Err(msg.into())
    }
}

/// `add-forward PROTO:SPEC`: append one forward. The caller parses the spec
/// (the `--tcp`/`--udp` grammar) into a forward with a resolved target, so
/// the daemon never sees an empty one.
pub async fn add_forward(socket: Option<&Path>, proto: Proto, fwd: Forward) -> Result<()> {
    command(
        socket,
        ClientMsg::AddForward {
            proto,
            port: fwd.port,
            target: fwd.target,
            proxy: fwd.proxy,
            idle_secs: fwd.idle.map(|d| d.as_secs() as u32).unwrap_or(0),
            enabled: fwd.enabled,
        },
    )
    .await
}

/// `remove-forward PROTO:PORT`: remove one forward. Removing a live
/// forward's port drops its open connections on the redial.
pub async fn remove_forward(socket: Option<&Path>, spec: &str) -> Result<()> {
    let (proto, port) = parse_proto_port(spec)?;
    command(socket, ClientMsg::RemoveForward { proto, port }).await
}

/// `connect [NAME]`: leave the offline park and bring up the boot-derived
/// session body, retargeting first when named. Reports the mode a follow-up
/// snapshot shows, so a connect on an idle-boot client truthfully answers
/// `idle`.
pub async fn connect(socket: Option<&Path>, name: Option<String>) -> Result<()> {
    let path = resolve_socket(socket)?;
    let req = ClientMsg::Connect {
        name: name.unwrap_or_default(),
    };
    let (ok, msg) = mutate(&path, req).await?;
    if !ok {
        return Err(msg.into());
    }
    let snap = snapshot(&path).await?;
    println!("mode {}", mode_name(snap.mode));
    Ok(())
}

/// `disconnect`: tear the session body down and park offline; nothing is
/// dialed until `connect`.
pub async fn disconnect(socket: Option<&Path>) -> Result<()> {
    command(socket, ClientMsg::Disconnect).await
}

/// Send one mutation and report the verdict: `ok` on stdout when the client
/// accepts, its refusal message as the error otherwise.
async fn command(socket: Option<&Path>, req: ClientMsg) -> Result<()> {
    let path = resolve_socket(socket)?;
    let (ok, msg) = mutate(&path, req).await?;
    if ok {
        println!("ok");
        Ok(())
    } else {
        Err(msg.into())
    }
}

/// A `PROTO:PORT` forward key, e.g. `tcp:443`.
fn parse_proto_port(spec: &str) -> Result<(Proto, u16)> {
    let (proto, port) = spec
        .split_once(':')
        .ok_or_else(|| -> crate::Error { format!("expected PROTO:PORT, got `{spec}`").into() })?;
    let proto = match proto {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => return Err(format!("proto must be tcp or udp, got `{other}`").into()),
    };
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| -> crate::Error { format!("invalid port `{port}`").into() })?;
    Ok((proto, port))
}

/// Read the secret from stdin: prompted with echo off on a terminal, read
/// plainly when piped. One line, without the trailing newline.
fn read_secret() -> Result<String> {
    use std::io::BufRead;
    let tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    if tty {
        eprint!("secret: ");
    }
    let mut line = String::new();
    {
        let _echo_off = if tty { Some(EchoOff::set()?) } else { None };
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| -> crate::Error {
                format!("reading the secret from stdin: {e}").into()
            })?;
    }
    if tty {
        eprintln!();
    }
    let secret = line.trim_end_matches(['\r', '\n']).to_string();
    if secret.is_empty() {
        return Err("the secret on stdin is empty".into());
    }
    Ok(secret)
}

/// Echo-off guard for the secret prompt: clears ECHO but keeps canonical mode,
/// so the read still ends at newline; `Drop` restores the saved settings.
struct EchoOff(libc::termios);

impl EchoOff {
    fn set() -> Result<EchoOff> {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut t) != 0 {
                return Err(format!(
                    "reading terminal settings: {}",
                    std::io::Error::last_os_error()
                )
                .into());
            }
            let saved = t;
            t.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) != 0 {
                return Err(format!(
                    "disabling terminal echo: {}",
                    std::io::Error::last_os_error()
                )
                .into());
            }
            Ok(EchoOff(saved))
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
        }
    }
}

fn mode_name(mode: SessionMode) -> &'static str {
    match mode {
        SessionMode::Idle => "idle",
        SessionMode::Forwards => "forwards",
        SessionMode::Device => "device",
        SessionMode::Pppoe => "pppoe",
        SessionMode::Offline => "offline",
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

fn link_name(link: LinkStatus) -> &'static str {
    match link {
        LinkStatus::Offline => "offline",
        LinkStatus::Dialing => "dialing",
        LinkStatus::Connected => "connected",
        LinkStatus::Backoff => "backoff",
    }
}

/// Render a client snapshot to a human-readable report. The PPP phase appears
/// only under a pppoe body, where it means something.
pub fn render(snap: &ClientSnapshotBody) -> String {
    let mut out = String::new();

    out.push_str("Client\n");
    out.push_str(&format!("  active  {}\n", snap.active));
    out.push_str(&format!("  mode    {}\n", mode_name(snap.mode)));
    out.push_str(&format!("  link    {}\n", link_name(snap.link)));
    if snap.mode == SessionMode::Pppoe {
        out.push_str(&format!("  phase   {}\n", phase_name(snap.phase)));
    }

    out.push_str("\nForwards\n");
    if snap.forwards.is_empty() {
        out.push_str("  (no forwards)\n");
    } else {
        for f in &snap.forwards {
            out.push_str(&format!(
                "  {}:{} -> {}  {}{}\n",
                proto_name(f.proto),
                f.port,
                f.target,
                crate::admin::fwd_opts(f.proxy, f.idle_secs),
                if f.enabled { "" } else { "  off" },
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clientproto::{ClientForwardEntry, LinkStatus};
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
            enabled: true,
        }
    }

    #[test]
    fn render_lists_forwards_with_their_options() {
        let mut disabled = entry(Proto::Udp, 51820, "10.0.0.5:51820", false, 300);
        disabled.enabled = false;
        let snap = ClientSnapshotBody {
            version: 1,
            active: "home".into(),
            mode: SessionMode::Forwards,
            phase: PppPhase::None,
            forwards: vec![
                entry(Proto::Tcp, 8080, "127.0.0.1:80", true, 600),
                disabled,
                entry(Proto::Tcp, 443, "127.0.0.1:8443", false, 0),
            ],
            servers: Vec::new(),
            pppoe: Vec::new(),
            session: String::new(),
            link: LinkStatus::Connected,
        };
        let s = render(&snap);
        assert!(s.contains("active  home"));
        assert!(s.contains("mode    forwards"));
        assert!(s.contains("link    connected"));
        assert!(s.contains("tcp:8080 -> 127.0.0.1:80  +proxy+idle=600\n"));
        // A disabled forward stays listed, flagged.
        assert!(s.contains("udp:51820 -> 10.0.0.5:51820  +idle=300  off\n"));
        assert!(s.contains("tcp:443 -> 127.0.0.1:8443  -\n"));
        // No pppoe body, no phase line.
        assert!(!s.contains("phase"));
    }

    #[test]
    fn render_names_the_offline_link() {
        let snap = ClientSnapshotBody {
            version: 1,
            active: "home".into(),
            mode: SessionMode::Offline,
            phase: PppPhase::None,
            forwards: Vec::new(),
            servers: Vec::new(),
            pppoe: Vec::new(),
            session: String::new(),
            link: LinkStatus::Offline,
        };
        let s = render(&snap);
        assert!(s.contains("mode    offline"));
        assert!(s.contains("link    offline"));
    }

    #[test]
    fn proto_port_specs_parse_or_name_the_fault() {
        assert_eq!(parse_proto_port("tcp:443").unwrap(), (Proto::Tcp, 443));
        assert_eq!(parse_proto_port("udp:53").unwrap(), (Proto::Udp, 53));
        for bad in ["443", "tcp", "icmp:1", "tcp:0", "tcp:70000", "tcp:x"] {
            assert!(parse_proto_port(bad).is_err(), "{bad} should not parse");
        }
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
            link: LinkStatus::Connected,
        };
        let s = render(&snap);
        assert!(s.contains("mode    pppoe"));
        assert!(s.contains("phase   established"));
        assert!(s.contains("(no forwards)"));
    }
}
