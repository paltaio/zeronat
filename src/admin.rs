use crate::proto::{proto_name, Msg, RouteEntry, SnapshotBody, Source};
use crate::Result;
use tokio::net::TcpStream;

/// Where the installer writes the deployment env file. `admin` reads its
/// `ZERONAT_SECRET` as the final fallback when neither `--secret` nor the
/// environment supplies one.
const ENV_FILE: &str = "/etc/zeronat/.env";

/// Best-effort read of the installer env file's shared secret.
pub fn secret_from_env_file() -> Option<String> {
    parse_env_secret(&std::fs::read_to_string(ENV_FILE).ok()?)
}

/// Pull `ZERONAT_SECRET` out of an env-file body (`KEY=VALUE` lines).
fn parse_env_secret(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        line.strip_prefix("ZERONAT_SECRET=")
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

/// Connect to a server's control port, request one snapshot, render it, and exit.
/// Read-only: the admin path never registers as a client or evicts a live one.
pub async fn show(server: String, secret: String) -> Result<()> {
    let psk = crate::noise::derive_psk(&secret);
    let snap = fetch_snapshot(&server, &psk).await?;
    print!("{}", render(&snap, &server));
    Ok(())
}

/// Open a fresh admin connection, request one snapshot, and return it. Each call
/// is a complete connect/handshake/exchange so callers hold no long-lived state.
pub async fn fetch_snapshot(server: &str, psk: &[u8; 32]) -> Result<SnapshotBody> {
    let sock = TcpStream::connect(server).await?;
    sock.set_nodelay(true).ok();
    let (mut r, mut w) = crate::noise::client_handshake(sock, psk).await?;
    w.send(
        &Msg::AdminHello {
            version: crate::identity::PROTO_VERSION,
            mode: 0,
        }
        .encode(),
    )
    .await?;
    let body = r.recv().await?;
    match Msg::decode(&body)? {
        Msg::Snapshot(snap) => Ok(snap),
        other => Err(format!("expected snapshot, got {other:?}").into()),
    }
}

/// Send one mutation (`AddListener`/`RemoveListener`/`SetRoute`/`ClearRoute`) and
/// return the server's `(ok, message)` verdict. Transport errors propagate as
/// `Err`; an applied-but-rejected mutation comes back as `Ok((false, reason))`.
pub async fn mutate(server: &str, psk: &[u8; 32], req: Msg) -> Result<(bool, String)> {
    let sock = TcpStream::connect(server).await?;
    sock.set_nodelay(true).ok();
    let (mut r, mut w) = crate::noise::client_handshake(sock, psk).await?;
    w.send(
        &Msg::AdminHello {
            version: crate::identity::PROTO_VERSION,
            mode: 1,
        }
        .encode(),
    )
    .await?;
    w.send(&req.encode()).await?;
    let body = r.recv().await?;
    match Msg::decode(&body)? {
        Msg::MutationResult { ok, msg } => Ok((ok, msg)),
        other => Err(format!("expected mutation result, got {other:?}").into()),
    }
}

fn route_state(state: u8) -> &'static str {
    match state {
        1 => "target offline",
        _ => "active",
    }
}

fn source_name(source: Source) -> &'static str {
    match source {
        Source::File => "file",
        Source::Cli => "cli",
        Source::Runtime => "runtime",
    }
}

/// Render a snapshot to a human-readable report. Pure (no IO) so it is testable.
fn render(snap: &SnapshotBody, addr: &str) -> String {
    let mut out = String::new();

    out.push_str("Servers\n");
    out.push_str(&format!(
        "  {:<8}  connected  {}  clients {}  bridge {}  routes {}\n",
        snap.server_id,
        addr,
        snap.clients.len(),
        snap.bridge_clients.len(),
        snap.routes.len()
    ));

    out.push_str("\nRoutes\n");
    if snap.routes.is_empty() {
        out.push_str("  (no routes)\n");
    } else {
        out.push_str(&format!(
            "  {:<8}  {:<15}  {:<5}  {:<5}  {:<16}  {:<14}  {:<16}  {}\n",
            "SERVER", "BIND IP", "PROTO", "PORT", "TARGET", "STATE", "OPTIONS", "SOURCE"
        ));
        for route in &snap.routes {
            out.push_str(&format!(
                "  {:<8}  {:<15}  {:<5}  {:<5}  {:<16}  {:<14}  {:<16}  {}\n",
                snap.server_id,
                route.bind_ip,
                proto_name(route.proto),
                route.port,
                route.client_id,
                route_state(route.state),
                route_opts(snap, route),
                source_name(route.source),
            ));
        }
    }

    out.push_str("\nClients\n");
    if snap.clients.is_empty() {
        out.push_str("  (no clients connected)\n");
    } else {
        for c in &snap.clients {
            out.push_str(&format!(
                "  {}  connected to {}\n",
                c.client_id, snap.server_id
            ));
            for e in &c.fwd {
                out.push_str(&format!(
                    "    {}:{}  {}\n",
                    proto_name(e.proto),
                    e.port,
                    fwd_opts(e.proxy, e.idle_secs),
                ));
            }
        }
    }

    out.push_str("\nBridge clients\n");
    if snap.bridge_clients.is_empty() {
        out.push_str("  (no bridge clients)\n");
    } else {
        out.push_str(&format!(
            "  {:<20}  {:<5}  {:<21}  {:<4}  {:<18}  {:<18}  {:<8}  {}\n",
            "NAME", "TRANS", "PEER", "MACS", "RX", "TX", "UPTIME", "IDLE"
        ));
        for e in &snap.bridge_clients {
            let label = if e.named {
                strip_ctrl(&e.label)
            } else {
                format!("{} (anon)", strip_ctrl(&e.label))
            };
            let peer = if e.peer.is_empty() {
                "-".to_string()
            } else {
                strip_ctrl(&e.peer)
            };
            let rx = format!("{} / {}", human_bytes(e.rx_bytes), human_count(e.rx_frames));
            let tx = format!("{} / {}", human_bytes(e.tx_bytes), human_count(e.tx_frames));
            out.push_str(&format!(
                "  {:<20}  {:<5}  {:<21}  {:<4}  {:<18}  {:<18}  {:<8}  {}\n",
                label,
                transport_name(e.transport),
                peer,
                e.macs.len(),
                rx,
                tx,
                fmt_dur(e.uptime_secs),
                fmt_dur(e.idle_secs),
            ));
        }
    }

    out.push_str("\nListeners\n");
    if snap.listeners.is_empty() {
        out.push_str("  (none)\n");
    } else {
        out.push_str(&format!(
            "  {:<5}  {:<15}  {:<5}  {}\n",
            "PROTO", "BIND IP", "PORT", "SOURCE"
        ));
        for l in &snap.listeners {
            out.push_str(&format!(
                "  {:<5}  {:<15}  {:<5}  {}\n",
                proto_name(l.proto),
                l.bind_ip,
                l.port,
                source_name(l.source),
            ));
        }
    }

    out
}

/// Transport label for a `BridgeEntry.transport` byte (1 = tcp, 2 = udp).
pub(crate) fn transport_name(t: u8) -> &'static str {
    match t {
        1 => "tcp",
        2 => "udp",
        _ => "?",
    }
}

/// Drop control characters from server-reported text before printing it, so a
/// crafted label or address cannot inject terminal escape sequences.
fn strip_ctrl(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Human-readable byte count for the fleet view, e.g. "1.5 MB".
pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

/// Compact 1000-based frame count for the fleet view, e.g. "900", "1.2k", "24.0k".
pub(crate) fn human_count(n: u64) -> String {
    const UNITS: [&str; 4] = ["", "k", "M", "B"];
    if n < 1000 {
        return format!("{n}");
    }
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    format!("{v:.1}{}", UNITS[unit])
}

/// The announced options for a route's forward, joined from the routed
/// client's snapshot entry; "-" when the client is offline or the forward
/// runs on defaults.
pub(crate) fn route_opts(snap: &SnapshotBody, r: &RouteEntry) -> String {
    snap.clients
        .iter()
        .find(|c| c.client_id == r.client_id)
        .and_then(|c| {
            c.fwd
                .iter()
                .find(|e| e.proto == r.proto && e.port == r.port)
        })
        .map(|e| fwd_opts(e.proxy, e.idle_secs))
        .unwrap_or_else(|| "-".into())
}

/// A forward's client-announced options in the CLI's spec-modifier syntax,
/// e.g. "+proxy+idle=600"; "-" when the forward runs on defaults.
pub(crate) fn fwd_opts(proxy: bool, idle_secs: u32) -> String {
    let mut s = String::new();
    if proxy {
        s.push_str("+proxy");
    }
    if idle_secs > 0 {
        s.push_str(&format!("+idle={idle_secs}"));
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

/// Compact duration for the fleet view, e.g. "45s", "4m12s", "1h03m".
pub(crate) fn fmt_dur(secs: u32) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = secs / 3600;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{BridgeEntry, ClientEntry, FwdOptionEntry, Listener, Proto, Source};
    use std::net::Ipv4Addr;

    #[test]
    fn render_single_client() {
        let snap = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: vec![
                Listener {
                    bind_ip: Ipv4Addr::LOCALHOST,
                    proto: Proto::Tcp,
                    port: 443,
                    source: Source::File,
                },
                Listener {
                    bind_ip: Ipv4Addr::LOCALHOST,
                    proto: Proto::Udp,
                    port: 51820,
                    source: Source::Cli,
                },
            ],
            clients: vec![ClientEntry {
                client_id: "rpi-2-ab12".into(),
                transport: 1,
                fwd: vec![FwdOptionEntry {
                    proto: Proto::Tcp,
                    port: 443,
                    proxy: true,
                    idle_secs: 600,
                }],
            }],
            routes: vec![RouteEntry {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: 443,
                client_id: "rpi-2-ab12".into(),
                state: 0,
                source: Source::Runtime,
            }],
            bridge_clients: Vec::new(),
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("Servers"));
        assert!(s.contains("clients 1"));
        assert!(s.contains("routes 1"));
        assert!(s.contains("active"));
        assert!(s.contains("rpi-2-ab12"));
        assert!(s.contains("tcp"));
        assert!(s.contains("443"));
        assert!(s.contains("udp"));
        assert!(s.contains("51820"));
        assert!(s.contains("127.0.0.1"));
        assert!(s.contains("rpi-2-ab12  connected to 0"));
        // SOURCE column: the file listener, cli listener, and runtime route.
        assert!(s.contains("SOURCE"));
        assert!(s.contains("file"));
        assert!(s.contains("cli"));
        assert!(s.contains("runtime"));
        // OPTIONS column: the route joins the client's announced options, and
        // the client lists its optioned forwards.
        assert!(s.contains("OPTIONS"));
        assert!(s.contains("+proxy+idle=600"));
        assert!(s.contains("tcp:443  +proxy+idle=600"));
    }

    #[test]
    fn fwd_opts_renders_each_combination() {
        assert_eq!(fwd_opts(false, 0), "-");
        assert_eq!(fwd_opts(true, 0), "+proxy");
        assert_eq!(fwd_opts(false, 300), "+idle=300");
        assert_eq!(fwd_opts(true, 600), "+proxy+idle=600");
    }

    #[test]
    fn render_no_client() {
        let snap = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
            bridge_clients: Vec::new(),
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("clients 0"));
        assert!(s.contains("routes 0"));
        assert!(s.contains("(no clients connected)"));
        assert!(s.contains("(no bridge clients)"));
        assert!(s.contains("(no routes)"));
        assert!(s.contains("(none)"));
    }

    #[test]
    fn render_bridge_clients() {
        let snap = SnapshotBody {
            version: 2,
            server_id: "0".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
            bridge_clients: vec![
                BridgeEntry {
                    label: "rpi-3-ef56".into(),
                    named: true,
                    transport: 1,
                    peer: "203.0.113.5:51820".into(),
                    macs: vec![[0x02, 0, 0, 0, 0, 1]],
                    rx_bytes: 1_572_864,
                    rx_frames: 1200,
                    tx_bytes: 524_288,
                    tx_frames: 900,
                    uptime_secs: 252,
                    idle_secs: 0,
                },
                BridgeEntry {
                    label: "bridge-7".into(),
                    named: false,
                    transport: 2,
                    peer: String::new(),
                    macs: Vec::new(),
                    rx_bytes: 0,
                    rx_frames: 0,
                    tx_bytes: 0,
                    tx_frames: 0,
                    uptime_secs: 2,
                    idle_secs: 2,
                },
            ],
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("bridge 2"));
        assert!(s.contains("Bridge clients"));
        assert!(s.contains("rpi-3-ef56"));
        assert!(s.contains("tcp"));
        assert!(s.contains("203.0.113.5:51820"));
        assert!(s.contains("1.5 MB / 1.2k"));
        assert!(s.contains("900"));
        assert!(s.contains("4m12s"));
        // The anonymous udp port shows its fallback label and the anon marker.
        assert!(s.contains("bridge-7 (anon)"));
        assert!(s.contains("udp"));
    }

    #[test]
    fn human_count_scales() {
        assert_eq!(human_count(0), "0");
        assert_eq!(human_count(900), "900");
        assert_eq!(human_count(1200), "1.2k");
        assert_eq!(human_count(24010), "24.0k");
    }

    #[test]
    fn parse_env_secret_reads_the_value() {
        let body = "ZERONAT_SECRET=deadbeef\nZERONAT_ARGS=server --control 2222\n";
        assert_eq!(parse_env_secret(body).as_deref(), Some("deadbeef"));
        // Missing or empty value yields nothing.
        assert_eq!(parse_env_secret("ZERONAT_ARGS=server\n"), None);
        assert_eq!(parse_env_secret("ZERONAT_SECRET=\n"), None);
    }
}
