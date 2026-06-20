use crate::proto::{proto_name, Msg, SnapshotBody, Source};
use crate::Result;
use tokio::net::TcpStream;

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
        "  {:<8}  connected  {}  clients {}  routes {}\n",
        snap.server_id,
        addr,
        snap.clients.len(),
        snap.routes.len()
    ));

    out.push_str("\nRoutes\n");
    if snap.routes.is_empty() {
        out.push_str("  (no routes)\n");
    } else {
        out.push_str(&format!(
            "  {:<8}  {:<15}  {:<5}  {:<5}  {:<16}  {:<14}  {}\n",
            "SERVER", "BIND IP", "PROTO", "PORT", "TARGET", "STATE", "SOURCE"
        ));
        for route in &snap.routes {
            out.push_str(&format!(
                "  {:<8}  {:<15}  {:<5}  {:<5}  {:<16}  {:<14}  {}\n",
                snap.server_id,
                route.bind_ip,
                proto_name(route.proto),
                route.port,
                route.client_id,
                route_state(route.state),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ClientEntry, Listener, Proto, RouteEntry, Source};
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
            }],
            routes: vec![RouteEntry {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: 443,
                client_id: "rpi-2-ab12".into(),
                state: 0,
                source: Source::Runtime,
            }],
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
    }

    #[test]
    fn render_no_client() {
        let snap = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("clients 0"));
        assert!(s.contains("routes 0"));
        assert!(s.contains("(no clients connected)"));
        assert!(s.contains("(no routes)"));
        assert!(s.contains("(none)"));
    }
}
