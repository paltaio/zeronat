use crate::proto::{Msg, Proto, SnapshotBody};
use crate::Result;
use tokio::net::TcpStream;

/// Connect to a server's control port, request one snapshot, render it, and exit.
/// Read-only: the admin path never registers as a client or evicts the live one.
pub async fn show(server: String, secret: String) -> Result<()> {
    let psk = crate::noise::derive_psk(&secret);
    let sock = TcpStream::connect(&server).await?;
    sock.set_nodelay(true).ok();
    let (mut r, mut w) = crate::noise::client_handshake(sock, &psk).await?;
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
        Msg::Snapshot(snap) => {
            print!("{}", render(&snap, &server));
            Ok(())
        }
        other => Err(format!("expected snapshot, got {other:?}").into()),
    }
}

/// Render a snapshot to a human-readable report. Pure (no IO) so it is testable.
fn render(snap: &SnapshotBody, addr: &str) -> String {
    let mut out = String::new();

    let clients = if snap.client.is_some() { 1 } else { 0 };
    out.push_str("Servers\n");
    out.push_str(&format!(
        "  {:<8}  connected  {}  clients {}\n",
        snap.server_id, addr, clients
    ));

    out.push_str("\nListeners\n");
    if snap.listeners.is_empty() {
        out.push_str("  (none)\n");
    } else {
        out.push_str(&format!("  {:<6}  {}\n", "PROTO", "PORT"));
        for l in &snap.listeners {
            let proto = match l.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
            };
            out.push_str(&format!("  {:<6}  {}\n", proto, l.port));
        }
    }

    out.push_str("\nClients\n");
    match &snap.client {
        Some(c) => out.push_str(&format!(
            "  {}  connected to {}\n",
            c.client_id, snap.server_id
        )),
        None => out.push_str("  (no clients connected)\n"),
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ClientEntry, Listener};

    #[test]
    fn render_single_client() {
        let snap = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: vec![
                Listener {
                    proto: Proto::Tcp,
                    port: 443,
                },
                Listener {
                    proto: Proto::Udp,
                    port: 51820,
                },
            ],
            client: Some(ClientEntry {
                client_id: "rpi-2-ab12".into(),
                transport: 1,
            }),
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("Servers"));
        assert!(s.contains("clients 1"));
        assert!(s.contains("tcp"));
        assert!(s.contains("443"));
        assert!(s.contains("udp"));
        assert!(s.contains("51820"));
        assert!(s.contains("rpi-2-ab12  connected to 0"));
    }

    #[test]
    fn render_no_client() {
        let snap = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: Vec::new(),
            client: None,
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("clients 0"));
        assert!(s.contains("(none)"));
        assert!(s.contains("(no clients connected)"));
    }
}
