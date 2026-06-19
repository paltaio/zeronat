use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

use zeronat::proto::{Msg, Proto};

const SECRET: &str = "integration-test-secret";

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Echoes back every chunk it receives on a local TCP port.
async fn tcp_echo(port: u16) {
    let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    loop {
        let (mut c, _) = l.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match c.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if c.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// Echoes back every datagram it receives on a local UDP port.
async fn udp_echo(port: u16) {
    let s = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 65535];
    loop {
        let (n, src) = s.recv_from(&mut buf).await.unwrap();
        s.send_to(&buf[..n], src).await.unwrap();
    }
}

/// Serves a fixed constant reply to the first chunk of every TCP connection, so a
/// caller can tell which of several services a route resolved to.
async fn tcp_tagged(port: u16, tag: &'static [u8]) {
    let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    loop {
        let (mut c, _) = l.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match c.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if c.write_all(tag).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// Public ports of a started server/client pair, for tests to drive traffic.
struct Tunnel {
    control: u16,
    public_tcp: u16,
    public_udp: u16,
}

/// Start a server and client mapping one public TCP and one public UDP port to
/// local echo services. Returns the ports so a test can drive traffic.
fn start_tunnel(transport: zeronat::client::Transport) -> Tunnel {
    let control = free_tcp_port();
    let public_tcp = free_tcp_port();
    let public_udp = free_udp_port();
    let local_tcp = free_tcp_port();
    let local_udp = free_udp_port();

    // Local services behind the client.
    tokio::spawn(tcp_echo(local_tcp));
    tokio::spawn(udp_echo(local_udp));

    // Server on the "public" side.
    tokio::spawn(zeronat::server::run(
        "127.0.0.1".into(),
        control,
        SECRET.into(),
        vec![public_tcp],
        vec![public_udp],
        None,
        None,
        "0".into(),
    ));

    // Client dialing out, mapping public ports to the local echo services.
    tokio::spawn(zeronat::client::run(
        format!("127.0.0.1:{control}"),
        SECRET.into(),
        vec![(public_tcp, format!("127.0.0.1:{local_tcp}"))],
        vec![(public_udp, format!("127.0.0.1:{local_udp}"))],
        transport,
        None,
        Some("rpi".into()),
    ));

    Tunnel {
        control,
        public_tcp,
        public_udp,
    }
}

/// Connect to the control port and run the admin Noise handshake, retrying until
/// the control listener is accepting. Returns the handshaked reader/writer.
async fn admin_connect(control: u16) -> (zeronat::noise::NoiseReader, zeronat::noise::NoiseWriter) {
    let psk = zeronat::noise::derive_psk(SECRET);
    loop {
        if let Ok(sock) = TcpStream::connect(("127.0.0.1", control)).await {
            sock.set_nodelay(true).ok();
            if let Ok(pair) = zeronat::noise::client_handshake(sock, &psk).await {
                return pair;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Open an admin snapshot session and decode the server's reply.
async fn fetch_snapshot(control: u16) -> zeronat::proto::SnapshotBody {
    let (mut r, mut w) = admin_connect(control).await;
    w.send(
        &Msg::AdminHello {
            version: zeronat::identity::PROTO_VERSION,
            mode: 0,
        }
        .encode(),
    )
    .await
    .unwrap();
    let frame = r.recv().await.unwrap();
    match Msg::decode(&frame).unwrap() {
        Msg::Snapshot(snap) => snap,
        other => panic!("expected snapshot, got {other:?}"),
    }
}

/// Run one admin mutation and return the server's `(ok, msg)` result.
async fn admin_mutate(control: u16, req: Msg) -> (bool, String) {
    let (mut r, mut w) = admin_connect(control).await;
    w.send(
        &Msg::AdminHello {
            version: zeronat::identity::PROTO_VERSION,
            mode: 1,
        }
        .encode(),
    )
    .await
    .unwrap();
    w.send(&req.encode()).await.unwrap();
    let frame = r.recv().await.unwrap();
    match Msg::decode(&frame).unwrap() {
        Msg::MutationResult { ok, msg } => (ok, msg),
        other => panic!("expected mutation result, got {other:?}"),
    }
}

/// Poll the snapshot until at least `want` clients are connected, or panic on
/// timeout. Returns the snapshot once the condition holds.
async fn wait_clients(control: u16, want: usize) -> zeronat::proto::SnapshotBody {
    loop {
        let snap = fetch_snapshot(control).await;
        if snap.clients.len() >= want {
            return snap;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Connect to the public TCP port and round-trip until the client has registered
/// and the path is live, then prove a second round-trip on the same connection.
/// Returns the live connection so the caller can reuse it.
async fn wait_tcp_path(public_tcp: u16) -> TcpStream {
    let mut conn = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", public_tcp)).await {
            s.set_nodelay(true).ok();
            let mut s = s;
            if s.write_all(b"hello-tcp").await.is_ok() {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    if &buf[..n] == b"hello-tcp" {
                        break s;
                    }
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    };
    // Second round-trip on the same connection.
    conn.write_all(b"again").await.unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"again");
    conn
}

/// Open a fresh public TCP connection, send a probe, and return the first reply.
/// `None` if the connection or round-trip fails (path not live yet).
async fn probe_tcp(public_tcp: u16) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", public_tcp)).await.ok()?;
    s.set_nodelay(true).ok();
    s.write_all(b"probe").await.ok()?;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.ok()?;
    if n == 0 {
        return None;
    }
    Some(buf[..n].to_vec())
}

/// Poll fresh public TCP connections until one returns exactly `want`, or panic.
async fn wait_tcp_reply(public_tcp: u16, want: &[u8]) {
    loop {
        if let Some(reply) = probe_tcp(public_tcp).await {
            if reply == want {
                return;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn run_tunnel_test(transport: zeronat::client::Transport) {
    let tunnel = start_tunnel(transport);

    let body = async {
        let _conn = wait_tcp_path(tunnel.public_tcp).await;

        // UDP: retry until a datagram echoes back.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(("127.0.0.1", tunnel.public_udp))
            .await
            .unwrap();
        loop {
            sock.send(b"hello-udp").await.unwrap();
            let mut buf = [0u8; 64];
            match timeout(Duration::from_millis(300), sock.recv(&mut buf)).await {
                Ok(Ok(n)) if &buf[..n] == b"hello-udp" => break,
                _ => sleep(Duration::from_millis(100)).await,
            }
        }
    };

    body.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_over_tcp_transport() {
    timeout(
        Duration::from_secs(20),
        run_tunnel_test(zeronat::client::Transport::Tcp),
    )
    .await
    .expect("tcp transport did not pass traffic within 20s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_over_udp_transport() {
    timeout(
        Duration::from_secs(20),
        run_tunnel_test(zeronat::client::Transport::Udp),
    )
    .await
    .expect("udp transport did not pass traffic within 20s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_snapshot_over_tcp() {
    let body = async {
        let tunnel = start_tunnel(zeronat::client::Transport::Tcp);

        // Drive the TCP path first so the ClientHello has registered the client.
        let mut conn = wait_tcp_path(tunnel.public_tcp).await;

        let snap = fetch_snapshot(tunnel.control).await;
        assert_eq!(snap.server_id, "0");
        assert!(snap
            .listeners
            .iter()
            .any(|l| l.proto == Proto::Tcp && l.port == tunnel.public_tcp));
        assert!(snap
            .listeners
            .iter()
            .any(|l| l.proto == Proto::Udp && l.port == tunnel.public_udp));
        assert_eq!(snap.clients.len(), 1);
        assert!(snap.clients[0].client_id.starts_with("rpi-"));

        // The read-only admin path must not have evicted the live client: one more
        // echo round-trip on the original tunnel connection still works.
        conn.write_all(b"after-admin").await.unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after-admin");
    };

    timeout(Duration::from_secs(20), body)
        .await
        .expect("admin snapshot did not complete within 20s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_client_route_switch() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let target1 = free_tcp_port();
        let target2 = free_tcp_port();

        // Two distinguishable local services.
        tokio::spawn(tcp_tagged(target1, b"ONE"));
        tokio::spawn(tcp_tagged(target2, b"TWO"));

        tokio::spawn(zeronat::server::run(
            "127.0.0.1".into(),
            control,
            SECRET.into(),
            vec![public_tcp],
            vec![],
            None,
            None,
            "0".into(),
        ));

        // Two clients, each mapping the same public port to its own target.
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![(public_tcp, format!("127.0.0.1:{target1}"))],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            Some("rpi-1".into()),
        ));
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![(public_tcp, format!("127.0.0.1:{target2}"))],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            Some("rpi-2".into()),
        ));

        // Discover both full client ids.
        let snap = wait_clients(control, 2).await;
        let id1 = snap
            .clients
            .iter()
            .find(|c| c.client_id.starts_with("rpi-1-"))
            .expect("rpi-1 connected")
            .client_id
            .clone();
        let id2 = snap
            .clients
            .iter()
            .find(|c| c.client_id.starts_with("rpi-2-"))
            .expect("rpi-2 connected")
            .client_id
            .clone();

        // Route the public port to rpi-1 and assert a fresh connection reaches ONE.
        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: std::net::Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: id1,
            },
        )
        .await;
        assert!(ok, "set route to rpi-1 failed: {msg}");
        wait_tcp_reply(public_tcp, b"ONE").await;

        // Switch the route to rpi-2 and assert fresh connections now reach TWO.
        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: std::net::Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: id2,
            },
        )
        .await;
        assert!(ok, "set route to rpi-2 failed: {msg}");
        wait_tcp_reply(public_tcp, b"TWO").await;
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("multi-client route switch did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_add_remove() {
    let body = async {
        let tunnel = start_tunnel(zeronat::client::Transport::Tcp);
        // Wait for the single client to register so the no-route fallback resolves.
        wait_clients(tunnel.control, 1).await;

        // The listener for public_tcp already exists from CLI; adding a duplicate
        // must be rejected.
        let (ok, _) = admin_mutate(
            tunnel.control,
            Msg::AddListener {
                bind_ip: std::net::Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: tunnel.public_tcp,
            },
        )
        .await;
        assert!(!ok, "duplicate AddListener should fail");

        // Removing a listener that does not exist must be rejected.
        let free = free_tcp_port();
        let (ok, _) = admin_mutate(
            tunnel.control,
            Msg::RemoveListener {
                bind_ip: std::net::Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: free,
            },
        )
        .await;
        assert!(!ok, "RemoveListener on a missing listener should fail");

        // Remove the CLI listener, prove new connections are refused, then re-add it
        // on the same port and prove it bridges to the single client again.
        let (ok, msg) = admin_mutate(
            tunnel.control,
            Msg::RemoveListener {
                bind_ip: std::net::Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: tunnel.public_tcp,
            },
        )
        .await;
        assert!(ok, "RemoveListener on the CLI listener failed: {msg}");

        // After removal, fresh public connections to that port must fail (the
        // socket was released) within a few seconds.
        let refused = async {
            loop {
                match TcpStream::connect(("127.0.0.1", tunnel.public_tcp)).await {
                    Err(_) => break,
                    Ok(_) => sleep(Duration::from_millis(100)).await,
                }
            }
        };
        timeout(Duration::from_secs(5), refused)
            .await
            .expect("removed listener still accepts connections");

        // Re-add the listener on the same port and prove it bridges to the client.
        let (ok, msg) = admin_mutate(
            tunnel.control,
            Msg::AddListener {
                bind_ip: std::net::Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: tunnel.public_tcp,
            },
        )
        .await;
        assert!(ok, "AddListener after removal failed: {msg}");
        // The client maps this public port to its echo, so a fresh connection echoes.
        let live = async {
            loop {
                if let Ok(mut s) = TcpStream::connect(("127.0.0.1", tunnel.public_tcp)).await {
                    s.set_nodelay(true).ok();
                    if s.write_all(b"readd").await.is_ok() {
                        let mut buf = [0u8; 64];
                        if let Ok(n) = s.read(&mut buf).await {
                            if &buf[..n] == b"readd" {
                                break;
                            }
                        }
                    }
                }
                sleep(Duration::from_millis(100)).await;
            }
        };
        timeout(Duration::from_secs(10), live)
            .await
            .expect("re-added listener did not bridge to the client");
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("listener add/remove did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_source_teardown_on_remove() {
    let body = async {
        let tunnel = start_tunnel(zeronat::client::Transport::Udp);
        wait_clients(tunnel.control, 1).await;

        // Bring up an active UDP forward: a source that gets echoes.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(("127.0.0.1", tunnel.public_udp))
            .await
            .unwrap();
        let live = async {
            loop {
                sock.send(b"hello-udp").await.unwrap();
                let mut buf = [0u8; 64];
                match timeout(Duration::from_millis(300), sock.recv(&mut buf)).await {
                    Ok(Ok(n)) if &buf[..n] == b"hello-udp" => break,
                    _ => sleep(Duration::from_millis(100)).await,
                }
            }
        };
        timeout(Duration::from_secs(15), live)
            .await
            .expect("udp forward never became live");

        // Remove the udp listener.
        let (ok, msg) = admin_mutate(
            tunnel.control,
            Msg::RemoveListener {
                bind_ip: std::net::Ipv4Addr::LOCALHOST,
                proto: Proto::Udp,
                port: tunnel.public_udp,
            },
        )
        .await;
        assert!(ok, "RemoveListener on the udp port failed: {msg}");

        // The socket must be released: a fresh bind to the same port now succeeds.
        let released = async {
            loop {
                if UdpSocket::bind(("127.0.0.1", tunnel.public_udp))
                    .await
                    .is_ok()
                {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
        };
        let bound = timeout(Duration::from_secs(5), released).await;
        assert!(bound.is_ok(), "udp listener socket was not released");
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("udp source teardown did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_same_id_supersede() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();

        tokio::spawn(tcp_echo(local_tcp));

        tokio::spawn(zeronat::server::run(
            "127.0.0.1".into(),
            control,
            SECRET.into(),
            vec![public_tcp],
            vec![],
            None,
            None,
            "0".into(),
        ));

        // Two clients with the same prefix on the same host resolve to the same
        // full id, so the second supersedes the first in the registry.
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![(public_tcp, format!("127.0.0.1:{local_tcp}"))],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            Some("dup".into()),
        ));
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![(public_tcp, format!("127.0.0.1:{local_tcp}"))],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            Some("dup".into()),
        ));

        // Wait until at least one client has registered, then prove the map never
        // grows past one entry for this id across a settling window.
        wait_clients(control, 1).await;
        for _ in 0..10 {
            let snap = fetch_snapshot(control).await;
            let dup = snap
                .clients
                .iter()
                .filter(|c| c.client_id.starts_with("dup-"))
                .count();
            assert_eq!(
                dup, 1,
                "exactly one client entry expected for the shared id"
            );
            sleep(Duration::from_millis(100)).await;
        }

        // The surviving session still bridges public traffic.
        let _conn = wait_tcp_path(public_tcp).await;
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("reconnect supersede did not complete within 30s");
}
