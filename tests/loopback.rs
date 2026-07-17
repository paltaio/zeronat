use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

use zeronat::clientproto::{ClientMsg, ClientSnapshotBody, PppPhase, SessionMode};
use zeronat::proto::{Msg, Proto, Source};
use zeronat::server::{ListenerSpec, ServerSettings};

const SECRET: &str = "integration-test-secret";
const SECRET_B: &str = "integration-test-secret-b";

/// Build a `ServerSettings` for a config-less (runtime-only) server: localhost
/// bind, removable runtime-sourced listeners, no routes, no config file. The
/// dedicated CLI-lock test pins its own cli-locked listener; here listeners stay
/// removable so the add/remove path is exercisable. Tests override fields as needed.
fn cli_settings(control: u16, tcp: Vec<u16>, udp: Vec<u16>) -> ServerSettings {
    let mut listeners: Vec<ListenerSpec> = tcp
        .into_iter()
        .map(|port| ListenerSpec {
            bind_ip: Ipv4Addr::LOCALHOST,
            proto: Proto::Tcp,
            port,
            source: Source::Runtime,
            cli_locked: false,
        })
        .collect();
    listeners.extend(udp.into_iter().map(|port| ListenerSpec {
        bind_ip: Ipv4Addr::LOCALHOST,
        proto: Proto::Udp,
        port,
        source: Source::Runtime,
        cli_locked: false,
    }));
    ServerSettings {
        bind: Ipv4Addr::LOCALHOST,
        control_port: control,
        secret: SECRET.into(),
        server_id: "0".into(),
        tap: None,
        tun: None,
        dht: None,
        listeners,
        routes: Vec::new(),
        config_path: None,
        file_id: None,
        file_control: None,
    }
}

/// A plain forward of `port` to a local target port: no proxy header, default
/// idle window.
fn fwd(port: u16, target: u16) -> zeronat::client::Forward {
    zeronat::client::Forward {
        port,
        target: format!("127.0.0.1:{target}"),
        proxy: false,
        idle: None,
        enabled: true,
    }
}

/// Claim a port for this test run. The probe socket closes before the caller
/// binds the port, so the kernel can re-issue it to a concurrent test; deduping
/// keeps two tests from ever being given the same port.
fn claim_port(port: u16) -> bool {
    use std::sync::{Mutex, OnceLock};
    static TAKEN: OnceLock<Mutex<std::collections::HashSet<u16>>> = OnceLock::new();
    TAKEN
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(port)
}

fn free_tcp_port() -> u16 {
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if claim_port(port) {
            return port;
        }
    }
}

fn free_udp_port() -> u16 {
    loop {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if claim_port(port) {
            return port;
        }
    }
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

/// Replies a fixed constant to every datagram it receives on a local UDP port, so
/// a caller can tell which of several services a route resolved to.
async fn udp_tagged(port: u16, tag: &'static [u8]) {
    let s = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 65535];
    loop {
        let (_, src) = s.recv_from(&mut buf).await.unwrap();
        s.send_to(tag, src).await.unwrap();
    }
}

/// Start a server with one public port plus two clients mapping that port to
/// tagged local services (ONE and TWO). Returns both full client ids in that
/// order, once both are registered.
async fn start_tagged_pair(
    control: u16,
    proto: Proto,
    public_port: u16,
    target1: u16,
    target2: u16,
) -> (String, String) {
    let (tcp_ports, udp_ports) = match proto {
        Proto::Tcp => (vec![public_port], vec![]),
        Proto::Udp => (vec![], vec![public_port]),
    };
    tokio::spawn(zeronat::server::run(cli_settings(
        control, tcp_ports, udp_ports,
    )));

    for (name, target) in [("rpi-1", target1), ("rpi-2", target2)] {
        let (tcp_map, udp_map) = match proto {
            Proto::Tcp => (vec![fwd(public_port, target)], vec![]),
            Proto::Udp => (vec![], vec![fwd(public_port, target)]),
        };
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            tcp_map,
            udp_map,
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some(name.into()),
            None,
        ));
    }

    let snap = wait_clients(control, 2).await;
    let id_of = |prefix: &str| {
        snap.clients
            .iter()
            .find(|c| c.client_id.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix} connected"))
            .client_id
            .clone()
    };
    (id_of("rpi-1-"), id_of("rpi-2-"))
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
    tokio::spawn(zeronat::server::run(cli_settings(
        control,
        vec![public_tcp],
        vec![public_udp],
    )));

    // Client dialing out, mapping public ports to the local echo services.
    tokio::spawn(zeronat::client::run(
        format!("127.0.0.1:{control}"),
        SECRET.into(),
        vec![fwd(public_tcp, local_tcp)],
        vec![fwd(public_udp, local_udp)],
        transport,
        None,
        None,
        None,
        Some("rpi".into()),
        None,
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

/// Connect to the public TCP port, retrying until a round-trip returns exactly
/// `want`, and hand back the established connection.
async fn hold_tcp_conn(public_tcp: u16, want: &[u8]) -> TcpStream {
    loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", public_tcp)).await {
            s.set_nodelay(true).ok();
            if s.write_all(b"probe").await.is_ok() {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    if &buf[..n] == want {
                        return s;
                    }
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Drive an established connection until the server cuts it (EOF or error);
/// the caller's timeout bounds the wait, so a connection that idles out
/// instead of being cut fails the test.
async fn wait_tcp_cut(conn: &mut TcpStream) {
    let mut buf = [0u8; 64];
    loop {
        if conn.write_all(b"still-there").await.is_err() {
            return;
        }
        match timeout(Duration::from_millis(300), conn.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            // A reply raced in from the old bridge before the abort landed.
            Ok(Ok(_)) => {}
            Err(_) => {}
        }
    }
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
        tokio::spawn(tcp_tagged(target1, b"ONE"));
        tokio::spawn(tcp_tagged(target2, b"TWO"));
        let (id1, id2) = start_tagged_pair(control, Proto::Tcp, public_tcp, target1, target2).await;

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
async fn route_switch_cuts_established_tcp() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let target1 = free_tcp_port();
        let target2 = free_tcp_port();
        tokio::spawn(tcp_tagged(target1, b"ONE"));
        tokio::spawn(tcp_tagged(target2, b"TWO"));
        let (id1, id2) = start_tagged_pair(control, Proto::Tcp, public_tcp, target1, target2).await;

        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: id1,
            },
        )
        .await;
        assert!(ok, "set route to rpi-1 failed: {msg}");

        let mut conn = hold_tcp_conn(public_tcp, b"ONE").await;

        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: id2,
            },
        )
        .await;
        assert!(ok, "set route to rpi-2 failed: {msg}");

        wait_tcp_cut(&mut conn).await;

        // Fresh connections reach the new client.
        wait_tcp_reply(public_tcp, b"TWO").await;
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("tcp route cut did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_clear_cuts_established_tcp() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let target1 = free_tcp_port();
        let target2 = free_tcp_port();
        tokio::spawn(tcp_tagged(target1, b"ONE"));
        tokio::spawn(tcp_tagged(target2, b"TWO"));
        let (id1, _id2) =
            start_tagged_pair(control, Proto::Tcp, public_tcp, target1, target2).await;

        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: id1,
            },
        )
        .await;
        assert!(ok, "set route to rpi-1 failed: {msg}");

        let mut conn = hold_tcp_conn(public_tcp, b"ONE").await;

        // With two clients connected, clearing the route leaves the key with no
        // resolved target, so the established flow must be cut.
        let (ok, msg) = admin_mutate(
            control,
            Msg::ClearRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
            },
        )
        .await;
        assert!(ok, "clear route failed: {msg}");

        wait_tcp_cut(&mut conn).await;
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("tcp route clear cut did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_switch_cuts_established_udp() {
    let body = async {
        let control = free_tcp_port();
        let public_udp = free_udp_port();
        let target1 = free_udp_port();
        let target2 = free_udp_port();
        tokio::spawn(udp_tagged(target1, b"ONE"));
        tokio::spawn(udp_tagged(target2, b"TWO"));
        let (id1, id2) = start_tagged_pair(control, Proto::Udp, public_udp, target1, target2).await;

        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Udp,
                port: public_udp,
                client_id: id1,
            },
        )
        .await;
        assert!(ok, "set route to rpi-1 failed: {msg}");

        // Pin this source to rpi-1's session.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(("127.0.0.1", public_udp)).await.unwrap();
        let mut buf = [0u8; 64];
        loop {
            sock.send(b"probe").await.unwrap();
            match timeout(Duration::from_millis(300), sock.recv(&mut buf)).await {
                Ok(Ok(n)) if &buf[..n] == b"ONE" => break,
                _ => sleep(Duration::from_millis(100)).await,
            }
        }

        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Udp,
                port: public_udp,
                client_id: id2,
            },
        )
        .await;
        assert!(ok, "set route to rpi-2 failed: {msg}");

        // The same source must be flushed and re-routed well before the session
        // TTL: its datagrams start reaching rpi-2.
        loop {
            sock.send(b"probe").await.unwrap();
            match timeout(Duration::from_millis(300), sock.recv(&mut buf)).await {
                Ok(Ok(n)) if &buf[..n] == b"TWO" => break,
                _ => sleep(Duration::from_millis(100)).await,
            }
        }
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("udp route cut did not complete within 30s");
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

        tokio::spawn(zeronat::server::run(cli_settings(
            control,
            vec![public_tcp],
            vec![],
        )));

        // Two clients with the same prefix on the same host resolve to the same
        // full id, so the second supersedes the first in the registry.
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![fwd(public_tcp, local_tcp)],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("dup".into()),
            None,
        ));
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![fwd(public_tcp, local_tcp)],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("dup".into()),
            None,
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

/// Allocate a fresh, process-unique temp directory for a config file.
fn temp_config_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zeronat-loopback-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_autosave_persists_route() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();

        tokio::spawn(tcp_echo(local_tcp));

        // Config-backed server: a CLI listener so the client can connect, and a
        // config_path so mutations auto-save. The file starts absent; save_atomic
        // creates it on the first persisted mutation.
        let dir = temp_config_dir("autosave");
        let path = dir.join("server.toml");
        let mut settings = cli_settings(control, vec![public_tcp], vec![]);
        settings.config_path = Some(path.clone());
        tokio::spawn(zeronat::server::run(settings));

        // One client maps the public port to its echo, so it serves the route.
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![fwd(public_tcp, local_tcp)],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("rpi".into()),
            None,
        ));

        let snap = wait_clients(control, 1).await;
        let client_id = snap.clients[0].client_id.clone();

        // SetRoute over the mutate protocol; the server must persist it.
        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: client_id.clone(),
            },
        )
        .await;
        assert!(ok, "SetRoute on a config-backed server failed: {msg}");

        // The on-disk config now carries the route.
        let cfg = zeronat::config::load(&path).expect("config file written");
        assert!(
            cfg.routes
                .iter()
                .any(|r| r.proto == Proto::Tcp && r.port == public_tcp && r.client == client_id),
            "persisted config missing the route: {:?}",
            cfg.routes
        );

        // ClearRoute persists the removal: the file no longer contains the route.
        let (ok, msg) = admin_mutate(
            control,
            Msg::ClearRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
            },
        )
        .await;
        assert!(ok, "ClearRoute on a config-backed server failed: {msg}");
        let cfg = zeronat::config::load(&path).expect("config file still present");
        assert!(
            !cfg.routes
                .iter()
                .any(|r| r.proto == Proto::Tcp && r.port == public_tcp),
            "cleared route still present in config: {:?}",
            cfg.routes
        );

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("config autosave did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_listener_remove_refused() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();

        tokio::spawn(tcp_echo(local_tcp));

        // A CLI-locked listener that admin must refuse to remove.
        let mut settings = cli_settings(control, vec![], vec![]);
        settings.listeners = vec![ListenerSpec {
            bind_ip: Ipv4Addr::LOCALHOST,
            proto: Proto::Tcp,
            port: public_tcp,
            source: Source::Cli,
            cli_locked: true,
        }];
        tokio::spawn(zeronat::server::run(settings));

        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![fwd(public_tcp, local_tcp)],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("rpi".into()),
            None,
        ));
        wait_clients(control, 1).await;

        let (ok, msg) = admin_mutate(
            control,
            Msg::RemoveListener {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
            },
        )
        .await;
        assert!(!ok, "CLI-locked listener removal must be refused");
        assert!(
            msg.contains("controlled by CLI args"),
            "unexpected refusal message: {msg}"
        );

        // The listener is still live: a fresh public connection still bridges.
        let _conn = wait_tcp_path(public_tcp).await;
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("cli listener remove refusal did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_node_does_not_persist() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();

        tokio::spawn(tcp_echo(local_tcp));

        // No config_path: a runtime-only node. Mutations apply in memory but are
        // marked `runtime` and never written.
        tokio::spawn(zeronat::server::run(cli_settings(
            control,
            vec![public_tcp],
            vec![],
        )));

        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![fwd(public_tcp, local_tcp)],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("rpi".into()),
            None,
        ));

        let snap = wait_clients(control, 1).await;
        let client_id = snap.clients[0].client_id.clone();

        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: client_id.clone(),
            },
        )
        .await;
        assert!(ok, "SetRoute on a runtime node failed: {msg}");

        // The route is live but marked runtime in the snapshot (nothing is written
        // because there is no config path).
        let snap = fetch_snapshot(control).await;
        let route = snap
            .routes
            .iter()
            .find(|r| r.proto == Proto::Tcp && r.port == public_tcp)
            .expect("route present in snapshot");
        assert_eq!(route.source, Source::Runtime, "route must be runtime-owned");
        assert_eq!(route.client_id, client_id);
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("runtime node persistence check did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_failure_reports_error() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);

    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();

        // A config path whose parent is a regular file: every atomic save fails
        // because the temp file cannot be created under a non-directory.
        let blocker = std::env::temp_dir().join(format!(
            "zeronat-blocker-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&blocker, b"x").unwrap();
        let mut settings = cli_settings(control, vec![public_tcp], vec![]);
        settings.config_path = Some(blocker.join("server.toml"));
        tokio::spawn(zeronat::server::run(settings));

        let (ok, msg) = admin_mutate(
            control,
            Msg::SetRoute {
                bind_ip: Ipv4Addr::LOCALHOST,
                proto: Proto::Tcp,
                port: public_tcp,
                client_id: "rpi-x".into(),
            },
        )
        .await;
        assert!(!ok, "a save to an unwritable path must report failure");
        assert!(msg.contains("rejected config save"), "msg was: {msg}");

        // The mutation still applied in memory despite the save failure.
        let snap = fetch_snapshot(control).await;
        assert!(
            snap.routes.iter().any(|r| r.port == public_tcp),
            "route must stay live in memory even though persistence failed"
        );

        std::fs::remove_file(&blocker).ok();
    };

    timeout(Duration::from_secs(20), body)
        .await
        .expect("save-failure check did not complete within 20s");
}

/// Drive a `+proxy` TCP forward and assert the local service's byte stream
/// starts with an exact PROXY v2 header followed immediately by the payload.
/// The local service is `tcp_echo`, which reflects every byte it receives in
/// order, so the echoed stream is a faithful capture of what reached it:
/// header first, then payload, and the round-trip itself proves the relay still
/// works after the header.
async fn run_proxy_header_test(transport: zeronat::client::Transport) {
    let control = free_tcp_port();
    let public_tcp = free_tcp_port();
    let local_tcp = free_tcp_port();
    tokio::spawn(tcp_echo(local_tcp));
    tokio::spawn(zeronat::server::run(cli_settings(
        control,
        vec![public_tcp],
        vec![],
    )));
    let mut forward = fwd(public_tcp, local_tcp);
    forward.proxy = true;
    tokio::spawn(zeronat::client::run(
        format!("127.0.0.1:{control}"),
        SECRET.into(),
        vec![forward],
        vec![],
        transport,
        None,
        None,
        None,
        Some("rpi".into()),
        None,
    ));

    let payload = b"proxied-payload";
    let want = 28 + payload.len();
    // Retry until the tunnel is live: a fresh connection whose echo returns the
    // full header + payload.
    let (bytes, src) = 'outer: loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", public_tcp)).await {
            s.set_nodelay(true).ok();
            let src = s.local_addr().unwrap();
            if s.write_all(payload).await.is_ok() {
                let mut buf = vec![0u8; want];
                let mut got = 0;
                while got < want {
                    match timeout(Duration::from_secs(2), s.read(&mut buf[got..])).await {
                        Ok(Ok(n)) if n > 0 => got += n,
                        _ => {
                            sleep(Duration::from_millis(100)).await;
                            continue 'outer;
                        }
                    }
                }
                break (buf, src);
            }
        }
        sleep(Duration::from_millis(100)).await;
    };

    // Signature, version/command, family/protocol, and address length.
    assert_eq!(
        &bytes[..12],
        &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
    );
    assert_eq!(bytes[12], 0x21, "version/command");
    assert_eq!(bytes[13], 0x11, "AF_INET/STREAM");
    assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 12, "length");
    // src is the connecting socket, dst the public listener.
    let src_ip = match src.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        other => panic!("loopback test connected from {other}"),
    };
    assert_eq!(&bytes[16..20], &src_ip, "src ip");
    assert_eq!(&bytes[20..24], &[127, 0, 0, 1], "dst ip");
    assert_eq!(
        u16::from_be_bytes([bytes[24], bytes[25]]),
        src.port(),
        "src port"
    );
    assert_eq!(
        u16::from_be_bytes([bytes[26], bytes[27]]),
        public_tcp,
        "dst port"
    );
    // The payload follows immediately after the 28-byte header.
    assert_eq!(&bytes[28..], payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_forward_delivers_v2_header_tcp_transport() {
    timeout(
        Duration::from_secs(30),
        run_proxy_header_test(zeronat::client::Transport::Tcp),
    )
    .await
    .expect("proxy header over tcp transport did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_forward_delivers_v2_header_udp_transport() {
    timeout(
        Duration::from_secs(30),
        run_proxy_header_test(zeronat::client::Transport::Udp),
    )
    .await
    .expect("proxy header over udp transport did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_forward_has_zero_extra_bytes() {
    let body = async {
        let tunnel = start_tunnel(zeronat::client::Transport::Tcp);

        let payload = b"plain-forward-payload";
        // Retry fresh connections until the tunnel round-trips the payload; the
        // echo reflects exactly what the local service received, so the first
        // bytes must be the payload itself with no injected prefix.
        let bytes = 'outer: loop {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", tunnel.public_tcp)).await {
                s.set_nodelay(true).ok();
                if s.write_all(payload).await.is_ok() {
                    let mut buf = vec![0u8; payload.len()];
                    let mut got = 0;
                    while got < buf.len() {
                        match timeout(Duration::from_secs(2), s.read(&mut buf[got..])).await {
                            Ok(Ok(n)) if n > 0 => got += n,
                            _ => {
                                sleep(Duration::from_millis(100)).await;
                                continue 'outer;
                            }
                        }
                    }
                    // Nothing else may be in flight: the service saw only the
                    // payload, so only the payload comes back.
                    let mut extra = [0u8; 1];
                    assert!(
                        timeout(Duration::from_millis(500), s.read(&mut extra))
                            .await
                            .is_err(),
                        "unexpected extra bytes after the echoed payload"
                    );
                    break buf;
                }
            }
            sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(&bytes, payload, "prefix bytes were injected into the relay");
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("plain forward byte check did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_forward_refuses_headerless_open() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();
        let local = TcpListener::bind(("127.0.0.1", local_tcp)).await.unwrap();

        // A hand-rolled server modeling an old release: it answers Ping with
        // Pong, ignores every other control frame (so FwdOptions is never
        // acked), and sends a plain Open for the proxy-flagged port. It fires
        // `open_sent` only after validating ClientHello and sending the Open;
        // a bad first frame drops the sender so the test fails loudly.
        let extra_conns = Arc::new(AtomicUsize::new(0));
        let control_dead = Arc::new(AtomicBool::new(false));
        let (open_sent_tx, open_sent_rx) = tokio::sync::oneshot::channel::<()>();
        {
            let extra_conns = extra_conns.clone();
            let control_dead = control_dead.clone();
            let l = TcpListener::bind(("127.0.0.1", control)).await.unwrap();
            tokio::spawn(async move {
                let psk = zeronat::noise::derive_psk(SECRET);
                // The first connection is the control channel.
                let (sock, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = zeronat::noise::server_handshake(sock, &psk)
                        .await
                        .expect("control handshake");
                    let first = r.recv().await.expect("client hello");
                    if !matches!(Msg::decode(&first), Ok(Msg::ClientHello { .. })) {
                        return; // drops open_sent_tx
                    }
                    w.send(
                        &Msg::Open {
                            proto: Proto::Tcp,
                            port: public_tcp,
                            id: 1,
                        }
                        .encode(),
                    )
                    .await
                    .expect("send open");
                    open_sent_tx.send(()).ok();
                    while let Ok(bytes) = r.recv().await {
                        if let Ok(Msg::Ping) = Msg::decode(&bytes) {
                            w.send(&Msg::Pong.encode()).await.ok();
                        }
                    }
                    control_dead.store(true, Ordering::Relaxed);
                });
                // Any further connection would be the data connection for the
                // open the client is supposed to refuse.
                loop {
                    if l.accept().await.is_ok() {
                        extra_conns.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }

        let mut forward = fwd(public_tcp, local_tcp);
        forward.proxy = true;
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![forward],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("rpi".into()),
            None,
        ));

        // Wait until the fake server has actually seen the ClientHello and
        // sent the plain Open; only then does the no-dial window prove a
        // refusal rather than a client that never connected.
        timeout(Duration::from_secs(10), open_sent_rx)
            .await
            .expect("fake server never received the client hello")
            .expect("fake server rejected the first control frame");

        // The client must refuse the headerless open outright: no dial back to
        // the server for the stream and no connection to the local target.
        assert!(
            timeout(Duration::from_secs(5), local.accept())
                .await
                .is_err(),
            "client dialed the local target despite the refused open"
        );
        assert_eq!(
            extra_conns.load(Ordering::Relaxed),
            0,
            "client opened a data connection for the refused open"
        );
        assert!(
            !control_dead.load(Ordering::Relaxed),
            "control connection died instead of staying alive"
        );
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("headerless-open refusal did not complete within 30s");
}

fn server_target(name: &str, control: u16, secret: &str) -> zeronat::client::ServerTarget {
    zeronat::client::ServerTarget {
        name: name.into(),
        addr: format!("127.0.0.1:{control}"),
        secret: secret.into(),
        transport: zeronat::client::Transport::Tcp,
    }
}

/// `ClientSettings` for a switchable client: the given profiles and TCP
/// forwards, an admin socket when `sock` is set, and nothing else. Tests add
/// pppoe sessions or a persistence target on top.
fn client_settings(
    servers: Vec<zeronat::client::ServerTarget>,
    tcp: Vec<zeronat::client::Forward>,
    id: &str,
    sock: Option<&Path>,
) -> zeronat::client::ClientSettings {
    zeronat::client::ClientSettings {
        servers,
        tcp,
        udp: vec![],
        tap: None,
        tun: None,
        pppoe: vec![],
        autostart: None,
        id_prefix: Some(id.into()),
        control: sock.map(|p| zeronat::clientctl::ControlPath::Explicit(p.to_path_buf())),
        config: None,
    }
}

/// One snapshot exchange over a client admin socket, retrying until the
/// socket accepts: it comes up with the client.
async fn client_snapshot(sock: &Path) -> ClientSnapshotBody {
    loop {
        if let Ok(snap) = zeronat::client_admin::snapshot(sock).await {
            return snap;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// One mutation exchange over a client admin socket. Mutations are never
/// retried; waiting for a snapshot first keeps the single-shot send from
/// racing the socket coming up.
async fn client_mutate(sock: &Path, req: ClientMsg) -> (bool, String) {
    client_snapshot(sock).await;
    zeronat::client_admin::mutate(sock, req)
        .await
        .expect("mutation exchange")
}

/// Poll client snapshots until `pred` holds; the caller's timeout bounds the
/// wait. Returns the matching snapshot.
async fn wait_client_snapshot(
    sock: &Path,
    pred: impl Fn(&ClientSnapshotBody) -> bool,
) -> ClientSnapshotBody {
    loop {
        let snap = client_snapshot(sock).await;
        if pred(&snap) {
            return snap;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// A pppoe session config whose discovery runs over the tunnel but never
/// completes (no access concentrator answers in the harness); the spawn/stop
/// tests exercise the mode machinery, not a full PPP bringup.
#[cfg(target_os = "linux")]
fn test_pppoe_config() -> zeronat::client::PppoeRunConfig {
    zeronat::client::PppoeRunConfig {
        username: b"user".to_vec(),
        password: b"pass".to_vec(),
        service_name: Vec::new(),
        ac_name: None,
        tun_name: "zpppt0".into(),
        effective_mtu: 1400,
        default_route: false,
        clamp_mss: None,
        request_dns: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_switch_moves_session() {
    let body = async {
        let control_a = free_tcp_port();
        let control_b = free_tcp_port();
        let public_a = free_tcp_port();
        let public_b = free_tcp_port();
        let local_echo = free_tcp_port();
        tokio::spawn(tcp_echo(local_echo));

        // Two independent servers with distinct secrets, each exposing its own
        // public port.
        tokio::spawn(zeronat::server::run(cli_settings(
            control_a,
            vec![public_a],
            vec![],
        )));
        let mut settings_b = cli_settings(control_b, vec![public_b], vec![]);
        settings_b.secret = SECRET_B.into();
        tokio::spawn(zeronat::server::run(settings_b));

        // One client dialing A, carrying forwards for both servers' public
        // ports so the same forward set serves whichever server is active.
        let active = zeronat::client::ActiveTarget::new(server_target("a", control_a, SECRET));
        tokio::spawn(zeronat::client::run_switchable(
            active.clone(),
            client_settings(
                vec![],
                vec![fwd(public_a, local_echo), fwd(public_b, local_echo)],
                "sw",
                None,
            ),
        ));

        // Session up against A: traffic round-trips through A's public port.
        let mut conn = wait_tcp_path(public_a).await;

        // Switch to B. The switch must abort the in-flight session, not sit
        // out the 90s control timeout waiting to notice A is gone: the
        // established relay through A is cut and traffic round-trips through
        // B's public port under B's secret within the 15s bound.
        active.switch(server_target("b", control_b, SECRET_B));
        timeout(Duration::from_secs(15), async {
            wait_tcp_cut(&mut conn).await;
            wait_tcp_path(public_b).await;
        })
        .await
        .expect("switch did not move traffic to B within 15s");
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("server switch did not complete within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_client_future_aborts_session() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();
        tokio::spawn(tcp_echo(local_tcp));
        tokio::spawn(zeronat::server::run(cli_settings(
            control,
            vec![public_tcp],
            vec![],
        )));
        let client = tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![fwd(public_tcp, local_tcp)],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("drop".into()),
            None,
        ));

        let mut conn = wait_tcp_path(public_tcp).await;

        // Dropping the client future must take the live session down with it:
        // a detached session would keep relaying and the cut would never come.
        client.abort();
        wait_tcp_cut(&mut conn).await;
    };

    timeout(Duration::from_secs(30), body)
        .await
        .expect("dropped client future did not cut the session within 30s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_admin_socket_serves_snapshot() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();
        tokio::spawn(tcp_echo(local_tcp));
        tokio::spawn(zeronat::server::run(cli_settings(
            control,
            vec![public_tcp],
            vec![],
        )));

        let dir = temp_config_dir("adminsock");
        let sock = dir.join("client.sock");
        tokio::spawn(zeronat::client::run(
            format!("127.0.0.1:{control}"),
            SECRET.into(),
            vec![fwd(public_tcp, local_tcp)],
            vec![],
            zeronat::client::Transport::Tcp,
            None,
            None,
            None,
            Some("adm".into()),
            Some(zeronat::clientctl::ControlPath::Explicit(sock.clone())),
        ));

        // The admin socket comes up with the client; retry until the whole
        // snapshot exchange completes.
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.version, zeronat::identity::PROTO_VERSION);
        assert_eq!(snap.active, format!("127.0.0.1:{control}"));
        assert_eq!(snap.mode, SessionMode::Forwards);
        assert_eq!(snap.phase, PppPhase::None);
        assert_eq!(snap.forwards.len(), 1);
        let f = &snap.forwards[0];
        assert_eq!(f.proto, Proto::Tcp);
        assert_eq!(f.port, public_tcp);
        assert_eq!(f.target, format!("127.0.0.1:{local_tcp}"));
        assert!(!f.proxy);
        assert_eq!(f.idle_secs, 0);
        // A CLI-shaped client's one profile is its server address; there are
        // no pppoe sessions to list and no live one to name.
        assert_eq!(snap.servers.len(), 1);
        assert_eq!(snap.servers[0].name, format!("127.0.0.1:{control}"));
        assert_eq!(snap.servers[0].addr, format!("127.0.0.1:{control}"));
        assert!(snap.pppoe.is_empty());
        assert_eq!(snap.session, "");

        // Mode 1 carries one mutation and gets a result on the same
        // connection; a CLI client's only profile is its server address, so
        // any other name is refused.
        let (ok, msg) = client_mutate(
            &sock,
            ClientMsg::SelectServer {
                name: "other".into(),
            },
        )
        .await;
        assert!(!ok);
        assert!(
            msg.contains("no configured server"),
            "unexpected refusal message: {msg}"
        );

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(20), body)
        .await
        .expect("client admin socket did not answer within 20s");
}

/// `show` against a live client: the rendered snapshot lists each forward with
/// its modifiers in the forward-list syntax, and the pppoe commands are refused when
/// nothing is configured to spawn and no pppoe body is running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_admin_show_renders_forward_options() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let public_udp = free_udp_port();
        let local_tcp = free_tcp_port();
        let local_udp = free_udp_port();
        tokio::spawn(zeronat::server::run(cli_settings(
            control,
            vec![public_tcp],
            vec![public_udp],
        )));

        let dir = temp_config_dir("showopts");
        let sock = dir.join("client.sock");
        let mut proxied = fwd(public_tcp, local_tcp);
        proxied.proxy = true;
        proxied.idle = Some(Duration::from_secs(600));
        let mut idled = fwd(public_udp, local_udp);
        idled.idle = Some(Duration::from_secs(300));
        let mut settings = client_settings(
            vec![server_target("home", control, SECRET)],
            vec![proxied],
            "show",
            Some(&sock),
        );
        settings.udp = vec![idled];
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(server_target("home", control, SECRET)),
            settings,
        ));

        let snap = wait_client_snapshot(&sock, |s| s.mode == SessionMode::Forwards).await;
        let s = zeronat::client_admin::render(&snap);
        assert!(s.contains("active  home"), "render:\n{s}");
        assert!(s.contains("mode    forwards"), "render:\n{s}");
        assert!(
            s.contains(&format!(
                "tcp:{public_tcp} -> 127.0.0.1:{local_tcp}  +proxy+idle=600"
            )),
            "render:\n{s}"
        );
        assert!(
            s.contains(&format!(
                "udp:{public_udp} -> 127.0.0.1:{local_udp}  +idle=300"
            )),
            "render:\n{s}"
        );

        zeronat::client_admin::show(Some(&sock))
            .await
            .expect("show command");
        let err = zeronat::client_admin::spawn_pppoe(Some(&sock), "wan".into())
            .await
            .expect_err("spawn must be refused with no pppoe entries");
        assert!(
            err.to_string().contains("no configured pppoe session"),
            "unexpected refusal: {err}"
        );
        let err = zeronat::client_admin::stop_pppoe(Some(&sock), "wan".into())
            .await
            .expect_err("stop must be refused on a forwards body");
        assert!(
            err.to_string().contains("no active pppoe session"),
            "unexpected refusal: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(20), body)
        .await
        .expect("show render flow did not complete within 20s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn select_server_moves_session_and_persists() {
    let body = async {
        let control_a = free_tcp_port();
        let control_b = free_tcp_port();
        let public_a = free_tcp_port();
        let public_b = free_tcp_port();
        let local_echo = free_tcp_port();
        tokio::spawn(tcp_echo(local_echo));
        tokio::spawn(zeronat::server::run(cli_settings(
            control_a,
            vec![public_a],
            vec![],
        )));
        let mut settings_b = cli_settings(control_b, vec![public_b], vec![]);
        settings_b.secret = SECRET_B.into();
        tokio::spawn(zeronat::server::run(settings_b));

        // A file-backed client: the config on disk is what mutations persist
        // into, and it parses to the same shape the settings carry.
        let dir = temp_config_dir("selectsrv");
        let path = dir.join("client.toml");
        let sock = dir.join("client.sock");
        let text = format!(
            "[client]\nactive = \"a\"\n\
             [[servers]]\nname = \"a\"\naddr = \"127.0.0.1:{control_a}\"\nsecret = \"{SECRET}\"\ntransport = \"tcp\"\n\
             [[servers]]\nname = \"b\"\naddr = \"127.0.0.1:{control_b}\"\nsecret = \"{SECRET_B}\"\ntransport = \"tcp\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = {public_a}\ntarget = \"127.0.0.1:{local_echo}\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = {public_b}\ntarget = \"127.0.0.1:{local_echo}\"\n"
        );
        std::fs::write(&path, &text).unwrap();
        let cfg = zeronat::clientcfg::parse_client(&text).unwrap();
        cfg.validate().unwrap();

        let mut settings = client_settings(
            vec![
                server_target("a", control_a, SECRET),
                server_target("b", control_b, SECRET_B),
            ],
            vec![fwd(public_a, local_echo), fwd(public_b, local_echo)],
            "sel",
            Some(&sock),
        );
        settings.config = Some((path.clone(), cfg));
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(server_target("a", control_a, SECRET)),
            settings,
        ));

        let mut conn = wait_tcp_path(public_a).await;

        // An unknown profile is refused through the admin command (the client's
        // refusal message is the error) and changes nothing, on disk or live.
        let before = std::fs::read_to_string(&path).unwrap();
        let err = zeronat::client_admin::select_server(Some(&sock), "nope".into())
            .await
            .expect_err("an unknown server name must be refused");
        assert!(
            err.to_string().contains("no configured server"),
            "unexpected refusal: {err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.active, "a");
        assert_eq!(snap.mode, SessionMode::Forwards);
        // The snapshot lists the selectable profiles by their config fields.
        let names: Vec<&str> = snap.servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);

        // Selecting b through the admin command moves the session: the relay
        // through a is cut and traffic round-trips through b's public port
        // under b's secret.
        zeronat::client_admin::select_server(Some(&sock), "b".into())
            .await
            .expect("select server b");
        timeout(Duration::from_secs(15), async {
            wait_tcp_cut(&mut conn).await;
            wait_tcp_path(public_b).await;
        })
        .await
        .expect("select-server did not move traffic to b within 15s");

        // The switch preserved the session body.
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.active, "b");
        assert_eq!(snap.mode, SessionMode::Forwards);

        // The persisted config round-trips through the client parser with the
        // new active profile and the rest of the shape intact.
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        on_disk.validate().unwrap();
        assert_eq!(on_disk.active.as_deref(), Some("b"));
        assert_eq!(on_disk.servers.len(), 2);
        assert_eq!(on_disk.forwards.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(60), body)
        .await
        .expect("select-server flow did not complete within 60s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_forward_options_redials_and_persists() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let public_udp = free_udp_port();
        let local_tcp = free_tcp_port();
        let local_udp = free_udp_port();
        tokio::spawn(tcp_echo(local_tcp));
        tokio::spawn(udp_echo(local_udp));
        tokio::spawn(zeronat::server::run(cli_settings(
            control,
            vec![public_tcp],
            vec![public_udp],
        )));

        let dir = temp_config_dir("fwdopts");
        let path = dir.join("client.toml");
        let sock = dir.join("client.sock");
        let text = format!(
            "[[servers]]\nname = \"home\"\naddr = \"127.0.0.1:{control}\"\nsecret = \"{SECRET}\"\ntransport = \"tcp\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = {public_tcp}\ntarget = \"127.0.0.1:{local_tcp}\"\n\
             [[forwards]]\nproto = \"udp\"\nport = {public_udp}\ntarget = \"127.0.0.1:{local_udp}\"\n"
        );
        std::fs::write(&path, &text).unwrap();
        let cfg = zeronat::clientcfg::parse_client(&text).unwrap();
        cfg.validate().unwrap();

        let mut settings = client_settings(
            vec![server_target("home", control, SECRET)],
            vec![fwd(public_tcp, local_tcp)],
            "fwo",
            Some(&sock),
        );
        settings.udp = vec![fwd(public_udp, local_udp)];
        settings.config = Some((path.clone(), cfg));
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(server_target("home", control, SECRET)),
            settings,
        ));

        let mut conn = wait_tcp_path(public_tcp).await;

        // A valid edit is accepted, redials the forwards session (the
        // established relay is cut), and shows up in the next snapshot.
        let (ok, msg) = client_mutate(
            &sock,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: public_tcp,
                enabled: true,
                proxy: false,
                idle_secs: 600,
            },
        )
        .await;
        assert!(ok, "set forward options failed: {msg}");
        timeout(Duration::from_secs(15), wait_tcp_cut(&mut conn))
            .await
            .expect("option edit did not redial the forwards session");
        let _conn = wait_tcp_path(public_tcp).await;
        let snap = client_snapshot(&sock).await;
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Tcp && f.port == public_tcp)
            .expect("tcp forward in snapshot");
        assert_eq!(f.idle_secs, 600);

        // The persisted entry round-trips through the client parser.
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        on_disk.validate().unwrap();
        let entry = on_disk
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Tcp && f.port == public_tcp)
            .expect("tcp forward on disk");
        assert_eq!(entry.idle, Some(600));

        // Wire idle 0 clears the override; the file carries no idle key.
        let (ok, msg) = client_mutate(
            &sock,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: public_tcp,
                enabled: true,
                proxy: false,
                idle_secs: 0,
            },
        )
        .await;
        assert!(ok, "clearing the idle override failed: {msg}");
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.forwards[0].idle_secs, 0);
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        on_disk.validate().unwrap();
        assert_eq!(on_disk.forwards[0].idle, None);

        // Disabling the tcp forward drops it from the redialed session's maps:
        // the port stops serving while the udp forward keeps echoing.
        let mut conn = wait_tcp_path(public_tcp).await;
        let (ok, msg) = client_mutate(
            &sock,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: public_tcp,
                enabled: false,
                proxy: false,
                idle_secs: 0,
            },
        )
        .await;
        assert!(ok, "disabling the tcp forward failed: {msg}");
        timeout(Duration::from_secs(15), wait_tcp_cut(&mut conn))
            .await
            .expect("disable did not redial the forwards session");
        // The udp round-trip proves the new session is up before the tcp probe,
        // so a dead probe means a disabled forward, not a client mid-redial.
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_sock.connect(("127.0.0.1", public_udp)).await.unwrap();
        let mut buf = [0u8; 64];
        loop {
            udp_sock.send(b"hello-udp").await.unwrap();
            match timeout(Duration::from_millis(300), udp_sock.recv(&mut buf)).await {
                Ok(Ok(n)) if &buf[..n] == b"hello-udp" => break,
                _ => {}
            }
        }
        // The listener still accepts, but the client refuses the open, so the
        // connection is never bridged and no echo comes back.
        if let Ok(Some(reply)) = timeout(Duration::from_secs(2), probe_tcp(public_tcp)).await {
            panic!("disabled forward still echoes: {reply:?}");
        }

        // Re-enabling puts the forward back in the maps and the port serves.
        let (ok, msg) = client_mutate(
            &sock,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: public_tcp,
                enabled: true,
                proxy: false,
                idle_secs: 0,
            },
        )
        .await;
        assert!(ok, "re-enabling the tcp forward failed: {msg}");
        let _conn = wait_tcp_path(public_tcp).await;

        // A failing validation persists and applies nothing: the file bytes
        // and the snapshot stay exactly as they were.
        let before = std::fs::read_to_string(&path).unwrap();
        let snap_before = client_snapshot(&sock).await;
        let (ok, _) = client_mutate(
            &sock,
            ClientMsg::SetForwardOptions {
                proto: Proto::Udp,
                port: public_udp,
                enabled: true,
                proxy: true,
                idle_secs: 0,
            },
        )
        .await;
        assert!(!ok, "proxy on a udp forward must be refused");
        let (ok, _) = client_mutate(
            &sock,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: 9,
                enabled: true,
                proxy: false,
                idle_secs: 5,
            },
        )
        .await;
        assert!(!ok, "an unknown forward must be refused");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.forwards, snap_before.forwards);

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(60), body)
        .await
        .expect("forward-options flow did not complete within 60s");
}

/// Real PPPoE needs an access concentrator on the far side, so this drives
/// the state machinery as far as the harness allows: the mode swap into and
/// out of a spawned session, the live discovery phase in snapshots, and the
/// no-drop rule for forward edits while the pppoe body runs. LCP/auth/IPCP
/// and zppp0 bringup never happen here.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_and_stop_pppoe_swap_the_session_body() {
    let body = async {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let local_tcp = free_tcp_port();
        tokio::spawn(tcp_echo(local_tcp));
        tokio::spawn(zeronat::server::run(cli_settings(
            control,
            vec![public_tcp],
            vec![],
        )));

        // Runtime-only client: spawn/stop and the option edit stay in memory.
        let dir = temp_config_dir("pppoeswap");
        let sock = dir.join("client.sock");
        let mut settings = client_settings(
            vec![server_target("a", control, SECRET)],
            vec![fwd(public_tcp, local_tcp)],
            "pps",
            Some(&sock),
        );
        settings.pppoe = vec![zeronat::client::PppoeSession {
            name: "wan".into(),
            config: test_pppoe_config(),
        }];
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(server_target("a", control, SECRET)),
            settings,
        ));

        let _conn = wait_tcp_path(public_tcp).await;
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.mode, SessionMode::Forwards);
        assert_eq!(snap.phase, PppPhase::None);

        let err = zeronat::client_admin::spawn_pppoe(Some(&sock), "dsl".into())
            .await
            .expect_err("an unknown pppoe name must be refused");
        assert!(
            err.to_string().contains("no configured pppoe session"),
            "unexpected refusal: {err}"
        );

        // Spawn tears the forwards body down and brings the pppoe up; the
        // live datapath writes its phase into the status cell.
        zeronat::client_admin::spawn_pppoe(Some(&sock), "wan".into())
            .await
            .expect("spawn pppoe");
        let snap = wait_client_snapshot(&sock, |s| {
            s.mode == SessionMode::Pppoe && s.phase != PppPhase::None
        })
        .await;
        assert_eq!(snap.pppoe, ["wan"]);
        assert_eq!(snap.session, "wan");

        // A forward edit while the pppoe body runs lands in memory but must
        // not drop the unrelated session.
        let (ok, msg) = client_mutate(
            &sock,
            ClientMsg::SetForwardOptions {
                proto: Proto::Tcp,
                port: public_tcp,
                enabled: true,
                proxy: false,
                idle_secs: 300,
            },
        )
        .await;
        assert!(ok, "forward edit under a pppoe body failed: {msg}");
        sleep(Duration::from_millis(300)).await;
        let snap = client_snapshot(&sock).await;
        assert_eq!(
            snap.mode,
            SessionMode::Pppoe,
            "forward edit dropped the pppoe body"
        );
        assert_eq!(snap.forwards[0].idle_secs, 300);

        // Stop with the wrong name is refused; the right name returns to the
        // boot-derived base mode and the forwards session (with the edited
        // options) comes back up.
        let err = zeronat::client_admin::stop_pppoe(Some(&sock), "dsl".into())
            .await
            .expect_err("stopping a session that is not running must be refused");
        assert!(
            err.to_string().contains("no active pppoe session"),
            "unexpected refusal: {err}"
        );
        zeronat::client_admin::stop_pppoe(Some(&sock), "wan".into())
            .await
            .expect("stop pppoe");
        wait_client_snapshot(&sock, |s| s.mode == SessionMode::Forwards).await;
        let _conn = wait_tcp_path(public_tcp).await;

        // With the forwards body running there is no pppoe to stop.
        assert!(
            zeronat::client_admin::stop_pppoe(Some(&sock), "wan".into())
                .await
                .is_err(),
            "stop must be refused when the body is not that pppoe"
        );

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(60), body)
        .await
        .expect("pppoe spawn/stop flow did not complete within 60s");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autostart_pppoe_boots_and_stops_to_idle() {
    let body = async {
        let control = free_tcp_port();
        tokio::spawn(zeronat::server::run(cli_settings(control, vec![], vec![])));

        let dir = temp_config_dir("autostart");
        let sock = dir.join("client.sock");
        let mut settings = client_settings(
            vec![server_target("a", control, SECRET)],
            vec![],
            "auto",
            Some(&sock),
        );
        settings.pppoe = vec![zeronat::client::PppoeSession {
            name: "wan".into(),
            config: test_pppoe_config(),
        }];
        settings.autostart = Some("wan".into());
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(server_target("a", control, SECRET)),
            settings,
        ));

        // Boot derives the pppoe body from the autostart entry; the live
        // datapath reports its phase.
        wait_client_snapshot(&sock, |s| {
            s.mode == SessionMode::Pppoe && s.phase != PppPhase::None
        })
        .await;

        // No concentrator answers, so discovery exhausts its retries and the
        // session task exits; snapshots must report the link dead through the
        // redial backoff instead of the last live phase.
        wait_client_snapshot(&sock, |s| {
            s.mode == SessionMode::Pppoe && s.phase == PppPhase::Dead
        })
        .await;

        // Stopping it falls back to idle (no forwards are declared), from
        // which the same session can be spawned again.
        let (ok, msg) = client_mutate(&sock, ClientMsg::StopSession { name: "wan".into() }).await;
        assert!(ok, "stop autostart pppoe failed: {msg}");
        wait_client_snapshot(&sock, |s| s.mode == SessionMode::Idle).await;
        let (ok, msg) = client_mutate(&sock, ClientMsg::SpawnPppoe { name: "wan".into() }).await;
        assert!(ok, "respawn after stop failed: {msg}");
        wait_client_snapshot(&sock, |s| s.mode == SessionMode::Pppoe).await;

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(60), body)
        .await
        .expect("autostart pppoe flow did not complete within 60s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_client_with_no_session_body_idles() {
    let body = async {
        // Servers are declared but never dialed: an idle client runs no
        // session body, so no server process is needed at all.
        let dir = temp_config_dir("idleboot");
        let path = dir.join("client.toml");
        let sock = dir.join("client.sock");
        let text = "[client]\nactive = \"a\"\n\
                    [[servers]]\nname = \"a\"\naddr = \"127.0.0.1:1\"\nsecret = \"s\"\n\
                    [[servers]]\nname = \"b\"\naddr = \"127.0.0.1:2\"\nsecret = \"t\"\n";
        std::fs::write(&path, text).unwrap();
        let cfg = zeronat::clientcfg::parse_client(text).unwrap();
        cfg.validate().unwrap();

        let a = server_target("a", 1, "s");
        let b = server_target("b", 2, "t");
        let mut settings = client_settings(vec![a.clone(), b], vec![], "idle", Some(&sock));
        settings.config = Some((path.clone(), cfg));
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(a),
            settings,
        ));

        // The client boots into idle with only the admin socket up.
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.mode, SessionMode::Idle);
        assert_eq!(snap.active, "a");
        assert_eq!(snap.phase, PppPhase::None);
        assert!(snap.forwards.is_empty());

        // Idle has no pppoe to stop and nothing configured to spawn.
        let (ok, _) = client_mutate(&sock, ClientMsg::StopSession { name: "a".into() }).await;
        assert!(!ok, "stop must be refused on an idle body");
        let (ok, _) = client_mutate(&sock, ClientMsg::SpawnPppoe { name: "wan".into() }).await;
        assert!(!ok, "spawn must be refused with no pppoe entries");

        // Selecting another profile keeps the idle body and persists.
        let (ok, msg) = client_mutate(&sock, ClientMsg::SelectServer { name: "b".into() }).await;
        assert!(ok, "select server on an idle client failed: {msg}");
        let snap = client_snapshot(&sock).await;
        assert_eq!(snap.active, "b");
        assert_eq!(snap.mode, SessionMode::Idle);
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        on_disk.validate().unwrap();
        assert_eq!(on_disk.active.as_deref(), Some("b"));

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(20), body)
        .await
        .expect("idle-mode client flow did not complete within 20s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_healthy_stream_outlives_reap_tcp_transport() {
    let body = async {
        let tunnel = start_tunnel(zeronat::client::Transport::Tcp);
        let mut conn = wait_tcp_path(tunnel.public_tcp).await;
        // Fully quiet for longer than TCP_IDLE (120s): the relay's liveness
        // probes must keep the healthy stream alive, not reap it.
        sleep(Duration::from_secs(150)).await;
        conn.write_all(b"after-quiet").await.unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"after-quiet",
            "stream did not survive the quiet window"
        );
    };

    timeout(Duration::from_secs(240), body)
        .await
        .expect("tcp idle survival did not complete within 240s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_healthy_stream_outlives_reap_udp_transport() {
    let body = async {
        let tunnel = start_tunnel(zeronat::client::Transport::Udp);
        let mut conn = wait_tcp_path(tunnel.public_tcp).await;
        // Fully quiet past both the relay idle window (120s) and the KCP conv
        // idle (180s): the probes must keep the whole path warm.
        sleep(Duration::from_secs(200)).await;
        conn.write_all(b"after-quiet").await.unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"after-quiet",
            "stream did not survive the quiet window"
        );
    };

    timeout(Duration::from_secs(320), body)
        .await
        .expect("udp idle survival did not complete within 320s");
}
