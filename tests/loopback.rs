use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

use zeronat::clientproto::{ClientMsg, SessionMode};
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
        let target = |name: &str, control: u16, secret: &str| zeronat::client::ServerTarget {
            name: name.into(),
            addr: format!("127.0.0.1:{control}"),
            secret: secret.into(),
            transport: zeronat::client::Transport::Tcp,
        };
        let active = zeronat::client::ActiveTarget::new(target("a", control_a, SECRET));
        tokio::spawn(zeronat::client::run_switchable(
            active.clone(),
            vec![fwd(public_a, local_echo), fwd(public_b, local_echo)],
            vec![],
            None,
            None,
            None,
            Some("sw".into()),
            None,
        ));

        // Session up against A: traffic round-trips through A's public port.
        let mut conn = wait_tcp_path(public_a).await;

        // Switch to B. The switch must abort the in-flight session, not sit
        // out the 90s control timeout waiting to notice A is gone: the
        // established relay through A is cut and traffic round-trips through
        // B's public port under B's secret within the 15s bound.
        active.switch(target("b", control_b, SECRET_B));
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
        let psk = zeronat::clientctl::admin_psk();
        let snap = loop {
            if let Ok(stream) = tokio::net::UnixStream::connect(&sock).await {
                if let Ok((mut r, mut w)) = zeronat::noise::client_handshake(stream, &psk).await {
                    w.send(
                        &ClientMsg::ClientAdminHello {
                            version: zeronat::identity::PROTO_VERSION,
                            mode: 0,
                        }
                        .encode(),
                    )
                    .await
                    .unwrap();
                    let frame = r.recv().await.unwrap();
                    match ClientMsg::decode(&frame).unwrap() {
                        ClientMsg::ClientSnapshot(snap) => break snap,
                        other => panic!("expected client snapshot, got {other:?}"),
                    }
                }
            }
            sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(snap.version, zeronat::identity::PROTO_VERSION);
        assert_eq!(snap.active, format!("127.0.0.1:{control}"));
        assert_eq!(snap.mode, SessionMode::Forwards);
        assert_eq!(snap.forwards.len(), 1);
        let f = &snap.forwards[0];
        assert_eq!(f.proto, Proto::Tcp);
        assert_eq!(f.port, public_tcp);
        assert_eq!(f.target, format!("127.0.0.1:{local_tcp}"));
        assert!(!f.proxy);
        assert_eq!(f.idle_secs, 0);

        // Mode 1 carries one mutation and gets a result on the same
        // connection.
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let (mut r, mut w) = zeronat::noise::client_handshake(stream, &psk)
            .await
            .unwrap();
        w.send(
            &ClientMsg::ClientAdminHello {
                version: zeronat::identity::PROTO_VERSION,
                mode: 1,
            }
            .encode(),
        )
        .await
        .unwrap();
        w.send(
            &ClientMsg::SelectServer {
                name: "other".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
        let frame = r.recv().await.unwrap();
        match ClientMsg::decode(&frame).unwrap() {
            ClientMsg::MutationResult { ok, msg } => {
                assert!(!ok);
                assert_eq!(msg, "not implemented");
            }
            other => panic!("expected mutation result, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    };

    timeout(Duration::from_secs(20), body)
        .await
        .expect("client admin socket did not answer within 20s");
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
