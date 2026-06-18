use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

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
    use zeronat::proto::{Msg, Proto};

    let body = async {
        let tunnel = start_tunnel(zeronat::client::Transport::Tcp);

        // Drive the TCP path first so the ClientHello has registered the client.
        let mut conn = wait_tcp_path(tunnel.public_tcp).await;

        // Fresh admin connection to the control port.
        let sock = TcpStream::connect(("127.0.0.1", tunnel.control))
            .await
            .unwrap();
        sock.set_nodelay(true).ok();
        let psk = zeronat::noise::derive_psk(SECRET);
        let (mut r, mut w) = zeronat::noise::client_handshake(sock, &psk).await.unwrap();
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
        let snap = match Msg::decode(&frame).unwrap() {
            Msg::Snapshot(snap) => snap,
            other => panic!("expected snapshot, got {other:?}"),
        };
        assert_eq!(snap.server_id, "0");
        assert!(snap
            .listeners
            .iter()
            .any(|l| l.proto == Proto::Tcp && l.port == tunnel.public_tcp));
        assert!(snap
            .listeners
            .iter()
            .any(|l| l.proto == Proto::Udp && l.port == tunnel.public_udp));
        let client = snap.client.expect("client present");
        assert!(client.client_id.starts_with("rpi-"));

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
