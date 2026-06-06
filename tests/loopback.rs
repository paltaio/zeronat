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

async fn run_tunnel_test(transport: zeronat::client::Transport) {
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
    ));

    // Client dialing out, mapping public ports to the local echo services.
    tokio::spawn(zeronat::client::run(
        format!("127.0.0.1:{control}"),
        SECRET.into(),
        vec![(public_tcp, format!("127.0.0.1:{local_tcp}"))],
        vec![(public_udp, format!("127.0.0.1:{local_udp}"))],
        transport,
        None,
    ));

    let body = async {
        // TCP: retry until the client has registered and the path is live.
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

        // UDP: retry until a datagram echoes back.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(("127.0.0.1", public_udp)).await.unwrap();
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
