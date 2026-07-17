//! Drive the client admin console over a real pseudo-terminal.
//!
//! The binary re-executes itself as the console child: the driver allocates a
//! pty pair, spawns `current_exe` with the child env var set, and the child
//! runs `zeronat::tui::run_client` with the pty slave as its stdio, exactly
//! the raw-mode/stdin/stdout path the console uses in production. The driver
//! feeds key bytes to the pty master, reconstructs the screen from the
//! renderer's cursor-addressed output, and asserts against a live loopback
//! tunnel: a server, a config-driven client with an admin socket, and a local
//! echo service capturing what actually reaches the forward target.

#[cfg(all(feature = "tui", unix))]
mod pty {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, timeout};

    use zeronat::proto::{Proto, Source};
    use zeronat::server::{ListenerSpec, ServerSettings};

    const SECRET: &str = "console-pty-test-secret";
    /// Carries the admin socket path into the re-executed console child.
    const CHILD_ENV: &str = "ZERONAT_CONSOLE_PTY_CHILD";

    pub fn main() {
        if let Some(sock) = std::env::var_os(CHILD_ENV) {
            child(PathBuf::from(sock));
            return;
        }
        driver();
        println!("console_pty: ok");
    }

    /// The console process: plain `run_client` on the inherited pty stdio.
    fn child(sock: PathBuf) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("child runtime");
        if let Err(e) = rt.block_on(zeronat::tui::run_client(Some(sock))) {
            eprintln!("console failed: {e}");
            std::process::exit(1);
        }
    }

    // ---- pty plumbing ------------------------------------------------------

    struct Pty {
        master: std::fs::File,
        slave: std::fs::File,
    }

    fn open_pty() -> Pty {
        // SAFETY: plain libc pty allocation; the raw fd is immediately owned
        // by a File and never used elsewhere.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "posix_openpt failed");
            assert_eq!(libc::grantpt(master), 0, "grantpt failed");
            assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
            let ws = libc::winsize {
                ws_row: 32,
                ws_col: 100,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            assert_eq!(
                libc::ioctl(master, libc::TIOCSWINSZ, &ws),
                0,
                "TIOCSWINSZ failed"
            );
            let mut buf = [0u8; 128];
            assert_eq!(
                libc::ptsname_r(master, buf.as_mut_ptr().cast(), buf.len()),
                0,
                "ptsname_r failed"
            );
            let end = buf.iter().position(|&b| b == 0).unwrap();
            let name = std::str::from_utf8(&buf[..end]).unwrap();
            let slave = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(name)
                .expect("open pty slave");
            Pty {
                master: std::fs::File::from_raw_fd(master),
                slave,
            }
        }
    }

    /// Kills the console child on drop, so a panicking assert cannot leave a
    /// stray process holding the pty.
    struct KillOnDrop(Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Everything the console child ever wrote to the pty, appended by a
    /// reader thread; the screen is reconstructed from it on demand.
    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);

    impl Output {
        fn screen(&self) -> Vec<String> {
            parse_screen(&self.0.lock().unwrap())
        }
    }

    /// Replay the renderer's cursor-addressed stream into screen rows. The
    /// renderer writes whole rows: position (`CSI r;1 H`), erase (`CSI 2K`),
    /// then the row text; `CSI 2J` clears; SGR and mode sequences carry no
    /// content and are dropped, so rows come back as plain text.
    fn parse_screen(bytes: &[u8]) -> Vec<String> {
        let s = String::from_utf8_lossy(bytes);
        let mut rows: Vec<String> = Vec::new();
        let mut cur = 0usize;
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '\u{1b}' {
                if c == '\r' || c == '\n' {
                    continue;
                }
                while rows.len() <= cur {
                    rows.push(String::new());
                }
                rows[cur].push(c);
                continue;
            }
            if chars.peek() != Some(&'[') {
                continue;
            }
            chars.next();
            let mut params = String::new();
            let mut fin = '\0';
            for d in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&d) {
                    fin = d;
                    break;
                }
                params.push(d);
            }
            match fin {
                'H' => {
                    let row: usize = params.split(';').next().unwrap_or("1").parse().unwrap_or(1);
                    cur = row.saturating_sub(1);
                }
                'J' => rows.clear(),
                'K' => {
                    if let Some(r) = rows.get_mut(cur) {
                        r.clear();
                    }
                }
                _ => {}
            }
        }
        rows
    }

    fn send(master: &mut std::fs::File, bytes: &[u8]) {
        master.write_all(bytes).expect("write to pty master");
        master.flush().expect("flush pty master");
    }

    /// Poll the reconstructed screen until `pred` holds, panicking with a
    /// screen dump on timeout.
    fn wait_screen(out: &Output, what: &str, secs: u64, pred: impl Fn(&[String]) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let screen = out.screen();
            if pred(&screen) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; screen:\n{}",
                screen.join("\n")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn row_containing(screen: &[String], needle: &str) -> Option<String> {
        screen.iter().find(|r| r.contains(needle)).cloned()
    }

    // ---- loopback fixture --------------------------------------------------

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

    /// Echoes back every chunk it receives, so the echoed stream is a
    /// faithful capture of what reached the forward target.
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

    fn server_settings(control: u16, tcp: u16, udp: u16) -> ServerSettings {
        ServerSettings {
            bind: std::net::Ipv4Addr::LOCALHOST,
            control_port: control,
            secret: SECRET.into(),
            server_id: "0".into(),
            tap: None,
            tun: None,
            dht: None,
            listeners: vec![
                ListenerSpec {
                    bind_ip: std::net::Ipv4Addr::LOCALHOST,
                    proto: Proto::Tcp,
                    port: tcp,
                    source: Source::Runtime,
                    cli_locked: false,
                },
                ListenerSpec {
                    bind_ip: std::net::Ipv4Addr::LOCALHOST,
                    proto: Proto::Udp,
                    port: udp,
                    source: Source::Runtime,
                    cli_locked: false,
                },
            ],
            routes: Vec::new(),
            config_path: None,
            file_id: None,
            file_control: None,
        }
    }

    fn forward(port: u16, target: u16) -> zeronat::client::Forward {
        zeronat::client::Forward {
            port,
            target: format!("127.0.0.1:{target}"),
            proxy: false,
            idle: None,
            enabled: true,
        }
    }

    /// Round-trip `payload` through the public port on a fresh connection,
    /// retrying until the tunnel serves it; returns the exact bytes the echo
    /// reflected (`want` of them) and the connecting socket's address.
    async fn echo_roundtrip(
        public: u16,
        payload: &[u8],
        want: usize,
    ) -> (Vec<u8>, std::net::SocketAddr) {
        'outer: loop {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", public)).await {
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
                    return (buf, src);
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn snapshot(sock: &Path) -> zeronat::clientproto::ClientSnapshotBody {
        loop {
            if let Ok(snap) = zeronat::client_admin::snapshot(sock).await {
                return snap;
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    // ---- the scenario ------------------------------------------------------

    fn driver() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("driver runtime");
        rt.block_on(async {
            timeout(Duration::from_secs(240), scenario())
                .await
                .expect("console pty scenario did not complete within 240s");
        });
    }

    async fn scenario() {
        let control = free_tcp_port();
        let public_tcp = free_tcp_port();
        let public_udp = free_udp_port();
        let local_tcp = free_tcp_port();
        let local_udp = free_udp_port();
        tokio::spawn(tcp_echo(local_tcp));
        tokio::spawn(zeronat::server::run(server_settings(
            control, public_tcp, public_udp,
        )));

        // A config-driven client: two server profiles (only `home` is ever
        // dialed) and two forwards, persisted to a real file the mutations
        // rewrite.
        let dir = std::env::temp_dir().join(format!("zeronat-console-pty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        let sock = dir.join("client.sock");
        let text = format!(
            "[client]\nactive = \"home\"\n\
             [[servers]]\nname = \"home\"\naddr = \"127.0.0.1:{control}\"\nsecret = \"{SECRET}\"\ntransport = \"tcp\"\n\
             [[servers]]\nname = \"away\"\naddr = \"192.0.2.9:9000\"\nsecret = \"other\"\ntransport = \"tcp\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = {public_tcp}\ntarget = \"127.0.0.1:{local_tcp}\"\n\
             [[forwards]]\nproto = \"udp\"\nport = {public_udp}\ntarget = \"127.0.0.1:{local_udp}\"\n"
        );
        std::fs::write(&path, &text).unwrap();
        let cfg = zeronat::clientcfg::parse_client(&text).unwrap();
        cfg.validate().unwrap();
        let home = zeronat::client::ServerTarget {
            name: "home".into(),
            addr: format!("127.0.0.1:{control}"),
            secret: SECRET.into(),
            transport: zeronat::client::Transport::Tcp,
        };
        let away = zeronat::client::ServerTarget {
            name: "away".into(),
            addr: "192.0.2.9:9000".into(),
            secret: "other".into(),
            transport: zeronat::client::Transport::Tcp,
        };
        let settings = zeronat::client::ClientSettings {
            servers: vec![home.clone(), away],
            tcp: vec![forward(public_tcp, local_tcp)],
            udp: vec![forward(public_udp, local_udp)],
            tap: None,
            tun: None,
            pppoe: vec![],
            autostart: None,
            id_prefix: Some("pty".into()),
            control: Some(zeronat::clientctl::ControlPath::Explicit(sock.clone())),
            config: Some((path.clone(), cfg)),
        };
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(home),
            settings,
        ));

        // Baseline: the tunnel is up and the target sees the payload with no
        // injected prefix.
        let payload = b"pty-proxied-payload";
        let (bytes, _) = echo_roundtrip(public_tcp, payload, payload.len()).await;
        assert_eq!(&bytes, payload, "baseline forward injected bytes");

        // Spawn the console on the pty and mirror its screen.
        let pty = open_pty();
        let child = Command::new(std::env::current_exe().unwrap())
            .env(CHILD_ENV, &sock)
            .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
            .stdout(Stdio::from(pty.slave))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn console child");
        let mut child = KillOnDrop(child);
        let mut master = pty.master;
        let out = Output::default();
        {
            let out = out.clone();
            let mut reader = master.try_clone().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => out.0.lock().unwrap().extend_from_slice(&buf[..n]),
                    }
                }
            });
        }

        // The servers panel lists both profiles; the marker sits on the
        // active row only. The sessions panel lists both forwards with their
        // targets and (default) modifiers.
        wait_screen(&out, "the initial panels", 20, |s| {
            row_containing(s, "192.0.2.9:9000").is_some()
                && row_containing(s, &format!(":{public_tcp}")).is_some()
                && row_containing(s, &format!(":{public_udp}")).is_some()
                && row_containing(s, "mode").is_some_and(|r| r.contains("forwards"))
        });
        let screen = out.screen();
        let home_row = row_containing(&screen, &format!("127.0.0.1:{control}")).unwrap();
        assert!(home_row.contains("home"), "home row: {home_row}");
        assert!(home_row.contains("● active"), "home row: {home_row}");
        let away_row = row_containing(&screen, "192.0.2.9:9000").unwrap();
        assert!(away_row.contains("away"), "away row: {away_row}");
        assert!(
            !away_row.contains("active"),
            "inactive row must show config fields only: {away_row}"
        );
        let tcp_row = row_containing(&screen, &format!(":{public_tcp}")).unwrap();
        assert!(
            tcp_row.contains(&format!("-> 127.0.0.1:{local_tcp}")),
            "tcp forward row: {tcp_row}"
        );
        assert!(
            !tcp_row.contains('+'),
            "default options must render bare: {tcp_row}"
        );

        // Rows: home(0), away(1), tcp forward(2), udp forward(3). Open the
        // tcp forward's option editor and flip proxy on, idle 600. The form
        // leads with the enabled toggle, so proxy is one tab in.
        send(&mut master, b"\x1b[B\x1b[B\r");
        wait_screen(&out, "the forward editor", 10, |s| {
            row_containing(s, &format!("edit forward  tcp:{public_tcp}")).is_some()
        });
        send(&mut master, b"\t "); // to proxy, toggle on
        wait_screen(&out, "proxy toggled on", 10, |s| {
            row_containing(s, "proxy").is_some_and(|r| r.contains(" on "))
        });
        send(&mut master, b"\t600\r");
        wait_screen(&out, "the accepted-edit toast", 10, |s| {
            row_containing(s, &format!("set tcp:{public_tcp} +proxy+idle=600")).is_some()
        });

        // The mutation redials the forwards session and re-announces the
        // options: the next connection reaches the target with an exact PROXY
        // v2 header in front of the payload.
        let want = 28 + payload.len();
        let (bytes, src) = timeout(
            Duration::from_secs(30),
            echo_roundtrip(public_tcp, payload, want),
        )
        .await
        .expect("proxied roundtrip after the flip did not complete within 30s");
        assert_eq!(
            &bytes[..12],
            &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A],
            "PROXY v2 signature"
        );
        assert_eq!(bytes[12], 0x21, "version/command");
        assert_eq!(bytes[13], 0x11, "AF_INET/STREAM");
        assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 12, "length");
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
        assert_eq!(&bytes[28..], payload, "payload follows the header");

        // The edit landed in the daemon and on disk, and the polled screen
        // shows the forward with its new modifiers.
        let snap = snapshot(&sock).await;
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Tcp && f.port == public_tcp)
            .expect("tcp forward in snapshot");
        assert!(f.proxy);
        assert_eq!(f.idle_secs, 600);
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        assert!(on_disk.forwards.iter().any(|f| f.proxy));
        wait_screen(&out, "the refreshed forward row", 10, |s| {
            row_containing(s, &format!(":{public_tcp}"))
                .is_some_and(|r| r.contains("+proxy+idle=600"))
        });

        // Validation refusal: proxy on the udp forward. The daemon's message
        // surfaces verbatim in the toast and nothing changes.
        send(&mut master, b"\x1b[B\r");
        wait_screen(&out, "the udp forward editor", 10, |s| {
            row_containing(s, &format!("edit forward  udp:{public_udp}")).is_some()
        });
        send(&mut master, b"\t \r");
        wait_screen(&out, "the refusal toast", 10, |s| {
            row_containing(s, "is not supported on udp forwards").is_some()
        });
        let snap = snapshot(&sock).await;
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Udp && f.port == public_udp)
            .expect("udp forward in snapshot");
        assert!(!f.proxy, "a refused mutation must change nothing");

        // Idle 0 clears: reopen the tcp editor (prefilled 600), erase the
        // idle field, submit. Proxy stays on; the override is gone.
        send(&mut master, b"\x1b[A\r");
        wait_screen(&out, "the tcp editor again", 10, |s| {
            row_containing(s, &format!("edit forward  tcp:{public_tcp}")).is_some()
        });
        send(&mut master, b"\t\t\x7f\x7f\x7f\r");
        wait_screen(&out, "the cleared-idle toast", 10, |s| {
            row_containing(s, &format!("set tcp:{public_tcp} +proxy"))
                .is_some_and(|r| !r.contains("idle"))
        });
        let snap = snapshot(&sock).await;
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Tcp && f.port == public_tcp)
            .expect("tcp forward in snapshot");
        assert!(f.proxy);
        assert_eq!(f.idle_secs, 0);
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        let entry = on_disk
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Tcp && f.port == public_tcp)
            .expect("tcp forward on disk");
        assert!(entry.proxy);
        assert_eq!(entry.idle, None);

        // Space on a forward row is the enable toggle: the udp forward goes
        // off in the daemon and on disk, and its row gains the off marker.
        send(&mut master, b"\x1b[B "); // down to the udp row, toggle
        wait_screen(&out, "the disable toast", 10, |s| {
            row_containing(s, &format!("disabled udp:{public_udp}")).is_some()
        });
        let snap = snapshot(&sock).await;
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Udp && f.port == public_udp)
            .expect("udp forward in snapshot");
        assert!(!f.enabled, "the toggle must disable the forward");
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        let entry = on_disk
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Udp && f.port == public_udp)
            .expect("udp forward on disk");
        assert!(!entry.enabled);
        wait_screen(&out, "the off marker", 10, |s| {
            row_containing(s, &format!("-> 127.0.0.1:{local_udp}"))
                .is_some_and(|r| r.contains(" off"))
        });

        // Space again re-enables; the full-state frame preserved the options.
        send(&mut master, b" ");
        wait_screen(&out, "the enable toast", 10, |s| {
            row_containing(s, &format!("enabled udp:{public_udp}")).is_some()
        });
        let snap = snapshot(&sock).await;
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Udp && f.port == public_udp)
            .expect("udp forward in snapshot");
        assert!(f.enabled);

        // The add-server form masks the secret: one * per typed character,
        // and the typed text never reaches the screen.
        send(&mut master, b"a");
        wait_screen(&out, "the add-server form", 10, |s| {
            row_containing(s, "add server").is_some()
        });
        send(&mut master, b"\t\t\thunter2"); // to the secret field, type
        wait_screen(&out, "the masked secret", 10, |s| {
            row_containing(s, "*******").is_some()
        });
        let screen = out.screen();
        assert!(
            row_containing(&screen, "hunter2").is_none(),
            "secret text leaked to the screen"
        );
        send(&mut master, b"\x1b");
        wait_screen(&out, "the form closed", 10, |s| {
            row_containing(s, "add server").is_none()
        });

        // d confirms and parks the client offline: the mode row flips, the
        // daemon reports it, and the active row's link goes offline.
        send(&mut master, b"d");
        wait_screen(&out, "the disconnect confirm", 10, |s| {
            row_containing(s, "disconnect and stay offline").is_some()
        });
        send(&mut master, b"y");
        wait_screen(&out, "the offline mode", 15, |s| {
            row_containing(s, "mode").is_some_and(|r| r.contains("offline"))
        });
        let snap = snapshot(&sock).await;
        assert_eq!(snap.mode, zeronat::clientproto::SessionMode::Offline);

        // c is the park's exit: the boot-derived forwards body comes back and
        // the tunnel really redials, shown by the link on the active row.
        send(&mut master, b"c");
        wait_screen(&out, "the forwards mode again", 15, |s| {
            row_containing(s, "mode").is_some_and(|r| r.contains("forwards"))
        });
        wait_screen(&out, "the reconnected link", 30, |s| {
            row_containing(s, "● active").is_some_and(|r| r.contains("connected"))
        });
        let snap = snapshot(&sock).await;
        assert_eq!(snap.mode, zeronat::clientproto::SessionMode::Forwards);

        // Quit cleanly.
        send(&mut master, b"q");
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait().expect("wait console child") {
                break status;
            }
            assert!(Instant::now() < deadline, "console did not exit on q");
            sleep(Duration::from_millis(50)).await;
        };
        assert!(status.success(), "console exited with {status}");

        std::fs::remove_dir_all(&dir).ok();
    }
}

fn main() {
    #[cfg(all(feature = "tui", unix))]
    pty::main();
}
