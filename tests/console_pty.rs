//! Drive the client admin console over a real pseudo-terminal.
//!
//! The binary re-executes itself as the console child: the driver allocates a
//! pty pair, spawns `current_exe` with the child env var set, and the child
//! runs `zeronat::tui::run_client` with the pty slave as its stdio, exactly
//! the raw-mode/stdin/stdout path the console uses in production. The driver
//! feeds key bytes to the pty master, reconstructs the screen from the
//! renderer's cursor-addressed output, and asserts against a live loopback
//! tunnel: a server, a config-driven client with an admin socket, a second
//! client providing the exit bit so a real pair forms, and a local echo
//! service capturing what actually reaches the forward target. The server
//! console runs on a pty of its own against the same server.

// A test crate cannot see the crate-private spawn helper, and its tasks are not
// in the shipped binary.
#![allow(clippy::disallowed_methods)]

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

    use zeronat::proto::{Proto, Source, PROVIDES_EXIT};
    use zeronat::server::{ListenerSpec, ServerSettings};

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER_SECRET: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    /// Carries the admin socket path into the re-executed console child.
    const CHILD_ENV: &str = "ZERONAT_CONSOLE_PTY_CHILD";
    /// Carries the server address into the re-executed fleet-console child.
    const SERVER_CHILD_ENV: &str = "ZERONAT_CONSOLE_PTY_SERVER_CHILD";

    pub fn main() {
        if let Some(sock) = std::env::var_os(CHILD_ENV) {
            child(PathBuf::from(sock));
            return;
        }
        if let Some(addr) = std::env::var_os(SERVER_CHILD_ENV) {
            server_child(addr.to_string_lossy().into_owned());
            return;
        }
        driver();
        println!("console_pty: ok");
    }

    fn child_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("child runtime")
    }

    /// The client console process: plain `run_client` on the inherited pty
    /// stdio.
    fn child(sock: PathBuf) {
        if let Err(e) = child_runtime().block_on(zeronat::tui::run_client(Some(sock))) {
            eprintln!("console failed: {e}");
            std::process::exit(1);
        }
    }

    /// The fleet console process: `run` against one server's control port.
    fn server_child(addr: String) {
        if let Err(e) = child_runtime().block_on(zeronat::tui::run(addr, OTHER_SECRET.into())) {
            eprintln!("fleet console failed: {e}");
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

    /// Spawn one console on its own pty, mirroring everything it writes.
    /// The child re-executes this binary with `env` naming what to run.
    fn spawn_console(env: &str, value: &std::ffi::OsStr) -> (KillOnDrop, std::fs::File, Output) {
        let pty = open_pty();
        let child = Command::new(std::env::current_exe().unwrap())
            .env(env, value)
            .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
            .stdout(Stdio::from(pty.slave))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn console child");
        let master = pty.master;
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
        (KillOnDrop(child), master, out)
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

    /// Claim a port for the code under test to bind. A claimed number is probed
    /// on TCP and UDP: the control port carries both, and one protocol being
    /// free says nothing about the other.
    ///
    /// `20000..32768` sits below the Linux default `ip_local_port_range`, so on
    /// this platform the kernel does not draw ephemeral source ports from it.
    /// Fixed-port daemons do sit in that window, and a host can be configured
    /// with a lower range; the probes cover both cases.
    ///
    /// The guarantees are per process: a number goes out at most once, and
    /// both binds succeeded moments before it was returned. Another process
    /// can still take a claimed port before the caller binds it, so the walk
    /// starts at a pid-derived offset to keep concurrent test runs off each
    /// other's numbers.
    fn free_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        const LO: u16 = 20000;
        const HI: u16 = 32768;
        const SPAN: u16 = HI - LO;
        // Coprime with SPAN, so neighbouring pids start far apart.
        const STRIDE: u64 = 1013;
        static TAKEN: AtomicU16 = AtomicU16::new(0);
        let start = (u64::from(std::process::id()) * STRIDE % u64::from(SPAN)) as u16;
        loop {
            let taken = TAKEN.fetch_add(1, Ordering::Relaxed);
            assert!(taken < SPAN, "test ports exhausted: {LO}..{HI}");
            let port = LO + (start + taken) % SPAN;
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
                && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
            {
                return port;
            }
        }
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

    fn server_settings(control: u16, tcp: u16, udp: u16, routed: &str) -> ServerSettings {
        ServerSettings {
            bind: std::net::Ipv4Addr::LOCALHOST,
            control_port: control,
            secret: SECRET.into(),
            admin_secret: Some(OTHER_SECRET.into()),
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
            // Two clients are connected, so the forwards need an explicit
            // route to the one the console drives.
            routes: [Proto::Tcp, Proto::Udp]
                .into_iter()
                .zip([tcp, udp])
                .map(|(proto, port)| zeronat::server::RouteSpec {
                    bind_ip: std::net::Ipv4Addr::LOCALHOST,
                    proto,
                    port,
                    client_id: routed.to_string(),
                    source: Source::Runtime,
                })
                .collect(),
            config_path: None,
            file_id: None,
            file_control: None,
            file_admin_secret: None,
            file_exit: None,
            file_exit_iface: None,
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
        let control = free_port();
        let public_tcp = free_port();
        let public_udp = free_port();
        let local_tcp = free_port();
        let local_udp = free_port();
        tokio::spawn(tcp_echo(local_tcp));
        let client_id = zeronat::identity::derive_client_id(Some("pty"));
        let provider_id = zeronat::identity::derive_client_id(Some("ptyexit"));
        tokio::spawn(zeronat::server::run(server_settings(
            control, public_tcp, public_udp, &client_id,
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
             [[servers]]\nname = \"away\"\naddr = \"192.0.2.9:9000\"\nsecret = \"{OTHER_SECRET}\"\ntransport = \"tcp\"\n\
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
            secret: OTHER_SECRET.into(),
            transport: zeronat::client::Transport::Tcp,
        };
        // The peer the console client exits through: a second client
        // announcing the exit bit with no adapter, so the pair carries frames
        // and opens no device. Both sinks stay alive for the whole scenario;
        // a dropped one would end the slot that hands its session over.
        let (prov_tx, mut prov_rx) = tokio::sync::mpsc::channel(4);
        let provider = zeronat::client::ClientSettings {
            servers: vec![home.clone()],
            tcp: vec![],
            udp: vec![],
            tap: None,
            tun: None,
            pppoe: vec![],
            autostart: None,
            id_prefix: Some("ptyexit".into()),
            control: None,
            config: None,
            peers: vec![zeronat::client::PeerSlotSpec::Provider {
                provides: PROVIDES_EXIT,
                adapter: None,
            }],
            peer_sessions: Some(prov_tx),
        };
        tokio::spawn(zeronat::client::run_switchable(
            zeronat::client::ActiveTarget::new(home.clone()),
            provider,
        ));

        let (cons_tx, mut cons_rx) = tokio::sync::mpsc::channel(4);
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
            peers: vec![zeronat::client::PeerSlotSpec::Consumer {
                peer_id: provider_id.clone(),
                want: PROVIDES_EXIT,
                adapter: None,
            }],
            peer_sessions: Some(cons_tx),
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
        let (mut child, mut master, out) = spawn_console(CHILD_ENV, sock.as_os_str());

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

        // Both clients reach the pair and name each other. Their sessions stay
        // bound for the rest of the scenario; dropping one would end the slot
        // the consoles below read. The tcp control transport lets neither
        // party probe, so the pair settles relayed.
        let consumer_slot = timeout(Duration::from_secs(120), cons_rx.recv())
            .await
            .expect("the consumer slot never paired")
            .expect("the consumer sink closed");
        let provider_slot = timeout(Duration::from_secs(120), prov_rx.recv())
            .await
            .expect("the provider slot never paired")
            .expect("the provider sink closed");
        assert_eq!(consumer_slot.peer_id, provider_id);
        assert_eq!(provider_slot.peer_id, client_id);

        // The client's peers panel names the slot, the peer it exits through,
        // and the path its pair settled on.
        wait_screen(&out, "the peer slot row", 30, |s| {
            row_containing(s, &format!("via {provider_id}"))
                .is_some_and(|r| r.contains("connected") && r.contains("relay"))
        });
        let peer_row = row_containing(&out.screen(), &format!("via {provider_id}")).unwrap();
        assert!(peer_row.contains("exit"), "peer row: {peer_row}");

        // The fleet console lists the same pair from the server's side, with
        // the capability it carries and the path both parties settled on.
        let (fleet, _fleet_master, fleet_out) = spawn_console(
            SERVER_CHILD_ENV,
            std::ffi::OsStr::new(&format!("127.0.0.1:{control}")),
        );
        wait_screen(&fleet_out, "the fleet pairs panel", 60, |s| {
            s.iter().any(|r| {
                r.contains(&client_id)
                    && r.contains(&provider_id)
                    && r.contains("exit")
                    && r.contains("relay")
            })
        });
        let fleet_screen = fleet_out.screen();
        assert!(
            row_containing(&fleet_screen, "PAIRS").is_some_and(|r| r.contains('1')),
            "fleet screen:\n{}",
            fleet_screen.join("\n")
        );
        drop(fleet);
        // The mutations below bounce the control session, and every pair that
        // forms after this one is left to the slots.
        drop(consumer_slot);
        drop(provider_slot);

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

        // The f form adds a forward: proto stays on tcp, port typed, target
        // left blank so the daemon resolves the 127.0.0.1:PORT default. No
        // server listener exists for it, so the asserts are snapshot-driven.
        let new_port = free_port();
        send(&mut master, b"f");
        wait_screen(&out, "the add-forward form", 10, |s| {
            row_containing(s, "add forward").is_some()
        });
        send(&mut master, b"\t");
        send(&mut master, new_port.to_string().as_bytes());
        // The blank target renders the default it will resolve to.
        wait_screen(&out, "the rendered default target", 10, |s| {
            row_containing(s, &format!("127.0.0.1:{new_port}")).is_some()
        });
        send(&mut master, b"\r");
        wait_screen(&out, "the added-forward toast", 10, |s| {
            row_containing(s, &format!("added tcp:{new_port}")).is_some()
        });
        wait_screen(&out, "the new forward row", 10, |s| {
            row_containing(s, &format!("-> 127.0.0.1:{new_port}")).is_some()
        });
        let snap = snapshot(&sock).await;
        let f = snap
            .forwards
            .iter()
            .find(|f| f.proto == Proto::Tcp && f.port == new_port)
            .expect("added forward in snapshot");
        assert_eq!(f.target, format!("127.0.0.1:{new_port}"));
        assert!(f.enabled);
        assert_eq!(f.idle_secs, 0);
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        assert!(on_disk
            .forwards
            .iter()
            .any(|f| f.port == new_port && f.target == format!("127.0.0.1:{new_port}")));

        // x on the new forward's row confirms and removes it. Rows are the
        // two servers, then tcp forwards sorted by port, then the udp one;
        // ports are claimed in ascending order, so the added one sorts last.
        let tcp_row = 3;
        send(
            &mut master,
            &[b"\x1b[A".repeat(8), b"\x1b[B".repeat(tcp_row)].concat(),
        );
        send(&mut master, b"x");
        wait_screen(&out, "the remove-forward confirm", 10, |s| {
            row_containing(s, &format!("remove forward tcp:{new_port}")).is_some()
        });
        send(&mut master, b"y");
        wait_screen(&out, "the removed-forward toast", 10, |s| {
            row_containing(s, &format!("removed tcp:{new_port}")).is_some()
        });
        wait_screen(&out, "the forward row gone", 10, |s| {
            row_containing(s, &format!("-> 127.0.0.1:{new_port}")).is_none()
        });
        let snap = snapshot(&sock).await;
        assert!(
            !snap
                .forwards
                .iter()
                .any(|f| f.proto == Proto::Tcp && f.port == new_port),
            "removed forward still in the snapshot"
        );
        let on_disk = zeronat::clientcfg::load(&path).expect("persisted config parses");
        assert!(!on_disk.forwards.iter().any(|f| f.port == new_port));

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
