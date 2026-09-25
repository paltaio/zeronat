use crate::proto::{path_name, proto_name, provides_name, Msg, RouteEntry, SnapshotBody, Source};
use crate::Result;
use tokio::net::TcpStream;

/// Where the installer writes the deployment env file. `admin` reads its
/// `ZERONAT_ADMIN_SECRET`, or derives one from its `ZERONAT_SEED`, as the
/// final fallback when neither `--secret` nor the environment supplies one.
const ENV_FILE: &str = "/etc/zeronat/.env";

/// Best-effort read of the installer env file's administrative secret.
#[inline(never)]
pub fn admin_secret_from_env_file() -> Option<String> {
    parse_env_admin_secret(&std::fs::read_to_string(ENV_FILE).ok()?)
}

/// The admin secret an env-file body (`KEY=VALUE` lines) yields: its
/// `ZERONAT_ADMIN_SECRET`, else the one derived from its `ZERONAT_SEED`.
fn parse_env_admin_secret(body: &str) -> Option<String> {
    env_value(body, "ZERONAT_ADMIN_SECRET").or_else(|| {
        crate::seed::Seed::parse(&env_value(body, "ZERONAT_SEED")?)
            .ok()
            .map(|seed| seed.admin())
    })
}

fn env_value(body: &str, key: &str) -> Option<String> {
    body.lines().find_map(|line| {
        line.strip_prefix(key)?
            .strip_prefix('=')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

/// Connect to a server's control port, request one snapshot, render it, and exit.
/// Read-only: the admin path never registers as a client or evicts a live one.
#[inline(never)]
pub fn show(
    server: String,
    secret: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
    Box::pin(print_snapshot(server, secret))
}

async fn print_snapshot(server: String, secret: String) -> Result<()> {
    let secret = crate::secret::normalize(&secret)?;
    let psk = crate::noise::derive_psk(&secret);
    let snap = fetch_snapshot(&server, &psk).await?;
    print!("{}", render(&snap, &server));
    Ok(())
}

/// Open a fresh admin connection, request one snapshot, and return it. Each call
/// is a complete connect/handshake/exchange so callers hold no long-lived state.
pub async fn fetch_snapshot(server: &str, psk: &[u8; 32]) -> Result<SnapshotBody> {
    match exchange(server, psk, 0, None).await? {
        Msg::Snapshot(snap) => Ok(snap),
        other => Err(errf!("expected snapshot, got {other:?}")),
    }
}

/// Send one mutation (`AddListener`/`RemoveListener`/`SetRoute`/`ClearRoute`) and
/// return the server's `(ok, message)` verdict. Transport errors propagate as
/// `Err`; an applied-but-rejected mutation comes back as `Ok((false, reason))`.
pub async fn mutate(server: &str, psk: &[u8; 32], req: Msg) -> Result<(bool, String)> {
    match exchange(server, psk, 1, Some(req)).await? {
        Msg::MutationResult { ok, msg } => Ok((ok, msg)),
        other => Err(errf!("expected mutation result, got {other:?}")),
    }
}

/// One admin round trip: connect, handshake, hello in `mode`, the request if
/// any, and the server's one reply.
async fn exchange(server: &str, psk: &[u8; 32], mode: u8, req: Option<Msg>) -> Result<Msg> {
    let sock = TcpStream::connect(server).await?;
    sock.set_nodelay(true).ok();
    let (mut r, mut w) =
        crate::noise::client_handshake_remote(sock, psk, crate::noise::AuthRole::Admin).await?;
    w.send(
        &Msg::AdminHello {
            version: crate::identity::PROTO_VERSION,
            mode,
        }
        .encode(),
    )
    .await?;
    if let Some(req) = req {
        w.send(&req.encode()).await?;
    }
    let body = r.recv().await?;
    Msg::decode(&body)
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
#[inline(never)]
fn render(snap: &SnapshotBody, addr: &str) -> String {
    let mut out = String::new();

    out.push_str("Servers\n");
    out.push_str(&cat(&[
        "  ",
        &pad(&snap.server_id, 8),
        "  connected  ",
        addr,
        "  clients ",
        &num(snap.clients.len() as u64),
        "  bridge ",
        &num(snap.bridge_clients.len() as u64),
        "  routes ",
        &num(snap.routes.len() as u64),
        "  pairs ",
        &num(snap.pairs.len() as u64),
        "\n",
    ]));

    out.push_str("\nRoutes\n");
    if snap.routes.is_empty() {
        out.push_str("  (no routes)\n");
    } else {
        const W: [usize; 8] = [8, 15, 5, 5, 16, 14, 16, 0];
        cols(
            &mut out,
            &W,
            &[
                "SERVER", "BIND IP", "PROTO", "PORT", "TARGET", "STATE", "OPTIONS", "SOURCE",
            ],
        );
        for route in &snap.routes {
            cols(
                &mut out,
                &W,
                &[
                    &snap.server_id,
                    &route.bind_ip.to_string(),
                    proto_name(route.proto),
                    &num(route.port as u64),
                    &route.client_id,
                    route_state(route.state),
                    &route_opts(snap, route),
                    source_name(route.source),
                ],
            );
        }
    }

    out.push_str("\nClients\n");
    if snap.clients.is_empty() {
        out.push_str("  (no clients connected)\n");
    } else {
        for c in &snap.clients {
            out.push_str(&cat(&[
                "  ",
                &c.client_id,
                "  connected to ",
                &snap.server_id,
                "\n",
            ]));
            for e in &c.fwd {
                out.push_str(&cat(&[
                    "    ",
                    proto_name(e.proto),
                    ":",
                    &num(e.port as u64),
                    "  ",
                    &fwd_opts(e.proxy, e.idle_secs),
                    "\n",
                ]));
            }
        }
    }

    out.push_str("\nBridge clients\n");
    if snap.bridge_clients.is_empty() {
        out.push_str("  (no bridge clients)\n");
    } else {
        const W: [usize; 8] = [20, 5, 21, 4, 18, 18, 8, 0];
        cols(
            &mut out,
            &W,
            &[
                "NAME", "TRANS", "PEER", "MACS", "RX", "TX", "UPTIME", "IDLE",
            ],
        );
        for e in &snap.bridge_clients {
            let label = if e.named {
                strip_ctrl(&e.label)
            } else {
                cat(&[&strip_ctrl(&e.label), " (anon)"])
            };
            let peer = if e.peer.is_empty() {
                "-".to_string()
            } else {
                strip_ctrl(&e.peer)
            };
            cols(
                &mut out,
                &W,
                &[
                    &label,
                    transport_name(e.transport),
                    &peer,
                    &num(e.macs.len() as u64),
                    &traffic(e.rx_bytes, e.rx_frames),
                    &traffic(e.tx_bytes, e.tx_frames),
                    &fmt_dur(e.uptime_secs),
                    &fmt_dur(e.idle_secs),
                ],
            );
        }
    }

    out.push_str("\nPairs\n");
    if snap.pairs.is_empty() {
        out.push_str("  (no pairs)\n");
    } else {
        const W: [usize; 4] = [20, 20, 8, 0];
        cols(&mut out, &W, &["CONSUMER", "PROVIDER", "CAP", "PATH"]);
        for p in &snap.pairs {
            cols(
                &mut out,
                &W,
                &[
                    &strip_ctrl(&p.consumer_id),
                    &strip_ctrl(&p.provider_id),
                    provides_name(p.want),
                    p.path.map_or("pairing", path_name),
                ],
            );
        }
    }

    out.push_str("\nListeners\n");
    if snap.listeners.is_empty() {
        out.push_str("  (none)\n");
    } else {
        const W: [usize; 4] = [5, 15, 5, 0];
        cols(&mut out, &W, &["PROTO", "BIND IP", "PORT", "SOURCE"]);
        for l in &snap.listeners {
            cols(
                &mut out,
                &W,
                &[
                    proto_name(l.proto),
                    &l.bind_ip.to_string(),
                    &num(l.port as u64),
                    source_name(l.source),
                ],
            );
        }
    }

    out
}

/// One table row: two leading spaces, each cell padded to its column width
/// (0 leaves it as is), cells two spaces apart, a newline.
fn cols(out: &mut String, widths: &[usize], cells: &[&str]) {
    for (cell, w) in cells.iter().zip(widths) {
        out.push_str("  ");
        out.push_str(&pad(cell, *w));
    }
    out.push('\n');
}

/// Bytes and frames as one `BYTES / FRAMES` cell.
fn traffic(bytes: u64, frames: u64) -> String {
    cat(&[&human_bytes(bytes), " / ", &human_count(frames)])
}

/// The parts joined into one string.
pub(crate) fn cat(parts: &[&str]) -> String {
    let mut s = String::new();
    for p in parts {
        s.push_str(p);
    }
    s
}

pub(crate) fn num(n: u64) -> String {
    n.to_string()
}

/// `text` padded with trailing spaces to `width` columns; longer text is
/// returned whole.
pub(crate) fn pad(text: &str, width: usize) -> String {
    let mut s = String::from(text);
    let n = text.chars().count();
    if n < width {
        s.push_str(&" ".repeat(width - n));
    }
    s
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
pub(crate) fn strip_ctrl(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Human-readable byte count for the fleet view, e.g. "1.5 MB".
pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return cat(&[&num(n), " B"]);
    }
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    cat(&[&one_decimal(v), " ", UNITS[unit]])
}

/// Compact 1000-based frame count for the fleet view, e.g. "900", "1.2k", "24.0k".
pub(crate) fn human_count(n: u64) -> String {
    const UNITS: [&str; 4] = ["", "k", "M", "B"];
    if n < 1000 {
        return num(n);
    }
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    cat(&[&one_decimal(v), UNITS[unit]])
}

/// `v` to one decimal place, correctly rounded with ties to even, for
/// `1.0 <= v < 2^63`.
fn one_decimal(v: f64) -> String {
    let bits = v.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let mant = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    // v = mant * 2^(exp - 1075); ten times that, rounded to an integer.
    let tenths = match exp - 1075 {
        e if e >= 0 => (mant << e) * 10,
        e => {
            let shift = (-e) as u32;
            let x = mant * 10;
            let mut q = x >> shift;
            let rem = x & ((1u64 << shift) - 1);
            let half = 1u64 << (shift - 1);
            if rem > half || (rem == half && q & 1 == 1) {
                q += 1;
            }
            q
        }
    };
    cat(&[&num(tenths / 10), ".", &num(tenths % 10)])
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
        s.push_str("+idle=");
        s.push_str(&num(idle_secs as u64));
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
    use crate::proto::{
        BridgeEntry, ClientEntry, FwdOptionEntry, Listener, PairEntry, PathStatus, Proto, Source,
        PROVIDES_EXIT, PROVIDES_SEGMENT,
    };
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
            pairs: Vec::new(),
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
            pairs: Vec::new(),
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("clients 0"));
        assert!(s.contains("routes 0"));
        assert!(s.contains("(no clients connected)"));
        assert!(s.contains("(no bridge clients)"));
        assert!(s.contains("(no pairs)"));
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
            pairs: Vec::new(),
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

    /// The fleet view lists every accepted pair with the capability it carries
    /// and the path it settled on, including a pair still pairing.
    #[test]
    fn render_pairs() {
        let snap = SnapshotBody {
            version: 1,
            server_id: "0".into(),
            listeners: Vec::new(),
            clients: Vec::new(),
            routes: Vec::new(),
            bridge_clients: Vec::new(),
            pairs: vec![
                PairEntry {
                    consumer_id: "laptop-ab12".into(),
                    provider_id: "office-b1c2".into(),
                    want: PROVIDES_EXIT,
                    path: Some(PathStatus::Direct),
                },
                PairEntry {
                    consumer_id: "znpppoe-42-cd34".into(),
                    provider_id: "office-b1c2".into(),
                    want: PROVIDES_SEGMENT,
                    path: Some(PathStatus::Relay),
                },
                PairEntry {
                    consumer_id: "rpi-ef56".into(),
                    provider_id: "office-b1c2".into(),
                    want: PROVIDES_EXIT,
                    path: None,
                },
            ],
        };
        let s = render(&snap, "vps.example:2222");
        assert!(s.contains("pairs 3"));
        assert!(s.contains("CONSUMER"));
        for row in [
            "laptop-ab12           office-b1c2           exit      direct",
            "znpppoe-42-cd34       office-b1c2           segment   relay",
            "rpi-ef56              office-b1c2           exit      pairing",
        ] {
            assert!(s.contains(row), "{s}");
        }
    }

    #[test]
    fn one_decimal_matches_fixed_formatting() {
        for v in [
            1.0, 1.25, 1.35, 2.5, 9.95, 9.96, 999.95, 1023.99, 1.05, 3.94159,
        ] {
            assert_eq!(one_decimal(v), format!("{v:.1}"), "{v}");
        }
        let mut x: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = x >> (x % 40);
            assert_eq!(human_bytes(n), reference_bytes(n), "{n}");
            assert_eq!(human_count(n), reference_count(n), "{n}");
        }
    }

    fn reference_bytes(n: u64) -> String {
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

    fn reference_count(n: u64) -> String {
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

    #[test]
    fn human_count_scales() {
        assert_eq!(human_count(0), "0");
        assert_eq!(human_count(900), "900");
        assert_eq!(human_count(1200), "1.2k");
        assert_eq!(human_count(24010), "24.0k");
    }

    #[test]
    fn parse_env_admin_secret_reads_the_value() {
        let body = "ZERONAT_ADMIN_SECRET=deadbeef\nZERONAT_ARGS=server --control 2222\n";
        assert_eq!(parse_env_admin_secret(body).as_deref(), Some("deadbeef"));
        // Missing or empty value yields nothing.
        assert_eq!(parse_env_admin_secret("ZERONAT_ARGS=server\n"), None);
        assert_eq!(parse_env_admin_secret("ZERONAT_ADMIN_SECRET=\n"), None);
    }

    #[test]
    fn parse_env_admin_secret_derives_from_the_seed() {
        let seed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let derived = crate::seed::Seed::parse(seed).unwrap().admin();
        let body = format!("ZERONAT_SEED={seed}\nZERONAT_ARGS=server\n");
        assert_eq!(
            parse_env_admin_secret(&body).as_deref(),
            Some(derived.as_str())
        );
        // An explicit admin secret wins over the seed.
        let body = format!("ZERONAT_SEED={seed}\nZERONAT_ADMIN_SECRET=deadbeef\n");
        assert_eq!(parse_env_admin_secret(&body).as_deref(), Some("deadbeef"));
        assert_eq!(parse_env_admin_secret("ZERONAT_SEED=short\n"), None);
    }
}
