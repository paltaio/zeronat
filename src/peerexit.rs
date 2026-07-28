//! The L3 adapter an exit provider runs for the pair it serves: a tun device on
//! the provider's end of the pair's derived subnet, the switch that moves IP
//! packets between that device and the inner session, and the masquerade that
//! puts the consumer's traffic on this node's uplink.
//!
//! Everything the adapter opens lives in the future that runs it, so dropping
//! that future closes the device and removes the rules. The slot that owns it
//! is what a profile switch awaits, which is how the next slot set finds the
//! interface free.

use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::bridge::TapSwitch;
use crate::netfilter::{self, NatPlan};
use crate::peer::PeerSession;
use crate::peerslot::PeerExit;
use crate::tap::{TapDevice, TunConfig};
use crate::Result;

/// Prefix length of the tunnel the pair shares, matching the `/24` a server
/// tun assigns.
const TUN_PREFIX_LEN: u8 = 24;

/// A peer session is neither of the two control transports the switch records
/// for its ports, and direct and relayed are the same thing above it.
const TRANSPORT_PEER: u8 = 0;

/// What the provider can settle about its bringup before a pair arrives: the
/// interface the pair's traffic would leave by, and the capability opening the
/// tun needs. Both outlive any one pair, so a failure here is what refuses the
/// pairs that follow, rather than a hangup after each handshake.
pub(crate) fn precheck(exit: &PeerExit) -> Result<()> {
    let route_table = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    egress_iface(&exit.device, exit.iface.as_deref(), &route_table)?;
    if !has_net_admin() {
        return Err(format!(
            "this process may not open the tun {}; it holds no CAP_NET_ADMIN",
            exit.device
        )
        .into());
    }
    Ok(())
}

/// Serve one pair: bring the tun up, install the masquerade for the pair's
/// subnet, and carry IP packets both ways until the session dies. An error is
/// a bringup this provider cannot do, which the caller holds against the pairs
/// that follow.
pub(crate) async fn serve(session: PeerSession, exit: &PeerExit, secret: &str) -> Result<()> {
    let cfg = tun_config(exit, secret);
    let route_table = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let egress = egress_iface(&cfg.name, exit.iface.as_deref(), &route_table)?;
    let dev = Arc::new(TapDevice::open_tun(&cfg)?);
    let nat = install_nat(nat_plan(&cfg, egress.clone())).await;
    if let Some(guard) = &nat {
        crate::elog!(
            "peer exit {}: masquerading the pair's traffic out {egress} via {}",
            cfg.name,
            guard.backend_name(),
        );
    }
    run_switch(dev, session).await;
    // Awaited, not detached: the rules live in a table the next install
    // recreates, so a delete still queued when the next pair installs would
    // strip it. An adapter dropped mid-pair never reaches this and falls back
    // to the guard's own `Drop`, which is synchronous and is what a profile
    // switch's barrier relies on.
    if let Some(guard) = nat {
        tokio::task::spawn_blocking(move || drop(guard)).await.ok();
    }
    Ok(())
}

/// Program the masquerade off the runtime: `install` forks and waits on the
/// backend commands, and the slot task driving this adapter has other pairs'
/// control frames waiting behind it.
async fn install_nat(plan: NatPlan) -> Option<netfilter::NatGuard> {
    match tokio::task::spawn_blocking(move || netfilter::install(&plan)).await {
        Ok(netfilter::Outcome::Installed(guard)) => Some(guard),
        Ok(netfilter::Outcome::Degraded(msg)) => {
            eprint!("{msg}");
            None
        }
        Err(e) => {
            crate::elog!("peer exit: {e}");
            None
        }
    }
}

/// Move IP packets between the device and the inner session. The reader runs
/// here rather than in a task of its own, so the device is released with this
/// future. One packet is one frame in either direction, and nothing waits on
/// another frame, so the lossy unordered pipe under the session costs the
/// adapter nothing.
async fn run_switch(dev: Arc<TapDevice>, session: PeerSession) {
    let switch = TapSwitch::detached(dev, false);
    let port = switch
        .add_port(TRANSPORT_PEER, None)
        .expect("a fresh switch admits its first port");
    tokio::select! {
        _ = switch.clone().read_loop() => {}
        _ = crate::bridge::switch_port_peer(port, session) => {}
    }
}

/// The provider's end of the pair's tunnel. Assignment stays with the
/// provider: the secret's derived `/24` with `.1` here and `.2` on the
/// consumer, the same pair a server tun hands out.
fn tun_config(exit: &PeerExit, secret: &str) -> TunConfig {
    let base = crate::identity::derive_tun_subnet(secret);
    TunConfig {
        name: exit.device.clone(),
        mtu: exit.mtu,
        addr: Ipv4Addr::new(base[0], base[1], base[2], 1),
        prefix_len: TUN_PREFIX_LEN,
    }
}

/// The interface the pair's traffic leaves by: the named one when set, else
/// the default-route interface parsed from `route_table` (`/proc/net/route`
/// contents). The pair's own tun is refused: masquerading onto it would send
/// the traffic back where it came from.
fn egress_iface(device: &str, iface: Option<&str>, route_table: &str) -> Result<String> {
    match iface {
        Some(name) if name == device => Err(format!(
            "the exit provider's egress interface cannot be its own tun {device}"
        )
        .into()),
        Some(name) => Ok(name.to_string()),
        None => {
            crate::route::default_route_iface(route_table, device).ok_or_else(|| -> crate::Error {
                "the exit provider could not detect its egress interface; set exit_iface in [peer]"
                    .into()
            })
        }
    }
}

/// Whether this process holds the capability the tun open needs. A status file
/// that cannot be read or parsed counts as holding it: the check is here to
/// name a misconfiguration, not to invent one.
fn has_net_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|status| net_admin_in_status(&status))
        .unwrap_or(true)
}

/// Read the effective capability set out of `/proc/self/status` contents and
/// test the bit `TUNSETIFF` needs.
fn net_admin_in_status(status: &str) -> bool {
    const CAP_NET_ADMIN: u32 = 12;
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|bits| u64::from_str_radix(bits.trim(), 16).ok())
        .is_none_or(|caps| caps & (1 << CAP_NET_ADMIN) != 0)
}

/// Masquerade the pair's subnet out `egress`. An exit provider carries the
/// consumer's outbound traffic and nothing inbound, so the plan has no DNAT.
fn nat_plan(cfg: &TunConfig, egress: String) -> NatPlan {
    let o = cfg.addr.octets();
    NatPlan {
        iface: cfg.name.clone(),
        subnet: Ipv4Addr::new(o[0], o[1], o[2], 0),
        prefix_len: cfg.prefix_len,
        server_ip: cfg.addr,
        mtu: cfg.mtu,
        dnat: None,
        egress: Some(egress),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::RawFd;
    use std::time::Duration;

    use crate::peer::PeerPath;

    const PROC_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    const SECRET: &str = "peer exit test";

    fn exit() -> PeerExit {
        PeerExit {
            device: "znp0".into(),
            mtu: 1400,
            iface: None,
        }
    }

    #[test]
    fn the_provider_takes_the_first_address_of_the_derived_subnet() {
        let base = crate::identity::derive_tun_subnet(SECRET);
        let cfg = tun_config(&exit(), SECRET);
        assert_eq!(cfg.name, "znp0");
        assert_eq!(cfg.mtu, 1400);
        assert_eq!(cfg.addr, Ipv4Addr::new(base[0], base[1], base[2], 1));
        assert_eq!(cfg.prefix_len, 24);
    }

    #[test]
    fn the_plan_masquerades_the_pair_subnet_and_forwards_nothing_inbound() {
        let cfg = tun_config(&exit(), SECRET);
        let plan = nat_plan(&cfg, "eth0".into());
        assert_eq!(plan.egress.as_deref(), Some("eth0"));
        assert!(plan.dnat.is_none());
        assert_eq!(plan.iface, cfg.name);
        assert_eq!(plan.server_ip, cfg.addr);
        assert_eq!(plan.prefix_len, 24);
        let o = cfg.addr.octets();
        assert_eq!(plan.subnet, Ipv4Addr::new(o[0], o[1], o[2], 0));
    }

    #[test]
    fn a_named_exit_iface_wins_over_the_default_route() {
        assert_eq!(egress_iface("znx0", None, PROC_ROUTE).unwrap(), "eth0");
        assert_eq!(
            egress_iface("znx0", Some("wan1"), PROC_ROUTE).unwrap(),
            "wan1"
        );
    }

    // With no egress interface there is nowhere for the pair's traffic to go,
    // and masquerading onto the pair's own tun feeds it back to itself. Both
    // are states the precheck refuses the pair for, rather than ones the
    // adapter discovers with a session already handed to it.
    #[test]
    fn the_precheck_needs_an_egress_that_is_not_the_pairs_own_tun() {
        assert!(egress_iface("znx0", None, "").is_err());
        let own = egress_iface("znx0", Some("znx0"), PROC_ROUTE).unwrap_err();
        assert!(own.to_string().contains("znx0"), "{own}");
        assert!(precheck(&PeerExit {
            iface: Some("znx0".into()),
            ..exit()
        })
        .is_err());
    }

    // A process without CAP_NET_ADMIN cannot open the tun, and that outlives
    // every pair. A status file this cannot read counts as holding the
    // capability, so an unexpected procfs never invents a refusal.
    #[test]
    fn missing_net_admin_is_read_off_the_effective_capability_set() {
        assert!(net_admin_in_status("CapEff:\t000001ffffffffff\n"));
        assert!(net_admin_in_status(
            "Name:\tzeronat\nCapEff:\t0000000000001000\n"
        ));
        assert!(!net_admin_in_status("CapEff:\t0000000000000ff7\n"));
        assert!(!net_admin_in_status(
            "Name:\tzeronat\nCapEff:\t0000000000000000\n"
        ));
        assert!(net_admin_in_status(""));
        assert!(net_admin_in_status("CapEff:\tnot-a-mask\n"));
    }

    /// Both ends of one inner session, handshaked over a duplex standing in for
    /// a relay leg.
    async fn inner_pair() -> (PeerSession, PeerSession) {
        let psk = crate::noise::derive_psk(SECRET);
        let (a, b) = tokio::io::duplex(1 << 16);
        let responder =
            tokio::spawn(async move { crate::noise::server_handshake(b, &psk).await.unwrap() });
        let initiator = crate::noise::client_handshake(a, &psk).await.unwrap();
        let responder = responder.await.unwrap();
        let ((consumer, answer), provider) = tokio::try_join!(
            PeerSession::consumer(PeerPath::relay_stream(initiator), &psk, 1),
            PeerSession::provider(PeerPath::relay_stream(responder), &psk, 1, &[]),
        )
        .expect("the inner handshake must complete on both sides");
        assert!(answer.is_empty());
        (consumer, provider)
    }

    /// The next frame the adapter wrote to the device, read off the other end
    /// of the socketpair standing in for it.
    async fn read_device(fd: RawFd) -> Vec<u8> {
        for _ in 0..300 {
            let mut buf = [0u8; 2048];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                return buf[..n as usize].to_vec();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no frame reached the device");
    }

    fn write_device(fd: RawFd, frame: &[u8]) {
        let n = unsafe { libc::write(fd, frame.as_ptr() as *const libc::c_void, frame.len()) };
        assert_eq!(n, frame.len() as isize);
    }

    /// One minimal IPv4 packet with `mark` in its payload.
    fn packet(mark: u8) -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 2, 8,
            8, 8, 8,
        ];
        p.extend_from_slice(&[mark; 4]);
        p
    }

    /// Closes the peer end of the socketpair when the test ends.
    struct DeviceFd(RawFd);
    impl Drop for DeviceFd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    // The adapter's datapath: a packet the consumer sends comes out of the
    // provider's device, and a packet arriving on that device reaches the
    // consumer. The device here is a socketpair rather than a kernel tun, so
    // the test needs no privilege and no routing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ip_packets_cross_between_the_pair_and_the_device() {
        let (mut consumer, provider) = inner_pair().await;
        let (dev, peer) = TapDevice::socketpair_for_test(1500).unwrap();
        let _fd = DeviceFd(peer);
        let adapter = crate::client::AbortOnDrop(tokio::spawn(run_switch(Arc::new(dev), provider)));

        let out = packet(0xa1);
        consumer.send(&out).await.unwrap();
        assert_eq!(read_device(peer).await, out);

        let back = packet(0xb2);
        write_device(peer, &back);
        let got = tokio::time::timeout(Duration::from_secs(10), consumer.recv())
            .await
            .expect("no frame came back from the device")
            .expect("the peer session closed");
        assert_eq!(got, back);
        drop(adapter);
    }
}
