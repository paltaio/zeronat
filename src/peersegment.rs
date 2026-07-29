//! The L2 adapter a segment provider runs: one TAP device joined to the
//! bridge that carries this node's segment, and the learning switch that
//! moves Ethernet frames between that device and every consumer attached to
//! it. One switch serves all of a provider's pairs, so a MAC learned behind
//! one consumer is reachable from the next.
//!
//! The device and the switch live in the slot that owns them, so the slot's
//! end closes the device and takes its bridge port with it. A pair that dies
//! detaches its own port and leaves the rest of the switch running.
//!
//! One Ethernet frame is one session frame in either direction and nothing
//! waits on another, so the lossy unordered pipe under a pair costs the
//! adapter nothing.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::bridge::{switch_port_peer, TapSwitch, TRANSPORT_PEER};
use crate::peer::PeerSession;
use crate::peerslot::PeerSegment;
use crate::tap::{has_net_admin, TapConfig, TapDevice};
use crate::Result;

/// Where the kernel lists interfaces. A bridge carries a `bridge` directory
/// under its entry.
const SYSFS_NET: &str = "/sys/class/net";

/// What the provider can settle about its bringup before a pair arrives: the
/// bridge its TAP joins has to be a bridge that exists, and the process needs
/// the capability the TAP open takes. Both outlive any one pair, so a failure
/// here is what refuses the pairs that follow.
pub(crate) fn precheck(segment: &PeerSegment) -> Result<()> {
    check_bridge(&segment.bridge, Path::new(SYSFS_NET))?;
    if !has_net_admin() {
        return Err(format!(
            "this process may not open the tap {}; it holds no CAP_NET_ADMIN",
            segment.device
        )
        .into());
    }
    Ok(())
}

/// Read `sysfs` for the named interface and refuse anything the TAP cannot be
/// enslaved to. Enslaving is an ioctl on the master, which only a bridge
/// answers.
fn check_bridge(name: &str, sysfs: &Path) -> Result<()> {
    let entry: PathBuf = sysfs.join(name);
    if !entry.exists() {
        return Err(format!("the segment provider has no interface named {name}").into());
    }
    if !entry.join("bridge").is_dir() {
        return Err(format!(
            "the segment provider's {name} is not a bridge; name the bridge the segment's \
             interface belongs to"
        )
        .into());
    }
    Ok(())
}

/// Open the provider's TAP, join it to the configured bridge, and build the
/// switch its consumers attach to.
pub(crate) fn open(segment: &PeerSegment) -> Result<Segment> {
    let dev = TapDevice::open(&TapConfig {
        name: segment.device.clone(),
        mtu: segment.mtu,
        bridge: Some(segment.bridge.clone()),
    })?;
    crate::elog!(
        "peer segment: {} is up on bridge {}",
        segment.device,
        segment.bridge
    );
    Ok(Segment::over(Arc::new(dev)))
}

/// A provider's open segment: the device on the bridge and the switch every
/// consumer takes a port on.
pub(crate) struct Segment {
    switch: Arc<TapSwitch>,
}

impl Segment {
    fn over(dev: Arc<TapDevice>) -> Self {
        Segment {
            switch: TapSwitch::segment(dev),
        }
    }

    /// A segment over a socketpair standing in for the TAP, with the other end
    /// returned so a test can inject and drain device frames. It opens no
    /// kernel device and takes no privilege.
    #[cfg(test)]
    pub(crate) fn for_test() -> (Self, std::os::unix::io::RawFd) {
        let (dev, peer) = TapDevice::socketpair_for_test(1500).expect("socketpair device");
        (Segment::over(Arc::new(dev)), peer)
    }

    /// Fan every frame the device delivers out to the ports that want it. The
    /// future ends when the device stops reading, which cancels every port.
    pub(crate) fn reader(&self) -> impl Future<Output = ()> + Send + 'static {
        self.switch.clone().read_loop()
    }

    /// Attach one consumer as a port on the switch. The future carries frames
    /// both ways until the pair's session dies or the device does; dropping it
    /// detaches the port and purges the MACs learned behind it.
    pub(crate) fn attach(
        &self,
        session: PeerSession,
    ) -> Result<impl Future<Output = ()> + Send + 'static> {
        let port = self.switch.add_port(TRANSPORT_PEER, None)?;
        Ok(switch_port_peer(port, session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::RawFd;
    use std::time::Duration;

    use crate::bridge::frame;
    use crate::client::AbortOnDrop;
    use crate::tap::{read_device, write_device, DeviceFd};

    const SECRET: &str = "peer segment test";
    const M1: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const M2: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
    const LAN: [u8; 6] = [0x02, 0, 0, 0, 0, 0x09];
    const BCAST: [u8; 6] = [0xff; 6];

    /// The next frame a consumer's end of a pair receives.
    async fn recv_frame(session: &mut PeerSession) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("no frame reached the consumer")
            .expect("the peer session closed")
    }

    /// A test segment with its reader running.
    fn test_segment() -> (Segment, RawFd, AbortOnDrop) {
        let (seg, peer) = Segment::for_test();
        let reader = AbortOnDrop(crate::spawn(seg.reader()));
        (seg, peer, reader)
    }

    // Two consumers on one provider: a broadcast reaches the other consumer
    // and the device, and the switch learns the sender behind its port on the
    // way, so the answer to it goes to that port alone. A unicast for a
    // station no port has claimed is on the segment, so it goes to the device
    // and to no consumer. Traffic the device delivers crosses the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_consumers_share_one_switch_and_learn_each_other() {
        let (seg, dev_fd, _reader) = test_segment();
        let _fd = DeviceFd(dev_fd);
        let (mut a, a_provider) = crate::peer::duplex_pair(SECRET, 1).await;
        let (mut b, b_provider) = crate::peer::duplex_pair(SECRET, 2).await;
        let _port_a = AbortOnDrop(crate::spawn(seg.attach(a_provider).unwrap()));
        let _port_b = AbortOnDrop(crate::spawn(seg.attach(b_provider).unwrap()));

        // A's broadcast reaches B and the device, and the switch learns M1
        // behind A's port on the way.
        let hello = frame(BCAST, M1, b"who-has-m2");
        a.send(&hello).await.unwrap();
        assert_eq!(recv_frame(&mut b).await, hello);
        assert_eq!(read_device(dev_fd).await, hello);

        // B answers M1, which the switch now owns: A gets it and the device
        // does not. The broadcast behind it is what the device sees next, so
        // the unicast was never written there.
        let answer = frame(M1, M2, b"m2-is-here");
        b.send(&answer).await.unwrap();
        assert_eq!(recv_frame(&mut a).await, answer);
        let shout = frame(BCAST, M2, b"everyone");
        b.send(&shout).await.unwrap();
        assert_eq!(read_device(dev_fd).await, shout);
        assert_eq!(recv_frame(&mut a).await, shout);

        // A frame for a station behind no port goes to the device alone. The
        // broadcast after it is what B reads next, so B never saw it.
        let outbound = frame(LAN, M1, b"to-the-lan");
        a.send(&outbound).await.unwrap();
        assert_eq!(read_device(dev_fd).await, outbound);
        let again = frame(BCAST, M1, b"anyone");
        a.send(&again).await.unwrap();
        assert_eq!(recv_frame(&mut b).await, again);
        assert_eq!(read_device(dev_fd).await, again);

        // The device end is one more source of frames: unicast for a learned
        // station goes to the one port, and a broadcast reaches both.
        let inbound = frame(M1, LAN, b"from-the-segment");
        write_device(dev_fd, &inbound);
        assert_eq!(recv_frame(&mut a).await, inbound);
        let flooded = frame(BCAST, LAN, b"to-the-segment");
        write_device(dev_fd, &flooded);
        assert_eq!(recv_frame(&mut a).await, flooded);
        assert_eq!(recv_frame(&mut b).await, flooded);
    }

    // A pair that dies takes its own port and nothing else: the surviving
    // consumer keeps carrying frames, and the MACs the dead port owned are
    // purged, so a frame for one of them floods instead of following a stale
    // route into a closed port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dead_pair_detaches_its_port_alone() {
        let (seg, dev_fd, _reader) = test_segment();
        let _fd = DeviceFd(dev_fd);
        let (a, a_provider) = crate::peer::duplex_pair(SECRET, 1).await;
        let (mut b, b_provider) = crate::peer::duplex_pair(SECRET, 2).await;
        let port_a = AbortOnDrop(crate::spawn(seg.attach(a_provider).unwrap()));
        let _port_b = AbortOnDrop(crate::spawn(seg.attach(b_provider).unwrap()));

        let hello = frame(BCAST, M1, b"learn-m1");
        a.send(&hello).await.unwrap();
        assert_eq!(recv_frame(&mut b).await, hello);
        assert_eq!(read_device(dev_fd).await, hello);
        assert_eq!(seg.switch.ports_snapshot().len(), 2);

        // A's pair dies with the session that carried it.
        drop(a);
        drop(port_a);
        for _ in 0..50 {
            if seg.switch.ports_snapshot().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let ports = seg.switch.ports_snapshot();
        assert_eq!(ports.len(), 1, "the dead pair kept its port");
        assert!(ports[0].macs.is_empty(), "a dead port left a learned MAC");

        // The surviving consumer is untouched, and M1 goes to the device
        // again rather than following the port that owned it.
        let after = frame(M1, M2, b"still-here");
        b.send(&after).await.unwrap();
        assert_eq!(read_device(dev_fd).await, after);
    }

    /// Removes the sysfs stand-in when the test ends, however it ends.
    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    // The bringup a provider can check without a pair: the bridge has to exist
    // and be a bridge. Both failures name the interface, which is what the
    // refusal the consumer reads carries.
    #[test]
    fn the_precheck_needs_a_bridge_that_exists() {
        let root = std::env::temp_dir().join(format!("zeronat-segment-{}", std::process::id()));
        let _cleanup = TempDir(root.clone());
        std::fs::create_dir_all(root.join("br-test").join("bridge")).unwrap();
        std::fs::create_dir_all(root.join("eth-test")).unwrap();

        check_bridge("br-test", &root).unwrap();
        let missing = check_bridge("nosuchif", &root).unwrap_err().to_string();
        assert!(missing.contains("nosuchif"), "{missing}");
        let plain = check_bridge("eth-test", &root).unwrap_err().to_string();
        assert!(plain.contains("eth-test"), "{plain}");
        assert!(plain.contains("not a bridge"), "{plain}");
    }
}
