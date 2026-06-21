//! Sans-IO PPPoE-over-tunnel datapath core.
//!
//! Drives the discovery FSM (`discovery::Discovery`) and the PPP session
//! (`engine::PppSession`) over a raw Ethernet L2 channel, demuxing inbound frames
//! by ethertype and wrapping outbound PPP payloads in 0x8864 session frames. It
//! performs no IO: outbound L2 frames are queued and drained with
//! `poll_transmit_frame`; inbound IPv4 packets destined for the TUN are queued and
//! drained with `poll_inbound_ip`. The async shell (`super::tunnel`) owns the real
//! channel and the TUN and pumps this core.
//!
//! The L2 backend (the tunnel channel, or a future raw `AF_PACKET` bare client)
//! is interchangeable precisely because this core touches no socket:
//! a different shell can reuse `PppoeDatapath` verbatim and route the drained
//! frames to a different channel.
//!
//! Every inbound parse goes through the bounds-checked typed-error decoders in
//! `session`/`discovery`/`engine`; `on_l2_frame` never indexes a raw byte and
//! never panics on a malformed frame (the release profile is panic=abort).

use super::discovery::{Action, Discovery, Established as DiscoveryEstablished};
use super::engine::{self, FeedOutcome, PppConfig, PppSession};
use super::session::{build_session_frame, parse_eth_header, parse_session_frame};
use super::{MacAddr, ETHERTYPE_DISCOVERY, ETHERTYPE_SESSION};

/// IPv4 over PPP protocol field, prepended to every IP packet inside a PPP frame.
const PPP_PROTO_IPV4: [u8; 2] = [0x00, 0x21];

/// PPPoE-over-tunnel overhead the inner PPP MTU must leave room for: the 6-byte
/// PPPoE session header plus the 2-byte PPP Protocol field.
pub const PPPOE_OVERHEAD: u16 = 8;

/// Effective IP MTU / advertised LCP MRU for a PPPoE link riding a tunnel whose L2
/// MTU is `tunnel_tap_mtu`. The inner PPP payload is capped by the tunnel MTU
/// minus the PPPoE+PPP overhead, then clamped to the requested `pppoe_mtu`.
///
/// Saturates so a pathologically small tunnel MTU yields 0 rather than
/// underflowing (panic=abort makes an arithmetic underflow fatal). 0 is not a
/// usable link value: the caller enforces a floor before passing this to the TUN
/// or the LCP ConfReq (see `super::cli::resolve_effective_mtu`).
pub fn effective_mtu(pppoe_mtu: u16, tunnel_tap_mtu: u16) -> u16 {
    pppoe_mtu.min(tunnel_tap_mtu.saturating_sub(PPPOE_OVERHEAD))
}

/// Phase the shell observes to decide when to open zppp0 and start pumping it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpPhase {
    /// PADI/PADO/PADR/PADS discovery in flight; no PPP yet.
    Discovery,
    /// Discovery done; LCP/auth/IPCP negotiating. No zppp0 yet.
    Ppp,
    /// IPCP up; the negotiated IP config is ready, zppp0 can come up / is up.
    Established(engine::Established),
    /// Discovery failed permanently (retries exhausted or PADT).
    Dead,
}

/// Session parameters latched once discovery reaches Established.
#[derive(Clone, Copy)]
struct SessionParams {
    ac_mac: MacAddr,
    session_id: u16,
}

/// Sans-IO PPPoE-over-tunnel datapath.
pub struct PppoeDatapath<'a> {
    our_mac: MacAddr,
    discovery: Discovery,
    ppp: PppSession<'a>,
    /// Set once discovery reaches Established; needed to address session frames.
    session: Option<SessionParams>,
    /// Set once PPP reaches Established; a clean edge for one-time zppp0 bring-up.
    established: Option<engine::Established>,
    /// Outbound raw Ethernet frames pending transmit on the L2 channel, FIFO.
    out: Vec<Vec<u8>>,
    /// Inbound IPv4 datagrams pending write to zppp0, FIFO.
    inbound_ip: Vec<Vec<u8>>,
    /// True once discovery has permanently failed.
    dead: bool,
}

impl<'a> PppoeDatapath<'a> {
    /// Build a datapath. `mru` is the effective MRU/MTU (`effective_mtu`).
    /// `service_name` is the PPPoE Service-Name selector (empty = any). A random
    /// local MAC and a 4-byte Host-Uniq are generated here; `magic` is drawn from
    /// the system RNG. `retransmit_ticks`/`max_attempts` bound discovery resends.
    pub fn new(
        username: &'a [u8],
        password: &'a [u8],
        service_name: Vec<u8>,
        mru: u16,
        retransmit_ticks: u32,
        max_attempts: u32,
    ) -> super::Result<Self> {
        let our_mac = MacAddr::random_local()?;
        let mut host_uniq = [0u8; 4];
        getrandom::getrandom(&mut host_uniq).map_err(|_| super::Error::Rng)?;
        let discovery = Discovery::new(
            our_mac,
            service_name,
            Some(host_uniq.to_vec()),
            retransmit_ticks,
            max_attempts,
        );
        let mut cfg = PppConfig::with_random_magic(username, password)?;
        cfg.mru = mru;
        let ppp = PppSession::new(cfg)?;
        Ok(Self {
            our_mac,
            discovery,
            ppp,
            session: None,
            established: None,
            out: Vec::new(),
            inbound_ip: Vec::new(),
            dead: false,
        })
    }

    /// Our locally-administered client MAC for this session.
    pub fn our_mac(&self) -> MacAddr {
        self.our_mac
    }

    /// Kick discovery: emit the first PADI into the outbound queue. Call once
    /// after `new`.
    pub fn start(&mut self) {
        let action = self.discovery.start();
        self.apply_discovery_action(action);
    }

    /// Feed one inbound raw Ethernet frame from the L2 channel and return the
    /// resulting phase. Demuxes by ethertype:
    ///   0x8863 -> discovery FSM; on Established, latch session params, open PPP.
    ///   0x8864 (our session_id) -> strip the PPPoE header, feed the PPP session.
    ///   anything else / parse error / wrong session_id -> dropped, no panic.
    pub fn on_l2_frame(&mut self, frame: &[u8]) -> DpPhase {
        // Demux on ethertype via the bounds-checked header parser; <14 bytes or a
        // parse error drops the frame.
        let ethertype = match parse_eth_header(frame) {
            Ok((eth, _)) => eth.ethertype,
            Err(_) => return self.phase(),
        };
        match ethertype {
            ETHERTYPE_DISCOVERY => {
                let action = self.discovery.on_frame(frame);
                self.apply_discovery_action(action);
            }
            ETHERTYPE_SESSION => self.on_session_frame(frame),
            _ => {} // not PPPoE; drop
        }
        self.phase()
    }

    /// Submit one IP packet read from zppp0: wrap it in a 0x8864 session frame
    /// addressed to the AC and queue it. A no-op before discovery is Established
    /// (no session id / AC yet); the shell does not read zppp0 until then.
    pub fn on_tun_ip(&mut self, ip: &[u8]) {
        let session = match self.session {
            Some(s) => s,
            None => return,
        };
        let mut payload = Vec::with_capacity(PPP_PROTO_IPV4.len() + ip.len());
        payload.extend_from_slice(&PPP_PROTO_IPV4);
        payload.extend_from_slice(ip);
        let frame = build_session_frame(session.ac_mac, self.our_mac, session.session_id, &payload);
        self.out.push(frame);
    }

    /// Advance the timers and return the resulting phase. Drives
    /// `Discovery::on_tick` (PADI/PADR retransmit, the only real retransmit in the
    /// stack) and `PppSession::poll` (phase advance, originating ConfReqs once a
    /// sub-FSM is Closed). The PPP layer has no restart timer, so a lost LCP/IPCP
    /// ConfReq is not retransmitted here; the shell's idle reaper redials.
    pub fn on_tick(&mut self) -> DpPhase {
        let action = self.discovery.on_tick();
        self.apply_discovery_action(action);
        self.ppp.poll();
        self.drain_ppp_out();
        self.phase()
    }

    /// Drain the next outbound raw Ethernet frame for the L2 channel, or `None`.
    pub fn poll_transmit_frame(&mut self) -> Option<Vec<u8>> {
        if self.out.is_empty() {
            None
        } else {
            Some(self.out.remove(0))
        }
    }

    /// Drain the next inbound IP packet destined for zppp0, or `None`.
    pub fn poll_inbound_ip(&mut self) -> Option<Vec<u8>> {
        if self.inbound_ip.is_empty() {
            None
        } else {
            Some(self.inbound_ip.remove(0))
        }
    }

    /// Current phase.
    pub fn phase(&self) -> DpPhase {
        if self.dead {
            return DpPhase::Dead;
        }
        if let Some(est) = self.established {
            return DpPhase::Established(est);
        }
        if self.session.is_some() {
            DpPhase::Ppp
        } else {
            DpPhase::Discovery
        }
    }

    /// Demux a 0x8864 session frame: validate it carries our session id, slice the
    /// PPP payload, feed the PPP session, surface inbound IPv4, drain replies.
    fn on_session_frame(&mut self, frame: &[u8]) {
        let session = match self.session {
            Some(s) => s,
            None => return, // no session yet; drop session-stage frames
        };
        let header = match parse_session_frame(frame) {
            Ok(h) => h,
            Err(_) => return, // malformed; drop, no panic
        };
        if header.session_id != session.session_id {
            return; // a session frame for another client on the segment
        }
        // `ppp_start..ppp_end` was validated against the PPPoE LENGTH, so indexing
        // it cannot fault.
        let payload = &frame[header.ppp_start..header.ppp_end];
        match self.ppp.feed(payload) {
            FeedOutcome::Ip(ip) => self.inbound_ip.push(ip),
            FeedOutcome::Consumed | FeedOutcome::Truncated => {}
        }
        self.drain_ppp_out();
        self.refresh_established();
    }

    /// Act on a discovery `Action`: queue frames to send, latch the session and
    /// open PPP on Established, or mark dead on Failed.
    fn apply_discovery_action(&mut self, action: Action) {
        match action {
            Action::Send(bytes) => self.out.push(bytes),
            Action::Idle => {}
            Action::Established(est) => self.on_discovery_established(est),
            Action::Failed => self.dead = true,
        }
    }

    /// Discovery reached an established session: latch the AC/session, open the PPP
    /// FSM, and drain its initial LCP ConfReq into session frames.
    fn on_discovery_established(&mut self, est: DiscoveryEstablished) {
        self.session = Some(SessionParams {
            ac_mac: est.ac_mac,
            session_id: est.session_id,
        });
        if self.ppp.open().is_ok() {
            self.drain_ppp_out();
            self.refresh_established();
        }
    }

    /// Wrap every queued outbound PPP payload in a 0x8864 session frame addressed
    /// to the AC. Requires `session` to be set (only called after discovery is
    /// established).
    fn drain_ppp_out(&mut self) {
        let session = match self.session {
            Some(s) => s,
            None => return,
        };
        while let Some(payload) = self.ppp.poll_transmit() {
            let frame =
                build_session_frame(session.ac_mac, self.our_mac, session.session_id, &payload);
            self.out.push(frame);
        }
    }

    /// Cache the IPCP-negotiated config the first time PPP reports Established, so
    /// the shell sees a clean Established edge.
    fn refresh_established(&mut self) {
        if self.established.is_none() {
            if let Some(est) = self.ppp.established() {
                self.established = Some(est);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pppoe::session::parse_session_frame;
    use std::net::Ipv4Addr;

    // Golden MACs/Host-Uniq from the NE40-BRAS capture used in discovery.rs.
    const OUR: MacAddr = MacAddr([0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74]);
    const AC: MacAddr = MacAddr([0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17]);
    const HU: [u8; 4] = [0x95, 0x16, 0x00, 0x00];
    const SESSION_ID: u16 = 0x5e61;

    const USER: &[u8] = b"client";
    const SECRET: &[u8] = b"tchile";
    const MRU: u16 = 1392;
    const MAGIC: u32 = 0x06c27d42;

    const CHALLENGE: [u8; 16] = [
        0x1a, 0x88, 0x05, 0x28, 0x03, 0x05, 0x07, 0x22, 0xcd, 0x6c, 0x29, 0xed, 0x93, 0xd9, 0x4a,
        0xe8,
    ];

    // PADO/PADS as the AC sends them, addressed to OUR with our Host-Uniq echoed.
    const PADO: &[u8] = &[
        0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74, 0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17, 0x88, 0x63, 0x11,
        0x07, 0x00, 0x00, 0x00, 0x19, 0x01, 0x02, 0x00, 0x09, 0x4e, 0x45, 0x34, 0x30, 0x2d, 0x42,
        0x52, 0x41, 0x53, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x95, 0x16, 0x00, 0x00,
    ];
    const PADS: &[u8] = &[
        0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74, 0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17, 0x88, 0x63, 0x11,
        0x65, 0x5e, 0x61, 0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x95, 0x16,
        0x00, 0x00,
    ];

    /// A datapath with deterministic MAC/Host-Uniq/magic, built directly (bypassing
    /// `new`'s RNG) so the assertions can pin exact bytes.
    fn fixed_dp() -> PppoeDatapath<'static> {
        let discovery = Discovery::new(OUR, vec![], Some(HU.to_vec()), 3, 5);
        let ppp = PppSession::new(PppConfig {
            username: USER,
            password: SECRET,
            mru: MRU,
            magic: MAGIC,
            request_dns: false,
        })
        .expect("construct ppp");
        PppoeDatapath {
            our_mac: OUR,
            discovery,
            ppp,
            session: None,
            established: None,
            out: Vec::new(),
            inbound_ip: Vec::new(),
            dead: false,
        }
    }

    fn lcp(code: u8, id: u8, opts: &[u8]) -> Vec<u8> {
        ctrl(0xc021, code, id, opts)
    }
    fn ipcp(code: u8, id: u8, opts: &[u8]) -> Vec<u8> {
        ctrl(0x8021, code, id, opts)
    }
    fn ctrl(proto: u16, code: u8, id: u8, opts: &[u8]) -> Vec<u8> {
        let length = 4 + opts.len();
        let mut p = Vec::new();
        p.extend_from_slice(&proto.to_be_bytes());
        p.push(code);
        p.push(id);
        p.extend_from_slice(&(length as u16).to_be_bytes());
        p.extend_from_slice(opts);
        p
    }
    fn chap_challenge(id: u8, challenge: &[u8], name: &[u8]) -> Vec<u8> {
        let length = 4 + 1 + challenge.len() + name.len();
        let mut p = vec![0xc2, 0x23, 1, id];
        p.extend_from_slice(&(length as u16).to_be_bytes());
        p.push(challenge.len() as u8);
        p.extend_from_slice(challenge);
        p.extend_from_slice(name);
        p
    }
    fn chap_result(code: u8, id: u8) -> Vec<u8> {
        let mut p = vec![0xc2, 0x23, code, id];
        p.extend_from_slice(&4u16.to_be_bytes());
        p
    }

    /// Wrap a raw PPP payload in a 0x8864 session frame addressed to OUR (i.e. as
    /// the AC would send it to us).
    fn from_ac(ppp: &[u8]) -> Vec<u8> {
        build_session_frame(OUR, AC, SESSION_ID, ppp)
    }

    /// Drain every queued outbound frame.
    fn drain_frames(dp: &mut PppoeDatapath) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Some(f) = dp.poll_transmit_frame() {
            v.push(f);
        }
        v
    }

    /// Extract the PPP payload of the single session frame in `frames`, asserting
    /// it is addressed dst=AC src=OUR with our session id.
    fn one_ppp_out(frames: &[Vec<u8>]) -> Vec<u8> {
        assert_eq!(frames.len(), 1, "expected exactly one outbound frame");
        let h = parse_session_frame(&frames[0]).expect("parse session frame");
        assert_eq!(h.eth.dst, AC);
        assert_eq!(h.eth.src, OUR);
        assert_eq!(h.session_id, SESSION_ID);
        frames[0][h.ppp_start..h.ppp_end].to_vec()
    }

    /// Drive a datapath all the way to PPP Established over synthetic frames.
    fn drive_to_established(dp: &mut PppoeDatapath) {
        dp.start();
        let frames = drain_frames(dp);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][14], 0x11);
        assert_eq!(frames[0][15], 0x09); // PADI code

        assert_eq!(dp.on_l2_frame(PADO), DpPhase::Discovery);
        let frames = drain_frames(dp);
        assert_eq!(frames[0][15], 0x19); // PADR code

        // PADS -> Ppp; PPP opens and emits the LCP ConfReq.
        assert_eq!(dp.on_l2_frame(PADS), DpPhase::Ppp);
        let our_lcp_req = one_ppp_out(&drain_frames(dp));
        assert_eq!(&our_lcp_req[0..2], &[0xc0, 0x21]);
        assert_eq!(our_lcp_req[2], 0x01); // ConfigureReq
        let lcp_id = our_lcp_req[3];

        // Peer LCP ConfReq: MRU 1492 + CHAP-MD5 + Magic.
        let peer_opts = [
            0x01, 0x04, 0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0xf6, 0xb2, 0xf2,
            0xce,
        ];
        dp.on_l2_frame(&from_ac(&lcp(0x01, 1, &peer_opts)));
        let _ = drain_frames(dp); // our ConfAck
        dp.on_l2_frame(&from_ac(&lcp(0x02, lcp_id, &our_lcp_req[6..])));
        let _ = drain_frames(dp);

        // CHAP challenge -> response.
        dp.on_l2_frame(&from_ac(&chap_challenge(1, &CHALLENGE, b"NE40-BRAS")));
        let _ = drain_frames(dp);
        // CHAP success -> IPCP ConfReq.
        dp.on_l2_frame(&from_ac(&chap_result(3, 1)));
        let our_ipcp_req = one_ppp_out(&drain_frames(dp));
        assert_eq!(&our_ipcp_req[0..2], &[0x80, 0x21]);
        let ipcp_id = our_ipcp_req[3];

        // Peer IPCP ConfReq <peer addr> -> ConfAck.
        let peer_ip = [0x03, 0x06, 0xba, 0x6b, 0x60, 0x01];
        dp.on_l2_frame(&from_ac(&ipcp(0x01, 1, &peer_ip)));
        let _ = drain_frames(dp);
        // Peer Naks our addr -> we re-ConfReq it.
        let our_ip = [0x03, 0x06, 0xba, 0x6b, 0x74, 0x10];
        dp.on_l2_frame(&from_ac(&ipcp(0x03, ipcp_id, &our_ip)));
        let our_ipcp_req2 = one_ppp_out(&drain_frames(dp));
        let ipcp_id2 = our_ipcp_req2[3];
        // Peer Acks -> Established.
        let phase = dp.on_l2_frame(&from_ac(&ipcp(0x02, ipcp_id2, &our_ip)));
        match phase {
            DpPhase::Established(est) => {
                assert_eq!(est.local_ip, Ipv4Addr::new(186, 107, 116, 16));
                assert_eq!(est.peer_ip, Ipv4Addr::new(186, 107, 96, 1));
                assert_eq!(est.mru, 1392);
            }
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn full_negotiation_drive_to_established() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        assert!(matches!(dp.phase(), DpPhase::Established(_)));
    }

    #[test]
    fn tun_ip_wrapped_into_session_frame() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp); // clear any residue

        let ip: &[u8] = &[0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef];
        dp.on_tun_ip(ip);
        let frames = drain_frames(&mut dp);
        let payload = one_ppp_out(&frames);
        assert_eq!(&payload[0..2], &PPP_PROTO_IPV4);
        assert_eq!(&payload[2..], ip);
    }

    #[test]
    fn inbound_ip_routed_to_tun() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        let ip: &[u8] = &[0x45, 0x00, 0x00, 0x14, 0x12, 0x34];
        let mut ppp = PPP_PROTO_IPV4.to_vec();
        ppp.extend_from_slice(ip);
        dp.on_l2_frame(&from_ac(&ppp));
        assert_eq!(dp.poll_inbound_ip().as_deref(), Some(ip));
        assert!(dp.poll_inbound_ip().is_none());
        // An inbound IP packet produces no outbound L2 frame.
        assert!(dp.poll_transmit_frame().is_none());
    }

    #[test]
    fn wrong_session_id_dropped() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        let ip: &[u8] = &[0x45, 0x00, 0x00, 0x14];
        let mut ppp = PPP_PROTO_IPV4.to_vec();
        ppp.extend_from_slice(ip);
        // Same payload but a different session id.
        let frame = build_session_frame(OUR, AC, SESSION_ID ^ 0x1, &ppp);
        dp.on_l2_frame(&frame);
        assert!(dp.poll_inbound_ip().is_none());
        assert!(dp.poll_transmit_frame().is_none());
    }

    #[test]
    fn effective_mtu_math() {
        assert_eq!(effective_mtu(1492, 1400), 1392);
        assert_eq!(effective_mtu(1492, 1500), 1492);
        assert_eq!(effective_mtu(1280, 1400), 1280);
        // Saturating: a tiny tunnel MTU yields 0, never an underflow panic.
        assert_eq!(effective_mtu(1492, 4), 0);
        assert_eq!(effective_mtu(1492, 8), 0);
    }

    // De-panic gate for the inbound L2 demux. The sub-decoders are already fuzzed
    // in discovery.rs/engine.rs; this proves the demux glue adds no panic site.
    #[test]
    fn fuzz_on_l2_frame_never_panics() {
        let session_seed = build_session_frame(OUR, AC, SESSION_ID, &[0x00, 0x21, 0x45, 0x00]);
        let mut curated: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0xff; 13],                       // runt < eth header
            vec![0xff; 14],                       // eth header only, zero ethertype
            PADO.to_vec(),
            PADS.to_vec(),
            session_seed.clone(),
            from_ac(&[0x00, 0x21, 0x45]),         // session frame with a short IP
            from_ac(&lcp(0x01, 1, &[0x01, 0x04])),
        ];
        // 0x8864 with a LENGTH overrun.
        let mut overrun = session_seed.clone();
        overrun[18..20].copy_from_slice(&0xffffu16.to_be_bytes());
        curated.push(overrun);
        // Truncated PPPoE header on a discovery ethertype.
        let mut short_pppoe = vec![0u8; 14];
        short_pppoe[12..14].copy_from_slice(&ETHERTYPE_DISCOVERY.to_be_bytes());
        curated.push(short_pppoe);

        // Replay each curated case against fresh datapaths in every reachable phase.
        let builders: [fn() -> PppoeDatapath<'static>; 3] =
            [discovery_phase, ppp_phase, established_phase];
        for case in &curated {
            for build in &builders {
                let mut dp = build();
                let _ = dp.on_l2_frame(case);
                let _ = drain_frames(&mut dp);
            }
        }

        // LCG-pseudorandom buffers, length 0..64, against every phase.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..2000 {
            let len = (next() % 64) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((next() & 0xff) as u8);
            }
            for build in &builders {
                let mut dp = build();
                let _ = dp.on_l2_frame(&buf);
                let _ = drain_frames(&mut dp);
            }
        }
    }

    fn discovery_phase() -> PppoeDatapath<'static> {
        let mut dp = fixed_dp();
        dp.start();
        let _ = drain_frames(&mut dp);
        dp
    }
    fn ppp_phase() -> PppoeDatapath<'static> {
        let mut dp = fixed_dp();
        dp.start();
        let _ = drain_frames(&mut dp);
        dp.on_l2_frame(PADO);
        let _ = drain_frames(&mut dp);
        dp.on_l2_frame(PADS);
        let _ = drain_frames(&mut dp);
        assert!(matches!(dp.phase(), DpPhase::Ppp));
        dp
    }
    fn established_phase() -> PppoeDatapath<'static> {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);
        dp
    }
}
