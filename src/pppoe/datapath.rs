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
//! Because this core touches no socket, the L2 backend is interchangeable: a
//! different shell can reuse `PppoeDatapath` verbatim and route the drained
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

/// LCP Echo-Request cadence, in `on_tick` ticks, once the link is Established.
/// The shell drives `on_tick` once a second, so this probes every 25s, on the
/// same timescale the tunnel transport already keepalives, without flooding.
const ECHO_INTERVAL_TICKS: u32 = 25;

/// Consecutive unanswered Echo-Request intervals that declare the link dead.
/// With ECHO_INTERVAL_TICKS this is a ~75s liveness window: above a single lost
/// echo or a brief peer pause, well under a stuck-forever link.
const ECHO_DEAD_THRESHOLD: u32 = 3;

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

/// Clamp the TCP MSS option of a forwarded IPv4 SYN down to `clamp`, returning
/// whether the packet was rewritten. Pure and panic-free on untrusted input: every
/// read is bounds-checked (the release profile is panic=abort). Only IPv4 TCP SYN
/// or SYN+ACK segments whose MSS option exceeds `clamp` are touched; everything
/// else is left byte-identical. The change is folded into the TCP checksum
/// incrementally (RFC 1624) so the segment stays valid without a full recompute.
///
/// This matters only for FORWARDED traffic over the sub-1500 link; a kernel that
/// originates a SYN locally already emits a correct MSS, so the clamp is inert
/// there (the MSS is already <= the link and the rewrite is skipped).
fn clamp_tcp_mss(pkt: &mut [u8], clamp: u16) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false; // too short for an IPv4 header, or not IPv4
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 20 {
        return false; // header malformed, or no room for the fixed TCP header
    }
    if pkt[9] != 6 {
        return false; // not TCP
    }
    // A non-first fragment (low 13 bits of bytes 6..8) carries no TCP header.
    if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff != 0 {
        return false;
    }
    let tcp = &mut pkt[ihl..]; // len >= 20 from the ihl + 20 check
    if tcp[13] & 0x02 == 0 {
        return false; // SYN bit clear: not a SYN/SYN+ACK
    }
    let data_off = (tcp[12] >> 4) as usize * 4;
    if data_off < 20 || data_off > tcp.len() {
        return false; // options region does not fit
    }
    let mut i = 20;
    while i < data_off {
        let kind = tcp[i];
        if kind == 0 {
            break; // End of Option List
        }
        if kind == 1 {
            i += 1; // No-Operation, single byte
            continue;
        }
        if i + 1 >= data_off {
            break; // length byte would run past the options region
        }
        let len = tcp[i + 1] as usize;
        if len < 2 || i + len > data_off {
            break; // malformed option length; stop walking
        }
        if kind == 2 && len == 4 {
            let cur = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
            if cur <= clamp {
                return false; // already within the path; leave byte-identical
            }
            tcp[i + 2] = (clamp >> 8) as u8;
            tcp[i + 3] = (clamp & 0xff) as u8;
            fold_tcp_checksum(tcp, cur, clamp);
            return true;
        }
        i += len;
    }
    false
}

/// One's-complement 16-bit add (end-around carry), used for the incremental
/// checksum update.
fn ones_complement_add(a: u16, b: u16) -> u16 {
    let s = a as u32 + b as u32;
    ((s & 0xffff) + (s >> 16)) as u16
}

/// Update the TCP checksum at `tcp[16..18]` after a 16-bit field changed from `old`
/// to `new`, per RFC 1624 Eqn 3: `HC' = ~(~HC + ~old + new)`. The incremental form
/// can produce 0x0000 where a full recompute gives 0xFFFF, but only when `new` is 0;
/// both are valid TCP checksums, and the clamp value is always >= 536, so that edge
/// never arises here.
fn fold_tcp_checksum(tcp: &mut [u8], old: u16, new: u16) {
    let hc = u16::from_be_bytes([tcp[16], tcp[17]]);
    let mut acc = ones_complement_add(!hc, !old);
    acc = ones_complement_add(acc, new);
    let hc_new = !acc;
    tcp[16] = (hc_new >> 8) as u8;
    tcp[17] = (hc_new & 0xff) as u8;
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
    /// The link was Established and then died (echo timeout, inbound PADT, or the
    /// PPP FSM dropping below Opened). The shell tears down zppp0 and redials in
    /// place. Distinct from `Dead`, which is a permanent discovery failure that
    /// bounces the whole tunnel.
    LinkDown,
    /// Discovery failed permanently (retries exhausted or PADT before the link
    /// ever came up).
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
    /// Ticks since the last Echo-Request, counted only while Established.
    echo_ticks: u32,
    /// Consecutive Echo-Request intervals with no matching reply observed.
    echo_misses: u32,
    /// True once an Echo-Request has been sent and its interval has not yet been
    /// scored. Keeps the first interval (before any request) from being counted.
    echo_outstanding: bool,
    /// Set when any inbound session frame from the AC arrives; cleared each scored
    /// interval. Liveness keys on this, not only matching echo-replies: a link
    /// passing traffic or receiving the AC's own keepalives is alive even when the
    /// AC never answers our Echo-Requests (pppd leaves LCP-echo off by default for
    /// exactly that reason). Only total AC silence over the window declares a death.
    inbound_seen: bool,
    /// Set when liveness fails, an inbound PADT for our session arrives, or the
    /// PPP FSM drops below Opened after the link came up. The shell redials.
    link_down: bool,
    /// Why `link_down` was set (`echo-timeout`, `padt`, `lcp-closed`), for the log.
    link_down_reason: Option<&'static str>,
    // Construction inputs retained so `reset` can rebuild the inner FSMs for an
    // in-session redial without re-borrowing from `new`. The credentials are
    // borrowed for `'a`, the lifetime the datapath already carries.
    username: &'a [u8],
    password: &'a [u8],
    service_name: Vec<u8>,
    host_uniq: Option<Vec<u8>>,
    mru: u16,
    retransmit_ticks: u32,
    max_attempts: u32,
    request_dns: bool,
    /// When set, the TCP MSS to clamp forwarded SYNs to (in both directions). `None`
    /// leaves forwarded packets untouched. Survives `reset` like the other inputs.
    clamp_mss: Option<u16>,
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
        let mut hu = [0u8; 4];
        getrandom::getrandom(&mut hu).map_err(|_| super::Error::Rng)?;
        let host_uniq = Some(hu.to_vec());
        let discovery = Discovery::new(
            our_mac,
            service_name.clone(),
            host_uniq.clone(),
            retransmit_ticks,
            max_attempts,
        );
        let request_dns = false;
        let mut cfg = PppConfig::with_random_magic(username, password)?;
        cfg.mru = mru;
        cfg.request_dns = request_dns;
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
            echo_ticks: 0,
            echo_misses: 0,
            echo_outstanding: false,
            inbound_seen: false,
            link_down: false,
            link_down_reason: None,
            username,
            password,
            service_name,
            host_uniq,
            mru,
            retransmit_ticks,
            max_attempts,
            request_dns,
            clamp_mss: None,
        })
    }

    /// Enable forwarded-TCP MSS clamping to `clamp` (in both directions). Set by the
    /// shell when `--pppoe-default-route` is on without `--pppoe-no-mss-clamp`.
    pub fn set_clamp_mss(&mut self, clamp: u16) {
        self.clamp_mss = Some(clamp);
    }

    /// Request the IPCP DNS options on (re)negotiation. Flips the default-off
    /// `request_dns`; takes effect on the current session and survives `reset`.
    pub fn set_request_dns(&mut self, on: bool) {
        self.request_dns = on;
        self.ppp.set_request_dns(on);
    }

    /// Our locally-administered client MAC for this session.
    pub fn our_mac(&self) -> MacAddr {
        self.our_mac
    }

    /// Why the link last went down (`echo-timeout`, `padt`, `lcp-closed`), for the
    /// shell's redial log. `unknown` before any link-down.
    pub fn link_down_reason(&self) -> &'static str {
        self.link_down_reason.unwrap_or("unknown")
    }

    /// Kick discovery: emit the first PADI into the outbound queue. Call once
    /// after `new`.
    pub fn start(&mut self) {
        let action = self.discovery.start();
        self.apply_discovery_action(action);
    }

    /// Tear down the current session and return to Discovery for an in-session
    /// redial: same source MAC, Service-Name, and Host-Uniq selector, but a fresh
    /// discovery (new PADI -> new session id) and a fresh PPP session with a new
    /// Magic-Number. Called by the shell after it observes LinkDown and closes
    /// zppp0. Re-emits the first PADI, so the caller drains `poll_transmit_frame`
    /// right after.
    ///
    /// No PADT is sent to the AC: the old session is already dead and a fresh PADI
    /// starts a new one the BRAS treats independently.
    ///
    /// Errors only if the system RNG fails while drawing the new Magic-Number,
    /// which on Linux is effectively impossible; the shell then tears down the
    /// tunnel and the reconnect loop redials from scratch.
    pub fn reset(&mut self) -> super::Result<()> {
        self.discovery = Discovery::new(
            self.our_mac,
            self.service_name.clone(),
            self.host_uniq.clone(),
            self.retransmit_ticks,
            self.max_attempts,
        );
        let mut cfg = PppConfig::with_random_magic(self.username, self.password)?;
        cfg.mru = self.mru;
        cfg.request_dns = self.request_dns;
        self.ppp = PppSession::new(cfg)?;

        self.session = None;
        self.established = None;
        self.out.clear();
        self.inbound_ip.clear();
        self.echo_ticks = 0;
        self.echo_misses = 0;
        self.echo_outstanding = false;
        self.inbound_seen = false;
        self.link_down = false;
        self.link_down_reason = None;

        self.start();
        Ok(())
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
        // Egress zppp0 -> BRAS: clamp the forwarded SYN's MSS in place on the IP
        // bytes (after the 2-byte PPP protocol field) before framing.
        if let Some(c) = self.clamp_mss {
            clamp_tcp_mss(&mut payload[PPP_PROTO_IPV4.len()..], c);
        }
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
        self.tick_liveness();
        self.phase()
    }

    /// Run the LCP-echo liveness cycle for one tick. A no-op unless the link is
    /// Established and not already down.
    ///
    /// The first Echo-Request goes out on the Established edge. Each subsequent
    /// interval is scored exactly once: the interval counts as alive if the AC
    /// answered our echo OR sent any session frame (`inbound_seen`); both flags are
    /// take-and-cleared once per interval. This keys liveness on AC activity rather
    /// than only on matching echo-replies, because some BRAS deployments do not
    /// answer LCP echoes yet keep the link up. Only ECHO_DEAD_THRESHOLD consecutive
    /// intervals of total AC silence declare the link down. A PPP-side drop below
    /// LCP-Opened is also a down.
    fn tick_liveness(&mut self) {
        if self.established.is_none() || self.link_down {
            return;
        }

        // A previously-Opened link whose LCP reached Closed (inbound Terminate, or
        // a local close) is a PPP-side down. A transient sub-Opened dip while an
        // inbound Configure-Request renegotiates (ReqSent/AckSent/AckReceived) is a
        // RFC 1661 reopen, not a teardown: leave the link up and let it resettle.
        if self.ppp.lcp_closed() {
            self.link_down = true;
            self.link_down_reason = Some("lcp-closed");
            return;
        }

        // First echo on the Established edge: send immediately, start the timer, and
        // clear any inbound/reply seen during negotiation so the window starts clean.
        if !self.echo_outstanding {
            self.ppp.send_echo_request();
            self.drain_ppp_out();
            self.echo_outstanding = true;
            self.echo_ticks = 0;
            self.inbound_seen = false;
            let _ = self.ppp.take_echo_reply_seen();
            return;
        }

        self.echo_ticks += 1;
        if self.echo_ticks < ECHO_INTERVAL_TICKS {
            return;
        }

        // Interval boundary: the link is alive if the AC answered our echo OR sent
        // any session frame this interval. Take-and-clear both flags exactly once.
        self.echo_ticks = 0;
        let reply = self.ppp.take_echo_reply_seen();
        let inbound = core::mem::take(&mut self.inbound_seen);
        if reply || inbound {
            self.echo_misses = 0;
        } else {
            self.echo_misses += 1;
        }
        if self.echo_misses >= ECHO_DEAD_THRESHOLD {
            self.link_down = true;
            self.link_down_reason = Some("echo-timeout");
            return;
        }
        // Send the next request to open the next interval.
        self.ppp.send_echo_request();
        self.drain_ppp_out();
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
        if self.link_down {
            return DpPhase::LinkDown;
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
        // A valid session frame for us is proof the AC is alive: it drives liveness.
        self.inbound_seen = true;
        // `ppp_start..ppp_end` was validated against the PPPoE LENGTH, so indexing
        // it cannot fault.
        let payload = &frame[header.ppp_start..header.ppp_end];
        match self.ppp.feed(payload) {
            // Ingress BRAS -> zppp0: clamp the forwarded SYN's MSS before it is
            // written to the TUN and forwarded on by the kernel.
            FeedOutcome::Ip(mut ip) => {
                if let Some(c) = self.clamp_mss {
                    clamp_tcp_mss(&mut ip, c);
                }
                self.inbound_ip.push(ip);
            }
            FeedOutcome::Consumed | FeedOutcome::Truncated => {}
        }
        self.drain_ppp_out();
        self.refresh_established();
        // An inbound Terminate that drives LCP to Closed after the link came up is a
        // link-down. Catch it on the frame rather than waiting a tick. An inbound
        // Configure-Request that reopens negotiation (RFC 1661 RcR in Opened) dips
        // below Opened but stays sub-Closed; that is renegotiation, not teardown, so
        // it must not redial.
        if self.established.is_some() && !self.link_down && self.ppp.lcp_closed() {
            self.link_down = true;
            self.link_down_reason = Some("lcp-closed");
        }
    }

    /// Act on a discovery `Action`: queue frames to send, latch the session and
    /// open PPP on Established, or mark dead on Failed.
    fn apply_discovery_action(&mut self, action: Action) {
        match action {
            Action::Send(bytes) => self.out.push(bytes),
            Action::Idle => {}
            Action::Established(est) => self.on_discovery_established(est),
            // A discovery failure once a session has latched (inbound PADT for our
            // session, or a post-Established failure) is a recoverable link-down:
            // the shell redials in place. Before any session latches it stays a
            // hard discovery death that bounces the tunnel.
            Action::Failed => {
                if self.established.is_some() || self.session.is_some() {
                    self.link_down = true;
                    self.link_down_reason = Some("padt");
                } else {
                    self.dead = true;
                }
            }
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
    /// The AC's Magic-Number, distinct from ours. A real LCP Echo-Reply carries the
    /// peer's magic; only a reply whose magic differs from ours counts as liveness.
    const PEER_MAGIC: u32 = 0x5ea17b03;

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
            echo_ticks: 0,
            echo_misses: 0,
            echo_outstanding: false,
            inbound_seen: false,
            link_down: false,
            link_down_reason: None,
            username: USER,
            password: SECRET,
            service_name: vec![],
            host_uniq: Some(HU.to_vec()),
            mru: MRU,
            retransmit_ticks: 3,
            max_attempts: 5,
            clamp_mss: None,
            request_dns: false,
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

    // ---- LCP-echo liveness + in-session redial ----

    /// An LCP Echo-Reply PPP payload echoing `magic` (as the AC would send it).
    fn echo_reply(magic: u32) -> Vec<u8> {
        let mut p = vec![0xc0, 0x21, 0x0a, 0x01];
        p.extend_from_slice(&8u16.to_be_bytes());
        p.extend_from_slice(&magic.to_be_bytes());
        p
    }

    /// A PADT discovery frame as the AC sends it to us: src=AC, dst=OUR, our id.
    fn padt_from_ac(session_id: u16) -> Vec<u8> {
        let mut f = Vec::new();
        crate::pppoe::session::put_eth_header(&mut f, OUR, AC, ETHERTYPE_DISCOVERY);
        f.push(crate::pppoe::VER_TYPE);
        f.push(crate::pppoe::discovery::CODE_PADT);
        f.extend_from_slice(&session_id.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f
    }

    /// Find the single emitted LCP Echo-Request among drained frames and return
    /// its PPP payload, or `None` if none is present.
    fn find_echo(frames: &[Vec<u8>]) -> Option<Vec<u8>> {
        for f in frames {
            if let Ok(h) = parse_session_frame(f) {
                let ppp = &f[h.ppp_start..h.ppp_end];
                if ppp.len() >= 4 && ppp[0..2] == [0xc0, 0x21] && ppp[2] == 0x09 {
                    return Some(ppp.to_vec());
                }
            }
        }
        None
    }

    #[test]
    fn echo_emitted_on_interval() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        // The first echo goes out on the Established edge (first on_tick).
        dp.on_tick();
        let first = find_echo(&drain_frames(&mut dp)).expect("first echo on the edge");
        assert_eq!(u16::from_be_bytes([first[4], first[5]]), 0x0008);
        assert_eq!(&first[6..10], &MAGIC.to_be_bytes());

        // No echo on the intervening ticks; the next one only at the boundary.
        for _ in 0..(ECHO_INTERVAL_TICKS - 1) {
            dp.on_tick();
            assert!(find_echo(&drain_frames(&mut dp)).is_none());
        }
        dp.on_tick();
        assert!(find_echo(&drain_frames(&mut dp)).is_some());
    }

    #[test]
    fn echo_reply_keeps_link_alive() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        // Drive well past the dead window, answering every echo with a reply.
        for _ in 0..(ECHO_DEAD_THRESHOLD * ECHO_INTERVAL_TICKS + ECHO_INTERVAL_TICKS) {
            let phase = dp.on_tick();
            if find_echo(&drain_frames(&mut dp)).is_some() {
                dp.on_l2_frame(&from_ac(&echo_reply(PEER_MAGIC)));
                let _ = drain_frames(&mut dp);
            }
            assert!(matches!(phase, DpPhase::Established(_)));
        }
        assert_eq!(dp.echo_misses, 0);
        assert!(matches!(dp.phase(), DpPhase::Established(_)));
    }

    #[test]
    fn any_inbound_frame_keeps_link_alive_without_echo_replies() {
        // Liveness resets on ANY inbound session frame from the AC, not only on a
        // matching echo-reply. Here every tick delivers a loopback echo-reply (our
        // own magic), which does NOT set the echo-reply-seen flag yet still counts
        // as AC activity, so the link stays up past the dead window. This is the
        // case the live NE40-BRAS hit: it does not answer our echoes but the link is
        // alive, and pppd likewise leaves LCP-echo teardown off by default.
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        for _ in 0..(ECHO_DEAD_THRESHOLD * ECHO_INTERVAL_TICKS + ECHO_INTERVAL_TICKS) {
            let phase = dp.on_tick();
            let _ = drain_frames(&mut dp);
            dp.on_l2_frame(&from_ac(&echo_reply(MAGIC))); // inbound activity, not a reply
            assert!(matches!(phase, DpPhase::Established(_)));
        }
        assert!(matches!(dp.phase(), DpPhase::Established(_)));
    }

    #[test]
    fn total_ac_silence_declares_link_down() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        // Edge echo + ECHO_DEAD_THRESHOLD intervals of TOTAL AC silence (no reply,
        // no inbound frame). The threshold is hit at exactly THRESHOLD*INTERVAL ticks
        // past the edge; not before.
        dp.on_tick(); // edge: first echo, window starts clean
        let _ = drain_frames(&mut dp);
        let mut ticks = 0u32;
        loop {
            let phase = dp.on_tick();
            let _ = drain_frames(&mut dp);
            ticks += 1;
            if matches!(phase, DpPhase::LinkDown) {
                break;
            }
            assert!(matches!(phase, DpPhase::Established(_)));
            assert!(
                ticks < ECHO_DEAD_THRESHOLD * ECHO_INTERVAL_TICKS,
                "link should have gone down by now"
            );
        }
        assert_eq!(ticks, ECHO_DEAD_THRESHOLD * ECHO_INTERVAL_TICKS);
        assert_eq!(dp.link_down_reason(), "echo-timeout");
    }

    #[test]
    fn inbound_padt_after_established_is_link_down() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);
        assert_eq!(dp.on_l2_frame(&padt_from_ac(SESSION_ID)), DpPhase::LinkDown);
    }

    #[test]
    fn discovery_padt_before_established_is_dead() {
        // No session latched yet (still in Discovery): a PADT is a hard death.
        let mut dp = discovery_phase();
        // The discovery FSM only honors a PADT from its chosen AC, so feed a PADO
        // first to latch the AC without latching a session, then PADT.
        dp.on_l2_frame(PADO); // -> PadrSent, ac_mac latched, no session yet
        let _ = drain_frames(&mut dp);
        assert!(matches!(dp.phase(), DpPhase::Discovery));
        assert_eq!(dp.on_l2_frame(&padt_from_ac(0)), DpPhase::Dead);
    }

    #[test]
    fn ppp_phase_padt_is_link_down() {
        // Session latched (PADS seen) but PPP not yet Established: a PADT redials
        // in-session because the session id is dead.
        let mut dp = ppp_phase();
        assert!(matches!(dp.phase(), DpPhase::Ppp));
        assert_eq!(dp.on_l2_frame(&padt_from_ac(SESSION_ID)), DpPhase::LinkDown);
    }

    #[test]
    fn link_down_terminate_req() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);
        // Inbound LCP TerminateReq drops LCP below Opened -> link-down on the frame.
        let phase = dp.on_l2_frame(&from_ac(&lcp(0x05, 0x07, &[])));
        assert_eq!(phase, DpPhase::LinkDown);
    }

    #[test]
    fn inbound_lcp_confreq_after_established_keeps_link_up() {
        // RFC 1661 section 4.2 RcR in Opened: an inbound Configure-Request reopens
        // negotiation, transiting LCP through AckSent/ReqSent (sub-Opened) before it
        // resettles to Opened. That transient dip must not be misread as link death.
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        // Peer reopens with a Magic-Number-only Configure-Request; we Ack it and
        // emit our own Configure-Request (LCP -> AckSent, sub-Opened).
        let reneg_opts = [0x05, 0x06, 0xab, 0xcd, 0xef, 0x01];
        let phase = dp.on_l2_frame(&from_ac(&lcp(0x01, 0x42, &reneg_opts)));
        assert_eq!(phase, DpPhase::Established(*dp.established.as_ref().unwrap()));
        assert!(!dp.link_down, "renegotiation must not declare link-down");

        // A tick mid-renegotiation must not redial either: LCP is sub-Opened but
        // not Closed.
        assert!(matches!(dp.on_tick(), DpPhase::Established(_)));
        assert!(!dp.link_down);

        // Find our reopened Configure-Request and let the peer Ack it; LCP -> Opened.
        let our_req = {
            let mut req = None;
            for f in drain_frames(&mut dp) {
                if let Ok(h) = parse_session_frame(&f) {
                    let ppp = &f[h.ppp_start..h.ppp_end];
                    if ppp.len() >= 4 && ppp[0..2] == [0xc0, 0x21] && ppp[2] == 0x01 {
                        req = Some(ppp.to_vec());
                    }
                }
            }
            req.expect("our reopened LCP Configure-Request")
        };
        let phase = dp.on_l2_frame(&from_ac(&lcp(0x02, our_req[3], &our_req[6..])));
        assert!(matches!(phase, DpPhase::Established(_)));
        assert!(dp.ppp.lcp_opened(), "LCP resettles to Opened after reopen");

        // The link still echoes after the reopen: an Echo-Request goes out at the
        // next interval boundary and a reply keeps it alive.
        let _ = drain_frames(&mut dp);
        let mut echoed = false;
        for _ in 0..=ECHO_INTERVAL_TICKS {
            assert!(matches!(dp.on_tick(), DpPhase::Established(_)));
            if find_echo(&drain_frames(&mut dp)).is_some() {
                echoed = true;
                dp.on_l2_frame(&from_ac(&echo_reply(PEER_MAGIC)));
                let _ = drain_frames(&mut dp);
                break;
            }
        }
        assert!(echoed, "echo cycle resumes after the reopen");
        assert!(matches!(dp.phase(), DpPhase::Established(_)));
    }

    #[test]
    fn reset_returns_to_discovery_and_reestablishes() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        dp.reset().expect("reset");
        assert_eq!(dp.phase(), DpPhase::Discovery);
        assert!(dp.established.is_none());
        // Exactly one outbound PADI was re-emitted.
        let frames = drain_frames(&mut dp);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][14], 0x11);
        assert_eq!(frames[0][15], 0x09); // PADI

        // Re-drive to Established with a different session id and confirm outbound
        // session frames address the new id.
        re_drive_to_established(&mut dp, 0x1234);
        let _ = drain_frames(&mut dp);
        dp.on_tun_ip(&[0x45, 0x00, 0x00, 0x14]);
        let frames = drain_frames(&mut dp);
        let h = parse_session_frame(&frames[0]).expect("session frame");
        assert_eq!(h.session_id, 0x1234);
        assert!(matches!(dp.phase(), DpPhase::Established(_)));
    }

    #[test]
    fn reset_twice_reestablishes_each_time() {
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);

        dp.reset().expect("reset 1");
        assert_eq!(dp.phase(), DpPhase::Discovery);
        let _ = drain_frames(&mut dp);
        re_drive_to_established(&mut dp, 0x1111);
        assert!(matches!(dp.phase(), DpPhase::Established(_)));
        let _ = drain_frames(&mut dp);

        dp.reset().expect("reset 2");
        assert_eq!(dp.phase(), DpPhase::Discovery);
        let _ = drain_frames(&mut dp);
        re_drive_to_established(&mut dp, 0x2222);
        assert!(matches!(dp.phase(), DpPhase::Established(_)));
    }

    #[test]
    fn reset_rebuilds_ppp_session() {
        // reset rebuilds the PPP session: the liveness counters and the
        // outstanding-echo latch are cleared, so the post-reset link starts a
        // fresh echo cycle rather than carrying pre-reset state.
        let mut dp = fixed_dp();
        drive_to_established(&mut dp);
        dp.on_tick(); // sends the first echo, sets echo_outstanding
        assert!(dp.echo_outstanding);
        let _ = drain_frames(&mut dp);

        dp.reset().expect("reset");
        assert!(!dp.echo_outstanding);
        assert_eq!(dp.echo_misses, 0);
        assert_eq!(dp.echo_ticks, 0);
    }

    /// Re-drive a post-reset datapath from Discovery to Established, assigning
    /// `session_id` in the synthetic PADS. Mirrors `drive_to_established` but with
    /// a caller-chosen session id so a reset's fresh id can be asserted.
    fn re_drive_to_established(dp: &mut PppoeDatapath, session_id: u16) {
        // PADO -> PADR.
        assert_eq!(dp.on_l2_frame(PADO), DpPhase::Discovery);
        let _ = drain_frames(dp);
        // PADS with the chosen session id -> Ppp.
        let mut pads = PADS.to_vec();
        pads[16..18].copy_from_slice(&session_id.to_be_bytes());
        assert_eq!(dp.on_l2_frame(&pads), DpPhase::Ppp);
        let our_lcp_req = {
            let frames = drain_frames(dp);
            let h = parse_session_frame(&frames[0]).expect("lcp req");
            frames[0][h.ppp_start..h.ppp_end].to_vec()
        };
        let lcp_id = our_lcp_req[3];

        // Session frames now address `session_id`, so the AC's frames to us carry it.
        let from = |ppp: &[u8]| build_session_frame(OUR, AC, session_id, ppp);

        let peer_opts = [
            0x01, 0x04, 0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0xf6, 0xb2, 0xf2,
            0xce,
        ];
        dp.on_l2_frame(&from(&lcp(0x01, 1, &peer_opts)));
        let _ = drain_frames(dp);
        dp.on_l2_frame(&from(&lcp(0x02, lcp_id, &our_lcp_req[6..])));
        let _ = drain_frames(dp);
        dp.on_l2_frame(&from(&chap_challenge(1, &CHALLENGE, b"NE40-BRAS")));
        let _ = drain_frames(dp);
        dp.on_l2_frame(&from(&chap_result(3, 1)));
        let our_ipcp_req = {
            let frames = drain_frames(dp);
            let h = parse_session_frame(&frames[0]).expect("ipcp req");
            frames[0][h.ppp_start..h.ppp_end].to_vec()
        };
        let ipcp_id = our_ipcp_req[3];
        let peer_ip = [0x03, 0x06, 0xba, 0x6b, 0x60, 0x01];
        dp.on_l2_frame(&from(&ipcp(0x01, 1, &peer_ip)));
        let _ = drain_frames(dp);
        let our_ip = [0x03, 0x06, 0xba, 0x6b, 0x74, 0x10];
        dp.on_l2_frame(&from(&ipcp(0x03, ipcp_id, &our_ip)));
        let our_ipcp_req2 = {
            let frames = drain_frames(dp);
            let h = parse_session_frame(&frames[0]).expect("ipcp req2");
            frames[0][h.ppp_start..h.ppp_end].to_vec()
        };
        let ipcp_id2 = our_ipcp_req2[3];
        let phase = dp.on_l2_frame(&from(&ipcp(0x02, ipcp_id2, &our_ip)));
        assert!(matches!(phase, DpPhase::Established(_)));
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
            from_ac(&echo_reply(PEER_MAGIC)),          // well-formed echo-reply (liveness peek)
            from_ac(&[0xc0, 0x21, 0x0a, 0x01, 0x00, 0x06]), // echo-reply, truncated body
            from_ac(&[0xc0, 0x21, 0x0a, 0x01, 0xff, 0xff, 0x06, 0xc2]), // echo-reply len overrun
            from_ac(&[0xc0, 0x21, 0x0a, 0x01, 0x00, 0x00]), // echo-reply, zero-length body
            from_ac(&[0xc0, 0x21, 0x05, 0x07, 0x00, 0x04]), // LCP TerminateReq
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

    // --- forwarded-TCP MSS clamp ---

    /// One's-complement 16-bit sum complement (Internet checksum) over `words`.
    fn ones16(words: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < words.len() {
            sum += u16::from_be_bytes([words[i], words[i + 1]]) as u32;
            i += 2;
        }
        if i < words.len() {
            sum += (words[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Full TCP checksum over the IPv4 pseudo-header + segment, for verifying that
    /// the incremental update matches a from-scratch recompute.
    fn tcp_cksum(ip: &[u8]) -> u16 {
        let ihl = (ip[0] & 0x0f) as usize * 4;
        let tcp = &ip[ihl..];
        let mut p = Vec::new();
        p.extend_from_slice(&ip[12..20]); // src + dst
        p.push(0);
        p.push(6); // TCP
        p.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        p.extend_from_slice(tcp);
        ones16(&p)
    }

    fn mss_opt(v: u16) -> Vec<u8> {
        vec![2, 4, (v >> 8) as u8, (v & 0xff) as u8]
    }

    /// Build an IPv4/TCP packet (ihl 5) with `flags` and the given TCP `opts`
    /// (zero-padded to a 4-byte boundary) and a valid TCP checksum.
    fn tcp_pkt(flags: u8, opts: &[u8]) -> Vec<u8> {
        let mut topts = opts.to_vec();
        while !topts.len().is_multiple_of(4) {
            topts.push(0);
        }
        let tcp_len = 20 + topts.len();
        let total = 20 + tcp_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        {
            let tcp = &mut p[20..];
            tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
            tcp[12] = ((tcp_len / 4) as u8) << 4;
            tcp[13] = flags;
            tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
            tcp[20..20 + topts.len()].copy_from_slice(&topts);
        }
        let ck = tcp_cksum(&p);
        p[36..38].copy_from_slice(&ck.to_be_bytes()); // tcp checksum at ip[20+16..]
        p
    }

    /// Read the 2-byte MSS value from a packet whose first TCP option is the MSS.
    fn read_mss(ip: &[u8]) -> u16 {
        u16::from_be_bytes([ip[42], ip[43]])
    }

    #[test]
    fn clamp_lowers_mss_and_keeps_checksum_valid() {
        let mut p = tcp_pkt(0x02, &mss_opt(1460));
        assert!(clamp_tcp_mss(&mut p, 1352));
        assert_eq!(read_mss(&p), 1352);
        // The incremental checksum update must equal a full recompute over the
        // segment (recompute with the stored field zeroed, compare to stored).
        let stored = u16::from_be_bytes([p[36], p[37]]);
        let mut q = p.clone();
        q[36] = 0;
        q[37] = 0;
        assert_eq!(tcp_cksum(&q), stored);
    }

    #[test]
    fn clamp_idempotent_when_already_small() {
        let mut p = tcp_pkt(0x02, &mss_opt(1000));
        let before = p.clone();
        assert!(!clamp_tcp_mss(&mut p, 1352));
        assert_eq!(p, before);
    }

    #[test]
    fn clamp_second_pass_is_noop() {
        let mut p = tcp_pkt(0x02, &mss_opt(1460));
        assert!(clamp_tcp_mss(&mut p, 1352));
        let after = p.clone();
        assert!(!clamp_tcp_mss(&mut p, 1352));
        assert_eq!(p, after);
    }

    #[test]
    fn clamp_syn_ack_clamped_pure_ack_untouched() {
        let mut sa = tcp_pkt(0x12, &mss_opt(1460)); // SYN+ACK
        assert!(clamp_tcp_mss(&mut sa, 1352));
        assert_eq!(read_mss(&sa), 1352);
        let mut ack = tcp_pkt(0x10, &mss_opt(1460)); // pure ACK
        let before = ack.clone();
        assert!(!clamp_tcp_mss(&mut ack, 1352));
        assert_eq!(ack, before);
    }

    #[test]
    fn clamp_skips_syn_without_mss_option() {
        let mut p = tcp_pkt(0x02, &[1, 1, 3, 3, 7, 0]); // NOP,NOP,WScale,pad
        let before = p.clone();
        assert!(!clamp_tcp_mss(&mut p, 1352));
        assert_eq!(p, before);
    }

    #[test]
    fn clamp_skips_non_tcp_and_ipv6() {
        let mut udp = tcp_pkt(0x02, &mss_opt(1460));
        udp[9] = 17; // UDP
        let before = udp.clone();
        assert!(!clamp_tcp_mss(&mut udp, 1352));
        assert_eq!(udp, before);
        let mut v6 = vec![0x60u8; 60]; // version nibble 6
        let before6 = v6.clone();
        assert!(!clamp_tcp_mss(&mut v6, 1352));
        assert_eq!(v6, before6);
    }

    #[test]
    fn clamp_skips_fragments_and_truncated() {
        let mut frag = tcp_pkt(0x02, &mss_opt(1460));
        frag[6] = 0x00;
        frag[7] = 0x01; // non-zero fragment offset
        let before = frag.clone();
        assert!(!clamp_tcp_mss(&mut frag, 1352));
        assert_eq!(frag, before);
        assert!(!clamp_tcp_mss(&mut [0x45u8; 10], 1352)); // < IP header
        assert!(!clamp_tcp_mss(&mut [0x45u8; 30], 1352)); // ihl 20 but no room for TCP
    }

    #[test]
    fn clamp_handles_malformed_options_without_panic() {
        // MSS-kind option whose length overruns the options region.
        let mut p = tcp_pkt(0x02, &[2, 0xff, 0x05, 0xb4]);
        let before = p.clone();
        assert!(!clamp_tcp_mss(&mut p, 1352));
        assert_eq!(p, before);
        // MSS kind with a non-4 length is not treated as a clampable MSS.
        let mut q = tcp_pkt(0x02, &[2, 3, 0x05, 0xb4]);
        let beforeq = q.clone();
        assert!(!clamp_tcp_mss(&mut q, 1352));
        assert_eq!(q, beforeq);
    }

    #[test]
    fn clamp_mss_survives_reset() {
        let mut dp = fixed_dp();
        dp.set_clamp_mss(1352);
        assert_eq!(dp.clamp_mss, Some(1352));
        dp.reset().unwrap();
        assert_eq!(dp.clamp_mss, Some(1352), "clamp persists across an in-session redial");
    }

    #[test]
    fn clamp_applied_to_egress_syn_in_on_tun_ip() {
        let mut dp = fixed_dp();
        dp.set_clamp_mss(1352);
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);
        dp.on_tun_ip(&tcp_pkt(0x02, &mss_opt(1460)));
        let ppp = one_ppp_out(&drain_frames(&mut dp));
        assert_eq!(&ppp[0..2], &[0x00, 0x21]); // IPv4-over-PPP
        assert_eq!(read_mss(&ppp[2..]), 1352);
    }

    #[test]
    fn no_clamp_leaves_egress_syn_untouched() {
        let mut dp = fixed_dp(); // clamp_mss is None
        drive_to_established(&mut dp);
        let _ = drain_frames(&mut dp);
        dp.on_tun_ip(&tcp_pkt(0x02, &mss_opt(1460)));
        let ppp = one_ppp_out(&drain_frames(&mut dp));
        assert_eq!(read_mss(&ppp[2..]), 1460);
    }

    #[test]
    fn fuzz_clamp_tcp_mss_never_panics() {
        let mut state: u64 = 0xdead_beef_cafe_babe;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..4000 {
            let len = (next() % 96) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((next() & 0xff) as u8);
            }
            let _ = clamp_tcp_mss(&mut buf, 1352);
        }
    }
}
