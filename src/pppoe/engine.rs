//! SANS-IO PPP session engine.
//!
//! Wraps the de-panicked PPP driver behind a no-IO interface: feed inbound raw
//! PPP payloads, drain outbound raw PPP payloads, step on a tick, read status.
//! It performs no IO, owns no sockets or TUN, and is fully testable by feeding
//! synthetic PPP frames. The caller wraps each outbound payload in a 0x8864
//! session frame (`session::build_session_frame`) and feeds inbound payloads from
//! `session::parse_session_frame`'s `frame[ppp_start..ppp_end]` slice.

use std::net::Ipv4Addr;

use super::ppp::{Config, OutFrame, Phase, RxError, RxOutcome, DEFAULT_MRU, PPP};
use super::{Error, Result};

/// Configuration for a PPP session. Credentials are borrowed for the session
/// lifetime; `mru`/`magic` are injected so the FSM stays deterministic for tests.
pub struct PppConfig<'a> {
    pub username: &'a [u8],
    pub password: &'a [u8],
    /// Our advertised MRU (default 1492; the effective MTU computation belongs to
    /// the datapath).
    pub mru: u16,
    /// Our LCP Magic-Number, random per session (use `with_random_magic`).
    pub magic: u32,
    /// Request DNS1/DNS2 from the peer (pppd's `usepeerdns`). Off by default.
    pub request_dns: bool,
}

impl<'a> PppConfig<'a> {
    /// Build a config with `mru = DEFAULT_MRU` and a Magic-Number drawn from the
    /// system RNG. The randomness lives here, at the IO boundary, so the FSM
    /// itself stays deterministic.
    pub fn with_random_magic(username: &'a [u8], password: &'a [u8]) -> Result<Self> {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).map_err(|_| Error::Rng)?;
        // A zero Magic-Number means "no magic" in RFC 1661 and would defeat the
        // liveness loopback guard (a peer that omits its magic replies with zero,
        // which must not read as our own magic). Force a nonzero value.
        let magic = match u32::from_be_bytes(b) {
            0 => 1,
            m => m,
        };
        Ok(Self {
            username,
            password,
            mru: DEFAULT_MRU,
            magic,
            request_dns: false,
        })
    }
}

/// Outcome of feeding one inbound payload.
///
/// The drop signal (`Truncated`) covers only the mandatory 2-byte proto read.
/// Deeper malformed frames (bad option, short control packet) are dropped inside
/// the sub-FSMs and report `Consumed`; the fuzz gate asserts no-panic, not a
/// specific outcome, so this is sufficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedOutcome {
    /// A control packet was processed (any replies are queued for transmit).
    Consumed,
    /// An inbound IPv4 datagram (proto stripped). The datapath routes it; this
    /// engine surfaces it and otherwise ignores it.
    Ip(Vec<u8>),
    /// The payload was too short to read the PPP Protocol field.
    Truncated,
}

/// PPP link phase exposed to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PppPhase {
    Dead,
    Establish,
    Auth,
    Network,
    Open,
}

impl From<Phase> for PppPhase {
    fn from(p: Phase) -> Self {
        match p {
            Phase::Dead => PppPhase::Dead,
            Phase::Establish => PppPhase::Establish,
            Phase::Auth => PppPhase::Auth,
            Phase::Network => PppPhase::Network,
            Phase::Open => PppPhase::Open,
        }
    }
}

/// The negotiated IP configuration once the link is Open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Established {
    pub local_ip: Ipv4Addr,
    pub peer_ip: Ipv4Addr,
    pub dns: [Option<Ipv4Addr>; 2],
    /// Effective MRU = min(our advertised, peer advertised).
    pub mru: u16,
}

/// A no-IO PPP session: feed inbound payloads, drain outbound payloads, step.
pub struct PppSession<'a> {
    ppp: PPP<'a>,
    /// Outbound raw PPP payloads (2-byte proto + body), FIFO.
    out: Vec<Vec<u8>>,
    /// Wrapping identifier sequenced into each originated LCP Echo-Request.
    echo_id: u8,
}

impl<'a> PppSession<'a> {
    /// Construct in `Phase::Dead`. Rejects credentials longer than 255 bytes
    /// (the PAP/CHAP length fields are a single byte) with a typed error.
    pub fn new(cfg: PppConfig<'a>) -> Result<Self> {
        if cfg.username.len() > u8::MAX as usize || cfg.password.len() > u8::MAX as usize {
            return Err(Error::CredentialTooLong);
        }
        let config = Config {
            username: cfg.username,
            password: cfg.password,
        };
        let mut ppp = PPP::new(config, cfg.mru, cfg.magic);
        ppp.set_request_dns(cfg.request_dns);
        Ok(Self {
            ppp,
            out: Vec::new(),
            echo_id: 0,
        })
    }

    /// Toggle whether IPCP requests the peer's DNS servers on the next negotiation.
    pub fn set_request_dns(&mut self, on: bool) {
        self.ppp.set_request_dns(on);
    }

    /// Kick the FSM: LCP starts opening. Call once after construction, then drain
    /// the initial LCP Configure-Request with `poll_transmit`.
    pub fn open(&mut self) -> Result<()> {
        self.ppp.open()?;
        self.drive_poll();
        Ok(())
    }

    /// Feed one inbound raw PPP payload (2-byte Protocol field + body).
    ///
    /// Never panics on hostile input: a truncated frame is dropped and
    /// reported as `Truncated`; a malformed control frame is dropped internally
    /// and reported `Consumed`. Returns `Ip` for an inbound IPv4 datagram. Always
    /// runs `poll()` afterward (matching upstream's received-then-poll ordering),
    /// so the caller only needs to drain `poll_transmit` after this returns.
    pub fn feed(&mut self, ppp_payload: &[u8]) -> FeedOutcome {
        // `received` needs `&mut [u8]` because Echo/Protocol-Reject replies mutate
        // the frame in place; copy into owned scratch so the caller's slice is
        // untouched.
        let mut scratch = ppp_payload.to_vec();
        let mut produced: Vec<Vec<u8>> = Vec::new();
        let result = self.ppp.received(&mut scratch, |frame| {
            produced.push(serialize(frame));
        });
        self.out.append(&mut produced);

        let outcome = match result {
            Err(RxError::Truncated) => FeedOutcome::Truncated,
            Ok(RxOutcome::IpPacket(range)) => {
                // `range` indexes the scratch copy; clamp defensively though
                // `received` only yields in-bounds ranges.
                match scratch.get(range) {
                    Some(ip) => FeedOutcome::Ip(ip.to_vec()),
                    None => FeedOutcome::Consumed,
                }
            }
            Ok(RxOutcome::Consumed) => FeedOutcome::Consumed,
        };

        self.drive_poll();
        outcome
    }

    /// Advance the restart timers and the link state machine one step:
    /// retransmit stale Configure-Requests (RFC 1661 restart timer), advance
    /// phases, originate ConfReqs, open IPCP after auth. Call once per timer
    /// tick; `feed` and `open` advance the state machine themselves.
    pub fn on_tick(&mut self) {
        let mut produced: Vec<Vec<u8>> = Vec::new();
        self.ppp.tick(|frame| produced.push(serialize(frame)));
        self.out.append(&mut produced);
        self.drive_poll();
    }

    /// Drain the next outbound raw PPP payload to send inside a 0x8864 session
    /// frame. `None` when the queue is empty.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        if self.out.is_empty() {
            None
        } else {
            Some(self.out.remove(0))
        }
    }

    pub fn phase(&self) -> PppPhase {
        self.ppp.status().phase.into()
    }

    /// `Some(Established)` once the link is Open and IPCP carries both a local and
    /// a peer address.
    pub fn established(&self) -> Option<Established> {
        let status = self.ppp.status();
        if status.phase != Phase::Open {
            return None;
        }
        let ipv4 = status.ipv4?;
        let local_ip = ipv4.address?;
        let peer_ip = ipv4.peer_address?;
        Some(Established {
            local_ip,
            peer_ip,
            dns: ipv4.dns_servers,
            mru: status.mru,
        })
    }

    /// Queue an LCP Echo-Request if the link is up (Opened, or the sub-`Opened`
    /// dip of a post-Open Configure-Request renegotiation). The identifier is
    /// sequenced here (wrapping) so the FSM stays deterministic for tests. Returns
    /// `true` if one was queued, `false` (no-op) if the link is not up.
    pub fn send_echo_request(&mut self) -> bool {
        self.echo_id = self.echo_id.wrapping_add(1);
        match self.ppp.lcp_echo_request(self.echo_id) {
            Some(frame) => {
                self.out.push(serialize(frame));
                true
            }
            None => false,
        }
    }

    /// Take-and-clear the liveness flag: `true` if a matching Echo-Reply arrived
    /// since the last call.
    pub fn take_echo_reply_seen(&mut self) -> bool {
        self.ppp.take_echo_reply_seen()
    }

    /// True once LCP is Opened (the link is up enough to echo). Stays true across
    /// Auth/Network/Open and goes false during an inbound renegotiation or a
    /// teardown.
    pub fn lcp_opened(&self) -> bool {
        self.ppp.lcp_opened()
    }

    /// True when LCP has reached Closed: a peer TerminateReq in Opened or a local
    /// close. This is the authoritative gate for link-down detection. A transient
    /// drop below Opened during an inbound Configure-Request renegotiation does not
    /// set this, so a RFC 1661 reopen is not misread as link death.
    pub fn lcp_closed(&self) -> bool {
        self.ppp.lcp_closed()
    }

    fn drive_poll(&mut self) {
        let mut produced: Vec<Vec<u8>> = Vec::new();
        self.ppp.poll(|frame| produced.push(serialize(frame)));
        self.out.append(&mut produced);
    }
}

/// Serialize one outbound frame into a raw PPP payload (2-byte proto + body).
///
/// Control packets allocate exactly `buffer_len()` bytes (no fixed-size stack
/// array, no assert!(len <= N)); CHAP frames arrive already assembled.
fn serialize(frame: OutFrame<'_>) -> Vec<u8> {
    match frame {
        OutFrame::Packet(pkt) => {
            let mut buf = vec![0u8; pkt.buffer_len()];
            pkt.emit(&mut buf);
            buf
        }
        OutFrame::Raw(bytes) => bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pppoe::ppp::wire::{Code, ProtocolType};

    const SECRET: &[u8] = b"tchile";
    const USER: &[u8] = b"client";
    // Deterministic to match the captured ConfReq option bytes.
    const MRU: u16 = 1392;
    const MAGIC: u32 = 0x06c27d42;
    /// The peer's Magic-Number, distinct from ours. A real LCP Echo-Reply carries
    /// the replier's magic, so a peer reply differs from our local magic.
    const PEER_MAGIC: u32 = 0x5ea17b03;

    const CHALLENGE: [u8; 16] = [
        0x1a, 0x88, 0x05, 0x28, 0x03, 0x05, 0x07, 0x22, 0xcd, 0x6c, 0x29, 0xed, 0x93, 0xd9, 0x4a,
        0xe8,
    ];
    const EXPECTED_RESP: [u8; 16] = [
        0xf5, 0xab, 0x4c, 0xd3, 0x3f, 0x95, 0x80, 0x80, 0xeb, 0x5d, 0xaf, 0xe9, 0xb0, 0xb5, 0xf3,
        0x0e,
    ];

    fn session() -> PppSession<'static> {
        config(false)
    }

    fn config(request_dns: bool) -> PppSession<'static> {
        PppSession::new(PppConfig {
            username: USER,
            password: SECRET,
            mru: MRU,
            magic: MAGIC,
            request_dns,
        })
        .expect("construct")
    }

    fn drain(s: &mut PppSession) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Some(p) = s.poll_transmit() {
            v.push(p);
        }
        v
    }

    /// Build an LCP control packet: proto c0 21, code, id, then raw option bytes.
    fn lcp(code: Code, id: u8, opts: &[u8]) -> Vec<u8> {
        ctrl(0xc021, code, id, opts)
    }

    fn ipcp(code: Code, id: u8, opts: &[u8]) -> Vec<u8> {
        ctrl(0x8021, code, id, opts)
    }

    fn ctrl(proto: u16, code: Code, id: u8, opts: &[u8]) -> Vec<u8> {
        let length = 4 + opts.len();
        let mut p = Vec::new();
        p.extend_from_slice(&proto.to_be_bytes());
        p.push(code as u8);
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

    // Read a control packet's code (3rd byte after the 2-byte proto).
    fn code_of(p: &[u8]) -> Code {
        Code::from(p[2])
    }

    fn proto_of(p: &[u8]) -> ProtocolType {
        ProtocolType::from(u16::from_be_bytes([p[0], p[1]]))
    }

    #[test]
    fn full_drive_to_established() {
        let mut s = session();

        // 1. open() -> our LCP ConfReq with MRU 1392 + Magic 0x06c27d42.
        s.open().expect("open");
        let out = drain(&mut s);
        assert_eq!(out.len(), 1);
        let req = &out[0];
        assert_eq!(proto_of(req), ProtocolType::LCP);
        assert_eq!(code_of(req), Code::ConfigureReq);
        // Options after the 6-byte header: MRU 01 04 05 70, Magic 05 06 06 c2 7d 42.
        assert_eq!(
            &req[6..],
            &[0x01, 0x04, 0x05, 0x70, 0x05, 0x06, 0x06, 0xc2, 0x7d, 0x42]
        );

        // 2. Peer LCP ConfReq: MRU 1492 + Auth CHAP-MD5 + Magic 0xf6b2f2ce.
        let peer_opts = [
            0x01, 0x04, 0x05, 0xd4, // MRU 1492
            0x03, 0x05, 0xc2, 0x23, 0x05, // Auth CHAP-MD5
            0x05, 0x06, 0xf6, 0xb2, 0xf2, 0xce, // Magic
        ];
        s.feed(&lcp(Code::ConfigureReq, 1, &peer_opts));
        let out = drain(&mut s);
        assert_eq!(out.len(), 1);
        let ack = &out[0];
        assert_eq!(proto_of(ack), ProtocolType::LCP);
        assert_eq!(code_of(ack), Code::ConfigureAck); // we accept all three
        assert_eq!(&ack[6..], &peer_opts); // every option acked, none Nak'd to PAP

        // 3. Peer ConfAck of our ConfReq -> LCP Opened, phase Auth.
        s.feed(&lcp(Code::ConfigureAck, req[3], &req[6..]));
        let _ = drain(&mut s);
        assert_eq!(s.phase(), PppPhase::Auth);

        // 4. CHAP Challenge -> Response with the golden value + our username.
        s.feed(&chap_challenge(1, &CHALLENGE, b"NE40-BRAS"));
        let out = drain(&mut s);
        assert_eq!(out.len(), 1);
        let resp = &out[0];
        assert_eq!(proto_of(resp), ProtocolType::CHAP);
        assert_eq!(resp[2], 2); // CHAP Response
        assert_eq!(resp[6], 16); // value-size
        assert_eq!(&resp[7..23], &EXPECTED_RESP);
        assert_eq!(&resp[23..], USER);

        // 5. CHAP Success -> phase Network, we open IPCP with <addr 0.0.0.0>.
        s.feed(&chap_result(3, 1));
        let out = drain(&mut s);
        assert_eq!(s.phase(), PppPhase::Network);
        assert_eq!(out.len(), 1);
        let ireq = &out[0];
        assert_eq!(proto_of(ireq), ProtocolType::IPv4CP);
        assert_eq!(code_of(ireq), Code::ConfigureReq);
        assert_eq!(&ireq[6..], &[0x03, 0x06, 0x00, 0x00, 0x00, 0x00]);

        // 6. Peer IPCP ConfReq <addr 186.107.96.1> -> we ConfAck.
        let peer_ip = [0x03, 0x06, 0xba, 0x6b, 0x60, 0x01];
        s.feed(&ipcp(Code::ConfigureReq, 1, &peer_ip));
        let out = drain(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(code_of(&out[0]), Code::ConfigureAck);
        assert_eq!(&out[0][6..], &peer_ip);

        // 7. Peer IPCP ConfNak <addr 186.107.116.16> -> we re-ConfReq that addr.
        let our_ip = [0x03, 0x06, 0xba, 0x6b, 0x74, 0x10];
        s.feed(&ipcp(Code::ConfigureNack, ireq[3], &our_ip));
        let out = drain(&mut s);
        assert_eq!(out.len(), 1);
        let ireq2 = &out[0];
        assert_eq!(code_of(ireq2), Code::ConfigureReq);
        assert_eq!(&ireq2[6..], &our_ip);

        // 8. Peer ConfAck of our new IP -> IPCP Opened, phase Open.
        s.feed(&ipcp(Code::ConfigureAck, ireq2[3], &our_ip));
        let _ = drain(&mut s);
        assert_eq!(s.phase(), PppPhase::Open);

        // 9. Established with the captured addresses, no DNS, mru = min(1392,1492).
        let est = s.established().expect("established");
        assert_eq!(est.local_ip, Ipv4Addr::new(186, 107, 116, 16));
        assert_eq!(est.peer_ip, Ipv4Addr::new(186, 107, 96, 1));
        assert_eq!(est.dns, [None, None]);
        assert_eq!(est.mru, 1392);
    }

    #[test]
    fn ipcp_learns_dns_from_nak() {
        let mut s = config(true); // pppd usepeerdns: request DNS too
        s.open().expect("open");
        let req = drain(&mut s).remove(0);

        // Bring LCP up with CHAP, auth, and IPCP through to a request.
        let peer_opts = [
            0x01, 0x04, 0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0xf6, 0xb2, 0xf2,
            0xce,
        ];
        s.feed(&lcp(Code::ConfigureReq, 1, &peer_opts));
        let _ = drain(&mut s);
        s.feed(&lcp(Code::ConfigureAck, req[3], &req[6..]));
        let _ = drain(&mut s);
        s.feed(&chap_challenge(1, &CHALLENGE, b"NE40-BRAS"));
        let _ = drain(&mut s);
        s.feed(&chap_result(3, 1));
        let ireq = drain(&mut s).remove(0);
        // With usepeerdns the ConfReq carries address + DNS1 + DNS2.
        assert!(ireq[6..].windows(2).any(|w| w == [0x81, 0x06])); // Dns1 requested

        // Peer Naks the address and DNS1; we re-request with the learned values.
        let nak = [
            0x03, 0x06, 0xba, 0x6b, 0x74, 0x10, // addr
            0x81, 0x06, 0x08, 0x08, 0x08, 0x08, // Dns1 8.8.8.8
        ];
        s.feed(&ipcp(Code::ConfigureNack, ireq[3], &nak));
        let ireq2 = drain(&mut s).remove(0);
        // The re-request must carry Dns1 8.8.8.8.
        assert!(ireq2[6..]
            .windows(6)
            .any(|w| w == [0x81, 0x06, 0x08, 0x08, 0x08, 0x08]));

        // Peer ConfReq for its own address so we learn peer_address.
        s.feed(&ipcp(
            Code::ConfigureReq,
            1,
            &[0x03, 0x06, 0xba, 0x6b, 0x60, 0x01],
        ));
        let _ = drain(&mut s);
        // Peer Acks our request; established carries the DNS and addresses.
        s.feed(&ipcp(Code::ConfigureAck, ireq2[3], &ireq2[6..]));
        let _ = drain(&mut s);
        let est = s.established().expect("established");
        assert_eq!(est.dns[0], Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(est.local_ip, Ipv4Addr::new(186, 107, 116, 16));
        assert_eq!(est.peer_ip, Ipv4Addr::new(186, 107, 96, 1));
    }

    #[test]
    fn rejects_overlong_credentials() {
        let long = vec![b'a'; 256];
        let r = PppSession::new(PppConfig {
            username: &long,
            password: SECRET,
            mru: MRU,
            magic: MAGIC,
            request_dns: false,
        });
        assert!(matches!(r, Err(Error::CredentialTooLong)));
    }

    // De-panic gate: a pile of crafted and pseudo-random payloads fed to the
    // receive path must drop/consume, never panic. Driven from several link
    // states (including LCP/IPCP Opened) so state-dependent arms are covered.
    // Run under the default test profile, which has overflow-checks ON, so
    // arithmetic overflow also traps.
    #[test]
    fn fuzz_receive_path_never_panics() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],                                                           // 0-byte: proto-field read
            vec![0xc0],                         // 1-byte: proto-field read
            vec![0xc0, 0x21],                   // proto only, no body
            vec![0xc0, 0x21, 0x01, 0x01, 0x00], // LCP len < 6
            vec![0xc0, 0x21, 0x01, 0x01, 0x00, 0x06, 0x01, 0x04], // ConfReq, truncated option
            vec![0xc0, 0x21, 0x01, 0x01, 0x00, 0x08, 0x01, 0x01, 0x05, 0x06], // option len < 2
            vec![0xc0, 0x21, 0x01, 0x01, 0x00, 0x08, 0x01, 0xff, 0x05, 0x06], // option len overrun
            // ConfReq with many small options (no MAX_OPTIONS cap: must parse).
            {
                let mut opts = Vec::new();
                for _ in 0..40 {
                    opts.extend_from_slice(&[0x05, 0x06, 0x00, 0x00, 0x00, 0x00]);
                }
                lcp(Code::ConfigureReq, 1, &opts)
            },
            lcp(Code::ConfigureNack, 1, &[0x00]), // Nak with len < 6 body
            lcp(Code::ConfigureRej, 1, &[0x01, 0xff]), // Rej with malformed option
            vec![0xc0, 0x21, 0x09, 0x01, 0x00, 0x00], // EchoReq, length field 0 (empty body)
            vec![0xc0, 0x21, 0x09, 0x01, 0x00, 0x01], // EchoReq, length 1 (< 4-byte header)
            vec![0xc0, 0x21, 0x09, 0x01, 0x00, 0x03], // EchoReq, length 3 (< 4-byte header)
            vec![0xc0, 0x21, 0x05, 0x01, 0x00, 0x00], // TerminateReq, length field 0
            vec![0xc0, 0x21, 0x05, 0x01, 0x00, 0x02], // TerminateReq, length 2 (< header)
            // EchoReply variants exercising the inbound liveness pre-dispatch peek.
            vec![0xc0, 0x21, 0x0a, 0x01, 0x00, 0x08, 0x06, 0xc2, 0x7d, 0x42], // well-formed, our magic
            vec![0xc0, 0x21, 0x0a, 0x01, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef], // well-formed, wrong magic
            vec![0xc0, 0x21, 0x0a, 0x01, 0x00, 0x06], // EchoReply, body truncated (no magic)
            vec![0xc0, 0x21, 0x0a, 0x01, 0xff, 0xff, 0x06, 0xc2, 0x7d, 0x42], // length overrun
            vec![0xc0, 0x21, 0x0a, 0x01, 0x00, 0x00], // EchoReply, length field 0 (empty body)
            chap_challenge(1, &[0xaa; 2], b"x"),      // value-size will be 2 here (well-formed)
            // CHAP Challenge with value-size overrunning the packet.
            vec![0xc2, 0x23, 0x01, 0x01, 0x00, 0x09, 0xff, 0xaa, 0xbb],
            vec![0x00, 0x21, 0xde, 0xad, 0xbe, 0xef], // inbound IPv4 before Open
            vec![0x12, 0x34, 0x01, 0x02, 0x03],       // unknown proto -> Protocol-Reject
        ];

        // Each payload is replayed against a fresh session in every reachable link
        // state, so state-dependent arms (e.g. EchoReq only answered in Opened) are
        // exercised, not just the post-open/pre-handshake state.
        let states: [fn() -> PppSession<'static>; 3] =
            [fresh_open, lcp_opened_session, established_session];

        for c in &cases {
            for build in &states {
                let mut s = build();
                let _ = s.feed(c);
                let _ = drain(&mut s);
            }
        }

        // Pseudo-random buffers with a fixed LCG (no IO, deterministic).
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
            for build in &states {
                let mut s = build();
                let _ = s.feed(&buf);
                let _ = drain(&mut s);
            }
        }
    }

    /// A fresh session that has sent its initial LCP ConfReq but seen no peer
    /// handshake, so LCP is in ReqSent.
    fn fresh_open() -> PppSession<'static> {
        let mut s = session();
        let _ = s.open();
        let _ = drain(&mut s);
        s
    }

    /// A session driven through the LCP handshake to Opened (phase Auth), so the
    /// EchoReq-in-Opened and other Opened-only arms are reachable.
    fn lcp_opened_session() -> PppSession<'static> {
        let mut s = session();
        s.open().expect("open");
        let req = drain(&mut s).remove(0);
        let peer_opts = [
            0x01, 0x04, 0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0xf6, 0xb2, 0xf2,
            0xce,
        ];
        s.feed(&lcp(Code::ConfigureReq, 1, &peer_opts));
        let _ = drain(&mut s);
        s.feed(&lcp(Code::ConfigureAck, req[3], &req[6..]));
        let _ = drain(&mut s);
        assert_eq!(s.phase(), PppPhase::Auth);
        s
    }

    /// A session driven all the way to phase Open (LCP and IPCP Opened).
    fn established_session() -> PppSession<'static> {
        let mut s = lcp_opened_session();
        s.feed(&chap_challenge(1, &CHALLENGE, b"NE40-BRAS"));
        let _ = drain(&mut s);
        let ireq = {
            s.feed(&chap_result(3, 1));
            drain(&mut s).remove(0)
        };
        s.feed(&ipcp(
            Code::ConfigureReq,
            1,
            &[0x03, 0x06, 0xba, 0x6b, 0x60, 0x01],
        ));
        let _ = drain(&mut s);
        let our_ip = [0x03, 0x06, 0xba, 0x6b, 0x74, 0x10];
        s.feed(&ipcp(Code::ConfigureNack, ireq[3], &our_ip));
        let ireq2 = drain(&mut s).remove(0);
        s.feed(&ipcp(Code::ConfigureAck, ireq2[3], &our_ip));
        let _ = drain(&mut s);
        assert_eq!(s.phase(), PppPhase::Open);
        s
    }

    #[test]
    fn inbound_ipv4_is_surfaced() {
        let mut s = session();
        let ip = vec![0x00, 0x21, 0x45, 0x00, 0x00, 0x14, 0xde, 0xad];
        match s.feed(&ip) {
            FeedOutcome::Ip(payload) => assert_eq!(payload, &ip[2..]),
            other => panic!("expected Ip, got {other:?}"),
        }
    }

    /// Build an LCP Echo-Reply (code 10) carrying a 4-byte Magic-Number body.
    fn echo_reply(id: u8, magic: u32) -> Vec<u8> {
        let mut p = vec![0xc0, 0x21, Code::EchoReply as u8, id];
        p.extend_from_slice(&8u16.to_be_bytes()); // length = 4 header + 4 magic
        p.extend_from_slice(&magic.to_be_bytes());
        p
    }

    #[test]
    fn echo_request_emitted_when_open() {
        let mut s = established_session();
        let _ = drain(&mut s);
        assert!(s.send_echo_request());
        let out = drain(&mut s);
        assert_eq!(out.len(), 1);
        let req = &out[0];
        assert_eq!(proto_of(req), ProtocolType::LCP);
        assert_eq!(code_of(req), Code::EchoReq);
        // Length field = 8 (4-byte header + 4-byte magic), body = our magic BE.
        assert_eq!(u16::from_be_bytes([req[4], req[5]]), 0x0008);
        assert_eq!(&req[6..10], &MAGIC.to_be_bytes());
        assert_eq!(req.len(), 10);
    }

    #[test]
    fn echo_request_noop_before_open() {
        let mut s = fresh_open(); // LCP in ReqSent, not Opened
        assert!(!s.send_echo_request());
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn echo_request_answered_with_our_magic() {
        // An inbound Echo-Request carries the peer's magic; our Echo-Reply must
        // carry OUR magic (RFC 1661 section 5.8), not echo the peer's back, or a
        // peer doing loopback detection sees its own magic and drops the reply.
        let mut s = established_session();
        let _ = drain(&mut s);
        let mut req = vec![0xc0, 0x21, Code::EchoReq as u8, 0x42];
        req.extend_from_slice(&8u16.to_be_bytes());
        req.extend_from_slice(&PEER_MAGIC.to_be_bytes());
        s.feed(&req);
        let out = drain(&mut s);
        let reply = out
            .iter()
            .find(|f| proto_of(f) == ProtocolType::LCP && code_of(f) == Code::EchoReply)
            .expect("an LCP Echo-Reply");
        assert_eq!(reply[3], 0x42, "reply keeps the request id");
        assert_eq!(
            &reply[6..10],
            &MAGIC.to_be_bytes(),
            "reply carries our magic"
        );
    }

    #[test]
    fn echo_reply_refreshes_liveness() {
        let mut s = established_session();
        let _ = drain(&mut s);
        // A reply carrying the peer's magic (not ours) is proof the peer answered.
        s.feed(&echo_reply(7, PEER_MAGIC));
        assert!(s.take_echo_reply_seen());
        // Take-and-clear: a second read is false.
        assert!(!s.take_echo_reply_seen());
    }

    #[test]
    fn echo_reply_own_magic_is_loopback_ignored() {
        // RFC 1661 section 5.8: a reply carrying OUR own Magic-Number means the link
        // is looped back, not a live peer, so it does not count as liveness.
        let mut s = established_session();
        let _ = drain(&mut s);
        s.feed(&echo_reply(1, MAGIC));
        assert!(!s.take_echo_reply_seen());
    }

    #[test]
    fn echo_reply_id_independent() {
        // A peer reply (its magic, not ours) proves liveness regardless of id:
        // liveness keys on the magic differing from ours, not on the id.
        let mut s = established_session();
        let _ = drain(&mut s);
        s.send_echo_request(); // echo_id is now 1
        let _ = drain(&mut s);
        s.feed(&echo_reply(0x99, PEER_MAGIC));
        assert!(s.take_echo_reply_seen());
    }

    #[test]
    fn echo_reply_with_zero_magic_is_liveness() {
        // A peer that did not negotiate a Magic-Number replies with magic 0. Our
        // magic is always nonzero (see PppConfig::with_random_magic), so a zero
        // reply differs from ours and counts as a live peer rather than a loopback.
        let mut s = established_session();
        let _ = drain(&mut s);
        s.feed(&echo_reply(5, 0));
        assert!(s.take_echo_reply_seen());
    }

    #[test]
    fn lcp_opened_tracks_state() {
        let s = fresh_open();
        assert!(!s.lcp_opened());
        let s = lcp_opened_session();
        assert!(s.lcp_opened());
        let s = established_session();
        assert!(s.lcp_opened());
    }

    /// Drive an established session, then feed a BRAS-style inbound LCP
    /// Configure-Request (RFC 1661 RcR in Opened) that we Ack but the peer never
    /// Acks back, leaving LCP in a sub-`Opened` renegotiation state. Returns the
    /// session and the peer's Configure-Request id.
    fn established_then_reneg() -> PppSession<'static> {
        let mut s = established_session();
        let _ = drain(&mut s);
        assert!(s.lcp_opened());
        // BRAS reopens LCP with a Magic-Number-only Configure-Request. We Ack it
        // and re-send our own Configure-Request; LCP dips to AckSent (sub-Opened).
        let reneg = [0x05, 0x06, 0xab, 0xcd, 0xef, 0x01];
        s.feed(&lcp(Code::ConfigureReq, 0x42, &reneg));
        let _ = drain(&mut s);
        assert!(!s.lcp_opened(), "renegotiation dips LCP below Opened");
        assert!(!s.lcp_closed(), "renegotiation is not a teardown");
        s
    }

    #[test]
    fn echo_request_answered_during_post_open_reneg() {
        // The live failure: after Open the BRAS sends a Configure-Request, dipping
        // LCP to AckSent, then keeps sending Echo-Requests every 30s. We must keep
        // replying for the whole life of the session, not only in strict Opened.
        let mut s = established_then_reneg();
        let mut req = vec![0xc0, 0x21, Code::EchoReq as u8, 0x10];
        req.extend_from_slice(&8u16.to_be_bytes());
        req.extend_from_slice(&PEER_MAGIC.to_be_bytes());
        s.feed(&req);
        let out = drain(&mut s);
        let reply = out
            .iter()
            .find(|f| proto_of(f) == ProtocolType::LCP && code_of(f) == Code::EchoReply)
            .expect("an Echo-Reply while sub-Opened after a post-Open reneg");
        assert_eq!(reply[3], 0x10, "reply keeps the request id");
        assert_eq!(
            &reply[6..10],
            &MAGIC.to_be_bytes(),
            "reply carries our magic"
        );
    }

    #[test]
    fn echo_request_originated_during_post_open_reneg() {
        // Our own keepalive must keep firing across the post-Open renegotiation dip,
        // not stall until the BRAS declares the link dead.
        let mut s = established_then_reneg();
        for _ in 0..3 {
            assert!(s.send_echo_request(), "echo originates while sub-Opened");
            let out = drain(&mut s);
            let req = out
                .iter()
                .find(|f| proto_of(f) == ProtocolType::LCP && code_of(f) == Code::EchoReq)
                .expect("an outbound Echo-Request");
            assert_eq!(&req[6..10], &MAGIC.to_be_bytes(), "echo carries our magic");
        }
    }

    #[test]
    fn echo_not_answered_or_originated_before_first_open() {
        // The sub-`Opened` states are reachable during initial bring-up too, before
        // the link has ever opened. There is no live peer to keep alive yet, so we
        // neither answer nor originate echoes there.
        let mut s = fresh_open(); // LCP in ReqSent, never reached Opened
        assert!(!s.lcp_opened());
        assert!(
            !s.send_echo_request(),
            "no echo before the link first opens"
        );
        let mut req = vec![0xc0, 0x21, Code::EchoReq as u8, 0x10];
        req.extend_from_slice(&8u16.to_be_bytes());
        req.extend_from_slice(&PEER_MAGIC.to_be_bytes());
        s.feed(&req);
        let out = drain(&mut s);
        assert!(
            !out.iter()
                .any(|f| proto_of(f) == ProtocolType::LCP && code_of(f) == Code::EchoReply),
            "no Echo-Reply before the link first opens"
        );
    }
}
