// Vendored and adapted from embassy-rs/ppproto, rev bd16b3093fe2ededb4fd7662ed253d7bc6b39a9b
// (tag v0.2.1). Upstream license: MIT OR Apache-2.0, Copyright (c) 2020 Dario Nieuwenhuis.
// Adapted to std, de-panicked for untrusted PPPoE session input, and extended for
// PPPoE+CHAP-MD5 (LCP MRU/Magic-Number/CHAP auth). See src/pppoe/ppp/mod.rs for the change log.

//! Generic Configure-Req/Ack/Nak/Rej option negotiation FSM (RFC 1661), driven by
//! a `Protocol` trait that LCP and IPCP implement.
//!
//! The whole `handle`/`received_configure_req` path runs on untrusted BRAS input.
//! Every length is bounds-checked with `.get(..)` and any malformed packet is
//! DROPPED (the function returns and sends nothing), never panics: the release
//! profile is panic=abort, so a single bad frame must not take down the process.

use super::wire::{Code, OptionVal, Options, PPPPayload, Packet, Payload, ProtocolType};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Verdict<'a> {
    Ack,
    Nack(&'a [u8]),
    Rej,
}

pub trait Protocol {
    fn protocol(&self) -> ProtocolType;

    fn own_options(&mut self, f: impl FnMut(u8, &[u8]));
    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool);

    fn peer_options_start(&mut self);
    fn peer_option_received<'a>(&mut self, code: u8, data: &'a [u8]) -> Verdict<'a>;

    /// The Magic-Number to stamp into an Echo-Reply this protocol originates. LCP
    /// returns its local magic (RFC 1661: each side sends its own magic, so the
    /// reply must not echo the requester's back); protocols without a magic leave
    /// the inbound bytes unchanged.
    fn echo_reply_magic(&self) -> Option<u32> {
        None
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum State {
    Closed,
    ReqSent,
    AckReceived,
    AckSent,
    Opened,
}

/// RFC 1661 restart timer period, in `on_tick` ticks (the driver ticks once a
/// second, so this is the RFC's 3-second default).
pub(crate) const RESTART_TICKS: u32 = 3;
/// RFC 1661 Max-Configure: total Configure-Request transmissions before the
/// negotiation is declared failed.
pub(crate) const MAX_CONFIGURE: u32 = 10;
/// RFC 1661 Max-Failure: Configure-Naks sent without an intervening
/// Configure-Ack before further Naks are converted to Configure-Reject.
const MAX_FAILURE: u32 = 5;

pub struct OptionFsm<P> {
    id: u8,
    state: State,
    /// Latched once the FSM first reaches `Opened`, cleared only on `close()`.
    /// Distinguishes a sub-`Opened` state during initial bring-up (no peer link
    /// yet) from the transient dip an RFC 1661 RcR-in-Opened renegotiation causes
    /// after the link is up. Echo handling keys on this so a BRAS that re-confirms
    /// LCP after Open does not silence our keepalive.
    up_seen: bool,
    /// Ticks since our last Configure-Request went out (the restart timer).
    ticks_since_send: u32,
    /// Configure-Requests sent since the last peer response (restart counter).
    attempts: u32,
    /// Configure-Naks sent since the last Configure-Ack (Max-Failure counter).
    naks_sent: u32,
    /// Latched when the restart counter exhausts: negotiation failed terminally
    /// and the FSM parked itself in `Closed`. Cleared by the next `open()`.
    failed: bool,
    proto: P,
}

impl<P: Protocol> OptionFsm<P> {
    pub fn new(proto: P) -> Self {
        Self {
            id: 1,
            state: State::Closed,
            up_seen: false,
            ticks_since_send: 0,
            attempts: 0,
            naks_sent: 0,
            failed: false,
            proto,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// True once the FSM has reached `Opened` and has not since been `close()`d.
    /// The link is usable for Echo keepalive even when an inbound Configure-Request
    /// has dipped it into a sub-`Opened` renegotiation state (RFC 1661 RcR in
    /// Opened): the peer expects Echo-Reply for the whole life of the session, and
    /// we keep originating our own Echo-Request across the dip.
    pub fn link_up(&self) -> bool {
        self.up_seen && self.state != State::Closed
    }

    pub fn proto(&self) -> &P {
        &self.proto
    }

    pub fn proto_mut(&mut self) -> &mut P {
        &mut self.proto
    }

    /// Kick off negotiation by sending our Configure-Request.
    ///
    /// The engine only calls this from `Closed`; the guard is defensive (the
    /// upstream `assert!(state == Closed)` would abort under panic=abort if a
    /// future caller ever broke that precondition).
    pub fn open(&mut self) -> Packet<'_> {
        if self.state != State::Closed {
            return self.send_configure_request();
        }
        self.failed = false;
        self.attempts = 0;
        self.naks_sent = 0;
        self.state = State::ReqSent;
        self.send_configure_request()
    }

    pub fn close(&mut self) {
        self.enter_closed();
    }

    /// True once the restart counter exhausted (RFC 1661 TO- with the counter at
    /// zero): negotiation failed terminally and the FSM is parked in `Closed`.
    /// The driver maps this to a link-down/redial; `open()` clears it.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Advance the restart timer one tick (RFC 1661 section 4.6, TO+/TO-).
    /// While our Configure-Request is unanswered (ReqSent/AckReceived/AckSent),
    /// retransmit it every `RESTART_TICKS`. Once `MAX_CONFIGURE` transmissions
    /// have gone unanswered the behavior splits on link history: during initial
    /// bring-up (`up_seen` false) the negotiation failed, so park in `Closed`
    /// and latch `failed`; after the link has been up, some BRASes reopen LCP
    /// and never Ack the reciprocal request while keeping the session usable,
    /// so just stop retransmitting and leave teardown to echo liveness. Per the
    /// RFC, a timeout in AckReceived falls back to ReqSent.
    pub fn on_tick(&mut self) -> Option<Packet<'static>> {
        match self.state {
            State::ReqSent | State::AckReceived | State::AckSent => {}
            State::Closed | State::Opened => return None,
        }
        self.ticks_since_send = self.ticks_since_send.saturating_add(1);
        if self.ticks_since_send < RESTART_TICKS {
            return None;
        }
        if self.attempts >= MAX_CONFIGURE {
            if !self.up_seen {
                self.enter_closed();
                self.failed = true;
            }
            return None;
        }
        if self.state == State::AckReceived {
            self.state = State::ReqSent;
        }
        // A retransmission of unchanged content keeps its Identifier (RFC 1661
        // section 5.1), so a late reply to any copy still matches.
        Some(self.configure_request(self.id))
    }

    /// The single path into `State::Closed`. Clearing `up_seen` here keeps the
    /// `link_up()` latch from surviving a teardown into a later Closed->ReqSent
    /// re-open, where a stale `up_seen` would report the link up during bring-up.
    fn enter_closed(&mut self) {
        self.state = State::Closed;
        self.up_seen = false;
    }

    pub fn handle(&mut self, pkt: &mut [u8], mut tx: impl FnMut(Packet<'_>)) {
        // Drop: PPP control packet shorter than its 2-byte proto + 4-byte header.
        if pkt.len() < 6 {
            return;
        }
        let code = Code::from(pkt[2]);
        let id = pkt[3];
        let len = match pkt.get(4..6) {
            Some(l) => u16::from_be_bytes([l[0], l[1]]) as usize,
            None => return,
        };
        // `len` counts the control packet from its Code byte (i.e. from pkt[2])
        // and must cover at least the mandatory 4-byte control header (Code, Id,
        // 2-byte Length) per RFC 1661. A smaller value (e.g. a 0-length EchoReq)
        // would re-slice `pkt` down to an empty body and panic downstream; drop it.
        if len < 4 {
            return;
        }
        // `len + 2` is the total payload incl. the 2-byte proto. Drop on overrun.
        if len + 2 > pkt.len() {
            return;
        }
        let pkt = &mut pkt[..len + 2];

        // A response to our Configure-Request re-arms the restart counter
        // (RFC 1661 irc): the peer is answering, negotiation is progressing.
        if self.state != State::Closed
            && matches!(
                code,
                Code::ConfigureAck | Code::ConfigureNack | Code::ConfigureRej
            )
        {
            self.attempts = 0;
        }

        match (code, self.state) {
            // Answer Echo-Request whenever the link is up (see `link_up`): Opened
            // plus the post-Open RcR dip, not pre-Open bring-up or teardown.
            (Code::EchoReq, _) if self.link_up() => {
                if let Some(resp) = self.send_echo_response(pkt) {
                    tx(resp)
                }
            }
            (Code::EchoReq, _) => {}

            // DiscardReqs are, well, discarded.
            (Code::DiscardReq, _) => {}

            // in state Closed, reply to any packet with TerminateAck (except to EchoReq!)
            (_, State::Closed) => tx(self.send_terminate_ack(id)),

            (Code::ConfigureReq, _) => {
                // A malformed ConfigureReq yields None: drop it, leave state
                // unchanged, send nothing. The peer's restart timer retransmits.
                let resp = match self.received_configure_req(pkt) {
                    Some(resp) => resp,
                    None => return,
                };
                let acked = matches!(resp.payload, Payload::PPP(Code::ConfigureAck, _, _));
                tx(resp);

                match (acked, self.state) {
                    // Unreachable in practice (the `_, Closed` arm above handles
                    // Closed); kept as a no-op so the RX path has no panic site.
                    (_, State::Closed) => {}
                    (true, State::ReqSent) => self.state = State::AckSent,
                    (true, State::AckReceived) => {
                        self.state = State::Opened;
                        self.up_seen = true;
                    }
                    (true, State::AckSent) => self.state = State::AckSent,
                    (true, State::Opened) => {
                        tx(self.send_configure_request());
                        self.state = State::AckSent;
                    }
                    (false, State::AckSent) => self.state = State::ReqSent,
                    (false, State::Opened) => {
                        tx(self.send_configure_request());
                        self.state = State::ReqSent;
                    }
                    (false, _) => {}
                }
            }

            (Code::ConfigureAck, State::ReqSent) => self.state = State::AckReceived,
            (Code::ConfigureAck, State::AckSent) => {
                self.state = State::Opened;
                self.up_seen = true;
            }
            (Code::ConfigureAck, State::AckReceived) | (Code::ConfigureAck, State::Opened) => {
                self.state = State::ReqSent;
                tx(self.send_configure_request())
            }

            (Code::ConfigureNack, _) | (Code::ConfigureRej, _) => {
                let is_rej = code == Code::ConfigureRej;

                // Drop a malformed Nak/Rej: no state change, no new ConfReq.
                if pkt.len() < 6 {
                    return;
                }
                let opts = &pkt[6..]; // skip header

                if parse_options(opts, |code, data| {
                    self.proto.own_option_nacked(code, data, is_rej)
                })
                .is_err()
                {
                    return;
                }

                match self.state {
                    State::Closed => return,
                    State::AckSent => {}
                    _ => self.state = State::ReqSent,
                }
                tx(self.send_configure_request())
            }
            (Code::TerminateReq, State::Opened) => {
                self.enter_closed();
                tx(self.send_terminate_ack(id))
            }
            (Code::TerminateReq, State::ReqSent)
            | (Code::TerminateReq, State::AckReceived)
            | (Code::TerminateReq, State::AckSent) => {
                self.state = State::ReqSent;
                tx(self.send_terminate_ack(id))
            }

            _ => {}
        };
    }

    fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1);
        self.id
    }

    fn send_configure_request(&mut self) -> Packet<'static> {
        let id = self.next_id();
        self.configure_request(id)
    }

    /// Build our Configure-Request under `id`. Every send restarts the timer
    /// (RFC 1661 scr) and spends one transmission from the restart counter.
    fn configure_request(&mut self, id: u8) -> Packet<'static> {
        self.ticks_since_send = 0;
        self.attempts = self.attempts.saturating_add(1);
        let mut opts = Vec::new();

        self.proto.own_options(|code, data| {
            opts.push(OptionVal::new(code, data));
        });

        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(Code::ConfigureReq, id, PPPPayload::Options(Options(opts))),
        }
    }

    fn send_terminate_ack(&mut self, id: u8) -> Packet<'static> {
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(Code::TerminateAck, id, PPPPayload::Raw(&mut [])),
        }
    }

    fn send_echo_response<'a>(&mut self, pkt: &'a mut [u8]) -> Option<Packet<'a>> {
        // `handle` enforces a 4-byte minimum control length, so the body past the
        // 2-byte proto is non-empty; the element guard is defense-in-depth to keep
        // this site index-panic-free even if a future caller changes that invariant.
        let magic = self.proto.echo_reply_magic();
        let body = pkt.get_mut(2..)?;
        *body.first_mut()? = Code::EchoReply as u8;
        // The inbound request holds the peer's Magic-Number; stamp ours over it so
        // the peer does not read its own magic back and treat the link as looped
        // (RFC 1661 section 5.8). Body layout: code, id, 2-byte length, 4-byte magic.
        if let Some(m) = magic {
            if let Some(slot) = body.get_mut(4..8) {
                slot.copy_from_slice(&m.to_be_bytes());
            }
        }
        Some(Packet {
            proto: self.proto.protocol(),
            payload: Payload::Raw(body),
        })
    }

    /// Build an outbound Echo-Request carrying a 4-byte Magic-Number body
    /// (RFC 1661 section 5.8). Only meaningful for LCP; the driver guards the call
    /// site so it is never built for IPCP. `id` is caller-sequenced (the engine
    /// sequences it so the FSM stays deterministic for tests); `magic` is our
    /// local Magic-Number. The owned body makes the returned packet `'static`.
    pub(super) fn send_echo_request(&mut self, id: u8, magic: u32) -> Packet<'static> {
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(
                Code::EchoReq,
                id,
                PPPPayload::Owned(magic.to_be_bytes().to_vec()),
            ),
        }
    }

    /// Answer an unknown PPP protocol with an LCP Protocol-Reject (RFC 1661).
    pub fn send_protocol_reject<'a>(&mut self, pkt: &'a mut [u8]) -> Packet<'a> {
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(Code::ProtocolRej, self.next_id(), PPPPayload::Raw(pkt)),
        }
    }

    /// Build the reply (ConfigureAck/Nak/Rej) to a peer Configure-Request.
    ///
    /// Returns `None` if the packet is too short or carries malformed options;
    /// the caller then drops the frame without advancing state.
    fn received_configure_req(&mut self, pkt: &[u8]) -> Option<Packet<'static>> {
        if pkt.len() < 6 {
            return None;
        }
        let id = pkt[3];
        let mut code = Code::ConfigureAck;
        let opts_in = &pkt[6..]; // skip header

        let mut opts = Vec::new();

        self.proto.peer_options_start();
        let naks_exhausted = self.naks_sent >= MAX_FAILURE;
        if parse_options(opts_in, |ocode, odata| {
            let (ret_code, data) = match self.proto.peer_option_received(ocode, odata) {
                Verdict::Ack => (Code::ConfigureAck, odata),
                // After MAX_FAILURE Naks without an Ack, negotiation is not
                // converging; further Naks become Rejects (RFC 1661 Max-Failure).
                Verdict::Nack(_) if naks_exhausted => (Code::ConfigureRej, odata),
                Verdict::Nack(data) => (Code::ConfigureNack, data),
                Verdict::Rej => (Code::ConfigureRej, odata),
            };

            if code < ret_code {
                code = ret_code;
                opts.clear();
            }

            if code == ret_code {
                opts.push(OptionVal::new(ocode, data));
            }
        })
        .is_err()
        {
            return None;
        }

        match code {
            Code::ConfigureAck => self.naks_sent = 0,
            Code::ConfigureNack => self.naks_sent = self.naks_sent.saturating_add(1),
            _ => {}
        }

        Some(Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(code, id, PPPPayload::Options(Options(opts))),
        })
    }
}

/// Iterate TLV options, bounds-checking every length. Returns `Err` if the option
/// stream is malformed (truncated, length under 2, or running past the buffer).
/// This is the correctness anchor for the receive path; it never indexes blind.
fn parse_options(mut pkt: &[u8], mut f: impl FnMut(u8, &[u8])) -> Result<(), MalformedError> {
    while !pkt.is_empty() {
        if pkt.len() < 2 {
            return Err(MalformedError);
        }

        let code = pkt[0];
        let len = pkt[1] as usize;

        if pkt.len() < len {
            return Err(MalformedError);
        }
        if len < 2 {
            return Err(MalformedError);
        }

        let data = &pkt[2..len];
        f(code, data);
        pkt = &pkt[len..];
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MalformedError;

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal protocol: offers one option, Naks the peer option codes in
    /// `nak` (echoing the offered bytes back as the hint), Acks the rest.
    struct Stub {
        nak: &'static [u8],
    }

    impl Protocol for Stub {
        fn protocol(&self) -> ProtocolType {
            ProtocolType::LCP
        }
        fn own_options(&mut self, mut f: impl FnMut(u8, &[u8])) {
            f(0x01, &[0x05, 0xd4]); // MRU 1492
        }
        fn own_option_nacked(&mut self, _code: u8, _data: &[u8], _is_rej: bool) {}
        fn peer_options_start(&mut self) {}
        fn peer_option_received<'a>(&mut self, code: u8, data: &'a [u8]) -> Verdict<'a> {
            if self.nak.contains(&code) {
                Verdict::Nack(data)
            } else {
                Verdict::Ack
            }
        }
    }

    fn fsm(nak: &'static [u8]) -> OptionFsm<Stub> {
        OptionFsm::new(Stub { nak })
    }

    /// Raw LCP control packet: 2-byte proto, code, id, length, options.
    fn lcp_pkt(code: Code, id: u8, opts: &[u8]) -> Vec<u8> {
        let mut p = vec![0xc0, 0x21, code as u8, id];
        p.extend_from_slice(&((4 + opts.len()) as u16).to_be_bytes());
        p.extend_from_slice(opts);
        p
    }

    fn code_of(p: &Packet<'_>) -> Code {
        match &p.payload {
            Payload::PPP(c, _, _) => *c,
            _ => panic!("expected a PPP control packet"),
        }
    }

    #[test]
    fn restart_timer_retransmits_then_fails_terminally() {
        let mut f = fsm(&[]);
        let first = f.open();
        let first_id = match first.payload {
            Payload::PPP(_, id, _) => id,
            _ => unreachable!(),
        };
        assert_eq!(f.state(), State::ReqSent);

        let mut sends = 1u32; // open() sent the first Configure-Request
        let mut ticks = 0u32;
        while f.state() != State::Closed {
            ticks += 1;
            assert!(
                ticks <= RESTART_TICKS * (MAX_CONFIGURE + 1),
                "the FSM must reach a terminal state"
            );
            if let Some(p) = f.on_tick() {
                assert_eq!(code_of(&p), Code::ConfigureReq);
                assert_eq!(ticks % RESTART_TICKS, 0, "retransmit only on the period");
                if let Payload::PPP(_, id, _) = p.payload {
                    assert_eq!(id, first_id, "retransmission keeps its Identifier");
                }
                sends += 1;
            }
        }
        assert!(f.failed());
        assert_eq!(sends, MAX_CONFIGURE);
        assert_eq!(ticks, RESTART_TICKS * MAX_CONFIGURE);

        // Terminal: further ticks stay silent, the state stays Closed.
        assert!(f.on_tick().is_none());
        assert_eq!(f.state(), State::Closed);

        // A fresh open() clears the latch and restarts negotiation.
        let _ = f.open();
        assert!(!f.failed());
        assert_eq!(f.state(), State::ReqSent);
    }

    #[test]
    fn peer_response_rearms_restart_counter() {
        let mut f = fsm(&[]);
        let _ = f.open();
        // Burn most of the budget waiting on a silent peer.
        for _ in 0..RESTART_TICKS * (MAX_CONFIGURE - 1) {
            let _ = f.on_tick();
        }
        assert_eq!(f.state(), State::ReqSent);

        // A ConfigureNak re-arms the counter (RFC 1661 irc) and re-requests.
        let mut nak = lcp_pkt(Code::ConfigureNack, 9, &[0x01, 0x04, 0x05, 0xd4]);
        let mut got = Vec::new();
        f.handle(&mut nak, |p| got.push(code_of(&p)));
        assert_eq!(got, vec![Code::ConfigureReq]);

        // The full budget is available again.
        for _ in 0..RESTART_TICKS * (MAX_CONFIGURE - 1) {
            let _ = f.on_tick();
        }
        assert_eq!(f.state(), State::ReqSent);
        assert!(!f.failed());
    }

    #[test]
    fn timeout_in_ack_received_falls_back_to_req_sent() {
        let mut f = fsm(&[]);
        let req = f.open();
        let id = match req.payload {
            Payload::PPP(_, id, _) => id,
            _ => unreachable!(),
        };
        let mut ack = lcp_pkt(Code::ConfigureAck, id, &[0x01, 0x04, 0x05, 0xd4]);
        f.handle(&mut ack, |_| {});
        assert_eq!(f.state(), State::AckReceived);

        for _ in 0..RESTART_TICKS - 1 {
            assert!(f.on_tick().is_none());
        }
        let p = f.on_tick().expect("retransmit on the restart period");
        assert_eq!(code_of(&p), Code::ConfigureReq);
        assert_eq!(f.state(), State::ReqSent);
    }

    #[test]
    fn post_open_reneg_exhaustion_parks_instead_of_failing() {
        // After the link has been up, a BRAS-initiated reopen whose reciprocal
        // request is never answered must not tear the link down: exhausting the
        // retransmit budget stops the retransmissions and nothing else, leaving
        // teardown to the echo-liveness layer.
        let mut f = fsm(&[]);
        let req = f.open();
        let id = match req.payload {
            Payload::PPP(_, id, _) => id,
            _ => unreachable!(),
        };
        let opts = [0x01, 0x04, 0x05, 0xd4];
        let mut peer_req = lcp_pkt(Code::ConfigureReq, 1, &opts);
        f.handle(&mut peer_req, |_| {});
        let mut ack = lcp_pkt(Code::ConfigureAck, id, &opts);
        f.handle(&mut ack, |_| {});
        assert_eq!(f.state(), State::Opened);

        // The BRAS reopens; we Ack and re-request, it never answers again.
        let mut reneg = lcp_pkt(Code::ConfigureReq, 2, &opts);
        f.handle(&mut reneg, |_| {});
        assert_eq!(f.state(), State::AckSent);

        for _ in 0..RESTART_TICKS * (MAX_CONFIGURE + 2) {
            let _ = f.on_tick();
        }
        assert_eq!(f.state(), State::AckSent, "the dip parks, never closes");
        assert!(!f.failed());
        assert!(f.on_tick().is_none(), "retransmissions stop at the budget");
    }

    #[test]
    fn max_failure_converts_nak_to_reject() {
        let mut f = fsm(&[0x99]);
        let _ = f.open();
        let opts = [0x99, 0x03, 0x01]; // one peer option we keep Nak'ing
        for i in 0..MAX_FAILURE {
            let mut req = lcp_pkt(Code::ConfigureReq, i as u8 + 1, &opts);
            let mut got = Vec::new();
            f.handle(&mut req, |p| got.push(code_of(&p)));
            assert_eq!(got, vec![Code::ConfigureNack], "Nak #{}", i + 1);
        }
        let mut req = lcp_pkt(Code::ConfigureReq, 0x77, &opts);
        let mut got = Vec::new();
        f.handle(&mut req, |p| got.push(code_of(&p)));
        assert_eq!(
            got,
            vec![Code::ConfigureRej],
            "past Max-Failure the Nak becomes a Reject"
        );
    }
}
