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

pub struct OptionFsm<P> {
    id: u8,
    state: State,
    /// Latched once the FSM first reaches `Opened`, cleared only on `close()`.
    /// Distinguishes a sub-`Opened` state during initial bring-up (no peer link
    /// yet) from the transient dip an RFC 1661 RcR-in-Opened renegotiation causes
    /// after the link is up. Echo handling keys on this so a BRAS that re-confirms
    /// LCP after Open does not silence our keepalive.
    up_seen: bool,
    proto: P,
}

impl<P: Protocol> OptionFsm<P> {
    pub fn new(proto: P) -> Self {
        Self {
            id: 1,
            state: State::Closed,
            up_seen: false,
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
        self.state = State::ReqSent;
        self.send_configure_request()
    }

    pub fn close(&mut self) {
        self.enter_closed();
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
        let mut opts = Vec::new();

        self.proto.own_options(|code, data| {
            opts.push(OptionVal::new(code, data));
        });

        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(
                Code::ConfigureReq,
                self.next_id(),
                PPPPayload::Options(Options(opts)),
            ),
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
        if parse_options(opts_in, |ocode, odata| {
            let (ret_code, data) = match self.proto.peer_option_received(ocode, odata) {
                Verdict::Ack => (Code::ConfigureAck, odata),
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
