// Vendored and adapted from embassy-rs/ppproto, rev bd16b3093fe2ededb4fd7662ed253d7bc6b39a9b
// (tag v0.2.1). Upstream license: MIT OR Apache-2.0, Copyright (c) 2020 Dario Nieuwenhuis.
// Adapted to std, de-panicked for untrusted PPPoE session input, and extended for
// PPPoE+CHAP-MD5 (LCP MRU/Magic-Number/CHAP auth). See src/pppoe/ppp/mod.rs for the change log.

//! PAP (RFC 1334), kept only as a fallback for a BRAS that offers PAP instead of
//! CHAP. `handle` runs on untrusted input: the dispatch in `mod.rs` routes ANY
//! PAP-proto frame here regardless of what we negotiated, so a hostile BRAS could
//! send one even on a CHAP link. Every length is bounds-checked; a malformed PAP
//! packet is dropped, never panics.
//!
//! Credentials are validated (<= 255 bytes, the 1-byte PAP length fields) at
//! engine construction, so `PAP::new` is infallible here.

use super::wire::{Code, PPPPayload, Packet, Payload, ProtocolType};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum State {
    Closed,
    ReqSent,
    Opened,
}

#[allow(clippy::upper_case_acronyms)] // protocol name, RFC 1334
pub struct PAP<'a> {
    state: State,
    id: u8,
    username: &'a [u8],
    password: &'a [u8],
}

impl<'a> PAP<'a> {
    pub fn new(username: &'a [u8], password: &'a [u8]) -> Self {
        Self {
            state: State::Closed,
            id: 1,
            username,
            password,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Send our PAP Authenticate-Request. The engine only calls this from
    /// `Closed`; the guard is defensive (upstream asserted the precondition).
    pub fn open(&mut self) -> Packet<'_> {
        if self.state != State::Closed {
            return self.send_configure_request();
        }
        self.state = State::ReqSent;
        self.send_configure_request()
    }

    pub fn close(&mut self) {
        self.state = State::Closed;
    }

    pub fn handle(&mut self, pkt: &mut [u8], mut tx: impl FnMut(Packet<'_>)) {
        // Drop: shorter than the 2-byte proto + 4-byte PAP header.
        if pkt.len() < 6 {
            return;
        }
        let code = Code::from(pkt[2]);
        let len = match pkt.get(4..6) {
            Some(l) => u16::from_be_bytes([l[0], l[1]]) as usize,
            None => return,
        };
        // `len` counts from the Code byte; total payload is `len + 2`. The
        // upstream check (`len > pkt.len()`) was off-by-two and would panic on
        // the `pkt[..len + 2]` slice for `len` near `pkt.len()`. This is an
        // attacker-reachable overflow, so the bound is corrected here.
        if len + 2 > pkt.len() {
            return;
        }
        let _pkt = &mut pkt[..len + 2];

        match (code, self.state) {
            (Code::ConfigureAck, State::ReqSent) => self.state = State::Opened,
            (Code::ConfigureNack, State::ReqSent) => tx(self.send_configure_request()),
            _ => {}
        }
    }

    fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1);
        self.id
    }

    fn send_configure_request(&mut self) -> Packet<'a> {
        Packet {
            proto: ProtocolType::PAP,
            payload: Payload::PPP(
                Code::ConfigureReq,
                self.next_id(),
                PPPPayload::PAP(self.username, self.password),
            ),
        }
    }
}
