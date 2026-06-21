// Vendored and adapted from embassy-rs/ppproto, rev bd16b3093fe2ededb4fd7662ed253d7bc6b39a9b
// (tag v0.2.1). Upstream license: MIT OR Apache-2.0, Copyright (c) 2020 Dario Nieuwenhuis.
// Adapted to std, de-panicked for untrusted PPPoE session input, and extended for
// PPPoE+CHAP-MD5 (LCP MRU/Magic-Number/CHAP auth). See src/pppoe/ppp/mod.rs for the change log.

//! LCP option negotiation for PPPoE.
//!
//! Differences from upstream (serial PPP) LCP, all driven by what a PPPoE BRAS
//! actually negotiates:
//!  - Accept the peer's CHAP-MD5 auth proposal (Auth-Protocol 0xc223, algo 0x05)
//!    and route to the CHAP handler. PAP is accepted only if the peer offers it;
//!    we never Nak the peer toward PAP (upstream forced PAP).
//!  - Send and accept the MRU option (type 1). The advertised value is injected.
//!  - Send and accept a Magic-Number (type 5). The value is random per session,
//!    injected from the IO boundary so the FSM stays deterministic for tests.
//!  - Do NOT originate Asyncmap/ACCM (type 2): that is an HDLC/serial concept,
//!    irrelevant over PPPoE. We still Ack a peer that sends it, to avoid a
//!    gratuitous Reject.

use super::option_fsm::{Protocol, Verdict};
use super::wire::ProtocolType;

/// LCP option codes we understand. Anything else decodes to `Unknown` and is
/// Rejected.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
enum Option {
    Unknown = 0,
    Mru = 1,
    Asyncmap = 2,
    Auth = 3,
    MagicNumber = 5,
}

impl From<u8> for Option {
    fn from(v: u8) -> Self {
        match v {
            1 => Option::Mru,
            2 => Option::Asyncmap,
            3 => Option::Auth,
            5 => Option::MagicNumber,
            _ => Option::Unknown,
        }
    }
}

/// Authentication protocol the peer selected in LCP.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AuthType {
    None,
    PAP,
    ChapMd5,
}

#[allow(clippy::upper_case_acronyms)] // protocol name, RFC 1661
pub struct LCP {
    pub auth: AuthType,

    /// Our advertised MRU (injected; default 1492 for PPPoE).
    pub mru_local: u16,
    /// MRU the peer advertised (default RFC 1661 value until told otherwise).
    pub mru_remote: u16,
    mru_rej: bool,

    /// Our LCP Magic-Number (random per session, injected).
    pub magic_local: u32,
    /// The peer's Magic-Number (needed to answer LCP Echo-Request).
    pub magic_remote: u32,
    magic_rej: bool,
}

impl LCP {
    pub fn new(mru_local: u16, magic_local: u32) -> Self {
        Self {
            auth: AuthType::None,
            mru_local,
            mru_remote: 1500,
            mru_rej: false,
            magic_local,
            magic_remote: 0,
            magic_rej: false,
        }
    }

    /// The peer's negotiated Magic-Number (0 until the peer sends one).
    pub fn magic_remote(&self) -> u32 {
        self.magic_remote
    }
}

impl Protocol for LCP {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::LCP
    }

    fn peer_options_start(&mut self) {
        self.auth = AuthType::None;
    }

    fn peer_option_received<'a>(&mut self, code: u8, data: &'a [u8]) -> Verdict<'a> {
        let opt = Option::from(code);
        match opt {
            Option::Unknown => Verdict::Rej,
            Option::Mru => {
                if data.len() == 2 {
                    self.mru_remote = u16::from_be_bytes([data[0], data[1]]);
                    Verdict::Ack
                } else {
                    Verdict::Rej
                }
            }
            Option::Asyncmap => {
                // Irrelevant for PPPoE, but Ack a well-formed value rather than
                // Rejecting a peer that gratuitously offers it.
                if data.len() == 4 {
                    Verdict::Ack
                } else {
                    Verdict::Rej
                }
            }
            Option::Auth => {
                // CHAP-MD5: 0xc223 + algorithm 0x05 (RFC 1994).
                if data == [0xc2, 0x23, 0x05] {
                    self.auth = AuthType::ChapMd5;
                    Verdict::Ack
                }
                // PAP fallback only if the peer actually offers it.
                else if data == [0xc0, 0x23] {
                    self.auth = AuthType::PAP;
                    Verdict::Ack
                }
                // Unknown auth: Reject the option. Do NOT Nak toward PAP.
                else {
                    Verdict::Rej
                }
            }
            Option::MagicNumber => {
                if data.len() == 4 {
                    self.magic_remote = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    Verdict::Ack
                } else {
                    Verdict::Rej
                }
            }
        }
    }

    fn own_options(&mut self, mut f: impl FnMut(u8, &[u8])) {
        if !self.mru_rej {
            f(Option::Mru as u8, &self.mru_local.to_be_bytes());
        }
        if !self.magic_rej {
            f(Option::MagicNumber as u8, &self.magic_local.to_be_bytes());
        }
    }

    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool) {
        let opt = Option::from(code);
        match opt {
            Option::Mru => {
                if is_rej {
                    self.mru_rej = true;
                } else if data.len() == 2 {
                    // Only honor a downward Nak. The advertised MRU caps the peer's
                    // frame size to fit the tunnel; adopting a larger value the peer
                    // suggests would defeat that, so ignore upward suggestions.
                    let v = u16::from_be_bytes([data[0], data[1]]);
                    if v < self.mru_local {
                        self.mru_local = v;
                    }
                } else {
                    self.mru_rej = true;
                }
            }
            Option::MagicNumber => {
                if is_rej {
                    self.magic_rej = true;
                } else if data.len() == 4 {
                    // Magic collision: adopt a fresh value the peer suggested.
                    self.magic_local = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                } else {
                    self.magic_rej = true;
                }
            }
            _ => {}
        }
    }
}
