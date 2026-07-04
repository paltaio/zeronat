// Vendored and adapted from embassy-rs/ppproto, rev bd16b3093fe2ededb4fd7662ed253d7bc6b39a9b
// (tag v0.2.1). Upstream license: MIT OR Apache-2.0, Copyright (c) 2020 Dario Nieuwenhuis.
// Upstream license text is in src/pppoe/ppp/LICENSE-ppproto.
//
// Change log (this fork vs upstream ppproto v0.2.1):
//  - Dropped the pppos/HDLC layer entirely. PPPoE session frames carry raw PPP
//    (2-byte Protocol field + body) with no HDLC framing/FCS/byte-stuffing, so
//    the driver consumes a raw PPP payload directly.
//  - Removed the `heapless` and `num_enum` dependencies: enums use hand-written
//    `From<int>` decode + `as`-casts for emit; option lists use `std::vec::Vec`.
//    This also deletes upstream's fixed MAX_OPTIONS cap and three panic sites.
//  - De-panicked the entire receive path: every todo!/panic!/unreachable!/assert!
//    and unguarded slice/unwrap reachable from `received` on untrusted BRAS input
//    is now a bounds-checked drop or a typed error. The release profile is
//    panic=abort, so one malformed frame must not abort the process.
//  - LCP: accept CHAP-MD5 auth (route to the CHAP handler), keep PAP only as a
//    peer-offered fallback (never Nak toward PAP), and add MRU + Magic-Number
//    options (sent in our ConfReq, parsed/accepted from the peer).
//  - Added CHAP-MD5 (RFC 1994) in src/pppoe/auth.rs; inbound IPv4 is surfaced to
//    the caller instead of `todo!()`.

mod ipv4cp;
mod lcp;
mod option_fsm;
mod pap;
pub mod wire;

use std::ops::Range;

use self::ipv4cp::IPv4CP;
use self::lcp::{AuthType, LCP};
use self::option_fsm::{OptionFsm, State};
#[cfg(test)]
pub(crate) use self::option_fsm::{MAX_CONFIGURE, RESTART_TICKS};
use self::pap::{State as PapState, PAP};
use self::wire::{Code, Packet, ProtocolType};
use crate::pppoe::auth::Chap;

pub use self::ipv4cp::Ipv4Status;
pub use self::lcp::AuthType as LcpAuthType;

/// Default MRU advertised over PPPoE (1500 minus the 8-byte PPPoE+PPP overhead).
pub const DEFAULT_MRU: u16 = 1492;

/// PPP session configuration. Credentials are borrowed for the session lifetime
/// and feed both CHAP (primary) and PAP (fallback).
#[derive(Debug, Clone)]
pub struct Config<'a> {
    pub username: &'a [u8],
    pub password: &'a [u8],
}

/// Phase of the PPP connection (RFC 1661 link phases).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
pub enum Phase {
    Dead,
    Establish,
    Auth,
    Network,
    Open,
}

/// Snapshot of the PPP connection state.
#[derive(Debug)]
pub struct Status {
    pub phase: Phase,
    /// IPv4 configuration from IPCP, present only once IPCP is Opened.
    pub ipv4: Option<Ipv4Status>,
    /// Effective MRU = min(our advertised, peer advertised).
    pub mru: u16,
}

/// Error from the top-level receive path. Reserved for the mandatory 2-byte PPP
/// Protocol-field read; deeper decode failures (bad option, short control packet)
/// are handled inside the sub-FSMs by dropping the frame and sending nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxError {
    /// Payload too short to hold the 2-byte PPP Protocol field.
    Truncated,
}

/// Outcome of `received` for one inbound PPP payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RxOutcome {
    /// A control packet was consumed by an FSM (any replies were tx'd).
    Consumed,
    /// An inbound IPv4 datagram; `Range` indexes the IP bytes after the 2-byte
    /// proto field within the payload passed to `received`. The datapath
    /// routes it; the PPP core does not.
    IpPacket(Range<usize>),
}

/// An outbound frame the driver wants to send: either a structured control
/// `Packet` (serialized by the engine via `Packet::emit`) or a pre-built raw PPP
/// payload (used by CHAP, which assembles its own bytes).
pub enum OutFrame<'a> {
    Packet(Packet<'a>),
    Raw(Vec<u8>),
}

impl<'a> From<Packet<'a>> for OutFrame<'a> {
    fn from(p: Packet<'a>) -> Self {
        OutFrame::Packet(p)
    }
}

pub struct PPP<'a> {
    phase: Phase,
    opening: bool,
    config: Config<'a>,
    pub lcp: OptionFsm<LCP>,
    pub pap: PAP<'a>,
    pub chap: Chap,
    pub ipv4cp: OptionFsm<IPv4CP>,
    /// Set when an inbound LCP Echo-Reply from the peer is observed (its
    /// Magic-Number differs from ours; a reply carrying our own magic is a
    /// loopback and is ignored). The datapath's liveness timer take-and-clears it
    /// to count missed replies.
    echo_reply_seen: bool,
}

impl<'a> PPP<'a> {
    /// Build a PPP driver. `mru_local`/`magic_local` are injected so the FSM is
    /// deterministic for tests; the engine generates `magic_local` at the IO
    /// boundary via the system RNG.
    pub fn new(config: Config<'a>, mru_local: u16, magic_local: u32) -> Self {
        Self {
            phase: Phase::Dead,
            opening: false,
            lcp: OptionFsm::new(LCP::new(mru_local, magic_local)),
            pap: PAP::new(config.username, config.password),
            chap: Chap::new(),
            ipv4cp: OptionFsm::new(IPv4CP::new()),
            config,
            echo_reply_seen: false,
        }
    }

    /// Request DNS1/DNS2 in our IPCP ConfReq (pppd's `usepeerdns`).
    pub fn set_request_dns(&mut self, on: bool) {
        self.ipv4cp.proto_mut().set_request_dns(on);
    }

    /// True once LCP has reached the Opened state, the only state on which an
    /// Echo-Request is valid.
    pub fn lcp_opened(&self) -> bool {
        self.lcp.state() == State::Opened
    }

    /// True when LCP is in the Closed state. This is teardown (a peer
    /// TerminateReq in Opened, or a local close), distinct from a transient
    /// sub-Opened dip during an inbound renegotiation, which sits in
    /// ReqSent/AckSent/AckReceived. The link-down detector keys on this so a
    /// RFC 1661 reopen (Configure-Request in Opened) is not misread as link death.
    pub fn lcp_closed(&self) -> bool {
        self.lcp.state() == State::Closed
    }

    /// Build an LCP Echo-Request once the link is up, else `None`. `id` is
    /// caller-sequenced. The body is our local Magic-Number; the peer answers with
    /// an Echo-Reply carrying its OWN magic (RFC 1661 section 5.8), which
    /// `is_peer_echo_reply` accepts as liveness because it differs from ours.
    ///
    /// "Up" is Opened plus the post-Open sub-`Opened` dip an inbound
    /// Configure-Request renegotiation causes (RFC 1661 RcR in Opened), so our
    /// keepalive keeps firing across a BRAS re-confirm instead of stalling until
    /// the link is declared dead. Pre-Open bring-up and teardown (Closed) yield
    /// `None`.
    pub fn lcp_echo_request(&mut self, id: u8) -> Option<OutFrame<'static>> {
        if !self.lcp.link_up() {
            return None;
        }
        let magic = self.lcp.proto().magic_local;
        Some(OutFrame::Packet(self.lcp.send_echo_request(id, magic)))
    }

    /// Take-and-clear the "a peer Echo-Reply arrived" liveness flag.
    pub fn take_echo_reply_seen(&mut self) -> bool {
        core::mem::take(&mut self.echo_reply_seen)
    }

    /// True iff `pkt` is a well-formed LCP Echo-Reply from the peer, i.e. proof the
    /// peer answered our Echo-Request. Untrusted input: every read is bounds-checked,
    /// never panics. RFC 1661 section 5.8 has each side stamp its OWN Magic-Number
    /// into the frames it transmits, so a genuine peer reply carries the peer's
    /// magic, which differs from ours; a reply carrying our own Magic-Number means
    /// the link is looped back, which is not liveness. Hence liveness is any
    /// Echo-Reply whose magic differs from our local Magic-Number.
    fn is_peer_echo_reply(pkt: &[u8], our_magic: u32) -> bool {
        // 2 proto + 1 code + 1 id + 2 length + 4 magic = 10 bytes minimum; the
        // body past the 2-byte proto must hold at least the 4-byte control header
        // plus the 4-byte Magic-Number.
        let body = match pkt.get(2..) {
            Some(b) if b.len() >= 8 => b,
            _ => return false,
        };
        if Code::from(body[0]) != Code::EchoReply {
            return false;
        }
        match body.get(4..8) {
            Some(m) => u32::from_be_bytes([m[0], m[1], m[2], m[3]]) != our_magic,
            None => false,
        }
    }

    pub fn status(&self) -> Status {
        let lcp = self.lcp.proto();
        Status {
            phase: self.phase,
            ipv4: if self.ipv4cp.state() == State::Opened {
                Some(self.ipv4cp.proto().status())
            } else {
                None
            },
            mru: lcp.mru_local.min(lcp.mru_remote),
        }
    }

    pub fn open(&mut self) -> Result<(), crate::pppoe::Error> {
        match self.phase {
            Phase::Dead => {
                self.phase = Phase::Establish;
                self.opening = true;
                Ok(())
            }
            _ => Err(crate::pppoe::Error::InvalidState),
        }
    }

    /// Decode one inbound PPP payload (2-byte proto + body), dispatching to the
    /// right sub-FSM. `tx` receives every outbound frame (control Packets and the
    /// CHAP Response). Returns `IpPacket` for inbound IPv4 (the datapath routes
    /// it), `Consumed` otherwise, or `RxError::Truncated` if the proto field is
    /// missing (the engine counts the drop).
    pub fn received(
        &mut self,
        pkt: &mut [u8],
        mut tx: impl FnMut(OutFrame<'_>),
    ) -> Result<RxOutcome, RxError> {
        // The 2-byte PPP Protocol field is mandatory; PFC is never negotiated.
        let proto = match pkt.get(0..2) {
            Some(p) => u16::from_be_bytes([p[0], p[1]]),
            None => return Err(RxError::Truncated),
        };

        match ProtocolType::from(proto) {
            ProtocolType::LCP => {
                // An Echo-Reply reaches `handle` only via its catch-all no-op arm,
                // so the FSM never surfaces it. Peek for a peer reply before
                // delegating, to drive the liveness timer.
                if Self::is_peer_echo_reply(pkt, self.lcp.proto().magic_local) {
                    self.echo_reply_seen = true;
                }
                self.lcp.handle(pkt, |p| tx(p.into()));
                Ok(RxOutcome::Consumed)
            }
            ProtocolType::PAP => {
                self.pap.handle(pkt, |p| tx(p.into()));
                Ok(RxOutcome::Consumed)
            }
            ProtocolType::CHAP => {
                match self
                    .chap
                    .handle(pkt, self.config.username, self.config.password)
                {
                    Ok(Some(resp)) => tx(OutFrame::Raw(resp)),
                    Ok(None) => {}
                    Err(_) => {} // drop malformed CHAP packet
                }
                Ok(RxOutcome::Consumed)
            }
            // Surface inbound IPv4 to the caller; the PPP core has no datapath.
            ProtocolType::IPv4 => Ok(RxOutcome::IpPacket(2..pkt.len())),
            ProtocolType::IPv4CP => {
                self.ipv4cp.handle(pkt, |p| tx(p.into()));
                Ok(RxOutcome::Consumed)
            }
            ProtocolType::Unknown => {
                tx(self.lcp.send_protocol_reject(pkt).into());
                Ok(RxOutcome::Consumed)
            }
        }
    }

    /// Advance the RFC 1661 restart timers one tick: retransmit a stale
    /// Configure-Request, or park a sub-FSM in failed-`Closed` once its budget
    /// is exhausted (`poll` then maps that to `Phase::Dead`).
    pub fn tick(&mut self, mut tx: impl FnMut(OutFrame<'_>)) {
        if let Some(p) = self.lcp.on_tick() {
            tx(p.into());
        }
        if let Some(p) = self.ipv4cp.on_tick() {
            tx(p.into());
        }
    }

    /// Advance the link state machine one step: originate ConfReqs, dispatch auth,
    /// open IPCP after auth, and reach `Open` when IPCP is up.
    pub fn poll(&mut self, mut tx: impl FnMut(OutFrame<'_>)) {
        let mut tx = |p: Packet<'_>| tx(p.into());
        match self.phase {
            Phase::Dead => {}
            Phase::Establish => {
                if self.lcp.state() == State::Closed && !self.lcp.failed() {
                    tx(self.lcp.open());
                    self.opening = false;
                }

                if self.lcp.state() == State::Opened {
                    match self.lcp.proto().auth {
                        AuthType::None => {
                            tx(self.ipv4cp.open());
                            self.phase = Phase::Network;
                        }
                        AuthType::ChapMd5 => {
                            // CHAP is server-initiated: enter Auth and wait for the
                            // peer's Challenge; we send nothing here.
                            self.phase = Phase::Auth;
                        }
                        AuthType::PAP => {
                            tx(self.pap.open());
                            self.phase = Phase::Auth;
                        }
                    }
                } else {
                    if self.pap.state() != PapState::Closed {
                        self.pap.close();
                    }
                    if self.ipv4cp.state() != State::Closed {
                        self.ipv4cp.close();
                    }
                }
            }
            Phase::Auth => {
                let chap_done = self.chap.is_success();
                let pap_done = self.pap.state() == PapState::Opened;
                if chap_done || pap_done {
                    tx(self.ipv4cp.open());
                    self.phase = Phase::Network;
                } else if self.ipv4cp.state() != State::Closed {
                    self.ipv4cp.close();
                }
            }
            Phase::Network => {
                if self.ipv4cp.state() == State::Opened {
                    self.phase = Phase::Open;
                }
            }
            Phase::Open => {}
        }

        // A negotiation that gave up (restart-counter exhaustion in either
        // sub-FSM) or a torn-down LCP ends the session.
        if (self.lcp.state() == State::Closed && !self.opening) || self.ipv4cp.failed() {
            self.phase = Phase::Dead
        }
    }
}
