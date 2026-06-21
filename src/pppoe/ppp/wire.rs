// Vendored and adapted from embassy-rs/ppproto, rev bd16b3093fe2ededb4fd7662ed253d7bc6b39a9b
// (tag v0.2.1). Upstream license: MIT OR Apache-2.0, Copyright (c) 2020 Dario Nieuwenhuis.
// Adapted to std, de-panicked for untrusted PPPoE session input, and extended for
// PPPoE+CHAP-MD5 (LCP MRU/Magic-Number/CHAP auth). See src/pppoe/ppp/mod.rs for the change log.

//! PPP wire types: protocol/code enums and the outbound packet emitter.
//!
//! The `num_enum` derive macros from upstream are replaced with hand-written
//! `From<int>` decode (any unknown value maps to `Unknown`, the original intent)
//! and plain `as u8`/`as u16` casts at the emit sites. This drops the `num_enum`
//! dependency without changing wire behavior.
//!
//! `Options`/`OptionData` use `std::vec::Vec` instead of `heapless::Vec`, which
//! removes the fixed `MAX_OPTIONS`/`MAX_OPTION_LEN` caps. Option count and length
//! are now bounded only by the (already length-validated) received packet, so a
//! valid multi-option ConfReq is never rejected by an arbitrary cap.
//!
//! Emit indexing (`buffer[0..2]`, etc.) is TX-side only. The caller allocates
//! exactly `buffer_len()` bytes and these frames are always ones WE construct,
//! never attacker-chosen lengths, so the slice writes here are exempt from the
//! receive-path de-panic rule, which targets attacker-controlled inbound
//! lengths.

/// PPP Protocol field values (the first 2 bytes of a session payload).
///
/// `Unknown` is the catch-all for any value we do not handle; the driver answers
/// such frames with an LCP Protocol-Reject, matching RFC 1661.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u16)]
pub enum ProtocolType {
    Unknown = 0,
    /// Link Control Protocol, RFC 1661.
    LCP = 0xc021,
    /// Password Authentication Protocol, RFC 1334.
    PAP = 0xc023,
    /// Challenge Handshake Authentication Protocol, RFC 1994.
    CHAP = 0xc223,
    /// Internet Protocol v4.
    IPv4 = 0x0021,
    /// Internet Protocol v4 Control Protocol, RFC 1332.
    IPv4CP = 0x8021,
}

impl From<u16> for ProtocolType {
    fn from(v: u16) -> Self {
        match v {
            0xc021 => ProtocolType::LCP,
            0xc023 => ProtocolType::PAP,
            0xc223 => ProtocolType::CHAP,
            0x0021 => ProtocolType::IPv4,
            0x8021 => ProtocolType::IPv4CP,
            _ => ProtocolType::Unknown,
        }
    }
}

/// PPP control-protocol packet codes (RFC 1661 section 5).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
#[repr(u8)]
pub enum Code {
    Unknown = 0,
    ConfigureReq = 1,
    ConfigureAck = 2,
    ConfigureNack = 3,
    ConfigureRej = 4,
    TerminateReq = 5,
    TerminateAck = 6,
    CodeRej = 7,
    ProtocolRej = 8,
    EchoReq = 9,
    EchoReply = 10,
    DiscardReq = 11,
}

impl From<u8> for Code {
    fn from(v: u8) -> Self {
        match v {
            1 => Code::ConfigureReq,
            2 => Code::ConfigureAck,
            3 => Code::ConfigureNack,
            4 => Code::ConfigureRej,
            5 => Code::TerminateReq,
            6 => Code::TerminateAck,
            7 => Code::CodeRej,
            8 => Code::ProtocolRej,
            9 => Code::EchoReq,
            10 => Code::EchoReply,
            11 => Code::DiscardReq,
            _ => Code::Unknown,
        }
    }
}

/// A complete outbound PPP packet: 2-byte Protocol field plus the payload.
pub struct Packet<'a> {
    pub proto: ProtocolType,
    pub payload: Payload<'a>,
}

impl<'a> Packet<'a> {
    pub fn buffer_len(&self) -> usize {
        2 + self.payload.buffer_len()
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        let proto = self.proto as u16;
        buffer[0..2].copy_from_slice(&proto.to_be_bytes());
        self.payload.emit(&mut buffer[2..])
    }
}

pub enum Payload<'a> {
    Raw(&'a mut [u8]),
    PPP(Code, u8, PPPPayload<'a>),
}

impl<'a> Payload<'a> {
    pub fn buffer_len(&self) -> usize {
        match self {
            Self::Raw(data) => data.len(),
            Self::PPP(_code, _id, payload) => 1 + 1 + 2 + payload.buffer_len(),
        }
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Raw(data) => buffer.copy_from_slice(data),
            Self::PPP(code, id, payload) => {
                buffer[0] = *code as u8;
                buffer[1] = *id;
                let len = payload.buffer_len() as u16 + 4;
                buffer[2..4].copy_from_slice(&len.to_be_bytes());
                payload.emit(&mut buffer[4..])
            }
        }
    }
}

pub enum PPPPayload<'a> {
    Raw(&'a mut [u8]),
    PAP(&'a [u8], &'a [u8]),
    Options(Options),
}

impl<'a> PPPPayload<'a> {
    pub fn buffer_len(&self) -> usize {
        match self {
            Self::Raw(data) => data.len(),
            Self::PAP(user, pass) => 1 + user.len() + 1 + pass.len(),
            Self::Options(options) => options.buffer_len(),
        }
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Raw(data) => buffer.copy_from_slice(data),
            Self::PAP(user, pass) => {
                buffer[0] = user.len() as u8;
                buffer[1..][..user.len()].copy_from_slice(user);
                buffer[1 + user.len()] = pass.len() as u8;
                buffer[1 + user.len() + 1..].copy_from_slice(pass);
            }
            Self::Options(options) => options.emit(buffer),
        }
    }
}

/// A list of LCP/IPCP options to emit. Backed by `std::vec::Vec`; pushes never
/// fail, so the upstream "too many options" panic sites are gone by construction.
pub struct Options(pub Vec<OptionVal>);

impl Options {
    pub fn buffer_len(&self) -> usize {
        self.0.iter().map(|opt| opt.buffer_len()).sum()
    }

    pub fn emit(&self, mut buffer: &mut [u8]) {
        for o in &self.0 {
            let len = o.buffer_len();
            o.emit(&mut buffer[..len]);
            buffer = &mut buffer[len..];
        }
    }
}

pub struct OptionVal {
    code: u8,
    data: Vec<u8>,
}

impl OptionVal {
    pub fn new(code: u8, data: &[u8]) -> Self {
        Self {
            code,
            data: data.to_vec(),
        }
    }

    pub fn buffer_len(&self) -> usize {
        2 + self.data.len()
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.code;
        buffer[1] = self.data.len() as u8 + 2;
        buffer[2..].copy_from_slice(&self.data);
    }
}
