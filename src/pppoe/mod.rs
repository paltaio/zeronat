//! Userspace PPPoE (RFC 2516) discovery and session-header codec.
//!
//! Every decoder here parses untrusted L2 input. The release profile is
//! panic=abort, so a single malformed frame from a hostile or buggy access
//! concentrator must never panic; decoders return `Error` instead. No slice
//! indexing that can fault on attacker-chosen lengths: bounds are checked and
//! every TAG_LENGTH is validated against the bytes that remain.

pub mod auth;
pub mod discovery;
pub mod engine;
pub mod ppp;
pub mod session;

use std::fmt;

/// EtherType for PPPoE Discovery stage frames (PADI/PADO/PADR/PADS/PADT).
pub const ETHERTYPE_DISCOVERY: u16 = 0x8863;
/// EtherType for PPPoE Session stage frames (PPP payload).
pub const ETHERTYPE_SESSION: u16 = 0x8864;

/// PPPoE byte0: VER(=1) in the high nibble, TYPE(=1) in the low nibble.
pub const VER_TYPE: u8 = 0x11;

/// A 48-bit Ethernet MAC address.
///
/// Stored as raw octets in wire order. `Copy` so it can flow through the FSM
/// without ownership churn.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The all-ones broadcast address used as the PADI destination.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// Borrow the raw 6 octets in wire order.
    pub fn octets(&self) -> &[u8; 6] {
        &self.0
    }

    /// Generate a random locally-administered unicast MAC for our client side.
    ///
    /// Sets the locally-administered bit and clears the multicast bit on the
    /// first octet: `(b & 0xfe) | 0x02`. Returns an error only if the system
    /// RNG fails.
    pub fn random_local() -> Result<MacAddr> {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).map_err(|_| Error::Rng)?;
        b[0] = (b[0] & 0xfe) | 0x02;
        Ok(MacAddr(b))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(b: [u8; 6]) -> Self {
        MacAddr(b)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// Decode/build failures for the PPPoE codec. Variants are assertable so tests
/// can pin the exact rejection reason rather than just "some error".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Buffer shorter than the fixed Ethernet + PPPoE headers require.
    TooShort,
    /// Ethernet EtherType was not the expected PPPoE Discovery/Session value.
    BadEtherType(u16),
    /// PPPoE byte0 (VER/TYPE) was not 0x11.
    BadVerType(u8),
    /// PPPoE CODE byte did not match an expected discovery/session code.
    BadCode(u8),
    /// PPPoE LENGTH field exceeds the bytes actually present after the header.
    LengthOverrun,
    /// A TAG_LENGTH ran past the end of the discovery payload.
    TagOverrun,
    /// System RNG failed while generating a local MAC or LCP Magic-Number.
    Rng,
    /// A PPP credential exceeds 255 bytes (the PAP/CHAP length fields are 1 byte).
    CredentialTooLong,
    /// A PPP operation was attempted from a phase that does not allow it.
    InvalidState,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooShort => write!(f, "frame too short for PPPoE headers"),
            Error::BadEtherType(t) => write!(f, "unexpected ethertype 0x{t:04x}"),
            Error::BadVerType(b) => write!(f, "bad PPPoE ver/type byte 0x{b:02x}"),
            Error::BadCode(c) => write!(f, "unexpected PPPoE code 0x{c:02x}"),
            Error::LengthOverrun => write!(f, "PPPoE length exceeds frame bytes"),
            Error::TagOverrun => write!(f, "tag length exceeds payload bytes"),
            Error::Rng => write!(f, "system rng failed"),
            Error::CredentialTooLong => write!(f, "ppp credential exceeds 255 bytes"),
            Error::InvalidState => write!(f, "ppp operation invalid in current phase"),
        }
    }
}

impl std::error::Error for Error {}

/// Codec result alias local to this module.
pub type Result<T> = std::result::Result<T, Error>;
