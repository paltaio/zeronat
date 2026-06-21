//! CHAP-MD5 (RFC 1994) for PPPoE authentication.
//!
//! The target BRAS (Huawei NE40) authenticates with CHAP-MD5, not MS-CHAP, so
//! this is hand-rolled over the `md-5` crate with no MD4/DES. The Response Value
//! is `MD5(Identifier ++ Secret ++ Challenge)` (RFC 1994 section 4.1); we reply
//! with our username in the Name field.
//!
//! `handle` parses a raw PPP CHAP payload from the BRAS (untrusted input). Every
//! field is read with bounds checks; a truncated or oversized packet returns
//! `Err` and is dropped by the caller. Nothing here panics: the release profile
//! is panic=abort.

use md5::{Digest, Md5};

/// CHAP packet codes (RFC 1994 section 4).
pub const CHAP_CHALLENGE: u8 = 1;
pub const CHAP_RESPONSE: u8 = 2;
pub const CHAP_SUCCESS: u8 = 3;
pub const CHAP_FAILURE: u8 = 4;

/// PPP Protocol field for CHAP.
const PPP_PROTO_CHAP: [u8; 2] = [0xc2, 0x23];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChapState {
    Idle,
    Responded,
    Success,
    Failure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChapError {
    /// Packet ended before a required field could be read.
    Truncated,
    /// A declared length field is inconsistent with the packet.
    BadLength,
}

/// The 16-byte CHAP-MD5 Response Value: `MD5(id ++ secret ++ challenge)`.
///
/// `id` is the single Identifier byte copied verbatim from the Challenge packet.
pub fn chap_md5_response(id: u8, secret: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update([id]);
    h.update(secret);
    h.update(challenge);
    h.finalize().into()
}

/// CHAP authenticator state. Holds only the state enum; the username/secret are
/// passed in on each `handle` so their lifetime stays with the engine, not here.
#[derive(Clone, Copy, Debug)]
pub struct Chap {
    state: ChapState,
}

impl Default for Chap {
    fn default() -> Self {
        Self::new()
    }
}

impl Chap {
    pub fn new() -> Self {
        Self {
            state: ChapState::Idle,
        }
    }

    pub fn state(&self) -> ChapState {
        self.state
    }

    pub fn is_success(&self) -> bool {
        self.state == ChapState::Success
    }

    pub fn is_failure(&self) -> bool {
        self.state == ChapState::Failure
    }

    /// Process an inbound CHAP packet and, for a Challenge, build the Response.
    ///
    /// `pkt` is the raw PPP payload INCLUDING the 2-byte Protocol field (0xc223),
    /// exactly what the driver matched on. Layout after the proto:
    /// `[code:1][id:1][length:2][value-size:1][value: value-size][name: rest]`,
    /// where `length` counts from the code byte.
    ///
    /// Returns `Ok(Some(resp))` with a finished raw PPP Response payload (proto
    /// prefix included) for a Challenge, `Ok(None)` for Success/Failure/ignored,
    /// or `Err` for any truncation (the caller drops the frame).
    pub fn handle(
        &mut self,
        pkt: &[u8],
        user: &[u8],
        secret: &[u8],
    ) -> Result<Option<Vec<u8>>, ChapError> {
        let code = *pkt.get(2).ok_or(ChapError::Truncated)?;
        let id = *pkt.get(3).ok_or(ChapError::Truncated)?;
        let length = {
            let l = pkt.get(4..6).ok_or(ChapError::Truncated)?;
            u16::from_be_bytes([l[0], l[1]]) as usize
        };
        // `length` covers code..end and must be >= the 4-byte CHAP header and not
        // claim more than the packet carries (after the 2-byte proto prefix).
        if length < 4 || 2 + length > pkt.len() {
            return Err(ChapError::BadLength);
        }

        match code {
            CHAP_CHALLENGE => {
                let value_size = *pkt.get(6).ok_or(ChapError::Truncated)? as usize;
                let value_end = 7 + value_size;
                // The value must fit inside what `length` declares.
                if value_end > 2 + length {
                    return Err(ChapError::BadLength);
                }
                let value = pkt.get(7..value_end).ok_or(ChapError::Truncated)?;
                let response = chap_md5_response(id, secret, value);
                self.state = ChapState::Responded;
                Ok(Some(build_response(id, &response, user)))
            }
            CHAP_SUCCESS => {
                self.state = ChapState::Success;
                Ok(None)
            }
            CHAP_FAILURE => {
                self.state = ChapState::Failure;
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

/// Build a raw PPP CHAP Response payload (proto prefix + RFC 1994 Response).
///
/// Body: `[CHAP_RESPONSE][id][length:2][value-size=16][16-byte value][name]`.
fn build_response(id: u8, response: &[u8; 16], user: &[u8]) -> Vec<u8> {
    // 4-byte header + 1-byte value-size + 16-byte value + username.
    let length = 4 + 1 + 16 + user.len();
    let mut out = Vec::with_capacity(2 + length);
    out.extend_from_slice(&PPP_PROTO_CHAP);
    out.push(CHAP_RESPONSE);
    out.push(id);
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.push(16);
    out.extend_from_slice(response);
    out.extend_from_slice(user);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real capture against the Huawei NE40-BRAS. The strongest correctness anchor:
    // MD5(0x01 ++ b"tchile" ++ challenge) must equal this exact response value.
    const CHALLENGE: [u8; 16] = [
        0x1a, 0x88, 0x05, 0x28, 0x03, 0x05, 0x07, 0x22, 0xcd, 0x6c, 0x29, 0xed, 0x93, 0xd9, 0x4a,
        0xe8,
    ];
    const EXPECTED: [u8; 16] = [
        0xf5, 0xab, 0x4c, 0xd3, 0x3f, 0x95, 0x80, 0x80, 0xeb, 0x5d, 0xaf, 0xe9, 0xb0, 0xb5, 0xf3,
        0x0e,
    ];

    #[test]
    fn chap_md5_golden_vector() {
        assert_eq!(chap_md5_response(0x01, b"tchile", &CHALLENGE), EXPECTED);
    }

    #[test]
    fn challenge_to_response_packet() {
        // Synthetic Challenge: proto c2 23, code 1, id 1, value-size 16, the 16
        // challenge bytes, then the Name "NE40-BRAS".
        let name = b"NE40-BRAS";
        let length = 4 + 1 + 16 + name.len();
        let mut pkt = vec![0xc2, 0x23, CHAP_CHALLENGE, 0x01];
        pkt.extend_from_slice(&(length as u16).to_be_bytes());
        pkt.push(16);
        pkt.extend_from_slice(&CHALLENGE);
        pkt.extend_from_slice(name);

        let mut chap = Chap::new();
        let resp = chap
            .handle(&pkt, b"user", b"tchile")
            .expect("handle ok")
            .expect("response built");
        assert_eq!(chap.state(), ChapState::Responded);

        // proto c2 23, code 2 (Response), id 1.
        assert_eq!(&resp[0..2], &[0xc2, 0x23]);
        assert_eq!(resp[2], CHAP_RESPONSE);
        assert_eq!(resp[3], 0x01);
        let rlen = u16::from_be_bytes([resp[4], resp[5]]) as usize;
        assert_eq!(rlen, 4 + 1 + 16 + 4); // header + size + value + "user"
        assert_eq!(resp[6], 16); // value-size
        assert_eq!(&resp[7..23], &EXPECTED); // the golden response value
        assert_eq!(&resp[23..], b"user"); // our username in the Name field
        assert_eq!(resp.len(), 2 + rlen);
    }

    #[test]
    fn success_and_failure_set_state() {
        let mut chap = Chap::new();
        let success = vec![0xc2, 0x23, CHAP_SUCCESS, 0x01, 0x00, 0x04];
        assert_eq!(chap.handle(&success, b"u", b"p"), Ok(None));
        assert!(chap.is_success());

        let mut chap = Chap::new();
        let failure = vec![0xc2, 0x23, CHAP_FAILURE, 0x01, 0x00, 0x04];
        assert_eq!(chap.handle(&failure, b"u", b"p"), Ok(None));
        assert!(chap.is_failure());
    }

    #[test]
    fn truncated_challenge_is_dropped() {
        let mut chap = Chap::new();
        // value-size 16 but only 2 challenge bytes present.
        let pkt = vec![0xc2, 0x23, CHAP_CHALLENGE, 0x01, 0x00, 0x09, 16, 0xaa, 0xbb];
        assert!(chap.handle(&pkt, b"u", b"p").is_err());
    }
}
