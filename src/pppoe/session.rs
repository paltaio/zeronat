use super::{Error, MacAddr, Result, ETHERTYPE_SESSION, VER_TYPE};

/// Ethernet header length: dst(6) + src(6) + ethertype(2).
pub const ETH_HDR_LEN: usize = 14;
/// PPPoE header length: ver/type(1) + code(1) + session(2) + length(2).
pub const PPPOE_HDR_LEN: usize = 6;
/// PPPoE session-data CODE.
pub const CODE_SESSION: u8 = 0x00;

/// A parsed Ethernet header (used by both stages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
}

/// Write the 14-byte Ethernet header into `out`.
pub fn put_eth_header(out: &mut Vec<u8>, dst: MacAddr, src: MacAddr, ethertype: u16) {
    out.extend_from_slice(dst.octets());
    out.extend_from_slice(src.octets());
    out.extend_from_slice(&ethertype.to_be_bytes());
}

/// Parse the Ethernet header from the front of `frame`.
///
/// Returns the header and the offset where the L2 payload begins (always
/// `ETH_HDR_LEN`). Errors `TooShort` if the buffer is under 14 bytes.
pub fn parse_eth_header(frame: &[u8]) -> Result<(EthHeader, usize)> {
    let dst: [u8; 6] = frame
        .get(0..6)
        .ok_or(Error::TooShort)?
        .try_into()
        .map_err(|_| Error::TooShort)?;
    let src: [u8; 6] = frame
        .get(6..12)
        .ok_or(Error::TooShort)?
        .try_into()
        .map_err(|_| Error::TooShort)?;
    let et = frame.get(12..14).ok_or(Error::TooShort)?;
    let ethertype = u16::from_be_bytes([et[0], et[1]]);
    Ok((
        EthHeader {
            dst: MacAddr(dst),
            src: MacAddr(src),
            ethertype,
        },
        ETH_HDR_LEN,
    ))
}

/// A decoded 0x8864 session frame: the assigned session id plus the byte range
/// of the PPP payload within the original frame.
///
/// P1 does NOT parse PPP. `ppp_start..ppp_end` indexes the caller's frame
/// slice; the caller reads the PPP payload there. The range is already
/// validated against the PPPoE LENGTH field, so indexing it cannot fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionHeader {
    pub eth: EthHeader,
    pub session_id: u16,
    pub ppp_start: usize,
    pub ppp_end: usize,
}

/// Build a complete 0x8864 session Ethernet frame carrying `ppp_payload`.
///
/// `ppp_payload` is the raw PPP frame beginning with the 2-byte PPP Protocol
/// field. The PPPoE LENGTH field is set to `ppp_payload.len()`.
pub fn build_session_frame(
    dst: MacAddr,
    src: MacAddr,
    session_id: u16,
    ppp_payload: &[u8],
) -> Vec<u8> {
    // PPP-over-PPPoE payload is MRU-bounded (<= 1500); the cast cannot truncate
    // for any real caller, and the assert traps a future caller that violates it.
    debug_assert!(ppp_payload.len() <= u16::MAX as usize);
    let mut out = Vec::with_capacity(ETH_HDR_LEN + PPPOE_HDR_LEN + ppp_payload.len());
    put_eth_header(&mut out, dst, src, ETHERTYPE_SESSION);
    out.push(VER_TYPE);
    out.push(CODE_SESSION);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&(ppp_payload.len() as u16).to_be_bytes());
    out.extend_from_slice(ppp_payload);
    out
}

/// Parse a 0x8864 session frame, returning the header and the PPP payload range.
///
/// Validates EtherType == 0x8864, ver/type == 0x11, code == 0x00, and that the
/// PPPoE LENGTH does not run past the bytes present. Does not require LENGTH to
/// equal the remaining bytes (Ethernet may pad short frames to 60 bytes); it
/// trusts LENGTH as the authoritative payload size and rejects only overrun.
pub fn parse_session_frame(frame: &[u8]) -> Result<SessionHeader> {
    let (eth, off) = parse_eth_header(frame)?;
    if eth.ethertype != ETHERTYPE_SESSION {
        return Err(Error::BadEtherType(eth.ethertype));
    }
    let hdr = frame.get(off..off + PPPOE_HDR_LEN).ok_or(Error::TooShort)?;
    if hdr[0] != VER_TYPE {
        return Err(Error::BadVerType(hdr[0]));
    }
    if hdr[1] != CODE_SESSION {
        return Err(Error::BadCode(hdr[1]));
    }
    let session_id = u16::from_be_bytes([hdr[2], hdr[3]]);
    let length = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let ppp_start = off + PPPOE_HDR_LEN;
    let ppp_end = ppp_start.checked_add(length).ok_or(Error::LengthOverrun)?;
    if ppp_end > frame.len() {
        return Err(Error::LengthOverrun);
    }
    Ok(SessionHeader {
        eth,
        session_id,
        ppp_start,
        ppp_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pppoe::ETHERTYPE_DISCOVERY;

    const OUR: MacAddr = MacAddr([0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74]);
    const AC: MacAddr = MacAddr([0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17]);

    // Section 3.5: 0x8864 session header with an empty PPP payload (20 bytes).
    const SESSION_HDR: &[u8] = &[
        0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74, 0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17, 0x88, 0x64, 0x11,
        0x00, 0x5e, 0x61, 0x00, 0x00,
    ];

    #[test]
    fn build_session_frame_empty_matches_golden() {
        assert_eq!(build_session_frame(OUR, AC, 0x5e61, &[]), SESSION_HDR);
    }

    #[test]
    fn parse_session_frame_golden() {
        let sh = parse_session_frame(SESSION_HDR).expect("parse");
        assert_eq!(sh.session_id, 0x5e61);
        assert_eq!(sh.ppp_start, 20);
        assert_eq!(sh.ppp_end, 20);
        assert_eq!(sh.eth.src, AC);
        assert_eq!(sh.eth.dst, OUR);
    }

    #[test]
    fn session_roundtrip_with_payload() {
        let ppp: &[u8] = &[0xc0, 0x21, 0x01, 0x01, 0x00, 0x04];
        let frame = build_session_frame(OUR, AC, 0x5e61, ppp);
        let sh = parse_session_frame(&frame).expect("parse");
        assert_eq!(sh.session_id, 0x5e61);
        assert_eq!(&frame[sh.ppp_start..sh.ppp_end], ppp);
    }

    #[test]
    fn parse_session_rejects_discovery_ethertype() {
        // A 0x8863 frame fed to the session parser must be rejected by ethertype.
        let mut frame = SESSION_HDR.to_vec();
        frame[12..14].copy_from_slice(&ETHERTYPE_DISCOVERY.to_be_bytes());
        assert_eq!(
            parse_session_frame(&frame),
            Err(Error::BadEtherType(ETHERTYPE_DISCOVERY))
        );
    }

    #[test]
    fn parse_session_rejects_short() {
        assert_eq!(parse_session_frame(&[]), Err(Error::TooShort));
        assert_eq!(parse_session_frame(&[0u8; 10]), Err(Error::TooShort));
    }

    #[test]
    fn parse_session_rejects_length_overrun() {
        let mut frame = SESSION_HDR.to_vec();
        // Claim 255 payload bytes when none are present.
        frame[18..20].copy_from_slice(&255u16.to_be_bytes());
        assert_eq!(parse_session_frame(&frame), Err(Error::LengthOverrun));
    }
}
