//! PROXY protocol v2 header encoding (haproxy's proxy-protocol spec). A client
//! writes one header as the very first bytes of a `+proxy` TCP forward's local
//! connection, so the target learns the real public peer instead of the
//! client's dial source.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// The fixed 12-byte signature every v2 header starts with.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Collapse an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, as a dual-stack
/// listener reports v4 peers) to its IPv4 form, so such a pair encodes as the
/// AF_INET family the target expects.
fn normalize(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        IpAddr::V4(_) => a,
    }
}

/// An address's 16-byte form for the AF_INET6 encoding: a lone IPv4 address in
/// a mixed pair is carried as its IPv4-mapped IPv6 equivalent.
fn as_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Encode a v2 PROXY header for a TCP stream: `peer` is the public connection's
/// real source (the header's src) and `local` the public listener address it
/// arrived on (the header's dst). 28 bytes when both addresses are IPv4 after
/// v4-mapped normalization, 52 bytes otherwise.
pub fn encode_v2(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let peer = normalize(peer);
    let local = normalize(local);
    let mut b = Vec::with_capacity(52);
    b.extend_from_slice(&SIGNATURE);
    b.push(0x21); // version 2, command PROXY
    match (peer.ip(), local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            b.push(0x11); // AF_INET, STREAM
            b.extend_from_slice(&12u16.to_be_bytes());
            b.extend_from_slice(&src.octets());
            b.extend_from_slice(&dst.octets());
        }
        (src, dst) => {
            b.push(0x21); // AF_INET6, STREAM
            b.extend_from_slice(&36u16.to_be_bytes());
            b.extend_from_slice(&as_v6(src).octets());
            b.extend_from_slice(&as_v6(dst).octets());
        }
    }
    b.extend_from_slice(&peer.port().to_be_bytes());
    b.extend_from_slice(&local.port().to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_pair_is_byte_exact() {
        let peer: SocketAddr = "203.0.113.5:51820".parse().unwrap();
        let local: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let expected: [u8; 28] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // signature
            0x21, // v2, PROXY
            0x11, // AF_INET, STREAM
            0x00, 0x0C, // length 12
            203, 0, 113, 5, // src ip
            198, 51, 100, 1, // dst ip
            0xCA, 0x6C, // src port 51820
            0x01, 0xBB, // dst port 443
        ];
        assert_eq!(encode_v2(peer, local), expected);
    }

    #[test]
    fn v6_pair_is_byte_exact() {
        let peer: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        let local: SocketAddr = "[2001:db8::2]:8443".parse().unwrap();
        let expected: [u8; 52] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // signature
            0x21, // v2, PROXY
            0x21, // AF_INET6, STREAM
            0x00, 0x24, // length 36
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // src ip
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // dst ip
            0x0F, 0xA0, // src port 4000
            0x20, 0xFB, // dst port 8443
        ];
        assert_eq!(encode_v2(peer, local), expected);
    }

    #[test]
    fn v4_mapped_v6_normalizes_to_v4() {
        let peer_v4: SocketAddr = "203.0.113.5:51820".parse().unwrap();
        let local_v4: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let peer_mapped: SocketAddr = "[::ffff:203.0.113.5]:51820".parse().unwrap();
        let local_mapped: SocketAddr = "[::ffff:198.51.100.1]:443".parse().unwrap();
        assert_eq!(
            encode_v2(peer_mapped, local_mapped),
            encode_v2(peer_v4, local_v4)
        );
    }

    #[test]
    fn mixed_pair_maps_v4_side_into_af_inet6() {
        let peer: SocketAddr = "203.0.113.5:51820".parse().unwrap();
        let local: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let b = encode_v2(peer, local);
        assert_eq!(b.len(), 52);
        assert_eq!(b[13], 0x21); // AF_INET6, STREAM
        assert_eq!(u16::from_be_bytes([b[14], b[15]]), 36);
        // src is the v4 peer in its IPv4-mapped form.
        let mapped: Ipv6Addr = "::ffff:203.0.113.5".parse().unwrap();
        assert_eq!(&b[16..32], &mapped.octets());
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(&b[32..48], &dst.octets());
        assert_eq!(u16::from_be_bytes([b[48], b[49]]), 51820);
        assert_eq!(u16::from_be_bytes([b[50], b[51]]), 443);
    }
}
