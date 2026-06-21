// Vendored and adapted from embassy-rs/ppproto, rev bd16b3093fe2ededb4fd7662ed253d7bc6b39a9b
// (tag v0.2.1). Upstream license: MIT OR Apache-2.0, Copyright (c) 2020 Dario Nieuwenhuis.
// Adapted to std, de-panicked for untrusted PPPoE session input, and extended for
// PPPoE+CHAP-MD5 (LCP MRU/Magic-Number/CHAP auth). See src/pppoe/ppp/mod.rs for the change log.

//! IPCP option negotiation (RFC 1332): our address plus optional DNS1/DNS2.
//!
//! Address learning is Nak-driven: we request `0.0.0.0`, the BRAS Naks with the
//! address it wants us to use, and we re-request that. DNS1 (129) / DNS2 (131)
//! are requested as `0.0.0.0` and learned the same way. All `try_from` paths
//! already fall back to a Reject on a non-4-byte value, so there is no unguarded
//! indexing on the receive path here.

use std::net::Ipv4Addr;

use super::option_fsm::{Protocol, Verdict};
use super::wire::ProtocolType;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
enum OptionCode {
    Unknown = 0,
    IpAddress = 3,
    Dns1 = 129,
    Dns2 = 131,
}

impl From<u8> for OptionCode {
    fn from(v: u8) -> Self {
        match v {
            3 => OptionCode::IpAddress,
            129 => OptionCode::Dns1,
            131 => OptionCode::Dns2,
            _ => OptionCode::Unknown,
        }
    }
}

struct IpOption {
    address: Ipv4Addr,
    is_rejected: bool,
}

impl IpOption {
    fn new() -> Self {
        Self {
            address: Ipv4Addr::UNSPECIFIED,
            is_rejected: false,
        }
    }

    fn get(&self) -> Option<Ipv4Addr> {
        if self.is_rejected || self.address.is_unspecified() {
            None
        } else {
            Some(self.address)
        }
    }

    fn nacked(&mut self, data: &[u8], is_rej: bool) {
        if is_rej {
            self.is_rejected = true
        } else {
            match <[u8; 4]>::try_from(data) {
                Ok(data) => self.address = Ipv4Addr::from(data),
                // Peer asked for a non-4-byte address: mark rejected to avoid an
                // endless re-request loop.
                Err(_) => self.is_rejected = true,
            }
        }
    }
}

/// Status of the IPv4 connection negotiated via IPCP.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4Status {
    /// Our address.
    pub address: Option<Ipv4Addr>,
    /// The peer's (gateway) address.
    pub peer_address: Option<Ipv4Addr>,
    /// DNS servers provided by the peer.
    pub dns_servers: [Option<Ipv4Addr>; 2],
}

pub struct IPv4CP {
    peer_address: Ipv4Addr,

    address: IpOption,
    dns_server_1: IpOption,
    dns_server_2: IpOption,
    /// Whether to request DNS1/DNS2 in our ConfReq. Off by default: a plain
    /// PPPoE dial (pppd without `usepeerdns`) does not ask for DNS, matching the
    /// captured exchange. The learning path stays live for callers that opt in.
    request_dns: bool,
}

impl IPv4CP {
    pub fn new() -> Self {
        Self {
            peer_address: Ipv4Addr::UNSPECIFIED,
            address: IpOption::new(),
            dns_server_1: IpOption::new(),
            dns_server_2: IpOption::new(),
            request_dns: false,
        }
    }

    /// Request DNS1/DNS2 from the peer (equivalent to pppd's `usepeerdns`).
    pub fn set_request_dns(&mut self, on: bool) {
        self.request_dns = on;
    }

    pub fn status(&self) -> Ipv4Status {
        let peer_address = if self.peer_address.is_unspecified() {
            None
        } else {
            Some(self.peer_address)
        };

        Ipv4Status {
            address: self.address.get(),
            peer_address,
            dns_servers: [self.dns_server_1.get(), self.dns_server_2.get()],
        }
    }
}

impl Protocol for IPv4CP {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::IPv4CP
    }

    fn peer_options_start(&mut self) {}

    fn peer_option_received<'a>(&mut self, code: u8, data: &'a [u8]) -> Verdict<'a> {
        let opt = OptionCode::from(code);
        match opt {
            OptionCode::IpAddress => match <[u8; 4]>::try_from(data) {
                Ok(data) => {
                    self.peer_address = Ipv4Addr::from(data);
                    Verdict::Ack
                }
                Err(_) => Verdict::Rej,
            },
            _ => Verdict::Rej,
        }
    }

    fn own_options(&mut self, mut f: impl FnMut(u8, &[u8])) {
        if !self.address.is_rejected {
            f(OptionCode::IpAddress as u8, &self.address.address.octets());
        }
        if self.request_dns {
            if !self.dns_server_1.is_rejected {
                f(OptionCode::Dns1 as u8, &self.dns_server_1.address.octets());
            }
            if !self.dns_server_2.is_rejected {
                f(OptionCode::Dns2 as u8, &self.dns_server_2.address.octets());
            }
        }
    }

    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool) {
        let opt = OptionCode::from(code);
        match opt {
            OptionCode::Unknown => {}
            OptionCode::IpAddress => self.address.nacked(data, is_rej),
            OptionCode::Dns1 => self.dns_server_1.nacked(data, is_rej),
            OptionCode::Dns2 => self.dns_server_2.nacked(data, is_rej),
        }
    }
}
