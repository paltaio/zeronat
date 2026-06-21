use super::session::{parse_eth_header, put_eth_header, EthHeader, ETH_HDR_LEN, PPPOE_HDR_LEN};
use super::{Error, MacAddr, Result, ETHERTYPE_DISCOVERY, VER_TYPE};

/// Discovery CODE bytes (RFC 2516).
pub const CODE_PADI: u8 = 0x09;
pub const CODE_PADO: u8 = 0x07;
pub const CODE_PADR: u8 = 0x19;
pub const CODE_PADS: u8 = 0x65;
pub const CODE_PADT: u8 = 0xa7;

/// Discovery TAG types (RFC 2516).
pub const TAG_END_OF_LIST: u16 = 0x0000;
pub const TAG_SERVICE_NAME: u16 = 0x0101;
pub const TAG_AC_NAME: u16 = 0x0102;
pub const TAG_HOST_UNIQ: u16 = 0x0103;
pub const TAG_AC_COOKIE: u16 = 0x0104;
pub const TAG_VENDOR_SPECIFIC: u16 = 0x0105;
pub const TAG_RELAY_SESSION_ID: u16 = 0x0110;
pub const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
pub const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
pub const TAG_GENERIC_ERROR: u16 = 0x0203;

/// Discovery SESSION_ID is zero in PADI/PADO/PADR; PADS assigns nonzero.
pub const SESSION_ID_NONE: u16 = 0x0000;

/// A single TAG_TYPE / value pair borrowed from a discovery payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag<'a> {
    pub tag_type: u16,
    pub value: &'a [u8],
}

/// Iterate the TAGs in a discovery payload, validating each TAG_LENGTH against
/// the bytes that remain. Stops at End-Of-List (0x0000) or end of buffer.
///
/// On a malformed tag header or a TAG_LENGTH that overruns the payload, the
/// iterator yields `Err(Error::TagOverrun)` once and then ends; this lets the
/// caller fail the whole decode without panicking.
pub struct Tags<'a> {
    buf: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Tags<'a> {
    pub fn new(buf: &'a [u8]) -> Tags<'a> {
        Tags {
            buf,
            pos: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for Tags<'a> {
    type Item = Result<Tag<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos >= self.buf.len() {
            return None;
        }
        // Need 4 bytes for TAG_TYPE + TAG_LENGTH.
        let header = match self.buf.get(self.pos..self.pos + 4) {
            Some(h) => h,
            None => {
                self.done = true;
                return Some(Err(Error::TagOverrun));
            }
        };
        let tag_type = u16::from_be_bytes([header[0], header[1]]);
        let tag_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if tag_type == TAG_END_OF_LIST {
            self.done = true;
            return None;
        }
        let val_start = self.pos + 4;
        let value = match self.buf.get(val_start..val_start + tag_len) {
            Some(v) => v,
            None => {
                self.done = true;
                return Some(Err(Error::TagOverrun));
            }
        };
        self.pos = val_start + tag_len;
        Some(Ok(Tag { tag_type, value }))
    }
}

/// Append a TAG: TAG_TYPE(BE) TAG_LENGTH(BE) VALUE.
fn put_tag(out: &mut Vec<u8>, tag_type: u16, value: &[u8]) {
    out.extend_from_slice(&tag_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Append the fixed PPPoE discovery header with the given code and session id,
/// then the payload, fixing up LENGTH to the payload byte count.
fn put_pppoe(out: &mut Vec<u8>, code: u8, session_id: u16, payload: &[u8]) {
    out.push(VER_TYPE);
    out.push(code);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Build a PADI Ethernet frame: dst=broadcast, exactly one Service-Name tag
/// (empty value = any), optional Host-Uniq, SESSION_ID=0.
pub fn build_padi(src: MacAddr, service_name: &[u8], host_uniq: Option<&[u8]>) -> Vec<u8> {
    let mut payload = Vec::new();
    put_tag(&mut payload, TAG_SERVICE_NAME, service_name);
    if let Some(hu) = host_uniq {
        put_tag(&mut payload, TAG_HOST_UNIQ, hu);
    }
    let mut out = Vec::with_capacity(ETH_HDR_LEN + PPPOE_HDR_LEN + payload.len());
    put_eth_header(&mut out, MacAddr::BROADCAST, src, ETHERTYPE_DISCOVERY);
    put_pppoe(&mut out, CODE_PADI, SESSION_ID_NONE, &payload);
    out
}

/// Build a PADR Ethernet frame: unicast to the chosen AC, Service-Name, echo
/// AC-Cookie and Host-Uniq if present, SESSION_ID=0.
///
/// Tag order: Service-Name, then AC-Cookie (if any), then Host-Uniq (if any).
pub fn build_padr(
    src: MacAddr,
    ac: MacAddr,
    service_name: &[u8],
    ac_cookie: Option<&[u8]>,
    host_uniq: Option<&[u8]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    put_tag(&mut payload, TAG_SERVICE_NAME, service_name);
    if let Some(c) = ac_cookie {
        put_tag(&mut payload, TAG_AC_COOKIE, c);
    }
    if let Some(hu) = host_uniq {
        put_tag(&mut payload, TAG_HOST_UNIQ, hu);
    }
    let mut out = Vec::with_capacity(ETH_HDR_LEN + PPPOE_HDR_LEN + payload.len());
    put_eth_header(&mut out, ac, src, ETHERTYPE_DISCOVERY);
    put_pppoe(&mut out, CODE_PADR, SESSION_ID_NONE, &payload);
    out
}

/// Build a PADT Ethernet frame: unicast to the AC, carries the SESSION_ID,
/// terminates the session. Provided for callers; the FSM does not require it.
pub fn build_padt(src: MacAddr, ac: MacAddr, session_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(ETH_HDR_LEN + PPPOE_HDR_LEN);
    put_eth_header(&mut out, ac, src, ETHERTYPE_DISCOVERY);
    put_pppoe(&mut out, CODE_PADT, session_id, &[]);
    out
}

/// A decoded discovery packet (PADO or PADS), with the fields the FSM needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryPacket {
    pub eth: EthHeader,
    pub code: u8,
    pub session_id: u16,
    /// AC-Name value, if the AC sent one.
    pub ac_name: Option<Vec<u8>>,
    /// AC-Cookie value to echo back in PADR, if present.
    pub ac_cookie: Option<Vec<u8>>,
    /// Host-Uniq value the AC echoed, for matching against ours.
    pub host_uniq: Option<Vec<u8>>,
}

/// Parse any 0x8863 discovery frame into a `DiscoveryPacket`.
///
/// Validates EtherType == 0x8863, ver/type == 0x11, and a known discovery code,
/// bounds the PPPoE LENGTH against the frame, then walks the TAGs collecting the
/// fields the FSM cares about. Unknown tags are skipped. Returns the first
/// TagOverrun if the tag stream is malformed.
pub fn parse_discovery_frame(frame: &[u8]) -> Result<DiscoveryPacket> {
    let (eth, off) = parse_eth_header(frame)?;
    if eth.ethertype != ETHERTYPE_DISCOVERY {
        return Err(Error::BadEtherType(eth.ethertype));
    }
    let hdr = frame.get(off..off + PPPOE_HDR_LEN).ok_or(Error::TooShort)?;
    if hdr[0] != VER_TYPE {
        return Err(Error::BadVerType(hdr[0]));
    }
    let code = hdr[1];
    match code {
        CODE_PADI | CODE_PADO | CODE_PADR | CODE_PADS | CODE_PADT => {}
        other => return Err(Error::BadCode(other)),
    }
    let session_id = u16::from_be_bytes([hdr[2], hdr[3]]);
    let length = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let pl_start = off + PPPOE_HDR_LEN;
    let pl_end = pl_start.checked_add(length).ok_or(Error::LengthOverrun)?;
    let payload = frame.get(pl_start..pl_end).ok_or(Error::LengthOverrun)?;

    let mut ac_name = None;
    let mut ac_cookie = None;
    let mut host_uniq = None;
    for tag in Tags::new(payload) {
        let tag = tag?; // propagate TagOverrun
        match tag.tag_type {
            TAG_AC_NAME if ac_name.is_none() => ac_name = Some(tag.value.to_vec()),
            TAG_AC_COOKIE if ac_cookie.is_none() => ac_cookie = Some(tag.value.to_vec()),
            TAG_HOST_UNIQ if host_uniq.is_none() => host_uniq = Some(tag.value.to_vec()),
            _ => {}
        }
    }
    Ok(DiscoveryPacket {
        eth,
        code,
        session_id,
        ac_name,
        ac_cookie,
        host_uniq,
    })
}

/// Terminal output once discovery completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Established {
    pub ac_mac: MacAddr,
    pub session_id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Init,
    PadiSent,
    PadrSent,
    Established(Established),
    Dead,
}

/// What the caller should do after pumping the FSM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Transmit these raw Ethernet bytes now.
    Send(Vec<u8>),
    /// Nothing to do this turn; wait for input or the next tick.
    Idle,
    /// Discovery reached an established session.
    Established(Established),
    /// Discovery failed permanently (retries exhausted or PADT/error).
    Failed,
}

/// Plain compare of our Host-Uniq against the value the AC echoed.
///
/// Host-Uniq is opaque correlation data, not a secret, so a constant-time
/// compare is unnecessary. If we did not tag, accept any (or no) echo.
fn host_uniq_matches(ours: &Option<Vec<u8>>, theirs: &Option<Vec<u8>>) -> bool {
    match ours {
        None => true,
        Some(o) => theirs.as_deref() == Some(o.as_slice()),
    }
}

/// Sans-IO PPPoE discovery driver.
///
/// Lifecycle: construct, call `start()` to get the first PADI, then on each
/// received discovery frame call `on_frame(...)`, and on each timer tick call
/// `on_tick()`. All three return an `Action` telling the caller what to send or
/// that discovery finished. The FSM never touches a socket or a clock itself.
pub struct Discovery {
    state: State,
    src: MacAddr,
    service_name: Vec<u8>,
    host_uniq: Option<Vec<u8>>,
    /// AC chosen from the first valid PADO; the unicast target for PADR.
    ac_mac: Option<MacAddr>,
    /// Cookie echoed from the chosen PADO, replayed in PADR.
    ac_cookie: Option<Vec<u8>>,
    /// Ticks since the last (re)transmit, compared against `retransmit_ticks`.
    ticks_since_send: u32,
    /// Retransmits attempted in the current stage.
    attempts: u32,
    retransmit_ticks: u32,
    max_attempts: u32,
}

impl Discovery {
    /// `service_name` empty = "any service". `host_uniq` (recommended) lets the
    /// FSM reject PADOs that do not echo our value. `retransmit_ticks` is how
    /// many `on_tick()` calls without progress before resending; `max_attempts`
    /// is the resend budget per stage before declaring failure.
    pub fn new(
        src: MacAddr,
        service_name: Vec<u8>,
        host_uniq: Option<Vec<u8>>,
        retransmit_ticks: u32,
        max_attempts: u32,
    ) -> Discovery {
        Discovery {
            state: State::Init,
            src,
            service_name,
            host_uniq,
            ac_mac: None,
            ac_cookie: None,
            ticks_since_send: 0,
            attempts: 0,
            retransmit_ticks,
            max_attempts,
        }
    }

    /// Current FSM state (for tests and observability).
    pub fn state(&self) -> State {
        self.state
    }

    /// Begin discovery: transition Init -> PadiSent and return the PADI to send.
    pub fn start(&mut self) -> Action {
        if self.state != State::Init {
            return Action::Idle;
        }
        let padi = build_padi(self.src, &self.service_name, self.host_uniq.as_deref());
        self.state = State::PadiSent;
        self.ticks_since_send = 0;
        self.attempts = 0;
        Action::Send(padi)
    }

    /// Feed a received discovery frame. Non-discovery ethertypes, parse errors,
    /// and packets that do not advance the current state return `Idle` (dropped,
    /// no panic). A valid matching PADO advances to PadrSent and returns the
    /// PADR to send; a valid PADS advances to Established.
    pub fn on_frame(&mut self, frame: &[u8]) -> Action {
        let packet = match parse_discovery_frame(frame) {
            Ok(p) => p,
            Err(_) => return Action::Idle,
        };

        // A PADT from our chosen AC tears the session down in any active state.
        if packet.code == CODE_PADT {
            if let Some(ac) = self.ac_mac {
                if packet.eth.src == ac {
                    self.state = State::Dead;
                    return Action::Failed;
                }
            }
            return Action::Idle;
        }

        match self.state {
            State::PadiSent => {
                if packet.code != CODE_PADO {
                    return Action::Idle;
                }
                // PADO is unicast to us; drop ones addressed elsewhere so a PADO
                // for another host on a shared segment cannot be latched when
                // Host-Uniq is absent.
                if packet.eth.dst != self.src {
                    return Action::Idle;
                }
                if !host_uniq_matches(&self.host_uniq, &packet.host_uniq) {
                    return Action::Idle;
                }
                // First valid PADO wins; later PADOs are ignored.
                let ac = packet.eth.src;
                self.ac_mac = Some(ac);
                self.ac_cookie = packet.ac_cookie.clone();
                let padr = build_padr(
                    self.src,
                    ac,
                    &self.service_name,
                    self.ac_cookie.as_deref(),
                    self.host_uniq.as_deref(),
                );
                self.state = State::PadrSent;
                self.ticks_since_send = 0;
                self.attempts = 0;
                Action::Send(padr)
            }
            State::PadrSent => {
                if packet.code != CODE_PADS {
                    return Action::Idle;
                }
                // PADS is unicast to us; drop ones addressed to another host.
                if packet.eth.dst != self.src {
                    return Action::Idle;
                }
                match self.ac_mac {
                    Some(ac) if packet.eth.src == ac => {}
                    _ => return Action::Idle,
                }
                if !host_uniq_matches(&self.host_uniq, &packet.host_uniq) {
                    return Action::Idle;
                }
                // PADS must assign a nonzero SESSION_ID; a zero one is malformed.
                if packet.session_id == 0 {
                    return Action::Idle;
                }
                let est = Established {
                    ac_mac: packet.eth.src,
                    session_id: packet.session_id,
                };
                self.state = State::Established(est);
                Action::Established(est)
            }
            State::Init | State::Established(_) | State::Dead => Action::Idle,
        }
    }

    /// Advance the logical clock by one tick. Returns `Send` to retransmit when
    /// `retransmit_ticks` elapse, `Failed` when `max_attempts` is exhausted, or
    /// `Idle` otherwise. No effect once Established or Dead.
    pub fn on_tick(&mut self) -> Action {
        match self.state {
            State::PadiSent | State::PadrSent => {
                self.ticks_since_send += 1;
                if self.ticks_since_send < self.retransmit_ticks {
                    return Action::Idle;
                }
                if self.attempts + 1 >= self.max_attempts {
                    self.state = State::Dead;
                    return Action::Failed;
                }
                self.attempts += 1;
                self.ticks_since_send = 0;
                let frame = match self.state {
                    State::PadiSent => {
                        build_padi(self.src, &self.service_name, self.host_uniq.as_deref())
                    }
                    State::PadrSent => {
                        // ac_mac is Some once we are in PadrSent; fall back to
                        // broadcast rather than panic if that invariant breaks.
                        let ac = self.ac_mac.unwrap_or(MacAddr::BROADCAST);
                        build_padr(
                            self.src,
                            ac,
                            &self.service_name,
                            self.ac_cookie.as_deref(),
                            self.host_uniq.as_deref(),
                        )
                    }
                    _ => return Action::Idle,
                };
                Action::Send(frame)
            }
            State::Init | State::Established(_) | State::Dead => Action::Idle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR: MacAddr = MacAddr([0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74]);
    const AC: MacAddr = MacAddr([0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17]);
    const HU: [u8; 4] = [0x95, 0x16, 0x00, 0x00];

    // PADI we build (32 bytes), from a real dial against the target BRAS.
    const PADI: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74, 0x88, 0x63, 0x11,
        0x09, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x95, 0x16,
        0x00, 0x00,
    ];

    // PADR we build (32 bytes).
    const PADR: &[u8] = &[
        0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17, 0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74, 0x88, 0x63, 0x11,
        0x19, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x95, 0x16,
        0x00, 0x00,
    ];

    // PADO the AC sends (45 bytes).
    const PADO: &[u8] = &[
        0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74, 0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17, 0x88, 0x63, 0x11,
        0x07, 0x00, 0x00, 0x00, 0x19, 0x01, 0x02, 0x00, 0x09, 0x4e, 0x45, 0x34, 0x30, 0x2d, 0x42,
        0x52, 0x41, 0x53, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x95, 0x16, 0x00, 0x00,
    ];

    // PADS the AC sends (32 bytes).
    const PADS: &[u8] = &[
        0xfe, 0xee, 0x13, 0xac, 0xc4, 0x74, 0x70, 0x7b, 0xe8, 0x74, 0x22, 0x17, 0x88, 0x63, 0x11,
        0x65, 0x5e, 0x61, 0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x95, 0x16,
        0x00, 0x00,
    ];

    // ---- Encode equality (exact golden bytes) ----

    #[test]
    fn build_padi_matches_golden() {
        assert_eq!(build_padi(OUR, b"", Some(&HU)), PADI);
    }

    #[test]
    fn build_padr_matches_golden() {
        assert_eq!(build_padr(OUR, AC, b"", None, Some(&HU)), PADR);
    }

    #[test]
    fn build_padt_layout() {
        let frame = build_padt(OUR, AC, 0x5e61);
        assert_eq!(frame.len(), 20);
        // Eth header + PPPoE: 11 a7 5e 61 00 00.
        assert_eq!(&frame[0..6], AC.octets());
        assert_eq!(&frame[6..12], OUR.octets());
        assert_eq!(&frame[12..14], &ETHERTYPE_DISCOVERY.to_be_bytes());
        assert_eq!(&frame[14..20], &[0x11, 0xa7, 0x5e, 0x61, 0x00, 0x00]);
    }

    // ---- Decode of AC frames ----

    #[test]
    fn parse_pado_golden() {
        let p = parse_discovery_frame(PADO).expect("parse");
        assert_eq!(p.code, CODE_PADO);
        assert_eq!(p.session_id, 0);
        assert_eq!(p.eth.src, AC);
        assert_eq!(p.ac_name.as_deref(), Some(b"NE40-BRAS".as_slice()));
        assert_eq!(p.ac_cookie, None);
        assert_eq!(p.host_uniq.as_deref(), Some(HU.as_slice()));
    }

    #[test]
    fn parse_pads_golden() {
        let p = parse_discovery_frame(PADS).expect("parse");
        assert_eq!(p.code, CODE_PADS);
        assert_eq!(p.session_id, 0x5e61);
        assert_eq!(p.eth.src, AC);
        assert_eq!(p.host_uniq.as_deref(), Some(HU.as_slice()));
    }

    // ---- Round-trips ----

    #[test]
    fn padi_roundtrip() {
        let p = parse_discovery_frame(&build_padi(OUR, b"", Some(&HU))).expect("parse");
        assert_eq!(p.code, CODE_PADI);
        assert_eq!(p.host_uniq.as_deref(), Some(HU.as_slice()));
        assert_eq!(p.session_id, 0);
    }

    #[test]
    fn padr_roundtrip_with_cookie() {
        let cookie = [0xaa, 0xbb];
        let frame = build_padr(OUR, AC, b"svc", Some(&cookie), Some(&HU));
        let p = parse_discovery_frame(&frame).expect("parse");
        assert_eq!(p.ac_cookie.as_deref(), Some(cookie.as_slice()));
        assert_eq!(p.host_uniq.as_deref(), Some(HU.as_slice()));
    }

    // ---- FSM drive-to-Established ----

    fn fsm() -> Discovery {
        Discovery::new(OUR, vec![], Some(HU.to_vec()), 3, 3)
    }

    #[test]
    fn fsm_start_sends_padi() {
        let mut d = fsm();
        match d.start() {
            Action::Send(bytes) => assert_eq!(bytes, PADI),
            other => panic!("expected Send, got {other:?}"),
        }
        assert_eq!(d.state(), State::PadiSent);
    }

    #[test]
    fn fsm_pado_yields_padr() {
        let mut d = fsm();
        d.start();
        match d.on_frame(PADO) {
            Action::Send(padr) => {
                assert_eq!(&padr[0..6], AC.octets()); // dst == AC
                let p = parse_discovery_frame(&padr).expect("parse");
                assert_eq!(p.code, CODE_PADR);
                assert_eq!(p.host_uniq.as_deref(), Some(HU.as_slice()));
            }
            other => panic!("expected Send, got {other:?}"),
        }
        assert_eq!(d.state(), State::PadrSent);
    }

    #[test]
    fn fsm_pads_yields_established() {
        let mut d = fsm();
        d.start();
        d.on_frame(PADO);
        let est = Established {
            ac_mac: AC,
            session_id: 0x5e61,
        };
        assert_eq!(d.on_frame(PADS), Action::Established(est));
        assert_eq!(d.state(), State::Established(est));
    }

    #[test]
    fn fsm_host_uniq_mismatch_drops_pado() {
        let mut d = fsm();
        d.start();
        // PADO with a non-matching Host-Uniq.
        let mut pado = PADO.to_vec();
        // Host-Uniq value sits in the last 4 bytes of section 3.3.
        let n = pado.len();
        pado[n - 4..].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(d.on_frame(&pado), Action::Idle);
        assert_eq!(d.state(), State::PadiSent);
    }

    #[test]
    fn fsm_retransmit_padi() {
        let mut d = fsm();
        d.start();
        // retransmit_ticks == 3: two Idle ticks, then a fresh PADI.
        assert_eq!(d.on_tick(), Action::Idle);
        assert_eq!(d.on_tick(), Action::Idle);
        match d.on_tick() {
            Action::Send(bytes) => assert_eq!(bytes, PADI),
            other => panic!("expected Send, got {other:?}"),
        }
        assert_eq!(d.attempts, 1);
        assert_eq!(d.state(), State::PadiSent);
    }

    #[test]
    fn fsm_failure_after_max_attempts() {
        // max_attempts == 2, retransmit_ticks == 1: tick1 resends (attempt 1),
        // tick2 exhausts the budget and fails.
        let mut d = Discovery::new(OUR, vec![], Some(HU.to_vec()), 1, 2);
        d.start();
        match d.on_tick() {
            Action::Send(_) => {}
            other => panic!("expected Send, got {other:?}"),
        }
        assert_eq!(d.on_tick(), Action::Failed);
        assert_eq!(d.state(), State::Dead);
    }

    #[test]
    fn fsm_pads_from_wrong_ac_dropped() {
        let mut d = fsm();
        d.start();
        d.on_frame(PADO);
        // PADS whose src is a different AC than the chosen one.
        let mut pads = PADS.to_vec();
        pads[6..12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(d.on_frame(&pads), Action::Idle);
        assert_eq!(d.state(), State::PadrSent);
    }

    #[test]
    fn fsm_padt_kills_session() {
        let mut d = fsm();
        d.start();
        d.on_frame(PADO); // chooses AC, now PadrSent
        let padt = build_padt(OUR, AC, 0x5e61);
        // PADT src must be the AC; build_padt sets src=our, dst=ac. The AC's
        // PADT to us has src=AC, dst=our.
        let mut from_ac = padt.clone();
        from_ac[0..6].copy_from_slice(OUR.octets()); // dst = us
        from_ac[6..12].copy_from_slice(AC.octets()); // src = AC
        assert_eq!(d.on_frame(&from_ac), Action::Failed);
        assert_eq!(d.state(), State::Dead);
    }

    // ---- Malformed / garbage input must not panic ----

    #[test]
    fn parse_rejects_truncated_eth() {
        assert_eq!(parse_discovery_frame(&[0x00; 10]), Err(Error::TooShort));
    }

    #[test]
    fn parse_rejects_truncated_pppoe() {
        // Valid 0x8863 ethertype but no PPPoE header bytes.
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&ETHERTYPE_DISCOVERY.to_be_bytes());
        assert_eq!(parse_discovery_frame(&frame), Err(Error::TooShort));
    }

    #[test]
    fn parse_rejects_bad_ethertype() {
        // A 0x8864 frame fed to the discovery parser.
        let mut frame = PADS.to_vec();
        frame[12..14].copy_from_slice(&super::super::ETHERTYPE_SESSION.to_be_bytes());
        assert_eq!(
            parse_discovery_frame(&frame),
            Err(Error::BadEtherType(0x8864))
        );
    }

    #[test]
    fn parse_rejects_bad_ver_type() {
        let mut frame = PADS.to_vec();
        frame[14] = 0x21;
        assert_eq!(parse_discovery_frame(&frame), Err(Error::BadVerType(0x21)));
    }

    #[test]
    fn parse_rejects_bad_code() {
        let mut frame = PADS.to_vec();
        frame[15] = 0xff;
        assert_eq!(parse_discovery_frame(&frame), Err(Error::BadCode(0xff)));
    }

    #[test]
    fn parse_rejects_length_overrun() {
        let mut frame = PADS.to_vec();
        // LENGTH at bytes 18..20 claims 255, frame carries 12.
        frame[18..20].copy_from_slice(&255u16.to_be_bytes());
        assert_eq!(parse_discovery_frame(&frame), Err(Error::LengthOverrun));
    }

    #[test]
    fn parse_rejects_tag_overrun() {
        // Eth + PPPoE(LENGTH=8) + payload `01 03 00 08 95 16 00 00`: the
        // Host-Uniq tag claims 8 value bytes but only 4 follow. PPPoE LENGTH
        // covers exactly the 8 payload bytes, isolating the tag overrun.
        let mut frame = Vec::new();
        put_eth_header(&mut frame, OUR, AC, ETHERTYPE_DISCOVERY);
        let payload: &[u8] = &[0x01, 0x03, 0x00, 0x08, 0x95, 0x16, 0x00, 0x00];
        put_pppoe(&mut frame, CODE_PADO, 0, payload);
        assert_eq!(parse_discovery_frame(&frame), Err(Error::TagOverrun));
    }

    #[test]
    fn parse_handles_empty_buffers() {
        assert_eq!(parse_discovery_frame(&[]), Err(Error::TooShort));
        assert!(Tags::new(&[]).next().is_none());
    }

    #[test]
    fn fuzz_no_panic() {
        // Deterministic xorshift-driven garbage. Every decoder and the FSM
        // entry point must reject (or accept) without panicking.
        let mut s: u32 = 0x1234_5678;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        };
        let mut d = Discovery::new(OUR, vec![], Some(HU.to_vec()), 3, 3);
        d.start();
        // Pure-random pass: proves the entry points reject fast-failing garbage.
        for _ in 0..256 {
            let len = (next() % 80) as usize;
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            let _ = parse_discovery_frame(&buf);
            let _ = crate::pppoe::session::parse_session_frame(&buf);
            let _ = d.on_frame(&buf);
        }
        // Structured pass: keep a valid Ethernet header + PPPoE EtherType so the
        // bytes reach the PPPoE LENGTH check and the Tags iterator, then corrupt
        // the rest. This exercises length overrun, tag overrun, and 0xffff
        // TAG_LENGTH paths that pure-random bytes never hit (they fail the
        // EtherType gate first). Seeds are known-good frames, mutated in place.
        let session_seed = crate::pppoe::session::build_session_frame(OUR, AC, 0x5e61, &[]);
        let seeds: [&[u8]; 4] = [PADO, PADS, PADI, &session_seed];
        for seed in seeds {
            let ethertype = u16::from_be_bytes([seed[12], seed[13]]);
            for _ in 0..256 {
                let mut buf = seed.to_vec();
                // Corrupt a random number of bytes past the Ethernet header,
                // leaving dst/src/EtherType intact so the parsers proceed into
                // the PPPoE header and payload decode under attacker control.
                let muts = (next() % 8) + 1;
                for _ in 0..muts {
                    let span = buf.len() - ETH_HDR_LEN;
                    if span == 0 {
                        break;
                    }
                    let idx = ETH_HDR_LEN + (next() as usize % span);
                    buf[idx] = (next() & 0xff) as u8;
                }
                // Sometimes truncate to fuzz the LENGTH-vs-bytes-present bound.
                if next() & 1 == 0 && buf.len() > ETH_HDR_LEN {
                    let keep = ETH_HDR_LEN + (next() as usize % (buf.len() - ETH_HDR_LEN + 1));
                    buf.truncate(keep);
                }
                if ethertype == ETHERTYPE_DISCOVERY {
                    let _ = parse_discovery_frame(&buf);
                } else {
                    let _ = crate::pppoe::session::parse_session_frame(&buf);
                }
                let _ = d.on_frame(&buf);
            }
        }
    }

    #[test]
    fn random_local_mac_bits_and_display() {
        for _ in 0..64 {
            let m = MacAddr::random_local().expect("rng");
            // Locally-administered set, multicast clear.
            assert_eq!(m.octets()[0] & 0x03, 0x02);
            // Display is lowercase colon-separated; parse it back.
            let s = m.to_string();
            let parts: Vec<u8> = s
                .split(':')
                .map(|p| u8::from_str_radix(p, 16).expect("hex"))
                .collect();
            assert_eq!(parts.as_slice(), m.octets());
            assert_eq!(s, s.to_lowercase());
        }
    }
}
