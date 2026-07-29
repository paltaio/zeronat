//! Client exit-mode routes (Linux only): send the host's IPv4 traffic through
//! the tun device while keeping the server reachable over the uplink. The
//! server gets a /32 pin via the current default route; `0.0.0.0/1` and
//! `128.0.0.0/1` point at the tun device and beat any /0 default on prefix
//! length, so the host's own default route stays in place. The decision layer
//! is pure and unit-tested without touching the host; route mutations go
//! through the `crate::route` ioctl helpers behind the [`RouteOps`] seam.
//!
//! Strict mode closes the fallbacks the base set leaves open: every original
//! default route is deleted and `::/1` and `8000::/1` are routed to loopback,
//! so IPv6 sends fail on the host instead of reaching the uplink while the
//! tunnel is up. Teardown restores the defaults and removes both `/1` routes;
//! a crash skips it and leaves the host without its default routes.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::route;

/// The two destinations that together cover all of IPv4.
const HALF_DEFAULTS: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(0, 0, 0, 0), 1),
    (Ipv4Addr::new(128, 0, 0, 0), 1),
];

/// The two `/1` destinations that together cover all of IPv6.
const V6_HALF_DEFAULTS: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
    Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
];

/// One route mutation as data, so the decision layer and the guard's add and
/// remove ordering are testable without ioctls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteChange {
    pub add: bool,
    pub dst: Ipv4Addr,
    pub prefix: u8,
    pub gw: Option<Ipv4Addr>,
    pub dev: String,
}

/// How a /32 pin reaches the uplink: via the default gateway, or link-scoped
/// on the default-route interface when the default is gatewayless (a
/// point-to-point uplink). The server and every punched peer the consumer
/// keeps off the half-defaults take the same shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UplinkPin {
    ViaGateway {
        addr: Ipv4Addr,
        gateway: Ipv4Addr,
        iface: String,
    },
    OnLink {
        addr: Ipv4Addr,
        iface: String,
    },
}

impl UplinkPin {
    /// The pinned address.
    pub fn addr(&self) -> Ipv4Addr {
        match self {
            UplinkPin::ViaGateway { addr, .. } | UplinkPin::OnLink { addr, .. } => *addr,
        }
    }

    /// The same uplink shape pinning a different address.
    fn with_addr(&self, addr: Ipv4Addr) -> UplinkPin {
        let mut pin = self.clone();
        match &mut pin {
            UplinkPin::ViaGateway { addr: a, .. } | UplinkPin::OnLink { addr: a, .. } => {
                *a = addr;
            }
        }
        pin
    }

    /// The pin as a route mutation.
    fn change(&self, add: bool) -> RouteChange {
        match self {
            UplinkPin::ViaGateway {
                addr,
                gateway,
                iface,
            } => RouteChange {
                add,
                dst: *addr,
                prefix: 32,
                gw: Some(*gateway),
                dev: iface.clone(),
            },
            UplinkPin::OnLink { addr, iface } => RouteChange {
                add,
                dst: *addr,
                prefix: 32,
                gw: None,
                dev: iface.clone(),
            },
        }
    }
}

/// Decide the /32 server pin from the current route table: a default route
/// with a gateway pins through that gateway, a gatewayless default pins
/// link-scoped on its interface, and no default at all is an error (there is
/// no uplink to keep the server on).
pub fn plan_server_pin(
    proc_route: &str,
    tun_name: &str,
    server: Ipv4Addr,
) -> crate::Result<UplinkPin> {
    if let Some(d) = route::parse_proc_route(proc_route, tun_name) {
        return Ok(UplinkPin::ViaGateway {
            addr: server,
            gateway: d.gateway,
            iface: d.iface,
        });
    }
    if let Some(iface) = route::default_route_iface(proc_route, tun_name) {
        return Ok(UplinkPin::OnLink {
            addr: server,
            iface,
        });
    }
    Err("no default route to pin the server through".into())
}

/// The /32 pins a peer-exit consumer holds beside the server's while its
/// half-default routes are up. A peer only the default route reaches would
/// otherwise have its datagrams swallowed by the half-defaults, and the tunnel
/// would carry what carries it; the pin takes the shape the current default
/// route decides, so a gatewayless uplink pins link-scoped as well.
///
/// A peer some route already reaches more specifically than a `/1` gets none:
/// that route beats the half-defaults on its own, and pinning a peer on the LAN
/// or behind a second interface through the default gateway would route it away
/// from the interface that reaches it.
pub fn plan_underlay_pins(
    proc_route: &str,
    tun_name: &str,
    peers: &[Ipv4Addr],
) -> crate::Result<Vec<UplinkPin>> {
    peers
        .iter()
        .filter(|&&peer| !route::covered_beyond_half(proc_route, tun_name, peer))
        .map(|&peer| plan_server_pin(proc_route, tun_name, peer))
        .collect()
}

/// Whether a route mutation failed only because the route already exists.
fn already_exists(e: &crate::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
}

/// How route mutations reach the kernel. The guard is generic over this so
/// its ordering is testable without live ioctls.
pub trait RouteOps {
    fn apply(&mut self, change: &RouteChange) -> crate::Result<()>;
}

/// Applies route changes with the `crate::route` ioctls.
pub struct SysRouteOps;

impl RouteOps for SysRouteOps {
    fn apply(&mut self, c: &RouteChange) -> crate::Result<()> {
        route::modify_route(c.add, c.dst, c.prefix, c.gw, Some(&c.dev), 0)
    }
}

/// One strict-mode route mutation as data, testable like [`RouteChange`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrictChange {
    /// One captured original IPv4 default route; deleted at bringup
    /// (`add = false`), restored on teardown. `gw` is `None` for a captured
    /// gatewayless default, which goes back link-scoped on its interface.
    Default {
        add: bool,
        gw: Option<Ipv4Addr>,
        iface: String,
        metric: u32,
    },
    /// A route covering one half of IPv6, pointed off the uplink.
    V6Half {
        add: bool,
        dst: Ipv6Addr,
        prefix: u8,
    },
}

/// How strict-mode mutations reach the kernel, the strict sibling of
/// [`RouteOps`].
pub trait StrictOps {
    fn apply(&mut self, change: &StrictChange) -> crate::Result<()>;
}

impl StrictOps for SysRouteOps {
    fn apply(&mut self, c: &StrictChange) -> crate::Result<()> {
        match c {
            StrictChange::Default {
                add,
                gw,
                iface,
                metric,
            } => route::modify_route(*add, Ipv4Addr::UNSPECIFIED, 0, *gw, Some(iface), *metric),
            StrictChange::V6Half { add, dst, prefix } => route::modify_route6(*add, *dst, *prefix),
        }
    }
}

/// Holds the programmed exit routes and removes them on drop. Held across
/// redials: the routes live as long as the tun session, and the /32 pin is
/// re-asserted before every dial because the guard's state is a cache of what
/// should exist, not what does (the kernel purges an interface's routes when
/// its uplink flaps). The release profile is panic=abort so Drop does not run
/// on a panic; the kernel drops the tun-device routes with the device, and
/// the surviving /32 pin is harmless.
pub struct ExitRouteGuard<S: RouteOps = SysRouteOps> {
    pin: UplinkPin,
    tun_name: String,
    ops: S,
}

impl ExitRouteGuard {
    /// Program the exit routes with the route ioctls and return the guard
    /// that removes them.
    pub fn bring_up(pin: UplinkPin, tun_name: &str) -> crate::Result<Self> {
        Self::bring_up_with(SysRouteOps, pin, tun_name)
    }
}

impl<S: RouteOps> ExitRouteGuard<S> {
    /// Program the server pin, then the two half-defaults via the tun device,
    /// pin first so no packet to the server can route into the tun in
    /// between. An already-exists answer counts as held for any of the three,
    /// the way the per-dial assert reads it: the pin sits on the uplink and
    /// survives a crash that took the tun and its half-defaults with it, so
    /// the next run adopts the leftover instead of failing its first cycle. A
    /// failed add removes whatever was already programmed.
    pub fn bring_up_with(ops: S, pin: UplinkPin, tun_name: &str) -> crate::Result<Self> {
        let mut guard = ExitRouteGuard {
            pin,
            tun_name: tun_name.to_string(),
            ops,
        };
        for change in guard.changes(true) {
            match guard.ops.apply(&change) {
                Err(e) if !already_exists(&e) => return Err(e),
                _ => {}
            }
        }
        Ok(guard)
    }

    /// Assert the /32 pin for `server` ahead of a dial: the pin is added
    /// every cycle, an already-exists answer counting as held, so a pin the
    /// kernel purged on an uplink flap is back before the dial. A changed
    /// address removes the old pin first (best-effort, it may already be
    /// gone). The half-defaults are not re-asserted: the process holds the
    /// tun fd, so that interface cannot flap while the guard lives.
    pub fn assert_pin(&mut self, server: Ipv4Addr) -> crate::Result<()> {
        if self.pin.addr() != server {
            let _ = self.ops.apply(&self.pin.change(false));
            self.pin = self.pin.with_addr(server);
        }
        match self.ops.apply(&self.pin.change(true)) {
            Err(e) if !already_exists(&e) => Err(e),
            _ => Ok(()),
        }
    }

    /// The full route set, pin first: what bringup adds and, reversed, what
    /// teardown removes.
    fn changes(&self, add: bool) -> Vec<RouteChange> {
        let mut v = vec![self.pin.change(add)];
        for (dst, prefix) in HALF_DEFAULTS {
            v.push(RouteChange {
                add,
                dst,
                prefix,
                gw: None,
                dev: self.tun_name.clone(),
            });
        }
        v
    }
}

impl<S: RouteOps> Drop for ExitRouteGuard<S> {
    /// Remove the exit routes: halves first, the pin last (the add order
    /// reversed). Each removal is best-effort so a partially applied bringup
    /// tears down cleanly.
    fn drop(&mut self) {
        for change in self.changes(false).into_iter().rev() {
            let _ = self.ops.apply(&change);
        }
    }
}

/// Holds the underlay pins programmed beside a base set and removes them on
/// drop. An add answering already-exists counts as held, the way the server
/// pin's per-dial assert does.
pub struct PinGuard<S: RouteOps = SysRouteOps> {
    pins: Vec<UplinkPin>,
    ops: S,
}

impl PinGuard {
    /// Program `pins` with the route ioctls and return the guard that removes
    /// them.
    pub fn bring_up(pins: Vec<UplinkPin>) -> crate::Result<Self> {
        Self::bring_up_with(SysRouteOps, pins)
    }
}

impl<S: RouteOps> PinGuard<S> {
    /// Program each pin in turn. A failed add drops the guard, which removes
    /// the pins already programmed.
    pub fn bring_up_with(ops: S, pins: Vec<UplinkPin>) -> crate::Result<Self> {
        let mut guard = PinGuard {
            pins: Vec::new(),
            ops,
        };
        for pin in pins {
            match guard.ops.apply(&pin.change(true)) {
                Err(e) if !already_exists(&e) => return Err(e),
                _ => guard.pins.push(pin),
            }
        }
        Ok(guard)
    }
}

impl<S: RouteOps> Drop for PinGuard<S> {
    /// Remove the pins in reverse of the order they went in, best-effort so a
    /// partially programmed set tears down cleanly.
    fn drop(&mut self) {
        for pin in self.pins.iter().rev() {
            let _ = self.ops.apply(&pin.change(false));
        }
    }
}

/// Holds the strict-mode route set: the two v6 halves and the deleted
/// original defaults, undone in reverse on drop.
pub struct StrictRouteGuard<S: StrictOps = SysRouteOps> {
    /// Every captured default, worst metric first: the deletion order.
    defaults: Vec<route::CapturedDefault>,
    ops: S,
}

impl<S: StrictOps> StrictRouteGuard<S> {
    /// Program the strict set: the v6 halves, then the default deletes
    /// last, worst metric first and the best last, so a failed earlier step
    /// never leaves the host without its working default. A failed step
    /// drops the guard, which unwinds the whole set.
    pub fn bring_up_with(ops: S, mut defaults: Vec<route::CapturedDefault>) -> crate::Result<Self> {
        defaults.sort_by_key(|d| std::cmp::Reverse(d.metric));
        let mut guard = StrictRouteGuard { defaults, ops };
        for change in guard.changes(true) {
            guard.ops.apply(&change)?;
        }
        Ok(guard)
    }

    /// The strict change set in bringup order; reversed, the teardown order.
    /// The default entries invert `up`: bringup deletes every captured
    /// default and teardown restores them, best metric first. A gateway of
    /// `0.0.0.0` in a capture means that default was gatewayless, restored
    /// link-scoped.
    fn changes(&self, up: bool) -> Vec<StrictChange> {
        let mut v: Vec<StrictChange> = V6_HALF_DEFAULTS
            .iter()
            .map(|&dst| StrictChange::V6Half {
                add: up,
                dst,
                prefix: 1,
            })
            .collect();
        for d in &self.defaults {
            v.push(StrictChange::Default {
                add: !up,
                gw: (d.gateway != Ipv4Addr::UNSPECIFIED).then_some(d.gateway),
                iface: d.iface.clone(),
                metric: d.metric,
            });
        }
        v
    }
}

impl<S: StrictOps> Drop for StrictRouteGuard<S> {
    /// Restore the defaults first, then remove the v6 halves (the
    /// bringup order reversed). Each step is best-effort so a partially
    /// applied bringup unwinds cleanly; a restore may find its default still
    /// in place when the delete never ran.
    fn drop(&mut self) {
        for change in self.changes(false).into_iter().rev() {
            let _ = self.ops.apply(&change);
        }
    }
}

/// The whole exit route set for one tun session: the base routes always, the
/// strict set on top when strict mode is on. Field order is the teardown
/// order: the strict set drops first, so the original default is back before
/// the base routes come off.
pub struct ExitRoutes<S: RouteOps = SysRouteOps, T: StrictOps = SysRouteOps> {
    #[allow(dead_code)] // held for its Drop
    strict: Option<StrictRouteGuard<T>>,
    base: ExitRouteGuard<S>,
}

impl ExitRoutes {
    /// Program the base routes and, when `strict` carries the captured
    /// defaults, the strict set on top of them.
    pub fn bring_up(
        pin: UplinkPin,
        tun_name: &str,
        strict: Option<Vec<route::CapturedDefault>>,
    ) -> crate::Result<Self> {
        Self::bring_up_with(SysRouteOps, SysRouteOps, pin, tun_name, strict)
    }

    /// Program the exit routes for `server` over `tun_name` from one read of
    /// the route table: the pin its default route decides and, in strict mode,
    /// the defaults captured from that same read. Strict mode with no default
    /// route to capture is an error.
    pub fn bring_up_from_table(
        table: &str,
        tun_name: &str,
        server: Ipv4Addr,
        strict: bool,
    ) -> crate::Result<Self> {
        let pin = plan_server_pin(table, tun_name, server)?;
        let original = if strict {
            let defaults = route::parse_all_defaults(table, tun_name);
            if defaults.is_empty() {
                return Err("no default route to capture for strict exit".into());
            }
            Some(defaults)
        } else {
            None
        };
        Self::bring_up(pin, tun_name, original)
    }
}

impl<S: RouteOps, T: StrictOps> ExitRoutes<S, T> {
    /// Base set first, strict set second; a failed strict bringup drops the
    /// base guard, so an error here leaves no route behind.
    pub fn bring_up_with(
        ops: S,
        strict_ops: T,
        pin: UplinkPin,
        tun_name: &str,
        strict: Option<Vec<route::CapturedDefault>>,
    ) -> crate::Result<Self> {
        let base = ExitRouteGuard::bring_up_with(ops, pin, tun_name)?;
        let strict = match strict {
            Some(defaults) => Some(StrictRouteGuard::bring_up_with(strict_ops, defaults)?),
            None => None,
        };
        Ok(ExitRoutes { strict, base })
    }

    /// Assert the /32 pin for `server` ahead of a dial. The strict set is
    /// never re-asserted: the v6 halves sit on loopback, so no uplink flap
    /// purges them, and the deleted defaults are an absence with nothing to
    /// re-add.
    pub fn assert_pin(&mut self, server: Ipv4Addr) -> crate::Result<()> {
        self.base.assert_pin(server)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    // A default via 192.168.80.1 on eth0 plus a connected route; gateway
    // 0150A8C0 is little-endian 192.168.80.1.
    const GW_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    // A point-to-point uplink: the default sits on ppp0 with a zero gateway.
    const PPP_ROUTE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    // Connected routes only: no default at all.
    const NO_DEFAULT: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    /// Injected kernel behavior for one destination's adds, switchable while
    /// the guard owns the recorder.
    #[derive(Clone, Copy, Default)]
    struct Fault {
        fail_add: Option<Ipv4Addr>,
        exists_add: Option<Ipv4Addr>,
    }

    type Log = Rc<RefCell<Vec<RouteChange>>>;

    /// Records every applied change; `fault` refuses matching adds, either
    /// with a plain error or an `AlreadyExists` one.
    struct Recorder {
        log: Log,
        fault: Rc<Cell<Fault>>,
    }

    fn recorder() -> (Recorder, Log, Rc<Cell<Fault>>) {
        let log = Rc::new(RefCell::new(Vec::new()));
        let fault = Rc::new(Cell::new(Fault::default()));
        (
            Recorder {
                log: log.clone(),
                fault: fault.clone(),
            },
            log,
            fault,
        )
    }

    impl RouteOps for Recorder {
        fn apply(&mut self, change: &RouteChange) -> crate::Result<()> {
            let fault = self.fault.get();
            if change.add && fault.fail_add == Some(change.dst) {
                return Err("add refused".into());
            }
            if change.add && fault.exists_add == Some(change.dst) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "route exists",
                )));
            }
            self.log.borrow_mut().push(change.clone());
            Ok(())
        }
    }

    fn half(add: bool, dst: [u8; 4], dev: &str) -> RouteChange {
        RouteChange {
            add,
            dst: Ipv4Addr::from(dst),
            prefix: 1,
            gw: None,
            dev: dev.into(),
        }
    }

    #[test]
    fn pin_goes_via_the_default_gateway() {
        assert_eq!(
            plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap(),
            UplinkPin::ViaGateway {
                addr: SERVER,
                gateway: Ipv4Addr::new(192, 168, 80, 1),
                iface: "eth0".into(),
            }
        );
    }

    #[test]
    fn gatewayless_default_pins_on_link() {
        assert_eq!(
            plan_server_pin(PPP_ROUTE, "zn0", SERVER).unwrap(),
            UplinkPin::OnLink {
                addr: SERVER,
                iface: "ppp0".into(),
            }
        );
    }

    #[test]
    fn no_default_route_is_a_bringup_error() {
        assert!(plan_server_pin(NO_DEFAULT, "zn0", SERVER).is_err());
        assert!(plan_server_pin("", "zn0", SERVER).is_err());
        // A default already on the tun itself is not an uplink.
        let tun_default = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
zn0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
";
        assert!(plan_server_pin(tun_default, "zn0", SERVER).is_err());
    }

    #[test]
    fn bringup_programs_pin_then_halves_and_drop_reverses() {
        let (rec, log, _fault) = recorder();
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        let guard = ExitRouteGuard::bring_up_with(rec, pin.clone(), "zn0").unwrap();
        assert_eq!(
            *log.borrow(),
            [
                pin.change(true),
                half(true, [0, 0, 0, 0], "zn0"),
                half(true, [128, 0, 0, 0], "zn0"),
            ]
        );

        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(
            *log.borrow(),
            [
                half(false, [128, 0, 0, 0], "zn0"),
                half(false, [0, 0, 0, 0], "zn0"),
                pin.change(false),
            ]
        );
    }

    // The tun and its half-defaults die with a crashed process while the pin
    // stays on the uplink, so the next bringup meets a pin it did not
    // program. It adopts the leftover and removes it on teardown, the way the
    // per-dial assert reads the same answer.
    #[test]
    fn bringup_adopts_a_pin_the_kernel_already_holds() {
        let (rec, log, fault) = recorder();
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        fault.set(Fault {
            exists_add: Some(SERVER),
            ..Fault::default()
        });
        let guard = ExitRouteGuard::bring_up_with(rec, pin.clone(), "zn0").unwrap();
        assert_eq!(
            *log.borrow(),
            [
                half(true, [0, 0, 0, 0], "zn0"),
                half(true, [128, 0, 0, 0], "zn0"),
            ]
        );

        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(
            *log.borrow(),
            [
                half(false, [128, 0, 0, 0], "zn0"),
                half(false, [0, 0, 0, 0], "zn0"),
                pin.change(false),
            ]
        );
    }

    #[test]
    fn link_scoped_pin_carries_no_gateway() {
        let (rec, log, _fault) = recorder();
        let pin = plan_server_pin(PPP_ROUTE, "zn0", SERVER).unwrap();
        let _guard = ExitRouteGuard::bring_up_with(rec, pin, "zn0").unwrap();
        assert_eq!(
            log.borrow()[0],
            RouteChange {
                add: true,
                dst: SERVER,
                prefix: 32,
                gw: None,
                dev: "ppp0".into(),
            }
        );
    }

    #[test]
    fn pin_is_reasserted_every_cycle_and_tolerates_already_exists() {
        let (rec, log, fault) = recorder();
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        let mut guard = ExitRouteGuard::bring_up_with(rec, pin.clone(), "zn0").unwrap();

        // An ordinary redial to the same address re-adds the pin (the kernel
        // may have purged it on an uplink flap); the halves are left alone.
        log.borrow_mut().clear();
        guard.assert_pin(SERVER).unwrap();
        assert_eq!(*log.borrow(), [pin.change(true)]);

        // The kernel still holds the pin: already-exists is success.
        fault.set(Fault {
            exists_add: Some(SERVER),
            ..Fault::default()
        });
        log.borrow_mut().clear();
        guard.assert_pin(SERVER).unwrap();
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn assert_pin_moves_a_changed_address() {
        let (rec, log, _fault) = recorder();
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        let mut guard = ExitRouteGuard::bring_up_with(rec, pin.clone(), "zn0").unwrap();

        // The server moved: the old pin goes, the new one lands, same uplink.
        log.borrow_mut().clear();
        let moved = Ipv4Addr::new(198, 51, 100, 4);
        guard.assert_pin(moved).unwrap();
        let new_pin = pin.with_addr(moved);
        assert_eq!(*log.borrow(), [pin.change(false), new_pin.change(true)]);

        // Teardown removes the current pin, not the original one.
        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(log.borrow().last(), Some(&new_pin.change(false)));
    }

    #[test]
    fn failed_pin_assert_surfaces_the_error() {
        let (rec, _log, fault) = recorder();
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        let mut guard = ExitRouteGuard::bring_up_with(rec, pin, "zn0").unwrap();
        fault.set(Fault {
            fail_add: Some(SERVER),
            ..Fault::default()
        });
        assert!(guard.assert_pin(SERVER).is_err());
    }

    /// The address a punched pair's own datagrams travel to.
    const PEER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    // The pins take the uplink the default route names, and go link-scoped
    // when that default has no gateway.
    #[test]
    fn underlay_pins_take_the_punched_peer_over_the_uplink() {
        assert_eq!(
            plan_underlay_pins(GW_ROUTE, "zn0", &[PEER]).unwrap(),
            [UplinkPin::ViaGateway {
                addr: PEER,
                gateway: Ipv4Addr::new(192, 168, 80, 1),
                iface: "eth0".into(),
            }]
        );
        assert_eq!(
            plan_underlay_pins(PPP_ROUTE, "zn0", &[PEER]).unwrap(),
            [UplinkPin::OnLink {
                addr: PEER,
                iface: "ppp0".into(),
            }]
        );
        assert!(plan_underlay_pins(GW_ROUTE, "zn0", &[]).unwrap().is_empty());
        assert!(plan_underlay_pins(NO_DEFAULT, "zn0", &[PEER]).is_err());
    }

    /// A peer on the LAN the default-route interface is connected to.
    const ON_LINK_PEER: Ipv4Addr = Ipv4Addr::new(192, 168, 80, 23);

    // The same uplink with a second NIC: its own connected /24, and a host
    // route for the peer 198.51.100.7.
    const MULTI_HOMED: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0050A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth1\t00000A0A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth1\t076433C6\t00000000\t0005\t0\t0\t100\tFFFFFFFF\t0\t0\t0
";

    // A peer the table already reaches keeps the route it has: two clients
    // behind one NAT punch to a LAN address the uplink is connected to, and a
    // pin through the default gateway would take that peer off the interface
    // that reaches it.
    #[test]
    fn a_peer_the_table_already_reaches_gets_no_pin() {
        assert!(plan_underlay_pins(GW_ROUTE, "zn0", &[ON_LINK_PEER])
            .unwrap()
            .is_empty());
        // The second NIC's connected /24 and its host route cover as well.
        let second_nic = Ipv4Addr::new(10, 10, 0, 5);
        assert!(
            plan_underlay_pins(MULTI_HOMED, "zn0", &[second_nic, PEER, ON_LINK_PEER])
                .unwrap()
                .is_empty()
        );
        // An address only the default route reaches still pins through it.
        assert_eq!(
            plan_underlay_pins(MULTI_HOMED, "zn0", &[ON_LINK_PEER, SERVER]).unwrap(),
            [UplinkPin::ViaGateway {
                addr: SERVER,
                gateway: Ipv4Addr::new(192, 168, 80, 1),
                iface: "eth0".into(),
            }]
        );
    }

    #[test]
    fn the_pin_guard_programs_every_pin_and_drop_removes_them() {
        let (rec, log, _fault) = recorder();
        let pins = plan_underlay_pins(GW_ROUTE, "zn0", &[PEER, SERVER]).unwrap();
        let guard = PinGuard::bring_up_with(rec, pins.clone()).unwrap();
        assert_eq!(*log.borrow(), [pins[0].change(true), pins[1].change(true)]);

        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(
            *log.borrow(),
            [pins[1].change(false), pins[0].change(false)]
        );
    }

    // A pin the kernel already holds counts as held, and an add it refuses
    // takes the pins before it back out.
    #[test]
    fn the_pin_guard_holds_an_existing_pin_and_unwinds_a_refused_one() {
        let (rec, log, fault) = recorder();
        fault.set(Fault {
            exists_add: Some(PEER),
            ..Fault::default()
        });
        let pins = plan_underlay_pins(GW_ROUTE, "zn0", &[PEER]).unwrap();
        let guard = PinGuard::bring_up_with(rec, pins.clone()).unwrap();
        assert!(log.borrow().is_empty());
        drop(guard);
        assert_eq!(*log.borrow(), [pins[0].change(false)]);

        let (rec, log, fault) = recorder();
        fault.set(Fault {
            fail_add: Some(SERVER),
            ..Fault::default()
        });
        let pins = plan_underlay_pins(GW_ROUTE, "zn0", &[PEER, SERVER]).unwrap();
        assert!(PinGuard::bring_up_with(rec, pins.clone()).is_err());
        assert_eq!(*log.borrow(), [pins[0].change(true), pins[0].change(false)]);
    }

    /// One applied change from either seam, so the composed guard's ordering
    /// across both is assertable in a single log.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Entry {
        Base(RouteChange),
        Strict(StrictChange),
    }

    type MixedLog = Rc<RefCell<Vec<Entry>>>;

    struct BaseRec {
        log: MixedLog,
    }

    impl RouteOps for BaseRec {
        fn apply(&mut self, change: &RouteChange) -> crate::Result<()> {
            self.log.borrow_mut().push(Entry::Base(change.clone()));
            Ok(())
        }
    }

    /// Records strict changes; `fail_delete_iface` refuses the default
    /// delete for that interface.
    struct StrictRec {
        log: MixedLog,
        fail_delete_iface: Option<&'static str>,
    }

    impl StrictOps for StrictRec {
        fn apply(&mut self, change: &StrictChange) -> crate::Result<()> {
            if let StrictChange::Default {
                add: false, iface, ..
            } = change
            {
                if self.fail_delete_iface == Some(iface.as_str()) {
                    return Err("delete refused".into());
                }
            }
            self.log.borrow_mut().push(Entry::Strict(change.clone()));
            Ok(())
        }
    }

    fn captured(gw: [u8; 4], iface: &str, metric: u32) -> route::CapturedDefault {
        route::CapturedDefault {
            gateway: Ipv4Addr::from(gw),
            iface: iface.into(),
            metric,
        }
    }

    fn v6half(hi: u16, add: bool) -> StrictChange {
        StrictChange::V6Half {
            add,
            dst: Ipv6Addr::new(hi, 0, 0, 0, 0, 0, 0, 0),
            prefix: 1,
        }
    }

    fn default_change(add: bool, gw: Option<[u8; 4]>, iface: &str, metric: u32) -> StrictChange {
        StrictChange::Default {
            add,
            gw: gw.map(Ipv4Addr::from),
            iface: iface.into(),
            metric,
        }
    }

    #[test]
    fn strict_bringup_adds_the_v6_halves_then_deletes_the_default_last() {
        let log: MixedLog = Rc::new(RefCell::new(Vec::new()));
        let rec = StrictRec {
            log: log.clone(),
            fail_delete_iface: None,
        };
        let guard =
            StrictRouteGuard::bring_up_with(rec, vec![captured([192, 168, 80, 1], "eth0", 100)])
                .unwrap();
        assert_eq!(
            *log.borrow(),
            [
                Entry::Strict(v6half(0, true)),
                Entry::Strict(v6half(0x8000, true)),
                Entry::Strict(default_change(false, Some([192, 168, 80, 1]), "eth0", 100)),
            ]
        );

        // Teardown reversed: the default is back before the v6 halves lift.
        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(
            *log.borrow(),
            [
                Entry::Strict(default_change(true, Some([192, 168, 80, 1]), "eth0", 100)),
                Entry::Strict(v6half(0x8000, false)),
                Entry::Strict(v6half(0, false)),
            ]
        );
    }

    #[test]
    fn gatewayless_captured_default_restores_link_scoped() {
        let log: MixedLog = Rc::new(RefCell::new(Vec::new()));
        let rec = StrictRec {
            log: log.clone(),
            fail_delete_iface: None,
        };
        let guard =
            StrictRouteGuard::bring_up_with(rec, vec![captured([0, 0, 0, 0], "ppp0", 0)]).unwrap();
        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(
            log.borrow().first(),
            Some(&Entry::Strict(default_change(true, None, "ppp0", 0)))
        );
    }

    #[test]
    fn every_captured_default_is_deleted_worst_first_and_restored_in_reverse() {
        // Two uplink defaults plus the tun's own row: the capture takes both
        // uplink rows and skips the tun. Gateways 0150A8C0 and 0100000A are
        // little-endian 192.168.80.1 and 10.0.0.1.
        let routes = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0150A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0100000A\t0003\t0\t0\t600\t00000000\t0\t0\t0
zn0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
";
        let defaults = route::parse_all_defaults(routes, "zn0");
        assert_eq!(defaults.len(), 2);

        let log: MixedLog = Rc::new(RefCell::new(Vec::new()));
        let rec = StrictRec {
            log: log.clone(),
            fail_delete_iface: None,
        };
        // Bringup deletes worst metric first: no default survives, and the
        // best one is the last to go.
        let guard = StrictRouteGuard::bring_up_with(rec, defaults).unwrap();
        assert_eq!(
            *log.borrow(),
            [
                Entry::Strict(v6half(0, true)),
                Entry::Strict(v6half(0x8000, true)),
                Entry::Strict(default_change(false, Some([10, 0, 0, 1]), "wlan0", 600)),
                Entry::Strict(default_change(false, Some([192, 168, 80, 1]), "eth0", 100)),
            ]
        );

        // Teardown restores in reverse: best first, worst last.
        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(
            *log.borrow(),
            [
                Entry::Strict(default_change(true, Some([192, 168, 80, 1]), "eth0", 100)),
                Entry::Strict(default_change(true, Some([10, 0, 0, 1]), "wlan0", 600)),
                Entry::Strict(v6half(0x8000, false)),
                Entry::Strict(v6half(0, false)),
            ]
        );
    }

    #[test]
    fn failed_delete_restores_the_rows_already_deleted() {
        let log: MixedLog = Rc::new(RefCell::new(Vec::new()));
        let rec = StrictRec {
            log: log.clone(),
            fail_delete_iface: Some("eth0"),
        };
        let res = StrictRouteGuard::bring_up_with(
            rec,
            vec![
                captured([192, 168, 80, 1], "eth0", 100),
                captured([10, 0, 0, 1], "wlan0", 600),
            ],
        );
        assert!(res.is_err());
        // The worst default (wlan0) was already gone when the best delete
        // was refused; the unwind puts both back, best first, then lifts the
        // v6 halves.
        assert_eq!(
            *log.borrow(),
            [
                Entry::Strict(v6half(0, true)),
                Entry::Strict(v6half(0x8000, true)),
                Entry::Strict(default_change(false, Some([10, 0, 0, 1]), "wlan0", 600)),
                Entry::Strict(default_change(true, Some([192, 168, 80, 1]), "eth0", 100)),
                Entry::Strict(default_change(true, Some([10, 0, 0, 1]), "wlan0", 600)),
                Entry::Strict(v6half(0x8000, false)),
                Entry::Strict(v6half(0, false)),
            ]
        );
    }

    #[test]
    fn strict_exit_layers_over_the_base_set_and_drop_reverses() {
        let log: MixedLog = Rc::new(RefCell::new(Vec::new()));
        let base = BaseRec { log: log.clone() };
        let strict = StrictRec {
            log: log.clone(),
            fail_delete_iface: None,
        };
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        let original = vec![captured([192, 168, 80, 1], "eth0", 100)];
        let mut guard =
            ExitRoutes::bring_up_with(base, strict, pin.clone(), "zn0", Some(original)).unwrap();
        assert_eq!(
            *log.borrow(),
            [
                Entry::Base(pin.change(true)),
                Entry::Base(half(true, [0, 0, 0, 0], "zn0")),
                Entry::Base(half(true, [128, 0, 0, 0], "zn0")),
                Entry::Strict(v6half(0, true)),
                Entry::Strict(v6half(0x8000, true)),
                Entry::Strict(default_change(false, Some([192, 168, 80, 1]), "eth0", 100)),
            ]
        );

        // A redial re-asserts the pin only; the strict set is left alone.
        log.borrow_mut().clear();
        guard.assert_pin(SERVER).unwrap();
        assert_eq!(*log.borrow(), [Entry::Base(pin.change(true))]);

        log.borrow_mut().clear();
        drop(guard);
        assert_eq!(
            *log.borrow(),
            [
                Entry::Strict(default_change(true, Some([192, 168, 80, 1]), "eth0", 100)),
                Entry::Strict(v6half(0x8000, false)),
                Entry::Strict(v6half(0, false)),
                Entry::Base(half(false, [128, 0, 0, 0], "zn0")),
                Entry::Base(half(false, [0, 0, 0, 0], "zn0")),
                Entry::Base(pin.change(false)),
            ]
        );
    }

    #[test]
    fn failed_strict_bringup_unwinds_and_restores_the_default() {
        let log: MixedLog = Rc::new(RefCell::new(Vec::new()));
        let base = BaseRec { log: log.clone() };
        let strict = StrictRec {
            log: log.clone(),
            fail_delete_iface: Some("eth0"),
        };
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        let original = vec![captured([192, 168, 80, 1], "eth0", 100)];
        let res = ExitRoutes::bring_up_with(base, strict, pin.clone(), "zn0", Some(original));
        assert!(res.is_err());
        // The base set and the v6 halves went in; the refused delete unwinds
        // the whole stack, the default restore first (best-effort: here the
        // delete never ran, so it finds the default still in place).
        assert_eq!(
            *log.borrow(),
            [
                Entry::Base(pin.change(true)),
                Entry::Base(half(true, [0, 0, 0, 0], "zn0")),
                Entry::Base(half(true, [128, 0, 0, 0], "zn0")),
                Entry::Strict(v6half(0, true)),
                Entry::Strict(v6half(0x8000, true)),
                Entry::Strict(default_change(true, Some([192, 168, 80, 1]), "eth0", 100)),
                Entry::Strict(v6half(0x8000, false)),
                Entry::Strict(v6half(0, false)),
                Entry::Base(half(false, [128, 0, 0, 0], "zn0")),
                Entry::Base(half(false, [0, 0, 0, 0], "zn0")),
                Entry::Base(pin.change(false)),
            ]
        );
    }

    #[test]
    fn failed_bringup_removes_what_was_added() {
        let (rec, log, fault) = recorder();
        fault.set(Fault {
            fail_add: Some(Ipv4Addr::new(128, 0, 0, 0)),
            ..Fault::default()
        });
        let pin = plan_server_pin(GW_ROUTE, "zn0", SERVER).unwrap();
        let res = ExitRouteGuard::bring_up_with(rec, pin.clone(), "zn0");
        assert!(res.is_err());
        // The pin and the first half went in, then the teardown removals ran
        // for the whole set (removing a never-added route is a no-op).
        assert_eq!(
            *log.borrow(),
            [
                pin.change(true),
                half(true, [0, 0, 0, 0], "zn0"),
                half(false, [128, 0, 0, 0], "zn0"),
                half(false, [0, 0, 0, 0], "zn0"),
                pin.change(false),
            ]
        );
    }
}
