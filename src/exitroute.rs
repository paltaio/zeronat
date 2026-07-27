//! Client exit-mode routes (Linux only): send the host's IPv4 traffic through
//! the tun device while keeping the server reachable over the uplink. The
//! server gets a /32 pin via the current default route; `0.0.0.0/1` and
//! `128.0.0.0/1` point at the tun device and beat any /0 default on prefix
//! length, so the host's own default route stays in place. The decision layer
//! is pure and unit-tested without touching the host; route mutations go
//! through the `crate::route` ioctl helpers behind the [`RouteOps`] seam.

use std::net::Ipv4Addr;

use crate::route;

/// The two destinations that together cover all of IPv4.
const HALF_DEFAULTS: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(0, 0, 0, 0), 1),
    (Ipv4Addr::new(128, 0, 0, 0), 1),
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

/// How the /32 server pin reaches the uplink: via the default gateway, or
/// link-scoped on the default-route interface when the default is gatewayless
/// (a point-to-point uplink).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerPin {
    ViaGateway {
        server: Ipv4Addr,
        gateway: Ipv4Addr,
        iface: String,
    },
    OnLink {
        server: Ipv4Addr,
        iface: String,
    },
}

impl ServerPin {
    /// The pinned server address.
    pub fn server(&self) -> Ipv4Addr {
        match self {
            ServerPin::ViaGateway { server, .. } | ServerPin::OnLink { server, .. } => *server,
        }
    }

    /// The same uplink shape pinning a different server address.
    fn with_server(&self, server: Ipv4Addr) -> ServerPin {
        let mut pin = self.clone();
        match &mut pin {
            ServerPin::ViaGateway { server: s, .. } | ServerPin::OnLink { server: s, .. } => {
                *s = server;
            }
        }
        pin
    }

    /// The pin as a route mutation.
    fn change(&self, add: bool) -> RouteChange {
        match self {
            ServerPin::ViaGateway {
                server,
                gateway,
                iface,
            } => RouteChange {
                add,
                dst: *server,
                prefix: 32,
                gw: Some(*gateway),
                dev: iface.clone(),
            },
            ServerPin::OnLink { server, iface } => RouteChange {
                add,
                dst: *server,
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
) -> crate::Result<ServerPin> {
    if let Some(d) = route::parse_proc_route(proc_route, tun_name) {
        return Ok(ServerPin::ViaGateway {
            server,
            gateway: d.gateway,
            iface: d.iface,
        });
    }
    if let Some(iface) = route::default_route_iface(proc_route, tun_name) {
        return Ok(ServerPin::OnLink { server, iface });
    }
    Err("no default route to pin the server through".into())
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

/// Holds the programmed exit routes and removes them on drop. Held across
/// redials: the routes live as long as the tun session, and the /32 pin is
/// re-asserted before every dial because the guard's state is a cache of what
/// should exist, not what does (the kernel purges an interface's routes when
/// its uplink flaps). The release profile is panic=abort so Drop does not run
/// on a panic; the kernel drops the tun-device routes with the device, and
/// the surviving /32 pin is harmless.
pub struct ExitRouteGuard<S: RouteOps = SysRouteOps> {
    pin: ServerPin,
    tun_name: String,
    ops: S,
}

impl ExitRouteGuard {
    /// Program the exit routes with the route ioctls and return the guard
    /// that removes them.
    pub fn bring_up(pin: ServerPin, tun_name: &str) -> crate::Result<Self> {
        Self::bring_up_with(SysRouteOps, pin, tun_name)
    }
}

impl<S: RouteOps> ExitRouteGuard<S> {
    /// Program the server pin, then the two half-defaults via the tun device,
    /// pin first so no packet to the server can route into the tun in
    /// between. A failed add removes whatever was already programmed.
    pub fn bring_up_with(ops: S, pin: ServerPin, tun_name: &str) -> crate::Result<Self> {
        let mut guard = ExitRouteGuard {
            pin,
            tun_name: tun_name.to_string(),
            ops,
        };
        for change in guard.changes(true) {
            guard.ops.apply(&change)?;
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
        if self.pin.server() != server {
            let _ = self.ops.apply(&self.pin.change(false));
            self.pin = self.pin.with_server(server);
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
            ServerPin::ViaGateway {
                server: SERVER,
                gateway: Ipv4Addr::new(192, 168, 80, 1),
                iface: "eth0".into(),
            }
        );
    }

    #[test]
    fn gatewayless_default_pins_on_link() {
        assert_eq!(
            plan_server_pin(PPP_ROUTE, "zn0", SERVER).unwrap(),
            ServerPin::OnLink {
                server: SERVER,
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
        let new_pin = pin.with_server(moved);
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
