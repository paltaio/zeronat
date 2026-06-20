//! Host-bridge setup for L2 (TAP) server mode. zeronat enslaves its TAP to a
//! Linux bridge; for PPPoE and other raw-Ethernet relaying that bridge must also
//! carry a physical NIC so a remote client's frames reach the segment. The common
//! case is a server with a single uplink NIC, so the bridge has to take over that
//! NIC's addressing without stranding the box.
//!
//! Mechanism: bring the bridge up live with `ip` (immediate and reliable, unlike
//! `netplan apply` on an addressed uplink), persist it through the host's network
//! manager so it survives reboot, and guard the whole thing with a systemd timer
//! that restores the captured state unless the operator confirms in time. systemd
//! owns the timer, so a dropped SSH session, the installer dying, or a wedged
//! reload cannot prevent the revert.

use std::process::Command;

pub const APPLY_PATH: &str = "/etc/zeronat/bridge-apply.sh";
pub const UNDO_PATH: &str = "/etc/zeronat/bridge-undo.sh";
pub const UNDO_UNIT: &str = "zeronat-bridge-undo";

/// One physical interface and the state the bridge must reproduce.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Nic {
    pub name: String,
    pub mtu: u32,
    /// The NIC's hardware MAC. The bridge is pinned to it so a reboot does not
    /// hand the bridge a different (policy-derived) MAC, which would break
    /// MAC-locked uplinks and DHCP reservations.
    pub mac: String,
    /// IPv4 addresses in `addr/prefix` form, scope global.
    pub addrs4: Vec<String>,
    /// IPv6 addresses in `addr/prefix` form, scope global (no link-local).
    pub addrs6: Vec<String>,
    /// The IPv4 address came from DHCP (`ip addr` "dynamic" flag).
    pub dynamic4: bool,
    /// An IPv6 address came from RA/DHCPv6.
    pub dynamic6: bool,
    pub gw4: Option<String>,
    pub gw6: Option<String>,
    pub enslaved: bool,
    /// Carries the SSH session the installer is running over.
    pub is_ssh: bool,
    pub wifi: bool,
}

impl Nic {
    pub fn has_ip(&self) -> bool {
        !self.addrs4.is_empty() || !self.addrs6.is_empty()
    }
    /// Bridging this NIC risks the operator's connectivity (it holds the SSH
    /// session or any address), so the apply must run under the revert watchdog.
    pub fn risky(&self) -> bool {
        self.is_ssh || self.has_ip()
    }
    fn addrs(&self) -> Vec<&String> {
        self.addrs4.iter().chain(self.addrs6.iter()).collect()
    }
    /// True when the IPv4 gateway sits outside every configured subnet (common on
    /// /32 VPS layouts), so routes need `onlink`.
    fn onlink4(&self) -> bool {
        match self.gw4.as_deref() {
            Some(gw) => gw_off_subnet4(&self.addrs4, gw),
            None => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mgr {
    Netplan,
    Networkd,
    /// Detected but not auto-configured; the label names what was found.
    Unsupported(&'static str),
}

// ---- NIC discovery -------------------------------------------------------

fn run_ip(args: &[&str]) -> String {
    Command::new("ip")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// The server IP of the current SSH session. `SSH_CONNECTION` is
/// "clientip clientport serverip serverport".
fn ssh_server_ip() -> Option<String> {
    std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|c| c.split_whitespace().nth(2).map(String::from))
}

/// Probe the host and return its bridgeable physical NICs.
pub fn list_nics() -> Vec<Nic> {
    let mut nics = parse_nics(
        &run_ip(&["-o", "link", "show"]),
        &run_ip(&["-o", "-4", "addr", "show"]),
        &run_ip(&["-o", "-6", "addr", "show"]),
        &run_ip(&["route", "show", "default"]),
        ssh_server_ip().as_deref(),
    );
    nics.retain(|n| std::path::Path::new(&format!("/sys/class/net/{}/device", n.name)).exists());
    for n in &mut nics {
        n.wifi = std::path::Path::new(&format!("/sys/class/net/{}/wireless", n.name)).exists();
    }
    nics
}

/// Pure parser for the `ip` text outputs, so discovery is unit-testable.
pub fn parse_nics(
    link_out: &str,
    a4: &str,
    a6: &str,
    route_out: &str,
    ssh_ip: Option<&str>,
) -> Vec<Nic> {
    let mut nics: Vec<Nic> = Vec::new();
    for line in link_out.lines() {
        let rest = match line.split_once(": ") {
            Some((_, r)) => r,
            None => continue,
        };
        let name = match rest.split_once(':') {
            Some((n, _)) => n.split('@').next().unwrap_or(n).trim().to_string(),
            None => continue,
        };
        if name == "lo" || name.is_empty() {
            continue;
        }
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let mtu = field_after(&toks, "mtu").and_then(|v| v.parse().ok()).unwrap_or(1500);
        let enslaved = toks.contains(&"master");
        let mac = field_after(&toks, "link/ether").unwrap_or_default().to_string();
        nics.push(Nic { name, mtu, mac, enslaved, ..Default::default() });
    }

    for (out, v6) in [(a4, false), (a6, true)] {
        for line in out.lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            let dev = match toks.get(1) {
                Some(d) => *d,
                None => continue,
            };
            let kw = if v6 { "inet6" } else { "inet" };
            let cidr = match field_after(&toks, kw) {
                Some(c) => c,
                None => continue,
            };
            if field_after(&toks, "scope").map(|s| s != "global").unwrap_or(true) {
                continue;
            }
            let dynamic = toks.contains(&"dynamic");
            if let Some(nic) = nics.iter_mut().find(|n| n.name == dev) {
                if v6 {
                    nic.addrs6.push(cidr.to_string());
                    nic.dynamic6 |= dynamic;
                } else {
                    nic.addrs4.push(cidr.to_string());
                    nic.dynamic4 |= dynamic;
                }
                if ssh_ip.is_some() && cidr.split('/').next() == ssh_ip {
                    nic.is_ssh = true;
                }
            }
        }
    }

    for line in route_out.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.first() != Some(&"default") {
            continue;
        }
        if let (Some(via), Some(dev)) = (field_after(&toks, "via"), field_after(&toks, "dev")) {
            if let Some(nic) = nics.iter_mut().find(|n| n.name == dev) {
                if via.contains(':') {
                    nic.gw6.get_or_insert_with(|| via.to_string());
                } else {
                    nic.gw4.get_or_insert_with(|| via.to_string());
                }
            }
        }
    }
    nics
}

fn field_after<'a>(toks: &[&'a str], key: &str) -> Option<&'a str> {
    toks.iter().position(|t| *t == key).and_then(|i| toks.get(i + 1)).copied()
}

fn ipv4_u32(s: &str) -> Option<u32> {
    let o: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if o.len() == 4 {
        Some(u32::from_be_bytes([o[0], o[1], o[2], o[3]]))
    } else {
        None
    }
}

/// True when `gw` is in none of the `addr/prefix` subnets.
fn gw_off_subnet4(addrs4: &[String], gw: &str) -> bool {
    let g = match ipv4_u32(gw) {
        Some(g) => g,
        None => return false,
    };
    for a in addrs4 {
        if let Some((ip, pfx)) = a.split_once('/') {
            if let (Some(ipu), Ok(p)) = (ipv4_u32(ip), pfx.parse::<u32>()) {
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p.min(32)) };
                if (ipu & mask) == (g & mask) {
                    return false;
                }
            }
        }
    }
    true
}

// ---- manager detection ---------------------------------------------------

fn cmd_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program).args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

pub fn detect_manager() -> Mgr {
    let has_netplan_cfg = std::fs::read_dir("/etc/netplan")
        .map(|d| d.flatten().any(|e| e.path().extension().is_some_and(|x| x == "yaml" || x == "yml")))
        .unwrap_or(false);
    if has_netplan_cfg && crate::sys::have("netplan") {
        return Mgr::Netplan;
    }
    if cmd_ok("systemctl", &["is-active", "--quiet", "systemd-networkd"]) {
        return Mgr::Networkd;
    }
    if cmd_ok("systemctl", &["is-active", "--quiet", "NetworkManager"]) {
        return Mgr::Unsupported("NetworkManager");
    }
    if std::path::Path::new("/etc/network/interfaces").exists() {
        return Mgr::Unsupported("ifupdown (/etc/network/interfaces)");
    }
    Mgr::Unsupported("unknown network manager")
}

/// systemd owns the revert timer, so it must be present for the risky path.
pub fn have_systemd_run() -> bool {
    crate::sys::have("systemd-run")
}

// ---- DNS source ----------------------------------------------------------

/// Upstream nameservers, preferring the real resolver list over the local stub.
/// On systemd-resolved hosts `/etc/resolv.conf` is just `127.0.0.53`, which is
/// useless once the original DHCP/static DNS is gone, so read the resolver's own
/// file first and drop loopback entries.
pub fn nameservers() -> Vec<String> {
    for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        let ns: Vec<String> = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().strip_prefix("nameserver ").map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty() && !s.starts_with("127."))
            .collect();
        if !ns.is_empty() {
            return ns;
        }
    }
    Vec::new()
}

// ---- persistent config generation ----------------------------------------

fn yesno(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Generate the bridge definition that moves the NIC's addressing onto the
/// bridge. On the uplink path the apply script makes this the sole netplan file
/// (renames the others aside); on the spare-NIC path it is an overlay. Either way
/// it cannot rely on netplan's per-key cross-file merge to delete a lower file's
/// addresses, which is why the uplink path renames them.
pub fn gen_netplan(bridge: &str, nic: &Nic, dns: &[String]) -> String {
    let mut s = String::from("network:\n  version: 2\n  renderer: networkd\n");
    s.push_str("  ethernets:\n");
    s.push_str(&format!("    {}:\n      dhcp4: no\n      dhcp6: no\n      accept-ra: no\n", nic.name));
    s.push_str("  bridges:\n");
    s.push_str(&format!("    {bridge}:\n"));
    s.push_str(&format!("      interfaces: [{}]\n", nic.name));
    if !nic.mac.is_empty() {
        s.push_str(&format!("      macaddress: {}\n", nic.mac));
    }
    s.push_str(&format!("      mtu: {}\n", nic.mtu));
    s.push_str(&format!("      dhcp4: {}\n", yesno(nic.dynamic4)));
    s.push_str(&format!("      accept-ra: {}\n", yesno(nic.dynamic6)));
    let statics: Vec<&String> = nic
        .addrs4
        .iter()
        .filter(|_| !nic.dynamic4)
        .chain(nic.addrs6.iter().filter(|_| !nic.dynamic6))
        .collect();
    if !statics.is_empty() {
        s.push_str("      addresses:\n");
        for a in &statics {
            s.push_str(&format!("        - {a}\n"));
        }
    }
    let onlink = nic.onlink4();
    let mut routes: Vec<(String, bool)> = Vec::new();
    if !nic.dynamic4 {
        if let Some(gw) = &nic.gw4 {
            routes.push((gw.clone(), onlink));
        }
    }
    if !nic.dynamic6 {
        if let Some(gw) = &nic.gw6 {
            routes.push((gw.clone(), false));
        }
    }
    if !routes.is_empty() {
        s.push_str("      routes:\n");
        for (gw, ol) in routes {
            s.push_str(&format!("        - to: default\n          via: {gw}\n"));
            if ol {
                s.push_str("          on-link: true\n");
            }
        }
    }
    if !dns.is_empty() && (!nic.dynamic4 || !statics.is_empty()) {
        s.push_str(&format!("      nameservers:\n        addresses: [{}]\n", dns.join(", ")));
    }
    s.push_str("      parameters:\n        stp: false\n        forward-delay: 0\n");
    s
}

/// The three networkd files zeronat writes: the bridge .netdev, the bridge
/// .network, and the per-port .network. Single source so apply and undo agree.
fn networkd_paths(nic: &Nic) -> [String; 3] {
    [
        "/etc/systemd/network/00-zeronat-br.netdev".to_string(),
        "/etc/systemd/network/00-zeronat-br.network".to_string(),
        format!("/etc/systemd/network/00-zeronat-port-{}.network", nic.name),
    ]
}

/// systemd-networkd: a .netdev for the bridge plus .network units for the bridge
/// and the port. networkd matches the first `.network` by name and does not merge
/// across files, so the `00-` port unit cleanly shadows the distro's unit.
pub fn gen_networkd(bridge: &str, nic: &Nic, dns: &[String]) -> Vec<(String, String)> {
    let mac = if nic.mac.is_empty() {
        String::new()
    } else {
        format!("MACAddress={}\n", nic.mac)
    };
    let netdev = format!(
        "[NetDev]\nName={bridge}\nKind=bridge\n{mac}MTUBytes={}\n\n[Bridge]\nSTP=no\nForwardDelaySec=0\n",
        nic.mtu
    );
    let mut br_net = format!("[Match]\nName={bridge}\n\n[Network]\n");
    if nic.dynamic4 {
        br_net.push_str("DHCP=ipv4\n");
    }
    br_net.push_str(&format!("IPv6AcceptRA={}\n", yesno(nic.dynamic6)));
    for a in nic.addrs4.iter().filter(|_| !nic.dynamic4) {
        br_net.push_str(&format!("Address={a}\n"));
    }
    for a in nic.addrs6.iter().filter(|_| !nic.dynamic6) {
        br_net.push_str(&format!("Address={a}\n"));
    }
    for d in dns {
        br_net.push_str(&format!("DNS={d}\n"));
    }
    if let Some(gw) = nic.gw4.as_ref().filter(|_| !nic.dynamic4) {
        br_net.push_str(&format!("\n[Route]\nGateway={gw}\n"));
        if nic.onlink4() {
            br_net.push_str("GatewayOnLink=yes\n");
        }
    }
    if let Some(gw) = nic.gw6.as_ref().filter(|_| !nic.dynamic6) {
        br_net.push_str(&format!("\n[Route]\nGateway={gw}\n"));
    }
    br_net.push_str(&format!("\n[Link]\nMTUBytes={}\n", nic.mtu));
    let port = format!("[Match]\nName={}\n\n[Network]\nBridge={bridge}\n", nic.name);
    let paths = networkd_paths(nic);
    vec![
        (paths[0].clone(), netdev),
        (paths[1].clone(), br_net),
        (paths[2].clone(), port),
    ]
}

pub fn manual_snippet(bridge: &str, nic: &Nic) -> String {
    format!(
        "auto-bridging is not supported for this host's network manager.\n\
         create the bridge, move {nic}'s addressing onto it, set its MTU to {mtu}, \
         and re-run with --bridge {bridge}:\n  \
         ip link add {bridge} type bridge\n  ip link set {bridge} up\n  \
         ip link set {nic} master {bridge}",
        nic = nic.name,
        mtu = nic.mtu
    )
}

// ---- apply / undo scripts ------------------------------------------------

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Shell lines that bring the bridge up live via `ip`, immediately. Used because
/// `netplan apply`/`networkctl` will not reliably move an addressed, live uplink
/// into a new bridge.
fn live_apply(bridge: &str, nic: &Nic) -> String {
    let mut s = String::new();
    s.push_str(&format!("ip link add name {0} type bridge 2>/dev/null || true\n", shq(bridge)));
    // Pin the bridge MAC to the NIC's so a reboot (where networkd would otherwise
    // assign a policy-derived MAC) keeps the same MAC the segment already knows.
    if !nic.mac.is_empty() {
        s.push_str(&format!("ip link set {} address {}\n", shq(bridge), shq(&nic.mac)));
    }
    s.push_str(&format!("ip link set {} mtu {}\n", shq(bridge), nic.mtu));
    s.push_str(&format!("ip link set {} up\n", shq(bridge)));
    s.push_str(&format!("ip addr flush dev {}\n", shq(&nic.name)));
    s.push_str(&format!("ip link set {} master {}\n", shq(&nic.name), shq(bridge)));
    s.push_str(&format!("ip link set {} up\n", shq(&nic.name)));
    for a in nic.addrs() {
        // `replace` (not `add`) so a re-run over an existing address is idempotent
        // and does not abort the script under `set -e`.
        s.push_str(&format!("ip addr replace {} dev {}\n", shq(a), shq(bridge)));
    }
    if let Some(gw) = &nic.gw4 {
        let ol = if nic.onlink4() { " onlink" } else { "" };
        s.push_str(&format!("ip route replace default via {} dev {}{ol}\n", shq(gw), shq(bridge)));
    }
    if let Some(gw) = &nic.gw6 {
        s.push_str(&format!("ip -6 route replace default via {} dev {}\n", shq(gw), shq(bridge)));
    }
    s
}

/// Shell lines that restore the captured `ip` state back onto the NIC.
fn live_undo(bridge: &str, nic: &Nic) -> String {
    let mut s = String::new();
    s.push_str(&format!("ip link set {} nomaster 2>/dev/null || true\n", shq(&nic.name)));
    s.push_str(&format!("ip link del {} 2>/dev/null || true\n", shq(bridge)));
    s.push_str(&format!("ip addr flush dev {} 2>/dev/null || true\n", shq(&nic.name)));
    s.push_str(&format!("ip link set {} up\n", shq(&nic.name)));
    for a in nic.addrs() {
        s.push_str(&format!("ip addr add {} dev {} 2>/dev/null || true\n", shq(a), shq(&nic.name)));
    }
    if let Some(gw) = &nic.gw4 {
        let ol = if nic.onlink4() { " onlink" } else { "" };
        s.push_str(&format!(
            "ip route replace default via {} dev {}{ol} 2>/dev/null || true\n",
            shq(gw),
            shq(&nic.name)
        ));
    }
    if let Some(gw) = &nic.gw6 {
        s.push_str(&format!(
            "ip -6 route replace default via {} dev {} 2>/dev/null || true\n",
            shq(gw),
            shq(&nic.name)
        ));
    }
    if nic.dynamic4 {
        // The captured lease address is re-added above for immediate reachability;
        // also kick a DHCP client so the lease is renewed properly.
        s.push_str(&format!(
            "{{ command -v dhclient >/dev/null 2>&1 && dhclient -nw {0}; }} || \
             {{ command -v udhcpc >/dev/null 2>&1 && udhcpc -b -i {0}; }} || true\n",
            shq(&nic.name)
        ));
    }
    s
}

fn heredoc(path: &str, content: &str) -> String {
    format!("cat > {} <<'ZNEOF'\n{content}\nZNEOF\n", shq(path))
}

/// The persist half of the apply script: write the manager config so the bridge
/// survives reboot. `authoritative` (the risky uplink path) takes over netplan by
/// renaming existing files aside, because moving the NIC's own addressing cannot
/// be expressed as a merge overlay. The dedicated-NIC path leaves other files
/// untouched and just adds an overlay, so a multi-NIC host keeps its config.
fn persist(bridge: &str, nic: &Nic, mgr: Mgr, dns: &[String], authoritative: bool) -> String {
    match mgr {
        Mgr::Netplan => {
            let mut s = String::new();
            if authoritative {
                // Stop cloud-init from regenerating the NIC's netplan on boot.
                s.push_str(
                    "if [ -d /etc/cloud ]; then mkdir -p /etc/cloud/cloud.cfg.d; \
                     printf 'network: {config: disabled}\\n' \
                     > /etc/cloud/cloud.cfg.d/99-zeronat-disable-net.cfg; fi\n",
                );
                // Move existing netplan aside so our file is the sole authority.
                s.push_str(
                    "for f in /etc/netplan/*.yaml /etc/netplan/*.yml; do \
                     [ -e \"$f\" ] && mv -f \"$f\" \"$f.zn-bak\"; done\n",
                );
            }
            s.push_str(&heredoc("/etc/netplan/90-zeronat.yaml", &gen_netplan(bridge, nic, dns)));
            s.push_str("chmod 600 /etc/netplan/90-zeronat.yaml\n");
            s.push_str("netplan generate\n");
            s
        }
        Mgr::Networkd => {
            let mut s = String::new();
            for (path, content) in gen_networkd(bridge, nic, dns) {
                s.push_str(&heredoc(&path, &content));
            }
            s.push_str("networkctl reload 2>/dev/null || systemctl restart systemd-networkd\n");
            s
        }
        Mgr::Unsupported(_) => String::new(),
    }
}

/// The undo half: reverse the persist step.
fn unpersist(nic: &Nic, mgr: Mgr) -> String {
    match mgr {
        Mgr::Netplan => "rm -f /etc/netplan/90-zeronat.yaml \
             /etc/cloud/cloud.cfg.d/99-zeronat-disable-net.cfg\n\
             for f in /etc/netplan/*.yaml.zn-bak /etc/netplan/*.yml.zn-bak; do \
             [ -e \"$f\" ] && mv -f \"$f\" \"${f%.zn-bak}\"; done\n\
             netplan generate 2>/dev/null || true\n"
            .to_string(),
        Mgr::Networkd => {
            let files = networkd_paths(nic).iter().map(|p| shq(p)).collect::<Vec<_>>().join(" ");
            format!(
                "rm -f {files}\nnetworkctl reload 2>/dev/null || systemctl restart systemd-networkd\n"
            )
        }
        Mgr::Unsupported(_) => String::new(),
    }
}

/// Full apply script: optionally arm the systemd revert timer first (so an
/// interrupted apply still reverts), then live bring-up (fast reachability on the
/// bridge), then persist. `set -e` aborts on any real failure so the caller can
/// trigger the undo; idempotent steps carry their own `|| true`.
///
/// `arm_revert_secs` is `Some(n)` on the risky uplink path: the timer is armed
/// before any surgery, so its clock starts at surgery time and a death between
/// here and the operator's confirmation is still covered.
pub fn apply_script(bridge: &str, nic: &Nic, mgr: Mgr, dns: &[String], arm_revert_secs: Option<u32>) -> String {
    let mut s = String::from("#!/bin/sh\nset -e\n");
    if let Some(n) = arm_revert_secs {
        s.push_str(&format!(
            "systemctl stop {U}.timer {U}.service 2>/dev/null || true\n\
             systemctl reset-failed {U}.timer {U}.service 2>/dev/null || true\n\
             systemd-run --on-active={n}s --unit={U} --collect /bin/sh {undo}\n",
            U = UNDO_UNIT,
            undo = UNDO_PATH,
        ));
    }
    s.push_str(&live_apply(bridge, nic));
    s.push_str(&persist(bridge, nic, mgr, dns, arm_revert_secs.is_some()));
    s
}

/// Full undo script: restore live networking first (regain access fast), then
/// reverse persistence. Every step is best-effort so a partial earlier apply
/// still gets unwound.
pub fn undo_script(bridge: &str, nic: &Nic, mgr: Mgr) -> String {
    format!("#!/bin/sh\n{}{}", live_undo(bridge, nic), unpersist(nic, mgr))
}

// ---- connectivity probe (headless confirm) -------------------------------

/// Headless keep/revert decision. With no operator to press a key, keep the
/// bridge only if the box is provably still reachable through it; default to
/// revert when that cannot be verified, since this is a strand-prevention gate.
///
/// In headless mode the only keep signal is an ICMP echo reply from the default
/// gateway or the SSH peer. A host that drops ICMP to both will always revert
/// (fails safe). Interactive installs are unaffected: an operator confirms by
/// keypress and never reaches this probe.
pub fn probe_connectivity(secs: u32) -> bool {
    if !crate::sys::have("ping") {
        return false;
    }
    let mut targets: Vec<String> = Vec::new();
    for line in run_ip(&["route", "show", "default"]).lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(via) = field_after(&toks, "via") {
            targets.push(via.to_string());
        }
    }
    if let Ok(c) = std::env::var("SSH_CONNECTION") {
        if let Some(peer) = c.split_whitespace().next() {
            targets.push(peer.to_string());
        }
    }
    if targets.is_empty() {
        return false;
    }
    for _ in 0..secs.max(1) {
        for t in &targets {
            if cmd_ok("ping", &["-c", "1", "-W", "1", t]) {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(800));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nic(name: &str) -> Nic {
        Nic { name: name.into(), mtu: 1500, mac: "aa:bb:cc:dd:ee:ff".into(), ..Default::default() }
    }

    #[test]
    fn parses_links_addrs_routes_and_ssh() {
        let link = "1: lo: <LOOPBACK> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\n\
                    2: eth0: <BROADCAST,UP> mtu 1500 qdisc fq state UP mode DEFAULT\\    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n\
                    3: eth1: <BROADCAST> mtu 1500 qdisc noop master br0 state DOWN mode DEFAULT";
        let a4 = "2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global dynamic eth0\n\
                  3: eth1    inet 10.0.0.2/24 scope global eth1";
        let a6 = "2: eth0    inet6 fe80::1/64 scope link\n\
                  2: eth0    inet6 2001:db8::5/64 scope global dynamic";
        let route = "default via 192.0.2.1 dev eth0 proto dhcp";
        let nics = parse_nics(link, a4, a6, route, Some("192.0.2.10"));
        let eth0 = nics.iter().find(|n| n.name == "eth0").unwrap();
        assert_eq!(eth0.addrs4, vec!["192.0.2.10/24"]);
        assert_eq!(eth0.addrs6, vec!["2001:db8::5/64"]);
        assert!(eth0.dynamic4 && eth0.dynamic6 && eth0.is_ssh);
        assert_eq!(eth0.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(eth0.gw4.as_deref(), Some("192.0.2.1"));
        let eth1 = nics.iter().find(|n| n.name == "eth1").unwrap();
        assert!(eth1.enslaved && !eth1.is_ssh);
        assert!(!nics.iter().any(|n| n.name == "lo"));
    }

    #[test]
    fn onlink_when_gateway_off_subnet() {
        // /32 host with an off-subnet gateway (Hetzner-style) needs onlink.
        let mut n = nic("eth0");
        n.addrs4.push("203.0.113.7/32".into());
        n.gw4 = Some("203.0.113.1".into());
        assert!(n.onlink4());
        // In-subnet gateway does not.
        let mut m = nic("eth0");
        m.addrs4.push("192.0.2.10/24".into());
        m.gw4 = Some("192.0.2.1".into());
        assert!(!m.onlink4());
    }

    #[test]
    fn netplan_static_carries_addr_route_dns_mtu_and_onlink() {
        let mut n = nic("eth0");
        n.addrs4.push("203.0.113.7/32".into());
        n.gw4 = Some("203.0.113.1".into());
        let y = gen_netplan("br-zeronat", &n, &["1.1.1.1".into()]);
        assert!(y.contains("dhcp4: no"), "{y}");
        assert!(y.contains("- 203.0.113.7/32"), "{y}");
        assert!(y.contains("via: 203.0.113.1"), "{y}");
        assert!(y.contains("on-link: true"), "{y}");
        assert!(y.contains("addresses: [1.1.1.1]"), "{y}");
        assert!(y.contains("mtu: 1500") && y.contains("interfaces: [eth0]"), "{y}");
        assert!(y.contains("macaddress: aa:bb:cc:dd:ee:ff"), "{y}");
    }

    #[test]
    fn netplan_dhcp_omits_static_addr_and_dns() {
        let mut n = nic("eth0");
        n.dynamic4 = true;
        n.addrs4.push("192.0.2.10/24".into());
        let y = gen_netplan("br-zeronat", &n, &["1.1.1.1".into()]);
        assert!(y.contains("dhcp4: yes"), "{y}");
        assert!(!y.contains("addresses:"), "{y}");
        assert!(!y.contains("nameservers:"), "{y}");
    }

    #[test]
    fn networkd_three_files_with_onlink_and_port() {
        let mut n = nic("eth0");
        n.addrs4.push("203.0.113.7/32".into());
        n.gw4 = Some("203.0.113.1".into());
        let files = gen_networkd("br-zeronat", &n, &["1.1.1.1".into()]);
        assert_eq!(files.len(), 3);
        assert!(files.iter().any(|(p, c)| p.ends_with(".netdev") && c.contains("Kind=bridge") && c.contains("MACAddress=aa:bb:cc:dd:ee:ff")));
        assert!(files.iter().any(|(_, c)| c.contains("Gateway=203.0.113.1") && c.contains("GatewayOnLink=yes")));
        assert!(files.iter().any(|(p, c)| p.contains("port-eth0") && c.contains("Bridge=br-zeronat")));
    }

    #[test]
    fn apply_script_arms_revert_then_brings_up_live_then_persists() {
        let mut n = nic("eth0");
        n.addrs4.push("192.0.2.10/24".into());
        n.gw4 = Some("192.0.2.1".into());
        let s = apply_script("br-zeronat", &n, Mgr::Netplan, &["1.1.1.1".into()], Some(45));
        assert!(s.starts_with("#!/bin/sh\nset -e\n"), "{s}");
        // revert armed before any surgery
        let arm = s.find("systemd-run --on-active=45s").unwrap();
        let flush = s.find("ip addr flush dev 'eth0'").unwrap();
        let enslave = s.find("ip link set 'eth0' master 'br-zeronat'").unwrap();
        let persist = s.find("/etc/netplan/90-zeronat.yaml").unwrap();
        assert!(arm < flush && flush < enslave && enslave < persist, "ordering wrong:\n{s}");
        assert!(s.contains("ip link set 'br-zeronat' address 'aa:bb:cc:dd:ee:ff'"), "{s}");
        assert!(s.contains("ip addr replace '192.0.2.10/24' dev 'br-zeronat'"), "{s}");
        assert!(s.contains("disable-net.cfg") && s.contains("mv -f \"$f\" \"$f.zn-bak\""), "{s}");
    }

    #[test]
    fn dedicated_apply_does_not_arm_revert() {
        let s = apply_script("br-zeronat", &nic("eth1"), Mgr::Networkd, &[], None);
        assert!(!s.contains("systemd-run"), "{s}");
        assert!(s.contains("ip link set 'eth1' master 'br-zeronat'"), "{s}");
    }

    #[test]
    fn undo_script_restores_nic_then_reverses_persist() {
        let mut n = nic("eth0");
        n.addrs4.push("192.0.2.10/24".into());
        n.gw4 = Some("192.0.2.1".into());
        let s = undo_script("br-zeronat", &n, Mgr::Netplan);
        let nomaster = s.find("ip link set 'eth0' nomaster").unwrap();
        let readd = s.find("ip addr add '192.0.2.10/24' dev 'eth0'").unwrap();
        let restore = s.find("mv -f \"$f\" \"${f%.zn-bak}\"").unwrap();
        assert!(nomaster < readd && readd < restore, "ordering wrong:\n{s}");
        assert!(s.contains("ip link del 'br-zeronat'"), "{s}");
    }

    #[test]
    fn undo_networkd_removes_our_files() {
        let s = undo_script("br-zeronat", &nic("eth0"), Mgr::Networkd);
        assert!(s.contains("00-zeronat-br.netdev") && s.contains("00-zeronat-port-eth0.network"), "{s}");
        assert!(s.contains("networkctl reload"), "{s}");
    }
}
