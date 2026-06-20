//! Server-side NAT for TUN all-ports mode. Redirects every inbound port (except
//! the control port and any operator exclusions) plus ICMP to the single tunnel
//! client, and source-NATs the forwarded traffic to the server's tunnel address
//! so the client's replies route back through the tunnel. Programs nftables when
//! available, else legacy iptables, else degrades to printing the rules for the
//! operator to apply by hand. All rules live in an owned `zeronat` table (nft) or
//! carry a `zeronat` comment (iptables) so teardown never touches operator rules.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::Result;

/// The NAT to install for a TUN server.
pub struct NatPlan {
    pub iface: String,
    /// Tunnel network base, e.g. `10.x.y.0`.
    pub subnet: Ipv4Addr,
    pub prefix_len: u8,
    /// Server tunnel address (`.1`), used as the SNAT source.
    pub server_ip: Ipv4Addr,
    /// Client tunnel address (`.2`), the DNAT target for every forwarded port.
    pub client_ip: Ipv4Addr,
    pub control_port: u16,
    /// Tunnel interface MTU, used to clamp forwarded TCP MSS.
    pub mtu: usize,
    /// Extra TCP/UDP destination ports kept on the host (not forwarded).
    pub except: Vec<u16>,
}

impl NatPlan {
    /// Destination ports that stay on the host: the control port plus any
    /// operator exclusions, de-duplicated and sorted for stable output.
    fn kept_ports(&self) -> Vec<u16> {
        let mut p: Vec<u16> = std::iter::once(self.control_port)
            .chain(self.except.iter().copied())
            .collect();
        p.sort_unstable();
        p.dedup();
        p
    }

    fn cidr(&self) -> String {
        format!("{}/{}", self.subnet, self.prefix_len)
    }

    /// Fixed TCP MSS for forwarded SYNs: MTU minus the IPv4 + TCP headers. Fixed
    /// (not clamp-to-PMTU) because the constraining link is the tunnel, which is
    /// not the egress route for the internet-bound direction, so a route-MTU
    /// clamp would under-clamp that side and black-hole large segments.
    fn mss(&self) -> u16 {
        self.mtu.saturating_sub(40).clamp(536, u16::MAX as usize) as u16
    }
}

/// The nftables ruleset for `plan`, as a script fed to `nft -f -`.
fn nft_script(plan: &NatPlan) -> String {
    let iface = &plan.iface;
    let cidr = plan.cidr();
    let client = plan.client_ip;
    let server = plan.server_ip;
    let mss = plan.mss();
    let keep = plan
        .kept_ports()
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "add table ip zeronat\n\
         add chain ip zeronat prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}\n\
         add chain ip zeronat postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n\
         add chain ip zeronat forward {{ type filter hook forward priority mangle; policy accept; }}\n\
         add rule ip zeronat prerouting iifname != \"{iface}\" ip daddr != {cidr} tcp dport != {{ {keep} }} dnat to {client}\n\
         add rule ip zeronat prerouting iifname != \"{iface}\" ip daddr != {cidr} udp dport != {{ {keep} }} dnat to {client}\n\
         add rule ip zeronat prerouting iifname != \"{iface}\" ip daddr != {cidr} ip protocol icmp dnat to {client}\n\
         add rule ip zeronat postrouting oifname \"{iface}\" snat to {server}\n\
         add rule ip zeronat forward oifname \"{iface}\" tcp flags & (syn | rst) == syn tcp option maxseg size set {mss}\n\
         add rule ip zeronat forward iifname \"{iface}\" tcp flags & (syn | rst) == syn tcp option maxseg size set {mss}\n\
         add rule ip zeronat forward oifname \"{iface}\" accept\n\
         add rule ip zeronat forward iifname \"{iface}\" accept\n"
    )
}

/// One iptables rule in the named table/chain; `command` builds its `-A`
/// invocation. Teardown deletes by `zeronat` comment, not by this spec.
struct IptRule {
    table: &'static str,
    chain: &'static str,
    args: Vec<String>,
}

impl IptRule {
    fn command(&self) -> Vec<String> {
        let mut c = vec!["-t".into(), self.table.into(), "-A".into(), self.chain.into()];
        c.extend(self.args.iter().cloned());
        c
    }
}

/// The iptables ruleset for `plan`. Mirrors `nft_script`: DNAT every forwarded
/// port plus ICMP to the client, SNAT egress out the tunnel to the server.
fn iptables_rules(plan: &NatPlan) -> Vec<IptRule> {
    let iface = plan.iface.clone();
    let cidr = plan.cidr();
    let client = plan.client_ip.to_string();
    let server = plan.server_ip.to_string();
    let keep = plan.kept_ports();
    let comment = || vec!["-m".into(), "comment".into(), "--comment".into(), "zeronat".into()];

    // Negated destination-port match: one port uses `! --dport`, several use the
    // multiport module (`! --dports a,b,c`).
    let dport_neg = |proto: &str| -> Vec<String> {
        let mut v = vec!["-p".into(), proto.into()];
        if keep.len() == 1 {
            v.extend(["!".into(), "--dport".into(), keep[0].to_string()]);
        } else {
            let list = keep
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            v.extend([
                "-m".into(),
                "multiport".into(),
                "!".into(),
                "--dports".into(),
                list,
            ]);
        }
        v
    };

    let mut rules = Vec::new();
    for proto in ["tcp", "udp"] {
        let mut args = vec![
            "!".into(),
            "-i".into(),
            iface.clone(),
            "!".into(),
            "-d".into(),
            cidr.clone(),
        ];
        args.extend(dport_neg(proto));
        args.extend([
            "-j".into(),
            "DNAT".into(),
            "--to-destination".into(),
            client.clone(),
        ]);
        args.extend(comment());
        rules.push(IptRule {
            table: "nat",
            chain: "PREROUTING",
            args,
        });
    }
    {
        let mut args = vec![
            "!".into(),
            "-i".into(),
            iface.clone(),
            "!".into(),
            "-d".into(),
            cidr.clone(),
            "-p".into(),
            "icmp".into(),
            "-j".into(),
            "DNAT".into(),
            "--to-destination".into(),
            client.clone(),
        ];
        args.extend(comment());
        rules.push(IptRule {
            table: "nat",
            chain: "PREROUTING",
            args,
        });
    }
    {
        let mut args = vec![
            "-o".into(),
            iface.clone(),
            "-j".into(),
            "SNAT".into(),
            "--to-source".into(),
            server,
        ];
        args.extend(comment());
        rules.push(IptRule {
            table: "nat",
            chain: "POSTROUTING",
            args,
        });
    }
    // Clamp forwarded TCP MSS in both tunnel directions so large segments fit the
    // tunnel MTU. Scoped to the tunnel interface so unrelated forwarding (e.g. a
    // container bridge) is untouched.
    let mss = plan.mss().to_string();
    for dir in ["-o", "-i"] {
        let mut args = vec![
            dir.into(),
            iface.clone(),
            "-p".into(),
            "tcp".into(),
            "--tcp-flags".into(),
            "SYN,RST".into(),
            "SYN".into(),
            "-j".into(),
            "TCPMSS".into(),
            "--set-mss".into(),
            mss.clone(),
        ];
        args.extend(comment());
        rules.push(IptRule {
            table: "mangle",
            chain: "FORWARD",
            args,
        });
    }
    // Accept forwarding to/from the tunnel so a host whose filter FORWARD policy
    // is DROP (a default-deny host, or Docker, which sets policy DROP) does not
    // black-hole the DNAT'd traffic. Appended, so it is reached before the policy
    // fallthrough. A host that installs its own explicit FORWARD drop ahead of
    // this still needs operator integration (see manual_instructions).
    for dir in ["-o", "-i"] {
        let mut args = vec![dir.into(), iface.clone(), "-j".into(), "ACCEPT".into()];
        args.extend(comment());
        rules.push(IptRule {
            table: "filter",
            chain: "FORWARD",
            args,
        });
    }
    rules
}

#[derive(Clone, Copy)]
enum Backend {
    Nft,
    Iptables,
}

/// The iptables tables/chains this module installs into, for comment-based flush.
const IPT_CHAINS: &[(&str, &str)] = &[
    ("nat", "PREROUTING"),
    ("nat", "POSTROUTING"),
    ("mangle", "FORWARD"),
    ("filter", "FORWARD"),
];

/// Holds the installed NAT and removes it on drop: an `nft delete table` (atomic)
/// or a comment-based flush of every `zeronat`-tagged iptables rule. Best-effort;
/// a hard kill skips teardown, but the next start flushes by comment before
/// installing, so stale rules are cleared even if the config changed meanwhile.
pub struct NatGuard {
    backend: Backend,
    /// True when this process flipped ip_forward 0 -> 1 and should restore it.
    restore_ip_forward: bool,
}

impl NatGuard {
    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            Backend::Nft => "nft",
            Backend::Iptables => "iptables",
        }
    }
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        match self.backend {
            Backend::Nft => nft_delete_table(),
            Backend::Iptables => flush_iptables(),
        }
        if self.restore_ip_forward {
            let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"0\n");
        }
    }
}

/// Result of installing NAT: a live guard, or degraded with operator guidance to
/// print (no backend, or a backend error). The tunnel runs either way.
pub enum Outcome {
    Installed(NatGuard),
    Degraded(String),
}

/// Enable, detect, and program NAT for `plan`. Never fails the server: any error
/// folds into `Degraded` with instructions, so the operator can apply the rules
/// while the tunnel is already up.
pub fn install(plan: &NatPlan) -> Outcome {
    let mut warn = String::new();
    let restore_ip_forward = match enable_ip_forward() {
        Ok(changed) => changed,
        Err(e) => {
            warn.push_str(&format!(
                "warning: could not enable ip_forward ({e}); run: sysctl -w net.ipv4.ip_forward=1\n"
            ));
            false
        }
    };

    let have_nft = command_available("nft");
    let have_ipt = command_available("iptables");

    if have_nft {
        match install_nft(plan) {
            Ok(()) => {
                return Outcome::Installed(NatGuard {
                    backend: Backend::Nft,
                    restore_ip_forward,
                })
            }
            Err(e) => warn.push_str(&format!("warning: nft NAT setup failed: {e}\n")),
        }
    }
    if have_ipt {
        let rules = iptables_rules(plan);
        match install_iptables(&rules) {
            Ok(()) => {
                return Outcome::Installed(NatGuard {
                    backend: Backend::Iptables,
                    restore_ip_forward,
                })
            }
            Err(e) => warn.push_str(&format!("warning: iptables NAT setup failed: {e}\n")),
        }
    }
    if !have_nft && !have_ipt {
        warn.push_str("warning: neither nft nor iptables found on PATH\n");
    }
    Outcome::Degraded(format!("{warn}{}", manual_instructions(plan)))
}

/// Operator-facing rules to apply when auto-setup did not run.
fn manual_instructions(plan: &NatPlan) -> String {
    let mut s = String::from(
        "tun all-ports mode is running, but NAT was not programmed automatically.\n\
         apply these on the server to forward every port to the client:\n\n  \
         sysctl -w net.ipv4.ip_forward=1\n",
    );
    for r in iptables_rules(plan) {
        s.push_str("  iptables ");
        s.push_str(&r.command().join(" "));
        s.push('\n');
    }
    s.push_str(
        "\nif the host has a restrictive FORWARD policy (e.g. Docker), also allow \
         forwarding to/from the tunnel interface.\n",
    );
    s
}

/// Enable IPv4 forwarding, returning whether it was previously off so the caller
/// can restore it on teardown.
fn enable_ip_forward() -> Result<bool> {
    let was_on = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n")
        .map_err(|e| -> crate::Error { format!("write ip_forward: {e}").into() })?;
    Ok(!was_on)
}

fn nft_delete_table() {
    run_ignore(
        "nft",
        &[
            "delete".into(),
            "table".into(),
            "ip".into(),
            "zeronat".into(),
        ],
    );
}

/// Delete every `zeronat`-tagged iptables rule across the chains we use, by rule
/// number (high to low so indices stay valid). Robust to a config change or a
/// prior hard kill: it removes stale rules regardless of their current spec.
fn flush_iptables() {
    for (table, chain) in IPT_CHAINS {
        let out = match Command::new("iptables")
            .args(["-t", table, "-S", chain])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };
        let mut nums: Vec<usize> = Vec::new();
        let mut idx = 0usize;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(rest) = line.strip_prefix("-A ") {
                idx += 1;
                if rest.contains("zeronat") {
                    nums.push(idx);
                }
            }
        }
        for n in nums.into_iter().rev() {
            run_ignore(
                "iptables",
                &[
                    "-t".into(),
                    (*table).into(),
                    "-D".into(),
                    (*chain).into(),
                    n.to_string(),
                ],
            );
        }
    }
}

fn install_nft(plan: &NatPlan) -> Result<()> {
    // Drop any stale table first so a re-run never stacks duplicate rules.
    nft_delete_table();
    let script = nft_script(plan);
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| -> crate::Error { format!("spawn nft: {e}").into() })?;
    {
        let mut si = child
            .stdin
            .take()
            .ok_or_else(|| -> crate::Error { "nft stdin unavailable".into() })?;
        si.write_all(script.as_bytes())
            .map_err(|e| -> crate::Error { format!("write nft script: {e}").into() })?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| -> crate::Error { format!("wait nft: {e}").into() })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string().into())
    }
}

fn install_iptables(rules: &[IptRule]) -> Result<()> {
    // Clear any stale zeronat rules (idempotent re-run), then append fresh.
    flush_iptables();
    for r in rules {
        run("iptables", &r.command())?;
    }
    Ok(())
}

fn command_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[String]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| -> crate::Error { format!("spawn {cmd}: {e}").into() })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into())
    }
}

fn run_ignore(cmd: &str, args: &[String]) {
    let _ = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> NatPlan {
        NatPlan {
            iface: "zn0".into(),
            subnet: Ipv4Addr::new(10, 7, 9, 0),
            prefix_len: 24,
            server_ip: Ipv4Addr::new(10, 7, 9, 1),
            client_ip: Ipv4Addr::new(10, 7, 9, 2),
            control_port: 2222,
            mtu: 1400,
            except: vec![22, 2222], // duplicate of control to exercise dedup
        }
    }

    #[test]
    fn kept_ports_dedup_sorted() {
        assert_eq!(plan().kept_ports(), vec![22, 2222]);
        let p = NatPlan {
            except: vec![],
            ..plan()
        };
        assert_eq!(p.kept_ports(), vec![2222]);
    }

    #[test]
    fn mss_is_mtu_minus_headers() {
        assert_eq!(plan().mss(), 1360);
        assert_eq!(NatPlan { mtu: 1280, ..plan() }.mss(), 1240);
        // A nonsensically small MTU floors at the IPv4 minimum MSS.
        assert_eq!(NatPlan { mtu: 100, ..plan() }.mss(), 536);
    }

    #[test]
    fn nft_script_shape() {
        let s = nft_script(&plan());
        assert!(s.contains("add table ip zeronat"));
        assert!(s.contains("type nat hook prerouting priority dstnat"));
        assert!(s.contains("type nat hook postrouting priority srcnat"));
        assert!(s.contains("type filter hook forward priority mangle"));
        assert!(s.contains("ip daddr != 10.7.9.0/24"));
        assert!(s.contains("tcp dport != { 22, 2222 } dnat to 10.7.9.2"));
        assert!(s.contains("udp dport != { 22, 2222 } dnat to 10.7.9.2"));
        assert!(s.contains("ip protocol icmp dnat to 10.7.9.2"));
        assert!(s.contains("oifname \"zn0\" snat to 10.7.9.1"));
        assert!(s.contains("oifname \"zn0\" tcp flags & (syn | rst) == syn tcp option maxseg size set 1360"));
        assert!(s.contains("iifname \"zn0\" tcp flags & (syn | rst) == syn tcp option maxseg size set 1360"));
        assert!(s.contains("forward oifname \"zn0\" accept"));
        assert!(s.contains("forward iifname \"zn0\" accept"));
    }

    #[test]
    fn iptables_rules_shape() {
        let rules = iptables_rules(&plan());
        assert_eq!(rules.len(), 8);
        // tcp/udp DNAT use multiport for several kept ports.
        let tcp = rules[0].command().join(" ");
        assert_eq!(
            tcp,
            "-t nat -A PREROUTING ! -i zn0 ! -d 10.7.9.0/24 -p tcp -m multiport ! --dports 22,2222 -j DNAT --to-destination 10.7.9.2 -m comment --comment zeronat"
        );
        // icmp DNAT and egress SNAT.
        assert!(rules[2]
            .command()
            .join(" ")
            .contains("-p icmp -j DNAT --to-destination 10.7.9.2"));
        assert!(rules[3]
            .command()
            .join(" ")
            .contains("-o zn0 -j SNAT --to-source 10.7.9.1"));
        // MSS clamp on the mangle table, both tunnel directions.
        assert_eq!(
            rules[4].command().join(" "),
            "-t mangle -A FORWARD -o zn0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 -m comment --comment zeronat"
        );
        assert!(rules[5]
            .command()
            .join(" ")
            .contains("-t mangle -A FORWARD -i zn0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360"));
        // filter FORWARD accept in both directions so a default-DROP host forwards.
        assert_eq!(
            rules[6].command().join(" "),
            "-t filter -A FORWARD -o zn0 -j ACCEPT -m comment --comment zeronat"
        );
        assert!(rules[7]
            .command()
            .join(" ")
            .contains("-t filter -A FORWARD -i zn0 -j ACCEPT"));
    }

    #[test]
    fn single_kept_port_uses_dport_not_multiport() {
        let p = NatPlan {
            except: vec![],
            ..plan()
        };
        let rules = iptables_rules(&p);
        let tcp = rules[0].command().join(" ");
        assert!(tcp.contains("-p tcp ! --dport 2222 -j DNAT"));
        assert!(!tcp.contains("multiport"));
    }
}
