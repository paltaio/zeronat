//! The install wizard: a small step machine rendered with the shared tui core.
//! Each step is either a single-choice list or a text field; the flow branches
//! on earlier answers exactly like the shell installer it replaces.

use zntui::key::Key;
use zntui::style::{Color, Line, Style, ACCENT, BAD, GOOD, MUTED, PLAIN, WARN};

const BOLD: Style = Style::fg(Color::Default).bold();

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Server,
    Client,
}
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Method {
    Docker,
    Systemd,
}
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Deploy {
    Compose,
    Run,
}
#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Ports,
    Bridge,
    All,
}
#[derive(Clone, Copy, PartialEq)]
pub enum SecretMode {
    Reuse,
    Generate,
    Enter,
}

struct PortItem {
    spec: String,
    label: &'static str,
    checked: bool,
}

/// An available upgrade for an existing install, shown as the first wizard step.
/// `systemd` and `docker` hold the current version of each deployment that has a
/// newer release; a deployment already current is omitted.
#[derive(Clone)]
pub struct UpgradeOffer {
    pub latest: String,
    pub systemd: Option<String>,
    pub docker: Option<String>,
    pub compose: bool,
}

/// Common ports offered as toggles, most-used first.
const COMMON_PORTS: &[(&str, &str)] = &[
    ("443/tcp", "HTTPS"),
    ("80/tcp", "HTTP"),
    ("22/tcp", "SSH"),
    ("51820/udp", "WireGuard"),
    ("8080/tcp", "HTTP alt"),
    ("53/udp", "DNS"),
];

#[derive(Clone)]
pub struct Config {
    pub mode: Mode,
    pub method: Method,
    pub deploy: Deploy,
    pub kind: Kind,
    pub ports: String,
    pub tap: String,
    pub bridge: String,
    /// Physical NIC the installer should enslave into the bridge. Empty means an
    /// existing bridge is reused (or none).
    pub bridge_nic: String,
    /// Build the host bridge (and enslave `bridge_nic`) instead of assuming one.
    pub bridge_create: bool,
    /// Candidate physical NICs and the one carrying this SSH session, probed for
    /// the bridge-NIC prompt.
    pub nics: Vec<String>,
    pub ssh_nic: String,
    pub tap_mtu: String,
    pub control: String,
    pub use_dht: bool,
    pub announce_ip: String,
    pub announce_port: String,
    pub server_addr: String,
    pub secret: String,
    pub secret_mode: SecretMode,
    pub have_docker: bool,
    pub have_compose: bool,
    pub existing_secret: Option<String>,
    /// All-traffic mode: keep `ssh_port` on the server instead of forwarding it.
    pub exclude_ssh: bool,
    pub ssh_port: u16,
}

impl Config {
    pub fn new(have_docker: bool, have_compose: bool, existing_secret: Option<String>) -> Config {
        Config {
            mode: Mode::Server,
            method: if have_docker {
                Method::Docker
            } else {
                Method::Systemd
            },
            deploy: Deploy::Compose,
            kind: Kind::Ports,
            ports: String::new(),
            tap: "zn0".to_string(),
            bridge: String::new(),
            bridge_nic: String::new(),
            bridge_create: false,
            nics: Vec::new(),
            ssh_nic: String::new(),
            tap_mtu: String::new(),
            control: "2222".to_string(),
            use_dht: false,
            announce_ip: String::new(),
            announce_port: String::new(),
            server_addr: String::new(),
            secret: String::new(),
            secret_mode: if existing_secret.is_some() {
                SecretMode::Reuse
            } else {
                SecretMode::Generate
            },
            have_docker,
            have_compose,
            existing_secret,
            exclude_ssh: true,
            ssh_port: 22,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Upgrade,
    Mode,
    Method,
    Deploy,
    Kind,
    Ports,
    Tap,
    BridgeNic,
    BridgeName,
    SshExclude,
    Discovery,
    ServerAddr,
    Control,
    Secret,
    SecretEntry,
    Summary,
}

struct Opt {
    label: &'static str,
    desc: &'static str,
}

pub struct App {
    pub cfg: Config,
    /// An available upgrade for the existing install, if any; surfaced as the
    /// first step. None means the normal fresh-install flow.
    upgrade: Option<UpgradeOffer>,
    /// Set when the operator chose to upgrade rather than reinstall.
    pub do_upgrade: bool,
    step: Step,
    history: Vec<Step>,
    sel: usize,
    input: String,
    ports_items: Vec<PortItem>,
    adding: bool,
    error: Option<String>,
    pub finished: bool,
    pub quit: bool,
}

impl App {
    pub fn new(cfg: Config, upgrade: Option<UpgradeOffer>) -> App {
        let start = if upgrade.is_some() {
            Step::Upgrade
        } else {
            Step::Mode
        };
        let mut app = App {
            cfg,
            upgrade,
            do_upgrade: false,
            step: start,
            history: Vec::new(),
            sel: 0,
            input: String::new(),
            ports_items: Vec::new(),
            adding: false,
            error: None,
            finished: false,
            quit: false,
        };
        app.enter(start);
        app
    }

    /// The chosen upgrade offer, valid only once `do_upgrade` is set.
    pub fn upgrade_offer(&self) -> Option<&UpgradeOffer> {
        self.upgrade.as_ref()
    }

    // ---- flow ------------------------------------------------------------

    fn is_input(step: Step) -> bool {
        matches!(
            step,
            Step::Tap
                | Step::BridgeNic
                | Step::BridgeName
                | Step::ServerAddr
                | Step::Control
                | Step::SecretEntry
        )
    }

    fn next_step(&self) -> Step {
        match self.step {
            Step::Upgrade => Step::Mode,
            Step::Mode => Step::Method,
            Step::Method if self.cfg.method == Method::Docker => Step::Deploy,
            Step::Method => Step::Kind,
            Step::Deploy => Step::Kind,
            Step::Kind => match self.cfg.kind {
                Kind::Ports => Step::Ports,
                Kind::Bridge => Step::Tap,
                // Only the server loses its ports to the client, so only it is
                // asked whether to keep SSH.
                Kind::All if self.cfg.mode == Mode::Server => Step::SshExclude,
                Kind::All => Step::Discovery,
            },
            // Only a server bridges into a host NIC; a client just runs on the TAP.
            Step::Tap if self.cfg.mode == Mode::Server => Step::BridgeNic,
            Step::BridgeNic if self.cfg.bridge_nic.trim().is_empty() => Step::BridgeName,
            Step::BridgeNic | Step::BridgeName => Step::Discovery,
            Step::Ports | Step::Tap | Step::SshExclude => Step::Discovery,
            Step::Discovery => match self.cfg.mode {
                Mode::Server => Step::Control,
                Mode::Client if self.cfg.use_dht => Step::Secret,
                Mode::Client => Step::ServerAddr,
            },
            Step::ServerAddr => Step::Secret,
            Step::Control => Step::Secret,
            Step::Secret if self.cfg.secret_mode == SecretMode::Enter => Step::SecretEntry,
            Step::Secret => Step::Summary,
            Step::SecretEntry => Step::Summary,
            Step::Summary => Step::Summary,
        }
    }

    /// Set the current step and seed the widget state from the config so a step
    /// re-entered via Back shows the prior choice.
    fn enter(&mut self, step: Step) {
        self.step = step;
        self.error = None;
        self.adding = false;
        if step == Step::Ports {
            self.init_ports();
            self.sel = 0;
        } else if App::is_input(step) {
            self.input = match step {
                Step::Tap => self.cfg.tap.clone(),
                Step::BridgeNic => self.cfg.bridge_nic.clone(),
                Step::BridgeName => self.cfg.bridge.clone(),
                Step::ServerAddr => self.cfg.server_addr.clone(),
                Step::Control => self.cfg.control.clone(),
                _ => String::new(),
            };
        } else {
            self.sel = self.current_selection();
        }
    }

    /// Build the port checklist from the common set, checking any already in the
    /// config and appending unknown ones as custom entries.
    fn init_ports(&mut self) {
        let existing: Vec<String> = self
            .cfg
            .ports
            .split_whitespace()
            .map(String::from)
            .collect();
        let mut items: Vec<PortItem> = COMMON_PORTS
            .iter()
            .map(|(spec, label)| PortItem {
                spec: spec.to_string(),
                label,
                checked: existing.iter().any(|e| e == spec),
            })
            .collect();
        for e in &existing {
            if !COMMON_PORTS.iter().any(|(s, _)| s == e) {
                items.push(PortItem {
                    spec: e.clone(),
                    label: "custom",
                    checked: true,
                });
            }
        }
        self.ports_items = items;
    }

    fn commit_ports(&mut self) -> bool {
        let specs: Vec<String> = self
            .ports_items
            .iter()
            .filter(|p| p.checked)
            .map(|p| p.spec.clone())
            .collect();
        if specs.is_empty() {
            self.error = Some("select or add at least one port (space toggles)".into());
            return false;
        }
        self.cfg.ports = specs.join(" ");
        true
    }

    fn advance(&mut self) {
        let next = self.next_step();
        self.history.push(self.step);
        self.enter(next);
    }

    fn back(&mut self) {
        if let Some(prev) = self.history.pop() {
            self.enter(prev);
        }
    }

    // ---- options for the current select step -----------------------------

    fn options(&self) -> Vec<Opt> {
        match self.step {
            Step::Upgrade => vec![
                Opt {
                    label: "Upgrade",
                    desc: "update the existing install in place",
                },
                Opt {
                    label: "Fresh install",
                    desc: "reconfigure from scratch",
                },
            ],
            Step::Mode => vec![
                Opt {
                    label: "Server",
                    desc: "public host / VPS with a routable IP",
                },
                Opt {
                    label: "Client",
                    desc: "machine behind CG-NAT or a dynamic IP",
                },
            ],
            Step::Method => {
                if self.cfg.have_docker {
                    vec![
                        Opt {
                            label: "Docker",
                            desc: "run as a container (detected)",
                        },
                        Opt {
                            label: "systemd",
                            desc: "download a static binary and run as a service",
                        },
                    ]
                } else {
                    vec![Opt {
                        label: "systemd",
                        desc: "download a static binary and run as a service",
                    }]
                }
            }
            Step::Deploy => {
                if self.cfg.have_compose {
                    vec![
                        Opt {
                            label: "docker compose",
                            desc: "managed compose file in /etc/zeronat",
                        },
                        Opt {
                            label: "docker run",
                            desc: "a single detached container",
                        },
                    ]
                } else {
                    vec![Opt {
                        label: "docker run",
                        desc: "a single detached container (compose not found)",
                    }]
                }
            }
            Step::Kind => vec![
                Opt {
                    label: "Forward ports",
                    desc: "expose TCP/UDP ports through the tunnel",
                },
                Opt {
                    label: "All traffic",
                    desc: "forward every port plus ICMP (Linux, root)",
                },
                Opt {
                    label: "L2 bridge (TAP)",
                    desc: "relay raw Ethernet / PPPoE (Linux, root)",
                },
            ],
            Step::SshExclude => vec![
                Opt {
                    label: "Keep SSH on this host",
                    desc: "exclude the SSH port so you keep remote access",
                },
                Opt {
                    label: "Forward every port",
                    desc: "SSH included; only safe with console access",
                },
            ],
            Step::Discovery => match self.cfg.mode {
                Mode::Server => vec![
                    Opt {
                        label: "Fixed address",
                        desc: "clients connect to this host's public IP",
                    },
                    Opt {
                        label: "Publish to DHT",
                        desc: "discoverable by dynamic IP, no fixed address",
                    },
                ],
                Mode::Client => vec![
                    Opt {
                        label: "By address",
                        desc: "connect to a known HOST[:PORT]",
                    },
                    Opt {
                        label: "By DHT",
                        desc: "find the server over the DHT (dynamic IP)",
                    },
                ],
            },
            Step::Secret => {
                let mut v = Vec::new();
                if self.cfg.existing_secret.is_some() {
                    v.push(Opt {
                        label: "Reuse existing",
                        desc: "keep the secret already in /etc/zeronat",
                    });
                }
                v.push(Opt {
                    label: "Generate new",
                    desc: "a fresh random 256-bit secret",
                });
                v.push(Opt {
                    label: "Enter manually",
                    desc: "paste a secret shared with the other side",
                });
                v
            }
            _ => Vec::new(),
        }
    }

    /// Which option index matches the current config (so Back restores it).
    fn current_selection(&self) -> usize {
        match self.step {
            Step::Mode => (self.cfg.mode == Mode::Client) as usize,
            Step::Method => (self.cfg.method == Method::Systemd && self.cfg.have_docker) as usize,
            Step::Deploy => (self.cfg.deploy == Deploy::Run && self.cfg.have_compose) as usize,
            Step::Kind => match self.cfg.kind {
                Kind::Ports => 0,
                Kind::All => 1,
                Kind::Bridge => 2,
            },
            Step::SshExclude => (!self.cfg.exclude_ssh) as usize,
            Step::Discovery => self.cfg.use_dht as usize,
            Step::Secret => {
                let has = self.cfg.existing_secret.is_some();
                match self.cfg.secret_mode {
                    SecretMode::Reuse => 0,
                    SecretMode::Generate => has as usize,
                    SecretMode::Enter => has as usize + 1,
                }
            }
            _ => 0,
        }
    }

    /// Returns false (with `error` set) to keep the user on the step.
    fn apply_selection(&mut self) -> bool {
        match self.step {
            Step::Mode => {
                self.cfg.mode = if self.sel == 0 {
                    Mode::Server
                } else {
                    Mode::Client
                }
            }
            Step::Method => {
                self.cfg.method = if self.cfg.have_docker && self.sel == 0 {
                    Method::Docker
                } else {
                    Method::Systemd
                };
            }
            Step::Deploy => {
                self.cfg.deploy = if self.cfg.have_compose && self.sel == 0 {
                    Deploy::Compose
                } else {
                    Deploy::Run
                };
            }
            Step::Kind => {
                self.cfg.kind = match self.sel {
                    0 => Kind::Ports,
                    1 => Kind::All,
                    _ => Kind::Bridge,
                }
            }
            Step::SshExclude => self.cfg.exclude_ssh = self.sel == 0,
            Step::Discovery => self.cfg.use_dht = self.sel == 1,
            Step::Secret => {
                let has = self.cfg.existing_secret.is_some();
                let n = if has { self.sel } else { self.sel + 1 };
                self.cfg.secret_mode = match n {
                    0 => SecretMode::Reuse,
                    1 => SecretMode::Generate,
                    _ => SecretMode::Enter,
                };
                match self.cfg.secret_mode {
                    SecretMode::Reuse => {
                        self.cfg.secret = self.cfg.existing_secret.clone().unwrap_or_default()
                    }
                    SecretMode::Generate => match crate::sys::gen_secret() {
                        Ok(s) => self.cfg.secret = s,
                        Err(e) => {
                            self.error = Some(e);
                            return false;
                        }
                    },
                    SecretMode::Enter => {}
                }
            }
            _ => {}
        }
        true
    }

    /// Validate and store a text field; returns false (with `error` set) to keep
    /// the user on the step.
    fn commit_input(&mut self) -> bool {
        let v = self.input.trim().to_string();
        match self.step {
            Step::Tap => {
                if v.is_empty() {
                    self.error = Some("enter a TAP device name".into());
                    return false;
                }
                self.cfg.tap = v;
            }
            Step::BridgeNic => {
                if v.is_empty() {
                    self.cfg.bridge_nic.clear();
                    self.cfg.bridge_create = false;
                } else {
                    self.cfg.bridge_nic = v;
                    self.cfg.bridge_create = true;
                    if self.cfg.bridge.trim().is_empty() {
                        self.cfg.bridge = "br-zeronat".to_string();
                    }
                }
            }
            // Empty is allowed: a standalone TAP with no host bridge.
            Step::BridgeName => self.cfg.bridge = v,
            Step::ServerAddr => {
                if v.is_empty() {
                    self.error = Some("enter the server address".into());
                    return false;
                }
                self.cfg.server_addr = v;
            }
            Step::Control => match v.parse::<u16>() {
                Ok(p) if p > 0 => self.cfg.control = v,
                _ => {
                    self.error = Some("control port must be 1-65535".into());
                    return false;
                }
            },
            Step::SecretEntry => {
                if v.len() < 8 {
                    self.error = Some("secret looks too short".into());
                    return false;
                }
                self.cfg.secret = v;
            }
            _ => {}
        }
        true
    }

    // ---- input -----------------------------------------------------------

    pub fn on_key(&mut self, k: Key) {
        if matches!(k, Key::CtrlC) {
            self.quit = true;
            return;
        }
        if self.step == Step::Upgrade {
            match k {
                Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
                Key::Down | Key::Char('j') if self.sel == 0 => self.sel = 1,
                Key::Enter => {
                    if self.sel == 0 {
                        self.do_upgrade = true;
                        self.finished = true;
                    } else {
                        self.history.push(Step::Upgrade);
                        self.enter(Step::Mode);
                    }
                }
                Key::Char('q') => self.quit = true,
                _ => {}
            }
            return;
        }
        if self.step == Step::Summary {
            match k {
                Key::Enter => self.finished = true,
                Key::Esc | Key::Left => self.back(),
                Key::Char('q') => self.quit = true,
                _ => {}
            }
            return;
        }
        if self.step == Step::Ports {
            self.on_key_ports(k);
            return;
        }
        if App::is_input(self.step) {
            match k {
                Key::Enter if self.commit_input() => {
                    self.advance();
                }
                Key::Esc => self.back(),
                Key::Backspace => {
                    self.input.pop();
                    self.error = None;
                }
                Key::Char(c) if !c.is_control() => {
                    self.input.push(c);
                    self.error = None;
                }
                _ => {}
            }
            return;
        }
        // select step
        let n = self.options().len();
        match k {
            Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
            Key::Down | Key::Char('j') if self.sel + 1 < n => {
                self.sel += 1;
            }
            Key::Enter => {
                if self.apply_selection() {
                    self.advance();
                }
            }
            Key::Esc | Key::Left => self.back(),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    fn on_key_ports(&mut self, k: Key) {
        let custom_row = self.ports_items.len();
        if self.adding {
            match k {
                Key::Enter => {
                    let v = self.input.trim().to_string();
                    let valid = v.split_once('/').is_some_and(|(n, p)| {
                        n.parse::<u16>().is_ok() && n != "0" && (p == "tcp" || p == "udp")
                    });
                    if valid {
                        self.ports_items.push(PortItem {
                            spec: v,
                            label: "custom",
                            checked: true,
                        });
                        self.sel = self.ports_items.len() - 1;
                        self.adding = false;
                        self.input.clear();
                        self.error = None;
                    } else {
                        self.error = Some("custom port must be PORT/PROTO, e.g. 8443/tcp".into());
                    }
                }
                Key::Esc => {
                    self.adding = false;
                    self.input.clear();
                    self.error = None;
                }
                Key::Backspace => {
                    self.input.pop();
                    self.error = None;
                }
                Key::Char(c) if !c.is_control() && c != ' ' => {
                    self.input.push(c);
                    self.error = None;
                }
                _ => {}
            }
            return;
        }
        match k {
            Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
            Key::Down | Key::Char('j') if self.sel < custom_row => {
                self.sel += 1;
            }
            Key::Char(' ') if self.sel < custom_row => {
                self.ports_items[self.sel].checked = !self.ports_items[self.sel].checked;
                self.error = None;
            }
            Key::Enter => {
                if self.sel == custom_row {
                    self.adding = true;
                    self.input.clear();
                    self.error = None;
                } else if self.commit_ports() {
                    self.advance();
                }
            }
            Key::Esc | Key::Left => self.back(),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    // ---- render ----------------------------------------------------------

    pub fn view(&self, w: usize, h: usize) -> Vec<String> {
        if w < 30 || h < 12 {
            return vec![" ".repeat(w); h];
        }
        let mut lines = Vec::with_capacity(h);
        let mut right = Line::new();
        right.add(MUTED, self.crumb());
        let mut left = Line::new();
        left.add(ACCENT, "zeronat");
        left.add(MUTED, " installer");
        lines.push(zntui::frame::top(w, left, right));

        let mut body: Vec<String> = Vec::new();
        body.push(zntui::frame::blank(w));
        let mut prompt = Line::new();
        prompt.add(BOLD, self.prompt());
        body.push(zntui::frame::row(w, prompt));
        body.push(zntui::frame::blank(w));

        if self.step == Step::Summary {
            self.summary_rows(w, &mut body);
        } else if self.step == Step::Upgrade {
            self.upgrade_rows(w, &mut body);
        } else if self.step == Step::Ports {
            self.ports_rows(w, &mut body);
        } else if self.step == Step::SshExclude {
            self.ssh_rows(w, &mut body);
        } else if App::is_input(self.step) {
            self.input_rows(w, &mut body);
        } else {
            self.select_rows(w, &mut body);
        }

        let area = h.saturating_sub(5);
        body.truncate(area);
        while body.len() < area {
            body.push(zntui::frame::blank(w));
        }
        lines.extend(body);

        lines.push(zntui::frame::divider(w));
        lines.push(zntui::frame::row(w, self.status_line()));
        lines.push(zntui::frame::row(w, self.hint_line()));
        lines.push(zntui::frame::bottom(w));
        lines
    }

    fn crumb(&self) -> &'static str {
        match self.cfg.mode {
            Mode::Server => "server",
            Mode::Client => "client",
        }
    }

    fn prompt(&self) -> &'static str {
        match self.step {
            Step::Upgrade => "A newer zeronat is available",
            Step::Mode => "Which side is this machine?",
            Step::Method => "How should zeronat run?",
            Step::Deploy => "Docker deployment style?",
            Step::Kind => "What should the tunnel carry?",
            Step::Ports => "Ports to forward",
            Step::Tap => "TAP device name",
            Step::BridgeNic => "Physical NIC to bridge",
            Step::BridgeName => "Existing bridge name",
            Step::SshExclude => "Forward every port?",
            Step::Discovery => match self.cfg.mode {
                Mode::Server => "How will clients reach this server?",
                Mode::Client => "How should the client find the server?",
            },
            Step::ServerAddr => "Server address",
            Step::Control => "Tunnel control port",
            Step::Secret => "Shared secret",
            Step::SecretEntry => "Enter the shared secret",
            Step::Summary => "Review and install",
        }
    }

    fn select_rows(&self, w: usize, body: &mut Vec<String>) {
        for (i, opt) in self.options().iter().enumerate() {
            let mut l = Line::new();
            if i == self.sel {
                l.add(ACCENT, "  ▸ ");
                l.add(BOLD, opt.label);
            } else {
                l.add(PLAIN, "    ");
                l.add(PLAIN, opt.label);
            }
            l.add(MUTED, &format!("   {}", opt.desc));
            body.push(zntui::frame::row(w, l));
        }
    }

    fn ports_rows(&self, w: usize, body: &mut Vec<String>) {
        for (i, p) in self.ports_items.iter().enumerate() {
            let cur = i == self.sel && !self.adding;
            let mut l = Line::new();
            l.add(
                if cur { ACCENT } else { PLAIN },
                if cur { "  ▸ " } else { "    " },
            );
            l.add(
                if p.checked { GOOD } else { MUTED },
                if p.checked { "[x] " } else { "[ ] " },
            );
            l.add(if cur { BOLD } else { PLAIN }, &format!("{:<10}", p.spec));
            l.add(MUTED, p.label);
            body.push(zntui::frame::row(w, l));
        }
        let cur = self.sel == self.ports_items.len() && !self.adding;
        let mut l = Line::new();
        l.add(
            if cur { ACCENT } else { MUTED },
            if cur { "  ▸ " } else { "    " },
        );
        l.add(if cur { BOLD } else { MUTED }, "+ add a custom port");
        body.push(zntui::frame::row(w, l));
        if self.adding {
            body.push(zntui::frame::blank(w));
            let mut inp = Line::new();
            inp.add(MUTED, "  > ");
            inp.add(PLAIN, &self.input);
            inp.add(ACCENT, "▏");
            body.push(zntui::frame::row(w, inp));
            let mut hint = Line::new();
            hint.add(MUTED, "  PORT/PROTO, e.g. 8443/tcp");
            body.push(zntui::frame::row(w, hint));
        }
    }

    fn upgrade_rows(&self, w: usize, body: &mut Vec<String>) {
        if let Some(u) = &self.upgrade {
            let mut row = |k: &str, cur: &str| {
                let mut l = Line::new();
                l.add(MUTED, &format!("  {k:<9}"));
                l.add(PLAIN, &format!("{cur} -> "));
                l.add(GOOD, &u.latest);
                body.push(zntui::frame::row(w, l));
            };
            if let Some(c) = &u.systemd {
                row("systemd", c);
            }
            if let Some(c) = &u.docker {
                row("docker", c);
            }
            body.push(zntui::frame::blank(w));
        }
        self.select_rows(w, body);
    }

    fn ssh_rows(&self, w: usize, body: &mut Vec<String>) {
        let mut warn = Line::new();
        warn.add(
            WARN,
            &format!(
                "  every port forwards to the client, SSH (port {}) included",
                self.cfg.ssh_port
            ),
        );
        body.push(zntui::frame::row(w, warn));
        body.push(zntui::frame::blank(w));
        self.select_rows(w, body);
    }

    fn input_rows(&self, w: usize, body: &mut Vec<String>) {
        let mut l = Line::new();
        l.add(MUTED, "  > ");
        l.add(PLAIN, &self.input);
        l.add(ACCENT, "▏");
        body.push(zntui::frame::row(w, l));
        body.push(zntui::frame::blank(w));
        let mut hint = Line::new();
        hint.add(MUTED, &format!("  {}", self.input_hint()));
        body.push(zntui::frame::row(w, hint));
    }

    fn input_hint(&self) -> String {
        match self.step {
            Step::Tap => "Linux only; the TAP relays raw Ethernet/PPPoE".into(),
            Step::BridgeNic => {
                let mut h = if self.cfg.nics.is_empty() {
                    "NIC to enslave; blank to use an existing bridge".to_string()
                } else {
                    format!("detected: {}", self.cfg.nics.join(", "))
                };
                if !self.cfg.ssh_nic.is_empty() {
                    h.push_str(&format!(
                        "  ({} carries this SSH session)",
                        self.cfg.ssh_nic
                    ));
                }
                h
            }
            Step::BridgeName => "the TAP is enslaved to this existing bridge".into(),
            Step::ServerAddr => "HOST or HOST:PORT (default port 2222)".into(),
            Step::Control => "the UDP/TCP port the tunnel control runs on".into(),
            Step::SecretEntry => "must match the secret on the other side".into(),
            _ => String::new(),
        }
    }

    fn summary_rows(&self, w: usize, body: &mut Vec<String>) {
        let mut add = |k: &str, v: String, vs: Style| {
            let mut l = Line::new();
            l.add(MUTED, &format!("  {:<10}", k));
            l.add(vs, &v);
            body.push(zntui::frame::row(w, l));
        };
        add("side", self.crumb().to_string(), PLAIN);
        add(
            "method",
            match self.cfg.method {
                Method::Docker => format!(
                    "docker ({})",
                    if self.cfg.deploy == Deploy::Compose {
                        "compose"
                    } else {
                        "run"
                    }
                ),
                Method::Systemd => "systemd".to_string(),
            },
            PLAIN,
        );
        match self.cfg.kind {
            Kind::Ports => add("ports", self.cfg.ports.clone(), PLAIN),
            Kind::Bridge => {
                add("tap", self.cfg.tap.clone(), PLAIN);
                if self.cfg.bridge_create {
                    add(
                        "bridge",
                        format!("{} (create on {})", self.cfg.bridge, self.cfg.bridge_nic),
                        WARN,
                    );
                } else if !self.cfg.bridge.trim().is_empty() {
                    add("bridge", self.cfg.bridge.clone(), PLAIN);
                }
            }
            Kind::All => {
                add("forward", "all traffic".into(), PLAIN);
                if self.cfg.mode == Mode::Server {
                    if self.cfg.exclude_ssh {
                        add(
                            "ssh",
                            format!("port {} kept on host", self.cfg.ssh_port),
                            GOOD,
                        );
                    } else {
                        add("ssh", "forwarded (no exclusion)".into(), WARN);
                    }
                }
            }
        }
        match self.cfg.mode {
            Mode::Client if self.cfg.use_dht => add("server", "via DHT".to_string(), PLAIN),
            Mode::Client => add("server", self.cfg.server_addr.clone(), PLAIN),
            Mode::Server if self.cfg.use_dht => add("discovery", "DHT publish".to_string(), PLAIN),
            Mode::Server => add("control", self.cfg.control.clone(), PLAIN),
        }
        add("secret", self.cfg.secret.clone(), GOOD);
    }

    fn status_line(&self) -> Line {
        let mut l = Line::new();
        if let Some(e) = &self.error {
            l.add(BAD, "✕ ");
            l.add(WARN, e);
        }
        l
    }

    fn hint_line(&self) -> Line {
        let mut l = Line::new();
        let mut h = |key: &str, label: &str| {
            l.add(ACCENT, key);
            l.add(MUTED, &format!(" {label}   "));
        };
        if self.step == Step::Summary {
            h("⏎", "install");
            h("esc", "back");
            h("ctrl-c", "quit");
        } else if self.step == Step::Ports {
            if self.adding {
                h("⏎", "add");
                h("esc", "cancel");
            } else {
                h("↑↓", "move");
                h("space", "toggle");
                h("⏎", "done");
                h("esc", "back");
            }
        } else if App::is_input(self.step) {
            h("type", "value");
            h("⏎", "next");
            h("esc", "back");
        } else {
            h("↑↓", "choose");
            h("⏎", "next");
            if !self.history.is_empty() {
                h("esc", "back");
            }
            h("q", "quit");
        }
        l
    }
}
