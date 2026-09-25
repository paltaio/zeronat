//! The zeronat client admin console: a live, controllable view of one
//! running client over its local admin socket.
//!
//! Same shape as the server console: every frame is rebuilt from the latest
//! snapshot and diffed by the renderer, snapshots are polled on an interval,
//! and each mutating keypress sends one admin mutation and then refetches, so
//! the screen always reflects the client's own view. A `SelectServer` or
//! pppoe spawn/stop is a real teardown-then-bringup with a brief link drop;
//! the toast announces the transition and the polled snapshots track it.

use std::path::PathBuf;

use crate::client::Transport;
use crate::client_admin;
use crate::clientproto::{
    ClientForwardEntry, ClientMsg, ClientPeerSlotEntry, ClientServerEntry, ClientSnapshotBody,
    LinkStatus, PppPhase, ServerSecret, SessionMode,
};
use crate::proto::{proto_name, provides_name, Proto};
use crate::Result;

use super::common::{
    self, caret, cat, cell, fail_text, hints, num, pad, pick_row, port_col, proto_port,
    proto_style, sanitize, set_toast, BoxFut, Console, Flow, Screen, Status, Toast, BOLD,
    NET_TIMEOUT,
};
use super::input::Key;
use super::style::{Line, ACCENT, BAD, GOOD, MUTED, PLAIN, WARN};

/// Entry point: resolve the admin socket once, take over the terminal, drive
/// the event loop, restore on exit.
pub async fn run(socket: Option<PathBuf>) -> Result<()> {
    let path = client_admin::resolve_socket(socket.as_deref())?;
    let mut app = App::new(path);
    common::event_loop(&mut app).await
}

enum Overlay {
    None,
    /// Re-selecting the already-active profile: a select is a real
    /// teardown/redial, so it needs a deliberate yes.
    ConfirmSelect {
        name: String,
    },
    /// Full option state for one forward; submit always sends every field.
    /// Fields in form order: enabled, proxy, idle.
    FwdForm {
        proto: Proto,
        port: u16,
        enabled: bool,
        proxy: bool,
        idle: String,
        field: u8,
    },
    /// The add-server form. The secret lives only here and renders masked;
    /// no toast or error ever echoes it.
    AddServer {
        name: String,
        addr: String,
        transport: Transport,
        secret: String,
        field: u8,
    },
    /// The add-forward form. A blank target is sent as the empty sentinel the
    /// daemon resolves to `127.0.0.1:PORT`; picking udp clears the proxy
    /// toggle, a state the daemon always refuses. Fields in form order:
    /// proto, port, target, proxy, enabled, idle.
    AddForward {
        proto: Proto,
        port: String,
        target: String,
        proxy: bool,
        enabled: bool,
        idle: String,
        field: u8,
    },
    /// Removing a profile is a config edit; it needs a deliberate yes.
    ConfirmRemove {
        name: String,
    },
    /// Removing a forward drops its open connections; it needs a deliberate
    /// yes.
    ConfirmRemoveForward {
        proto: Proto,
        port: u16,
    },
    /// Disconnecting parks the client offline; it needs a deliberate yes.
    ConfirmDisconnect,
    /// Picks among the snapshot's pppoe session names, which hold still while
    /// the picker is open: nothing refetches under an overlay.
    PppoePicker {
        sel: usize,
    },
    ConfirmStop {
        name: String,
    },
}

/// One admin exchange a keypress queued.
enum Pending {
    Refresh,
    Apply(ClientMsg, String),
}

struct App {
    socket: PathBuf,
    socket_text: String,
    snap: Option<ClientSnapshotBody>,
    status: Status,
    toast: Toast,
    sel: usize,
    overlay: Overlay,
    pending: Option<Pending>,
}

impl Console for App {
    fn view(&self, w: usize, h: usize) -> Vec<String> {
        self.view(w, h)
    }

    fn overlay_open(&self) -> bool {
        !matches!(self.overlay, Overlay::None)
    }

    fn key(&mut self, k: Key) -> Flow {
        self.handle(k)
    }

    fn refresh(&mut self) -> BoxFut<'_> {
        Box::pin(self.fetch())
    }

    fn run_pending(&mut self) -> BoxFut<'_> {
        Box::pin(async move {
            match self.pending.take() {
                None => {}
                Some(Pending::Refresh) => self.fetch().await,
                Some(Pending::Apply(req, msg)) => self.apply(req, msg).await,
            }
        })
    }
}

impl App {
    fn new(socket: PathBuf) -> App {
        App {
            socket_text: socket.display().to_string(),
            socket,
            snap: None,
            status: Status::Connecting,
            toast: None,
            sel: 0,
            overlay: Overlay::None,
            pending: None,
        }
    }

    /// Configured server profiles in config order; the daemon reports them
    /// with their dialable fields only.
    fn servers(&self) -> &[ClientServerEntry] {
        self.snap.as_ref().map_or(&[], |s| &s.servers)
    }

    /// Forwards as the daemon reports them (tcp before udp, sorted by port).
    fn forwards(&self) -> &[ClientForwardEntry] {
        self.snap.as_ref().map_or(&[], |s| &s.forwards)
    }

    /// Peer slots in the order the daemon runs them, consumers and providers
    /// alike.
    fn peers(&self) -> &[ClientPeerSlotEntry] {
        self.snap.as_ref().map_or(&[], |s| &s.peers)
    }

    fn active_name(&self) -> Option<&str> {
        self.snap.as_ref().map(|s| s.active.as_str())
    }

    fn item_count(&self) -> usize {
        self.servers().len() + self.forwards().len()
    }

    fn clamp_sel(&mut self) {
        let n = self.item_count();
        if n == 0 {
            self.sel = 0;
        } else if self.sel >= n {
            self.sel = n - 1;
        }
    }

    async fn fetch(&mut self) {
        let fetch = client_admin::snapshot(&self.socket);
        match tokio::time::timeout(NET_TIMEOUT, fetch).await {
            Ok(Ok(snap)) => {
                self.snap = Some(snap);
                self.status = Status::Connected;
                self.clamp_sel();
            }
            Ok(Err(e)) => self.status = Status::Error(fail_text(Some(e))),
            Err(_) => self.status = Status::Error(fail_text(None)),
        }
    }

    /// Send one mutation, surface its verdict as a toast, then refetch so the
    /// view reflects the client's post-mutation state. Acceptance is not
    /// completion: an accepted switch is a teardown-then-bringup that the
    /// polled snapshots track.
    async fn apply(&mut self, req: ClientMsg, ok_msg: String) {
        let send = client_admin::mutate(&self.socket, req);
        let (msg, is_err) = match tokio::time::timeout(NET_TIMEOUT, send).await {
            Ok(Ok((true, _))) => (ok_msg, false),
            Ok(Ok((false, msg))) => (refusal_text(msg), true),
            Ok(Err(e)) => (fail_text(Some(e)), true),
            Err(_) => (fail_text(None), true),
        };
        set_toast(&mut self.toast, msg, is_err);
        self.fetch().await;
    }

    fn queue(&mut self, req: ClientMsg, ok_msg: String) {
        self.pending = Some(Pending::Apply(req, ok_msg));
    }

    /// A keypress and the exchange it queued, in one step.
    #[cfg(test)]
    async fn on_key(&mut self, k: Key) -> Flow {
        let flow = self.handle(k);
        self.run_pending().await;
        flow
    }

    fn close(&mut self) {
        self.overlay = Overlay::None;
    }

    fn handle(&mut self, k: Key) -> Flow {
        if matches!(k, Key::CtrlC) {
            return Flow::Quit;
        }
        match self.overlay {
            Overlay::None => return self.on_key_normal(k),
            Overlay::ConfirmSelect { .. }
            | Overlay::ConfirmRemove { .. }
            | Overlay::ConfirmRemoveForward { .. }
            | Overlay::ConfirmDisconnect
            | Overlay::ConfirmStop { .. } => self.on_key_confirm(k),
            Overlay::FwdForm { .. } => self.on_key_form(k),
            Overlay::AddServer { .. } => self.on_key_add_server(k),
            Overlay::AddForward { .. } => self.on_key_add_forward(k),
            Overlay::PppoePicker { .. } => self.on_key_picker(k),
        }
        Flow::Continue
    }

    #[inline(never)]
    fn on_key_normal(&mut self, k: Key) -> Flow {
        let ns = self.servers().len();
        match k {
            Key::Char('q') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
            Key::Down | Key::Char('j') if self.sel + 1 < self.item_count() => {
                self.sel += 1;
            }
            Key::Char('r') => self.pending = Some(Pending::Refresh),
            Key::Enter => {
                if self.sel < ns {
                    let name = self.servers()[self.sel].name.clone();
                    if self.active_name() == Some(name.as_str()) {
                        self.overlay = Overlay::ConfirmSelect { name };
                    } else {
                        let msg = cat(&["switching to ", &name, ": teardown and redial"]);
                        self.queue(ClientMsg::SelectServer { name }, msg);
                    }
                } else if let Some(f) = self.forwards().get(self.sel - ns) {
                    self.overlay = Overlay::FwdForm {
                        proto: f.proto,
                        port: f.port,
                        enabled: f.enabled,
                        proxy: f.proxy,
                        idle: if f.idle_secs > 0 {
                            num(f.idle_secs as usize)
                        } else {
                            String::new()
                        },
                        field: 0,
                    };
                }
            }
            Key::Char('a') => {
                self.overlay = Overlay::AddServer {
                    name: String::new(),
                    addr: String::new(),
                    transport: Transport::Auto,
                    secret: String::new(),
                    field: 0,
                };
            }
            Key::Char('f') => {
                self.overlay = Overlay::AddForward {
                    proto: Proto::Tcp,
                    port: String::new(),
                    target: String::new(),
                    proxy: false,
                    enabled: true,
                    idle: String::new(),
                    field: 0,
                };
            }
            // One delete verb across the index space: server rows confirm a
            // profile removal, forward rows a forward removal.
            Key::Char('x') => {
                if let Some(s) = self.servers().get(self.sel) {
                    self.overlay = Overlay::ConfirmRemove {
                        name: s.name.clone(),
                    };
                } else if let Some(f) = self.forwards().get(self.sel - ns) {
                    self.overlay = Overlay::ConfirmRemoveForward {
                        proto: f.proto,
                        port: f.port,
                    };
                }
            }
            Key::Char(' ') => {
                if self.sel >= ns {
                    if let Some(f) = self.forwards().get(self.sel - ns) {
                        // Full-state replace: the row's own snapshot state
                        // supplies proxy/idle, only the flag flips.
                        let req = ClientMsg::SetForwardOptions {
                            proto: f.proto,
                            port: f.port,
                            enabled: !f.enabled,
                            proxy: f.proxy,
                            idle_secs: f.idle_secs,
                        };
                        let verb = if f.enabled { "disabled " } else { "enabled " };
                        let msg = cat(&[verb, &proto_port(f.proto, f.port)]);
                        self.queue(req, msg);
                    }
                }
            }
            // Connect is the offline park's exit; while anything else runs,
            // select-server is the retarget verb and the key does nothing.
            Key::Char('c') if self.mode() == Some(SessionMode::Offline) => {
                self.queue(
                    ClientMsg::Connect {
                        name: String::new(),
                    },
                    "connecting: bringing up the boot session body".to_string(),
                );
            }
            Key::Char('d') if self.mode().is_some_and(|m| m != SessionMode::Offline) => {
                self.overlay = Overlay::ConfirmDisconnect;
            }
            Key::Char('p') => {
                if self.pppoe_names().is_empty() {
                    set_toast(
                        &mut self.toast,
                        "no pppoe sessions configured".to_string(),
                        true,
                    );
                } else {
                    self.overlay = Overlay::PppoePicker { sel: 0 };
                }
            }
            Key::Char('s') => {
                if let Some(name) = self.live_pppoe() {
                    self.overlay = Overlay::ConfirmStop { name };
                }
            }
            _ => {}
        }
        Flow::Continue
    }

    fn mode(&self) -> Option<SessionMode> {
        self.snap.as_ref().map(|s| s.mode)
    }

    /// Configured pppoe session names `SpawnPppoe` may name.
    fn pppoe_names(&self) -> &[String] {
        self.snap.as_ref().map_or(&[], |s| &s.pppoe)
    }

    /// Name of the live pppoe session body, when there is one to stop.
    fn live_pppoe(&self) -> Option<String> {
        self.snap.as_ref().and_then(|s| {
            if s.mode == SessionMode::Pppoe && !s.session.is_empty() {
                Some(s.session.clone())
            } else {
                None
            }
        })
    }

    /// `y` or enter runs what the open confirm panel asks about; `n` or esc
    /// closes it.
    fn on_key_confirm(&mut self, k: Key) {
        match k {
            Key::Char('y') | Key::Enter => {
                let (req, msg) = match std::mem::replace(&mut self.overlay, Overlay::None) {
                    Overlay::ConfirmSelect { name } => (
                        ClientMsg::SelectServer { name: name.clone() },
                        cat(&["re-selected ", &name, ": teardown and redial"]),
                    ),
                    Overlay::ConfirmRemove { name } => (
                        ClientMsg::RemoveServer { name: name.clone() },
                        cat(&["removed ", &name]),
                    ),
                    Overlay::ConfirmRemoveForward { proto, port } => (
                        ClientMsg::RemoveForward { proto, port },
                        cat(&["removed ", &proto_port(proto, port)]),
                    ),
                    Overlay::ConfirmDisconnect => (
                        ClientMsg::Disconnect,
                        "disconnected: nothing dials until connect".to_string(),
                    ),
                    Overlay::ConfirmStop { name } => (
                        ClientMsg::StopSession { name: name.clone() },
                        cat(&["stopping pppoe ", &name, ": falling back to the base mode"]),
                    ),
                    _ => return,
                };
                self.queue(req, msg);
            }
            Key::Char('n') | Key::Esc => self.close(),
            _ => {}
        }
    }

    fn on_key_form(&mut self, k: Key) {
        let Overlay::FwdForm {
            enabled,
            proxy,
            idle,
            field,
            ..
        } = &mut self.overlay
        else {
            return;
        };
        match k {
            Key::Esc => self.close(),
            Key::Tab | Key::Down => *field = (*field + 1) % 3,
            Key::Up => *field = (*field + 2) % 3,
            Key::Left | Key::Right | Key::Char(' ') => match field {
                0 => *enabled = !*enabled,
                1 => *proxy = !*proxy,
                _ => {}
            },
            Key::Backspace => {
                if *field == 2 {
                    idle.pop();
                }
            }
            Key::Char(c) if c.is_ascii_digit() => {
                if *field == 2 && idle.len() < 9 {
                    idle.push(c);
                }
            }
            Key::Enter => self.submit_form(),
            _ => {}
        }
    }

    fn submit_form(&mut self) {
        let Overlay::FwdForm {
            proto,
            port,
            enabled,
            proxy,
            idle,
            ..
        } = &self.overlay
        else {
            return;
        };
        let (proto, port, enabled, proxy) = (*proto, *port, *enabled, *proxy);
        // Empty clears the idle override; the field is digits-only and
        // length-capped, so any non-empty value parses.
        let idle_secs: u32 = idle.parse().unwrap_or(0);
        self.close();
        // Full-state replace: every option is always sent, so what lands is
        // exactly what the form showed.
        let req = ClientMsg::SetForwardOptions {
            proto,
            port,
            enabled,
            proxy,
            idle_secs,
        };
        let msg = cat(&[
            "set ",
            &proto_port(proto, port),
            " ",
            &crate::admin::fwd_opts(proxy, idle_secs),
            if enabled { "" } else { "  off" },
        ]);
        self.queue(req, msg);
    }

    fn on_key_add_server(&mut self, k: Key) {
        let Overlay::AddServer {
            name,
            addr,
            transport,
            secret,
            field,
        } = &mut self.overlay
        else {
            return;
        };
        match k {
            Key::Esc => self.close(),
            Key::Tab | Key::Down => *field = (*field + 1) % 4,
            Key::Up => *field = (*field + 3) % 4,
            Key::Left => {
                if *field == 2 {
                    *transport = match transport {
                        Transport::Auto => Transport::Tcp,
                        Transport::Udp => Transport::Auto,
                        Transport::Tcp => Transport::Udp,
                    };
                }
            }
            Key::Right => {
                if *field == 2 {
                    *transport = match transport {
                        Transport::Auto => Transport::Udp,
                        Transport::Udp => Transport::Tcp,
                        Transport::Tcp => Transport::Auto,
                    };
                }
            }
            Key::Backspace => match field {
                0 => {
                    name.pop();
                }
                1 => {
                    addr.pop();
                }
                3 => {
                    secret.pop();
                }
                _ => {}
            },
            // The daemon refuses control characters; keeping them out of the
            // form spares a doomed round trip.
            Key::Char(c) if !c.is_control() => match field {
                0 => name.push(c),
                1 => addr.push(c),
                3 => secret.push(c),
                _ => {}
            },
            Key::Enter => self.submit_add_server(),
            _ => {}
        }
    }

    fn submit_add_server(&mut self) {
        let Overlay::AddServer {
            name,
            addr,
            transport,
            secret,
            ..
        } = &self.overlay
        else {
            return;
        };
        let secret = match crate::secret::normalize(secret) {
            Ok(secret) => secret,
            Err(e) => {
                set_toast(&mut self.toast, e.to_string(), true);
                return;
            }
        };
        // The ok toast names the profile only; the secret is never echoed.
        let req = ClientMsg::AddServer {
            name: name.clone(),
            addr: addr.clone(),
            secret: ServerSecret(secret),
            transport: *transport,
        };
        let msg = cat(&["added ", name]);
        self.close();
        self.queue(req, msg);
    }

    fn on_key_add_forward(&mut self, k: Key) {
        let Overlay::AddForward {
            proto,
            port,
            target,
            proxy,
            enabled,
            idle,
            field,
        } = &mut self.overlay
        else {
            return;
        };
        match k {
            Key::Esc => self.close(),
            Key::Tab | Key::Down => *field = (*field + 1) % 6,
            Key::Up => *field = (*field + 5) % 6,
            Key::Left | Key::Right => toggle_add_forward(*field, proto, proxy, enabled),
            Key::Backspace => match field {
                1 => {
                    port.pop();
                }
                2 => {
                    target.pop();
                }
                5 => {
                    idle.pop();
                }
                _ => {}
            },
            Key::Enter => self.submit_add_forward(),
            Key::Char(c) => match field {
                1 if c.is_ascii_digit() && port.len() < 5 => port.push(c),
                // The daemon refuses control characters; space stays
                // typeable, the toggle fields own it elsewhere.
                2 if !c.is_control() => target.push(c),
                5 if c.is_ascii_digit() && idle.len() < 9 => idle.push(c),
                _ if c == ' ' => toggle_add_forward(*field, proto, proxy, enabled),
                _ => {}
            },
            _ => {}
        }
    }

    fn submit_add_forward(&mut self) {
        let Overlay::AddForward {
            proto,
            port,
            target,
            proxy,
            enabled,
            idle,
            ..
        } = &self.overlay
        else {
            return;
        };
        // A submit without a usable port keeps the form open to fix it.
        let Some(port) = port.parse::<u16>().ok().filter(|p| *p != 0) else {
            set_toast(&mut self.toast, "port must be 1-65535".to_string(), true);
            return;
        };
        // The digits-only, length-capped idle field parses whenever non-empty;
        // empty means no override.
        let idle_secs: u32 = idle.parse().unwrap_or(0);
        // A blank target rides as the empty sentinel; the daemon resolves the
        // 127.0.0.1:PORT default the form displayed.
        let req = ClientMsg::AddForward {
            proto: *proto,
            port,
            target: target.clone(),
            proxy: *proxy,
            idle_secs,
            enabled: *enabled,
        };
        let msg = cat(&["added ", &proto_port(*proto, port)]);
        self.close();
        self.queue(req, msg);
    }

    fn on_key_picker(&mut self, k: Key) {
        let Overlay::PppoePicker { sel } = self.overlay else {
            return;
        };
        match k {
            Key::Esc => self.close(),
            Key::Up | Key::Char('k') => {
                self.overlay = Overlay::PppoePicker {
                    sel: sel.saturating_sub(1),
                };
            }
            Key::Down | Key::Char('j') => {
                if sel + 1 < self.pppoe_names().len() {
                    self.overlay = Overlay::PppoePicker { sel: sel + 1 };
                }
            }
            Key::Enter => {
                let name = self.pppoe_names()[sel].clone();
                self.close();
                let msg = cat(&["spawning pppoe ", &name]);
                self.queue(ClientMsg::SpawnPppoe { name }, msg);
            }
            _ => {}
        }
    }

    // ---- rendering -------------------------------------------------------

    fn view(&self, w: usize, h: usize) -> Vec<String> {
        if let Some(blank) = common::too_small(w, h) {
            return blank;
        }
        let servers = self.servers();
        let forwards = self.forwards();
        let peers = self.peers();

        let mut s = Screen::new(w);
        s.blank();
        s.head("SERVERS", servers.len());
        if servers.is_empty() {
            let msg = match self.active_name() {
                Some(active) => cat(&[
                    "  (no configured profiles; dialing ",
                    &sanitize(active),
                    ")",
                ]),
                None => "  (none)".to_string(),
            };
            s.muted(&msg);
        }
        for (i, e) in servers.iter().enumerate() {
            s.row(self.server_row(e, i));
        }
        s.blank();
        s.row(common::section_title("SESSION"));
        for l in self.session_lines() {
            s.row(l);
        }
        s.blank();
        s.head("FORWARDS", forwards.len());
        if forwards.is_empty() {
            s.muted("  (none)");
        }
        for (i, f) in forwards.iter().enumerate() {
            s.row(self.forward_row(f, servers.len() + i));
        }
        s.blank();
        s.head("PEERS", peers.len());
        if peers.is_empty() {
            s.muted("  (none)");
        }
        for slot in peers {
            s.row(peer_row(slot));
        }

        common::compose(
            w,
            h,
            self.header_left(),
            common::status_seg(&self.status),
            s.rows,
            common::toast_line(&self.toast),
            self.hint_line(servers.len()),
            self.overlay_panel(w, h),
        )
    }

    #[inline(never)]
    fn header_left(&self) -> Line {
        let mut l = Line::new();
        l.add(ACCENT, "zeronat");
        l.add(MUTED, "  client  ");
        l.add(PLAIN, &self.socket_text);
        if let Some(snap) = &self.snap {
            l.push(MUTED, cat(&["  active ", &sanitize(&snap.active)]));
        }
        l
    }

    fn selected(&self, idx: usize) -> bool {
        self.sel == idx && matches!(self.overlay, Overlay::None)
    }

    #[inline(never)]
    fn server_row(&self, s: &ClientServerEntry, idx: usize) -> Line {
        let is_active = self.active_name() == Some(s.name.as_str());
        let mut l = Line::new();
        caret(&mut l, self.selected(idx));
        l.push(if is_active { BOLD } else { PLAIN }, cell(&s.name, 18));
        l.push(MUTED, cell(&s.addr, 22));
        l.push(MUTED, pad(transport_label(s.transport), 6));
        if is_active {
            l.add(GOOD, "● active");
            // Reachability renders only on this row: the client never probes
            // a server it is not dialing. The link is the tunnel dial itself;
            // only a pppoe body also reports a PPP phase.
            if let Some(snap) = &self.snap {
                let (txt, style) = link_status_view(snap.link);
                l.add(MUTED, "  ");
                l.add(style, txt);
                if snap.mode == SessionMode::Pppoe {
                    let (txt, style) = phase_view(snap.phase);
                    l.add(MUTED, "  ");
                    l.add(style, txt);
                }
            }
        }
        l
    }

    #[inline(never)]
    fn session_lines(&self) -> Vec<Line> {
        let snap = match &self.snap {
            Some(snap) => snap,
            None => return vec![common::muted_line("  (no snapshot yet)")],
        };
        let mut l = Line::new();
        l.add(PLAIN, "  mode  ");
        match snap.mode {
            SessionMode::Idle => {
                l.add(BOLD, "idle");
                l.add(MUTED, "  no session body; only the admin socket is up");
            }
            SessionMode::Forwards => {
                l.add(BOLD, "forwards");
            }
            SessionMode::Device => {
                l.add(BOLD, "device");
            }
            SessionMode::Pppoe => {
                l.add(BOLD, "pppoe");
                l.push(ACCENT, cat(&["  ", &sanitize(&snap.session)]));
            }
            SessionMode::Offline => {
                l.add(BOLD, "offline");
                l.add(MUTED, "  nothing is dialed until connect");
            }
        }
        let mut v = vec![l];
        if snap.mode == SessionMode::Pppoe {
            let mut p = Line::new();
            p.add(PLAIN, "  phase ");
            let (txt, style) = phase_view(snap.phase);
            p.push(style, pad(txt, 12));
            p.add(PLAIN, "link ");
            let (txt, style) = link_view(snap.phase);
            p.add(style, txt);
            v.push(p);
        }
        v
    }

    #[inline(never)]
    fn forward_row(&self, f: &ClientForwardEntry, idx: usize) -> Line {
        let mut l = Line::new();
        caret(&mut l, self.selected(idx));
        l.add(proto_style(f.proto), proto_name(f.proto));
        l.push(PLAIN, port_col(f.port));
        l.add(MUTED, "-> ");
        l.push(PLAIN, cell(&f.target, 21));
        l.push(
            MUTED,
            cat(&["  ", &crate::admin::fwd_opts(f.proxy, f.idle_secs)]),
        );
        if !f.enabled {
            l.add(BAD, "  off");
        }
        l
    }

    #[inline(never)]
    fn hint_line(&self, server_count: usize) -> Line {
        let mut l = Line::new();
        match &self.overlay {
            Overlay::None => {
                hints(&mut l, "↑↓ move");
                if self.item_count() > 0 {
                    if self.sel < server_count {
                        hints(&mut l, "⏎ select|x remove");
                    } else {
                        hints(&mut l, "⏎ edit|␣ toggle|x remove");
                    }
                }
                hints(&mut l, "a add|f add fwd");
                // Connect is offered only while offline; disconnect while
                // anything (a body or the idle dial) is up.
                match self.mode() {
                    Some(SessionMode::Offline) => hints(&mut l, "c connect"),
                    Some(_) => hints(&mut l, "d disconnect"),
                    None => {}
                }
                if self.snap.as_ref().is_some_and(|s| !s.pppoe.is_empty()) {
                    hints(&mut l, "p pppoe");
                }
                if self.live_pppoe().is_some() {
                    hints(&mut l, "s stop pppoe");
                }
                hints(&mut l, "r refresh|q quit");
            }
            Overlay::FwdForm { .. } => {
                hints(&mut l, "tab field|←→ toggle|⏎ apply|esc cancel");
            }
            Overlay::AddServer { .. } => {
                hints(&mut l, "tab field|←→ transport|⏎ add|esc cancel");
            }
            Overlay::AddForward { .. } => {
                hints(&mut l, "tab field|←→ toggle|⏎ add|esc cancel");
            }
            Overlay::PppoePicker { .. } => {
                hints(&mut l, "↑↓ choose|⏎ spawn|esc cancel");
            }
            Overlay::ConfirmSelect { .. }
            | Overlay::ConfirmRemove { .. }
            | Overlay::ConfirmRemoveForward { .. }
            | Overlay::ConfirmDisconnect
            | Overlay::ConfirmStop { .. } => {
                hints(&mut l, "y confirm|n cancel");
            }
        }
        l
    }

    #[inline(never)]
    fn overlay_panel(&self, w: usize, h: usize) -> Vec<String> {
        match &self.overlay {
            Overlay::None => Vec::new(),
            Overlay::ConfirmSelect { name } => common::confirm_panel(
                w,
                &cat(&[&sanitize(name), " is already active; re-select and redial?"]),
            ),
            Overlay::FwdForm {
                proto,
                port,
                enabled,
                proxy,
                idle,
                field,
            } => {
                let mut p = Screen::panel(w, &cat(&["edit forward  ", &proto_port(*proto, *port)]));
                p.row(form_bool("enabled", *enabled, *field == 0));
                p.row(form_bool("proxy", *proxy, *field == 1));
                p.row(form_text("idle", idle, *field == 2));
                p.muted("  idle in seconds; empty clears the override");
                p.close()
            }
            Overlay::AddServer {
                name,
                addr,
                transport,
                secret,
                field,
            } => {
                let mut p = Screen::panel(w, "add server");
                p.row(form_text("name", name, *field == 0));
                p.row(form_text("addr", addr, *field == 1));
                p.row(form_pick(
                    "transport",
                    transport_label(*transport),
                    *field == 2,
                ));
                // One * per typed character; the secret itself never renders.
                p.row(form_text(
                    "secret",
                    &"*".repeat(secret.chars().count()),
                    *field == 3,
                ));
                p.muted("  addr is \"dht\" or host:port; the secret is sent, never shown");
                p.close()
            }
            Overlay::AddForward {
                proto,
                port,
                target,
                proxy,
                enabled,
                idle,
                field,
            } => {
                let mut p = Screen::panel(w, "add forward");
                p.row(form_pick("proto", proto_name(*proto), *field == 0));
                p.row(form_text("port", port, *field == 1));
                // A blank target renders as the default it resolves to.
                let default = cat(&["127.0.0.1:", if port.is_empty() { "PORT" } else { port }]);
                p.row(form_text_default("target", target, &default, *field == 2));
                p.row(form_bool("proxy", *proxy, *field == 3));
                p.row(form_bool("enabled", *enabled, *field == 4));
                p.row(form_text("idle", idle, *field == 5));
                p.muted("  blank target means the 127.0.0.1:PORT default; idle in seconds");
                p.close()
            }
            Overlay::ConfirmRemove { name } => common::confirm_panel(
                w,
                &cat(&["remove server ", &sanitize(name), " from the config?"]),
            ),
            Overlay::ConfirmRemoveForward { proto, port } => common::confirm_panel(
                w,
                &cat(&[
                    "remove forward ",
                    &proto_port(*proto, *port),
                    " and drop its connections?",
                ]),
            ),
            Overlay::ConfirmDisconnect => {
                common::confirm_panel(w, "disconnect and stay offline until connect?")
            }
            Overlay::PppoePicker { sel } => {
                let names = self.pppoe_names();
                let mut p = Screen::panel(w, "spawn pppoe");
                common::picker_rows(&mut p, h, names.len(), *sel, &|i, l| {
                    pick_row(l, i == *sel, &sanitize(&names[i]))
                });
                p.close()
            }
            Overlay::ConfirmStop { name } => common::confirm_panel(
                w,
                &cat(&[
                    "stop pppoe ",
                    &sanitize(name),
                    " and fall back to the base mode?",
                ]),
            ),
        }
    }
}

// ---- small builders --------------------------------------------------------

/// Flip the add-forward form's picker or toggle at `field`. Moving the
/// picker to udp clears the proxy toggle, and the proxy toggle is inert
/// while udp is picked: the daemon refuses proxy on udp.
fn toggle_add_forward(field: u8, proto: &mut Proto, proxy: &mut bool, enabled: &mut bool) {
    match field {
        0 => {
            *proto = match proto {
                Proto::Tcp => Proto::Udp,
                Proto::Udp => Proto::Tcp,
            };
            if *proto == Proto::Udp {
                *proxy = false;
            }
        }
        3 if *proto == Proto::Tcp => *proxy = !*proxy,
        4 => *enabled = !*enabled,
        _ => {}
    }
}

/// A refused config save means the mutation already applied in memory and
/// only the disk write failed, unlike a validation refusal, which changed
/// nothing. Flag the save case so the two read differently; the daemon's own
/// message is kept verbatim in both.
fn refusal_text(msg: String) -> String {
    if msg.starts_with("client rejected config save") || msg.starts_with("config save task failed")
    {
        cat(&[&msg, " (applied in memory, disk stale)"])
    } else {
        msg
    }
}

fn transport_label(t: Transport) -> &'static str {
    match t {
        Transport::Auto => "auto",
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    }
}

fn phase_view(p: PppPhase) -> (&'static str, super::style::Style) {
    match p {
        PppPhase::None => ("-", MUTED),
        PppPhase::Discovery => ("discovery", WARN),
        PppPhase::Negotiating => ("negotiating", WARN),
        PppPhase::Established => ("established", GOOD),
        PppPhase::LinkDown => ("link down", BAD),
        PppPhase::Dead => ("dead", BAD),
    }
}

/// The tunnel dial toward the active server, rendered on its row. Distinct
/// from [`link_view`], which folds the PPP layer of a pppoe body.
fn link_status_view(l: LinkStatus) -> (&'static str, super::style::Style) {
    match l {
        LinkStatus::Offline => ("offline", MUTED),
        LinkStatus::Dialing => ("dialing", WARN),
        LinkStatus::Connected => ("connected", GOOD),
        LinkStatus::Backoff => ("backoff", BAD),
    }
}

/// One peer slot: what it asks for, what it opens, and where its own loop
/// stands. A consumer names the peer it exits through; a provider names the
/// capability it serves. The path renders beside the status on a connected
/// consumer, which is the only slot that has settled on one.
#[inline(never)]
fn peer_row(slot: &ClientPeerSlotEntry) -> Line {
    let mut l = Line::new();
    l.add(PLAIN, "  ");
    l.push(MUTED, pad(provides_name(slot.want), 8));
    let name = match slot.peer() {
        Some(peer) => cat(&["via ", &common::trunc(&sanitize(peer), 22)]),
        None => "provider".to_string(),
    };
    l.push(PLAIN, pad(&name, 26));
    let iface = if slot.iface.is_empty() {
        "-".to_string()
    } else {
        common::trunc(&sanitize(&slot.iface), 12)
    };
    l.push(MUTED, pad(&iface, 14));
    let (txt, style) = link_status_view(slot.link);
    l.add(style, txt);
    if let Some(path) = slot.path {
        l.push(MUTED, cat(&["  ", crate::proto::path_name(path)]));
    }
    l
}

/// The PPP link, folded to up/down for the sessions panel.
fn link_view(p: PppPhase) -> (&'static str, super::style::Style) {
    match p {
        PppPhase::Established => ("up", GOOD),
        PppPhase::LinkDown | PppPhase::Dead => ("down", BAD),
        PppPhase::Discovery | PppPhase::Negotiating => ("negotiating", WARN),
        PppPhase::None => ("-", MUTED),
    }
}

fn form_bool(label: &str, value: bool, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.push(MUTED, pad(label, 10));
    l.add(
        if focused { BOLD.reverse() } else { BOLD },
        if value { " on " } else { " off " },
    );
    l
}

fn form_pick(label: &str, value: &str, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.push(MUTED, pad(label, 10));
    l.push(
        if focused { BOLD.reverse() } else { BOLD },
        cat(&[" ", value, " "]),
    );
    l
}

fn form_text(label: &str, value: &str, focused: bool) -> Line {
    common::form_text(label, value, focused, 10)
}

/// A text field whose empty value renders the default it resolves to, muted.
fn form_text_default(label: &str, value: &str, default: &str, focused: bool) -> Line {
    if value.is_empty() {
        let mut l = Line::new();
        caret(&mut l, focused);
        l.push(MUTED, pad(label, 10));
        l.add(MUTED, default);
        if focused {
            l.add(ACCENT, "_");
        }
        l
    } else {
        form_text(label, value, focused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clientproto::LinkStatus;
    use crate::proto::{PathStatus, PROVIDES_EXIT, PROVIDES_SEGMENT};

    fn server(name: &str, addr: &str, transport: Transport) -> ClientServerEntry {
        ClientServerEntry {
            name: name.into(),
            addr: addr.into(),
            transport,
        }
    }

    fn forward(
        proto: Proto,
        port: u16,
        target: &str,
        proxy: bool,
        idle: u32,
    ) -> ClientForwardEntry {
        ClientForwardEntry {
            proto,
            port,
            target: target.into(),
            proxy,
            idle_secs: idle,
            enabled: true,
        }
    }

    fn snap() -> ClientSnapshotBody {
        ClientSnapshotBody {
            version: 1,
            active: "home".into(),
            mode: SessionMode::Forwards,
            phase: PppPhase::None,
            forwards: vec![
                forward(Proto::Tcp, 443, "10.0.0.5:443", true, 600),
                forward(Proto::Udp, 53, "10.0.0.5:53", false, 0),
            ],
            servers: vec![
                server("home", "dht", Transport::Auto),
                server("away", "198.51.100.7:9000", Transport::Tcp),
            ],
            pppoe: vec!["wan".into()],
            session: String::new(),
            link: LinkStatus::Offline,
            peers: Vec::new(),
        }
    }

    fn peer(
        peer_id: &str,
        want: u8,
        iface: &str,
        link: LinkStatus,
        path: Option<PathStatus>,
    ) -> ClientPeerSlotEntry {
        ClientPeerSlotEntry {
            peer_id: peer_id.into(),
            want,
            iface: iface.into(),
            link,
            path,
        }
    }

    fn app_with(snap: ClientSnapshotBody) -> App {
        let mut app = App::new(PathBuf::from("/run/zeronat/client.sock"));
        app.snap = Some(snap);
        app.status = Status::Connected;
        app
    }

    /// Rendered rows with every escape sequence removed, for content asserts.
    fn plain_view(app: &App) -> Vec<String> {
        app.view(100, 32).iter().map(|l| strip(l)).collect()
    }

    fn strip(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for d in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&d) {
                            break;
                        }
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }

    fn row_containing<'a>(rows: &'a [String], needle: &str) -> &'a String {
        rows.iter()
            .find(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("no row contains {needle:?}:\n{}", rows.join("\n")))
    }

    #[test]
    fn active_marker_and_phase_render_only_on_the_active_row() {
        let mut s = snap();
        s.mode = SessionMode::Pppoe;
        s.phase = PppPhase::Established;
        s.session = "wan".into();
        let rows = plain_view(&app_with(s));

        // The active row (keyed by its unique addr) carries the marker and
        // the live phase.
        let home = row_containing(&rows, "dht");
        assert!(home.contains("home"), "{home}");
        assert!(home.contains("● active"), "{home}");
        assert!(home.contains("established"), "{home}");

        // The inactive row shows config fields only.
        let away = row_containing(&rows, "198.51.100.7:9000");
        assert!(away.contains("away"), "{away}");
        assert!(!away.contains("active"), "{away}");
        assert!(!away.contains("established"), "{away}");
    }

    #[test]
    fn forwards_render_with_their_modifiers() {
        let rows = plain_view(&app_with(snap()));
        let tcp = row_containing(&rows, ":443");
        assert!(tcp.contains("tcp"), "{tcp}");
        assert!(tcp.contains("-> 10.0.0.5:443"), "{tcp}");
        assert!(tcp.contains("+proxy+idle=600"), "{tcp}");
        let udp = row_containing(&rows, ":53");
        assert!(udp.contains("udp"), "{udp}");
        assert!(udp.contains("-> 10.0.0.5:53"), "{udp}");
        // Default options render as the bare "-" marker, inside the frame
        // border.
        let core = udp.trim_end().trim_end_matches('│').trim_end();
        assert!(core.ends_with('-'), "{udp}");
        assert!(!core.contains('+'), "{udp}");
    }

    #[test]
    fn each_session_mode_renders() {
        let mut s = snap();
        s.mode = SessionMode::Idle;
        let rows = plain_view(&app_with(s));
        let mode = row_containing(&rows, "mode");
        assert!(mode.contains("idle"), "{mode}");
        assert!(mode.contains("only the admin socket is up"), "{mode}");

        let mut s = snap();
        s.mode = SessionMode::Pppoe;
        s.phase = PppPhase::Discovery;
        s.session = "wan".into();
        let rows = plain_view(&app_with(s));
        let mode = row_containing(&rows, "mode");
        assert!(mode.contains("pppoe"), "{mode}");
        assert!(mode.contains("wan"), "{mode}");
        let phase = row_containing(&rows, "phase");
        assert!(phase.contains("discovery"), "{phase}");
        assert!(phase.contains("link negotiating"), "{phase}");
    }

    /// Peer-supplied text cannot smuggle escape bytes into the frame.
    #[test]
    fn peer_text_is_sanitized() {
        let mut s = snap();
        s.servers[0].name = "ho\u{1b}]0;me".into();
        s.forwards[0].target = "10.0.0.5:443\u{7}".into();
        s.active = "ho\u{1b}]0;me".into();
        let app = app_with(s);
        for row in app.view(100, 32) {
            assert!(!row.contains("\u{1b}]"), "OSC injected: {row:?}");
            assert!(!row.contains('\u{7}'), "BEL injected: {row:?}");
        }
        // The printable remainder still renders.
        let rows = plain_view(&app);
        assert!(rows.iter().any(|r| r.contains("ho]0;me")));
    }

    #[tokio::test]
    async fn enter_routes_by_row_kind() {
        // On the active server row: confirmation, because a re-select fires a
        // real teardown/redial.
        let mut app = app_with(snap());
        app.sel = 0;
        app.on_key(Key::Enter).await;
        assert!(matches!(&app.overlay, Overlay::ConfirmSelect { name } if name == "home"));

        // Declining leaves everything as it was.
        app.on_key(Key::Char('n')).await;
        assert!(matches!(app.overlay, Overlay::None));

        // On a forward row: the option editor, prefilled with the full
        // current option state.
        app.sel = 2;
        app.on_key(Key::Enter).await;
        match &app.overlay {
            Overlay::FwdForm {
                proto,
                port,
                enabled,
                proxy,
                idle,
                field,
            } => {
                assert_eq!(*proto, Proto::Tcp);
                assert_eq!(*port, 443);
                assert!(*enabled);
                assert!(*proxy);
                assert_eq!(idle, "600");
                assert_eq!(*field, 0);
            }
            _ => panic!("expected the forward editor"),
        }
    }

    #[tokio::test]
    async fn add_form_masks_the_secret() {
        let fixture = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut app = app_with(snap());
        app.on_key(Key::Char('a')).await;
        assert!(matches!(app.overlay, Overlay::AddServer { .. }));
        for _ in 0..3 {
            app.on_key(Key::Tab).await;
        }
        for c in fixture.chars() {
            app.on_key(Key::Char(c)).await;
        }
        let rows = plain_view(&app);
        assert!(
            rows.iter().any(|r| r.contains(&"*".repeat(64))),
            "expected one * per typed char:\n{}",
            rows.join("\n")
        );
        assert!(
            !rows.iter().any(|r| r.contains(fixture)),
            "the secret text must never render"
        );
        // The toggles walk the transport picker without touching the secret.
        app.on_key(Key::Up).await;
        app.on_key(Key::Right).await;
        match &app.overlay {
            Overlay::AddServer {
                transport, secret, ..
            } => {
                assert_eq!(*transport, Transport::Udp);
                assert_eq!(secret, fixture);
            }
            _ => panic!("expected the add-server form"),
        }
        // Submit against a dead socket: the error toast and status row must
        // not echo the secret either.
        app.socket = std::env::temp_dir().join("zeronat-console-test-none.sock");
        app.on_key(Key::Enter).await;
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.toast.is_some(), "the failed submit must toast");
        let rows = plain_view(&app);
        assert!(
            !rows.iter().any(|r| r.contains(fixture)),
            "the secret text must never render:\n{}",
            rows.join("\n")
        );
    }

    #[tokio::test]
    async fn add_form_rejects_invalid_secret_before_submit() {
        let mut app = app_with(snap());
        app.on_key(Key::Char('a')).await;
        for _ in 0..3 {
            app.on_key(Key::Tab).await;
        }
        for c in "short".chars() {
            app.on_key(Key::Char(c)).await;
        }
        app.on_key(Key::Enter).await;
        assert!(matches!(app.overlay, Overlay::AddServer { .. }));
        let (message, is_error, _) = app.toast.clone().expect("a refusal toast");
        assert!(is_error);
        assert!(message.contains("64 hexadecimal"), "{message}");
    }

    #[tokio::test]
    async fn remove_confirms_by_row_kind() {
        let mut app = app_with(snap());
        app.sel = 1;
        app.on_key(Key::Char('x')).await;
        assert!(matches!(&app.overlay, Overlay::ConfirmRemove { name } if name == "away"));
        app.on_key(Key::Char('n')).await;
        assert!(matches!(app.overlay, Overlay::None));

        // On a forward row the same key confirms a forward removal, keyed by
        // the row's own (proto, port).
        app.sel = 2;
        app.on_key(Key::Char('x')).await;
        assert!(matches!(
            app.overlay,
            Overlay::ConfirmRemoveForward {
                proto: Proto::Tcp,
                port: 443,
            }
        ));
        app.on_key(Key::Esc).await;
        assert!(matches!(app.overlay, Overlay::None));
    }

    /// The add-forward form opens on `f`, walks its fields, and the udp pick
    /// clears (and then pins) the proxy toggle the daemon would refuse.
    #[tokio::test]
    async fn add_forward_form_pins_proxy_off_on_udp() {
        let mut app = app_with(snap());
        app.on_key(Key::Char('f')).await;
        assert!(matches!(app.overlay, Overlay::AddForward { .. }));

        // Port digits, then proxy on (tcp allows it).
        app.on_key(Key::Tab).await;
        for c in "8443".chars() {
            app.on_key(Key::Char(c)).await;
        }
        app.on_key(Key::Tab).await;
        app.on_key(Key::Tab).await;
        app.on_key(Key::Char(' ')).await;
        match &app.overlay {
            Overlay::AddForward { port, proxy, .. } => {
                assert_eq!(port, "8443");
                assert!(*proxy);
            }
            _ => panic!("expected the add-forward form"),
        }

        // Flipping the picker to udp clears proxy; toggling proxy while udp
        // is picked does nothing; back on tcp it toggles again.
        for _ in 0..3 {
            app.on_key(Key::Up).await;
        }
        app.on_key(Key::Right).await;
        match &app.overlay {
            Overlay::AddForward { proto, proxy, .. } => {
                assert_eq!(*proto, Proto::Udp);
                assert!(!*proxy, "the udp pick must clear the proxy toggle");
            }
            _ => panic!("expected the add-forward form"),
        }
        app.on_key(Key::Tab).await;
        app.on_key(Key::Tab).await;
        app.on_key(Key::Tab).await;
        app.on_key(Key::Char(' ')).await;
        match &app.overlay {
            Overlay::AddForward { proxy, .. } => {
                assert!(!*proxy, "proxy must stay off while udp is picked");
            }
            _ => panic!("expected the add-forward form"),
        }
    }

    /// A blank target renders the daemon's default; typed text replaces it.
    #[tokio::test]
    async fn add_forward_form_renders_the_default_target() {
        let mut app = app_with(snap());
        app.on_key(Key::Char('f')).await;
        let rows = plain_view(&app);
        assert!(rows.iter().any(|r| r.contains("127.0.0.1:PORT")));

        app.on_key(Key::Tab).await;
        for c in "8443".chars() {
            app.on_key(Key::Char(c)).await;
        }
        let rows = plain_view(&app);
        assert!(rows.iter().any(|r| r.contains("127.0.0.1:8443")));

        app.on_key(Key::Tab).await;
        for c in "10.0.0.5:80".chars() {
            app.on_key(Key::Char(c)).await;
        }
        let rows = plain_view(&app);
        assert!(rows.iter().any(|r| r.contains("10.0.0.5:80")));
        assert!(!rows.iter().any(|r| r.contains("127.0.0.1:8443")));
    }

    /// Submitting without a usable port keeps the form open with an error
    /// toast, so the typed fields are not thrown away.
    #[tokio::test]
    async fn add_forward_submit_requires_a_port() {
        let mut app = app_with(snap());
        app.on_key(Key::Char('f')).await;
        app.on_key(Key::Enter).await;
        assert!(matches!(app.overlay, Overlay::AddForward { .. }));
        let (msg, is_err, _) = app.toast.clone().expect("a refusal toast");
        assert!(is_err);
        assert!(msg.contains("port"), "{msg}");

        // An out-of-range port is refused the same way.
        app.on_key(Key::Tab).await;
        for c in "99999".chars() {
            app.on_key(Key::Char(c)).await;
        }
        app.on_key(Key::Enter).await;
        assert!(matches!(app.overlay, Overlay::AddForward { .. }));
    }

    /// `d` and `c` key off the snapshot mode, never off any message text:
    /// disconnect is offered whenever the client is not already offline,
    /// connect only while it is.
    #[tokio::test]
    async fn disconnect_and_connect_key_on_the_snapshot_mode() {
        let mut app = app_with(snap());
        app.on_key(Key::Char('d')).await;
        assert!(matches!(app.overlay, Overlay::ConfirmDisconnect));
        app.on_key(Key::Esc).await;
        assert!(matches!(app.overlay, Overlay::None));

        // While a body is up, `c` is inert: no overlay, no mutation sent.
        app.on_key(Key::Char('c')).await;
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.toast.is_none());

        // While offline, `d` is inert.
        let mut s = snap();
        s.mode = SessionMode::Offline;
        let mut app = app_with(s);
        app.on_key(Key::Char('d')).await;
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.toast.is_none());
    }

    /// The forward form's first field is the enabled toggle; space flips it
    /// and tab moves on to proxy.
    #[tokio::test]
    async fn forward_form_leads_with_the_enabled_toggle() {
        let mut app = app_with(snap());
        app.sel = 2;
        app.on_key(Key::Enter).await;
        app.on_key(Key::Char(' ')).await;
        app.on_key(Key::Tab).await;
        app.on_key(Key::Char(' ')).await;
        match &app.overlay {
            Overlay::FwdForm {
                enabled,
                proxy,
                field,
                ..
            } => {
                assert!(!*enabled);
                assert!(!*proxy, "space after tab must hit the proxy field");
                assert_eq!(*field, 1);
            }
            _ => panic!("expected the forward editor"),
        }
    }

    #[test]
    fn link_and_disabled_states_render() {
        // The link renders on the active row only, beside the marker.
        let mut s = snap();
        s.link = LinkStatus::Backoff;
        s.forwards[1].enabled = false;
        let rows = plain_view(&app_with(s));
        let home = row_containing(&rows, "dht");
        assert!(home.contains("● active"), "{home}");
        assert!(home.contains("backoff"), "{home}");
        let away = row_containing(&rows, "198.51.100.7:9000");
        assert!(!away.contains("backoff"), "{away}");
        // A disabled forward keeps its row and gains the off marker.
        let udp = row_containing(&rows, ":53");
        assert!(udp.contains("-> 10.0.0.5:53"), "{udp}");
        assert!(udp.contains("off"), "{udp}");
        let tcp = row_containing(&rows, ":443");
        assert!(!tcp.contains("off"), "{tcp}");

        // The operator park is its own mode, not idle.
        let mut s = snap();
        s.mode = SessionMode::Offline;
        let rows = plain_view(&app_with(s));
        let mode = row_containing(&rows, "mode");
        assert!(mode.contains("offline"), "{mode}");
        assert!(mode.contains("nothing is dialed until connect"), "{mode}");
        assert!(!mode.contains("idle"), "{mode}");
    }

    /// Every configured slot gets a row naming what it asks for, what it
    /// opens, and where its loop stands; only a connected consumer names the
    /// path its pair settled on.
    #[test]
    fn peer_slots_render_with_their_status() {
        let mut s = snap();
        s.peers = vec![
            peer(
                "office-b1c2",
                PROVIDES_EXIT,
                "zn0",
                LinkStatus::Connected,
                Some(PathStatus::Direct),
            ),
            peer("", PROVIDES_EXIT, "", LinkStatus::Connected, None),
            peer("", PROVIDES_SEGMENT, "br0", LinkStatus::Offline, None),
            peer(
                "depot-cd34",
                PROVIDES_EXIT,
                "zn1",
                LinkStatus::Backoff,
                None,
            ),
        ];
        let rows = plain_view(&app_with(s));
        assert!(row_containing(&rows, "PEERS").contains('4'));

        let consumer = row_containing(&rows, "via office-b1c2");
        assert!(consumer.contains("exit"), "{consumer}");
        assert!(consumer.contains("zn0"), "{consumer}");
        assert!(consumer.contains("connected  direct"), "{consumer}");

        // An exit provider on the default-route interface names no device.
        let exit = row_containing(&rows, "exit    provider");
        assert!(exit.contains("connected"), "{exit}");
        assert!(!exit.contains("direct"), "{exit}");
        assert!(!exit.contains("relay"), "{exit}");

        let segment = row_containing(&rows, "segment provider");
        assert!(segment.contains("br0"), "{segment}");
        assert!(segment.contains("offline"), "{segment}");

        let backoff = row_containing(&rows, "via depot-cd34");
        assert!(backoff.contains("backoff"), "{backoff}");

        // An empty peers panel still names itself and reads (none).
        let rows = plain_view(&app_with(snap()));
        let head = rows
            .iter()
            .position(|r| r.contains("PEERS"))
            .expect("no peers head");
        assert!(rows[head].contains('0'), "{}", rows[head]);
        assert!(rows[head + 1].contains("(none)"), "{}", rows[head + 1]);
    }

    #[tokio::test]
    async fn stop_is_offered_only_while_a_pppoe_body_is_live() {
        let mut app = app_with(snap());
        app.on_key(Key::Char('s')).await;
        assert!(matches!(app.overlay, Overlay::None));

        let mut s = snap();
        s.mode = SessionMode::Pppoe;
        s.session = "wan".into();
        let mut app = app_with(s);
        app.on_key(Key::Char('s')).await;
        assert!(matches!(&app.overlay, Overlay::ConfirmStop { name } if name == "wan"));
    }

    #[test]
    fn refusal_classes_read_differently() {
        // A validation refusal is the daemon's message verbatim.
        let v = refusal_text("`proxy` is not supported on udp forwards".into());
        assert_eq!(v, "`proxy` is not supported on udp forwards");
        // A refused save is flagged: the mutation is live, the disk is stale.
        let s = refusal_text("client rejected config save: read-only fs".into());
        assert!(s.starts_with("client rejected config save: read-only fs"));
        assert!(s.ends_with("(applied in memory, disk stale)"));
    }
}
