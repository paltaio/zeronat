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
use std::time::{Duration, Instant};

use crate::client::Transport;
use crate::client_admin;
use crate::clientproto::{
    ClientForwardEntry, ClientMsg, ClientServerEntry, ClientSnapshotBody, LinkStatus, PppPhase,
    ServerSecret, SessionMode,
};
use crate::proto::{proto_name, Proto};
use crate::Result;

use super::input::{self, Key};
use super::render::Renderer;
use super::style::{Color, Line, Style, ACCENT, BAD, GOOD, MUTED, PLAIN, WARN};
use super::{frame, term};

const REFRESH: Duration = Duration::from_secs(1);
/// Upper bound on a single admin round trip.
const NET_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a toast stays on screen before it ages out.
const TOAST_TTL: Duration = Duration::from_secs(4);
const BOLD: Style = Style::fg(Color::Default).bold();
const TCP: Style = Style::fg(Color::Accent);
const UDP: Style = Style::fg(Color::Magenta);

/// Entry point: resolve the admin socket once, take over the terminal, drive
/// the event loop, restore on exit.
pub async fn run(socket: Option<PathBuf>) -> Result<()> {
    let path = client_admin::resolve_socket(socket.as_deref())?;
    let _raw = term::RawMode::enter()?;
    let mut keys = input::reader();
    let mut renderer = Renderer::new();
    let mut app = App::new(path);

    app.refresh().await;
    redraw(&mut renderer, &app)?;

    let mut ticker = tokio::time::interval(REFRESH);
    ticker.tick().await; // the first tick fires immediately; drop it

    loop {
        tokio::select! {
            key = keys.recv() => match key {
                Some(k) => if matches!(app.on_key(k).await, Flow::Quit) { break },
                None => break,
            },
            _ = ticker.tick() => {
                if matches!(app.overlay, Overlay::None) {
                    app.refresh().await;
                }
            }
        }
        redraw(&mut renderer, &app)?;
    }
    Ok(())
}

fn redraw(renderer: &mut Renderer, app: &App) -> Result<()> {
    let (w, h) = term::size();
    renderer.draw(app.view(w as usize, h as usize), w, h)?;
    Ok(())
}

enum Flow {
    Continue,
    Quit,
}

enum Status {
    Connecting,
    Connected,
    Error(String),
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
    PppoePicker {
        names: Vec<String>,
        sel: usize,
    },
    ConfirmStop {
        name: String,
    },
}

struct App {
    socket: PathBuf,
    snap: Option<ClientSnapshotBody>,
    status: Status,
    toast: Option<(String, bool, Instant)>,
    sel: usize,
    overlay: Overlay,
}

impl App {
    fn new(socket: PathBuf) -> App {
        App {
            socket,
            snap: None,
            status: Status::Connecting,
            toast: None,
            sel: 0,
            overlay: Overlay::None,
        }
    }

    /// Configured server profiles in config order; the daemon reports them
    /// with their dialable fields only.
    fn servers(&self) -> Vec<ClientServerEntry> {
        self.snap
            .as_ref()
            .map(|s| s.servers.clone())
            .unwrap_or_default()
    }

    /// Forwards as the daemon reports them (tcp before udp, sorted by port).
    fn forwards(&self) -> Vec<ClientForwardEntry> {
        self.snap
            .as_ref()
            .map(|s| s.forwards.clone())
            .unwrap_or_default()
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

    async fn refresh(&mut self) {
        let fetch = client_admin::snapshot(&self.socket);
        match tokio::time::timeout(NET_TIMEOUT, fetch).await {
            Ok(Ok(snap)) => {
                self.snap = Some(snap);
                self.status = Status::Connected;
                self.clamp_sel();
            }
            Ok(Err(e)) => self.status = Status::Error(e.to_string()),
            Err(_) => self.status = Status::Error("request timed out".to_string()),
        }
    }

    /// Send one mutation, surface its verdict as a toast, then refetch so the
    /// view reflects the client's post-mutation state. Acceptance is not
    /// completion: an accepted switch is a teardown-then-bringup that the
    /// polled snapshots track.
    async fn apply(&mut self, req: ClientMsg, ok_msg: String) {
        let send = client_admin::mutate(&self.socket, req);
        match tokio::time::timeout(NET_TIMEOUT, send).await {
            Ok(Ok((true, _))) => self.set_toast(ok_msg, false),
            Ok(Ok((false, msg))) => self.set_toast(refusal_text(msg), true),
            Ok(Err(e)) => self.set_toast(e.to_string(), true),
            Err(_) => self.set_toast("request timed out".to_string(), true),
        }
        self.refresh().await;
    }

    fn set_toast(&mut self, msg: String, is_err: bool) {
        self.toast = Some((msg, is_err, Instant::now()));
    }

    async fn on_key(&mut self, k: Key) -> Flow {
        if matches!(k, Key::CtrlC) {
            return Flow::Quit;
        }
        match &self.overlay {
            Overlay::None => self.on_key_normal(k).await,
            Overlay::ConfirmSelect { .. } => self.on_key_confirm_select(k).await,
            Overlay::FwdForm { .. } => self.on_key_form(k).await,
            Overlay::AddServer { .. } => self.on_key_add_server(k).await,
            Overlay::AddForward { .. } => self.on_key_add_forward(k).await,
            Overlay::ConfirmRemove { .. } => self.on_key_confirm_remove(k).await,
            Overlay::ConfirmRemoveForward { .. } => self.on_key_confirm_remove_forward(k).await,
            Overlay::ConfirmDisconnect => self.on_key_confirm_disconnect(k).await,
            Overlay::PppoePicker { .. } => self.on_key_picker(k).await,
            Overlay::ConfirmStop { .. } => self.on_key_confirm_stop(k).await,
        }
    }

    async fn on_key_normal(&mut self, k: Key) -> Flow {
        match k {
            Key::Char('q') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
            Key::Down | Key::Char('j') if self.sel + 1 < self.item_count() => {
                self.sel += 1;
            }
            Key::Char('r') => self.refresh().await,
            Key::Enter => {
                let servers = self.servers();
                if self.sel < servers.len() {
                    let s = &servers[self.sel];
                    if self.active_name() == Some(s.name.as_str()) {
                        self.overlay = Overlay::ConfirmSelect {
                            name: s.name.clone(),
                        };
                    } else {
                        let name = s.name.clone();
                        self.apply(
                            ClientMsg::SelectServer { name: name.clone() },
                            format!("switching to {name}: teardown and redial"),
                        )
                        .await;
                    }
                } else if let Some(f) = self.forwards().get(self.sel - servers.len()) {
                    self.overlay = Overlay::FwdForm {
                        proto: f.proto,
                        port: f.port,
                        enabled: f.enabled,
                        proxy: f.proxy,
                        idle: if f.idle_secs > 0 {
                            f.idle_secs.to_string()
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
                let servers = self.servers();
                if let Some(s) = servers.get(self.sel) {
                    self.overlay = Overlay::ConfirmRemove {
                        name: s.name.clone(),
                    };
                } else if let Some(f) = self.forwards().get(self.sel - servers.len()) {
                    self.overlay = Overlay::ConfirmRemoveForward {
                        proto: f.proto,
                        port: f.port,
                    };
                }
            }
            Key::Char(' ') => {
                let servers = self.servers();
                if self.sel >= servers.len() {
                    if let Some(f) = self.forwards().get(self.sel - servers.len()) {
                        // Full-state replace: the row's own snapshot state
                        // supplies proxy/idle, only the flag flips.
                        let req = ClientMsg::SetForwardOptions {
                            proto: f.proto,
                            port: f.port,
                            enabled: !f.enabled,
                            proxy: f.proxy,
                            idle_secs: f.idle_secs,
                        };
                        let verb = if f.enabled { "disabled" } else { "enabled" };
                        let msg = format!("{verb} {}:{}", proto_name(f.proto), f.port);
                        self.apply(req, msg).await;
                    }
                }
            }
            // Connect is the offline park's exit; while anything else runs,
            // select-server is the retarget verb and the key does nothing.
            Key::Char('c') if self.mode() == Some(SessionMode::Offline) => {
                self.apply(
                    ClientMsg::Connect {
                        name: String::new(),
                    },
                    "connecting: bringing up the boot session body".to_string(),
                )
                .await;
            }
            Key::Char('d') if self.mode().is_some_and(|m| m != SessionMode::Offline) => {
                self.overlay = Overlay::ConfirmDisconnect;
            }
            Key::Char('p') => {
                let names = self
                    .snap
                    .as_ref()
                    .map(|s| s.pppoe.clone())
                    .unwrap_or_default();
                if names.is_empty() {
                    self.set_toast("no pppoe sessions configured".to_string(), true);
                } else {
                    self.overlay = Overlay::PppoePicker { names, sel: 0 };
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

    async fn on_key_confirm_select(&mut self, k: Key) -> Flow {
        match k {
            Key::Char('y') | Key::Enter => {
                if let Overlay::ConfirmSelect { name } = &self.overlay {
                    let name = name.clone();
                    self.overlay = Overlay::None;
                    self.apply(
                        ClientMsg::SelectServer { name: name.clone() },
                        format!("re-selected {name}: teardown and redial"),
                    )
                    .await;
                }
            }
            Key::Char('n') | Key::Esc => self.overlay = Overlay::None,
            _ => {}
        }
        Flow::Continue
    }

    async fn on_key_form(&mut self, k: Key) -> Flow {
        match k {
            Key::Esc => self.overlay = Overlay::None,
            Key::Tab | Key::Down => {
                if let Overlay::FwdForm { field, .. } = &mut self.overlay {
                    *field = (*field + 1) % 3;
                }
            }
            Key::Up => {
                if let Overlay::FwdForm { field, .. } = &mut self.overlay {
                    *field = (*field + 2) % 3;
                }
            }
            Key::Left | Key::Right | Key::Char(' ') => {
                if let Overlay::FwdForm {
                    field,
                    enabled,
                    proxy,
                    ..
                } = &mut self.overlay
                {
                    match field {
                        0 => *enabled = !*enabled,
                        1 => *proxy = !*proxy,
                        _ => {}
                    }
                }
            }
            Key::Backspace => {
                if let Overlay::FwdForm { field, idle, .. } = &mut self.overlay {
                    if *field == 2 {
                        idle.pop();
                    }
                }
            }
            Key::Char(c) if c.is_ascii_digit() => {
                if let Overlay::FwdForm { field, idle, .. } = &mut self.overlay {
                    if *field == 2 && idle.len() < 9 {
                        idle.push(c);
                    }
                }
            }
            Key::Enter => return self.submit_form().await,
            _ => {}
        }
        Flow::Continue
    }

    async fn submit_form(&mut self) -> Flow {
        let (proto, port, enabled, proxy, idle) = match &self.overlay {
            Overlay::FwdForm {
                proto,
                port,
                enabled,
                proxy,
                idle,
                ..
            } => (*proto, *port, *enabled, *proxy, idle.clone()),
            _ => return Flow::Continue,
        };
        // Empty clears the idle override; the field is digits-only and
        // length-capped, so any non-empty value parses.
        let idle_secs: u32 = idle.parse().unwrap_or(0);
        self.overlay = Overlay::None;
        // Full-state replace: every option is always sent, so what lands is
        // exactly what the form showed.
        let req = ClientMsg::SetForwardOptions {
            proto,
            port,
            enabled,
            proxy,
            idle_secs,
        };
        self.apply(
            req,
            format!(
                "set {}:{port} {}{}",
                proto_name(proto),
                crate::admin::fwd_opts(proxy, idle_secs),
                if enabled { "" } else { "  off" }
            ),
        )
        .await;
        Flow::Continue
    }

    async fn on_key_add_server(&mut self, k: Key) -> Flow {
        match k {
            Key::Esc => self.overlay = Overlay::None,
            Key::Tab | Key::Down => {
                if let Overlay::AddServer { field, .. } = &mut self.overlay {
                    *field = (*field + 1) % 4;
                }
            }
            Key::Up => {
                if let Overlay::AddServer { field, .. } = &mut self.overlay {
                    *field = (*field + 3) % 4;
                }
            }
            Key::Left => {
                if let Overlay::AddServer {
                    field, transport, ..
                } = &mut self.overlay
                {
                    if *field == 2 {
                        *transport = match transport {
                            Transport::Auto => Transport::Tcp,
                            Transport::Udp => Transport::Auto,
                            Transport::Tcp => Transport::Udp,
                        };
                    }
                }
            }
            Key::Right => {
                if let Overlay::AddServer {
                    field, transport, ..
                } = &mut self.overlay
                {
                    if *field == 2 {
                        *transport = match transport {
                            Transport::Auto => Transport::Udp,
                            Transport::Udp => Transport::Tcp,
                            Transport::Tcp => Transport::Auto,
                        };
                    }
                }
            }
            Key::Backspace => {
                if let Overlay::AddServer {
                    field,
                    name,
                    addr,
                    secret,
                    ..
                } = &mut self.overlay
                {
                    match field {
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
                    }
                }
            }
            // The daemon refuses control characters; keeping them out of the
            // form spares a doomed round trip.
            Key::Char(c) if !c.is_control() => {
                if let Overlay::AddServer {
                    field,
                    name,
                    addr,
                    secret,
                    ..
                } = &mut self.overlay
                {
                    match field {
                        0 => name.push(c),
                        1 => addr.push(c),
                        3 => secret.push(c),
                        _ => {}
                    }
                }
            }
            Key::Enter => return self.submit_add_server().await,
            _ => {}
        }
        Flow::Continue
    }

    async fn submit_add_server(&mut self) -> Flow {
        let (name, addr, transport, secret) = match &self.overlay {
            Overlay::AddServer {
                name,
                addr,
                transport,
                secret,
                ..
            } => (name.clone(), addr.clone(), *transport, secret.clone()),
            _ => return Flow::Continue,
        };
        self.overlay = Overlay::None;
        // The ok toast names the profile only; the secret is never echoed.
        let req = ClientMsg::AddServer {
            name: name.clone(),
            addr,
            secret: ServerSecret(secret),
            transport,
        };
        self.apply(req, format!("added {name}")).await;
        Flow::Continue
    }

    async fn on_key_add_forward(&mut self, k: Key) -> Flow {
        match k {
            Key::Esc => self.overlay = Overlay::None,
            Key::Tab | Key::Down => {
                if let Overlay::AddForward { field, .. } = &mut self.overlay {
                    *field = (*field + 1) % 6;
                }
            }
            Key::Up => {
                if let Overlay::AddForward { field, .. } = &mut self.overlay {
                    *field = (*field + 5) % 6;
                }
            }
            Key::Left | Key::Right => {
                if let Overlay::AddForward { field, .. } = &mut self.overlay {
                    let field = *field;
                    self.toggle_add_forward(field);
                }
            }
            Key::Backspace => {
                if let Overlay::AddForward {
                    field,
                    port,
                    target,
                    idle,
                    ..
                } = &mut self.overlay
                {
                    match field {
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
                    }
                }
            }
            Key::Enter => return self.submit_add_forward().await,
            Key::Char(c) => {
                let toggled = if let Overlay::AddForward {
                    field,
                    port,
                    target,
                    idle,
                    ..
                } = &mut self.overlay
                {
                    match field {
                        1 if c.is_ascii_digit() && port.len() < 5 => {
                            port.push(c);
                            None
                        }
                        // The daemon refuses control characters; space stays
                        // typeable, the toggle fields own it elsewhere.
                        2 if !c.is_control() => {
                            target.push(c);
                            None
                        }
                        5 if c.is_ascii_digit() && idle.len() < 9 => {
                            idle.push(c);
                            None
                        }
                        f if c == ' ' => Some(*f),
                        _ => None,
                    }
                } else {
                    None
                };
                if let Some(field) = toggled {
                    self.toggle_add_forward(field);
                }
            }
            _ => {}
        }
        Flow::Continue
    }

    /// Flip the add-forward form's picker or toggle at `field`. Moving the
    /// picker to udp clears the proxy toggle, and the proxy toggle is inert
    /// while udp is picked: the daemon refuses proxy on udp.
    fn toggle_add_forward(&mut self, field: u8) {
        if let Overlay::AddForward {
            proto,
            proxy,
            enabled,
            ..
        } = &mut self.overlay
        {
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
    }

    async fn submit_add_forward(&mut self) -> Flow {
        let (proto, port, target, proxy, enabled, idle) = match &self.overlay {
            Overlay::AddForward {
                proto,
                port,
                target,
                proxy,
                enabled,
                idle,
                ..
            } => (
                *proto,
                port.clone(),
                target.clone(),
                *proxy,
                *enabled,
                idle.clone(),
            ),
            _ => return Flow::Continue,
        };
        // A submit without a usable port keeps the form open to fix it.
        let Some(port) = port.parse::<u16>().ok().filter(|p| *p != 0) else {
            self.set_toast("port must be 1-65535".to_string(), true);
            return Flow::Continue;
        };
        // The digits-only, length-capped idle field parses whenever non-empty;
        // empty means no override.
        let idle_secs: u32 = idle.parse().unwrap_or(0);
        self.overlay = Overlay::None;
        // A blank target rides as the empty sentinel; the daemon resolves the
        // 127.0.0.1:PORT default the form displayed.
        let req = ClientMsg::AddForward {
            proto,
            port,
            target,
            proxy,
            idle_secs,
            enabled,
        };
        self.apply(req, format!("added {}:{port}", proto_name(proto)))
            .await;
        Flow::Continue
    }

    async fn on_key_confirm_remove_forward(&mut self, k: Key) -> Flow {
        match k {
            Key::Char('y') | Key::Enter => {
                if let Overlay::ConfirmRemoveForward { proto, port } = self.overlay {
                    self.overlay = Overlay::None;
                    self.apply(
                        ClientMsg::RemoveForward { proto, port },
                        format!("removed {}:{port}", proto_name(proto)),
                    )
                    .await;
                }
            }
            Key::Char('n') | Key::Esc => self.overlay = Overlay::None,
            _ => {}
        }
        Flow::Continue
    }

    async fn on_key_confirm_remove(&mut self, k: Key) -> Flow {
        match k {
            Key::Char('y') | Key::Enter => {
                if let Overlay::ConfirmRemove { name } = &self.overlay {
                    let name = name.clone();
                    self.overlay = Overlay::None;
                    self.apply(
                        ClientMsg::RemoveServer { name: name.clone() },
                        format!("removed {name}"),
                    )
                    .await;
                }
            }
            Key::Char('n') | Key::Esc => self.overlay = Overlay::None,
            _ => {}
        }
        Flow::Continue
    }

    async fn on_key_confirm_disconnect(&mut self, k: Key) -> Flow {
        match k {
            Key::Char('y') | Key::Enter => {
                self.overlay = Overlay::None;
                self.apply(
                    ClientMsg::Disconnect,
                    "disconnected: nothing dials until connect".to_string(),
                )
                .await;
            }
            Key::Char('n') | Key::Esc => self.overlay = Overlay::None,
            _ => {}
        }
        Flow::Continue
    }

    async fn on_key_picker(&mut self, k: Key) -> Flow {
        match k {
            Key::Esc => self.overlay = Overlay::None,
            Key::Up | Key::Char('k') => {
                if let Overlay::PppoePicker { sel, .. } = &mut self.overlay {
                    *sel = sel.saturating_sub(1);
                }
            }
            Key::Down | Key::Char('j') => {
                if let Overlay::PppoePicker { names, sel } = &mut self.overlay {
                    if *sel + 1 < names.len() {
                        *sel += 1;
                    }
                }
            }
            Key::Enter => {
                if let Overlay::PppoePicker { names, sel } = &self.overlay {
                    let name = names[*sel].clone();
                    self.overlay = Overlay::None;
                    self.apply(
                        ClientMsg::SpawnPppoe { name: name.clone() },
                        format!("spawning pppoe {name}"),
                    )
                    .await;
                }
            }
            _ => {}
        }
        Flow::Continue
    }

    async fn on_key_confirm_stop(&mut self, k: Key) -> Flow {
        match k {
            Key::Char('y') | Key::Enter => {
                if let Overlay::ConfirmStop { name } = &self.overlay {
                    let name = name.clone();
                    self.overlay = Overlay::None;
                    self.apply(
                        ClientMsg::StopSession { name: name.clone() },
                        format!("stopping pppoe {name}: falling back to the base mode"),
                    )
                    .await;
                }
            }
            Key::Char('n') | Key::Esc => self.overlay = Overlay::None,
            _ => {}
        }
        Flow::Continue
    }

    // ---- rendering -------------------------------------------------------

    fn view(&self, w: usize, h: usize) -> Vec<String> {
        if w < 24 || h < 8 {
            return vec![" ".repeat(w); h];
        }
        let servers = self.servers();
        let forwards = self.forwards();

        let mut lines: Vec<String> = Vec::with_capacity(h);
        lines.push(frame::top(w, self.header_left(), self.status_seg()));

        let mut content: Vec<String> = Vec::new();
        content.push(frame::blank(w));
        content.push(frame::row(w, section_head("SERVERS", servers.len())));
        if servers.is_empty() {
            let msg = match self.active_name() {
                Some(active) => {
                    format!("  (no configured profiles; dialing {})", sanitize(active))
                }
                None => "  (none)".to_string(),
            };
            content.push(frame::row(w, muted_line(&msg)));
        }
        for (i, s) in servers.iter().enumerate() {
            content.push(frame::row(w, self.server_row(s, i)));
        }
        content.push(frame::blank(w));
        content.push(frame::row(w, section_title("SESSION")));
        for l in self.session_lines() {
            content.push(frame::row(w, l));
        }
        content.push(frame::blank(w));
        content.push(frame::row(w, section_head("FORWARDS", forwards.len())));
        if forwards.is_empty() {
            content.push(frame::row(w, muted_line("  (none)")));
        }
        for (i, f) in forwards.iter().enumerate() {
            content.push(frame::row(w, self.forward_row(f, servers.len() + i)));
        }

        // Reserve the last four rows: divider, toast, hints, bottom border.
        let area = h.saturating_sub(5);
        content.truncate(area);
        while content.len() < area {
            content.push(frame::blank(w));
        }
        lines.extend(content);

        lines.push(frame::divider(w));
        lines.push(frame::row(w, self.toast_line()));
        lines.push(frame::row(w, self.hint_line(servers.len())));
        lines.push(frame::bottom(w));

        if !matches!(self.overlay, Overlay::None) {
            let panel = self.overlay_panel(w, h);
            let top_row = h.saturating_sub(panel.len()) / 2;
            frame::overlay(&mut lines, &panel, top_row.max(1));
        }
        lines
    }

    fn header_left(&self) -> Line {
        let mut l = Line::new();
        l.add(ACCENT, "zeronat");
        l.add(MUTED, "  client  ");
        l.add(PLAIN, &self.socket.display().to_string());
        if let Some(snap) = &self.snap {
            l.add(MUTED, &format!("  active {}", sanitize(&snap.active)));
        }
        l
    }

    fn status_seg(&self) -> Line {
        let mut l = Line::new();
        match &self.status {
            Status::Connecting => {
                l.add(MUTED, "● connecting");
            }
            Status::Connected => {
                l.add(GOOD, "● ");
                l.add(MUTED, "connected");
            }
            Status::Error(e) => {
                l.add(BAD, "● ");
                l.add(MUTED, &trunc(&sanitize(e), 28));
            }
        }
        l
    }

    fn server_row(&self, s: &ClientServerEntry, idx: usize) -> Line {
        let selected = self.sel == idx && matches!(self.overlay, Overlay::None);
        let is_active = self.active_name() == Some(s.name.as_str());
        let mut l = Line::new();
        caret(&mut l, selected);
        l.add(
            if is_active { BOLD } else { PLAIN },
            &format!("{:<18}", trunc(&sanitize(&s.name), 18)),
        );
        l.add(MUTED, &format!("{:<22}", trunc(&sanitize(&s.addr), 22)));
        l.add(MUTED, &format!("{:<6}", transport_label(s.transport)));
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

    fn session_lines(&self) -> Vec<Line> {
        let snap = match &self.snap {
            Some(snap) => snap,
            None => return vec![muted_line("  (no snapshot yet)")],
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
                l.add(ACCENT, &format!("  {}", sanitize(&snap.session)));
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
            p.add(style, &format!("{txt:<12}"));
            p.add(PLAIN, "link ");
            let (txt, style) = link_view(snap.phase);
            p.add(style, txt);
            v.push(p);
        }
        v
    }

    fn forward_row(&self, f: &ClientForwardEntry, idx: usize) -> Line {
        let selected = self.sel == idx && matches!(self.overlay, Overlay::None);
        let mut l = Line::new();
        caret(&mut l, selected);
        l.add(proto_style(f.proto), proto_name(f.proto));
        l.add(PLAIN, &format!(":{:<6}", f.port));
        l.add(MUTED, "-> ");
        l.add(PLAIN, &format!("{:<21}", trunc(&sanitize(&f.target), 21)));
        l.add(
            MUTED,
            &format!("  {}", crate::admin::fwd_opts(f.proxy, f.idle_secs)),
        );
        if !f.enabled {
            l.add(BAD, "  off");
        }
        l
    }

    fn toast_line(&self) -> Line {
        let mut l = Line::new();
        if let Some((msg, is_err, at)) = &self.toast {
            if at.elapsed() < TOAST_TTL {
                l.add(
                    if *is_err { BAD } else { GOOD },
                    if *is_err { "✕ " } else { "✓ " },
                );
                l.add(if *is_err { WARN } else { MUTED }, &sanitize(msg));
            }
        }
        l
    }

    fn hint_line(&self, server_count: usize) -> Line {
        let mut l = Line::new();
        match &self.overlay {
            Overlay::None => {
                hint(&mut l, "↑↓", "move");
                if self.item_count() > 0 {
                    if self.sel < server_count {
                        hint(&mut l, "⏎", "select");
                        hint(&mut l, "x", "remove");
                    } else {
                        hint(&mut l, "⏎", "edit");
                        hint(&mut l, "␣", "toggle");
                        hint(&mut l, "x", "remove");
                    }
                }
                hint(&mut l, "a", "add");
                hint(&mut l, "f", "add fwd");
                // Connect is offered only while offline; disconnect while
                // anything (a body or the idle dial) is up.
                match self.mode() {
                    Some(SessionMode::Offline) => hint(&mut l, "c", "connect"),
                    Some(_) => hint(&mut l, "d", "disconnect"),
                    None => {}
                }
                if self.snap.as_ref().is_some_and(|s| !s.pppoe.is_empty()) {
                    hint(&mut l, "p", "pppoe");
                }
                if self.live_pppoe().is_some() {
                    hint(&mut l, "s", "stop pppoe");
                }
                hint(&mut l, "r", "refresh");
                hint(&mut l, "q", "quit");
            }
            Overlay::FwdForm { .. } => {
                hint(&mut l, "tab", "field");
                hint(&mut l, "←→", "toggle");
                hint(&mut l, "⏎", "apply");
                hint(&mut l, "esc", "cancel");
            }
            Overlay::AddServer { .. } => {
                hint(&mut l, "tab", "field");
                hint(&mut l, "←→", "transport");
                hint(&mut l, "⏎", "add");
                hint(&mut l, "esc", "cancel");
            }
            Overlay::AddForward { .. } => {
                hint(&mut l, "tab", "field");
                hint(&mut l, "←→", "toggle");
                hint(&mut l, "⏎", "add");
                hint(&mut l, "esc", "cancel");
            }
            Overlay::PppoePicker { .. } => {
                hint(&mut l, "↑↓", "choose");
                hint(&mut l, "⏎", "spawn");
                hint(&mut l, "esc", "cancel");
            }
            Overlay::ConfirmSelect { .. }
            | Overlay::ConfirmRemove { .. }
            | Overlay::ConfirmRemoveForward { .. }
            | Overlay::ConfirmDisconnect
            | Overlay::ConfirmStop { .. } => {
                hint(&mut l, "y", "confirm");
                hint(&mut l, "n", "cancel");
            }
        }
        l
    }

    fn overlay_panel(&self, w: usize, h: usize) -> Vec<String> {
        match &self.overlay {
            Overlay::None => Vec::new(),
            Overlay::ConfirmSelect { name } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "confirm"));
                let mut l = Line::new();
                l.add(
                    WARN,
                    &format!(
                        "{} is already active; re-select and redial?",
                        sanitize(name)
                    ),
                );
                p.push(frame::row_center(w, l));
                p.push(frame::divider(w));
                p
            }
            Overlay::FwdForm {
                proto,
                port,
                enabled,
                proxy,
                idle,
                field,
            } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(
                    w,
                    &format!("edit forward  {}:{}", proto_name(*proto), port),
                ));
                p.push(frame::row(w, form_bool("enabled", *enabled, *field == 0)));
                p.push(frame::row(w, form_bool("proxy", *proxy, *field == 1)));
                p.push(frame::row(w, form_text("idle", idle, *field == 2)));
                p.push(frame::row(
                    w,
                    muted_line("  idle in seconds; empty clears the override"),
                ));
                p.push(frame::divider(w));
                p
            }
            Overlay::AddServer {
                name,
                addr,
                transport,
                secret,
                field,
            } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "add server"));
                p.push(frame::row(w, form_text("name", name, *field == 0)));
                p.push(frame::row(w, form_text("addr", addr, *field == 1)));
                p.push(frame::row(
                    w,
                    form_pick("transport", transport_label(*transport), *field == 2),
                ));
                // One * per typed character; the secret itself never renders.
                p.push(frame::row(
                    w,
                    form_text("secret", &"*".repeat(secret.chars().count()), *field == 3),
                ));
                p.push(frame::row(
                    w,
                    muted_line("  addr is \"dht\" or host:port; the secret is sent, never shown"),
                ));
                p.push(frame::divider(w));
                p
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
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "add forward"));
                p.push(frame::row(
                    w,
                    form_pick("proto", proto_name(*proto), *field == 0),
                ));
                p.push(frame::row(w, form_text("port", port, *field == 1)));
                // A blank target renders as the default it resolves to.
                let default = if port.is_empty() {
                    "127.0.0.1:PORT".to_string()
                } else {
                    format!("127.0.0.1:{port}")
                };
                p.push(frame::row(
                    w,
                    form_text_default("target", target, &default, *field == 2),
                ));
                p.push(frame::row(w, form_bool("proxy", *proxy, *field == 3)));
                p.push(frame::row(w, form_bool("enabled", *enabled, *field == 4)));
                p.push(frame::row(w, form_text("idle", idle, *field == 5)));
                p.push(frame::row(
                    w,
                    muted_line("  blank target means the 127.0.0.1:PORT default; idle in seconds"),
                ));
                p.push(frame::divider(w));
                p
            }
            Overlay::ConfirmRemove { name } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "confirm"));
                let mut l = Line::new();
                l.add(
                    WARN,
                    &format!("remove server {} from the config?", sanitize(name)),
                );
                p.push(frame::row_center(w, l));
                p.push(frame::divider(w));
                p
            }
            Overlay::ConfirmRemoveForward { proto, port } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "confirm"));
                let mut l = Line::new();
                l.add(
                    WARN,
                    &format!(
                        "remove forward {}:{port} and drop its connections?",
                        proto_name(*proto)
                    ),
                );
                p.push(frame::row_center(w, l));
                p.push(frame::divider(w));
                p
            }
            Overlay::ConfirmDisconnect => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "confirm"));
                let mut l = Line::new();
                l.add(WARN, "disconnect and stay offline until connect?");
                p.push(frame::row_center(w, l));
                p.push(frame::divider(w));
                p
            }
            Overlay::PppoePicker { names, sel } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "spawn pppoe"));
                // Keep the panel inside the terminal: show a window of names
                // around the selection, with markers when some are off-screen.
                let (start, end) = window(*sel, names.len(), h.saturating_sub(7).max(1));
                if start > 0 {
                    p.push(frame::row(w, muted_line(&format!("  ↑ {start} more"))));
                }
                for (i, name) in names.iter().enumerate().take(end).skip(start) {
                    let mut l = Line::new();
                    caret(&mut l, i == *sel);
                    l.add(if i == *sel { BOLD } else { PLAIN }, &sanitize(name));
                    p.push(frame::row(w, l));
                }
                if end < names.len() {
                    p.push(frame::row(
                        w,
                        muted_line(&format!("  ↓ {} more", names.len() - end)),
                    ));
                }
                p.push(frame::divider(w));
                p
            }
            Overlay::ConfirmStop { name } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "confirm"));
                let mut l = Line::new();
                l.add(
                    WARN,
                    &format!(
                        "stop pppoe {} and fall back to the base mode?",
                        sanitize(name)
                    ),
                );
                p.push(frame::row_center(w, l));
                p.push(frame::divider(w));
                p
            }
        }
    }
}

// ---- small builders --------------------------------------------------------

/// A refused config save means the mutation already applied in memory and
/// only the disk write failed, unlike a validation refusal, which changed
/// nothing. Flag the save case so the two read differently; the daemon's own
/// message is kept verbatim in both.
fn refusal_text(msg: String) -> String {
    if msg.starts_with("client rejected config save") || msg.starts_with("config save task failed")
    {
        format!("{msg} (applied in memory, disk stale)")
    } else {
        msg
    }
}

fn proto_style(p: Proto) -> Style {
    match p {
        Proto::Tcp => TCP,
        Proto::Udp => UDP,
    }
}

fn transport_label(t: Transport) -> &'static str {
    match t {
        Transport::Auto => "auto",
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    }
}

fn phase_view(p: PppPhase) -> (&'static str, Style) {
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
fn link_status_view(l: LinkStatus) -> (&'static str, Style) {
    match l {
        LinkStatus::Offline => ("offline", MUTED),
        LinkStatus::Dialing => ("dialing", WARN),
        LinkStatus::Connected => ("connected", GOOD),
        LinkStatus::Backoff => ("backoff", BAD),
    }
}

/// The PPP link, folded to up/down for the sessions panel.
fn link_view(p: PppPhase) -> (&'static str, Style) {
    match p {
        PppPhase::Established => ("up", GOOD),
        PppPhase::LinkDown | PppPhase::Dead => ("down", BAD),
        PppPhase::Discovery | PppPhase::Negotiating => ("negotiating", WARN),
        PppPhase::None => ("-", MUTED),
    }
}

fn caret(l: &mut Line, selected: bool) {
    if selected {
        l.add(ACCENT, "▸ ");
    } else {
        l.add(PLAIN, "  ");
    }
}

fn hint(l: &mut Line, key: &str, label: &str) {
    l.add(ACCENT, key);
    l.add(MUTED, &format!(" {label}   "));
}

fn section_head(name: &str, count: usize) -> Line {
    let mut l = section_title(name);
    l.add(MUTED, &format!("  {count}"));
    l
}

fn section_title(name: &str) -> Line {
    let mut l = Line::new();
    l.add(Style::fg(Color::Accent).bold(), name);
    l
}

fn muted_line(text: &str) -> Line {
    let mut l = Line::new();
    l.add(MUTED, text);
    l
}

fn form_bool(label: &str, value: bool, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.add(MUTED, &format!("{label:<10}"));
    l.add(
        if focused { BOLD.reverse() } else { BOLD },
        if value { " on " } else { " off " },
    );
    l
}

fn form_pick(label: &str, value: &str, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.add(MUTED, &format!("{label:<10}"));
    l.add(
        if focused { BOLD.reverse() } else { BOLD },
        &format!(" {value} "),
    );
    l
}

fn form_text(label: &str, value: &str, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.add(MUTED, &format!("{label:<10}"));
    l.add(PLAIN, value);
    if focused {
        l.add(ACCENT, "_");
    }
    l
}

/// A text field whose empty value renders the default it resolves to, muted.
fn form_text_default(label: &str, value: &str, default: &str, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.add(MUTED, &format!("{label:<10}"));
    if value.is_empty() {
        l.add(MUTED, default);
    } else {
        l.add(PLAIN, value);
    }
    if focused {
        l.add(ACCENT, "_");
    }
    l
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}

/// Strip control characters from peer-supplied text before it reaches the
/// terminal, so a crafted profile name, target, or error string cannot inject
/// escape sequences that corrupt the frame.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// A `[start, end)` window of `len` items at most `max` rows tall, kept centred
/// on `sel` so the selection stays visible when the list is scrolled.
fn window(sel: usize, len: usize, max: usize) -> (usize, usize) {
    if len <= max {
        return (0, len);
    }
    let start = sel.saturating_sub(max / 2).min(len - max);
    (start, start + max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clientproto::LinkStatus;

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
        let mut app = app_with(snap());
        app.on_key(Key::Char('a')).await;
        assert!(matches!(app.overlay, Overlay::AddServer { .. }));
        for _ in 0..3 {
            app.on_key(Key::Tab).await;
        }
        for c in "hunter2".chars() {
            app.on_key(Key::Char(c)).await;
        }
        let rows = plain_view(&app);
        assert!(
            rows.iter().any(|r| r.contains("*******")),
            "expected one * per typed char:\n{}",
            rows.join("\n")
        );
        assert!(
            !rows.iter().any(|r| r.contains("hunter2")),
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
                assert_eq!(secret, "hunter2");
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
            !rows.iter().any(|r| r.contains("hunter2")),
            "the secret text must never render:\n{}",
            rows.join("\n")
        );
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
