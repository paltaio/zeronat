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
    ClientForwardEntry, ClientMsg, ClientServerEntry, ClientSnapshotBody, PppPhase, SessionMode,
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
    /// Full option state for one forward; submit always sends both fields.
    FwdForm {
        proto: Proto,
        port: u16,
        proxy: bool,
        idle: String,
        field: u8,
    },
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
            Key::Tab | Key::Up | Key::Down => {
                if let Overlay::FwdForm { field, .. } = &mut self.overlay {
                    *field = (*field + 1) % 2;
                }
            }
            Key::Left | Key::Right | Key::Char(' ') => {
                if let Overlay::FwdForm { field, proxy, .. } = &mut self.overlay {
                    if *field == 0 {
                        *proxy = !*proxy;
                    }
                }
            }
            Key::Backspace => {
                if let Overlay::FwdForm { field, idle, .. } = &mut self.overlay {
                    if *field == 1 {
                        idle.pop();
                    }
                }
            }
            Key::Char(c) if c.is_ascii_digit() => {
                if let Overlay::FwdForm { field, idle, .. } = &mut self.overlay {
                    if *field == 1 && idle.len() < 9 {
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
        let (proto, port, proxy, idle) = match &self.overlay {
            Overlay::FwdForm {
                proto,
                port,
                proxy,
                idle,
                ..
            } => (*proto, *port, *proxy, idle.clone()),
            _ => return Flow::Continue,
        };
        // Empty clears the idle override; the field is digits-only and
        // length-capped, so any non-empty value parses.
        let idle_secs: u32 = idle.parse().unwrap_or(0);
        self.overlay = Overlay::None;
        // Full-state replace: both options are always sent, so what lands is
        // exactly what the form showed.
        let req = ClientMsg::SetForwardOptions {
            proto,
            port,
            proxy,
            idle_secs,
        };
        self.apply(
            req,
            format!(
                "set {}:{port} {}",
                proto_name(proto),
                crate::admin::fwd_opts(proxy, idle_secs)
            ),
        )
        .await;
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
            // a server it is not dialing. Only a pppoe body reports a phase.
            if let Some(snap) = &self.snap {
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
                        hint(&mut l, "⏎", "select server");
                    } else {
                        hint(&mut l, "⏎", "edit forward");
                    }
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
            Overlay::PppoePicker { .. } => {
                hint(&mut l, "↑↓", "choose");
                hint(&mut l, "⏎", "spawn");
                hint(&mut l, "esc", "cancel");
            }
            Overlay::ConfirmSelect { .. } | Overlay::ConfirmStop { .. } => {
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
                proxy,
                idle,
                field,
            } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(
                    w,
                    &format!("edit forward  {}:{}", proto_name(*proto), port),
                ));
                p.push(frame::row(w, form_bool("proxy", *proxy, *field == 0)));
                p.push(frame::row(w, form_text("idle", idle, *field == 1)));
                p.push(frame::row(
                    w,
                    muted_line("  idle in seconds; empty clears the override"),
                ));
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
    l.add(MUTED, &format!("{label:<7}"));
    l.add(
        if focused { BOLD.reverse() } else { BOLD },
        if value { " on " } else { " off " },
    );
    l
}

fn form_text(label: &str, value: &str, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.add(MUTED, &format!("{label:<7}"));
    l.add(PLAIN, value);
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
                proxy,
                idle,
                field,
            } => {
                assert_eq!(*proto, Proto::Tcp);
                assert_eq!(*port, 443);
                assert!(*proxy);
                assert_eq!(idle, "600");
                assert_eq!(*field, 0);
            }
            _ => panic!("expected the forward editor"),
        }
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
