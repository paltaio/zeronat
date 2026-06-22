//! The zeronat admin console: a live, controllable view of one server.
//!
//! Every frame is rebuilt from the latest snapshot and diffed by the renderer.
//! Snapshots are polled on an interval; each keypress that mutates the server
//! issues one admin mutation and then refetches, so the screen always reflects
//! the server's own view rather than an optimistic local guess.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::admin;
use crate::proto::{
    proto_name, BridgeEntry, ClientEntry, Listener, Msg, Proto, RouteEntry, Source, SnapshotBody,
};
use crate::Result;

use super::input::{self, Key};
use super::render::Renderer;
use super::style::{Color, Line, Style, ACCENT, BAD, GOOD, MUTED, PLAIN, WARN};
use super::{frame, term};

const REFRESH: Duration = Duration::from_secs(1);
/// Upper bound on a single admin round trip so a hung server surfaces an error
/// toast instead of freezing the event loop.
const NET_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a toast stays on screen before it ages out.
const TOAST_TTL: Duration = Duration::from_secs(4);
const BOLD: Style = Style::fg(Color::Default).bold();
const TCP: Style = Style::fg(Color::Accent);
const UDP: Style = Style::fg(Color::Magenta);

/// Entry point: take over the terminal, drive the event loop, restore on exit.
pub async fn run(server: String, secret: String) -> Result<()> {
    let psk = crate::noise::derive_psk(&secret);
    let _raw = term::RawMode::enter()?;
    let mut keys = input::reader();
    let mut renderer = Renderer::new();
    let mut app = App::new(server, psk);

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
    Live,
    Error(String),
}

enum PickOption {
    Client(String),
    Clear,
}

enum Overlay {
    None,
    Picker {
        route: (Ipv4Addr, Proto, u16),
        sel: usize,
        options: Vec<PickOption>,
    },
    AddForm {
        proto: Proto,
        bind: String,
        port: String,
        field: u8,
    },
    Confirm {
        prompt: String,
        bind: Ipv4Addr,
        proto: Proto,
        port: u16,
    },
}

struct App {
    server: String,
    psk: [u8; 32],
    snap: Option<SnapshotBody>,
    status: Status,
    toast: Option<(String, bool, Instant)>,
    sel: usize,
    overlay: Overlay,
}

impl App {
    fn new(server: String, psk: [u8; 32]) -> App {
        App {
            server,
            psk,
            snap: None,
            status: Status::Connecting,
            toast: None,
            sel: 0,
            overlay: Overlay::None,
        }
    }

    fn routes(&self) -> Vec<RouteEntry> {
        let mut v = self.snap.as_ref().map(|s| s.routes.clone()).unwrap_or_default();
        v.sort_by_key(|r| (u32::from(r.bind_ip), pk(r.proto), r.port));
        v
    }

    fn listeners(&self) -> Vec<Listener> {
        let mut v = self.snap.as_ref().map(|s| s.listeners.clone()).unwrap_or_default();
        v.sort_by_key(|l| (u32::from(l.bind_ip), pk(l.proto), l.port));
        v
    }

    fn clients(&self) -> Vec<ClientEntry> {
        let mut v = self.snap.as_ref().map(|s| s.clients.clone()).unwrap_or_default();
        v.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        v
    }

    fn bridge(&self) -> Vec<BridgeEntry> {
        let mut v = self
            .snap
            .as_ref()
            .map(|s| s.bridge_clients.clone())
            .unwrap_or_default();
        v.sort_by(|a, b| a.label.cmp(&b.label));
        v
    }

    fn item_count(&self) -> usize {
        self.routes().len() + self.listeners().len()
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
        let fetch = admin::fetch_snapshot(&self.server, &self.psk);
        match tokio::time::timeout(NET_TIMEOUT, fetch).await {
            Ok(Ok(snap)) => {
                self.snap = Some(snap);
                self.status = Status::Live;
                self.clamp_sel();
            }
            Ok(Err(e)) => self.status = Status::Error(e.to_string()),
            Err(_) => self.status = Status::Error("request timed out".to_string()),
        }
    }

    /// Send one mutation, surface its verdict as a toast, then refetch so the
    /// view reflects the server's post-mutation state.
    async fn apply(&mut self, req: Msg, ok_msg: String) {
        let send = admin::mutate(&self.server, &self.psk, req);
        match tokio::time::timeout(NET_TIMEOUT, send).await {
            Ok(Ok((true, _))) => self.set_toast(ok_msg, false),
            Ok(Ok((false, msg))) => self.set_toast(msg, true),
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
            Overlay::Picker { .. } => self.on_key_picker(k).await,
            Overlay::AddForm { .. } => self.on_key_form(k).await,
            Overlay::Confirm { .. } => self.on_key_confirm(k).await,
        }
    }

    async fn on_key_normal(&mut self, k: Key) -> Flow {
        let routes = self.routes();
        let listeners = self.listeners();
        match k {
            Key::Char('q') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
            Key::Down | Key::Char('j') if self.sel + 1 < self.item_count() => {
                self.sel += 1;
            }
            Key::Char('r') => self.refresh().await,
            Key::Char('a') => {
                self.overlay = Overlay::AddForm {
                    proto: Proto::Tcp,
                    bind: "0.0.0.0".to_string(),
                    port: String::new(),
                    field: 2,
                };
            }
            Key::Enter => {
                // Enter assigns a client to the selected port. On a route row it
                // re-targets the route; on a listener row it creates one for that
                // bound port, preselecting any client it already routes to.
                let target = if self.sel < routes.len() {
                    let r = &routes[self.sel];
                    Some(((r.bind_ip, r.proto, r.port), Some(r.client_id.clone())))
                } else if self.sel - routes.len() < listeners.len() {
                    let l = &listeners[self.sel - routes.len()];
                    let key = (l.bind_ip, l.proto, l.port);
                    let cur = routes
                        .iter()
                        .find(|r| (r.bind_ip, r.proto, r.port) == key)
                        .map(|r| r.client_id.clone());
                    Some((key, cur))
                } else {
                    None
                };
                if let Some((key, current)) = target {
                    let mut options: Vec<PickOption> =
                        self.clients().into_iter().map(|c| PickOption::Client(c.client_id)).collect();
                    options.push(PickOption::Clear);
                    let psel = current
                        .as_ref()
                        .and_then(|id| {
                            options
                                .iter()
                                .position(|o| matches!(o, PickOption::Client(c) if c == id))
                        })
                        .unwrap_or(0);
                    self.overlay = Overlay::Picker {
                        route: key,
                        sel: psel,
                        options,
                    };
                }
            }
            Key::Char('c') if self.sel < routes.len() => {
                let r = &routes[self.sel];
                let req = Msg::ClearRoute {
                    bind_ip: r.bind_ip,
                    proto: r.proto,
                    port: r.port,
                };
                self.apply(req, format!("cleared route {}:{}", proto_name(r.proto), r.port))
                    .await;
            }
            Key::Char('d') if self.sel >= routes.len() => {
                if let Some(l) = listeners.get(self.sel - routes.len()) {
                    self.overlay = Overlay::Confirm {
                        prompt: format!("remove listener {} :{} ?", proto_name(l.proto), l.port),
                        bind: l.bind_ip,
                        proto: l.proto,
                        port: l.port,
                    };
                }
            }
            _ => {}
        }
        Flow::Continue
    }

    async fn on_key_picker(&mut self, k: Key) -> Flow {
        let (route, sel, len) = match &self.overlay {
            Overlay::Picker { route, sel, options } => (*route, *sel, options.len()),
            _ => return Flow::Continue,
        };
        match k {
            Key::Esc => self.overlay = Overlay::None,
            Key::Up | Key::Char('k') => {
                if let Overlay::Picker { sel, .. } = &mut self.overlay {
                    *sel = sel.saturating_sub(1);
                }
            }
            Key::Down | Key::Char('j') => {
                if let Overlay::Picker { sel, .. } = &mut self.overlay {
                    if *sel + 1 < len {
                        *sel += 1;
                    }
                }
            }
            Key::Enter => {
                let (bind_ip, proto, port) = route;
                let chosen = match &self.overlay {
                    Overlay::Picker { options, .. } => match &options[sel] {
                        PickOption::Client(id) => Some(id.clone()),
                        PickOption::Clear => None,
                    },
                    _ => None,
                };
                self.overlay = Overlay::None;
                let req = match &chosen {
                    Some(id) => Msg::SetRoute {
                        bind_ip,
                        proto,
                        port,
                        client_id: id.clone(),
                    },
                    None => Msg::ClearRoute { bind_ip, proto, port },
                };
                let msg = match chosen {
                    Some(id) => format!("{}:{} → {id}", proto_name(proto), port),
                    None => format!("cleared route {}:{}", proto_name(proto), port),
                };
                self.apply(req, msg).await;
            }
            _ => {}
        }
        Flow::Continue
    }

    async fn on_key_form(&mut self, k: Key) -> Flow {
        match k {
            Key::Esc => self.overlay = Overlay::None,
            Key::Tab => {
                if let Overlay::AddForm { field, .. } = &mut self.overlay {
                    *field = (*field + 1) % 3;
                }
            }
            Key::Up => {
                if let Overlay::AddForm { field, .. } = &mut self.overlay {
                    *field = (*field + 2) % 3;
                }
            }
            Key::Down => {
                if let Overlay::AddForm { field, .. } = &mut self.overlay {
                    *field = (*field + 1) % 3;
                }
            }
            Key::Left | Key::Right => {
                if let Overlay::AddForm { field, proto, .. } = &mut self.overlay {
                    if *field == 0 {
                        *proto = match *proto {
                            Proto::Tcp => Proto::Udp,
                            Proto::Udp => Proto::Tcp,
                        };
                    }
                }
            }
            Key::Backspace => {
                if let Overlay::AddForm { field, bind, port, .. } = &mut self.overlay {
                    match field {
                        1 => {
                            bind.pop();
                        }
                        2 => {
                            port.pop();
                        }
                        _ => {}
                    }
                }
            }
            Key::Char(c) => {
                if let Overlay::AddForm { field, bind, port, .. } = &mut self.overlay {
                    match field {
                        1 if c.is_ascii_digit() || c == '.' => bind.push(c),
                        2 if c.is_ascii_digit() => port.push(c),
                        _ => {}
                    }
                }
            }
            Key::Enter => return self.submit_form().await,
            _ => {}
        }
        Flow::Continue
    }

    async fn submit_form(&mut self) -> Flow {
        let (proto, bind, port) = match &self.overlay {
            Overlay::AddForm { proto, bind, port, .. } => (*proto, bind.clone(), port.clone()),
            _ => return Flow::Continue,
        };
        let bind_ip = if bind.trim().is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else {
            match bind.parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => {
                    self.set_toast(format!("invalid bind address '{bind}'"), true);
                    return Flow::Continue;
                }
            }
        };
        let port: u16 = match port.parse() {
            Ok(p) if p > 0 => p,
            _ => {
                self.set_toast("port must be 1-65535".to_string(), true);
                return Flow::Continue;
            }
        };
        self.overlay = Overlay::None;
        let req = Msg::AddListener {
            bind_ip,
            proto,
            port,
        };
        self.apply(req, format!("added {} :{port}", proto_name(proto))).await;
        Flow::Continue
    }

    async fn on_key_confirm(&mut self, k: Key) -> Flow {
        match k {
            Key::Char('y') | Key::Enter => {
                if let Overlay::Confirm { bind, proto, port, .. } = self.overlay {
                    self.overlay = Overlay::None;
                    let req = Msg::RemoveListener {
                        bind_ip: bind,
                        proto,
                        port,
                    };
                    self.apply(req, format!("removed {} :{port}", proto_name(proto))).await;
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
        let routes = self.routes();
        let listeners = self.listeners();
        let clients = self.clients();
        let bridge = self.bridge();

        let mut lines: Vec<String> = Vec::with_capacity(h);
        lines.push(frame::top(w, self.header_left(), self.status_seg()));

        let mut content: Vec<String> = Vec::new();
        content.push(frame::blank(w));
        content.push(frame::row(w, section_head("ROUTES", routes.len())));
        if routes.is_empty() {
            content.push(frame::row(w, muted_line("  (no routes)")));
        }
        for (i, r) in routes.iter().enumerate() {
            content.push(frame::row(w, self.route_row(r, i)));
        }
        content.push(frame::blank(w));
        content.push(frame::row(w, section_head("LISTENERS", listeners.len())));
        if listeners.is_empty() {
            content.push(frame::row(w, muted_line("  (none)")));
        }
        for (i, l) in listeners.iter().enumerate() {
            content.push(frame::row(w, self.listener_row(l, routes.len() + i)));
        }
        content.push(frame::blank(w));
        content.push(frame::row(w, section_head("CLIENTS", clients.len())));
        content.push(frame::row(w, clients_row(&clients)));
        content.push(frame::blank(w));
        content.push(frame::row(w, section_head("BRIDGE", bridge.len())));
        if bridge.is_empty() {
            content.push(frame::row(w, muted_line("  (none connected)")));
        }
        for e in &bridge {
            content.push(frame::row(w, bridge_row(e)));
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
        lines.push(frame::row(w, self.hint_line(&routes)));
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
        l.add(MUTED, "  ");
        l.add(PLAIN, &self.server);
        if let Some(snap) = &self.snap {
            l.add(MUTED, &format!("  server {}", sanitize(&snap.server_id)));
        }
        l
    }

    fn status_seg(&self) -> Line {
        let mut l = Line::new();
        match &self.status {
            Status::Connecting => {
                l.add(MUTED, "● connecting");
            }
            Status::Live => {
                l.add(GOOD, "● ");
                l.add(MUTED, "live");
            }
            Status::Error(e) => {
                l.add(BAD, "● ");
                l.add(MUTED, &trunc(e, 28));
            }
        }
        l
    }

    fn route_row(&self, r: &RouteEntry, idx: usize) -> Line {
        let selected = self.sel == idx && matches!(self.overlay, Overlay::None);
        let active = r.state == 0;
        let mut l = Line::new();
        caret(&mut l, selected);
        l.add(proto_style(r.proto), &format!("{:<4}", proto_name(r.proto)));
        l.add(PLAIN, &format!(":{:<6}", r.port));
        l.add(MUTED, "→ ");
        l.add(if active { BOLD } else { WARN }, &format!("{:<18}", trunc(&sanitize(&r.client_id), 18)));
        l.add(if active { GOOD } else { BAD }, &format!("{:<9}", if active { "active" } else { "offline" }));
        l.add(MUTED, source_tag(r.source));
        l
    }

    fn listener_row(&self, l_: &Listener, idx: usize) -> Line {
        let selected = self.sel == idx && matches!(self.overlay, Overlay::None);
        let mut l = Line::new();
        caret(&mut l, selected);
        l.add(proto_style(l_.proto), &format!("{:<4}", proto_name(l_.proto)));
        l.add(PLAIN, &format!(":{:<6}", l_.port));
        l.add(MUTED, &format!("{:<18}", l_.bind_ip));
        l.add(MUTED, source_tag(l_.source));
        l
    }

    fn toast_line(&self) -> Line {
        let mut l = Line::new();
        if let Some((msg, is_err, at)) = &self.toast {
            if at.elapsed() < TOAST_TTL {
                l.add(if *is_err { BAD } else { GOOD }, if *is_err { "✕ " } else { "✓ " });
                l.add(if *is_err { WARN } else { MUTED }, &sanitize(msg));
            }
        }
        l
    }

    fn hint_line(&self, routes: &[RouteEntry]) -> Line {
        let mut l = Line::new();
        match &self.overlay {
            Overlay::None => {
                hint(&mut l, "↑↓", "move");
                if self.item_count() > 0 {
                    hint(&mut l, "⏎", "set route");
                }
                if self.sel < routes.len() {
                    hint(&mut l, "c", "clear");
                }
                hint(&mut l, "a", "add");
                if self.sel >= routes.len() && self.item_count() > 0 {
                    hint(&mut l, "d", "remove");
                }
                hint(&mut l, "r", "refresh");
                hint(&mut l, "q", "quit");
            }
            Overlay::Picker { .. } => {
                hint(&mut l, "↑↓", "choose");
                hint(&mut l, "⏎", "apply");
                hint(&mut l, "esc", "cancel");
            }
            Overlay::AddForm { .. } => {
                hint(&mut l, "tab", "field");
                hint(&mut l, "←→", "proto");
                hint(&mut l, "⏎", "add");
                hint(&mut l, "esc", "cancel");
            }
            Overlay::Confirm { .. } => {
                hint(&mut l, "y", "confirm");
                hint(&mut l, "n", "cancel");
            }
        }
        l
    }

    fn overlay_panel(&self, w: usize, h: usize) -> Vec<String> {
        match &self.overlay {
            Overlay::None => Vec::new(),
            Overlay::Picker { route, sel, options } => {
                let (_, proto, port) = route;
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, &format!("set route  {} :{}", proto_name(*proto), port)));
                // Keep the panel inside the terminal: show a window of options
                // around the selection, with markers when some are off-screen.
                let (start, end) = window(*sel, options.len(), h.saturating_sub(7).max(1));
                if start > 0 {
                    p.push(frame::row(w, muted_line(&format!("  ↑ {start} more"))));
                }
                for (i, opt) in options.iter().enumerate().take(end).skip(start) {
                    let mut l = Line::new();
                    caret(&mut l, i == *sel);
                    match opt {
                        PickOption::Client(id) => l.add(if i == *sel { BOLD } else { PLAIN }, &sanitize(id)),
                        PickOption::Clear => l.add(WARN, "(clear route)"),
                    };
                    p.push(frame::row(w, l));
                }
                if end < options.len() {
                    p.push(frame::row(w, muted_line(&format!("  ↓ {} more", options.len() - end))));
                }
                p.push(frame::divider(w));
                p
            }
            Overlay::AddForm { proto, bind, port, field } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "add listener"));
                p.push(frame::row(w, form_proto(*proto, *field == 0)));
                p.push(frame::row(w, form_text("bind", bind, *field == 1)));
                p.push(frame::row(w, form_text("port", port, *field == 2)));
                p.push(frame::divider(w));
                p
            }
            Overlay::Confirm { prompt, .. } => {
                let mut p = vec![frame::divider(w)];
                p.push(frame::panel_title(w, "confirm"));
                let mut l = Line::new();
                l.add(WARN, prompt);
                p.push(frame::row_center(w, l));
                p.push(frame::divider(w));
                p
            }
        }
    }
}

// ---- small builders ------------------------------------------------------

fn pk(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 0,
        Proto::Udp => 1,
    }
}

fn proto_style(p: Proto) -> Style {
    match p {
        Proto::Tcp => TCP,
        Proto::Udp => UDP,
    }
}

fn source_tag(s: Source) -> &'static str {
    match s {
        Source::File => "file",
        Source::Cli => "cli",
        Source::Runtime => "runtime",
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
    let mut l = Line::new();
    l.add(Style::fg(Color::Accent).bold(), name);
    l.add(MUTED, &format!("  {count}"));
    l
}

fn muted_line(text: &str) -> Line {
    let mut l = Line::new();
    l.add(MUTED, text);
    l
}

fn clients_row(clients: &[ClientEntry]) -> Line {
    let mut l = Line::new();
    l.add(PLAIN, "  ");
    if clients.is_empty() {
        l.add(MUTED, "(none connected)");
        return l;
    }
    for (i, c) in clients.iter().enumerate() {
        if i > 0 {
            l.add(MUTED, " · ");
        }
        l.add(ACCENT, &sanitize(&c.client_id));
    }
    l
}

fn bridge_row(e: &BridgeEntry) -> Line {
    let mut l = Line::new();
    l.add(PLAIN, "  ");
    l.add(ACCENT, &sanitize(&e.label));
    if !e.named {
        l.add(MUTED, " (anon)");
    }
    let proto = crate::admin::transport_name(e.transport);
    let peer = if e.peer.is_empty() {
        "-".to_string()
    } else {
        sanitize(&e.peer)
    };
    let rx = format!(
        "{} / {}",
        crate::admin::human_bytes(e.rx_bytes),
        crate::admin::human_count(e.rx_frames)
    );
    let tx = format!(
        "{} / {}",
        crate::admin::human_bytes(e.tx_bytes),
        crate::admin::human_count(e.tx_frames)
    );
    let tail = format!(
        " · {proto} · {peer} · {} macs · {rx}/{tx} · up {} · idle {}",
        e.macs.len(),
        crate::admin::fmt_dur(e.uptime_secs),
        crate::admin::fmt_dur(e.idle_secs),
    );
    l.add(MUTED, &tail);
    l
}

fn form_proto(proto: Proto, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.add(MUTED, &format!("{:<6}", "proto"));
    let tcp = if matches!(proto, Proto::Tcp) { BOLD.reverse() } else { MUTED };
    let udp = if matches!(proto, Proto::Udp) { BOLD.reverse() } else { MUTED };
    l.add(tcp, " tcp ");
    l.add(PLAIN, " ");
    l.add(udp, " udp ");
    l
}

fn form_text(label: &str, value: &str, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.add(MUTED, &format!("{label:<6}"));
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
/// terminal, so a crafted id or server message cannot inject escape sequences or
/// zero-width glyphs that corrupt the frame.
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
