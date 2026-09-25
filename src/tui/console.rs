//! The zeronat admin console: a live, controllable view of one server.
//!
//! Every frame is rebuilt from the latest snapshot and diffed by the renderer.
//! Snapshots are polled on an interval; each keypress that mutates the server
//! issues one admin mutation and then refetches, so the screen always reflects
//! the server's own view rather than an optimistic local guess.

use std::net::Ipv4Addr;

use crate::admin;
use crate::proto::{
    proto_name, provides_name, BridgeEntry, ClientEntry, Listener, Msg, PairEntry, Proto,
    RouteEntry, SnapshotBody, Source,
};
use crate::Result;

use super::common::{
    self, caret, cat, cell, fail_text, hints, num, pad, pick_row, port_col, proto_port,
    proto_style, sanitize, set_toast, BoxFut, Console, Flow, Screen, Status, Toast, BOLD,
    NET_TIMEOUT,
};
use super::input::Key;
use super::style::{Line, ACCENT, BAD, GOOD, MUTED, PLAIN, WARN};

/// Entry point: take over the terminal, drive the event loop, restore on exit.
pub async fn run(server: String, secret: String) -> Result<()> {
    let secret = crate::secret::normalize(&secret)?;
    let psk = crate::noise::derive_psk(&secret);
    let mut app = App::new(server, psk);
    common::event_loop(&mut app).await
}

enum Overlay {
    None,
    Picker {
        route: (Ipv4Addr, Proto, u16),
        sel: usize,
        /// The client ids to pick from; one past the last is "clear".
        ids: Vec<String>,
    },
    ClientMenu {
        client_id: String,
        sel: usize,
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

/// One admin exchange a keypress queued.
enum Pending {
    Refresh,
    Apply(Msg, String),
    ForwardAll(Vec<Msg>, String),
}

struct App {
    server: String,
    psk: [u8; 32],
    snap: Option<SnapshotBody>,
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
        self.on_key(k)
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
                Some(Pending::ForwardAll(reqs, id)) => self.forward_all(reqs, id).await,
            }
        })
    }
}

/// Put every list into display order: routes and listeners by bind, proto,
/// port; clients by id; bridge clients by label. Pairs arrive ordered, since
/// the server keeps them in a map and sorts them itself.
#[inline(never)]
fn sort(snap: &mut SnapshotBody) {
    let key = |ip: Ipv4Addr, proto: Proto, port: u16| {
        ((u32::from(ip) as u64) << 24) | ((pk(proto) as u64) << 16) | port as u64
    };
    let r = &mut snap.routes;
    let idx = common::order(r.len(), &mut |a, b| {
        key(r[a].bind_ip, r[a].proto, r[a].port) < key(r[b].bind_ip, r[b].proto, r[b].port)
    });
    common::permute(&idx, &mut |i, j| r.swap(i, j));
    let l = &mut snap.listeners;
    let idx = common::order(l.len(), &mut |a, b| {
        key(l[a].bind_ip, l[a].proto, l[a].port) < key(l[b].bind_ip, l[b].proto, l[b].port)
    });
    common::permute(&idx, &mut |i, j| l.swap(i, j));
    let c = &mut snap.clients;
    let idx = common::order(c.len(), &mut |a, b| c[a].client_id < c[b].client_id);
    common::permute(&idx, &mut |i, j| c.swap(i, j));
    let b = &mut snap.bridge_clients;
    let idx = common::order(b.len(), &mut |x, y| b[x].label < b[y].label);
    common::permute(&idx, &mut |i, j| b.swap(i, j));
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
            pending: None,
        }
    }

    fn routes(&self) -> &[RouteEntry] {
        self.snap.as_ref().map_or(&[], |s| &s.routes)
    }

    fn listeners(&self) -> &[Listener] {
        self.snap.as_ref().map_or(&[], |s| &s.listeners)
    }

    fn clients(&self) -> &[ClientEntry] {
        self.snap.as_ref().map_or(&[], |s| &s.clients)
    }

    fn bridge(&self) -> &[BridgeEntry] {
        self.snap.as_ref().map_or(&[], |s| &s.bridge_clients)
    }

    fn pairs(&self) -> &[PairEntry] {
        self.snap.as_ref().map_or(&[], |s| &s.pairs)
    }

    fn item_count(&self) -> usize {
        self.routes().len() + self.listeners().len() + self.clients().len()
    }

    fn clamp_sel(&mut self) {
        let n = self.item_count();
        if n == 0 {
            self.sel = 0;
        } else if self.sel >= n {
            self.sel = n - 1;
        }
    }

    /// The client a listener's route targets, if it has one.
    fn route_target(&self, key: (Ipv4Addr, Proto, u16)) -> Option<&str> {
        self.routes()
            .iter()
            .find(|r| (r.bind_ip, r.proto, r.port) == key)
            .map(|r| r.client_id.as_str())
    }

    async fn fetch(&mut self) {
        let fetch = admin::fetch_snapshot(&self.server, &self.psk);
        match tokio::time::timeout(NET_TIMEOUT, fetch).await {
            Ok(Ok(mut snap)) => {
                sort(&mut snap);
                self.snap = Some(snap);
                self.status = Status::Connected;
                self.clamp_sel();
            }
            Ok(Err(e)) => self.status = Status::Error(fail_text(Some(e))),
            Err(_) => self.status = Status::Error(fail_text(None)),
        }
    }

    /// Send one mutation, surface its verdict as a toast, then refetch so the
    /// view reflects the server's post-mutation state.
    async fn apply(&mut self, req: Msg, ok_msg: String) {
        let send = admin::mutate(&self.server, &self.psk, req);
        let (msg, is_err) = match tokio::time::timeout(NET_TIMEOUT, send).await {
            Ok(Ok((true, _))) => (ok_msg, false),
            Ok(Ok((false, msg))) => (msg, true),
            Ok(Err(e)) => (fail_text(Some(e)), true),
            Err(_) => (fail_text(None), true),
        };
        set_toast(&mut self.toast, msg, is_err);
        self.fetch().await;
    }

    /// Point every listener at one client, stopping at the first refusal.
    async fn forward_all(&mut self, reqs: Vec<Msg>, client_id: String) {
        let total = reqs.len();
        for (i, req) in reqs.into_iter().enumerate() {
            let send = admin::mutate(&self.server, &self.psk, req);
            let fail = match tokio::time::timeout(NET_TIMEOUT, send).await {
                Ok(Ok((true, _))) => continue,
                Ok(Ok((false, msg))) => cat(&[
                    "server reported after ",
                    &num(i + 1),
                    "/",
                    &num(total),
                    ": ",
                    &msg,
                ]),
                r => cat(&[
                    "forwarded ",
                    &num(i),
                    "/",
                    &num(total),
                    ": ",
                    &fail_text(r.ok().and_then(Result::err)),
                ]),
            };
            set_toast(&mut self.toast, fail, true);
            self.fetch().await;
            return;
        }
        set_toast(
            &mut self.toast,
            cat(&["forwarded ", &num(total), " listeners to ", &client_id]),
            false,
        );
        self.fetch().await;
    }

    fn queue(&mut self, req: Msg, ok_msg: String) {
        self.pending = Some(Pending::Apply(req, ok_msg));
    }

    fn close(&mut self) {
        self.overlay = Overlay::None;
    }

    fn on_key(&mut self, k: Key) -> Flow {
        if matches!(k, Key::CtrlC) {
            return Flow::Quit;
        }
        match self.overlay {
            Overlay::None => return self.on_key_normal(k),
            Overlay::Picker { .. } => self.on_key_picker(k),
            Overlay::ClientMenu { .. } => self.on_key_client_menu(k),
            Overlay::AddForm { .. } => self.on_key_form(k),
            Overlay::Confirm { .. } => self.on_key_confirm(k),
        }
        Flow::Continue
    }

    #[inline(never)]
    fn on_key_normal(&mut self, k: Key) -> Flow {
        let nr = self.routes().len();
        let nl = self.listeners().len();
        match k {
            Key::Char('q') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.sel = self.sel.saturating_sub(1),
            Key::Down | Key::Char('j') if self.sel + 1 < self.item_count() => {
                self.sel += 1;
            }
            Key::Char('r') => self.pending = Some(Pending::Refresh),
            Key::Char('a') => {
                self.overlay = Overlay::AddForm {
                    proto: Proto::Tcp,
                    bind: "0.0.0.0".to_string(),
                    port: String::new(),
                    field: 2,
                };
            }
            Key::Enter => {
                let client_start = nr + nl;
                if self.sel >= client_start {
                    if let Some(client) = self.clients().get(self.sel - client_start) {
                        self.overlay = Overlay::ClientMenu {
                            client_id: client.client_id.clone(),
                            sel: 0,
                        };
                    }
                    return Flow::Continue;
                }

                let (key, current) = if self.sel < nr {
                    let r = &self.routes()[self.sel];
                    ((r.bind_ip, r.proto, r.port), Some(r.client_id.clone()))
                } else {
                    let l = &self.listeners()[self.sel - nr];
                    let key = (l.bind_ip, l.proto, l.port);
                    (key, self.route_target(key).map(str::to_string))
                };
                let ids: Vec<String> = self.clients().iter().map(|c| c.client_id.clone()).collect();
                let psel = current
                    .and_then(|id| ids.iter().position(|c| *c == id))
                    .unwrap_or(0);
                self.overlay = Overlay::Picker {
                    route: key,
                    sel: psel,
                    ids,
                };
            }
            Key::Char('c') if self.sel < nr => {
                let r = &self.routes()[self.sel];
                let (bind_ip, proto, port) = (r.bind_ip, r.proto, r.port);
                self.queue(
                    Msg::ClearRoute {
                        bind_ip,
                        proto,
                        port,
                    },
                    cleared(proto, port),
                );
            }
            Key::Char('d') if self.sel >= nr => {
                if let Some(l) = self.listeners().get(self.sel - nr) {
                    self.overlay = Overlay::Confirm {
                        prompt: cat(&[
                            "remove listener ",
                            proto_name(l.proto),
                            " :",
                            &num(l.port as usize),
                            " ?",
                        ]),
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

    fn on_key_client_menu(&mut self, k: Key) {
        let Overlay::ClientMenu { client_id, sel } = &mut self.overlay else {
            return;
        };
        match k {
            Key::Esc => self.close(),
            Key::Up | Key::Char('k') => *sel = sel.saturating_sub(1),
            Key::Down | Key::Char('j') => {
                if *sel == 0 {
                    *sel += 1;
                }
            }
            Key::Enter => {
                let (client_id, sel) = (std::mem::take(client_id), *sel);
                self.close();
                if sel == 0 {
                    self.forward_all_listeners(client_id);
                }
            }
            _ => {}
        }
    }

    /// Queue a `SetRoute` for every listener not already routed to
    /// `client_id`; toast at once when there is nothing to send.
    fn forward_all_listeners(&mut self, client_id: String) {
        if self.listeners().is_empty() {
            set_toast(&mut self.toast, "no listeners to forward".to_string(), true);
            return;
        }
        let mut reqs = Vec::new();
        for l in self.listeners() {
            let key = (l.bind_ip, l.proto, l.port);
            if self.route_target(key) != Some(client_id.as_str()) {
                reqs.push(Msg::SetRoute {
                    bind_ip: l.bind_ip,
                    proto: l.proto,
                    port: l.port,
                    client_id: client_id.clone(),
                });
            }
        }
        if reqs.is_empty() {
            set_toast(
                &mut self.toast,
                cat(&["all listeners already target ", &client_id]),
                false,
            );
            return;
        }
        self.pending = Some(Pending::ForwardAll(reqs, client_id));
    }

    fn on_key_picker(&mut self, k: Key) {
        let Overlay::Picker { route, sel, ids } = &mut self.overlay else {
            return;
        };
        match k {
            Key::Esc => self.close(),
            Key::Up | Key::Char('k') => *sel = sel.saturating_sub(1),
            Key::Down | Key::Char('j') => {
                if *sel < ids.len() {
                    *sel += 1;
                }
            }
            Key::Enter => {
                let (bind_ip, proto, port) = *route;
                let chosen = ids.get(*sel).cloned();
                self.close();
                let (req, msg) = match chosen {
                    Some(id) => (
                        Msg::SetRoute {
                            bind_ip,
                            proto,
                            port,
                            client_id: id.clone(),
                        },
                        cat(&[&proto_port(proto, port), " → ", &id]),
                    ),
                    None => (
                        Msg::ClearRoute {
                            bind_ip,
                            proto,
                            port,
                        },
                        cleared(proto, port),
                    ),
                };
                self.queue(req, msg);
            }
            _ => {}
        }
    }

    fn on_key_form(&mut self, k: Key) {
        let Overlay::AddForm {
            proto,
            bind,
            port,
            field,
        } = &mut self.overlay
        else {
            return;
        };
        match k {
            Key::Esc => self.close(),
            Key::Tab | Key::Down => *field = (*field + 1) % 3,
            Key::Up => *field = (*field + 2) % 3,
            Key::Left | Key::Right => {
                if *field == 0 {
                    *proto = match *proto {
                        Proto::Tcp => Proto::Udp,
                        Proto::Udp => Proto::Tcp,
                    };
                }
            }
            Key::Backspace => match field {
                1 => {
                    bind.pop();
                }
                2 => {
                    port.pop();
                }
                _ => {}
            },
            Key::Char(c) => match field {
                1 if c.is_ascii_digit() || c == '.' => bind.push(c),
                2 if c.is_ascii_digit() => port.push(c),
                _ => {}
            },
            Key::Enter => self.submit_form(),
            _ => {}
        }
    }

    fn submit_form(&mut self) {
        let Overlay::AddForm {
            proto, bind, port, ..
        } = &self.overlay
        else {
            return;
        };
        let proto = *proto;
        let bind_ip = if bind.trim().is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else {
            match bind.parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => {
                    let msg = cat(&["invalid bind address '", bind, "'"]);
                    set_toast(&mut self.toast, msg, true);
                    return;
                }
            }
        };
        let port: u16 = match port.parse() {
            Ok(p) if p > 0 => p,
            _ => {
                set_toast(&mut self.toast, "port must be 1-65535".to_string(), true);
                return;
            }
        };
        self.close();
        self.queue(
            Msg::AddListener {
                bind_ip,
                proto,
                port,
            },
            listener_msg("added ", proto, port),
        );
    }

    fn on_key_confirm(&mut self, k: Key) {
        match k {
            Key::Char('y') | Key::Enter => {
                if let Overlay::Confirm {
                    bind, proto, port, ..
                } = self.overlay
                {
                    self.close();
                    self.queue(
                        Msg::RemoveListener {
                            bind_ip: bind,
                            proto,
                            port,
                        },
                        listener_msg("removed ", proto, port),
                    );
                }
            }
            Key::Char('n') | Key::Esc => self.close(),
            _ => {}
        }
    }

    // ---- rendering -------------------------------------------------------

    fn view(&self, w: usize, h: usize) -> Vec<String> {
        if let Some(blank) = common::too_small(w, h) {
            return blank;
        }
        let routes = self.routes();
        let listeners = self.listeners();
        let clients = self.clients();
        let bridge = self.bridge();
        let pairs = self.pairs();

        let mut s = Screen::new(w);
        s.blank();
        s.head("ROUTES", routes.len());
        if routes.is_empty() {
            s.muted("  (no routes)");
        }
        for (i, r) in routes.iter().enumerate() {
            s.row(self.route_row(r, i));
        }
        s.blank();
        s.head("LISTENERS", listeners.len());
        if listeners.is_empty() {
            s.muted("  (none)");
        }
        for (i, l) in listeners.iter().enumerate() {
            s.row(self.listener_row(l, routes.len() + i));
        }
        s.blank();
        s.head("CLIENTS", clients.len());
        if clients.is_empty() {
            s.muted("  (none connected)");
        }
        let client_start = routes.len() + listeners.len();
        for (i, c) in clients.iter().enumerate() {
            s.row(self.client_row(c, client_start + i));
        }
        s.blank();
        s.head("BRIDGE", bridge.len());
        if bridge.is_empty() {
            s.muted("  (none connected)");
        }
        for e in bridge {
            s.row(bridge_row(e));
        }
        s.blank();
        s.head("PAIRS", pairs.len());
        if pairs.is_empty() {
            s.muted("  (none)");
        }
        for p in pairs {
            s.row(pair_row(p));
        }

        common::compose(
            w,
            h,
            self.header_left(),
            common::status_seg(&self.status),
            s.rows,
            common::toast_line(&self.toast),
            self.hint_line(routes.len(), listeners.len()),
            self.overlay_panel(w, h),
        )
    }

    #[inline(never)]
    fn header_left(&self) -> Line {
        let mut l = Line::new();
        l.add(ACCENT, "zeronat");
        l.add(MUTED, "  ");
        l.add(PLAIN, &self.server);
        if let Some(snap) = &self.snap {
            l.push(MUTED, cat(&["  server ", &sanitize(&snap.server_id)]));
        }
        l
    }

    fn selected(&self, idx: usize) -> bool {
        self.sel == idx && matches!(self.overlay, Overlay::None)
    }

    #[inline(never)]
    fn route_row(&self, r: &RouteEntry, idx: usize) -> Line {
        let active = r.state == 0;
        let mut l = Line::new();
        caret(&mut l, self.selected(idx));
        l.push(proto_style(r.proto), pad(proto_name(r.proto), 4));
        l.push(PLAIN, port_col(r.port));
        l.add(MUTED, "→ ");
        l.push(if active { BOLD } else { WARN }, cell(&r.client_id, 18));
        l.push(
            if active { GOOD } else { BAD },
            pad(if active { "active" } else { "offline" }, 9),
        );
        l.add(MUTED, source_tag(r.source));
        if let Some(snap) = &self.snap {
            let opts = admin::route_opts(snap, r);
            if opts != "-" {
                l.push(MUTED, cat(&["  ", &opts]));
            }
        }
        l
    }

    #[inline(never)]
    fn listener_row(&self, l_: &Listener, idx: usize) -> Line {
        let mut l = Line::new();
        caret(&mut l, self.selected(idx));
        l.push(proto_style(l_.proto), pad(proto_name(l_.proto), 4));
        l.push(PLAIN, port_col(l_.port));
        l.push(MUTED, pad(&l_.bind_ip.to_string(), 18));
        l.add(MUTED, source_tag(l_.source));
        l
    }

    #[inline(never)]
    fn client_row(&self, c: &ClientEntry, idx: usize) -> Line {
        let mut l = Line::new();
        caret(&mut l, self.selected(idx));
        l.push(ACCENT, cell(&c.client_id, 18));
        l.add(MUTED, admin::transport_name(c.transport));
        for e in &c.fwd {
            l.push(
                MUTED,
                cat(&[
                    "  ",
                    &proto_port(e.proto, e.port),
                    &admin::fwd_opts(e.proxy, e.idle_secs),
                ]),
            );
        }
        l
    }

    #[inline(never)]
    fn hint_line(&self, nr: usize, nl: usize) -> Line {
        let mut l = Line::new();
        match &self.overlay {
            Overlay::None => {
                hints(&mut l, "↑↓ move");
                if self.item_count() > 0 {
                    if self.sel >= nr + nl {
                        hints(&mut l, "⏎ client");
                    } else {
                        hints(&mut l, "⏎ set route");
                    }
                }
                if self.sel < nr {
                    hints(&mut l, "c clear");
                }
                hints(&mut l, "a add");
                if self.sel >= nr && self.sel < nr + nl {
                    hints(&mut l, "d remove");
                }
                hints(&mut l, "r refresh|q quit");
            }
            Overlay::Picker { .. } | Overlay::ClientMenu { .. } => {
                hints(&mut l, "↑↓ choose|⏎ apply|esc cancel");
            }
            Overlay::AddForm { .. } => {
                hints(&mut l, "tab field|←→ proto|⏎ add|esc cancel");
            }
            Overlay::Confirm { .. } => {
                hints(&mut l, "y confirm|n cancel");
            }
        }
        l
    }

    #[inline(never)]
    fn overlay_panel(&self, w: usize, h: usize) -> Vec<String> {
        match &self.overlay {
            Overlay::None => Vec::new(),
            Overlay::Picker { route, sel, ids } => {
                let (_, proto, port) = *route;
                let mut p = Screen::panel(
                    w,
                    &cat(&["set route  ", proto_name(proto), " :", &num(port as usize)]),
                );
                common::picker_rows(&mut p, h, ids.len() + 1, *sel, &|i, l| match ids.get(i) {
                    Some(id) => pick_row(l, i == *sel, &sanitize(id)),
                    None => {
                        l.add(WARN, "(clear route)");
                    }
                });
                p.close()
            }
            Overlay::ClientMenu { client_id, sel } => {
                let mut p = Screen::panel(w, &cat(&["client  ", &sanitize(client_id)]));
                p.row(client_menu_row(*sel == 0, "forward all listeners"));
                p.row(client_menu_row(*sel == 1, "cancel"));
                p.close()
            }
            Overlay::AddForm {
                proto,
                bind,
                port,
                field,
            } => {
                let mut p = Screen::panel(w, "add listener");
                p.row(form_proto(*proto, *field == 0));
                p.row(common::form_text("bind", bind, *field == 1, 6));
                p.row(common::form_text("port", port, *field == 2, 6));
                p.close()
            }
            Overlay::Confirm { prompt, .. } => common::confirm_panel(w, prompt),
        }
    }
}

// ---- small builders ------------------------------------------------------

fn cleared(proto: Proto, port: u16) -> String {
    cat(&["cleared route ", &proto_port(proto, port)])
}

/// `<verb>PROTO :PORT`, the toast for a listener added or removed.
fn listener_msg(verb: &str, proto: Proto, port: u16) -> String {
    cat(&[verb, proto_name(proto), " :", &num(port as usize)])
}

fn pk(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 0,
        Proto::Udp => 1,
    }
}

fn source_tag(s: Source) -> &'static str {
    match s {
        Source::File => "file",
        Source::Cli => "cli",
        Source::Runtime => "runtime",
    }
}

#[inline(never)]
fn bridge_row(e: &BridgeEntry) -> Line {
    let mut l = Line::new();
    l.add(PLAIN, "  ");
    l.push(ACCENT, sanitize(&e.label));
    if !e.named {
        l.add(MUTED, " (anon)");
    }
    let peer = if e.peer.is_empty() {
        "-".to_string()
    } else {
        sanitize(&e.peer)
    };
    l.push(
        MUTED,
        cat(&[
            " · ",
            admin::transport_name(e.transport),
            " · ",
            &peer,
            " · ",
            &num(e.macs.len()),
            " macs · ",
            &admin::human_bytes(e.rx_bytes),
            " / ",
            &admin::human_count(e.rx_frames),
            "/",
            &admin::human_bytes(e.tx_bytes),
            " / ",
            &admin::human_count(e.tx_frames),
            " · up ",
            &admin::fmt_dur(e.uptime_secs),
            " · idle ",
            &admin::fmt_dur(e.idle_secs),
        ]),
    );
    l
}

/// One accepted pair: who consumes, who provides, the capability, and the path
/// the two ends settled on. A pair carrying traffic reads good, a pair still
/// pairing reads muted.
#[inline(never)]
fn pair_row(p: &PairEntry) -> Line {
    let mut l = Line::new();
    l.add(PLAIN, "  ");
    l.push(ACCENT, cell(&p.consumer_id, 20));
    l.add(MUTED, "→ ");
    l.push(PLAIN, cell(&p.provider_id, 20));
    l.push(MUTED, pad(provides_name(p.want), 9));
    let (txt, style) = match p.path {
        Some(path) => (crate::proto::path_name(path), GOOD),
        None => ("pairing", MUTED),
    };
    l.add(style, txt);
    l
}

fn client_menu_row(selected: bool, label: &str) -> Line {
    let mut l = Line::new();
    caret(&mut l, selected);
    pick_row(&mut l, selected, label);
    l
}

fn form_proto(proto: Proto, focused: bool) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.push(MUTED, pad("proto", 6));
    let pick = |on: bool| if on { BOLD.reverse() } else { MUTED };
    l.add(pick(matches!(proto, Proto::Tcp)), " tcp ");
    l.add(PLAIN, " ");
    l.add(pick(matches!(proto, Proto::Udp)), " udp ");
    l
}
