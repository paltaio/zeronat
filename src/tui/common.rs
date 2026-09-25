//! What the two admin consoles share: the terminal event loop, the frame
//! layout around a screen's content, the connection and toast state, and the
//! small row builders both screens are made of.

use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::proto::Proto;
use crate::Result;

use super::input::{self, Key};
use super::render::Renderer;
use super::style::{Color, Line, Style, ACCENT, BAD, GOOD, MUTED, PLAIN, WARN};
use super::{frame, term};

const REFRESH: Duration = Duration::from_secs(1);
/// Upper bound on a single admin round trip.
pub const NET_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a toast stays on screen before it ages out.
const TOAST_TTL: Duration = Duration::from_secs(4);
pub const BOLD: Style = Style::fg(Color::Default).bold();
const TCP: Style = Style::fg(Color::Accent);
const UDP: Style = Style::fg(Color::Magenta);

pub enum Flow {
    Continue,
    Quit,
}

pub enum Status {
    Connecting,
    Connected,
    Error(String),
}

/// A toast: the message, whether it reports an error, and when it was set.
pub type Toast = Option<(String, bool, Instant)>;

pub fn set_toast(toast: &mut Toast, msg: String, is_err: bool) {
    *toast = Some((msg, is_err, Instant::now()));
}

/// The text a failed admin round trip reports; `None` is a timeout.
pub fn fail_text(e: Option<crate::Error>) -> String {
    match e {
        Some(e) => e.to_string(),
        None => "request timed out".to_string(),
    }
}

pub type BoxFut<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

/// One console screen: a snapshot-backed view with its own key map. Key
/// handling is synchronous and may queue one admin exchange, which
/// `run_pending` performs before the next redraw.
pub trait Console {
    fn view(&self, w: usize, h: usize) -> Vec<String>;
    fn overlay_open(&self) -> bool;
    fn key(&mut self, k: Key) -> Flow;
    fn refresh(&mut self) -> BoxFut<'_>;
    fn run_pending(&mut self) -> BoxFut<'_>;
}

enum Ev {
    Key(Key),
    Closed,
    Tick,
}

/// Take over the terminal, drive the event loop, restore on exit. Snapshots
/// are polled on an interval while no overlay is open; every keypress ends
/// in a redraw.
pub async fn event_loop(app: &mut dyn Console) -> Result<()> {
    let _raw = term::RawMode::enter()?;
    let mut keys = input::reader();
    let mut renderer = Renderer::new();

    app.refresh().await;
    redraw(&mut renderer, app)?;

    let mut ticker = tokio::time::interval(REFRESH);
    ticker.tick().await; // the first tick fires immediately; drop it

    loop {
        let ev = std::future::poll_fn(|cx| {
            if let Poll::Ready(k) = keys.poll_recv(cx) {
                return Poll::Ready(k.map_or(Ev::Closed, Ev::Key));
            }
            if ticker.poll_tick(cx).is_ready() {
                return Poll::Ready(Ev::Tick);
            }
            Poll::Pending
        })
        .await;
        match ev {
            Ev::Closed => break,
            Ev::Key(k) => {
                if matches!(app.key(k), Flow::Quit) {
                    break;
                }
                app.run_pending().await;
            }
            Ev::Tick => {
                if !app.overlay_open() {
                    app.refresh().await;
                }
            }
        }
        redraw(&mut renderer, app)?;
    }
    Ok(())
}

fn redraw(renderer: &mut Renderer, app: &dyn Console) -> Result<()> {
    let (w, h) = term::size();
    renderer.draw(app.view(w as usize, h as usize), w, h)?;
    Ok(())
}

// ---- layout ----------------------------------------------------------------

/// The blank screen drawn when the terminal is too small for the frame.
pub fn too_small(w: usize, h: usize) -> Option<Vec<String>> {
    if w < 24 || h < 8 {
        Some(vec![" ".repeat(w); h])
    } else {
        None
    }
}

/// The finished screen: top border, `content` cut or padded to the rows above
/// the divider, the toast and hint rows, the bottom border, and `panel` laid
/// over the middle when an overlay is open.
#[allow(clippy::too_many_arguments)]
pub fn compose(
    w: usize,
    h: usize,
    header: Line,
    status: Line,
    mut content: Vec<String>,
    toast: Line,
    hints: Line,
    panel: Vec<String>,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::with_capacity(h);
    lines.push(frame::top(w, header, status));
    // Reserve the last four rows: divider, toast, hints, bottom border.
    let area = h.saturating_sub(5);
    content.truncate(area);
    while content.len() < area {
        content.push(frame::blank(w));
    }
    lines.extend(content);
    lines.push(frame::divider(w));
    lines.push(frame::row(w, toast));
    lines.push(frame::row(w, hints));
    lines.push(frame::bottom(w));
    if !panel.is_empty() {
        let top_row = h.saturating_sub(panel.len()) / 2;
        frame::overlay(&mut lines, &panel, top_row.max(1));
    }
    lines
}

/// Rows of one screen or panel, each framed at the screen width.
pub struct Screen {
    w: usize,
    pub rows: Vec<String>,
}

impl Screen {
    pub fn new(w: usize) -> Screen {
        Screen {
            w,
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, l: Line) {
        self.rows.push(frame::row(self.w, l));
    }

    pub fn center(&mut self, l: Line) {
        self.rows.push(frame::row_center(self.w, l));
    }

    pub fn blank(&mut self) {
        self.rows.push(frame::blank(self.w));
    }

    pub fn divider(&mut self) {
        self.rows.push(frame::divider(self.w));
    }

    pub fn title(&mut self, caption: &str) {
        self.rows.push(frame::panel_title(self.w, caption));
    }

    pub fn muted(&mut self, text: &str) {
        self.row(muted_line(text));
    }

    pub fn head(&mut self, name: &str, count: usize) {
        let mut l = section_title(name);
        l.push(MUTED, cat(&["  ", &num(count)]));
        self.row(l);
    }

    /// A modal panel: divider, title, the given rows, divider.
    pub fn panel(w: usize, caption: &str) -> Screen {
        let mut p = Screen::new(w);
        p.divider();
        p.title(caption);
        p
    }

    pub fn close(mut self) -> Vec<String> {
        self.divider();
        self.rows
    }
}

/// A confirm panel carrying one warning prompt.
pub fn confirm_panel(w: usize, prompt: &str) -> Vec<String> {
    let mut p = Screen::panel(w, "confirm");
    let mut l = Line::new();
    l.add(WARN, prompt);
    p.center(l);
    p.close()
}

/// The rows of a picker panel: the window of `len` items around `sel`, with
/// markers when some are off-screen. `label` renders one item at its index.
pub fn picker_rows(
    p: &mut Screen,
    h: usize,
    len: usize,
    sel: usize,
    label: &dyn Fn(usize, &mut Line),
) {
    let (start, end) = window(sel, len, h.saturating_sub(7).max(1));
    if start > 0 {
        p.muted(&cat(&["  ↑ ", &num(start), " more"]));
    }
    for i in start..end {
        let mut l = Line::new();
        caret(&mut l, i == sel);
        label(i, &mut l);
        p.row(l);
    }
    if end < len {
        p.muted(&cat(&["  ↓ ", &num(len - end), " more"]));
    }
}

// ---- small builders --------------------------------------------------------

pub(crate) use crate::admin::{cat, order, pad, permute};

pub fn num(n: usize) -> String {
    crate::admin::num(n as u64)
}

/// `text` sanitized, cut to `n` columns, and padded to `n` columns.
pub fn cell(text: &str, n: usize) -> String {
    pad(&trunc(&sanitize(text), n), n)
}

/// `:PORT` padded to a seven-column field.
pub fn port_col(port: u16) -> String {
    cat(&[":", &pad(&num(port as usize), 6)])
}

/// `PROTO:PORT`.
pub fn proto_port(proto: Proto, port: u16) -> String {
    cat(&[crate::proto::proto_name(proto), ":", &num(port as usize)])
}

pub fn proto_style(p: Proto) -> Style {
    match p {
        Proto::Tcp => TCP,
        Proto::Udp => UDP,
    }
}

pub fn status_seg(status: &Status) -> Line {
    let mut l = Line::new();
    match status {
        Status::Connecting => {
            l.add(MUTED, "● connecting");
        }
        Status::Connected => {
            l.add(GOOD, "● ");
            l.add(MUTED, "connected");
        }
        Status::Error(e) => {
            l.add(BAD, "● ");
            l.push(MUTED, trunc(&sanitize(e), 28));
        }
    }
    l
}

pub fn toast_line(toast: &Toast) -> Line {
    let mut l = Line::new();
    if let Some((msg, is_err, at)) = toast {
        if at.elapsed() < TOAST_TTL {
            l.add(
                if *is_err { BAD } else { GOOD },
                if *is_err { "✕ " } else { "✓ " },
            );
            l.push(if *is_err { WARN } else { MUTED }, sanitize(msg));
        }
    }
    l
}

pub fn caret(l: &mut Line, selected: bool) {
    if selected {
        l.add(ACCENT, "▸ ");
    } else {
        l.add(PLAIN, "  ");
    }
}

/// Key hints from `spec`: `|`-separated `KEY LABEL` pairs, the key up to the
/// first space.
pub fn hints(l: &mut Line, spec: &str) {
    for item in spec.split('|') {
        let (key, label) = item.split_once(' ').unwrap_or((item, ""));
        l.add(ACCENT, key);
        l.push(MUTED, cat(&[" ", label, "   "]));
    }
}

pub fn section_title(name: &str) -> Line {
    let mut l = Line::new();
    l.add(ACCENT, name);
    l
}

pub fn muted_line(text: &str) -> Line {
    let mut l = Line::new();
    l.add(MUTED, text);
    l
}

/// A menu or picker entry: bold when selected.
pub fn pick_row(l: &mut Line, selected: bool, label: &str) {
    l.add(if selected { BOLD } else { PLAIN }, label);
}

/// A text field: the label in a `lw`-column field, the value, and a cursor
/// mark when focused.
pub fn form_text(label: &str, value: &str, focused: bool, lw: usize) -> Line {
    let mut l = Line::new();
    caret(&mut l, focused);
    l.push(MUTED, pad(label, lw));
    l.add(PLAIN, value);
    if focused {
        l.add(ACCENT, "_");
    }
    l
}

pub fn trunc(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((cut, _)) => s[..cut].to_string(),
        None => s.to_string(),
    }
}

/// Strip control characters from peer-supplied text before it reaches the
/// terminal, so a crafted id or server message cannot inject escape sequences
/// or zero-width glyphs that corrupt the frame.
pub fn sanitize(s: &str) -> String {
    crate::admin::strip_ctrl(s)
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

    #[test]
    fn order_and_permute_sort_stably() {
        let mut v = vec![(3, 'a'), (1, 'b'), (3, 'c'), (2, 'd'), (1, 'e')];
        let idx = order(v.len(), &mut |a, b| v[a].0 < v[b].0);
        permute(&idx, &mut |i, j| v.swap(i, j));
        assert_eq!(v, vec![(1, 'b'), (1, 'e'), (2, 'd'), (3, 'a'), (3, 'c')]);
    }

    #[test]
    fn trunc_and_pad_count_chars() {
        assert_eq!(trunc("héllo", 3), "hél");
        assert_eq!(trunc("hé", 3), "hé");
        assert_eq!(super::pad("hé", 4), "hé  ");
        assert_eq!(super::pad("hello", 4), "hello");
    }
}
