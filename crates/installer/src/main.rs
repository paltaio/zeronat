//! zeronat installer: a small terminal wizard that configures and installs
//! zeronat (server or client) with no flags to remember. Driven over /dev/tty so
//! it works under `curl ... | sh`.

mod install;
mod sys;
mod term;
mod ui;

use install::{Lvl, Outcome};
use term::{Renderer, Tty};
use ui::{App, Config};
use zntui::frame;
use zntui::style::{Color, Line, Style, ACCENT, BAD, GOOD, MUTED, PLAIN};

const BOLD: Style = Style::fg(Color::Default).bold();
const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

fn main() {
    std::process::exit(real_main());
}

/// Runs each install command on a background thread while animating a spinner on
/// the current step, so a slow pull or download shows visible progress instead
/// of a frozen screen.
struct LiveRunner<'a> {
    tty: &'a mut Tty,
    renderer: &'a mut Renderer,
    log: Vec<(Lvl, String)>,
    spin: usize,
}

impl LiveRunner<'_> {
    fn redraw(&mut self) {
        let (w, h) = self.tty.size();
        let ch = SPINNER[self.spin % SPINNER.len()];
        let view = progress_view(&self.log, Status::Working, ch, w as usize, h as usize);
        let _ = self.renderer.draw(self.tty, view, w, h);
    }
}

impl install::Runner for LiveRunner<'_> {
    fn step(&mut self, desc: String) {
        self.log.push((Lvl::Step, desc));
        self.spin = 0;
        self.redraw();
    }

    fn info(&mut self, msg: String) {
        self.log.push((Lvl::Info, msg));
        self.redraw();
    }

    fn run(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
    ) -> Result<std::process::Output, String> {
        let prog = program.to_string();
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let handle = std::thread::spawn(move || {
            let aref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            sys::run(privileged, &prog, &aref)
        });
        while !handle.is_finished() {
            self.spin = self.spin.wrapping_add(1);
            self.redraw();
            std::thread::sleep(std::time::Duration::from_millis(90));
        }
        handle
            .join()
            .unwrap_or_else(|_| Err("command thread panicked".into()))
    }
}

fn real_main() -> i32 {
    // --dry-run previews the steps and makes no changes (and needs no root).
    let dry = std::env::args()
        .skip(1)
        .any(|a| a == "--dry-run" || a == "-n");

    // Pre-flight on the normal terminal, before the alt screen: cache sudo creds
    // and probe the host so the wizard reflects what is actually available.
    if !dry {
        if let Err(e) = sys::ensure_privilege() {
            eprintln!("zeronat installer: {e}");
            return 1;
        }
    }
    let have_docker = sys::have("docker");
    let have_compose = have_docker && sys::have_compose();
    let existing = if dry { None } else { sys::existing_secret() };
    let cfg = Config::new(have_docker, have_compose, existing);

    let mut tty = match Tty::open() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("zeronat installer: no terminal available: {e}");
            return 1;
        }
    };
    if let Err(e) = tty.enter_raw() {
        eprintln!("zeronat installer: {e}");
        return 1;
    }

    let mut renderer = Renderer::new();
    let mut app = App::new(cfg);

    let aborted = loop {
        let (w, h) = tty.size();
        let _ = renderer.draw(&mut tty, app.view(w as usize, h as usize), w, h);
        let key = match tty.next_key() {
            Ok(k) => k,
            Err(_) => break true,
        };
        app.on_key(key);
        if app.quit {
            break true;
        }
        if app.finished {
            break false;
        }
    };

    if aborted {
        tty.restore();
        return 0;
    }

    // Execute, animating a progress screen as each step runs.
    let cfg = app.cfg.clone();
    let (result, log) = {
        let mut runner = LiveRunner {
            tty: &mut tty,
            renderer: &mut renderer,
            log: Vec::new(),
            spin: 0,
        };
        let result = install::execute(&cfg, dry, &mut runner);
        (result, runner.log)
    };

    let status = match &result {
        Ok(o) => Status::Done(o),
        Err(e) => Status::Failed(e),
    };
    let (w, h) = tty.size();
    let _ = renderer.draw(
        &mut tty,
        progress_view(&log, status, ' ', w as usize, h as usize),
        w,
        h,
    );
    let _ = tty.next_key();
    tty.restore();

    // Persist the outcome on the normal screen so it survives the alt screen.
    match result {
        Ok(o) => {
            print_outcome(&mut tty, &o);
            0
        }
        Err(e) => {
            let _ =
                tty.write_all(format!("\n  \x1b[91m✕ install failed\x1b[0m  {e}\n\n").as_bytes());
            1
        }
    }
}

enum Status<'a> {
    Working,
    Done(&'a Outcome),
    Failed(&'a str),
}

/// Print the result to the normal terminal after the alt screen closes, so it
/// stays in the scrollback. The peer command is one line and indented on its
/// own, so a copy-paste picks up exactly the command.
fn print_outcome(tty: &mut Tty, o: &Outcome) {
    let (green, accent, dim, bold, reset) =
        ("\x1b[92m", "\x1b[96;1m", "\x1b[90m", "\x1b[1m", "\x1b[0m");
    let mut s = String::new();
    s.push_str(&format!(
        "\n  {green}✓{reset} {bold}{}{reset}\n\n",
        o.headline
    ));
    s.push_str(&format!(
        "  {dim}manage it with{reset}\n    {}\n\n",
        o.manage
    ));
    s.push_str(&format!("  {accent}{}{reset}\n\n", o.peer_intro));
    s.push_str(&format!("    {bold}{}{reset}\n\n", o.peer_cmd));
    let _ = tty.write_all(s.as_bytes());
}

fn progress_view(
    log: &[(Lvl, String)],
    status: Status,
    spin: char,
    w: usize,
    h: usize,
) -> Vec<String> {
    if w < 30 || h < 12 {
        return vec![" ".repeat(w); h];
    }
    let mut left = Line::new();
    left.add(ACCENT, "zeronat");
    left.add(MUTED, " installer");
    let mut right = Line::new();
    right.add(MUTED, "install");
    let mut lines = vec![frame::top(w, left, right)];

    let mut body: Vec<String> = vec![frame::blank(w)];
    let mut title = Line::new();
    match status {
        Status::Failed(_) => title.add(BAD, "Install failed"),
        Status::Done(_) => title.add(GOOD, "zeronat installed"),
        Status::Working => title.add(BOLD, "Installing zeronat"),
    };
    body.push(frame::row(w, title));
    body.push(frame::blank(w));

    let last = log.len().saturating_sub(1);
    for (i, (lvl, msg)) in log.iter().enumerate() {
        let mut l = Line::new();
        match lvl {
            Lvl::Info => {
                l.add(MUTED, &format!("    {msg}"));
            }
            Lvl::Step if i == last && matches!(status, Status::Working) => {
                l.add(ACCENT, &format!("  {spin} "));
                l.add(PLAIN, msg);
            }
            Lvl::Step => {
                l.add(GOOD, "  ✓ ");
                l.add(MUTED, msg);
            }
        }
        body.push(frame::row(w, l));
    }

    if let Status::Done(o) = status {
        body.push(frame::blank(w));
        let mut m = Line::new();
        m.add(MUTED, "  manage  ");
        m.add(PLAIN, &o.manage);
        body.push(frame::row(w, m));
    }

    let area = h.saturating_sub(5);
    body.truncate(area);
    while body.len() < area {
        body.push(frame::blank(w));
    }
    lines.extend(body);

    lines.push(frame::divider(w));
    let mut st = Line::new();
    match status {
        Status::Working => st.add(MUTED, "  working, please wait..."),
        Status::Done(_) => {
            st.add(GOOD, "  ✓ ");
            st.add(MUTED, "done")
        }
        Status::Failed(e) => {
            st.add(BAD, "  ✕ ");
            st.add(MUTED, e)
        }
    };
    lines.push(frame::row(w, st));
    let mut hint = Line::new();
    if matches!(status, Status::Working) {
        hint.add(MUTED, "  ");
    } else {
        hint.add(ACCENT, "  any key");
        hint.add(MUTED, " finish");
    }
    lines.push(frame::row(w, hint));
    lines.push(frame::bottom(w));
    lines
}
