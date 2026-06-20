//! zeronat installer: a small terminal wizard that configures and installs
//! zeronat (server or client) with no flags to remember. Driven over /dev/tty so
//! it works under `curl ... | sh`.

mod args;
mod install;
mod sys;
mod term;
mod ui;

use args::Host;
use install::{Lvl, Outcome};
use term::{Renderer, Tty};
use ui::App;
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

const USAGE: &str = "\
zeronat installer

  curl -fsSL https://paltaio.github.io/zeronat/get.sh | sh -s -- [options]

  --server | --client       side to install on this machine
  --method docker|systemd   install method (default: docker if present, else systemd)
  --deploy compose|run      (docker only) compose file or plain docker run
  --ports \"443/tcp 80/tcp 51820/udp\"
  --control PORT            tunnel control port (default 2222)
  --secret SECRET           shared secret (default: generated)
  --server-addr HOST[:PORT] (client only) where the server is reachable
  --dht                     find the server over the DHT (dynamic IP, no fixed address)
  --announce-ip IP          (server, with --dht) public IPv4 to announce
  --announce-port PORT      (server, with --dht) public port to announce
  --tap NAME                L2 bridge instead of ports: relay raw Ethernet/PPPoE (Linux)
  --bridge NAME             (with --tap) enslave the TAP to this existing bridge
  --tap-mtu N               (with --tap) TAP MTU (default 1400)
  -y, --yes                 no prompts; fail if a required value is missing
  -n, --dry-run             preview the steps without making changes
  -h, --help

With no options it runs the interactive wizard. --ports and --tap are mutually exclusive.";

fn real_main() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match args::parse(&argv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if parsed.help {
        println!("{USAGE}");
        return 0;
    }

    let dry = parsed.dry;
    // Headless when -y is passed or there is no terminal to drive the wizard.
    let headless = parsed.headless || Tty::open().is_err();

    // Pre-flight on the normal terminal, before any alt screen: cache sudo creds
    // and probe the host so config reflects what is actually available.
    if !dry {
        if let Err(e) = sys::ensure_privilege() {
            eprintln!("error: {e}");
            return 1;
        }
    }
    let have_docker = sys::have("docker");
    let have_compose = have_docker && sys::have_compose();
    // Read the on-disk secret even in dry-run so the preview shows the secret a
    // real run would reuse, not a freshly generated one.
    let existing = sys::existing_secret();
    let host = Host {
        have_docker,
        have_compose,
        existing_secret: existing,
    };

    if headless {
        return run_headless(&parsed, &host, dry);
    }

    let cfg = match args::build(&parsed, &host, headless) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

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
            let _ = tty.write_all(render_outcome(&o, true).as_bytes());
            0
        }
        Err(e) => {
            let _ =
                tty.write_all(format!("\n  \x1b[91m✕ install failed\x1b[0m  {e}\n\n").as_bytes());
            1
        }
    }
}

/// Non-interactive install: build and validate the config from flags, then run
/// it printing plain lines (no raw mode, alt screen, or spinner). Steps and info
/// go to stderr; the copy-pasteable outcome goes to stdout.
fn run_headless(parsed: &args::Parsed, host: &Host, dry: bool) -> i32 {
    let cfg = match args::build(parsed, host, true) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut runner = PlainRunner;
    match install::execute(&cfg, dry, &mut runner) {
        Ok(o) => {
            print!("{}", render_outcome(&o, false));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

struct PlainRunner;

impl install::Runner for PlainRunner {
    fn step(&mut self, desc: String) {
        eprintln!("  {desc}");
    }

    fn info(&mut self, msg: String) {
        eprintln!("    {msg}");
    }

    fn run(
        &mut self,
        privileged: bool,
        program: &str,
        args: &[&str],
    ) -> Result<std::process::Output, String> {
        sys::run(privileged, program, args)
    }
}

enum Status<'a> {
    Working,
    Done(&'a Outcome),
    Failed(&'a str),
}

/// Format the install result for the normal screen: the wizard writes it to the
/// tty after the alt screen closes, the headless path prints it to stdout. The
/// peer command sits alone on an indented line so a copy-paste grabs exactly it.
/// `color` adds ANSI styling for an interactive terminal.
fn render_outcome(o: &Outcome, color: bool) -> String {
    let (green, accent, dim, bold, reset, check) = if color {
        ("\x1b[92m", "\x1b[96;1m", "\x1b[90m", "\x1b[1m", "\x1b[0m", "✓ ")
    } else {
        ("", "", "", "", "", "")
    };
    let mut s = String::new();
    s.push_str(&format!("\n  {green}{check}{reset}{bold}{}{reset}\n\n", o.headline));
    if let Some(ran) = &o.ran {
        s.push_str(&format!("  {dim}Ran:{reset}\n    {ran}\n\n"));
    }
    s.push_str(&format!("  {dim}manage it with{reset}\n    {}\n\n", o.manage));
    s.push_str(&format!("  {accent}{}{reset}\n\n", o.peer_intro));
    s.push_str(&format!("    {bold}{}{reset}\n\n", o.peer_cmd));
    s
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
