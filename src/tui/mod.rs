//! A small terminal-UI toolkit and the admin console built on it.
//!
//! The toolkit is intentionally thin: raw-mode terminal control, a key reader,
//! ANSI styling, box-drawing, and a frame renderer that diffs rows so a steady
//! screen emits nothing. `console` is its first consumer, a live view of one
//! server with inline control over its routes and listeners.

mod console;
mod frame;
mod input;
mod render;
mod style;
mod term;

pub use console::run;
pub use term::stdout_is_tty;
