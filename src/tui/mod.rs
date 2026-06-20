//! The admin console and the stdio terminal shim that drives it.
//!
//! Styling, box-drawing, and key parsing come from the shared `zntui` crate; the
//! pieces here are zeronat-specific: raw-mode control of stdio, an async key
//! reader, a frame renderer, and `console`, a live view of one server with
//! inline control over its routes and listeners.

pub use zntui::{frame, style};

mod console;
mod input;
mod render;
mod term;

pub use console::run;
pub use term::stdout_is_tty;
