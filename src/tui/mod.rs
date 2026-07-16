//! The admin console and the stdio terminal shim that drives it.
//!
//! Styling, box-drawing, and key parsing come from the shared `zntui` crate; the
//! pieces here are zeronat-specific: raw-mode control of stdio, an async key
//! reader, a frame renderer, `console`, a live view of one server with inline
//! control over its routes and listeners, and `client_console`, the same for
//! one running client over its local admin socket.

pub use zntui::{frame, style};

mod client_console;
mod console;
mod input;
mod render;
mod term;

pub use client_console::run as run_client;
pub use console::run;
pub use term::stdout_is_tty;
