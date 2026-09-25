//! The admin console and the stdio terminal shim that drives it.
//!
//! Styling, box-drawing, and key parsing come from the shared `zntui` crate; the
//! pieces here are zeronat-specific: raw-mode control of stdio, an async key
//! reader, a frame renderer, `console`, a live view of one server with inline
//! control over its routes and listeners, and `client_console`, the same for
//! one running client over its local admin socket.

pub use zntui::{frame, style};

mod client_console;
mod common;
mod console;
mod input;
mod render;
mod term;

pub use term::stdout_is_tty;

type Session = std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<()>>>>;

/// The server console, boxed: the caller holds one pointer instead of the
/// console's whole state.
#[inline(never)]
pub fn run(server: String, secret: String) -> Session {
    Box::pin(console::run(server, secret))
}

/// The client console, boxed like [`run`].
#[inline(never)]
pub fn run_client(socket: Option<std::path::PathBuf>) -> Session {
    Box::pin(client_console::run(socket))
}
