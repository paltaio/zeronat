//! Dependency-free terminal-UI core shared by the zeronat admin console and the
//! installer: ANSI styling, box-drawing frames, and key parsing.
//!
//! Terminal I/O (raw mode, the render target) is intentionally not here: the two
//! consumers drive different devices (the console uses stdio, the installer uses
//! /dev/tty so it works under `curl | sh`), so each keeps its own small shim and
//! shares only the visual vocabulary and input model.

pub mod frame;
pub mod key;
pub mod style;
