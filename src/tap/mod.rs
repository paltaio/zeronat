//! L2 TAP bridge. The device implementation is Linux-only (it speaks the Linux
//! tun/tap and bridge ioctls); `TapConfig` is plain data shared by all platforms
//! so the CLI and run loops compile everywhere and can report a clear error when
//! `--tap` is requested on a platform without an implementation.

/// Bridge-mode configuration parsed from the CLI.
pub struct TapConfig {
    pub name: String,
    pub mtu: usize,
    pub bridge: Option<String>,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::TapDevice;
