//! Virtual network device. Backs both the L2 `--tap` bridge and the L3 `--tun`
//! all-ports mode: the read/write path is identical (one syscall is one frame),
//! only the open flags and post-open configuration differ (a TAP enslaves to a
//! bridge; a TUN is assigned an IP). The device implementation is Linux-only (it
//! speaks the Linux tun/tap, bridge, and address ioctls); `TapConfig`/`TunConfig`
//! are plain data shared by all platforms so the CLI and run loops compile
//! everywhere and report a clear error when the mode is requested off Linux.

use std::net::Ipv4Addr;

/// L2 bridge-mode configuration parsed from the CLI.
#[derive(Clone)]
pub struct TapConfig {
    pub name: String,
    pub mtu: usize,
    pub bridge: Option<String>,
}

/// L3 tunnel-mode configuration. `addr`/`prefix_len` are this node's address on
/// the secret-derived tunnel subnet (server `.1`, client `.2`).
#[derive(Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: usize,
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::TapDevice;
