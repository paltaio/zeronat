pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub mod admin;
pub mod bridge;
pub mod client;
pub mod config;
pub mod dgram;
#[cfg(feature = "dht")]
pub mod dht;
pub mod identity;
pub mod kcp;
#[cfg(target_os = "linux")]
pub mod netfilter;
pub mod noise;
pub mod pppoe;
pub mod proto;
pub mod server;
pub mod tap;
#[cfg(all(feature = "tui", unix))]
pub mod tui;
