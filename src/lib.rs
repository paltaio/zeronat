pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub mod admin;
pub mod admission;
pub mod bridge;
pub mod client;
pub mod client_admin;
pub mod clientcfg;
pub mod clientctl;
pub mod clientproto;
pub mod config;
pub mod dgram;
#[cfg(feature = "dht")]
pub mod dht;
#[cfg(target_os = "linux")]
pub mod exitroute;
pub mod identity;
pub mod kcp;
pub mod logging;
#[cfg(target_os = "linux")]
pub mod netfilter;
pub mod noise;
pub mod peer;
#[cfg(target_os = "linux")]
pub(crate) mod peerexit;
#[cfg(target_os = "linux")]
pub(crate) mod peersegment;
pub mod peerslot;
pub mod pktinfo;
pub mod pppoe;
pub mod proto;
pub mod proxyproto;
pub mod punch;
#[cfg(target_os = "linux")]
pub mod route;
pub mod server;
pub mod tap;
#[cfg(all(feature = "tui", unix))]
pub mod tui;
pub mod upgrade;

/// Spawn a task on the tokio runtime.
///
/// A direct `tokio::spawn` instantiates the spawn path and the task vtable for
/// every future type it is handed; erasing the future first leaves one
/// instantiation per output type, at the cost of an allocation per task and an
/// indirect call per poll.
#[track_caller]
#[allow(clippy::disallowed_methods)]
pub(crate) fn spawn<T: Send + 'static>(
    f: impl std::future::Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    let f: std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>> = Box::pin(f);
    tokio::spawn(f)
}
