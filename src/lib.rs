pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub mod bridge;
pub mod client;
pub mod dgram;
pub mod kcp;
pub mod noise;
pub mod proto;
pub mod server;
