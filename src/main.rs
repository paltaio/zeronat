use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use zeronat::{client, server};

#[derive(Parser)]
#[command(name = "zeronat", about = "Minimal encrypted reverse port tunnel")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run on the public host (VPS). Exposes ports and forwards them over the tunnel.
    Server {
        /// Address to bind public and control listeners on.
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        /// Control port the client connects to.
        #[arg(long, default_value_t = 2222)]
        control: u16,
        /// Shared secret. Must match the client.
        #[arg(long, env = "ZERONAT_SECRET")]
        secret: String,
        /// Public TCP port to expose (repeatable).
        #[arg(long = "tcp")]
        tcp: Vec<u16>,
        /// Public UDP port to expose (repeatable).
        #[arg(long = "udp")]
        udp: Vec<u16>,
    },
    /// Run on the host behind CG-NAT. Dials out to the server and serves local ports.
    Client {
        /// Server control address, e.g. 203.0.113.10:2222.
        #[arg(long)]
        server: String,
        /// Shared secret. Must match the server.
        #[arg(long, env = "ZERONAT_SECRET")]
        secret: String,
        /// Forward a TCP port: PORT | PORT:LOCALPORT | PORT:HOST:PORT (repeatable).
        #[arg(long = "tcp")]
        tcp: Vec<String>,
        /// Forward a UDP port: PORT | PORT:LOCALPORT | PORT:HOST:PORT (repeatable).
        #[arg(long = "udp")]
        udp: Vec<String>,
    },
}

/// Parse a forward spec into (public_port, "host:port" target).
fn parse_forward(spec: &str) -> Result<(u16, String)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [p] => {
            let port: u16 = p.parse()?;
            Ok((port, format!("127.0.0.1:{port}")))
        }
        [p, lp] => {
            let port: u16 = p.parse()?;
            let lport: u16 = lp.parse()?;
            Ok((port, format!("127.0.0.1:{lport}")))
        }
        [p, host, lp] => {
            let port: u16 = p.parse()?;
            let lport: u16 = lp.parse()?;
            Ok((port, format!("{host}:{lport}")))
        }
        _ => bail!("invalid forward spec '{spec}'"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Server {
            bind,
            control,
            secret,
            tcp,
            udp,
        } => {
            if tcp.is_empty() && udp.is_empty() {
                bail!("no ports to expose: pass at least one --tcp or --udp");
            }
            server::run(bind, control, secret, tcp, udp).await
        }
        Cmd::Client {
            server,
            secret,
            tcp,
            udp,
        } => {
            if tcp.is_empty() && udp.is_empty() {
                bail!("nothing to forward: pass at least one --tcp or --udp");
            }
            let tcp = tcp
                .iter()
                .map(|s| parse_forward(s))
                .collect::<Result<Vec<_>>>()?;
            let udp = udp
                .iter()
                .map(|s| parse_forward(s))
                .collect::<Result<Vec<_>>>()?;
            client::run(server, secret, tcp, udp, client::Transport::Auto).await
        }
    }
}
