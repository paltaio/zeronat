//! Strict TOML-subset grammar for the client config file.
//!
//! A `[client]` singleton plus `[[servers]]`/`[[forwards]]`/`[[pppoe]]`
//! arrays-of-tables and an optional `[tap]` or `[tun]` device table, built on
//! the value-agnostic lexer in [`crate::config::codec`]. `parse_client`
//! enforces the grammar and per-entry rules; cross-entry rules live in
//! [`ClientConfig::validate`] so that a parseable but contradictory file is a
//! fatal boot error the operator can fix in place, never quarantined.

use std::net::Ipv4Addr;
use std::path::Path;

use crate::client::Transport;
use crate::clientproto::ServerSecret;
use crate::config::codec::{
    err, kv_bool, kv_num, kv_quoted, parse_tables, quote, quote_into, table, Grammar, Key, Record,
    TableDef,
};
use crate::config::LoadError;
use crate::proto::{proto_name, Proto};
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgServer {
    /// Unique profile name; the select-server key.
    pub name: String,
    /// `"dht"` or `host:port`.
    pub addr: String,
    /// Fills `secret`, `discovery`, and the `credential` derived for
    /// `[client].id` when the entry leaves them out.
    pub seed: Option<ServerSecret>,
    pub secret: ServerSecret,
    pub credential: ServerSecret,
    /// The credential the server's DHT record is keyed by; required when
    /// `addr` is `"dht"`.
    pub discovery: Option<ServerSecret>,
    pub transport: Transport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgForward {
    pub proto: Proto,
    pub port: u16,
    pub target: String,
    /// Prefix each local connection with a PROXY protocol v2 header (TCP only).
    pub proxy: bool,
    /// Relay idle window override in whole seconds, minimum 1.
    pub idle: Option<u32>,
    /// Whether the forward is served; a disabled entry keeps its
    /// configuration.
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgPppoe {
    /// Unique session name; the spawn/stop key.
    pub name: String,
    /// Bring this session up at boot when no `[[forwards]]` are declared.
    pub autostart: bool,
    pub username: String,
    pub password: Option<String>,
    /// Path to a file holding the password; takes precedence over `password`.
    pub password_file: Option<String>,
    /// PPPoE Service-Name selector (empty = any).
    pub service: String,
    pub mtu: u16,
    pub default_route: bool,
    /// MSS clamp that rides with `default_route`.
    pub clamp_mss: bool,
    pub request_dns: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgTap {
    pub dev: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgTun {
    pub dev: Option<String>,
    /// This node's tunnel address as `(ip, prefix_len)`; derived from the
    /// active server's secret when unset.
    pub address: Option<(Ipv4Addr, u8)>,
    /// Route the host's IPv4 traffic through the tunnel while the profile is
    /// up.
    pub exit: bool,
    /// Exit with no fallback: every original default route is deleted and
    /// IPv6 goes to loopback while the tunnel is up; a crash leaves the host
    /// without a default route.
    pub exit_strict: bool,
    /// The peer whose internet connection this tunnel exits through, naming
    /// its 64-hex public identity. Set, the table feeds a peer consumer slot;
    /// unset, it feeds the server slot.
    pub exit_via: Option<String>,
}

/// What this node provides to peers. Provider roles are explicit, never
/// implied: the union of these bits is what the client announces.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CfgPeer {
    /// Serve one consumer's IPv4 traffic out this node's connection.
    pub exit: bool,
    /// Interface the served consumer's traffic masquerades out of; the
    /// default-route interface when unset.
    pub exit_iface: Option<String>,
    /// Attach consumers to this node's L2 segment, naming the bridge the
    /// segment's interface belongs to.
    pub segment: Option<String>,
    /// The consumer identities this node's providers admit, each 64 hex
    /// characters. Required non-empty when `exit` or `segment` is set.
    pub allow: Vec<String>,
}

impl CfgPeer {
    /// The allowlist as decoded identities. A malformed entry is an error, and
    /// so is an empty list when any provider capability is set: a provider no
    /// consumer may use serves nothing.
    pub fn allow_identities(&self) -> Result<Vec<[u8; 32]>> {
        let mut allow = Vec::with_capacity(self.allow.len());
        for entry in &self.allow {
            allow.push(crate::secret::decode(entry).map_err(|_| -> crate::Error {
                errf!("[peer] allow entry `{entry}` must be a 64-hex peer identity")
            })?);
        }
        if (self.exit || self.segment.is_some()) && allow.is_empty() {
            return Err(
                "[peer] allow must name at least one consumer identity when `exit` or `segment` \
                 is set"
                    .into(),
            );
        }
        Ok(allow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientConfig {
    pub id: Option<String>,
    /// The static x25519 private key peer sessions authenticate with, as 64
    /// hex characters. Required when any peer slot is configured.
    pub peer_secret: Option<ServerSecret>,
    /// Which `[[servers]]` entry to dial at boot; the first entry when unset.
    pub active: Option<String>,
    /// Admin socket path override.
    pub control: Option<String>,
    pub servers: Vec<CfgServer>,
    pub forwards: Vec<CfgForward>,
    pub pppoe: Vec<CfgPppoe>,
    pub tap: Option<CfgTap>,
    pub tun: Option<CfgTun>,
    pub peer: Option<CfgPeer>,
}

impl CfgTun {
    /// Whether this table feeds a peer consumer slot rather than the server
    /// slot.
    pub fn is_peer(&self) -> bool {
        self.exit_via.is_some()
    }
}

impl ClientConfig {
    /// Cross-entry rules over a successfully parsed config: the active
    /// reference, name and forward-key uniqueness, the single-autostart rule,
    /// and device exclusivity. A violation here is a fatal boot error, kept
    /// out of `parse_client` so the file is never quarantined for it.
    #[inline(never)]
    pub fn validate(&self) -> Result<()> {
        let peer_secret = self
            .peer_secret
            .as_ref()
            .map(|secret| crate::secret::decode(&secret.0))
            .transpose()
            .map_err(|e| -> crate::Error { errf!("[client] peer_secret {e}") })?;
        let has_peer_slots = self.tun.as_ref().is_some_and(CfgTun::is_peer)
            || self
                .peer
                .as_ref()
                .is_some_and(|peer| peer.exit || peer.segment.is_some());
        if has_peer_slots && peer_secret.is_none() {
            return Err(
                "[client] peer_secret is required when peer sessions are configured".into(),
            );
        }
        if let Some(peer) = self.tun.as_ref().and_then(|tun| tun.exit_via.as_deref()) {
            crate::secret::decode(peer).map_err(|_| -> crate::Error {
                "[tun] exit_via must be a 64-hex peer identity".into()
            })?;
        }
        if let Some(peer) = &self.peer {
            peer.allow_identities()?;
        }
        let mut names: Vec<&str> = Vec::new();
        let mut session_keys: Vec<[u8; 32]> = Vec::new();
        for s in &self.servers {
            let secret = crate::secret::decode(&s.secret.0)
                .map_err(|e| server_err(&s.name, &e.to_string()))?;
            let credential = crate::secret::decode(&s.credential.0)
                .map_err(|e| server_err(&s.name, &format!("client credential {e}")))?;
            if peer_secret.is_some_and(|peer| peer == secret || peer == credential) {
                return Err(format!(
                    "[client] peer_secret must differ from the secret and credential for server `{}`",
                    s.name
                )
                .into());
            }
            if names.contains(&s.name.as_str()) {
                return Err(errf!("duplicate server name `{}`", s.name));
            }
            names.push(&s.name);
            session_keys.push(secret);
            session_keys.push(credential);
        }
        // The discovery credential must not double as any authenticating
        // value in the file: whoever holds it may locate a server, nothing
        // more.
        for s in &self.servers {
            let discovery = s
                .discovery
                .as_ref()
                .map(|d| crate::secret::decode(&d.0))
                .transpose()
                .map_err(|e| server_err(&s.name, &format!("`discovery` {e}")))?;
            let Some(discovery) = discovery else {
                if s.addr == "dht" {
                    return Err(server_err(
                        &s.name,
                        "uses addr = \"dht\" and needs a `discovery` credential",
                    ));
                }
                continue;
            };
            if session_keys.contains(&discovery) || peer_secret == Some(discovery) {
                return Err(server_err(
                    &s.name,
                    "`discovery` must differ from every secret and credential in the file",
                ));
            }
        }
        if let Some(active) = &self.active {
            if !self.servers.iter().any(|s| &s.name == active) {
                return Err(errf!(
                    "active = {} names no [[servers]] entry",
                    quote(active)
                ));
            }
        }
        let mut fwd: Vec<(Proto, u16)> = Vec::new();
        for f in &self.forwards {
            if fwd.contains(&(f.proto, f.port)) {
                return Err(errf!(
                    "duplicate forward {} {}",
                    proto_name(f.proto),
                    f.port
                ));
            }
            fwd.push((f.proto, f.port));
        }
        let mut sessions: Vec<&str> = Vec::new();
        for p in &self.pppoe {
            if sessions.contains(&p.name.as_str()) {
                return Err(errf!("duplicate pppoe name `{}`", p.name));
            }
            sessions.push(&p.name);
        }
        if self.pppoe.iter().filter(|p| p.autostart).count() > 1 {
            return Err("more than one [[pppoe]] entry sets autostart = true".into());
        }
        // A pair addresses both its ends off the shared secret, so a consumer
        // table has no address of its own to take.
        if self
            .tun
            .as_ref()
            .is_some_and(|t| t.is_peer() && t.address.is_some())
        {
            return Err("[tun] `address` cannot be combined with `exit_via`".into());
        }
        // Device exclusivity keys on the slot a table feeds, not on the table
        // being present: a [tun] naming a peer feeds a consumer slot and
        // leaves the server slot to its forwards, its pppoe sessions, or
        // nothing. What that consumer opens is admitted against the running
        // slots at startup instead.
        let server_tun = self.tun.as_ref().is_some_and(|t| !t.is_peer());
        if self.tap.is_some() && server_tun {
            return Err("[tap] and [tun] are mutually exclusive".into());
        }
        if (self.tap.is_some() || server_tun)
            && (!self.forwards.is_empty() || !self.pppoe.is_empty())
        {
            return Err("[tap]/[tun] cannot be combined with [[forwards]] or [[pppoe]]".into());
        }
        Ok(())
    }
}

/// A `validate` error about the `[[servers]]` entry `name`.
#[inline(never)]
fn server_err(name: &str, what: &str) -> crate::Error {
    errf!("server `{name}` {what}")
}

const GRAMMAR: Grammar = Grammar {
    headers: "client [servers] [forwards] [pppoe] tap tun peer",
    tables: &[
        TableDef {
            label: "[client]",
            single: true,
            keys: "id peer_secret active control",
            kinds: &[Key::Str(0), Key::Str(1), Key::Str(2), Key::Str(3)],
        },
        TableDef {
            label: "[[servers]]",
            single: false,
            keys: "name addr seed secret credential discovery transport",
            kinds: &[
                Key::Str(0),
                Key::Str(1),
                Key::Str(2),
                Key::Str(3),
                Key::Str(4),
                Key::Str(5),
                Key::Transport,
            ],
        },
        TableDef {
            label: "[[forwards]]",
            single: false,
            keys: "proto port target proxy idle enabled",
            kinds: &[
                Key::Proto,
                Key::Int(0),
                Key::Str(0),
                Key::Bool(0),
                Key::Idle,
                Key::Bool(1),
            ],
        },
        TableDef {
            label: "[[pppoe]]",
            single: false,
            keys: "name autostart username password password_file service mtu default_route \
                   clamp_mss request_dns",
            kinds: &[
                Key::Str(0),
                Key::Bool(0),
                Key::Str(1),
                Key::Str(2),
                Key::Str(3),
                Key::Str(4),
                Key::Int(0),
                Key::Bool(1),
                Key::Bool(2),
                Key::Bool(3),
            ],
        },
        TableDef {
            label: "[tap]",
            single: true,
            keys: "dev",
            kinds: &[Key::Str(0)],
        },
        TableDef {
            label: "[tun]",
            single: true,
            keys: "dev address exit exit_strict exit_via",
            kinds: &[
                Key::Str(0),
                Key::Cidr,
                Key::Bool(0),
                Key::Bool(1),
                Key::Str(1),
            ],
        },
        TableDef {
            label: "[peer]",
            single: true,
            keys: "exit exit_iface segment allow",
            kinds: &[Key::Bool(0), Key::Str(0), Key::Str(1), Key::StrList],
        },
    ],
};

/// Load a client config. A missing file yields the default (empty) config so a
/// first boot with `--config` pointing at a not-yet-written path is not an
/// error.
pub fn load(path: &Path) -> std::result::Result<ClientConfig, LoadError> {
    crate::config::codec::load(path, parse_client)
}

#[inline(never)]
pub fn parse_client(text: &str) -> Result<ClientConfig> {
    let mut cfg = ClientConfig::default();
    // Seeded `[[servers]]` entries without a `credential`, by index. Their
    // credential names `[client].id`, which may be declared after them, so it
    // is derived once the whole file is read.
    let mut seeded: Vec<(usize, crate::seed::Seed)> = Vec::new();

    parse_tables(text, &GRAMMAR, &mut |table, record, n| {
        close_record(table, &mut cfg, record, &mut seeded, n)
    })?;

    if !seeded.is_empty() {
        let id = cfg.id.as_deref().ok_or_else(|| {
            err(
                text.lines().count(),
                "a [[servers]] `seed` derives the client credential for [client].id, which is missing",
            )
        })?;
        for (index, seed) in &seeded {
            cfg.servers[*index].credential = ServerSecret(seed.client(id));
        }
    }
    Ok(cfg)
}

/// Validate and commit the in-progress record. Required keys and
/// combinations that depend on more than one key of the same entry (`proxy`
/// against `proto`, `clamp_mss` against `default_route`) are checked here,
/// where the whole entry is known.
#[inline(never)]
fn close_record(
    table: usize,
    cfg: &mut ClientConfig,
    record: &mut Record,
    seeded: &mut Vec<(usize, crate::seed::Seed)>,
    n: usize,
) -> Result<()> {
    match table {
        0 => {
            cfg.id = record.strs[0].take();
            cfg.peer_secret = record.strs[1].take().map(ServerSecret);
            cfg.active = record.strs[2].take();
            cfg.control = record.strs[3].take();
        }
        1 => {
            let name = record.required(0, n, "server missing `name`")?;
            if name.is_empty() {
                return Err(err(n, "server `name` must not be empty"));
            }
            let addr = record.required(1, n, "server missing `addr`")?;
            let seed = match record.strs[2].take() {
                Some(hex) => {
                    let seed = crate::seed::Seed::parse(&hex)
                        .map_err(|e| err(n, &format!("server {e}")))?;
                    Some((hex, seed))
                }
                None => None,
            };
            let secret = match (record.strs[3].take(), &seed) {
                (Some(secret), _) => secret,
                (None, Some((_, seed))) => seed.network(),
                (None, None) => return Err(err(n, "server missing `secret` or `seed`")),
            };
            let discovery = record.strs[5]
                .take()
                .or_else(|| seed.as_ref().map(|(_, seed)| seed.discovery()));
            let (seed_hex, seed) = seed.unzip();
            let credential = match (record.strs[4].take(), seed) {
                (Some(credential), _) => credential,
                // Replaced by the seed's `client <id>` once the whole file is
                // read; the secret stands in until then.
                (None, Some(seed)) => {
                    seeded.push((cfg.servers.len(), seed));
                    secret.clone()
                }
                (None, None) => secret.clone(),
            };
            cfg.servers.push(CfgServer {
                name,
                addr,
                seed: seed_hex.map(ServerSecret),
                secret: ServerSecret(secret),
                credential: ServerSecret(credential),
                discovery: discovery.map(ServerSecret),
                transport: record.transport.take().unwrap_or(Transport::Auto),
            });
        }
        2 => {
            let proto = record
                .proto
                .ok_or_else(|| err(n, "forward missing `proto`"))?;
            let port = record.ints[0].ok_or_else(|| err(n, "forward missing `port`"))?;
            if record.bools[0].is_some() && proto == Proto::Udp {
                return Err(err(n, "`proxy` is not supported on udp forwards"));
            }
            cfg.forwards.push(CfgForward {
                proto,
                port,
                target: record.strs[0]
                    .take()
                    .unwrap_or_else(|| format!("127.0.0.1:{port}")),
                proxy: record.bools[0].unwrap_or(false),
                idle: record.idle.take(),
                enabled: record.bools[1].unwrap_or(true),
            });
        }
        3 => {
            let name = record.required(0, n, "pppoe missing `name`")?;
            if name.is_empty() {
                return Err(err(n, "pppoe `name` must not be empty"));
            }
            let username = record.required(1, n, "pppoe missing `username`")?;
            let default_route = record.bools[1].unwrap_or(false);
            if record.bools[2] == Some(false) && !default_route {
                return Err(err(
                    n,
                    "`clamp_mss = false` requires `default_route = true`",
                ));
            }
            cfg.pppoe.push(CfgPppoe {
                name,
                autostart: record.bools[0].unwrap_or(false),
                username,
                password: record.strs[2].take(),
                password_file: record.strs[3].take(),
                service: record.strs[4].take().unwrap_or_default(),
                mtu: record.ints[0].unwrap_or(1492),
                default_route,
                clamp_mss: record.bools[2].unwrap_or(true),
                request_dns: record.bools[3].unwrap_or(false),
            });
        }
        4 => {
            let dev = record.required(0, n, "tap missing `dev`")?;
            if dev.is_empty() {
                return Err(err(n, "tap `dev` must not be empty"));
            }
            cfg.tap = Some(CfgTap { dev });
        }
        5 => {
            let exit = record.bools[0].unwrap_or(false);
            let exit_strict = record.bools[1].unwrap_or(false);
            if exit_strict && !exit {
                return Err(err(n, "`exit_strict = true` requires `exit = true`"));
            }
            if record.strs[1].as_deref() == Some("") {
                return Err(err(n, "tun `exit_via` must name a peer"));
            }
            cfg.tun = Some(CfgTun {
                dev: record.strs[0].take(),
                address: record.address.take(),
                exit,
                exit_strict,
                exit_via: record.strs[1].take(),
            });
        }
        _ => {
            if record.strs[1].as_deref() == Some("") {
                return Err(err(n, "peer `segment` must name an interface"));
            }
            let exit = record.bools[0].unwrap_or(false);
            if record.strs[0].as_deref() == Some("") {
                return Err(err(n, "peer `exit_iface` must name an interface"));
            }
            if record.strs[0].is_some() && !exit {
                return Err(err(n, "`exit_iface` requires `exit = true`"));
            }
            cfg.peer = Some(CfgPeer {
                exit,
                exit_iface: record.strs[0].take(),
                segment: record.strs[1].take(),
                allow: record.allow.take().unwrap_or_default(),
            });
        }
    }
    Ok(())
}

fn transport_str(t: Transport) -> &'static str {
    match t {
        Transport::Auto => "auto",
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    }
}

/// Emit a deterministic, comment-free rendering of `cfg`. Entries keep their
/// declaration order (the first `[[servers]]` entry is the boot default when
/// `active` is unset) and default-valued keys are omitted.
#[inline(never)]
pub fn serialize_client(cfg: &ClientConfig) -> String {
    let mut out = String::new();

    if cfg.id.is_some()
        || cfg.peer_secret.is_some()
        || cfg.active.is_some()
        || cfg.control.is_some()
    {
        out.push_str("[client]\n");
        if let Some(id) = &cfg.id {
            kv_quoted(&mut out, "id", id);
        }
        if let Some(secret) = &cfg.peer_secret {
            kv_quoted(&mut out, "peer_secret", &secret.0);
        }
        if let Some(active) = &cfg.active {
            kv_quoted(&mut out, "active", active);
        }
        if let Some(control) = &cfg.control {
            kv_quoted(&mut out, "control", control);
        }
    }

    for s in &cfg.servers {
        table(&mut out, "[[servers]]");
        kv_quoted(&mut out, "name", &s.name);
        kv_quoted(&mut out, "addr", &s.addr);
        // A value the seed derives is left to the seed, so a later change to
        // `[client].id` re-derives the credential instead of keeping a stale
        // copy.
        let seed = s
            .seed
            .as_ref()
            .and_then(|seed| crate::seed::Seed::parse(&seed.0).ok());
        let derived = |value: Option<String>, explicit: &str| value.as_deref() == Some(explicit);
        if let Some(seed) = &s.seed {
            kv_quoted(&mut out, "seed", &seed.0);
        }
        if !derived(seed.as_ref().map(|seed| seed.network()), &s.secret.0) {
            kv_quoted(&mut out, "secret", &s.secret.0);
        }
        let client = seed
            .as_ref()
            .zip(cfg.id.as_deref())
            .map(|(seed, id)| seed.client(id));
        if !derived(client, &s.credential.0) {
            kv_quoted(&mut out, "credential", &s.credential.0);
        }
        if let Some(discovery) = &s.discovery {
            if !derived(seed.as_ref().map(|seed| seed.discovery()), &discovery.0) {
                kv_quoted(&mut out, "discovery", &discovery.0);
            }
        }
        if s.transport != Transport::Auto {
            kv_quoted(&mut out, "transport", transport_str(s.transport));
        }
    }

    for f in &cfg.forwards {
        table(&mut out, "[[forwards]]");
        kv_quoted(&mut out, "proto", proto_name(f.proto));
        kv_num(&mut out, "port", f.port.into());
        kv_quoted(&mut out, "target", &f.target);
        if !f.enabled {
            kv_bool(&mut out, "enabled", false);
        }
        if f.proxy {
            kv_bool(&mut out, "proxy", true);
        }
        if let Some(secs) = f.idle {
            kv_num(&mut out, "idle", secs.into());
        }
    }

    for p in &cfg.pppoe {
        table(&mut out, "[[pppoe]]");
        kv_quoted(&mut out, "name", &p.name);
        if p.autostart {
            kv_bool(&mut out, "autostart", true);
        }
        kv_quoted(&mut out, "username", &p.username);
        if let Some(password) = &p.password {
            kv_quoted(&mut out, "password", password);
        }
        if let Some(path) = &p.password_file {
            kv_quoted(&mut out, "password_file", path);
        }
        if !p.service.is_empty() {
            kv_quoted(&mut out, "service", &p.service);
        }
        if p.mtu != 1492 {
            kv_num(&mut out, "mtu", p.mtu.into());
        }
        if p.default_route {
            kv_bool(&mut out, "default_route", true);
        }
        if !p.clamp_mss {
            kv_bool(&mut out, "clamp_mss", false);
        }
        if p.request_dns {
            kv_bool(&mut out, "request_dns", true);
        }
    }

    if let Some(tap) = &cfg.tap {
        table(&mut out, "[tap]");
        kv_quoted(&mut out, "dev", &tap.dev);
    }

    if let Some(tun) = &cfg.tun {
        table(&mut out, "[tun]");
        if let Some(dev) = &tun.dev {
            kv_quoted(&mut out, "dev", dev);
        }
        if let Some((ip, len)) = tun.address {
            kv_quoted(&mut out, "address", &format!("{ip}/{len}"));
        }
        if tun.exit {
            kv_bool(&mut out, "exit", true);
        }
        if tun.exit_strict {
            kv_bool(&mut out, "exit_strict", true);
        }
        if let Some(peer) = &tun.exit_via {
            kv_quoted(&mut out, "exit_via", peer);
        }
    }

    if let Some(peer) = &cfg.peer {
        table(&mut out, "[peer]");
        if peer.exit {
            kv_bool(&mut out, "exit", true);
        }
        if let Some(iface) = &peer.exit_iface {
            kv_quoted(&mut out, "exit_iface", iface);
        }
        if let Some(bridge) = &peer.segment {
            kv_quoted(&mut out, "segment", bridge);
        }
        if !peer.allow.is_empty() {
            out.push_str("allow = [");
            for (i, id) in peer.allow.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                quote_into(&mut out, id);
            }
            out.push_str("]\n");
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER_SECRET: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    const DISCOVERY_SECRET: &str =
        "5555555555555555555555555555555555555555555555555555555555555555";

    fn sample() -> ClientConfig {
        ClientConfig {
            id: Some("rpi-2".into()),
            peer_secret: None,
            active: Some("home".into()),
            control: Some("/run/zeronat/client.sock".into()),
            servers: vec![
                CfgServer {
                    name: "home".into(),
                    addr: "dht".into(),
                    seed: None,
                    secret: ServerSecret(TEST_SECRET.into()),
                    credential: ServerSecret(TEST_SECRET.into()),
                    discovery: Some(ServerSecret(DISCOVERY_SECRET.into())),
                    transport: Transport::Auto,
                },
                CfgServer {
                    name: "oci".into(),
                    addr: "203.0.113.10:2222".into(),
                    seed: None,
                    secret: ServerSecret(OTHER_SECRET.into()),
                    credential: ServerSecret(OTHER_SECRET.into()),
                    discovery: None,
                    transport: Transport::Tcp,
                },
            ],
            forwards: vec![
                CfgForward {
                    proto: Proto::Tcp,
                    port: 8080,
                    target: "127.0.0.1:80".into(),
                    proxy: true,
                    idle: Some(600),
                    enabled: true,
                },
                CfgForward {
                    proto: Proto::Udp,
                    port: 51820,
                    target: "10.0.0.5:51820".into(),
                    proxy: false,
                    idle: None,
                    enabled: false,
                },
            ],
            pppoe: vec![CfgPppoe {
                name: "wan".into(),
                autostart: true,
                username: "user@isp".into(),
                password: None,
                password_file: Some("/etc/zeronat/wan.pass".into()),
                service: "fibra".into(),
                mtu: 1480,
                default_route: true,
                clamp_mss: false,
                request_dns: true,
            }],
            tap: None,
            tun: None,
            peer: None,
        }
    }

    #[test]
    fn roundtrip() {
        let cfg = sample();
        cfg.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&cfg)).unwrap(), cfg);
    }

    // Assertion failures and logged errors debug-print whole configs, so a
    // debug-printed config must not carry any secret or private key.
    #[test]
    fn cfg_debug_redacts_the_server_secret() {
        let peer_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut cfg = sample();
        cfg.peer_secret = Some(ServerSecret(peer_secret.into()));
        let s = format!("{cfg:?}");
        assert!(!s.contains(TEST_SECRET), "{s}");
        assert!(!s.contains(OTHER_SECRET), "{s}");
        assert!(!s.contains(DISCOVERY_SECRET), "{s}");
        assert!(!s.contains(peer_secret), "{s}");
        assert!(s.contains("home"));
    }

    // peer_secret is the trust anchor of every peer slot: it must be present
    // when one is configured, well formed, and never a value the relay knows.
    #[test]
    fn peer_secret_gates_the_peer_slots() {
        let consumer = format!("[tun]\nexit_via = \"{TEST_SECRET}\"\n");
        let error = parse_client(&consumer).unwrap().validate().unwrap_err();
        assert!(
            error.to_string().contains("peer_secret is required"),
            "{error}"
        );
        let provider = "[peer]\nexit = true\n";
        let error = parse_client(provider).unwrap().validate().unwrap_err();
        assert!(
            error.to_string().contains("peer_secret is required"),
            "{error}"
        );

        let malformed = "[client]\npeer_secret = \"short\"\n";
        let error = parse_client(malformed).unwrap().validate().unwrap_err();
        assert!(error.to_string().contains("peer_secret"), "{error}");

        for copied in [TEST_SECRET.to_string(), OTHER_SECRET.to_ascii_uppercase()] {
            let mut cfg = sample();
            cfg.servers.truncate(1);
            cfg.servers[0].credential = ServerSecret(OTHER_SECRET.into());
            cfg.peer_secret = Some(ServerSecret(copied));
            let error = cfg.validate().unwrap_err();
            assert!(error.to_string().contains("must differ"), "{error}");
        }
    }

    #[test]
    fn exit_via_must_be_a_peer_identity() {
        let named = format!(
            "[client]\npeer_secret = \"{OTHER_SECRET}\"\n[tun]\nexit_via = \"office-b1c2\"\n"
        );
        let error = parse_client(&named).unwrap().validate().unwrap_err();
        assert!(
            error.to_string().contains("64-hex peer identity"),
            "{error}"
        );
    }

    #[test]
    fn runtime_secret_format_is_strict() {
        let config = |secret: &str| {
            format!(
                "[[servers]]\nname = \"home\"\naddr = \"127.0.0.1:2222\"\nsecret = \"{secret}\"\n"
            )
        };
        for invalid in [
            "short".to_string(),
            "a".repeat(63),
            "a".repeat(65),
            format!("{}g", "a".repeat(63)),
            format!("{}é", "a".repeat(63)),
        ] {
            let parsed = parse_client(&config(&invalid)).unwrap();
            assert!(
                parsed.validate().is_err(),
                "accepted invalid secret {invalid:?}"
            );
        }
        assert!(parse_client(&config(&"a".repeat(64)))
            .unwrap()
            .validate()
            .is_ok());
        let uppercase = parse_client(&config(&"A".repeat(64))).unwrap();
        assert!(uppercase.validate().is_ok());
    }

    // A dht profile is resolvable only through its discovery credential, so
    // the entry must carry one, well formed and never a value that also
    // authenticates something.
    #[test]
    fn dht_server_requires_its_own_discovery_credential() {
        let entry = |addr: &str, extra: &str| {
            format!(
                "[[servers]]\nname = \"home\"\naddr = \"{addr}\"\nsecret = \"{TEST_SECRET}\"\n\
                 credential = \"{OTHER_SECRET}\"\n{extra}"
            )
        };

        let missing = parse_client(&entry("dht", "")).unwrap();
        let error = missing.validate().unwrap_err().to_string();
        assert!(error.contains("server `home`"), "{error}");
        assert!(error.contains("`discovery`"), "{error}");

        let malformed = parse_client(&entry("dht", "discovery = \"short\"\n")).unwrap();
        let error = malformed.validate().unwrap_err().to_string();
        assert!(error.contains("`discovery`"), "{error}");

        let ok = parse_client(&entry(
            "dht",
            &format!("discovery = \"{DISCOVERY_SECRET}\"\n"),
        ))
        .unwrap();
        ok.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&ok)).unwrap(), ok);

        // A host:port profile needs no discovery credential and may keep one.
        parse_client(&entry("203.0.113.10:2222", ""))
            .unwrap()
            .validate()
            .unwrap();
        let kept = parse_client(&entry(
            "203.0.113.10:2222",
            &format!("discovery = \"{DISCOVERY_SECRET}\"\n"),
        ))
        .unwrap();
        kept.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&kept)).unwrap(), kept);

        // Reusing any secret, credential, or peer key as the discovery
        // credential collapses the separation and is refused.
        for copied in [TEST_SECRET, &TEST_SECRET.to_ascii_uppercase(), OTHER_SECRET] {
            let cfg = parse_client(&entry("dht", &format!("discovery = \"{copied}\"\n"))).unwrap();
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("must differ"), "{error}");
        }
        let peer_copy = format!(
            "[client]\npeer_secret = \"{DISCOVERY_SECRET}\"\n{}",
            entry("dht", &format!("discovery = \"{DISCOVERY_SECRET}\"\n"))
        );
        let error = parse_client(&peer_copy)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(error.contains("must differ"), "{error}");
    }

    #[test]
    fn seeded_server_derives_what_it_leaves_out() {
        let seed = crate::seed::Seed::parse(TEST_SECRET).unwrap();
        // [client] after [[servers]]: the credential still names its id.
        let text = format!(
            "[[servers]]\nname = \"home\"\naddr = \"dht\"\nseed = \"{TEST_SECRET}\"\n\n[client]\nid = \"rpi\"\n"
        );
        let cfg = parse_client(&text).unwrap();
        cfg.validate().unwrap();
        let home = &cfg.servers[0];
        assert_eq!(home.seed.as_ref().unwrap().0, TEST_SECRET);
        assert_eq!(home.secret.0, seed.network());
        assert_eq!(home.credential.0, seed.client("rpi"));
        assert_eq!(home.discovery.as_ref().unwrap().0, seed.discovery());
        assert_eq!(parse_client(&serialize_client(&cfg)).unwrap(), cfg);
        // Derived values stay out of the file; an explicit one is kept.
        let out = serialize_client(&cfg);
        assert!(!out.contains("secret ="), "{out}");
        assert!(!out.contains("credential ="), "{out}");
        assert!(!out.contains("discovery ="), "{out}");
        let text = format!(
            "[client]\nid = \"rpi\"\n\n[[servers]]\nname = \"home\"\naddr = \"dht\"\nseed = \"{TEST_SECRET}\"\ncredential = \"{OTHER_SECRET}\"\n"
        );
        let cfg = parse_client(&text).unwrap();
        assert_eq!(cfg.servers[0].credential.0, OTHER_SECRET);
        assert_eq!(serialize_client(&cfg), text);
    }

    #[test]
    fn seeded_server_needs_a_client_id_and_a_valid_seed() {
        let text =
            format!("[[servers]]\nname = \"home\"\naddr = \"dht\"\nseed = \"{TEST_SECRET}\"\n");
        let error = parse_client(&text).unwrap_err().to_string();
        assert!(error.contains("[client].id"), "{error}");
        let text = "[[servers]]\nname = \"home\"\naddr = \"dht\"\nseed = \"short\"\n";
        assert!(parse_client(text).is_err());
        let text = "[[servers]]\nname = \"home\"\naddr = \"dht\"\n";
        let error = parse_client(text).unwrap_err().to_string();
        assert!(error.contains("`secret` or `seed`"), "{error}");
    }

    #[test]
    fn roundtrip_devices() {
        let tap = ClientConfig {
            servers: vec![CfgServer {
                name: "home".into(),
                addr: "dht".into(),
                seed: None,
                secret: ServerSecret(TEST_SECRET.into()),
                credential: ServerSecret(TEST_SECRET.into()),
                discovery: Some(ServerSecret(DISCOVERY_SECRET.into())),
                transport: Transport::Auto,
            }],
            tap: Some(CfgTap {
                dev: "ztap0".into(),
            }),
            ..ClientConfig::default()
        };
        tap.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&tap)).unwrap(), tap);

        let tun = ClientConfig {
            tun: Some(CfgTun {
                dev: Some("zn0".into()),
                address: Some((Ipv4Addr::new(10, 0, 0, 2), 24)),
                exit: false,
                exit_strict: false,
                exit_via: None,
            }),
            ..ClientConfig::default()
        };
        tun.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&tun)).unwrap(), tun);

        let bare_tun = ClientConfig {
            tun: Some(CfgTun {
                dev: None,
                address: None,
                exit: false,
                exit_strict: false,
                exit_via: None,
            }),
            ..ClientConfig::default()
        };
        assert_eq!(parse_client("[tun]\n").unwrap(), bare_tun);
        assert_eq!(
            parse_client(&serialize_client(&bare_tun)).unwrap(),
            bare_tun
        );
    }

    #[test]
    fn tun_exit_keys_roundtrip_and_default_off() {
        // A bare [tun] leaves exit mode off, and the false defaults are
        // omitted from the rendering.
        let cfg = parse_client("[tun]\nexit = true\n").unwrap();
        let tun = cfg.tun.as_ref().unwrap();
        assert!(tun.exit);
        assert!(!tun.exit_strict);
        assert_eq!(serialize_client(&cfg), "[tun]\nexit = true\n");
        assert_eq!(parse_client(&serialize_client(&cfg)).unwrap(), cfg);

        let strict = ClientConfig {
            tun: Some(CfgTun {
                dev: Some("zn0".into()),
                address: None,
                exit: true,
                exit_strict: true,
                exit_via: None,
            }),
            ..ClientConfig::default()
        };
        strict.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&strict)).unwrap(), strict);
    }

    // A [tun] naming a peer feeds a consumer slot, so it coexists with the
    // forwards and pppoe sessions the server slot keeps serving; a [peer]
    // table declares the provider bits.
    #[test]
    fn peer_slot_tables_roundtrip() {
        let cfg = parse_client(&format!(
            "[client]\npeer_secret = \"{OTHER_SECRET}\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = 443\n\
             [[pppoe]]\nname = \"wan\"\nusername = \"u\"\n\
             [tun]\ndev = \"zn0\"\nexit = true\nexit_via = \"{TEST_SECRET}\"\n\
             [peer]\nexit = true\nexit_iface = \"wan0\"\nsegment = \"eth1\"\n\
             allow = [\"{TEST_SECRET}\", \"{OTHER_SECRET}\"]\n",
        ))
        .unwrap();
        cfg.validate().unwrap();
        let tun = cfg.tun.as_ref().unwrap();
        assert!(tun.is_peer());
        assert_eq!(tun.exit_via.as_deref(), Some(TEST_SECRET));
        let peer = cfg.peer.as_ref().unwrap();
        assert!(peer.exit);
        assert_eq!(peer.exit_iface.as_deref(), Some("wan0"));
        assert_eq!(peer.segment.as_deref(), Some("eth1"));
        assert_eq!(peer.allow, [TEST_SECRET, OTHER_SECRET]);
        assert_eq!(parse_client(&serialize_client(&cfg)).unwrap(), cfg);

        // An exit provider without a named interface takes the default-route
        // one at bringup.
        let auto = parse_client("[peer]\nexit = true\n").unwrap();
        assert_eq!(auto.peer.as_ref().unwrap().exit_iface, None);
        assert_eq!(parse_client(&serialize_client(&auto)).unwrap(), auto);

        // A bare [peer] declares no provider at all.
        let none = parse_client("[peer]\n").unwrap();
        assert_eq!(none.peer, Some(CfgPeer::default()));
        assert_eq!(parse_client(&serialize_client(&none)).unwrap(), none);
    }

    // A provider no consumer may use is a boot error naming the key, an
    // allow entry must be an identity, and a consumer-only config needs no
    // allowlist.
    #[test]
    fn a_provider_requires_a_consumer_allowlist() {
        let with_key = |peer: &str| format!("[client]\npeer_secret = \"{OTHER_SECRET}\"\n{peer}");
        for provider in [
            "[peer]\nexit = true\n",
            "[peer]\nsegment = \"eth1\"\n",
            "[peer]\nexit = true\nallow = []\n",
        ] {
            let error = parse_client(&with_key(provider))
                .unwrap()
                .validate()
                .unwrap_err();
            assert!(error.to_string().contains("[peer] allow"), "{error}");
        }

        let malformed = with_key("[peer]\nexit = true\nallow = [\"office\"]\n");
        let error = parse_client(&malformed).unwrap().validate().unwrap_err();
        assert!(error.to_string().contains("[peer] allow"), "{error}");
        assert!(error.to_string().contains("office"), "{error}");

        let consumer = with_key(&format!("[tun]\nexit_via = \"{TEST_SECRET}\"\n"));
        parse_client(&consumer).unwrap().validate().unwrap();

        let listed = with_key(&format!(
            "[peer]\nexit = true\nsegment = \"eth1\"\nallow = [\"{TEST_SECRET}\"]\n"
        ));
        let cfg = parse_client(&listed).unwrap();
        cfg.validate().unwrap();
        assert_eq!(parse_client(&serialize_client(&cfg)).unwrap(), cfg);
    }

    #[test]
    fn entry_defaults() {
        let cfg = parse_client(
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\ndiscovery = \"5555555555555555555555555555555555555555555555555555555555555555\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = 8080\n\
             [[pppoe]]\nname = \"wan\"\nusername = \"u\"\n",
        )
        .unwrap();
        assert_eq!(cfg.servers[0].transport, Transport::Auto);
        let f = &cfg.forwards[0];
        assert_eq!(f.target, "127.0.0.1:8080");
        assert!(!f.proxy);
        assert_eq!(f.idle, None);
        assert!(f.enabled);
        let p = &cfg.pppoe[0];
        assert!(!p.autostart);
        assert_eq!(p.password, None);
        assert_eq!(p.password_file, None);
        assert_eq!(p.service, "");
        assert_eq!(p.mtu, 1492);
        assert!(!p.default_route);
        assert!(p.clamp_mss);
        assert!(!p.request_dns);
        cfg.validate().unwrap();
    }

    #[test]
    fn serialize_omits_defaults() {
        let cfg = parse_client(
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n\
             [[forwards]]\nproto = \"tcp\"\nport = 8080\n\
             [[pppoe]]\nname = \"wan\"\nusername = \"u\"\n",
        )
        .unwrap();
        let out = serialize_client(&cfg);
        for key in [
            "transport",
            "proxy",
            "idle",
            "enabled",
            "autostart",
            "service",
            "mtu",
        ] {
            assert!(
                !out.contains(key),
                "default `{key}` must be omitted:\n{out}"
            );
        }
    }

    #[test]
    fn idle_wider_than_port_range() {
        let cfg =
            parse_client("[[forwards]]\nproto = \"tcp\"\nport = 443\nidle = 100000\n").unwrap();
        assert_eq!(cfg.forwards[0].idle, Some(100_000));
    }

    #[test]
    fn rejects_malformed() {
        let cases = [
            // Unknown tables and keys.
            "[bogus]\n",
            "[client]\nfoo = 1\n",
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\nfoo = 1\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nfoo = 1\n",
            "[[pppoe]]\nname = \"w\"\nusername = \"u\"\nfoo = 1\n",
            "[tap]\ndev = \"t0\"\nfoo = 1\n",
            "[tun]\nfoo = 1\n",
            "id = \"x\"\n",
            // Missing required keys.
            "[[servers]]\naddr = \"dht\"\nsecret = \"s\"\n",
            "[[servers]]\nname = \"a\"\nsecret = \"s\"\n",
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\n",
            "[[forwards]]\nport = 1\n",
            "[[forwards]]\nproto = \"tcp\"\n",
            "[[pppoe]]\nusername = \"u\"\n",
            "[[pppoe]]\nname = \"w\"\n",
            "[tap]\n",
            // Empty names and devices.
            "[[servers]]\nname = \"\"\naddr = \"dht\"\nsecret = \"s\"\n",
            "[[pppoe]]\nname = \"\"\nusername = \"u\"\n",
            "[tap]\ndev = \"\"\n",
            // Type and value errors.
            "[[servers]]\nname = \"a\"\naddr = \"dht\"\nsecret = \"s\"\ntransport = \"quic\"\n",
            "[[forwards]]\nproto = \"tap\"\nport = 1\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 99999\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nidle = 0\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nidle = \"x\"\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nproxy = 1\n",
            "[[forwards]]\nproto = \"tcp\"\nport = 1\nenabled = 1\n",
            "[tun]\naddress = \"10.0.0.2\"\n",
            "[tun]\naddress = \"bogus/24\"\n",
            "[tun]\naddress = \"10.0.0.2/33\"\n",
            "[tun]\nexit = 1\n",
            "[tun]\nexit = \"true\"\n",
            "[tun]\nexit_strict = 1\n",
            "[tun]\nexit_via = \"\"\n",
            "[peer]\nexit = 1\n",
            "[peer]\nsegment = \"\"\n",
            "[peer]\nfoo = 1\n",
            "[peer]\n[peer]\n",
            // `allow` is a list of quoted strings.
            "[peer]\nallow = \"a\"\n",
            "[peer]\nallow = [\"a\" \"b\"]\n",
            "[peer]\nallow = [1]\n",
            "[peer]\nallow = [\"a\"\n",
            "[peer]\nallow = [\"a]\n",
            "[peer]\nexit = true\nexit_iface = \"\"\n",
            // The masquerade the interface names is what `exit` turns on.
            "[peer]\nexit_iface = \"wan0\"\n",
            // `exit_iface` is a [peer] key; [tun] takes `exit_via` instead.
            "[tun]\nexit_iface = \"wan0\"\n",
            // `exit_strict` hardens exit mode, so it needs exit mode on.
            "[tun]\nexit_strict = true\n",
            "[tun]\nexit = false\nexit_strict = true\n",
            // `exit` is a [tun] key; the other tables reject it.
            "[client]\nexit = true\n",
            "[tap]\ndev = \"t0\"\nexit = true\n",
            // `proxy` belongs to tcp entries only, whatever its value and
            // whatever `enabled` says.
            "[[forwards]]\nproto = \"udp\"\nport = 1\nproxy = true\n",
            "[[forwards]]\nproto = \"udp\"\nport = 1\nproxy = false\n",
            "[[forwards]]\nproto = \"udp\"\nport = 1\nenabled = false\nproxy = true\n",
            // `clamp_mss = false` without the default-route swap it rides with.
            "[[pppoe]]\nname = \"w\"\nusername = \"u\"\nclamp_mss = false\n",
            // Duplicate keys and singleton tables.
            "[client]\nid = \"a\"\nid = \"b\"\n",
            "[client]\nid = \"a\"\n[client]\ncontrol = \"c\"\n",
            "[tap]\ndev = \"t0\"\n[tap]\ndev = \"t1\"\n",
            "[tun]\n[tun]\n",
            "[[servers]]\nname = \"a\"\nname = \"b\"\naddr = \"dht\"\nsecret = \"s\"\n",
        ];
        for case in cases {
            assert!(parse_client(case).is_err(), "expected Err for:\n{case}");
        }
    }

    #[test]
    fn semantic_errors_parse_but_fail_validate() {
        let cases = [
            // active names no [[servers]] entry.
            "[client]\nactive = \"gone\"\n[[servers]]\nname = \"a\"\naddr = \"127.0.0.1:2222\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n",
            // Duplicate server names.
            "[[servers]]\nname = \"a\"\naddr = \"127.0.0.1:2222\"\nsecret = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n\
             [[servers]]\nname = \"a\"\naddr = \"127.0.0.1:2222\"\nsecret = \"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\"\n",
            // Duplicate (proto, port) forwards.
            "[[forwards]]\nproto = \"tcp\"\nport = 443\n[[forwards]]\nproto = \"tcp\"\nport = 443\n",
            // More than one autostart.
            "[[pppoe]]\nname = \"a\"\nusername = \"u\"\nautostart = true\n\
             [[pppoe]]\nname = \"b\"\nusername = \"u\"\nautostart = true\n",
            // Duplicate pppoe names.
            "[[pppoe]]\nname = \"a\"\nusername = \"u\"\n[[pppoe]]\nname = \"a\"\nusername = \"v\"\n",
            // Device exclusivity.
            "[tap]\ndev = \"t0\"\n[tun]\n",
            "[tap]\ndev = \"t0\"\n[[forwards]]\nproto = \"tcp\"\nport = 443\n",
            "[tun]\n[[pppoe]]\nname = \"w\"\nusername = \"u\"\n",
        ];
        for case in cases {
            let cfg = parse_client(case).unwrap_or_else(|e| {
                panic!("expected a clean parse (semantic error only) for:\n{case}\ngot: {e}")
            });
            assert!(
                cfg.validate().is_err(),
                "expected validate Err for:\n{case}"
            );
        }

        // A peer pair derives both ends of its subnet from the secret, so a
        // consumer table has no address of its own to take.
        let address_with_peer = format!(
            "[client]\npeer_secret = \"{OTHER_SECRET}\"\n\
             [tun]\naddress = \"10.9.0.2/24\"\nexit_via = \"{TEST_SECRET}\"\n"
        );
        let error = parse_client(&address_with_peer)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("`address` cannot be combined with `exit_via`"),
            "{error}"
        );
    }

    #[test]
    fn tcp_and_udp_may_share_a_port() {
        let cfg = parse_client(
            "[[forwards]]\nproto = \"tcp\"\nport = 443\n[[forwards]]\nproto = \"udp\"\nport = 443\n",
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.forwards.len(), 2);
    }

    #[test]
    fn empty_input() {
        let cfg = parse_client("").unwrap();
        assert_eq!(cfg, ClientConfig::default());
        cfg.validate().unwrap();
    }

    #[test]
    fn load_missing_file_is_default() {
        let path =
            std::env::temp_dir().join(format!("zeronat-client-absent-{}.toml", std::process::id()));
        assert_eq!(load(&path).unwrap(), ClientConfig::default());
    }

    #[test]
    fn load_reports_malformed() {
        let dir = std::env::temp_dir().join(format!("zeronat-client-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        std::fs::write(&path, "[client\nid = ").unwrap();
        assert!(matches!(load(&path), Err(LoadError::Malformed(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_keeps_invalid_secret_for_fatal_validation() {
        let dir =
            std::env::temp_dir().join(format!("zeronat-client-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.toml");
        std::fs::write(
            &path,
            "[[servers]]\nname = \"home\"\naddr = \"127.0.0.1:2222\"\nsecret = \"short\"\n",
        )
        .unwrap();

        let config = load(&path).unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("server `home`"), "{error}");
        assert!(error.contains("64 hexadecimal"), "{error}");
        assert!(path.exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
