use blake2::{Blake2s256, Digest};

pub const PROTO_VERSION: u8 = 1;

/// Derive the tunnel's private `/24` from the secret. Both ends compute the same
/// network with no exchange: the server takes `.1` and the single client takes
/// `.2`. The base sits in `10.0.0.0/8` with the two middle octets taken from the
/// secret hash, so two unrelated deployments are very unlikely to collide. The
/// returned value is the network base, e.g. `[10, x, y, 0]`.
pub fn derive_tun_subnet(secret: &str) -> [u8; 4] {
    let mut h = Blake2s256::new();
    h.update(b"zeronat-tun-subnet-v1");
    h.update(secret.as_bytes());
    let out = h.finalize();
    [10, out[0], out[1], 0]
}

/// Derive a stable client identity label. The prefix is the caller's label when
/// non-empty, otherwise the short hostname; the suffix disambiguates hosts that
/// share a prefix and must stay constant across restarts of the same machine.
pub fn derive_client_id(prefix: Option<&str>) -> String {
    let prefix = match prefix {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => short_hostname(),
    };
    format!("{prefix}-{}", machine_suffix())
}

/// A 4-hex-char suffix that is stable across restarts of the same host. A
/// drifting suffix would silently break route targets, so this derives only
/// from durable host state: the machine-id when present, else a hash of the
/// hostname. Never random.
fn machine_suffix() -> String {
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim();
        if id.len() >= 4 {
            return id[id.len() - 4..].to_ascii_lowercase();
        }
    }
    let mut h = Blake2s256::new();
    h.update(b"zeronat-client-suffix-v1");
    h.update(short_hostname().as_bytes());
    let out = h.finalize();
    format!("{:02x}{:02x}", out[0], out[1])
}

/// Best-effort short hostname, normalized to `[a-z0-9_]`: lowercased, stripped
/// at the first dot, with every other character replaced by `_`. Falls back to
/// `"node"` when no hostname is available or normalization empties it.
fn short_hostname() -> String {
    let raw = std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .and_then(|s| s.split_whitespace().next().map(|t| t.to_string()))
        })
        .unwrap_or_else(|| "node".to_string());

    let normalized: String = raw
        .to_ascii_lowercase()
        .split('.')
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if normalized.is_empty() {
        "node".to_string()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_hex_lower(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    }

    #[test]
    fn client_id_is_stable() {
        let a = derive_client_id(Some("rpi"));
        let b = derive_client_id(Some("rpi"));
        assert_eq!(a, b);
        let suffix = a.strip_prefix("rpi-").expect("starts with rpi-");
        assert_eq!(suffix.len(), 4);
        assert!(is_hex_lower(suffix));
    }

    #[test]
    fn empty_prefix_falls_back_to_hostname() {
        let id = derive_client_id(Some(""));
        assert!(!id.starts_with('-'));
        let (prefix, suffix) = id.rsplit_once('-').expect("contains a -");
        assert!(!prefix.is_empty());
        assert_eq!(suffix.len(), 4);
        assert!(is_hex_lower(suffix));
    }

    #[test]
    fn none_prefix_uses_hostname() {
        let id = derive_client_id(None);
        assert!(!id.is_empty());
        let (prefix, suffix) = id.rsplit_once('-').expect("contains a -");
        assert!(!prefix.is_empty());
        assert!(prefix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
        assert_eq!(suffix.len(), 4);
        assert!(is_hex_lower(suffix));
    }

    #[test]
    fn suffix_is_four_lowercase_hex() {
        let suffix = machine_suffix();
        assert_eq!(suffix.len(), 4);
        assert!(is_hex_lower(&suffix));
    }

    #[test]
    fn tun_subnet_is_stable_and_private() {
        let a = derive_tun_subnet("hunter2");
        let b = derive_tun_subnet("hunter2");
        assert_eq!(a, b);
        assert_eq!(a[0], 10);
        assert_eq!(a[3], 0);
        // A different secret yields a different network (with overwhelming odds).
        assert_ne!(derive_tun_subnet("hunter2"), derive_tun_subnet("other"));
    }
}
