//! Signed release manifests. A release ships `release.manifest`, listing the
//! sha256 digest and size of every binary asset, and `release.manifest.sig`,
//! an ed25519 signature over the manifest bytes. Downloaders verify the
//! signature against the public key embedded at build time, then check each
//! downloaded artifact against its manifest entry before running it.

use std::collections::HashMap;
use std::io::Read;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MANIFEST_NAME: &str = "release.manifest";
pub const SIGNATURE_NAME: &str = "release.manifest.sig";
const MANIFEST_HEADER: &str = "zeronat-release-v1";

/// Ceilings on fetched and verified content, so a malicious or broken server
/// cannot make a downloader hash or hold unbounded data.
pub const MANIFEST_LIMIT: u64 = 65_536;
pub const SIGNATURE_LIMIT: u64 = 4_096;
pub const ARTIFACT_LIMIT: u64 = 268_435_456;

/// The release public key embedded at build time, or `None` for a build that
/// cannot verify releases. Set `ZERONAT_RELEASE_PUBKEY` to the 64-hex ed25519
/// public key when building release binaries.
pub fn embedded_public_key() -> Option<[u8; 32]> {
    option_env!("ZERONAT_RELEASE_PUBKEY").and_then(|hex| zeronat_secret::decode(hex).ok())
}

pub struct ReleaseManifest {
    version: String,
    entries: HashMap<String, ([u8; 32], u64)>,
}

impl ReleaseManifest {
    /// Verify `signature_hex` over `manifest` with `public_key`, then parse.
    /// Any signature or format defect refuses the whole manifest.
    pub fn verify(
        manifest: &[u8],
        signature_hex: &[u8],
        public_key: &[u8; 32],
    ) -> Result<Self, String> {
        if manifest.len() as u64 > MANIFEST_LIMIT {
            return Err("the release manifest is too large".into());
        }
        if signature_hex.len() as u64 > SIGNATURE_LIMIT {
            return Err("the release signature is too large".into());
        }
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| "the release public key is invalid".to_string())?;
        let signature_hex = std::str::from_utf8(signature_hex)
            .map_err(|_| "the release signature is malformed".to_string())?;
        let signature = decode_signature(signature_hex.trim_end_matches('\n'))
            .ok_or("the release signature is malformed")?;
        key.verify_strict(manifest, &signature)
            .map_err(|_| "the release manifest signature is invalid".to_string())?;
        Self::parse(manifest)
    }

    fn parse(manifest: &[u8]) -> Result<Self, String> {
        let malformed = || "the release manifest is malformed".to_string();
        let text = std::str::from_utf8(manifest).map_err(|_| malformed())?;
        let body = text.strip_suffix('\n').ok_or_else(malformed)?;
        if body.contains('\r') {
            return Err(malformed());
        }
        let mut lines = body.split('\n');
        let header = lines.next().ok_or_else(malformed)?;
        let version = header
            .strip_prefix(MANIFEST_HEADER)
            .and_then(|rest| rest.strip_prefix(" v"))
            .ok_or_else(malformed)?;
        if !version_ok(version) {
            return Err(malformed());
        }

        let mut entries = HashMap::new();
        let mut previous: Option<&str> = None;
        for line in lines {
            let mut fields = line.split(' ');
            let (digest, size, name) =
                match (fields.next(), fields.next(), fields.next(), fields.next()) {
                    (Some(digest), Some(size), Some(name), None) => (digest, size, name),
                    _ => return Err(malformed()),
                };
            let digest = zeronat_secret::decode(digest).map_err(|_| malformed())?;
            if size.len() > 1 && size.starts_with('0') {
                return Err(malformed());
            }
            let size: u64 = size.parse().map_err(|_| malformed())?;
            if size == 0 || size > ARTIFACT_LIMIT {
                return Err(malformed());
            }
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(malformed());
            }
            // Strictly ascending names make duplicates impossible and the
            // manifest canonical: one byte sequence per content.
            if previous.is_some_and(|p| p >= name) {
                return Err(malformed());
            }
            previous = Some(name);
            entries.insert(name.to_string(), (digest, size));
        }
        if entries.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            version: version.to_string(),
            entries,
        })
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// The signed size of a listed artifact, for bounding its download.
    pub fn expected_size(&self, name: &str) -> Option<u64> {
        self.entries.get(name).map(|(_, size)| *size)
    }

    /// Check a downloaded artifact against its manifest entry, reading
    /// `reader` to the end. Refuses an artifact the manifest does not list,
    /// one whose size disagrees, and one whose digest disagrees.
    pub fn verify_artifact(&self, name: &str, mut reader: impl Read) -> Result<(), String> {
        let (digest, size) = self
            .entries
            .get(name)
            .ok_or_else(|| format!("the release manifest has no entry for {name}"))?;
        let mut hasher = Sha256::new();
        let mut remaining = *size;
        let mut buf = [0u8; 65_536];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| format!("failed to read the downloaded artifact: {e}"))?;
            if n == 0 {
                break;
            }
            if n as u64 > remaining {
                return Err(format!("{name} does not match the signed release manifest"));
            }
            remaining -= n as u64;
            hasher.update(&buf[..n]);
        }
        if remaining != 0 || hasher.finalize().as_slice() != digest {
            return Err(format!("{name} does not match the signed release manifest"));
        }
        Ok(())
    }
}

fn version_ok(version: &str) -> bool {
    let mut parts = version.split('.');
    let numeric = |part: Option<&str>| {
        part.is_some_and(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
    };
    numeric(parts.next())
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_none()
}

fn decode_signature(hex: &str) -> Option<Signature> {
    if hex.len() != 128 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for (out, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(Signature::from_bytes(&bytes))
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_key() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
            .unwrap();
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    fn manifest_for(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut text = String::from("zeronat-release-v1 v0.25.0\n");
        for (name, content) in entries {
            let digest = Sha256::digest(content);
            let mut hex = String::new();
            for byte in digest {
                hex.push_str(&format!("{byte:02x}"));
            }
            text.push_str(&format!("{hex} {} {name}\n", content.len()));
        }
        text.into_bytes()
    }

    fn sign(signing: &SigningKey, manifest: &[u8]) -> Vec<u8> {
        let signature = signing.sign(manifest);
        let mut hex = String::new();
        for byte in signature.to_bytes() {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex.push('\n');
        hex.into_bytes()
    }

    #[test]
    fn a_signed_manifest_verifies_and_checks_artifacts() {
        let (signing, public) = test_key();
        let manifest = manifest_for(&[("zeronat-a", b"binary a"), ("zeronat-b", b"binary b")]);
        let signature = sign(&signing, &manifest);

        let parsed = ReleaseManifest::verify(&manifest, &signature, &public).unwrap();
        assert_eq!(parsed.version(), "0.25.0");
        parsed
            .verify_artifact("zeronat-a", &b"binary a"[..])
            .unwrap();
        parsed
            .verify_artifact("zeronat-b", &b"binary b"[..])
            .unwrap();
    }

    #[test]
    fn an_unsigned_or_wrongly_signed_manifest_is_refused() {
        let (signing, public) = test_key();
        let (other_signing, _) = test_key();
        let manifest = manifest_for(&[("zeronat-a", b"binary a")]);

        assert!(ReleaseManifest::verify(&manifest, b"", &public).is_err());
        assert!(ReleaseManifest::verify(&manifest, b"not hex", &public).is_err());
        let wrong_key = sign(&other_signing, &manifest);
        assert!(ReleaseManifest::verify(&manifest, &wrong_key, &public).is_err());
        let mut tampered = manifest.clone();
        let signature = sign(&signing, &manifest);
        tampered[0] ^= 1;
        assert!(ReleaseManifest::verify(&tampered, &signature, &public).is_err());
        assert!(ReleaseManifest::verify(&manifest, &signature, &public).is_ok());
    }

    #[test]
    fn a_tampered_or_unlisted_artifact_is_refused() {
        let (signing, public) = test_key();
        let manifest = manifest_for(&[("zeronat-a", b"binary a")]);
        let signature = sign(&signing, &manifest);
        let parsed = ReleaseManifest::verify(&manifest, &signature, &public).unwrap();

        assert!(parsed
            .verify_artifact("zeronat-a", &b"tampered!"[..])
            .is_err());
        assert!(parsed
            .verify_artifact("zeronat-a", &b"binary a plus"[..])
            .is_err());
        assert!(parsed
            .verify_artifact("zeronat-a", &b"binary "[..])
            .is_err());
        assert!(parsed
            .verify_artifact("zeronat-missing", &b"binary a"[..])
            .is_err());
    }

    #[test]
    fn malformed_manifests_are_refused() {
        let (signing, public) = test_key();
        let good = String::from_utf8(manifest_for(&[
            ("zeronat-a", b"binary a"),
            ("zeronat-b", b"binary b"),
        ]))
        .unwrap();
        let digest = &good.lines().nth(1).unwrap()[..64];

        let cases = [
            // Missing trailing newline.
            good.trim_end().to_string(),
            // CR line ending.
            good.replace('\n', "\r\n"),
            // Wrong header.
            good.replace("zeronat-release-v1", "zeronat-release-v2"),
            // Non-canonical version.
            good.replace("v0.25.0", "v0.25.00"),
            // Header only, no entries.
            "zeronat-release-v1 v0.25.0\n".to_string(),
            // Duplicate entry.
            format!("zeronat-release-v1 v0.25.0\n{digest} 8 zeronat-a\n{digest} 8 zeronat-a\n"),
            // Unsorted entries.
            format!("zeronat-release-v1 v0.25.0\n{digest} 8 zeronat-b\n{digest} 8 zeronat-a\n"),
            // Extra field.
            format!("zeronat-release-v1 v0.25.0\n{digest} 8 zeronat-a extra\n"),
            // Bad digest, size, and name.
            "zeronat-release-v1 v0.25.0\nnothex 8 zeronat-a\n".to_string(),
            format!("zeronat-release-v1 v0.25.0\n{digest} 08 zeronat-a\n"),
            format!("zeronat-release-v1 v0.25.0\n{digest} 0 zeronat-a\n"),
            format!("zeronat-release-v1 v0.25.0\n{digest} 8 bad/name\n"),
        ];
        for manifest in cases {
            let signature = sign(&signing, manifest.as_bytes());
            assert!(
                ReleaseManifest::verify(manifest.as_bytes(), &signature, &public).is_err(),
                "accepted: {manifest:?}"
            );
        }
    }
}
