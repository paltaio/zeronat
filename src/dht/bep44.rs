//! BEP44 mutable-item signing. The signing input must be byte-exact or DHT nodes
//! silently reject the put; the published BEP44 vectors anchor it in the tests.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha1::{Digest, Sha1};

/// The bytes an ed25519 signature covers for a mutable item: the bencoded `salt`
/// (only when present), `seq`, then `v`, concatenated in that order.
pub fn signing_input(salt: Option<&[u8]>, seq: i64, v: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    if let Some(s) = salt {
        b.extend_from_slice(b"4:salt");
        b.extend_from_slice(s.len().to_string().as_bytes());
        b.push(b':');
        b.extend_from_slice(s);
    }
    b.extend_from_slice(b"3:seqi");
    b.extend_from_slice(seq.to_string().as_bytes());
    b.extend_from_slice(b"e1:v");
    b.extend_from_slice(v.len().to_string().as_bytes());
    b.push(b':');
    b.extend_from_slice(v);
    b
}

/// The DHT key a mutable item is stored under: `SHA1(pubkey || salt)`.
pub fn target(pubkey: &[u8; 32], salt: Option<&[u8]>) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(pubkey);
    if let Some(s) = salt {
        h.update(s);
    }
    h.finalize().into()
}

pub fn sign(sk: &SigningKey, salt: Option<&[u8]>, seq: i64, v: &[u8]) -> [u8; 64] {
    sk.sign(&signing_input(salt, seq, v)).to_bytes()
}

pub fn verify(pubkey: &[u8; 32], salt: Option<&[u8]>, seq: i64, v: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    vk.verify_strict(&signing_input(salt, seq, v), &Signature::from_bytes(sig))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // BEP44 published signing-input vectors (value "Hello World!").
    #[test]
    fn signing_input_vectors() {
        assert_eq!(
            signing_input(None, 1, b"Hello World!"),
            b"3:seqi1e1:v12:Hello World!"
        );
        assert_eq!(
            signing_input(Some(b"foobar"), 1, b"Hello World!"),
            b"4:salt6:foobar3:seqi1e1:v12:Hello World!"
        );
    }

    // BEP44 published target vectors for the example public key.
    #[test]
    fn target_vectors() {
        let pk: [u8; 32] =
            unhex("77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548")
                .try_into()
                .unwrap();
        assert_eq!(
            hex(&target(&pk, None)),
            "4a533d47ec9c7d95b1ad75f576cffc641853b750"
        );
        assert_eq!(
            hex(&target(&pk, Some(b"foobar"))),
            "411eba73b6f087ca51a3795d9c8c938d365e32c1"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let salt = b"zn";
        let sig = sign(&sk, Some(salt), 42, b"payload");
        assert!(verify(&pk, Some(salt), 42, b"payload", &sig));
        assert!(!verify(&pk, Some(salt), 43, b"payload", &sig));
        assert!(!verify(&pk, Some(b"xx"), 42, b"payload", &sig));
        assert!(!verify(&pk, None, 42, b"payload", &sig));
    }
}
