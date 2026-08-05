use std::fmt;

use blake2::{Blake2s256, Digest};
use ed25519_dalek::SigningKey;

pub const BYTE_LEN: usize = 32;
pub const HEX_LEN: usize = BYTE_LEN * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatError;

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("secret must be exactly 64 hexadecimal characters (32 bytes)")
    }
}

impl std::error::Error for FormatError {}

pub fn decode(value: &str) -> Result<[u8; BYTE_LEN], FormatError> {
    if value.len() != HEX_LEN {
        return Err(FormatError);
    }

    let mut decoded = [0u8; BYTE_LEN];
    for (out, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(decoded)
}

pub fn normalize(value: &str) -> Result<String, FormatError> {
    decode(value).map(encode)
}

pub fn generate() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; BYTE_LEN];
    getrandom::getrandom(&mut bytes)?;
    Ok(encode(bytes))
}

pub fn server_signing_seed(secret: &str) -> Result<[u8; BYTE_LEN], FormatError> {
    derive(b"zeronat-server-signing-v1", secret)
}

pub fn server_public(secret: &str) -> Result<String, FormatError> {
    let signing = SigningKey::from_bytes(&server_signing_seed(secret)?);
    Ok(encode(signing.verifying_key().to_bytes()))
}

pub fn client_credential(secret: &str) -> Result<String, FormatError> {
    derive(b"zeronat-client-credential-v1", secret).map(encode)
}

fn derive(domain: &[u8], secret: &str) -> Result<[u8; BYTE_LEN], FormatError> {
    let secret = decode(secret)?;
    let mut hash = Blake2s256::new();
    hash.update(domain);
    hash.update(secret);
    Ok(hash.finalize().into())
}

pub fn encode(bytes: [u8; BYTE_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(HEX_LEN);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn nibble(value: u8) -> Result<u8, FormatError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(FormatError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_32_byte_hex_encoding() {
        let lower = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let upper = lower.to_ascii_uppercase();
        assert_eq!(decode(lower).unwrap(), decode(&upper).unwrap());
        assert_eq!(normalize(&upper).unwrap(), lower);
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            format!("{}g", "a".repeat(63)),
            format!("{}é", "a".repeat(63)),
        ] {
            assert_eq!(decode(&invalid), Err(FormatError));
        }
    }

    #[test]
    fn generated_secret_uses_the_runtime_format() {
        let secret = generate().unwrap();
        assert_eq!(secret.len(), HEX_LEN);
        assert!(secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn server_public_and_client_credential_are_separate_derivations() {
        let secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let public = server_public(secret).unwrap();
        let credential = client_credential(secret).unwrap();
        assert_ne!(public, secret);
        assert_ne!(credential, secret);
        assert_ne!(public, credential);
        decode(&public).unwrap();
        decode(&credential).unwrap();
    }
}
