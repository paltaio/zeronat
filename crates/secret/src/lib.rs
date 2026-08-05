use std::fmt;

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

fn encode(bytes: [u8; BYTE_LEN]) -> String {
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
}
