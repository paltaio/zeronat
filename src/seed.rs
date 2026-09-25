//! Credentials derived from one 64-hex seed.
//!
//! Every derived value is `BLAKE2s(label || seed)` under its own label, so the
//! values differ by construction and none of them reveals the seed or another
//! derived value. The client label ends in the client id; the seed is a fixed
//! 32 bytes, so the id needs no length prefix to be unambiguous.

use blake2::{Blake2s256, Digest};

use crate::Result;

const NETWORK: &[u8] = b"zeronat:v1:network";
const ADMIN: &[u8] = b"zeronat:v1:admin";
const DISCOVERY: &[u8] = b"zeronat:v1:discovery";
const PEER: &[u8] = b"zeronat:v1:peer";
const CLIENT: &[u8] = b"zeronat:v1:client:";

pub struct Seed([u8; crate::secret::BYTE_LEN]);

impl Seed {
    pub fn parse(value: &str) -> Result<Seed> {
        crate::secret::decode(value)
            .map(Seed)
            .map_err(|_| "seed must be exactly 64 hexadecimal characters (32 bytes)".into())
    }

    /// The seed in the runtime format, for writing it back out.
    pub fn to_hex(&self) -> String {
        crate::secret::encode(self.0)
    }

    pub fn network(&self) -> String {
        self.derive(NETWORK, b"")
    }

    pub fn admin(&self) -> String {
        self.derive(ADMIN, b"")
    }

    pub fn discovery(&self) -> String {
        self.derive(DISCOVERY, b"")
    }

    pub fn peer(&self) -> String {
        self.derive(PEER, b"")
    }

    pub fn client(&self, id: &str) -> String {
        self.derive(CLIENT, id.as_bytes())
    }

    fn derive(&self, label: &[u8], suffix: &[u8]) -> String {
        let mut h = Blake2s256::new();
        h.update(label);
        h.update(suffix);
        h.update(self.0);
        crate::secret::encode(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn parse_takes_only_the_runtime_format() {
        assert_eq!(Seed::parse(SEED).unwrap().to_hex(), SEED);
        assert_eq!(
            Seed::parse(&SEED.to_ascii_uppercase()).unwrap().to_hex(),
            SEED
        );
        let short_by_one = "a".repeat(63);
        let non_hex = "g".repeat(64);
        for invalid in ["short", short_by_one.as_str(), non_hex.as_str()] {
            assert!(Seed::parse(invalid).is_err());
        }
    }

    #[test]
    fn derived_values_are_stable_distinct_and_well_formed() {
        let seed = Seed::parse(SEED).unwrap();
        let values = [
            seed.network(),
            seed.admin(),
            seed.discovery(),
            seed.peer(),
            seed.client("rpi"),
            seed.client("rpi2"),
        ];
        for value in &values {
            assert_eq!(crate::secret::normalize(value).unwrap(), *value);
        }
        for (i, a) in values.iter().enumerate() {
            for b in &values[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(seed.client("rpi"), Seed::parse(SEED).unwrap().client("rpi"));
        assert_ne!(
            seed.network(),
            Seed::parse(&"7".repeat(64)).unwrap().network()
        );
    }

    #[test]
    fn derived_credentials_pass_the_server_separation_checks() {
        let seed = Seed::parse(SEED).unwrap();
        let client = crate::noise::derive_psk(&seed.client("rpi"));
        assert_ne!(crate::noise::derive_psk(&seed.admin()), client);
        assert_ne!(crate::noise::derive_psk(&seed.discovery()), client);
        assert_ne!(seed.admin(), seed.network());
    }
}
