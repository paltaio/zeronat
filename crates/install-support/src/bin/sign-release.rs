//! Sign a release manifest: reads the manifest from stdin, signs it with the
//! 64-hex ed25519 seed in `ZERONAT_RELEASE_SIGNING_KEY`, and prints the hex
//! signature. Refuses to sign a manifest a downloader would reject. With
//! `--pubkey`, prints the seed's public key and exits.

use std::io::Read;

use ed25519_dalek::{Signer, SigningKey};
use zeronat_install_support::release::ReleaseManifest;

fn main() {
    if let Err(e) = run() {
        eprintln!("sign-release: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let key_hex = std::env::var("ZERONAT_RELEASE_SIGNING_KEY")
        .map_err(|_| "ZERONAT_RELEASE_SIGNING_KEY is not set".to_string())?;
    let seed = zeronat_secret::decode(key_hex.trim()).map_err(|e| e.to_string())?;
    let signing = SigningKey::from_bytes(&seed);

    match std::env::args().nth(1).as_deref() {
        Some("--pubkey") => {
            println!(
                "{}",
                zeronat_secret::encode(signing.verifying_key().to_bytes())
            );
            return Ok(());
        }
        Some(other) => return Err(format!("unknown option: {other}")),
        None => {}
    }

    let mut manifest = Vec::new();
    std::io::stdin()
        .read_to_end(&mut manifest)
        .map_err(|e| format!("reading the manifest: {e}"))?;

    let signature = signing.sign(&manifest);
    let mut hex = String::with_capacity(128);
    for byte in signature.to_bytes() {
        hex.push_str(&format!("{byte:02x}"));
    }
    ReleaseManifest::verify(
        &manifest,
        hex.as_bytes(),
        &signing.verifying_key().to_bytes(),
    )?;
    println!("{hex}");
    Ok(())
}
