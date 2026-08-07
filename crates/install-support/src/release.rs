use crate::DownloadFile;
use flate2::read::GzDecoder;
use minisign_verify::{PublicKey, Signature};
use std::collections::HashSet;
use std::fs::File;

const RELEASE_ORIGIN: &str = "https://github.com/paltaio/zeronat";
const MANIFEST_LIMIT: u64 = 65_536;
const SIGNATURE_LIMIT: u64 = 4_096;
const ARTIFACT_LIMIT: u64 = 268_435_456;
const MANIFEST_PREFIX: &str = "zeronat-release-v2";
const MANIFEST_NAME: &str = "release.manifest";
const SIGNATURE_NAME: &str = "release.manifest.minisig";
const ZERONAT_IMAGE_PREFIX: &str = "ghcr.io/paltaio/zeronat@sha256:";
const ZNPPPOE_IMAGE_PREFIX: &str = "ghcr.io/paltaio/znpppoe@sha256:";

pub const PACKAGE_BINARY: &str = "zeronat";
pub const PACKAGE_INSTALLER: &str = "zeronat-installer";

#[derive(Clone, Copy)]
pub struct TrustedKey {
    pub id: &'static str,
    pub public_key: &'static str,
}

pub const TRUSTED_RELEASE_KEYS: &[TrustedKey] = &[TrustedKey {
    id: "85ba020a1bd957f1",
    public_key: include_str!("../../../release/minisign.pub"),
}];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedRelease {
    tag: String,
    version: String,
}

impl SelectedRelease {
    pub fn from_version(version: &str) -> Result<Self, String> {
        parse_version(version)?;
        Ok(Self {
            tag: format!("v{version}"),
            version: version.to_string(),
        })
    }

    pub fn from_latest_url(url: &str) -> Result<Self, String> {
        let prefix = format!("{RELEASE_ORIGIN}/releases/tag/");
        let tag = url
            .trim()
            .strip_prefix(&prefix)
            .ok_or_else(|| "latest release redirect has an unexpected URL".to_string())?;
        if tag.contains('/') {
            return Err("latest release redirect has an unexpected URL".into());
        }
        let version = tag
            .strip_prefix('v')
            .ok_or_else(|| "latest release tag must start with v".to_string())?;
        let selected = Self::from_version(version)?;
        if selected.tag != tag {
            return Err("latest release tag is not canonical".into());
        }
        Ok(selected)
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn is_newer_than(&self, current: &str) -> Result<bool, String> {
        Ok(parse_version(&self.version)? > parse_version(current)?)
    }

    pub fn package_name(&self, target: &str) -> Result<String, String> {
        let platform = match target {
            "x86_64-unknown-linux-gnu" => "linux-amd64-gnu",
            "x86_64-unknown-linux-musl" => "linux-amd64",
            "aarch64-unknown-linux-gnu" => "linux-arm64-gnu",
            "aarch64-unknown-linux-musl" => "linux-arm64",
            "arm-unknown-linux-gnueabihf" => "linux-armv6-gnu",
            "arm-unknown-linux-musleabihf" => "linux-armv6",
            "armv7-unknown-linux-gnueabihf" => "linux-armv7-gnu",
            "armv7-unknown-linux-musleabihf" => "linux-armv7",
            "mips-unknown-linux-musl" => "linux-mips",
            "mipsel-unknown-linux-musl" => "linux-mipsel",
            "mips64-unknown-linux-gnuabi64" => "linux-mips64",
            "mips64el-unknown-linux-gnuabi64" => "linux-mips64el",
            "x86_64-unknown-freebsd" => "freebsd-amd64",
            "aarch64-unknown-freebsd" => "freebsd-arm64",
            _ => return Err(format!("unsupported release target {target}")),
        };
        Ok(format!("zeronat-{}-{platform}.tar.gz", self.tag))
    }

    fn download_url(&self, name: &str) -> String {
        format!("{RELEASE_ORIGIN}/releases/download/{}/{name}", self.tag)
    }
}

pub fn curl_fetch_command(url: &str, max_bytes: u64) -> (&'static str, Vec<String>) {
    let file_blocks = max_bytes.div_ceil(512);
    let args = vec![
        "-c".into(),
        "limit=$1; shift; ulimit -f \"$limit\" || exit 125; exec \"$@\"".into(),
        "zeronat-curl".into(),
        file_blocks.to_string(),
        "curl".into(),
        "--fail".into(),
        "--silent".into(),
        "--show-error".into(),
        "--location".into(),
        "--proto".into(),
        "=https".into(),
        "--proto-redir".into(),
        "=https".into(),
        "--max-redirs".into(),
        "5".into(),
        "--max-filesize".into(),
        max_bytes.to_string(),
        "--max-time".into(),
        "180".into(),
        url.into(),
    ];
    ("sh", args)
}

pub fn download_verified_asset_with_keys<F>(
    release: &SelectedRelease,
    asset_name: &str,
    trusted_keys: &[TrustedKey],
    mut fetch: F,
) -> Result<DownloadFile, String>
where
    F: FnMut(&str, u64, &File) -> Result<bool, String>,
{
    validate_asset_name(asset_name)?;
    let manifest = fetch_verified_manifest(release, trusted_keys, &mut fetch)?;
    let entry = parse_manifest(&manifest, release.tag(), Some(asset_name))?
        .selected
        .ok_or_else(|| format!("release manifest does not list {asset_name}"))?;
    let mut artifact = DownloadFile::create()?;
    if !fetch(
        &release.download_url(asset_name),
        entry.length,
        artifact.output(),
    )? {
        return Err(format!("release asset {asset_name} is missing"));
    }
    artifact.verify_sha256(entry.length, &entry.digest)?;
    Ok(artifact)
}

pub fn download_release_image_with_keys<F>(
    release: &SelectedRelease,
    trusted_keys: &[TrustedKey],
    mut fetch: F,
) -> Result<String, String>
where
    F: FnMut(&str, u64, &File) -> Result<bool, String>,
{
    let manifest = fetch_verified_manifest(release, trusted_keys, &mut fetch)?;
    Ok(parse_manifest(&manifest, release.tag(), None)?.zeronat_image)
}

pub fn extract_package_member(
    package: &mut DownloadFile,
    member: &str,
) -> Result<DownloadFile, String> {
    if !matches!(member, PACKAGE_BINARY | PACKAGE_INSTALLER) {
        return Err("release package member is unsupported".into());
    }

    let input = package
        .prepare_install()?
        .try_clone()
        .map_err(|e| format!("failed to read release package: {e}"))?;
    let mut archive = tar::Archive::new(GzDecoder::new(input));
    let mut output = DownloadFile::create()?;
    let mut seen = HashSet::new();
    let mut found = false;
    let mut expanded_size = 0u64;

    let entries = archive
        .entries()
        .map_err(|e| format!("failed to read release package: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("failed to read release package: {e}"))?;
        let path = entry.path_bytes();
        let name = std::str::from_utf8(path.as_ref())
            .map_err(|_| "release package contains an invalid member name".to_string())?;
        if !matches!(name, PACKAGE_BINARY | PACKAGE_INSTALLER)
            || !entry.header().entry_type().is_file()
        {
            return Err("release package contains an unsupported member".into());
        }
        expanded_size = expanded_size
            .checked_add(entry.size())
            .ok_or_else(|| "release package expanded size is invalid".to_string())?;
        if expanded_size > ARTIFACT_LIMIT {
            return Err("release package expanded size exceeds the limit".into());
        }
        if !seen.insert(name.to_string()) {
            return Err("release package contains a duplicate member".into());
        }
        if name == member {
            let mut destination = output
                .output()
                .try_clone()
                .map_err(|e| format!("failed to extract release package: {e}"))?;
            std::io::copy(&mut entry, &mut destination)
                .map_err(|e| format!("failed to extract release package: {e}"))?;
            found = true;
        }
    }
    if !found {
        return Err(format!("release package does not contain {member}"));
    }
    output.prepare_install()?;
    Ok(output)
}

fn fetch_verified_manifest<F>(
    release: &SelectedRelease,
    trusted_keys: &[TrustedKey],
    fetch: &mut F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(&str, u64, &File) -> Result<bool, String>,
{
    validate_trusted_keys(trusted_keys)?;
    let mut manifest_file = DownloadFile::create()?;
    if !fetch(
        &release.download_url(MANIFEST_NAME),
        MANIFEST_LIMIT,
        manifest_file.output(),
    )? {
        return Err("release manifest is missing".into());
    }
    let manifest = manifest_file.read_limited(MANIFEST_LIMIT, "release manifest")?;

    let mut signature_file = DownloadFile::create()?;
    if !fetch(
        &release.download_url(SIGNATURE_NAME),
        SIGNATURE_LIMIT,
        signature_file.output(),
    )? {
        return Err("release signature is missing".into());
    }
    let signature = signature_file.read_limited(SIGNATURE_LIMIT, "release signature")?;
    if !trusted_keys
        .iter()
        .any(|trusted| verify_signature(&manifest, &signature, trusted).is_ok())
    {
        return Err("release manifest has no valid trusted signature".into());
    }
    Ok(manifest)
}

fn parse_image_reference(reference: &str, prefix: &str) -> Result<String, String> {
    let digest = reference
        .strip_prefix(prefix)
        .ok_or_else(|| "release image reference has an unexpected repository".to_string())?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("release image reference has an invalid SHA-256 digest".into());
    }
    Ok(reference.into())
}

fn verify_signature(
    manifest: &[u8],
    encoded_signature: &[u8],
    trusted: &TrustedKey,
) -> Result<(), String> {
    let public_key = PublicKey::decode(trusted.public_key)
        .map_err(|e| format!("invalid embedded release public key {}: {e}", trusted.id))?;
    let encoded_signature = std::str::from_utf8(encoded_signature)
        .map_err(|_| "release signature is not UTF-8".to_string())?;
    let signature = Signature::decode(encoded_signature)
        .map_err(|e| format!("invalid release signature: {e}"))?;
    public_key
        .verify(manifest, &signature, false)
        .map_err(|e| format!("release signature verification failed: {e}"))
}

struct ManifestEntry {
    digest: [u8; 32],
    length: u64,
}

struct ParsedManifest {
    zeronat_image: String,
    selected: Option<ManifestEntry>,
}

fn parse_manifest(
    bytes: &[u8],
    expected_tag: &str,
    expected_asset: Option<&str>,
) -> Result<ParsedManifest, String> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
        return Err("release manifest must end with one newline".into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "release manifest is not valid UTF-8".to_string())?;
    let mut lines = text[..text.len() - 1].split('\n');
    let expected_header = format!("{MANIFEST_PREFIX} {expected_tag}");
    if lines.next() != Some(expected_header.as_str()) {
        return Err("release manifest tag mismatch".into());
    }

    let zeronat_image =
        parse_manifest_image_line(lines.next(), "zeronat-image", ZERONAT_IMAGE_PREFIX)?;
    parse_manifest_image_line(lines.next(), "znpppoe-image", ZNPPPOE_IMAGE_PREFIX)?;

    let mut previous_name: Option<&str> = None;
    let mut selected = None;
    let mut asset_count = 0usize;
    for line in lines {
        let mut fields = line.split(' ');
        let digest = fields.next().unwrap_or_default();
        let length = fields.next().unwrap_or_default();
        let name = fields.next().unwrap_or_default();
        if fields.next().is_some() || digest.is_empty() || length.is_empty() || name.is_empty() {
            return Err("release manifest contains a malformed entry".into());
        }
        validate_asset_name(name)?;
        if previous_name.is_some_and(|previous| previous >= name) {
            return Err("release manifest entries are not sorted and unique".into());
        }
        previous_name = Some(name);

        let length = parse_length(length)?;
        let digest = parse_digest(digest)?;
        asset_count += 1;
        if Some(name) == expected_asset {
            selected = Some(ManifestEntry { digest, length });
        }
    }
    if asset_count == 0 {
        return Err("release manifest contains no assets".into());
    }
    Ok(ParsedManifest {
        zeronat_image,
        selected,
    })
}

fn parse_manifest_image_line(
    line: Option<&str>,
    expected_name: &str,
    prefix: &str,
) -> Result<String, String> {
    let line = line.ok_or_else(|| "release manifest is missing image metadata".to_string())?;
    let (name, reference) = line
        .split_once(' ')
        .ok_or_else(|| "release manifest contains malformed image metadata".to_string())?;
    if name != expected_name || reference.contains(' ') {
        return Err("release manifest contains malformed image metadata".into());
    }
    parse_image_reference(reference, prefix)
}

fn parse_version(version: &str) -> Result<(u64, u64, u64), String> {
    let mut parts = version.split('.');
    let major = parse_version_part(parts.next(), "major")?;
    let minor = parse_version_part(parts.next(), "minor")?;
    let patch = parse_version_part(parts.next(), "patch")?;
    if parts.next().is_some() {
        return Err("release version must have three components".into());
    }
    Ok((major, minor, patch))
}

fn parse_version_part(value: Option<&str>, label: &str) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("release version is missing {label}"))?;
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("release version has an invalid {label}"));
    }
    value
        .parse()
        .map_err(|_| format!("release version {label} is too large"))
}

fn validate_asset_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("release asset name contains unsupported characters".into());
    }
    Ok(())
}

fn validate_trusted_keys(keys: &[TrustedKey]) -> Result<(), String> {
    if keys.is_empty() {
        return Err("no release verification keys are configured".into());
    }
    let mut ids = HashSet::new();
    for key in keys {
        if key.id.len() != 16
            || !key
                .id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("release verification key ID is malformed".into());
        }
        if !ids.insert(key.id) {
            return Err("release verification key IDs are duplicated".into());
        }
    }
    Ok(())
}

fn parse_length(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("release manifest contains an invalid length".into());
    }
    let length: u64 = value
        .parse()
        .map_err(|_| "release manifest length is too large".to_string())?;
    if length == 0 || length > ARTIFACT_LIMIT {
        return Err("release manifest artifact length is outside the allowed range".into());
    }
    Ok(length)
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("release manifest contains an invalid SHA-256 digest".into());
    }
    let mut digest = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    Ok(digest)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest characters are validated before decoding"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    const TEST_KEY: TrustedKey = TrustedKey {
        id: "4271ab4a2334630e",
        public_key: include_str!("../tests/fixtures/minisign.pub"),
    };
    const TEST_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/v0.25.1.manifest");
    const TEST_SIGNATURE: &[u8] = include_bytes!("../tests/fixtures/v0.25.1.manifest.minisig");
    const TEST_ASSET: &str = "zeronat-v0.25.1-linux-amd64.tar.gz";
    const TEST_PACKAGE: &[u8] =
        include_bytes!("../tests/fixtures/zeronat-v0.25.1-x86_64-unknown-linux-musl.tar.gz");
    const TEST_BINARY: &[u8] = include_bytes!("../tests/fixtures/zeronat");
    const TEST_INSTALLER: &[u8] = include_bytes!("../tests/fixtures/zeronat-installer");

    #[test]
    fn selected_release_requires_canonical_stable_versions() {
        let release = SelectedRelease::from_latest_url(
            "https://github.com/paltaio/zeronat/releases/tag/v1.2.3\n",
        )
        .unwrap();
        assert_eq!(release.tag(), "v1.2.3");
        assert_eq!(release.version(), "1.2.3");

        for invalid in [
            "1.2",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-rc1",
            "1.2.3+build",
            "1.2.3.4",
        ] {
            assert!(SelectedRelease::from_version(invalid).is_err(), "{invalid}");
        }
        assert!(SelectedRelease::from_latest_url(
            "https://github.com/other/repo/releases/tag/v1.2.3"
        )
        .is_err());
    }

    #[test]
    fn package_names_use_public_platform_names() {
        let release = SelectedRelease::from_version("0.25.1").unwrap();

        assert_eq!(
            release.package_name("x86_64-unknown-linux-musl").unwrap(),
            "zeronat-v0.25.1-linux-amd64.tar.gz"
        );
        assert_eq!(
            release.package_name("aarch64-unknown-linux-gnu").unwrap(),
            "zeronat-v0.25.1-linux-arm64-gnu.tar.gz"
        );
        assert_eq!(
            release.package_name("x86_64-unknown-freebsd").unwrap(),
            "zeronat-v0.25.1-freebsd-amd64.tar.gz"
        );
        assert!(release.package_name("x86_64-apple-darwin").is_err());
    }

    #[test]
    fn image_reference_requires_the_repository_and_an_oci_digest() {
        let digest = "01".repeat(32);
        let expected = format!("{ZERONAT_IMAGE_PREFIX}{digest}");
        assert_eq!(
            parse_image_reference(&expected, ZERONAT_IMAGE_PREFIX).unwrap(),
            expected
        );

        for invalid in [
            format!("ghcr.io/other/zeronat@sha256:{digest}"),
            format!("ghcr.io/paltaio/zeronat:{digest}"),
            format!("{ZERONAT_IMAGE_PREFIX}{}", "0".repeat(63)),
            format!("{ZERONAT_IMAGE_PREFIX}{}", "A".repeat(64)),
            format!("{ZERONAT_IMAGE_PREFIX}{digest}\n"),
        ] {
            assert!(
                parse_image_reference(&invalid, ZERONAT_IMAGE_PREFIX).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn curl_fetch_uses_a_kernel_file_size_limit() {
        let (program, args) = curl_fetch_command("https://example.test/artifact", 513);
        assert_eq!(program, "sh");
        assert_eq!(args[3], "2");
        assert!(args[1].contains("ulimit -f"));
        assert!(args.windows(2).any(|pair| pair == ["--proto", "=https"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--proto-redir", "=https"]));
        assert!(args.windows(2).any(|pair| pair == ["--max-redirs", "5"]));
    }

    #[test]
    fn manifest_parser_rejects_substitution_and_malformed_entries() {
        let digest = "00".repeat(32);
        let valid = format!(
            "{MANIFEST_PREFIX} v1.2.3\n\
             zeronat-image {ZERONAT_IMAGE_PREFIX}{digest}\n\
             znpppoe-image {ZNPPPOE_IMAGE_PREFIX}{digest}\n\
             {digest} 17 zeronat-v1.2.3-linux-amd64.tar.gz\n"
        );
        assert!(parse_manifest(
            valid.as_bytes(),
            "v1.2.3",
            Some("zeronat-v1.2.3-linux-amd64.tar.gz")
        )
        .is_ok());
        assert!(parse_manifest(
            valid.as_bytes(),
            "v1.2.4",
            Some("zeronat-v1.2.3-linux-amd64.tar.gz")
        )
        .is_err());
        assert!(parse_manifest(
            valid.as_bytes(),
            "v1.2.3",
            Some("zeronat-v1.2.3-other.tar.gz")
        )
        .unwrap()
        .selected
        .is_none());

        let duplicate = format!(
            "{MANIFEST_PREFIX} v1.2.3\n\
             zeronat-image {ZERONAT_IMAGE_PREFIX}{digest}\n\
             znpppoe-image {ZNPPPOE_IMAGE_PREFIX}{digest}\n\
             {digest} 17 asset\n\
             {digest} 17 asset\n"
        );
        assert!(parse_manifest(duplicate.as_bytes(), "v1.2.3", Some("asset")).is_err());
    }

    #[test]
    fn verified_download_accepts_the_signed_artifact() {
        let release = SelectedRelease::from_version("0.25.1").unwrap();
        let mut download = download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .unwrap();
        let mut package = Vec::new();
        download
            .prepare_install()
            .unwrap()
            .read_to_end(&mut package)
            .unwrap();
        assert_eq!(package, TEST_PACKAGE);
    }

    #[test]
    fn verified_manifest_exposes_the_image_reference() {
        let release = SelectedRelease::from_version("0.25.1").unwrap();
        let image = download_release_image_with_keys(
            &release,
            &[TEST_KEY],
            fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .unwrap();

        assert_eq!(image, format!("{ZERONAT_IMAGE_PREFIX}{}", "0".repeat(64)));
    }

    #[test]
    fn package_extraction_returns_each_selected_binary() {
        let release = SelectedRelease::from_version("0.25.1").unwrap();
        let mut package = download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .unwrap();

        let mut binary = extract_package_member(&mut package, PACKAGE_BINARY).unwrap();
        let mut installed = Vec::new();
        binary
            .prepare_install()
            .unwrap()
            .read_to_end(&mut installed)
            .unwrap();
        assert_eq!(installed, TEST_BINARY);

        let mut installer = extract_package_member(&mut package, PACKAGE_INSTALLER).unwrap();
        let mut installed = Vec::new();
        installer
            .prepare_install()
            .unwrap()
            .read_to_end(&mut installed)
            .unwrap();
        assert_eq!(installed, TEST_INSTALLER);
    }

    #[test]
    fn package_extraction_rejects_excessive_expanded_size() {
        let mut header = tar::Header::new_ustar();
        header.set_path(PACKAGE_BINARY).unwrap();
        header.set_size(ARTIFACT_LIMIT + 1);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(header.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut package = DownloadFile::create().unwrap();
        package
            .output()
            .try_clone()
            .unwrap()
            .write_all(&compressed)
            .unwrap();

        let error = extract_package_member(&mut package, PACKAGE_BINARY)
            .err()
            .unwrap();
        assert!(error.contains("expanded size exceeds"), "{error}");
    }

    #[test]
    fn verified_download_rejects_changed_or_missing_inputs() {
        let release = SelectedRelease::from_version("0.25.1").unwrap();
        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, b"changed binary"),
        )
        .is_err());

        let mut changed_manifest = TEST_MANIFEST.to_vec();
        changed_manifest[0] ^= 1;
        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(&changed_manifest, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .is_err());

        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            |url, _, output| {
                if url.ends_with(".manifest") {
                    return Ok(false);
                }
                fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE)(url, 0, output)
            },
        )
        .is_err());

        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(TEST_MANIFEST, b"invalid signature", TEST_PACKAGE),
        )
        .is_err());

        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            |url, _, output| {
                if url.ends_with(".minisig") {
                    return Ok(false);
                }
                fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE)(url, 0, output)
            },
        )
        .is_err());

        let substituted = SelectedRelease::from_version("0.25.2").unwrap();
        assert!(download_verified_asset_with_keys(
            &substituted,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .is_err());
    }

    #[test]
    fn verified_download_rejects_wrong_keys_and_legacy_signatures() {
        const OTHER_KEY: TrustedKey = TrustedKey {
            id: "e7620f1842b4e81f",
            public_key: "untrusted comment: test-only wrong public key\n\
                         RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n",
        };
        const LEGACY_SIGNATURE: &[u8] = b"untrusted comment: test-only legacy signature\n\
RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n\
trusted comment: timestamp:1555779966\tfile:test\n\
QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==\n";
        let release = SelectedRelease::from_version("0.25.1").unwrap();

        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[OTHER_KEY],
            fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .is_err());
        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[OTHER_KEY],
            fixture_fetch(TEST_MANIFEST, LEGACY_SIGNATURE, TEST_PACKAGE),
        )
        .is_err());

        let mut download = download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[OTHER_KEY, TEST_KEY],
            fixture_fetch(TEST_MANIFEST, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .unwrap();
        assert!(download.prepare_install().is_ok());
    }

    #[test]
    fn verified_download_enforces_metadata_limits() {
        let release = SelectedRelease::from_version("0.25.1").unwrap();
        let oversized_manifest = vec![b'x'; MANIFEST_LIMIT as usize + 1];
        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(&oversized_manifest, TEST_SIGNATURE, TEST_PACKAGE),
        )
        .is_err());

        let oversized_signature = vec![b'x'; SIGNATURE_LIMIT as usize + 1];
        assert!(download_verified_asset_with_keys(
            &release,
            TEST_ASSET,
            &[TEST_KEY],
            fixture_fetch(TEST_MANIFEST, &oversized_signature, TEST_PACKAGE),
        )
        .is_err());
    }

    fn fixture_fetch<'a>(
        manifest: &'a [u8],
        signature: &'a [u8],
        artifact: &'a [u8],
    ) -> impl FnMut(&str, u64, &File) -> Result<bool, String> + 'a {
        fixture_fetch_named(manifest, signature, TEST_ASSET, artifact)
    }

    fn fixture_fetch_named<'a>(
        manifest: &'a [u8],
        signature: &'a [u8],
        asset_name: &'a str,
        artifact: &'a [u8],
    ) -> impl FnMut(&str, u64, &File) -> Result<bool, String> + 'a {
        move |url, _, output| {
            let bytes = if url.ends_with(".manifest") {
                manifest
            } else if url.ends_with(".minisig") {
                signature
            } else if url.ends_with(asset_name) {
                artifact
            } else {
                return Ok(false);
            };
            output
                .try_clone()
                .and_then(|mut file| file.write_all(bytes))
                .map_err(|e| format!("writing fixture: {e}"))?;
            Ok(true)
        }
    }
}
