//! Supported payload identities and remote architecture metadata.
use anyhow::{Result, bail, ensure};

pub(super) const BINARY_LIMIT: u64 = 32 * 1024 * 1024;
// Extracted frps digests from the official 0.71.1 release archives, themselves
// verified against that release's frp_sha256_checksums.txt. Never trust a
// caller-provided sidecar checksum instead of these pinned payload digests.
pub(super) const AMD64_SHA256: &str =
    "2322762939e66e66850bbc9103b6d73fec39e83bd8ad6c71ebeeb120d56d6ab3";
pub(super) const ARM64_SHA256: &str =
    "45a45650cf6ad2568a90f646b1ad79ac483510c1d845ecc55c532ad271ff5366";

pub(super) fn binary_digest(architecture: &str) -> Result<&'static str> {
    match architecture {
        "amd64" => Ok(AMD64_SHA256),
        "arm64" => Ok(ARM64_SHA256),
        _ => bail!("only Linux amd64 and arm64 FRP payloads are supported"),
    }
}

pub(super) fn parse_architecture(output: &str) -> Result<String> {
    let architectures: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("TUNNELLB_ARCH "))
        .collect();
    ensure!(
        architectures.len() == 1,
        "remote worker returned invalid architecture metadata"
    );
    binary_digest(architectures[0])?;

    Ok(architectures[0].into())
}
