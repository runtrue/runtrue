use crate::error::ImageCliError;
use runtrue_model::ContentDigest;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub(crate) struct DigestResult {
    pub(crate) path: PathBuf,
    pub(crate) digest: ContentDigest,
    pub(crate) size_bytes: u64,
}
#[derive(Debug, Serialize)]
pub(crate) struct StageComponentResult {
    pub(crate) reference: String,
    pub(crate) manifest_digest: ContentDigest,
    pub(crate) payload_digest: ContentDigest,
    pub(crate) payload_size_bytes: u64,
    pub(crate) output: PathBuf,
}
#[derive(Debug, Serialize)]
pub(crate) struct KeygenResult {
    pub(crate) private_key: PathBuf,
    pub(crate) public_key: PathBuf,
    pub(crate) key_id: ContentDigest,
}
#[derive(Debug, Serialize)]
pub(crate) struct ManifestResult {
    pub(crate) output: PathBuf,
    pub(crate) manifest_digest: ContentDigest,
    pub(crate) payload_digest: ContentDigest,
    pub(crate) payload_size_bytes: u64,
}
#[derive(Debug, Serialize)]
pub(crate) struct SignResult {
    pub(crate) output: PathBuf,
    pub(crate) manifest_digest: ContentDigest,
    pub(crate) key_id: ContentDigest,
}
#[derive(Debug, Serialize)]
pub(crate) struct VerifyResult {
    pub(crate) verified: bool,
    pub(crate) manifest_digest: ContentDigest,
    pub(crate) payload_digest: ContentDigest,
    pub(crate) sbom_digest: ContentDigest,
    pub(crate) provenance_digest: ContentDigest,
    pub(crate) key_id: ContentDigest,
    pub(crate) warm_snapshot_authorized: bool,
}

pub(crate) fn print<T: Serialize>(json: bool, value: &T, human: &str) -> Result<(), ImageCliError> {
    if json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{human}");
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}
