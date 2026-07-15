use crate::{
    digest::{digest_file, MAX_HASHED_FILE_BYTES},
    error::ImageCliError,
    output::{self, ManifestResult},
    secure_fs::write_new_file,
};
use runtrue_attest::{ImageKind, ImageManifest, SnapshotPhase};
use runtrue_model::ContentDigest;
use std::{collections::BTreeMap, path::PathBuf};

pub(crate) struct CreateRequest {
    pub(crate) kind: ImageKind,
    pub(crate) name: String,
    pub(crate) payload: PathBuf,
    pub(crate) payload_media_type: String,
    pub(crate) operating_system: String,
    pub(crate) architecture: String,
    pub(crate) builder_id: String,
    pub(crate) provenance: PathBuf,
    pub(crate) sbom: PathBuf,
    pub(crate) created_unix_ms: u64,
    pub(crate) expires_unix_ms: Option<u64>,
    pub(crate) snapshot_phase: Option<SnapshotPhase>,
    pub(crate) components: Vec<String>,
    pub(crate) compatibility: Vec<String>,
    pub(crate) output: PathBuf,
}

pub(crate) fn create(request: CreateRequest, json: bool) -> Result<(), ImageCliError> {
    let (payload_digest, payload_size_bytes) =
        digest_file(&request.payload, MAX_HASHED_FILE_BYTES)?;
    let (build_provenance_digest, _) = digest_file(&request.provenance, MAX_HASHED_FILE_BYTES)?;
    let (sbom_digest, _) = digest_file(&request.sbom, MAX_HASHED_FILE_BYTES)?;
    let manifest = ImageManifest {
        manifest_version: 1,
        kind: request.kind,
        name: request.name,
        payload_digest: payload_digest.clone(),
        payload_size_bytes,
        payload_media_type: request.payload_media_type,
        operating_system: request.operating_system,
        architecture: request.architecture,
        builder_id: request.builder_id,
        build_provenance_digest,
        sbom_digest,
        created_unix_ms: request.created_unix_ms,
        expires_unix_ms: request.expires_unix_ms,
        snapshot_phase: request.snapshot_phase,
        components: parse_digest_map(request.components)?,
        compatibility: parse_string_map(request.compatibility)?,
    };
    let bytes = manifest.canonical_bytes()?;
    let manifest_digest = ContentDigest::sha256(&bytes);
    write_new_file(&request.output, &bytes, 0o600)?;
    output::print(
        json,
        &ManifestResult {
            output: request.output,
            manifest_digest,
            payload_digest,
            payload_size_bytes,
        },
        "created canonical image manifest",
    )
}
fn parse_digest_map(values: Vec<String>) -> Result<BTreeMap<String, ContentDigest>, ImageCliError> {
    let mut result = BTreeMap::new();
    for value in values {
        let (name, digest) = split_pair(&value)?;
        if result
            .insert(name.to_owned(), ContentDigest::parse(digest.to_owned())?)
            .is_some()
        {
            return Err(ImageCliError::DuplicateMetadataKey(name.to_owned()));
        }
    }
    Ok(result)
}
fn parse_string_map(values: Vec<String>) -> Result<BTreeMap<String, String>, ImageCliError> {
    let mut result = BTreeMap::new();
    for value in values {
        let (name, v) = split_pair(&value)?;
        if result.insert(name.to_owned(), v.to_owned()).is_some() {
            return Err(ImageCliError::DuplicateMetadataKey(name.to_owned()));
        }
    }
    Ok(result)
}
fn split_pair(value: &str) -> Result<(&str, &str), ImageCliError> {
    let Some((name, v)) = value.split_once('=') else {
        return Err(ImageCliError::InvalidMetadataPair(value.to_owned()));
    };
    if name.is_empty() || v.is_empty() || name.contains('\0') || v.contains('\0') {
        return Err(ImageCliError::InvalidMetadataPair(value.to_owned()));
    }
    Ok((name, v))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_reject_duplicates_and_invalid_digests() {
        let d = ContentDigest::sha256(b"x");
        assert!(parse_digest_map(vec![format!("root={d}")]).is_ok());
        assert!(matches!(
            parse_digest_map(vec![format!("root={d}"), format!("root={d}")]),
            Err(ImageCliError::DuplicateMetadataKey(_))
        ));
        assert!(parse_digest_map(vec!["root=latest".to_owned()]).is_err());
    }
}
