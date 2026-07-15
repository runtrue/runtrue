use crate::{
    digest::{digest_file, MAX_HASHED_FILE_BYTES},
    error::ImageCliError,
    keys::read_verifying_key,
    output::{self, VerifyResult},
    secure_fs::read_bounded_regular,
    sign::strict_json,
    snapshot::authorize_if_required,
};
use runtrue_attest::SignedImageManifest;
use std::path::PathBuf;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) struct VerifyRequest {
    pub(crate) signed_manifest: PathBuf,
    pub(crate) public_key: PathBuf,
    pub(crate) payload: PathBuf,
    pub(crate) provenance: PathBuf,
    pub(crate) sbom: PathBuf,
    pub(crate) now_unix_ms: u64,
    pub(crate) require_warm_snapshot: bool,
}
pub(crate) fn verify(request: VerifyRequest, json: bool) -> Result<(), ImageCliError> {
    let bytes = read_bounded_regular(&request.signed_manifest, MAX_MANIFEST_BYTES, false)?;
    let signed: SignedImageManifest = strict_json(&bytes)?;
    if serde_json::to_vec(&signed)? != bytes {
        return Err(ImageCliError::NonCanonicalSignedManifest);
    }
    let key = read_verifying_key(&request.public_key)?;
    key.verify_manifest(&signed)?;
    if request.now_unix_ms < signed.manifest.created_unix_ms
        || signed
            .manifest
            .expires_unix_ms
            .is_some_and(|expires| request.now_unix_ms >= expires)
    {
        return Err(ImageCliError::ManifestNotCurrentlyValid);
    }
    let (payload_digest, payload_size) = digest_file(&request.payload, MAX_HASHED_FILE_BYTES)?;
    if payload_digest != signed.manifest.payload_digest
        || payload_size != signed.manifest.payload_size_bytes
    {
        return Err(ImageCliError::PayloadMismatch);
    }
    let (provenance_digest, _) = digest_file(&request.provenance, MAX_HASHED_FILE_BYTES)?;
    if provenance_digest != signed.manifest.build_provenance_digest {
        return Err(ImageCliError::ProvenanceMismatch);
    }
    let (sbom_digest, _) = digest_file(&request.sbom, MAX_HASHED_FILE_BYTES)?;
    if sbom_digest != signed.manifest.sbom_digest {
        return Err(ImageCliError::SbomMismatch);
    }
    authorize_if_required(&signed, request.require_warm_snapshot)?;
    output::print(
        json,
        &VerifyResult {
            verified: true,
            manifest_digest: signed.manifest_digest,
            payload_digest,
            sbom_digest,
            provenance_digest,
            key_id: signed.key_id,
            warm_snapshot_authorized: request.require_warm_snapshot,
        },
        "verified image manifest and referenced bytes",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys,
        manifest::{self, CreateRequest},
        secure_fs::write_new_file,
        sign,
    };
    use runtrue_attest::{ImageKind, SnapshotPhase};
    use tempfile::TempDir;

    #[test]
    fn manifest_sign_and_full_byte_verification_round_trip() {
        let temp = TempDir::new().unwrap();
        let private_key = temp.path().join("image.key");
        let public_key = temp.path().join("image.pub");
        keys::generate(private_key.clone(), public_key.clone(), true).unwrap();
        let payload = temp.path().join("snapshot");
        let provenance = temp.path().join("provenance.json");
        let sbom = temp.path().join("sbom.json");
        write_new_file(&payload, b"sterile-snapshot", 0o600).unwrap();
        write_new_file(&provenance, b"{\"builder\":\"test\"}", 0o600).unwrap();
        write_new_file(&sbom, b"{\"packages\":[]}", 0o600).unwrap();
        let manifest_path = temp.path().join("manifest.json");
        manifest::create(
            CreateRequest {
                kind: ImageKind::FirecrackerSnapshot,
                name: "test-snapshot".to_owned(),
                payload: payload.clone(),
                payload_media_type: "application/vnd.runtrue.firecracker.snapshot".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                builder_id: "test-builder".to_owned(),
                provenance: provenance.clone(),
                sbom: sbom.clone(),
                created_unix_ms: 1,
                expires_unix_ms: Some(1_000),
                snapshot_phase: Some(SnapshotPhase::Sterile),
                components: Vec::new(),
                compatibility: vec!["firecracker=1.x".to_owned()],
                output: manifest_path.clone(),
            },
            true,
        )
        .unwrap();
        let signed_manifest = temp.path().join("manifest.signed.json");
        sign::sign(manifest_path, private_key, signed_manifest.clone(), true).unwrap();
        verify(
            VerifyRequest {
                signed_manifest,
                public_key,
                payload,
                provenance,
                sbom,
                now_unix_ms: 10,
                require_warm_snapshot: true,
            },
            true,
        )
        .unwrap();
    }
}
