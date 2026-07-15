use super::ImageAttestError;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::canonicalize_value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const IMAGE_MANIFEST_MEDIA_TYPE: &str =
    "application/vnd.runtrue.isolation-image-manifest+canonical-json;version=1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageKind {
    FirecrackerKernel,
    FirecrackerRootFilesystem,
    FirecrackerSnapshot,
    GuestAgent,
    OciImage,
    ToolchainLayer,
    WasmComponent,
    WasmAot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotPhase {
    /// No job identity, source, writable job disk, token, or secret was added.
    Sterile,
    JobIdentityInjected,
    SourceMounted,
    SecretReleased,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageManifest {
    pub manifest_version: u32,
    pub kind: ImageKind,
    pub name: String,
    pub payload_digest: ContentDigest,
    pub payload_size_bytes: u64,
    pub payload_media_type: String,
    pub operating_system: String,
    pub architecture: String,
    pub builder_id: String,
    pub build_provenance_digest: ContentDigest,
    pub sbom_digest: ContentDigest,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_phase: Option<SnapshotPhase>,
    /// Exact subordinate objects, such as kernel, rootfs, guest, or WIT world.
    pub components: BTreeMap<String, ContentDigest>,
    /// Runtime versions, WIT world, CPU feature floor, or ABI constraints.
    pub compatibility: BTreeMap<String, String>,
}

impl ImageManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ImageAttestError> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        Ok(serde_json::to_vec(&canonicalize_value(value))?)
    }

    pub fn digest(&self) -> Result<ContentDigest, ImageAttestError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedImageManifest {
    pub manifest: ImageManifest,
    pub manifest_digest: ContentDigest,
    pub media_type: String,
    pub algorithm: String,
    pub key_id: ContentDigest,
    pub signature: Vec<u8>,
}
