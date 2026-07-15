use crate::{
    exact_reference_digest, expected_compatibility, WasmError, WasmLimits, WasmTarget,
    COMPONENT_MEDIA_TYPE, WIT_SOURCE,
};
use runtrue_attest::{ImageKind, ImageVerifyingKey, SignedImageManifest};
use runtrue_model::ContentDigest;
use std::{collections::BTreeMap, fmt, sync::Arc};
#[derive(Clone)]
pub struct WasmComponentArtifact {
    pub(crate) reference: String,
    pub(crate) bytes: Arc<[u8]>,
    pub(crate) signed_manifest: SignedImageManifest,
    pub(crate) expected_signer: ImageVerifyingKey,
}

impl WasmComponentArtifact {
    pub fn new(
        reference: impl Into<String>,
        bytes: impl Into<Arc<[u8]>>,
        signed_manifest: SignedImageManifest,
        expected_signer: ImageVerifyingKey,
    ) -> Result<Self, WasmError> {
        let reference = reference.into();
        exact_reference_digest(&reference)?;
        Ok(Self {
            reference,
            bytes: bytes.into(),
            signed_manifest,
            expected_signer,
        })
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn signed_manifest(&self) -> &SignedImageManifest {
        &self.signed_manifest
    }

    pub(crate) fn verify(
        &self,
        target: &WasmTarget,
        limits: WasmLimits,
        now_unix_ms: u64,
    ) -> Result<(), WasmError> {
        if self.bytes.is_empty() || self.bytes.len() > limits.max_component_bytes {
            return Err(WasmError::LimitExceeded("component bytes"));
        }
        if self.signed_manifest.key_id != self.expected_signer.key_id() {
            return Err(WasmError::SignerMismatch);
        }
        self.expected_signer
            .verify_manifest(&self.signed_manifest)?;
        let manifest = &self.signed_manifest.manifest;
        let reference_digest = exact_reference_digest(&self.reference)?;
        let payload_size = u64::try_from(self.bytes.len())
            .map_err(|_| WasmError::LimitExceeded("component bytes"))?;
        if manifest.kind != ImageKind::WasmComponent
            || manifest.payload_digest != reference_digest
            || manifest.payload_digest != ContentDigest::sha256(&self.bytes)
            || manifest.payload_size_bytes != payload_size
            || manifest.payload_media_type != COMPONENT_MEDIA_TYPE
            || manifest.operating_system != "wasm"
            || manifest.architecture != target.manifest_architecture()
            || manifest.snapshot_phase.is_some()
        {
            return Err(WasmError::ManifestMismatch);
        }
        if manifest.created_unix_ms > now_unix_ms
            || manifest
                .expires_unix_ms
                .is_some_and(|expires| now_unix_ms >= expires)
        {
            return Err(WasmError::ManifestExpired);
        }
        let expected_components =
            BTreeMap::from([("wit".to_owned(), ContentDigest::sha256(WIT_SOURCE))]);
        if manifest.components != expected_components
            || manifest.compatibility != expected_compatibility(target)
        {
            return Err(WasmError::ManifestCompatibilityMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for WasmComponentArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmComponentArtifact")
            .field("reference", &self.reference)
            .field("payload_digest", &ContentDigest::sha256(&self.bytes))
            .field("signer", &self.expected_signer.key_id())
            .finish()
    }
}
