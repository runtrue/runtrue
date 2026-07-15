use crate::FirecrackerError;
use runtrue_attest::{ImageVerifyingKey, SignedImageManifest};
use runtrue_model::ContentDigest;
use std::{collections::BTreeMap, path::PathBuf};

/// Installation-scoped image-signing trust. Capsule keys are intentionally a
/// different type and cannot be inserted here.
#[derive(Debug, Clone, Default)]
pub struct ImageTrustStore {
    pub(super) keys: BTreeMap<ContentDigest, ImageVerifyingKey>,
}

impl ImageTrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: ImageVerifyingKey) -> Result<ContentDigest, FirecrackerError> {
        let key_id = key.key_id();
        if self.keys.insert(key_id.clone(), key).is_some() {
            return Err(FirecrackerError::DuplicateImageKey(key_id));
        }
        Ok(key_id)
    }

    pub(super) fn verify(&self, signed: &SignedImageManifest) -> Result<(), FirecrackerError> {
        self.keys
            .get(&signed.key_id)
            .ok_or_else(|| FirecrackerError::UntrustedImageKey(signed.key_id.clone()))?
            .verify_manifest(signed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageArtifact {
    pub signed: SignedImageManifest,
    pub payload_path: PathBuf,
}

impl ImageArtifact {
    #[must_use]
    pub fn new(signed: SignedImageManifest, payload_path: impl Into<PathBuf>) -> Self {
        Self {
            signed,
            payload_path: payload_path.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirecrackerImageSet {
    pub kernel: ImageArtifact,
    pub rootfs: ImageArtifact,
    pub guest: ImageArtifact,
    pub snapshot: Option<SnapshotImageSet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotImageSet {
    pub state: ImageArtifact,
    pub memory: ImageArtifact,
}
