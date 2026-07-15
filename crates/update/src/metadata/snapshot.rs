#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataReference {
    pub version: u64,
    pub sha256: ContentDigest,
    pub length: u64,
}

impl MetadataReference {
    pub fn for_envelope<T: Serialize>(
        version: u64,
        envelope: &SignedEnvelope<T>,
    ) -> Result<Self, UpdateError> {
        let bytes = canonical_bytes(envelope)?;
        let length = u64::try_from(bytes.len()).map_err(|_| UpdateError::MetadataTooLarge)?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(UpdateError::MetadataTooLarge);
        }
        Ok(Self {
            version,
            sha256: ContentDigest::sha256(bytes),
            length,
        })
    }

    pub(crate) fn verify<T: Serialize>(
        &self,
        actual_version: u64,
        envelope: &SignedEnvelope<T>,
    ) -> Result<(), UpdateError> {
        if self.version == 0 || self.version != actual_version {
            return Err(UpdateError::ReferencedVersionMismatch);
        }
        let actual = Self::for_envelope(actual_version, envelope)?;
        if &actual != self {
            return Err(UpdateError::MetadataReferenceMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMetadata {
    pub header: MetadataHeader,
    pub targets: MetadataReference,
}

impl SnapshotMetadata {
    pub fn validate_structure(&self) -> Result<(), UpdateError> {
        self.header.validate_structure(RoleType::Snapshot)?;
        if self.targets.version == 0
            || self.targets.length == 0
            || self.targets.length > MAX_METADATA_BYTES as u64
        {
            return Err(UpdateError::InvalidSnapshotMetadata);
        }
        Ok(())
    }

    pub(crate) fn validate_at(&self, now_unix_seconds: u64) -> Result<(), UpdateError> {
        self.validate_structure()?;
        self.header
            .validate_at(RoleType::Snapshot, now_unix_seconds)
    }
}

use crate::{
    canonical_bytes, MetadataHeader, RoleType, SignedEnvelope, UpdateError, MAX_METADATA_BYTES,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
