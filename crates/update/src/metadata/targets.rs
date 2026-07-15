#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDescription {
    pub sha256: ContentDigest,
    pub length: u64,
    pub media_type: String,
    pub platform: String,
    pub architecture: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,
}

impl TargetDescription {
    pub fn from_bytes(
        bytes: &[u8],
        media_type: impl Into<String>,
        platform: impl Into<String>,
        architecture: impl Into<String>,
        version: impl Into<String>,
        custom: BTreeMap<String, String>,
    ) -> Result<Self, UpdateError> {
        let length = u64::try_from(bytes.len()).map_err(|_| UpdateError::TargetTooLarge)?;
        let target = Self {
            sha256: ContentDigest::sha256(bytes),
            length,
            media_type: media_type.into(),
            platform: platform.into(),
            architecture: architecture.into(),
            version: version.into(),
            custom,
        };
        target.validate()?;
        Ok(target)
    }

    pub(crate) fn validate(&self) -> Result<(), UpdateError> {
        if self.length > MAX_TARGET_BYTES
            || !valid_text(&self.media_type)
            || !valid_text(&self.platform)
            || !valid_text(&self.architecture)
            || !valid_text(&self.version)
            || self.custom.len() > MAX_CUSTOM_FIELDS
            || self
                .custom
                .iter()
                .any(|(key, value)| !valid_text(key) || !valid_text(value))
        {
            return Err(UpdateError::InvalidTargetDescription);
        }
        Ok(())
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<(), UpdateError> {
        let length = u64::try_from(bytes.len()).map_err(|_| UpdateError::TargetTooLarge)?;
        if length > MAX_TARGET_BYTES || length != self.length {
            return Err(UpdateError::TargetLengthMismatch);
        }
        let actual = ContentDigest::sha256(bytes);
        if actual != self.sha256 {
            return Err(UpdateError::TargetDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetsMetadata {
    pub header: MetadataHeader,
    pub targets: BTreeMap<String, TargetDescription>,
}

impl TargetsMetadata {
    pub fn validate_structure(&self) -> Result<(), UpdateError> {
        self.header.validate_structure(RoleType::Targets)?;
        if self.targets.is_empty() || self.targets.len() > MAX_TARGETS {
            return Err(UpdateError::InvalidTargetsMetadata);
        }
        for (path, target) in &self.targets {
            if path.len() > MAX_STRING_BYTES
                || normalize_relative_path(path).ok().as_deref() != Some(path.as_str())
            {
                return Err(UpdateError::UnsafeTargetPath(path.clone()));
            }
            target.validate()?;
        }
        Ok(())
    }

    pub(crate) fn validate_at(&self, now_unix_seconds: u64) -> Result<(), UpdateError> {
        self.validate_structure()?;
        self.header.validate_at(RoleType::Targets, now_unix_seconds)
    }
}

use crate::{
    valid_text, MetadataHeader, RoleType, UpdateError, MAX_CUSTOM_FIELDS, MAX_STRING_BYTES,
    MAX_TARGETS, MAX_TARGET_BYTES,
};
use runtrue_model::{normalize_relative_path, ContentDigest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
