#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampMetadata {
    pub header: MetadataHeader,
    pub snapshot: MetadataReference,
}

impl TimestampMetadata {
    pub fn validate_structure(&self) -> Result<(), UpdateError> {
        self.header.validate_structure(RoleType::Timestamp)?;
        if self.snapshot.version == 0
            || self.snapshot.length == 0
            || self.snapshot.length > MAX_METADATA_BYTES as u64
        {
            return Err(UpdateError::InvalidTimestampMetadata);
        }
        Ok(())
    }

    pub(crate) fn validate_at(&self, now_unix_seconds: u64) -> Result<(), UpdateError> {
        self.validate_structure()?;
        self.header
            .validate_at(RoleType::Timestamp, now_unix_seconds)
    }
}
use crate::{MetadataHeader, MetadataReference, RoleType, UpdateError, MAX_METADATA_BYTES};
use serde::{Deserialize, Serialize};
