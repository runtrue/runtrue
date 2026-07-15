#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleType {
    Root,
    Targets,
    Snapshot,
    Timestamp,
}

impl RoleType {
    pub(crate) const ALL: [Self; 4] = [Self::Root, Self::Targets, Self::Snapshot, Self::Timestamp];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Targets => "targets",
            Self::Snapshot => "snapshot",
            Self::Timestamp => "timestamp",
        }
    }

    const fn maximum_lifetime(self) -> u64 {
        match self {
            Self::Root => ROOT_MAX_LIFETIME,
            Self::Targets => TARGETS_MAX_LIFETIME,
            Self::Snapshot => SNAPSHOT_MAX_LIFETIME,
            Self::Timestamp => TIMESTAMP_MAX_LIFETIME,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataHeader {
    pub schema_version: u32,
    pub role: RoleType,
    pub version: u64,
    pub issued_unix_seconds: u64,
    pub expires_unix_seconds: u64,
}

impl MetadataHeader {
    pub fn new(
        role: RoleType,
        version: u64,
        issued_unix_seconds: u64,
        expires_unix_seconds: u64,
    ) -> Self {
        Self {
            schema_version: UPDATE_SCHEMA_VERSION,
            role,
            version,
            issued_unix_seconds,
            expires_unix_seconds,
        }
    }

    pub(crate) fn validate_structure(&self, expected: RoleType) -> Result<(), UpdateError> {
        if self.schema_version != UPDATE_SCHEMA_VERSION
            || self.role != expected
            || self.version == 0
            || self.issued_unix_seconds >= self.expires_unix_seconds
            || self
                .expires_unix_seconds
                .saturating_sub(self.issued_unix_seconds)
                > expected.maximum_lifetime()
        {
            return Err(UpdateError::InvalidMetadataHeader(expected));
        }
        Ok(())
    }

    pub(crate) fn validate_at(
        &self,
        expected: RoleType,
        now_unix_seconds: u64,
    ) -> Result<(), UpdateError> {
        self.validate_structure(expected)?;
        if now_unix_seconds < self.issued_unix_seconds {
            return Err(UpdateError::MetadataFromFuture(expected));
        }
        if now_unix_seconds >= self.expires_unix_seconds {
            return Err(UpdateError::MetadataExpired(expected));
        }
        Ok(())
    }
}
use crate::{
    UpdateError, ROOT_MAX_LIFETIME, SNAPSHOT_MAX_LIFETIME, TARGETS_MAX_LIFETIME,
    TIMESTAMP_MAX_LIFETIME, UPDATE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
