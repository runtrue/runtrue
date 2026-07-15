use crate::{
    canonical::{validate_identifier, validate_profile_name, validate_text, MAX_SHORT_TEXT_BYTES},
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

pub const MAX_LOGICAL_READ_BYTES: u64 = 64 * 1024 * 1024;
const TOMBSTONE_DOMAIN: &[u8] = b"runtrue.provider.object-tombstone.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalObjectClass {
    PublicImmutable,
    Program,
    Source,
    Artifact,
    Cache,
    Checkpoint,
    ReplayBundle,
    EvidencePayload,
    CanonicalManifest,
    Secret,
}

impl LogicalObjectClass {
    #[must_use]
    pub const fn is_protected(self) -> bool {
        !matches!(self, Self::PublicImmutable)
    }

    #[must_use]
    pub const fn forbids_cross_tenant_deduplication(self) -> bool {
        self.is_protected()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LogicalObjectScope {
    Public {
        sharing_policy_digest: ContentDigest,
    },
    Tenant {
        tenant_id: String,
        administrative_trust_domain: String,
        encryption_context_digest: ContentDigest,
    },
}

impl LogicalObjectScope {
    pub fn validate_for(&self, class: LogicalObjectClass) -> Result<(), ProviderContractError> {
        match self {
            Self::Public { .. } if class.is_protected() => {
                Err(ProviderContractError::InvalidObjectContract(
                    "protected object class cannot use public scope",
                ))
            }
            Self::Public { .. } => Ok(()),
            Self::Tenant {
                tenant_id,
                administrative_trust_domain,
                ..
            } => {
                validate_identifier("object tenant id", tenant_id)?;
                validate_identifier(
                    "object administrative trust domain",
                    administrative_trust_domain,
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthority {
    pub principal_digest: ContentDigest,
    pub tenant_id: Option<String>,
    pub administrative_trust_domain: String,
    pub purpose: String,
    pub authorization_decision_digest: ContentDigest,
}

impl StorageAuthority {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if let Some(tenant) = &self.tenant_id {
            validate_identifier("storage authority tenant", tenant)?;
        }
        validate_identifier(
            "storage authority trust domain",
            &self.administrative_trust_domain,
        )?;
        validate_profile_name(&self.purpose)
    }

    pub fn authorize_scope(&self, scope: &LogicalObjectScope) -> Result<(), ProviderContractError> {
        self.validate()?;
        if let LogicalObjectScope::Tenant {
            tenant_id,
            administrative_trust_domain,
            ..
        } = scope
        {
            if self.tenant_id.as_deref() != Some(tenant_id)
                || &self.administrative_trust_domain != administrative_trust_domain
            {
                return Err(ProviderContractError::InvalidObjectContract(
                    "storage authority does not match tenant scope",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationCondition {
    CreateOnce,
    CompareAndSwap {
        expected_current_digest: Option<ContentDigest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectWriteDeclaration {
    pub object_class: LogicalObjectClass,
    pub scope: LogicalObjectScope,
    pub expected_digest: ContentDigest,
    pub expected_size_bytes: u64,
    pub media_type: String,
    pub maximum_chunk_bytes: u64,
    pub publication: PublicationCondition,
    pub authority: StorageAuthority,
}

impl ObjectWriteDeclaration {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.scope.validate_for(self.object_class)?;
        self.authority.authorize_scope(&self.scope)?;
        validate_text(
            "logical object media type",
            &self.media_type,
            MAX_SHORT_TEXT_BYTES,
        )?;
        if self.maximum_chunk_bytes == 0
            || self.maximum_chunk_bytes > self.expected_size_bytes.max(1)
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "invalid logical object chunk bound",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWriteLease {
    pub write_id: String,
    pub declaration_digest: ContentDigest,
    pub next_offset: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectChunk<'a> {
    pub write_id: &'a str,
    pub offset: u64,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalObjectState {
    Available,
    Tombstoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalObjectMetadata {
    pub object_class: LogicalObjectClass,
    pub scope: LogicalObjectScope,
    pub digest: ContentDigest,
    pub size_bytes: u64,
    pub media_type: String,
    pub state: LogicalObjectState,
    pub created_unix_ms: u64,
    pub encryption_generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishObjectOutcome {
    Published(LogicalObjectMetadata),
    ExactReplay(LogicalObjectMetadata),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectReadRequest {
    pub object_class: LogicalObjectClass,
    pub scope: LogicalObjectScope,
    pub digest: ContentDigest,
    /// Size and verification-record digest obtained from authenticated object
    /// metadata before requesting any bytes.
    pub expected_size_bytes: u64,
    pub expected_object_verification_digest: ContentDigest,
    pub offset: u64,
    pub maximum_bytes: u64,
    pub authority: StorageAuthority,
}

impl ObjectReadRequest {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.scope.validate_for(self.object_class)?;
        self.authority.authorize_scope(&self.scope)?;
        if self.offset > self.expected_size_bytes
            || self.maximum_bytes == 0
            || self.maximum_bytes > MAX_LOGICAL_READ_BYTES
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "logical object read bound is zero or too large",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectReadChunk {
    pub digest: ContentDigest,
    pub total_size_bytes: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub chunk_digest: ContentDigest,
    /// Digest of the store's authenticated object-verification record. Range
    /// bytes alone cannot re-hash the whole object.
    pub object_verification_digest: ContentDigest,
    pub complete: bool,
}

impl ObjectReadChunk {
    pub fn verify_against(&self, request: &ObjectReadRequest) -> Result<(), ProviderContractError> {
        request.validate()?;
        let length = u64::try_from(self.bytes.len()).map_err(|_| {
            ProviderContractError::InvalidObjectContract("logical read length overflow")
        })?;
        let end =
            self.offset
                .checked_add(length)
                .ok_or(ProviderContractError::InvalidObjectContract(
                    "logical read offset overflow",
                ))?;
        if self.digest != request.digest
            || self.total_size_bytes != request.expected_size_bytes
            || self.object_verification_digest != request.expected_object_verification_digest
            || self.offset != request.offset
            || length > request.maximum_bytes
            || end > self.total_size_bytes
            || self.chunk_digest != ContentDigest::sha256(&self.bytes)
            || self.complete != (end == self.total_size_bytes)
            || (self.offset == 0
                && self.complete
                && ContentDigest::sha256(&self.bytes) != self.digest)
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "logical object read failed digest, size, offset, or completion verification",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectTombstone {
    pub tombstone_version: u32,
    pub object_class: LogicalObjectClass,
    pub scope: LogicalObjectScope,
    pub original_digest: ContentDigest,
    pub original_size_bytes: u64,
    pub retention_policy_digest: ContentDigest,
    pub deleted_unix_ms: u64,
    pub deletion_method: String,
    pub deletion_proof_digest: Option<ContentDigest>,
}

impl ObjectTombstone {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.tombstone_version != 1 {
            return Err(ProviderContractError::InvalidObjectContract(
                "unsupported tombstone version",
            ));
        }
        self.scope.validate_for(self.object_class)?;
        validate_profile_name(&self.deletion_method)
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        crate::canonical::canonical_digest(TOMBSTONE_DOMAIN, self)
    }
}

/// Chunked integrity-preserving object store. A write is invisible until
/// `commit_write` verifies the declared digest and size and atomically applies
/// its publication condition.
pub trait LogicalObjectStore {
    type Error;

    fn begin_write(
        &self,
        declaration: &ObjectWriteDeclaration,
    ) -> Result<ObjectWriteLease, Self::Error>;

    fn append_chunk(&self, chunk: ObjectChunk<'_>) -> Result<ObjectWriteLease, Self::Error>;

    fn commit_write(
        &self,
        write_id: &str,
        expected_digest: &ContentDigest,
        expected_size_bytes: u64,
    ) -> Result<PublishObjectOutcome, Self::Error>;

    fn abort_write(&self, write_id: &str) -> Result<(), Self::Error>;

    /// Implementations must validate authority and return authenticated metadata.
    fn head(
        &self,
        request: &ObjectReadRequest,
    ) -> Result<Option<LogicalObjectMetadata>, Self::Error>;

    /// Implementations must verify the full stored object's digest and size
    /// before returning a range; callers then verify the returned chunk.
    fn read_range(&self, request: &ObjectReadRequest) -> Result<ObjectReadChunk, Self::Error>;

    fn tombstone(
        &self,
        tombstone: &ObjectTombstone,
        authority: &StorageAuthority,
    ) -> Result<ObjectTombstone, Self::Error>;
}
