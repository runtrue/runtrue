use crate::{CacheError, CacheIdentity, CacheProducer, PromotionRecord};
use runtrue_model::ContentDigest;
use runtrue_storage::TreeSnapshot;
use serde::{Deserialize, Serialize};

/// Immutable cache generation stored as a verified CAS blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheManifest {
    pub version: u32,
    pub identity: CacheIdentity,
    pub identity_digest: ContentDigest,
    pub generation: u64,
    pub fencing_generation: u64,
    pub tree: TreeSnapshot,
    pub producer: CacheProducer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ticket_id: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<PromotionRecord>,
}

/// Append-only head token. Callers must provide the exact token they observed
/// when committing a successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheHead {
    pub version: u32,
    pub identity_digest: ContentDigest,
    pub generation: u64,
    pub fencing_generation: u64,
    pub manifest_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ticket_id: Option<ContentDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheEntry {
    pub head: CacheHead,
    pub manifest: CacheManifest,
}

impl CacheEntry {
    /// Stable identity for any immutable cache generation, including promoted
    /// generations which intentionally have no runner claim ticket.
    pub fn immutable_id(&self) -> Result<ContentDigest, CacheError> {
        if self.head.identity_digest != self.manifest.identity_digest
            || self.head.generation != self.manifest.generation
            || self.head.manifest_digest
                != ContentDigest::sha256(
                    serde_json::to_vec(&self.manifest).map_err(CacheError::SerializeMetadata)?,
                )
        {
            return Err(CacheError::InvalidManifest(
                "cache entry head does not match its immutable manifest".to_owned(),
            ));
        }
        let material = serde_json::to_vec(&(
            "runtrue.cache-generation-id.v1",
            &self.head.identity_digest,
            &self.manifest.identity.trust_domain,
            self.head.generation,
            &self.head.manifest_digest,
            &self.manifest.tree.manifest_digest,
        ))
        .map_err(CacheError::SerializeMetadata)?;
        Ok(ContentDigest::sha256(material))
    }

    /// Globally scoped identity returned by commit/completion APIs. This is
    /// deliberately distinct from the content tree digest: equal bytes under
    /// different identities, trust scopes, generations, or tickets must not
    /// be substitutable.
    pub fn completion_id(&self, ticket_id: &ContentDigest) -> Result<ContentDigest, CacheError> {
        if self.head.claim_ticket_id.as_ref() != Some(ticket_id)
            || self.manifest.claim_ticket_id.as_ref() != Some(ticket_id)
            || self.head.identity_digest != self.manifest.identity_digest
            || self.head.generation != self.manifest.generation
        {
            return Err(CacheError::InvalidTicketClaim(
                "cache completion identity is not bound to the claimed generation".to_owned(),
            ));
        }
        let material = serde_json::to_vec(&(
            "runtrue.cache-entry-id.v1",
            &self.head.identity_digest,
            &self.manifest.identity.trust_domain,
            self.head.generation,
            &self.manifest.tree.manifest_digest,
            ticket_id,
        ))
        .map_err(CacheError::SerializeMetadata)?;
        Ok(ContentDigest::sha256(material))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMiss {
    NotFound,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    Hit(Box<CacheEntry>),
    Miss(CacheMiss),
}
