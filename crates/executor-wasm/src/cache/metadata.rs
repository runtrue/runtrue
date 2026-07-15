use super::AotCacheKey;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthenticatedMetadata {
    pub(super) schema_version: u32,
    pub(super) key: AotCacheKey,
    pub(super) artifact_digest: ContentDigest,
    pub(super) artifact_size: u64,
    pub(super) authentication_tag: String,
}

#[derive(Debug, Serialize)]
pub(super) struct UnsignedMetadata<'a> {
    pub(super) schema_version: u32,
    pub(super) key: &'a AotCacheKey,
    pub(super) artifact_digest: &'a ContentDigest,
    pub(super) artifact_size: u64,
}
