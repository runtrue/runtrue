use crate::cache::{AotAuthenticationKey, AotCacheError};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
pub struct AotCacheConfig {
    pub root: PathBuf,
    pub authentication_key: AotAuthenticationKey,
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_entry_bytes: usize,
}

impl AotCacheConfig {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, authentication_key: AotAuthenticationKey) -> Self {
        Self {
            root: root.into(),
            authentication_key,
            max_entries: 1_024,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_entry_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AotCacheKey {
    pub component_digest: ContentDigest,
    pub wit_world: String,
    pub wit_digest: ContentDigest,
    pub wasi_version: String,
    pub wasmtime_version: String,
    pub target_triple: String,
    pub cpu_feature_floor: String,
    pub compiler_settings: String,
    pub security_mitigation_profile: String,
    pub engine_compatibility_digest: ContentDigest,
}

impl AotCacheKey {
    pub fn digest(&self) -> Result<ContentDigest, AotCacheError> {
        Ok(ContentDigest::sha256(serde_json::to_vec(self)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AotCacheStatus {
    Hit,
    Miss,
    QuarantinedMiss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AotCacheEventKind {
    AuthenticationFailed,
    Incompatible,
    Corrupt,
    Malformed,
    UnsafePath,
    Io,
    Budget,
    UnsupportedPlatform,
    RandomnessUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AotCacheEvent {
    pub key_digest: ContentDigest,
    pub kind: AotCacheEventKind,
}
