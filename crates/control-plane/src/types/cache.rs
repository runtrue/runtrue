use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Durable mirror of one immutable filesystem cache generation. The control
/// plane stores digests and trust metadata only; cache bytes remain in CAS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheTrustGenerationRecord {
    pub cache_entry_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub identity_digest: ContentDigest,
    pub key_material_digest: ContentDigest,
    pub key_material: Value,
    pub trust_domain: Value,
    pub generation: u64,
    pub manifest_digest: ContentDigest,
    pub tree_manifest_digest: ContentDigest,
    pub fencing_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cache_entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_evidence_digest: Option<ContentDigest>,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachePromotionState {
    Pending,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachePromotionRecord {
    pub id: String,
    pub subject_digest: ContentDigest,
    pub tenant_id: String,
    pub repository_id: String,
    pub source_cache_entry_id: String,
    pub target_identity_digest: ContentDigest,
    pub target_trust_domain: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_cache_entry_id: Option<String>,
    pub evidence_digest: ContentDigest,
    pub evidence: Value,
    pub state: CachePromotionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_cache_entry_id: Option<String>,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheAccessObservation {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub operation: String,
    pub key_material_digest: ContentDigest,
    pub candidates: Vec<Value>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_trust_domain: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_generation: Option<u64>,
    pub transferred_bytes: u64,
    pub latency_ms: u64,
    pub breaker_state: String,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheTrustMetrics {
    pub hits: u64,
    pub misses: u64,
    pub bypassed_health: u64,
    pub saves: u64,
    pub save_failures: u64,
    pub denied: u64,
    pub promotions_pending: u64,
    pub promotions_completed: u64,
    pub promotions_failed: u64,
}
