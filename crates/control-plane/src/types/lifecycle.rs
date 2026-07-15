use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleGcRoot {
    pub digest: ContentDigest,
    pub root_kind: String,
    pub root_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleGcLease {
    pub generation: u64,
    pub phase: String,
    pub lease_owner: String,
    pub lease_token: String,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleGcMetrics {
    pub generation: u64,
    pub marked_objects: u64,
    pub candidate_objects: u64,
    pub swept_objects: u64,
    pub swept_bytes: u64,
    pub active_storage_reservations: u64,
    pub scan_pending: u64,
    pub scan_failed_or_error: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePruneSummary {
    pub storage_reservations: u64,
    pub download_tickets: u64,
    pub object_transfers: u64,
    pub cache_observations: u64,
    pub log_frames: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionRequestRecord {
    pub id: String,
    pub kind: String,
    pub source_id: String,
    pub target: Value,
    pub evidence: Value,
    pub status: String,
    pub created_unix_ms: u64,
}
