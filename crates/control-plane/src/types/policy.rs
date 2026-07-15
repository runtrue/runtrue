use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyVersionRecord {
    pub id: String,
    pub policy_id: String,
    pub version: u64,
    pub source: String,
    pub mode: String,
    pub digest: ContentDigest,
    pub created_unix_ms: u64,
}
