//! One-shot secret lease state and request metadata.
use super::model::SecretIdentity;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Issued,
    Consumed,
    Revoked,
    Expired,
}

/// Input used to mint one step- and purpose-bound release lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLeaseRequest {
    pub identity: SecretIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub step_id: String,
    pub purpose: String,
    pub expires_at_unix_ms: u64,
}

/// Safe lease metadata. Redemption returns plaintext separately and only once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLeaseMetadata {
    pub id: String,
    pub identity: SecretIdentity,
    pub secret_version: u64,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub step_id: String,
    pub purpose: String,
    pub expires_at_unix_ms: u64,
    pub state: LeaseState,
}
