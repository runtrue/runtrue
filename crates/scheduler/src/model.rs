use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerStatus {
    Online,
    Draining,
    Quarantined,
    Offline,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRecord {
    pub id: String,
    /// Authoritative tenant ownership inherited from the runner pool. This is
    /// control-plane data, never a self-reported inventory claim.
    pub tenant_id: String,
    pub pool_id: String,
    /// Ephemeral identities are automatically removed after they go offline,
    /// provided they have no durable lease history.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
    /// Retired ephemeral runners remain addressable for execution audit
    /// references but are excluded from the active fleet catalog.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retired: bool,
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub isolation_backends: BTreeSet<Isolation>,
    pub logical_cpus: u32,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Only attested or pool-policy-approved capabilities enter this set.
    pub verified_capabilities: BTreeSet<String>,
    /// Informational claims never used for a hard scheduling decision.
    pub self_reported_capabilities: BTreeSet<String>,
    pub status: RunnerStatus,
    pub active_jobs: u32,
    pub used_cpus: u32,
    pub used_memory_bytes: u64,
    pub used_storage_bytes: u64,
    pub locality: BTreeSet<ContentDigest>,
    pub last_heartbeat_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingRequirements {
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub isolation: Isolation,
    pub cpu: u32,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub required_capabilities: BTreeSet<String>,
    pub allowed_pools: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedJob {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub capsule_digest: ContentDigest,
    pub requirements: SchedulingRequirements,
    pub priority: i32,
    pub queued_unix_ms: u64,
    pub preferred_content: BTreeSet<ContentDigest>,
    /// Whether loss of a runner lease may create a fresh attempt automatically.
    pub retryable_after_runner_loss: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseState {
    Offered,
    Active,
    CancelRequested,
    Completed,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub id: String,
    pub job_id: String,
    pub tenant_id: String,
    pub runner_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub capsule_digest: ContentDigest,
    pub issued_unix_ms: u64,
    pub accept_by_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub state: LeaseState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result_digest: Option<ContentDigest>,
}
