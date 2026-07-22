use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackagePreparationTier {
    Warmish,
    Warm,
}

impl PackagePreparationTier {
    #[must_use]
    pub const fn placement_rank(self) -> u8 {
        match self {
            Self::Warmish => 1,
            Self::Warm => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementScoreObservation {
    pub fair_share: u64,
    pub effective_priority: i64,
    pub preferred_content_hits: u64,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub preferred_package_tier: u8,
    pub runner_active_jobs: u32,
}

const fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementObservation {
    pub runner_id: String,
    pub queued_jobs: u64,
    pub compatible_jobs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_score: Option<PlacementScoreObservation>,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedLeaseOffer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    pub placement: PlacementObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerStatus {
    /// Newly enrolled immutable replacement. It may prove health but has no
    /// scheduling or broker authority until the control plane activates it.
    Probationary,
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
    /// Maximum concurrent Wasm jobs hosted by this runner process. Other
    /// isolation backends remain exclusive at the process boundary.
    #[serde(default = "default_max_concurrent_wasm_jobs")]
    pub max_concurrent_wasm_jobs: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Only attested or pool-policy-approved capabilities enter this set.
    pub verified_capabilities: BTreeSet<String>,
    /// Informational claims never used for a hard scheduling decision.
    pub self_reported_capabilities: BTreeSet<String>,
    pub status: RunnerStatus,
    pub active_jobs: u32,
    #[serde(default)]
    pub active_wasm_jobs: u32,
    pub used_cpus: u32,
    pub used_memory_bytes: u64,
    pub used_storage_bytes: u64,
    pub locality: BTreeSet<ContentDigest>,
    /// Authenticated package-specific preparation state. Unlike `locality`,
    /// this is graded and may influence latency-oriented tie breaking.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub package_tiers: BTreeMap<ContentDigest, PackagePreparationTier>,
    pub last_heartbeat_unix_ms: u64,
}

const fn default_max_concurrent_wasm_jobs() -> u32 {
    1
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
