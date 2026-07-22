use runtrue_model::ContentDigest;
use runtrue_scheduler::SchedulingRequirements;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerPoolScalingPolicy {
    pub pool_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_runtime_compatibility_digest: Option<ContentDigest>,
    pub minimum_workers: u32,
    pub minimum_idle_workers: u32,
    pub maximum_workers: u32,
    pub scale_up_batch: u32,
    pub idle_timeout_ms: u64,
    pub offline_grace_ms: u64,
    pub cooldown_ms: u64,
    pub enabled: bool,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerPoolTemplateRecord {
    pub pool_id: String,
    /// Digest of the complete scheduling-requirements class this template serves.
    pub runtime_compatibility_digest: ContentDigest,
    pub provider: String,
    pub provider_template_id: String,
    /// Immutable runner image or binary digest expected during enrollment.
    pub runner_template_digest: ContentDigest,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerDemandGroup {
    pub runtime_compatibility_digest: ContentDigest,
    pub requirements: SchedulingRequirements,
    pub queued_jobs: u64,
    pub active_slots: u64,
    pub available_slots: u64,
    pub pending_slots: u64,
    pub slots_per_worker: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerPoolFleetSnapshot {
    pub pool_id: String,
    pub observed_unix_ms: u64,
    pub demand: Vec<RunnerDemandGroup>,
    pub online_workers: u64,
    pub draining_workers: u64,
    pub offline_workers: u64,
    pub quarantined_workers: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerFleetRequestState {
    Requested,
    Provisioning,
    Bootstrapping,
    Enrolled,
    Online,
    Draining,
    Terminating,
    Terminated,
    Failed,
    Quarantined,
}

impl RunnerFleetRequestState {
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        use RunnerFleetRequestState::{
            Bootstrapping, Draining, Enrolled, Failed, Online, Provisioning, Quarantined,
            Requested, Terminated, Terminating,
        };
        matches!(
            (self, next),
            (Requested, Provisioning | Failed)
                | (Provisioning, Bootstrapping | Failed | Quarantined)
                | (Bootstrapping, Enrolled | Failed | Quarantined)
                | (Enrolled, Online | Failed | Quarantined)
                | (Online, Draining | Quarantined)
                | (Draining, Terminating | Quarantined)
                | (Terminating, Terminated | Failed | Quarantined)
                | (Failed | Quarantined, Terminating)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerFleetRequestRecord {
    pub id: String,
    pub pool_id: String,
    pub runtime_compatibility_digest: ContentDigest,
    pub provider: String,
    pub provider_template_id: String,
    pub runner_template_digest: ContentDigest,
    pub state: RunnerFleetRequestState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

/// One-time autoscaler bearer returned only when a launch claim is created.
pub struct RunnerLaunchClaimToken(Zeroizing<String>);

impl RunnerLaunchClaimToken {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunnerLaunchClaimToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunnerLaunchClaimToken([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerLaunchClaimRecord {
    pub id: String,
    pub fleet_request_id: String,
    pub enrollment_token_id: String,
    pub pool_id: String,
    pub provider: String,
    pub provider_instance_id: String,
    pub runner_template_digest: ContentDigest,
    /// Digest of the exact provider identity evidence injected into the instance.
    pub identity_proof_digest: ContentDigest,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
}

#[derive(Debug)]
pub struct IssuedRunnerLaunchClaim {
    pub metadata: RunnerLaunchClaimRecord,
    pub token: RunnerLaunchClaimToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerAutoscalerLease {
    pub pool_id: String,
    pub owner_id: String,
    pub fencing_generation: u64,
    pub acquired_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::RunnerFleetRequestState::{
        Bootstrapping, Draining, Failed, Online, Provisioning, Quarantined, Requested, Terminated,
        Terminating,
    };

    #[test]
    fn fleet_lifecycle_requires_drain_before_normal_termination() {
        assert!(Requested.can_transition_to(Provisioning));
        assert!(Bootstrapping.can_transition_to(Failed));
        assert!(Online.can_transition_to(Draining));
        assert!(Draining.can_transition_to(Terminating));
        assert!(Terminating.can_transition_to(Terminated));
        assert!(!Online.can_transition_to(Terminating));
        assert!(!Quarantined.can_transition_to(Online));
    }
}
