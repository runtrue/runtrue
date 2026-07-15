use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::fmt;

/// Signed durable scheduler projection of one bounded dynamic matrix.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpandedJobSetRecord {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub parent_capsule_digest: ContentDigest,
    pub template_id: String,
    pub producer_job_id: String,
    pub producer_output_name: String,
    pub matrix_input_digest: ContentDigest,
    pub policy_epoch: u64,
    pub generated_job_count: u64,
    pub canonical_job_set: Vec<u8>,
    pub job_set_digest: ContentDigest,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
    pub created_unix_ms: u64,
}

/// Lease-bound request to turn a verified expansion into durable scheduler
/// jobs. The producer lease remains the authorization and fencing boundary;
/// callers cannot materialize an expansion from a naked signed record.
#[derive(Clone, PartialEq, Eq)]
pub struct MaterializeExpandedJobSet {
    pub record: ExpandedJobSetRecord,
    pub execution_lease_id: String,
    pub runner_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub producer_job_attempt: u32,
}

impl fmt::Debug for MaterializeExpandedJobSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializeExpandedJobSet")
            .field("record", &self.record)
            .field("execution_lease_id", &self.execution_lease_id)
            .field("runner_id", &self.runner_id)
            .field("fencing_generation", &self.fencing_generation)
            .field(
                "installation_fencing_epoch",
                &self.installation_fencing_epoch,
            )
            .field("producer_job_attempt", &self.producer_job_attempt)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpandedJobMaterialization {
    pub record_replayed: bool,
    pub jobs_inserted: u64,
}

impl fmt::Debug for ExpandedJobSetRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpandedJobSetRecord")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("repository_id", &self.repository_id)
            .field("run_id", &self.run_id)
            .field("template_id", &self.template_id)
            .field("producer_job_id", &self.producer_job_id)
            .field("producer_output_name", &self.producer_output_name)
            .field("matrix_input_digest", &self.matrix_input_digest)
            .field("policy_epoch", &self.policy_epoch)
            .field("generated_job_count", &self.generated_job_count)
            .field("canonical_job_set_bytes", &self.canonical_job_set.len())
            .field("job_set_digest", &self.job_set_digest)
            .field("signing_key_id", &self.signing_key_id)
            .field("signature_bytes", &self.signature.len())
            .field("created_unix_ms", &self.created_unix_ms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedTriggerEventRecord {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub trigger_kind: String,
    pub idempotency_identity: String,
    pub normalized_digest: ContentDigest,
    pub normalized_envelope: Value,
    pub actor_identity: String,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewScmWebhookEvent {
    pub delivery_id: String,
    pub installation_external_id: String,
    pub external_repository_id: String,
    pub provider_event_name: String,
    pub event_kind: String,
    pub actor_login: String,
    pub ref_name: Option<String>,
    pub normalized_digest: ContentDigest,
    pub payload_digest: ContentDigest,
    pub received_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmWebhookEventRecord {
    pub delivery_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub installation_id: String,
    pub external_repository_id: String,
    pub provider_event_name: String,
    pub event_kind: String,
    pub actor_login: String,
    pub ref_name: Option<String>,
    pub normalized_digest: ContentDigest,
    pub payload_digest: ContentDigest,
    pub received_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleTriggerCursor {
    pub tenant_id: String,
    pub repository_id: String,
    pub workflow_identity: String,
    pub schedule_key: String,
    pub cron_utc: String,
    pub catch_up_policy: String,
    pub maximum_catch_up: u64,
    pub next_fire_unix_ms: u64,
    pub last_fire_unix_ms: Option<u64>,
    pub version: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSemanticsMetrics {
    pub expanded_job_sets: u64,
    pub normalized_triggers: u64,
    pub due_schedules: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleReconciliationSummary {
    pub cursors_considered: u64,
    pub cursors_advanced: u64,
    pub triggers_inserted: u64,
    pub trigger_replays: u64,
    pub due_cursors_remaining: u64,
}
