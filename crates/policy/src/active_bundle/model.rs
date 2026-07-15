use crate::{CedarAuthorizationRequest, DenyFirstPolicy};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
pub(super) const BUNDLE_DIGEST_DOMAIN: &[u8] = b"runtrue.active-policy-bundle.v1\0";
pub(super) const CORPUS_DIGEST_DOMAIN: &[u8] = b"runtrue.policy-simulation-corpus.v1\0";
pub(super) const REPORT_DIGEST_DOMAIN: &[u8] = b"runtrue.policy-simulation-report.v1\0";
pub const MAX_CANONICAL_POLICY_BYTES: usize = 1024 * 1024;
pub const MAX_STORED_SIMULATION_CASES: usize = 1024;
pub const MAX_CALLER_SIMULATION_CASES: usize = 128;
pub const MAX_SIMULATION_CORPUS_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SHADOW_CASES: usize = 512;
pub(super) const MAX_IDENTIFIER_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyBundleDraftStatus {
    Draft,
    Simulated,
    Shadow,
    Activated,
    Retired,
}

/// Persistable validated draft. `canonical_policy_json` is Cedar's canonical
/// EST representation, not caller formatting. It is immutable after creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleDraft {
    pub id: String,
    pub tenant_id: String,
    pub author_id: String,
    pub(super) canonical_policy_json: String,
    pub digest: ContentDigest,
    pub created_unix_ms: u64,
    pub status: PolicyBundleDraftStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation_digest: Option<ContentDigest>,
    pub simulation_passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated_policy_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySimulationCase {
    pub id: String,
    pub request: CedarAuthorizationRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_allowed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySimulationResult {
    pub case_id: String,
    pub allowed: bool,
    pub evaluation_error: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expectation_matched: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySimulationReport {
    pub policy_digest: ContentDigest,
    pub corpus_digest: ContentDigest,
    pub report_digest: ContentDigest,
    pub stored_case_count: usize,
    pub caller_case_count: usize,
    pub evaluation_error_count: usize,
    pub expectation_mismatch_count: usize,
    pub results: Vec<PolicySimulationResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyShadowResult {
    pub case_id: String,
    pub active_allowed: bool,
    pub active_evaluation_error: bool,
    pub shadow_allowed: bool,
    pub shadow_evaluation_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyShadowReport {
    pub active_policy_digest: Option<ContentDigest>,
    pub shadow_policy_digest: ContentDigest,
    pub policy_epoch: u64,
    pub results: Vec<PolicyShadowResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatePolicyBundle {
    pub draft_digest: ContentDigest,
    pub simulation_digest: ContentDigest,
    pub expected_policy_epoch: u64,
    pub approval_id: String,
    pub approved_by: String,
    pub approved_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatedPolicyBundle {
    pub draft_id: String,
    pub tenant_id: String,
    pub author_id: String,
    pub digest: ContentDigest,
    pub(super) canonical_policy_json: String,
    pub simulation_digest: ContentDigest,
    pub approval_id: String,
    pub approved_by: String,
    pub policy_epoch: u64,
    pub activated_unix_ms: u64,
}
/// Durable controller state. A persistence adapter must serialize mutations
/// with compare-and-swap on the epoch/cache generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePolicyBundleState {
    pub tenant_id: String,
    pub policy_epoch: u64,
    pub decision_cache_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<ActivatedPolicyBundle>,
    #[serde(default)]
    pub emergency_denies: DenyFirstPolicy,
}
