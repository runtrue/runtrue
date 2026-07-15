pub struct CompileContext {
    pub installation_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub workflow_path: String,
    pub source_commit: String,
    pub base_commit: Option<String>,
    /// Server-derived trust for the source revision. Manual/local callers are
    /// untrusted unless a trusted planner explicitly supplies a stronger value.
    pub source_trust: ir::SourceTrust,
    pub event: Value,
    /// Authoritative digest from an authenticated, normalized SCM envelope.
    /// Local/manual callers leave this unset and bind the canonical event JSON.
    pub normalized_event_digest: Option<ContentDigest>,
    /// Trusted provider endpoint supplied by the SCM orchestration layer.
    pub scm_api_url: Option<String>,
    pub lockfile: Option<LockFile>,
    pub reusable_workflows: ReusableWorkflowSources,
    /// Integrity-validated source translation provenance supplied by the
    /// trusted planner. Native workflow compilation leaves this unset.
    pub workflow_frontend: Option<ir::WorkflowFrontendProvenance>,
    pub policy_version_ids: Vec<String>,
    pub workflow_changed: bool,
    pub expiration_boundary: Option<String>,
    pub selected_job: Option<String>,
}

impl Default for CompileContext {
    fn default() -> Self {
        Self {
            installation_id: "local".to_owned(),
            tenant_id: "local".to_owned(),
            repository_id: "local".to_owned(),
            workflow_path: ".runtrue/workflows/workflow.yaml".to_owned(),
            source_commit: "local-worktree".to_owned(),
            base_commit: None,
            source_trust: ir::SourceTrust::Untrusted,
            event: serde_json::json!({"type": "manual"}),
            normalized_event_digest: None,
            scm_api_url: None,
            lockfile: None,
            reusable_workflows: ReusableWorkflowSources::default(),
            workflow_frontend: None,
            policy_version_ids: vec!["local-default-deny-v1".to_owned()],
            workflow_changed: false,
            expiration_boundary: None,
            selected_job: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SemanticWorkflow<'a> {
    pub(crate) version: u32,
    pub(crate) name: String,
    pub(crate) triggers: &'a ast::Triggers,
    #[serde(skip_serializing_if = "strict_map_is_empty")]
    pub(crate) inputs: &'a ast::StrictMap<ast::InputDefinition>,
    #[serde(skip_serializing_if = "strict_map_is_empty")]
    pub(crate) outputs: &'a ast::StrictMap<ast::WorkflowOutputDefinition>,
    pub(crate) variables: &'a BTreeMap<String, ir::ScalarValue>,
    pub(crate) permissions: &'a ir::PermissionSet,
    pub(crate) jobs: &'a [ir::PlannedJob],
    #[serde(skip_serializing_if = "slice_is_empty")]
    pub(crate) dynamic_jobs: &'a [ir::DynamicJobTemplate],
    #[serde(skip_serializing_if = "slice_is_empty")]
    pub(crate) reusable_workflows: &'a [ReusableWorkflowIdentity],
    pub(crate) expected_parity: ir::ParityGrade,
}

pub(crate) fn slice_is_empty<T>(values: &&[T]) -> bool {
    values.is_empty()
}

pub(crate) fn strict_map_is_empty<T>(values: &&ast::StrictMap<T>) -> bool {
    values.is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReusableWorkflowIdentity {
    pub(crate) source: String,
    pub(crate) commit: String,
    pub(crate) digest: ContentDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compilation {
    pub capsule: ir::ExecutionCapsule,
    /// Canonical trigger declaration used by the event intake worker. It is
    /// part of the semantic workflow digest, but not the executable capsule.
    #[serde(default)]
    pub triggers: ast::Triggers,
    pub capsule_digest: ContentDigest,
    pub approval_subject: ApprovalSubject,
    pub approval_subject_digest: ContentDigest,
    pub risk_report: RiskReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSubject {
    pub subject_version: String,
    /// False until remote identity, policy, environment, and signature resolution exists.
    pub authorization_ready: bool,
    pub installation_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub source_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tree_digest: Option<ContentDigest>,
    pub base_commit: Option<String>,
    #[serde(default)]
    pub source_trust: ir::SourceTrust,
    pub normalized_event_digest: ContentDigest,
    pub canonical_workflow_digest: ContentDigest,
    pub execution_capsule_digest: ContentDigest,
    pub lockfile_digest: Option<ContentDigest>,
    pub resolved_action_digests: Vec<String>,
    pub resolved_image_digests: Vec<String>,
    pub reusable_workflow_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_frontend: Option<ir::WorkflowFrontendProvenance>,
    pub permission_set_digest: ContentDigest,
    pub secret_metadata_ids: Vec<String>,
    pub variable_snapshot_digest: ContentDigest,
    pub network_policy_digest: ContentDigest,
    pub cache_policy_digest: ContentDigest,
    pub artifact_policy_digest: ContentDigest,
    pub runner_profiles: Vec<RunnerApprovalProfile>,
    pub environment_ids: Vec<String>,
    pub deployment_target_digest: Option<ContentDigest>,
    pub policy_version_ids: Vec<String>,
    pub engine_compatibility_version: String,
    pub expiration_boundary: Option<String>,
}

impl ApprovalSubject {
    pub fn digest(&self) -> Result<ContentDigest, CompileError> {
        Ok(ContentDigest::sha256(canonical_bytes(self)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerApprovalProfile {
    pub os: ir::OperatingSystem,
    pub arch: ir::Architecture,
    pub isolation_floor: ir::Isolation,
    pub cpu: u16,
    pub memory_bytes: u64,
    pub storage_bytes: Option<u64>,
    pub region: Option<String>,
    pub capabilities: Vec<String>,
}
use super::{
    ast, canonical_bytes, ir, BTreeMap, CompileError, ContentDigest, LockFile,
    ReusableWorkflowSources, RiskReport, Value,
};
use serde::{Deserialize, Serialize};
