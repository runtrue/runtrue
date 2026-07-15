use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(super) const MAX_POLICY_SOURCE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_POLICIES: usize = 4096;
pub(super) const MAX_GROUPS: usize = 256;
pub(super) const MAX_IDENTIFIER_BYTES: usize = 512;
pub(super) const MAX_EMERGENCY_DENIES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CedarAction {
    ViewRepository,
    EditWorkflowSettings,
    ViewRun,
    CreateRun,
    CancelRun,
    ApproveWorkflow,
    ApprovePrivilegedRun,
    ReadSecretMetadata,
    WriteSecret,
    UseSecret,
    ReadVariable,
    WriteVariable,
    ManageRunnerPool,
    StartDebugSession,
    PromoteArtifact,
    DeployEnvironment,
    ManagePolicy,
    ReadAudit,
    ManageApiToken,
    MintOidcToken,
    BreakGlass,
}

impl CedarAction {
    pub(super) const ALL: [Self; 21] = [
        Self::ViewRepository,
        Self::EditWorkflowSettings,
        Self::ViewRun,
        Self::CreateRun,
        Self::CancelRun,
        Self::ApproveWorkflow,
        Self::ApprovePrivilegedRun,
        Self::ReadSecretMetadata,
        Self::WriteSecret,
        Self::UseSecret,
        Self::ReadVariable,
        Self::WriteVariable,
        Self::ManageRunnerPool,
        Self::StartDebugSession,
        Self::PromoteArtifact,
        Self::DeployEnvironment,
        Self::ManagePolicy,
        Self::ReadAudit,
        Self::ManageApiToken,
        Self::MintOidcToken,
        Self::BreakGlass,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ViewRepository => "ViewRepository",
            Self::EditWorkflowSettings => "EditWorkflowSettings",
            Self::ViewRun => "ViewRun",
            Self::CreateRun => "CreateRun",
            Self::CancelRun => "CancelRun",
            Self::ApproveWorkflow => "ApproveWorkflow",
            Self::ApprovePrivilegedRun => "ApprovePrivilegedRun",
            Self::ReadSecretMetadata => "ReadSecretMetadata",
            Self::WriteSecret => "WriteSecret",
            Self::UseSecret => "UseSecret",
            Self::ReadVariable => "ReadVariable",
            Self::WriteVariable => "WriteVariable",
            Self::ManageRunnerPool => "ManageRunnerPool",
            Self::StartDebugSession => "StartDebugSession",
            Self::PromoteArtifact => "PromoteArtifact",
            Self::DeployEnvironment => "DeployEnvironment",
            Self::ManagePolicy => "ManagePolicy",
            Self::ReadAudit => "ReadAudit",
            Self::ManageApiToken => "ManageApiToken",
            Self::MintOidcToken => "MintOidcToken",
            Self::BreakGlass => "BreakGlass",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CedarPrincipalKind {
    User,
    ServiceAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CedarResourceKind {
    Tenant,
    Repository,
    Workflow,
    Run,
    ApprovalRequest,
    Environment,
    Secret,
    Variable,
    RunnerPool,
    Runner,
    Artifact,
    CacheEntry,
    Policy,
    AuditLog,
    ApiToken,
    OidcGrant,
}

impl CedarResourceKind {
    pub(super) const ALL: [Self; 16] = [
        Self::Tenant,
        Self::Repository,
        Self::Workflow,
        Self::Run,
        Self::ApprovalRequest,
        Self::Environment,
        Self::Secret,
        Self::Variable,
        Self::RunnerPool,
        Self::Runner,
        Self::Artifact,
        Self::CacheEntry,
        Self::Policy,
        Self::AuditLog,
        Self::ApiToken,
        Self::OidcGrant,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "Tenant",
            Self::Repository => "Repository",
            Self::Workflow => "Workflow",
            Self::Run => "Run",
            Self::ApprovalRequest => "ApprovalRequest",
            Self::Environment => "Environment",
            Self::Secret => "Secret",
            Self::Variable => "Variable",
            Self::RunnerPool => "RunnerPool",
            Self::Runner => "Runner",
            Self::Artifact => "Artifact",
            Self::CacheEntry => "CacheEntry",
            Self::Policy => "Policy",
            Self::AuditLog => "AuditLog",
            Self::ApiToken => "ApiToken",
            Self::OidcGrant => "OidcGrant",
        }
    }
}

impl CedarPrincipalKind {
    pub(super) const fn entity_type(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::ServiceAccount => "ServiceAccount",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarPrincipal {
    pub kind: CedarPrincipalKind,
    pub id: String,
    pub tenant_id: String,
    #[serde(default)]
    pub groups: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarResource {
    pub kind: CedarResourceKind,
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_id: Option<String>,
    pub risk_score: u32,
    pub privileged: bool,
    pub untrusted: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarRequestContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauthentication_age_seconds: Option<u64>,
    #[serde(default)]
    pub break_glass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarAuthorizationRequest {
    pub principal: CedarPrincipal,
    pub action: CedarAction,
    pub resource: CedarResource,
    #[serde(default)]
    pub context: CedarRequestContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarAuthorizationDecision {
    pub allowed: bool,
    pub policy_digest: ContentDigest,
    pub determining_policy_ids: Vec<String>,
    pub evaluation_error_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_deny_id: Option<String>,
}
