use crate::AppState;
use base64ct::{Base64, Encoding as _};
use runtrue_attest::CapsuleSigningKey;
use runtrue_compiler::Compilation;
use runtrue_control_plane::{
    CapsuleApiMetadata, ControlPlane, ControlPlaneError, CreateRunRequest, DurableTask,
    DurableTaskStatus, NewJob, PreparedScmExecution, RecordScmCheckFailure, RecordScmCheckProgress,
    RecordScmFetchSnapshotReady, RepositoryRecord, ReserveScmCheckPublication,
    ReserveScmSourceFetch, ScmCheckPublicationState, ScmCheckPublishTask, ScmContinuationCommit,
    ScmContinuationContext, ScmContinuationResolution, ScmExecutionRole, ScmInstallationRecord,
    ScmProposedAnalysisRecord, ScmProposedAnalysisStatus, ScmRepositoryLinkRecord,
    ScmSourceIdentity, SignedCapsuleRecord, SourceSnapshotRecord, SourceSnapshotState,
};
#[cfg(feature = "github-actions")]
use runtrue_gha_import::GithubActionsFrontend;
use runtrue_git::{
    CredentialRequest, GitCredential, GitCredentialProvider, GitError, GitLimits, GitRepository,
    MirrorLimits, MirrorManager, MirrorMiss, MirrorSyncOutcome, OriginPolicy,
    RepositoryIdentity as GitRepositoryIdentity, SourceSnapshotLimits,
};
use runtrue_model::{normalize_relative_path, ContentDigest};
use runtrue_policy::{
    ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalRule, ApprovalStatus,
    Decision as ApprovalDecisionKind,
};
use runtrue_scheduler::SchedulingRequirements;
use runtrue_scm::{
    CheckConclusion, CheckRunRequest, CheckRunRequestedAction, CheckStatus, EventEnvelope,
    EventType, GitHubAppBroker, GitHubAppJwtProvider, GitHubError, GitHubPermission,
    GitHubPermissionLevel, GitHubProviderEndpoints, GitHubRepositoryCredential, GitHubTransport,
    GitRevision, InstallationTokenRequest, ProviderKind, WorkflowDefinitionApprovalEvidence,
    WorkflowDefinitionApprovalVerifier, WorkflowSourceError, WorkflowSourceInputs,
};
use runtrue_storage::FsCas;
use runtrue_trusted_planner::{
    ProposedAnalysisFailure, ProposedWorkflowAnalysis, ReusableWorkflowProviderError,
    ReusableWorkflowSourceProvider, TrustedPlanner, TrustedPlannerError, DEFAULT_LOCKFILE_PATH,
};
use runtrue_workflow_frontend::{WorkflowFrontendRegistry, WorkflowSourceFrontend};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

pub const DEFAULT_SCM_WORKFLOW_DIRECTORY: &str = ".runtrue/workflows";
const MAX_SCM_WORKFLOWS: usize = 64;
const SCM_TASK_KIND: &str = "scm.event";
const SCM_CONTINUATION_TASK_KIND: &str = "scm.approval.continue";
const SCM_CHECK_TASK_KIND: &str = "scm.check.publish";
const DEFAULT_POLICY_VERSION: &str = "server-default-deny-v1";
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_FAILURE_BYTES: usize = 1024;
const MAX_TASK_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_DEFINITION_DIFF_LINES_PER_SIDE: usize = 80;
const MAX_DEFINITION_DIFF_BYTES: usize = 16 * 1024;
const APPROVAL_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
#[cfg(feature = "github-actions")]
static GITHUB_ACTIONS_FRONTEND: GithubActionsFrontend = GithubActionsFrontend;
#[cfg(feature = "github-actions")]
static REGISTERED_WORKFLOW_FRONTENDS: [&'static dyn WorkflowSourceFrontend; 1] =
    [&GITHUB_ACTIONS_FRONTEND];
#[cfg(not(feature = "github-actions"))]
static REGISTERED_WORKFLOW_FRONTENDS: [&'static dyn WorkflowSourceFrontend; 0] = [];

fn workflow_frontends() -> &'static WorkflowFrontendRegistry<'static> {
    static REGISTRY: OnceLock<WorkflowFrontendRegistry<'static>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        WorkflowFrontendRegistry::new(&REGISTERED_WORKFLOW_FRONTENDS)
            .expect("compiled workflow frontend registry must be valid")
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScmWorkflowTaskPayload {
    #[serde(flatten)]
    event: EventEnvelope,
    workflow_path: String,
}

#[derive(Debug, Clone)]
pub struct ScmWorkerConfig {
    pub mirror_root: PathBuf,
    pub worker_id: String,
    pub workflow_directory: String,
    pub policy_version_ids: Vec<String>,
    pub max_attempts: u32,
    pub lease_duration: Duration,
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub poll_interval: Duration,
    pub mirror_limits: MirrorLimits,
    pub source_snapshot_limits: SourceSnapshotLimits,
    /// Exact operator-configured GitHub web/API pair. The web authority is the
    /// sole Git origin admitted by the source fetch and reusable-workflow
    /// reader; webhook/store data cannot broaden it.
    pub github_provider_endpoints: GitHubProviderEndpoints,
    /// Immutable OCI base image used for imported hosted-Linux jobs when this
    /// installation intentionally has no microVM runner.
    pub default_job_container_image: Option<String>,
}

impl ScmWorkerConfig {
    #[must_use]
    pub fn new(mirror_root: impl Into<PathBuf>, worker_id: impl Into<String>) -> Self {
        Self {
            mirror_root: mirror_root.into(),
            worker_id: worker_id.into(),
            workflow_directory: DEFAULT_SCM_WORKFLOW_DIRECTORY.to_owned(),
            policy_version_ids: vec![DEFAULT_POLICY_VERSION.to_owned()],
            max_attempts: 5,
            lease_duration: Duration::from_secs(5 * 60),
            retry_base: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
            poll_interval: Duration::from_millis(250),
            mirror_limits: MirrorLimits::default(),
            source_snapshot_limits: SourceSnapshotLimits::default(),
            github_provider_endpoints: GitHubProviderEndpoints::github_dot_com(),
            default_job_container_image: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GitHubRepositoryAccessToken {
    installation_external_id: String,
    repository_external_id: String,
    authorization_header: Zeroizing<String>,
    expires_unix_ms: u64,
    scope_digest: ContentDigest,
}

impl std::fmt::Debug for GitHubRepositoryAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubRepositoryAccessToken")
            .field("installation_external_id", &self.installation_external_id)
            .field("repository_external_id", &self.repository_external_id)
            .field("authorization_header", &"[REDACTED]")
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl GitHubRepositoryAccessToken {
    pub fn new(
        installation_external_id: impl Into<String>,
        repository_external_id: impl Into<String>,
        bearer_token: impl Into<String>,
        expires_unix_ms: u64,
    ) -> Result<Self, ScmSourceFetchError> {
        let installation_external_id = installation_external_id.into();
        let repository_external_id = repository_external_id.into();
        let bearer_token = bearer_token.into();
        let now = unix_ms().map_err(|_| ScmSourceFetchError::CredentialUnavailable)?;
        if installation_external_id.is_empty()
            || repository_external_id.is_empty()
            || bearer_token.is_empty()
            || bearer_token.len() > 16 * 1024
            || bearer_token.bytes().any(|byte| byte.is_ascii_control())
            || expires_unix_ms <= now.saturating_add(30_000)
            || expires_unix_ms > now.saturating_add(60 * 60 * 1000)
        {
            return Err(ScmSourceFetchError::CredentialUnavailable);
        }
        let scope_digest = ContentDigest::sha256(
            format!(
                "runtrue.github.repository-read-token-scope.v1\0{installation_external_id}\0{repository_external_id}\0metadata:read\0contents:read"
            )
            .as_bytes(),
        );
        let mut basic = Zeroizing::new(String::with_capacity(
            "x-access-token:".len() + bearer_token.len(),
        ));
        basic.push_str("x-access-token:");
        basic.push_str(&bearer_token);
        let encoded = Zeroizing::new(Base64::encode_string(basic.as_bytes()));
        Ok(Self {
            installation_external_id,
            repository_external_id,
            authorization_header: Zeroizing::new(format!(
                "Authorization: Basic {}",
                encoded.as_str()
            )),
            expires_unix_ms,
            scope_digest,
        })
    }

    fn from_scoped_credential(
        installation_external_id: impl Into<String>,
        repository_external_id: impl Into<String>,
        credential: GitHubRepositoryCredential,
    ) -> Result<Self, ScmSourceFetchError> {
        let installation_external_id = installation_external_id.into();
        let repository_external_id = repository_external_id.into();
        if installation_external_id.parse::<u64>().ok() != Some(credential.installation_id)
            || repository_external_id.parse::<u64>().ok() != Some(credential.repository_id)
        {
            return Err(ScmSourceFetchError::BindingMismatch);
        }
        let expires_unix_ms = credential
            .expires_at_unix_seconds
            .checked_mul(1_000)
            .ok_or(ScmSourceFetchError::CredentialUnavailable)?;
        let now = unix_ms().map_err(|_| ScmSourceFetchError::CredentialUnavailable)?;
        if expires_unix_ms <= now.saturating_add(30_000)
            || expires_unix_ms > now.saturating_add(60 * 60 * 1_000)
        {
            return Err(ScmSourceFetchError::CredentialUnavailable);
        }
        Ok(Self {
            installation_external_id,
            repository_external_id,
            authorization_header: Zeroizing::new(credential.authorization_header().to_owned()),
            expires_unix_ms,
            scope_digest: credential.scope_digest,
        })
    }
}

/// Non-exportable provider boundary. Implementations mint one repository-read
/// token just in time from the installation credential reference; neither the
/// private key nor returned token may be persisted or logged.
#[derive(Debug, Clone, Copy)]
pub struct GitHubWorkflowApprovalRequest<'a> {
    pub installation: &'a ScmInstallationRecord,
    pub repository: &'a ScmRepositoryLinkRecord,
    pub owner: &'a str,
    pub name: &'a str,
    pub actor_external_id: &'a str,
    pub actor_login: &'a str,
    pub pull_request_number: u64,
    pub expected_head_commit: &'a str,
}

pub trait GitHubInstallationTokenProvider: Send + Sync {
    fn mint_repository_read_token(
        &self,
        installation: &ScmInstallationRecord,
        repository: &ScmRepositoryLinkRecord,
        owner: &str,
        name: &str,
    ) -> Result<GitHubRepositoryAccessToken, ScmSourceFetchError>;

    fn mint_provider_token(
        &self,
        _installation: &ScmInstallationRecord,
        _repository: &ScmRepositoryLinkRecord,
        _owner: &str,
        _name: &str,
        _permissions: &std::collections::BTreeMap<GitHubPermission, GitHubPermissionLevel>,
    ) -> Result<runtrue_scm::GitHubProviderCredential, ScmSourceFetchError> {
        Err(ScmSourceFetchError::CredentialUnavailable)
    }

    fn resolve_default_branch_head(
        &self,
        _installation: &ScmInstallationRecord,
        _repository: &ScmRepositoryLinkRecord,
        _owner: &str,
        _name: &str,
        _default_branch: &str,
    ) -> Result<String, ScmSourceFetchError> {
        Err(ScmSourceFetchError::CredentialUnavailable)
    }

    fn actor_can_approve_workflow(
        &self,
        _request: GitHubWorkflowApprovalRequest<'_>,
    ) -> Result<bool, ScmSourceFetchError> {
        Err(ScmSourceFetchError::CredentialUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedScmCheck {
    pub provider_check_run_id: u64,
    pub confirmed_annotations: u32,
    pub reconciled: bool,
}

#[derive(Debug, Error)]
pub enum ScmCheckPublishError {
    #[error("SCM check binding or permission is invalid")]
    Rejected,
    #[error("SCM check provider is temporarily unavailable")]
    Unavailable,
    #[error("SCM check provider requested retry after {0} seconds")]
    RateLimited(u64),
}

pub trait GitHubCheckPublisher: Send + Sync {
    fn reconcile_or_publish(
        &self,
        installation: &ScmInstallationRecord,
        repository: &ScmRepositoryLinkRecord,
        request: &CheckRunRequest,
    ) -> Result<PublishedScmCheck, ScmCheckPublishError>;
}

/// Production adapter from a non-exportable App JWT signer and hardened API
/// transport to the exact repository-read credential used by MirrorManager.
/// One configured credential reference intentionally serves one App identity;
/// a stored installation cannot select another signer or substitute Runtrue's
/// installation id for GitHub's numeric installation id.
pub struct GitHubAppInstallationTokenProvider<T, J> {
    broker: Mutex<GitHubAppBroker<T, J>>,
    credential_reference: String,
    endpoints: GitHubProviderEndpoints,
}

impl<T, J> std::fmt::Debug for GitHubAppInstallationTokenProvider<T, J> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubAppInstallationTokenProvider")
            .field("broker", &"[REDACTED PROVIDER]")
            .field("credential_reference", &self.credential_reference)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

impl<T, J> GitHubAppInstallationTokenProvider<T, J>
where
    T: GitHubTransport,
    J: GitHubAppJwtProvider,
{
    pub fn new(
        broker: GitHubAppBroker<T, J>,
        credential_reference: impl Into<String>,
        endpoints: GitHubProviderEndpoints,
    ) -> Result<Self, ScmWorkerBuildError> {
        let credential_reference = credential_reference.into();
        if credential_reference.is_empty()
            || credential_reference.len() > MAX_COMPONENT_BYTES
            || credential_reference
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || !credential_reference.starts_with("provider://github-app/")
        {
            return Err(ScmWorkerBuildError::InvalidConfiguration(
                "invalid GitHub App credential reference",
            ));
        }
        Ok(Self {
            broker: Mutex::new(broker),
            credential_reference,
            endpoints,
        })
    }
}

impl<T, J> GitHubInstallationTokenProvider for GitHubAppInstallationTokenProvider<T, J>
where
    T: GitHubTransport + Send,
    J: GitHubAppJwtProvider + Send,
{
    fn mint_repository_read_token(
        &self,
        installation: &ScmInstallationRecord,
        repository: &ScmRepositoryLinkRecord,
        owner: &str,
        name: &str,
    ) -> Result<GitHubRepositoryAccessToken, ScmSourceFetchError> {
        if installation.provider != "github"
            || installation.status != "active"
            || repository.status != "active"
            || installation.tenant_id != repository.tenant_id
            || installation.id != repository.installation_id
            || installation.credential_reference != self.credential_reference
            || !github_read_permissions(&installation.permissions)
            || !exact_github_repository_origin(&self.endpoints, repository, owner, name)
        {
            return Err(ScmSourceFetchError::CredentialUnavailable);
        }
        let installation_id = parse_github_external_id(&installation.external_id)?;
        let repository_id = parse_github_external_id(&repository.external_repository_id)?;
        let now_unix_seconds =
            unix_ms().map_err(|_| ScmSourceFetchError::CredentialUnavailable)? / 1_000;
        let token = self
            .broker
            .lock()
            .map_err(|_| ScmSourceFetchError::CredentialUnavailable)?
            .mint_installation_token(
                InstallationTokenRequest {
                    installation_id,
                    repository_ids: vec![repository_id],
                    permissions: std::collections::BTreeMap::from([
                        (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
                        (GitHubPermission::Contents, GitHubPermissionLevel::Read),
                    ]),
                },
                now_unix_seconds,
            )
            .and_then(|token| token.into_repository_read_credential(repository_id))
            .map_err(|_| ScmSourceFetchError::CredentialUnavailable)?;
        GitHubRepositoryAccessToken::from_scoped_credential(
            &installation.external_id,
            &repository.external_repository_id,
            token,
        )
    }

    fn mint_provider_token(
        &self,
        installation: &ScmInstallationRecord,
        repository: &ScmRepositoryLinkRecord,
        owner: &str,
        name: &str,
        permissions: &std::collections::BTreeMap<GitHubPermission, GitHubPermissionLevel>,
    ) -> Result<runtrue_scm::GitHubProviderCredential, ScmSourceFetchError> {
        if installation.provider != "github"
            || installation.status != "active"
            || repository.status != "active"
            || installation.tenant_id != repository.tenant_id
            || installation.id != repository.installation_id
            || installation.credential_reference != self.credential_reference
            || !github_provider_permissions(&installation.permissions, permissions)
            || !exact_github_repository_origin(&self.endpoints, repository, owner, name)
        {
            eprintln!("SCM provider credential precondition validation failed");
            return Err(ScmSourceFetchError::CredentialUnavailable);
        }
        let installation_id = parse_github_external_id(&installation.external_id)?;
        let repository_id = parse_github_external_id(&repository.external_repository_id)?;
        let now_unix_seconds =
            unix_ms().map_err(|_| ScmSourceFetchError::CredentialUnavailable)? / 1_000;
        let token = self
            .broker
            .lock()
            .map_err(|_| ScmSourceFetchError::CredentialUnavailable)?
            .mint_installation_token(
                InstallationTokenRequest {
                    installation_id,
                    repository_ids: vec![repository_id],
                    permissions: permissions.clone(),
                },
                now_unix_seconds,
            )
            .map_err(|error| {
                eprintln!("GitHub provider token mint failed: {error}");
                ScmSourceFetchError::CredentialUnavailable
            })?;
        token
            .into_provider_credential(repository_id)
            .map_err(|error| {
                eprintln!("GitHub provider token binding failed: {error}");
                ScmSourceFetchError::CredentialUnavailable
            })
    }

    fn resolve_default_branch_head(
        &self,
        installation: &ScmInstallationRecord,
        repository: &ScmRepositoryLinkRecord,
        owner: &str,
        name: &str,
        default_branch: &str,
    ) -> Result<String, ScmSourceFetchError> {
        if installation.provider != "github"
            || installation.status != "active"
            || repository.status != "active"
            || installation.tenant_id != repository.tenant_id
            || installation.id != repository.installation_id
            || installation.credential_reference != self.credential_reference
            || !github_read_permissions(&installation.permissions)
            || !exact_github_repository_origin(&self.endpoints, repository, owner, name)
        {
            return Err(ScmSourceFetchError::CredentialUnavailable);
        }
        let installation_id = parse_github_external_id(&installation.external_id)?;
        let repository_id = parse_github_external_id(&repository.external_repository_id)?;
        let now_unix_seconds =
            unix_ms().map_err(|_| ScmSourceFetchError::CredentialUnavailable)? / 1_000;
        let mut broker = self
            .broker
            .lock()
            .map_err(|_| ScmSourceFetchError::CredentialUnavailable)?;
        let token = broker
            .mint_installation_token(
                InstallationTokenRequest {
                    installation_id,
                    repository_ids: vec![repository_id],
                    permissions: std::collections::BTreeMap::from([
                        (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
                        (GitHubPermission::Contents, GitHubPermissionLevel::Read),
                    ]),
                },
                now_unix_seconds,
            )
            .map_err(|_| ScmSourceFetchError::CredentialUnavailable)?;
        broker
            .resolve_repository_branch_head(&token, repository_id, owner, name, default_branch)
            .map_err(|error| match error {
                runtrue_scm::GitHubError::Transport => ScmSourceFetchError::Unavailable,
                _ => ScmSourceFetchError::Rejected,
            })
    }

    fn actor_can_approve_workflow(
        &self,
        request: GitHubWorkflowApprovalRequest<'_>,
    ) -> Result<bool, ScmSourceFetchError> {
        let GitHubWorkflowApprovalRequest {
            installation,
            repository,
            owner,
            name,
            actor_external_id,
            actor_login,
            pull_request_number,
            expected_head_commit,
        } = request;
        if installation.provider != "github"
            || installation.status != "active"
            || repository.status != "active"
            || installation.tenant_id != repository.tenant_id
            || installation.id != repository.installation_id
            || installation.credential_reference != self.credential_reference
            || !exact_github_repository_origin(&self.endpoints, repository, owner, name)
        {
            return Err(ScmSourceFetchError::CredentialUnavailable);
        }
        let installation_id = parse_github_external_id(&installation.external_id)?;
        let repository_id = parse_github_external_id(&repository.external_repository_id)?;
        let actor_id = parse_github_external_id(actor_external_id)?;
        let now_unix_seconds =
            unix_ms().map_err(|_| ScmSourceFetchError::CredentialUnavailable)? / 1_000;
        let mut broker = self
            .broker
            .lock()
            .map_err(|_| ScmSourceFetchError::CredentialUnavailable)?;
        let token = broker
            .mint_installation_token(
                InstallationTokenRequest {
                    installation_id,
                    repository_ids: vec![repository_id],
                    permissions: std::collections::BTreeMap::from([
                        (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
                        (GitHubPermission::PullRequests, GitHubPermissionLevel::Read),
                    ]),
                },
                now_unix_seconds,
            )
            .map_err(|_| ScmSourceFetchError::CredentialUnavailable)?;
        let permission = broker
            .repository_permission_for_user(
                &token,
                repository_id,
                owner,
                name,
                actor_id,
                actor_login,
            )
            .map_err(|error| match error {
                GitHubError::Transport => ScmSourceFetchError::Unavailable,
                _ => ScmSourceFetchError::Rejected,
            })?;
        let head = broker
            .pull_request_head(&token, repository_id, owner, name, pull_request_number)
            .map_err(|error| match error {
                GitHubError::Transport => ScmSourceFetchError::Unavailable,
                _ => ScmSourceFetchError::Rejected,
            })?;
        Ok(permission.can_approve_workflow() && head.eq_ignore_ascii_case(expected_head_commit))
    }
}

impl<T, J> GitHubCheckPublisher for GitHubAppInstallationTokenProvider<T, J>
where
    T: GitHubTransport + Send,
    J: GitHubAppJwtProvider + Send,
{
    fn reconcile_or_publish(
        &self,
        installation: &ScmInstallationRecord,
        repository: &ScmRepositoryLinkRecord,
        request: &CheckRunRequest,
    ) -> Result<PublishedScmCheck, ScmCheckPublishError> {
        if installation.provider != "github"
            || installation.status != "active"
            || repository.status != "active"
            || installation.tenant_id != repository.tenant_id
            || installation.id != repository.installation_id
            || installation.credential_reference != self.credential_reference
            || !github_check_permissions(&installation.permissions)
            || !exact_github_repository_origin(
                &self.endpoints,
                repository,
                &request.owner,
                &request.repository,
            )
        {
            return Err(ScmCheckPublishError::Rejected);
        }
        let installation_id = parse_github_external_id(&installation.external_id)
            .map_err(|_| ScmCheckPublishError::Rejected)?;
        let repository_id = parse_github_external_id(&repository.external_repository_id)
            .map_err(|_| ScmCheckPublishError::Rejected)?;
        if request.repository_id != repository_id {
            return Err(ScmCheckPublishError::Rejected);
        }
        let now_unix_seconds = unix_ms().map_err(|_| ScmCheckPublishError::Unavailable)? / 1_000;
        let mut broker = self
            .broker
            .lock()
            .map_err(|_| ScmCheckPublishError::Unavailable)?;
        let token = broker
            .mint_installation_token(
                InstallationTokenRequest {
                    installation_id,
                    repository_ids: vec![repository_id],
                    permissions: std::collections::BTreeMap::from([
                        (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
                        (GitHubPermission::Checks, GitHubPermissionLevel::Write),
                    ]),
                },
                now_unix_seconds,
            )
            .map_err(classify_check_publish_error)?;
        let reconciled = broker
            .reconcile_check_run(&token, request, now_unix_seconds)
            .map_err(classify_check_publish_error)?;
        let (published, was_reconciled) = if let Some(reconciled) = reconciled {
            (
                broker
                    .resume_check_run(&token, request, reconciled, now_unix_seconds)
                    .map_err(classify_check_publish_error)?,
                true,
            )
        } else {
            (
                broker
                    .publish_check_run(&token, request, now_unix_seconds)
                    .map_err(classify_check_publish_error)?,
                false,
            )
        };
        Ok(PublishedScmCheck {
            provider_check_run_id: published.check_run_id,
            confirmed_annotations: u32::try_from(request.annotations.len())
                .map_err(|_| ScmCheckPublishError::Rejected)?,
            reconciled: was_reconciled,
        })
    }
}

fn classify_check_publish_error(error: GitHubError) -> ScmCheckPublishError {
    match error {
        GitHubError::RateLimited {
            retry_after_seconds,
        } => ScmCheckPublishError::RateLimited(retry_after_seconds),
        GitHubError::InvalidConfiguration
        | GitHubError::InvalidInstallState
        | GitHubError::InvalidInstallation
        | GitHubError::InstallationSubstitution
        | GitHubError::InsufficientInstallationPermissions
        | GitHubError::RepositoryCatalogTooLarge
        | GitHubError::InvalidTokenScope
        | GitHubError::InvalidCheckRequest
        | GitHubError::MalformedResponse
        | GitHubError::AmbiguousCheckReconciliation
        | GitHubError::UnexpectedStatus(400 | 401 | 403 | 404 | 409 | 422) => {
            ScmCheckPublishError::Rejected
        }
        GitHubError::ResponseTooLarge
        | GitHubError::RequestTooLarge
        | GitHubError::UnexpectedStatus(_)
        | GitHubError::Transport
        | GitHubError::JwtProvider
        | GitHubError::PartialPublish { .. } => ScmCheckPublishError::Unavailable,
    }
}

fn exact_github_repository_origin(
    endpoints: &GitHubProviderEndpoints,
    repository: &ScmRepositoryLinkRecord,
    owner: &str,
    name: &str,
) -> bool {
    endpoints
        .repository_clone_url(owner, name)
        .is_ok_and(|origin| origin == repository.clone_url)
}

fn parse_github_external_id(value: &str) -> Result<u64, ScmSourceFetchError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(ScmSourceFetchError::BindingMismatch)
}

fn github_read_permissions(value: &serde_json::Value) -> bool {
    github_provider_permissions(
        value,
        &std::collections::BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Contents, GitHubPermissionLevel::Read),
        ]),
    )
}

fn github_check_permissions(value: &serde_json::Value) -> bool {
    github_provider_permissions(
        value,
        &std::collections::BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Checks, GitHubPermissionLevel::Write),
        ]),
    )
}

fn github_provider_permissions(
    installed: &serde_json::Value,
    requested: &std::collections::BTreeMap<GitHubPermission, GitHubPermissionLevel>,
) -> bool {
    let Some(installed) = installed.as_object() else {
        return false;
    };
    requested.iter().all(|(permission, required)| {
        let available = installed
            .get(permission.api_name())
            .and_then(serde_json::Value::as_str)
            .and_then(|level| match level {
                "read" => Some(GitHubPermissionLevel::Read),
                "write" => Some(GitHubPermissionLevel::Write),
                _ => None,
            });
        available.is_some_and(|available| available.satisfies(*required))
    })
}

#[derive(Debug, Clone)]
pub struct ScmSourceFetchRequest {
    pub installation: ScmInstallationRecord,
    pub repository: ScmRepositoryLinkRecord,
    pub tenant_id: String,
    pub repository_id: String,
    pub owner: String,
    pub name: String,
    pub source_commit: String,
    pub base_commit: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FetchedScmRepository {
    pub repository: GitRepository,
    pub token_scope_digest: ContentDigest,
    pub mirror_identity_digest: ContentDigest,
}

pub trait ScmSourceFetcher: Send + Sync {
    fn resolve_default_branch_head(
        &self,
        _request: &ScmSourceFetchRequest,
        _default_branch: &str,
    ) -> Result<String, ScmSourceFetchError> {
        Err(ScmSourceFetchError::Unavailable)
    }

    fn fetch(
        &self,
        request: &ScmSourceFetchRequest,
    ) -> Result<FetchedScmRepository, ScmSourceFetchError>;
}

#[derive(Debug, Error)]
pub enum ScmSourceFetchError {
    #[error("SCM installation credential is unavailable or invalid")]
    CredentialUnavailable,
    #[error("SCM source fetch binding is invalid")]
    BindingMismatch,
    #[error("SCM source fetch was unavailable within configured bounds")]
    Unavailable,
    #[error("SCM mirror rejected the authenticated origin or repository")]
    Rejected,
}

pub struct GitHubMirrorSourceFetcher {
    manager: MirrorManager,
    tokens: Arc<dyn GitHubInstallationTokenProvider>,
    endpoints: GitHubProviderEndpoints,
}

impl std::fmt::Debug for GitHubMirrorSourceFetcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubMirrorSourceFetcher")
            .field("manager", &self.manager)
            .field("tokens", &"[REDACTED PROVIDER]")
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

impl GitHubMirrorSourceFetcher {
    pub fn open(
        root: impl AsRef<Path>,
        tokens: Arc<dyn GitHubInstallationTokenProvider>,
        limits: MirrorLimits,
        endpoints: GitHubProviderEndpoints,
    ) -> Result<Self, ScmWorkerBuildError> {
        let mut policy =
            OriginPolicy::new([endpoints.provider_host().to_owned()]).map_err(|_| {
                ScmWorkerBuildError::InvalidConfiguration("invalid GitHub origin policy")
            })?;
        if endpoints.provider_port() != 443 {
            policy
                .allow_nonstandard_port(
                    endpoints.provider_host().to_owned(),
                    endpoints.provider_port(),
                )
                .map_err(|_| {
                    ScmWorkerBuildError::InvalidConfiguration("invalid GitHub origin port")
                })?;
        }
        let manager =
            MirrorManager::open(root, policy, limits).map_err(ScmWorkerBuildError::Git)?;
        Ok(Self {
            manager,
            tokens,
            endpoints,
        })
    }
}

struct ExactGitCredential {
    identity: GitRepositoryIdentity,
    origin: String,
    token: GitHubRepositoryAccessToken,
}

impl GitCredentialProvider for ExactGitCredential {
    fn credential(&self, request: &CredentialRequest) -> Result<GitCredential, GitError> {
        if request.identity != self.identity
            || request.origin.as_str() != self.origin
            || !request.repository_read_only
        {
            return Err(GitError::InvalidCredential);
        }
        GitCredential::new(
            self.token.authorization_header.as_str().to_owned(),
            self.token.expires_unix_ms,
        )
    }
}

impl ScmSourceFetcher for GitHubMirrorSourceFetcher {
    fn resolve_default_branch_head(
        &self,
        request: &ScmSourceFetchRequest,
        default_branch: &str,
    ) -> Result<String, ScmSourceFetchError> {
        if request.installation.tenant_id != request.tenant_id
            || request.repository.tenant_id != request.tenant_id
            || request.repository.repository_id != request.repository_id
            || request.repository.installation_id != request.installation.id
            || request.installation.provider != "github"
        {
            return Err(ScmSourceFetchError::BindingMismatch);
        }
        self.tokens.resolve_default_branch_head(
            &request.installation,
            &request.repository,
            &request.owner,
            &request.name,
            default_branch,
        )
    }

    fn fetch(
        &self,
        request: &ScmSourceFetchRequest,
    ) -> Result<FetchedScmRepository, ScmSourceFetchError> {
        if request.installation.tenant_id != request.tenant_id
            || request.repository.tenant_id != request.tenant_id
            || request.repository.repository_id != request.repository_id
            || request.repository.installation_id != request.installation.id
            || request.installation.provider != "github"
        {
            return Err(ScmSourceFetchError::BindingMismatch);
        }
        let expected_origin = self
            .endpoints
            .repository_clone_url(&request.owner, &request.name)
            .map_err(|_| ScmSourceFetchError::BindingMismatch)?;
        if request.repository.clone_url != expected_origin {
            return Err(ScmSourceFetchError::BindingMismatch);
        }
        let token = self.tokens.mint_repository_read_token(
            &request.installation,
            &request.repository,
            &request.owner,
            &request.name,
        )?;
        if token.installation_external_id != request.installation.external_id
            || token.repository_external_id != request.repository.external_repository_id
        {
            return Err(ScmSourceFetchError::BindingMismatch);
        }
        let identity = GitRepositoryIdentity::new(&request.tenant_id, &request.repository_id)
            .map_err(|_| ScmSourceFetchError::BindingMismatch)?;
        let credential = ExactGitCredential {
            identity: identity.clone(),
            origin: request.repository.clone_url.clone(),
            token,
        };
        let mut commits = vec![request.source_commit.clone()];
        if let Some(base) = &request.base_commit {
            commits.push(base.clone());
        }
        commits.sort();
        commits.dedup();
        match self.manager.sync(
            &identity,
            &request.repository.clone_url,
            &commits,
            &credential,
        ) {
            Ok(MirrorSyncOutcome::Ready(handle)) => Ok(FetchedScmRepository {
                repository: handle.repository().clone(),
                token_scope_digest: credential.token.scope_digest.clone(),
                mirror_identity_digest: handle.identity_digest().clone(),
            }),
            Ok(MirrorSyncOutcome::Miss(
                MirrorMiss::WriterTimeout | MirrorMiss::FetchUnavailable,
            )) => Err(ScmSourceFetchError::Unavailable),
            Ok(MirrorSyncOutcome::Miss(_)) | Err(_) => Err(ScmSourceFetchError::Rejected),
        }
    }
}

struct PreparedEventSource {
    repository: EventGitRepository,
    source_snapshot: Option<SourceSnapshotRecord>,
    fetch_id: Option<String>,
}

enum EventGitRepository {
    Legacy(SecureGitRepository),
    Fetched {
        repository: GitRepository,
        requested_commits: Vec<String>,
    },
}

impl EventGitRepository {
    fn repository(&self) -> &GitRepository {
        match self {
            Self::Legacy(repository) => repository.repository(),
            Self::Fetched { repository, .. } => repository,
        }
    }

    fn revalidate(&self) -> Result<(), ()> {
        match self {
            Self::Legacy(repository) => repository.revalidate().map_err(|_| ()),
            Self::Fetched {
                repository,
                requested_commits,
            } => requested_commits.iter().try_for_each(|commit| {
                match repository.verify_commit(commit) {
                    Ok(actual) if actual == *commit => Ok(()),
                    Ok(_) | Err(_) => Err(()),
                }
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScmWorkerTick {
    Idle,
    PausedSafeMode,
    Completed {
        task_id: String,
        run_id: Option<String>,
        replayed: bool,
    },
    Retried {
        task_id: String,
        attempt: u32,
        retry_at_unix_ms: u64,
    },
    Failed {
        task_id: String,
        attempts: u32,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScmWorkerMetricsSnapshot {
    pub source_fetch_attempts: u64,
    pub source_fetch_rejections: u64,
    pub source_snapshots_committed: u64,
    pub source_fetch_replays: u64,
    pub check_publish_attempts: u64,
    pub checks_published: u64,
    pub check_reconciliations: u64,
    pub check_rate_limits: u64,
    pub task_retries: u64,
    pub task_terminal_failures: u64,
}

#[derive(Debug, Default)]
struct ScmWorkerMetrics {
    source_fetch_attempts: AtomicU64,
    source_fetch_rejections: AtomicU64,
    source_snapshots_committed: AtomicU64,
    source_fetch_replays: AtomicU64,
    check_publish_attempts: AtomicU64,
    checks_published: AtomicU64,
    check_reconciliations: AtomicU64,
    check_rate_limits: AtomicU64,
    task_retries: AtomicU64,
    task_terminal_failures: AtomicU64,
}

impl ScmWorkerMetrics {
    fn snapshot(&self) -> ScmWorkerMetricsSnapshot {
        ScmWorkerMetricsSnapshot {
            source_fetch_attempts: self.source_fetch_attempts.load(Ordering::Relaxed),
            source_fetch_rejections: self.source_fetch_rejections.load(Ordering::Relaxed),
            source_snapshots_committed: self.source_snapshots_committed.load(Ordering::Relaxed),
            source_fetch_replays: self.source_fetch_replays.load(Ordering::Relaxed),
            check_publish_attempts: self.check_publish_attempts.load(Ordering::Relaxed),
            checks_published: self.checks_published.load(Ordering::Relaxed),
            check_reconciliations: self.check_reconciliations.load(Ordering::Relaxed),
            check_rate_limits: self.check_rate_limits.load(Ordering::Relaxed),
            task_retries: self.task_retries.load(Ordering::Relaxed),
            task_terminal_failures: self.task_terminal_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Error)]
pub enum ScmWorkerBuildError {
    #[error("SCM worker configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("Git mirror root is unsafe: {0}")]
    Mirror(#[from] MirrorPathError),
    #[error("Git mirror manager rejected configuration: {0}")]
    Git(#[source] GitError),
    #[error("configured SCM source fetching requires the runner data-plane CAS")]
    MissingSourceCas,
}

#[derive(Debug, Error)]
pub enum ScmWorkerError {
    #[error("control-plane SCM worker operation failed: {0}")]
    ControlPlane(#[from] ControlPlaneError),
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Clone)]
pub struct ScmTaskWorker {
    control_plane: Arc<ControlPlane>,
    signing_key: Arc<CapsuleSigningKey>,
    mirror_root: Option<SecureMirrorRoot>,
    source_fetcher: Option<Arc<dyn ScmSourceFetcher>>,
    check_publisher: Option<Arc<dyn GitHubCheckPublisher>>,
    approval_authorizer: Option<Arc<dyn GitHubInstallationTokenProvider>>,
    source_cas: Option<FsCas>,
    config: ScmWorkerConfig,
    metrics: Arc<ScmWorkerMetrics>,
}

impl std::fmt::Debug for ScmTaskWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScmTaskWorker")
            .field("mirror_root", &self.mirror_root)
            .field(
                "source_fetcher",
                &self.source_fetcher.as_ref().map(|_| "configured"),
            )
            .field(
                "source_cas",
                &self.source_cas.as_ref().map(|_| "configured"),
            )
            .field(
                "check_publisher",
                &self.check_publisher.as_ref().map(|_| "configured"),
            )
            .field(
                "approval_authorizer",
                &self.approval_authorizer.as_ref().map(|_| "configured"),
            )
            .field("config", &self.config)
            .field("signing_key", &"[REDACTED]")
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

impl AppState {
    pub fn scm_task_worker(
        &self,
        config: ScmWorkerConfig,
    ) -> Result<ScmTaskWorker, ScmWorkerBuildError> {
        ScmTaskWorker::new(
            Arc::clone(&self.control_plane),
            Arc::clone(&self.capsule_signing_key),
            config,
            None,
            None,
        )
    }

    pub fn scm_task_worker_with_github_fetch(
        &self,
        config: ScmWorkerConfig,
        tokens: Arc<dyn GitHubInstallationTokenProvider>,
    ) -> Result<ScmTaskWorker, ScmWorkerBuildError> {
        let approval_authorizer = Arc::clone(&tokens);
        let fetcher = Arc::new(GitHubMirrorSourceFetcher::open(
            &config.mirror_root,
            tokens,
            config.mirror_limits,
            config.github_provider_endpoints.clone(),
        )?);
        let mut worker = self.scm_task_worker_with_source_fetcher(config, fetcher)?;
        worker.approval_authorizer = Some(approval_authorizer);
        Ok(worker)
    }

    pub fn scm_task_worker_with_github_app<P>(
        &self,
        config: ScmWorkerConfig,
        provider: Arc<P>,
    ) -> Result<ScmTaskWorker, ScmWorkerBuildError>
    where
        P: GitHubInstallationTokenProvider + GitHubCheckPublisher + 'static,
    {
        let tokens: Arc<dyn GitHubInstallationTokenProvider> = provider.clone();
        let approval_authorizer = Arc::clone(&tokens);
        let publisher: Arc<dyn GitHubCheckPublisher> = provider;
        let fetcher = Arc::new(GitHubMirrorSourceFetcher::open(
            &config.mirror_root,
            tokens,
            config.mirror_limits,
            config.github_provider_endpoints.clone(),
        )?);
        let mut worker = self.scm_task_worker_with_source_fetcher(config, fetcher)?;
        worker.check_publisher = Some(publisher);
        worker.approval_authorizer = Some(approval_authorizer);
        Ok(worker)
    }

    #[doc(hidden)]
    pub fn scm_task_worker_with_source_fetcher(
        &self,
        config: ScmWorkerConfig,
        fetcher: Arc<dyn ScmSourceFetcher>,
    ) -> Result<ScmTaskWorker, ScmWorkerBuildError> {
        ScmTaskWorker::new(
            Arc::clone(&self.control_plane),
            Arc::clone(&self.capsule_signing_key),
            config,
            Some(fetcher),
            self.runner_source_cas(),
        )
    }

    #[doc(hidden)]
    pub fn scm_task_worker_with_adapters(
        &self,
        config: ScmWorkerConfig,
        fetcher: Arc<dyn ScmSourceFetcher>,
        publisher: Arc<dyn GitHubCheckPublisher>,
    ) -> Result<ScmTaskWorker, ScmWorkerBuildError> {
        let mut worker = self.scm_task_worker_with_source_fetcher(config, fetcher)?;
        worker.check_publisher = Some(publisher);
        Ok(worker)
    }
}

impl ScmTaskWorker {
    fn new(
        control_plane: Arc<ControlPlane>,
        signing_key: Arc<CapsuleSigningKey>,
        config: ScmWorkerConfig,
        source_fetcher: Option<Arc<dyn ScmSourceFetcher>>,
        source_cas: Option<FsCas>,
    ) -> Result<Self, ScmWorkerBuildError> {
        validate_config(&config)?;
        if source_fetcher.is_some() && source_cas.is_none() {
            return Err(ScmWorkerBuildError::MissingSourceCas);
        }
        let mirror_root = source_fetcher
            .is_none()
            .then(|| SecureMirrorRoot::open(&config.mirror_root))
            .transpose()?;
        Ok(Self {
            control_plane,
            signing_key,
            mirror_root,
            source_fetcher,
            check_publisher: None,
            approval_authorizer: None,
            source_cas,
            config,
            metrics: Arc::new(ScmWorkerMetrics::default()),
        })
    }

    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        self.config.poll_interval
    }

    #[must_use]
    pub fn metrics(&self) -> ScmWorkerMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Process at most one pending SCM task using the current wall clock.
    pub fn process_once(&self) -> Result<ScmWorkerTick, ScmWorkerError> {
        let claim_now = unix_ms()?;
        self.process_once_with_clock(claim_now, unix_ms)
    }

    /// Deterministic single-tick entry point for integration tests and
    /// embedders with an externally controlled clock.
    pub fn process_once_at(&self, now_unix_ms: u64) -> Result<ScmWorkerTick, ScmWorkerError> {
        self.process_once_with_clock(now_unix_ms, || Ok(now_unix_ms))
    }

    fn process_once_with_clock(
        &self,
        claim_now: u64,
        finish_clock: impl Fn() -> Result<u64, ScmWorkerError>,
    ) -> Result<ScmWorkerTick, ScmWorkerError> {
        if self.control_plane.recovery_state()?.safe_mode {
            return Ok(ScmWorkerTick::PausedSafeMode);
        }
        let lease_ms = duration_ms(self.config.lease_duration)?;
        let check_task = if self.check_publisher.is_some() {
            self.control_plane.claim_task_by_kind(
                &self.config.worker_id,
                SCM_CHECK_TASK_KIND,
                claim_now,
                lease_ms,
            )?
        } else {
            None
        };
        let task = if let Some(task) = check_task {
            task
        } else if let Some(task) = self.control_plane.claim_task_by_kind(
            &self.config.worker_id,
            SCM_CONTINUATION_TASK_KIND,
            claim_now,
            lease_ms,
        )? {
            task
        } else if let Some(task) = self.control_plane.claim_task_by_kind(
            &self.config.worker_id,
            SCM_TASK_KIND,
            claim_now,
            lease_ms,
        )? {
            task
        } else {
            return Ok(ScmWorkerTick::Idle);
        };

        let result = match task.kind.as_str() {
            SCM_CHECK_TASK_KIND => self.publish_check_and_commit(&task, &finish_clock),
            SCM_TASK_KIND => self.prepare_event_and_commit(&task, &finish_clock),
            SCM_CONTINUATION_TASK_KIND => {
                self.prepare_continuation_and_commit(&task, &finish_clock)
            }
            _ => Err(TaskFailure::terminal("claimed an unsupported SCM task kind").into()),
        };
        match result {
            Ok(completed) => Ok(completed),
            Err(ProcessError::Task(failure)) => {
                self.record_failure(&task, failure, finish_clock()?)
            }
            Err(ProcessError::Worker(error)) => Err(error),
        }
    }

    fn publish_check_and_commit<F>(
        &self,
        task: &DurableTask,
        finish_clock: &F,
    ) -> Result<ScmWorkerTick, ProcessError>
    where
        F: Fn() -> Result<u64, ScmWorkerError>,
    {
        let encoded = serde_json::to_vec(&task.payload)
            .map_err(|_| TaskFailure::terminal("invalid SCM check task payload"))?;
        if encoded.len() > MAX_TASK_PAYLOAD_BYTES {
            return Err(TaskFailure::terminal("SCM check task payload is oversized").into());
        }
        let payload: ScmCheckPublishTask = serde_json::from_slice(&encoded)
            .map_err(|_| TaskFailure::terminal("invalid SCM check task payload"))?;
        let (repository, installation, repository_link) = self
            .control_plane
            .github_repository_for_event(
                &payload.installation_external_id,
                &payload.external_repository_id,
                &payload.owner,
                &payload.repository,
            )
            .map_err(TaskFailure::from_repository_lookup)?;
        if repository.id != payload.repository_id
            || repository.tenant_id != payload.tenant_id
            || installation.id != payload.installation_id
            || repository_link.repository_id != payload.repository_id
            || repository_link.external_repository_id != payload.external_repository_id
        {
            return Err(TaskFailure::terminal("SCM check repository binding changed").into());
        }
        let status = match payload.status.as_str() {
            "queued" => CheckStatus::Queued,
            "in_progress" => CheckStatus::InProgress,
            "completed" => CheckStatus::Completed,
            _ => return Err(TaskFailure::terminal("invalid SCM check status").into()),
        };
        let conclusion = payload
            .conclusion
            .as_deref()
            .map(|conclusion| match conclusion {
                "action_required" => Ok(CheckConclusion::ActionRequired),
                "cancelled" => Ok(CheckConclusion::Cancelled),
                "failure" => Ok(CheckConclusion::Failure),
                "neutral" => Ok(CheckConclusion::Neutral),
                "success" => Ok(CheckConclusion::Success),
                "skipped" => Ok(CheckConclusion::Skipped),
                "timed_out" => Ok(CheckConclusion::TimedOut),
                _ => Err(TaskFailure::terminal("invalid SCM check conclusion")),
            })
            .transpose()?;
        let repository_id = parse_github_external_id(&payload.external_repository_id)
            .map_err(|_| TaskFailure::terminal("invalid SCM provider repository id"))?;
        let request = CheckRunRequest {
            repository_id,
            owner: payload.owner.clone(),
            repository: payload.repository.clone(),
            name: payload.check_name.clone(),
            head_sha: payload.commit_sha.clone(),
            details_url: None,
            external_id: payload.external_id.clone(),
            status,
            conclusion,
            title: payload.title.clone(),
            summary: payload.summary.clone(),
            render_markdown: payload.render_markdown,
            actions: payload
                .actions
                .iter()
                .map(|action| CheckRunRequestedAction {
                    label: action.label.clone(),
                    description: action.description.clone(),
                    identifier: action.identifier.clone(),
                })
                .collect(),
            trusted_base_workflow: payload.trusted_base_workflow,
            annotations: Vec::new(),
        };
        let request_digest = ContentDigest::sha256(&encoded);
        let begin_now = finish_clock()?;
        let reservation = self
            .control_plane
            .reserve_scm_check_publication(&ReserveScmCheckPublication {
                id: payload.publication_id.clone(),
                tenant_id: payload.tenant_id.clone(),
                repository_id: payload.repository_id.clone(),
                installation_id: payload.installation_id.clone(),
                run_id: payload.run_id.clone(),
                task_id: task.id.clone(),
                worker_id: self.config.worker_id.clone(),
                commit_sha: payload.commit_sha.clone(),
                logical_name: payload.logical_name.clone(),
                external_id: payload.external_id.clone(),
                request_digest,
                annotation_count: 0,
                now_unix_ms: begin_now,
            })
            .map_err(TaskFailure::control)?;
        self.metrics
            .check_publish_attempts
            .fetch_add(1, Ordering::Relaxed);
        if reservation.value.state == ScmCheckPublicationState::Published {
            self.control_plane
                .complete_task(&task.id, &self.config.worker_id, begin_now)
                .map_err(TaskFailure::control)?;
            self.metrics
                .check_reconciliations
                .fetch_add(1, Ordering::Relaxed);
            return Ok(ScmWorkerTick::Completed {
                task_id: task.id.clone(),
                run_id: Some(payload.run_id),
                replayed: true,
            });
        }
        if reservation.value.state == ScmCheckPublicationState::Failed {
            return Err(TaskFailure::terminal("SCM check publication is terminally failed").into());
        }
        let publisher = self
            .check_publisher
            .as_ref()
            .ok_or_else(|| TaskFailure::terminal("SCM check publisher is not configured"))?;
        let published =
            match publisher.reconcile_or_publish(&installation, &repository_link, &request) {
                Ok(published) => published,
                Err(error) => {
                    let (error_code, failure) = match error {
                        ScmCheckPublishError::Rejected => (
                            "provider-rejected",
                            TaskFailure::terminal("SCM check provider rejected the exact binding"),
                        ),
                        ScmCheckPublishError::Unavailable => (
                            "provider-unavailable",
                            TaskFailure::retryable("SCM check provider is temporarily unavailable"),
                        ),
                        ScmCheckPublishError::RateLimited(seconds) => {
                            self.metrics
                                .check_rate_limits
                                .fetch_add(1, Ordering::Relaxed);
                            (
                                "provider-rate-limited",
                                TaskFailure::rate_limited(
                                    "SCM check provider rate limited publication",
                                    seconds,
                                ),
                            )
                        }
                    };
                    let terminal = !failure.retryable || task.attempts >= self.config.max_attempts;
                    self.control_plane
                        .record_scm_check_failure(&RecordScmCheckFailure {
                            tenant_id: payload.tenant_id.clone(),
                            publication_id: payload.publication_id.clone(),
                            task_id: task.id.clone(),
                            worker_id: self.config.worker_id.clone(),
                            error_code: error_code.to_owned(),
                            terminal,
                            now_unix_ms: finish_clock()?,
                        })
                        .map_err(TaskFailure::control)?;
                    return Err(failure.into());
                }
            };
        let finish_now = finish_clock()?;
        self.control_plane
            .record_scm_check_progress(&RecordScmCheckProgress {
                tenant_id: payload.tenant_id.clone(),
                publication_id: payload.publication_id.clone(),
                task_id: task.id.clone(),
                worker_id: self.config.worker_id.clone(),
                provider_check_run_id: published.provider_check_run_id,
                confirmed_annotations: published.confirmed_annotations,
                now_unix_ms: finish_now,
            })
            .map_err(TaskFailure::control)?;
        self.control_plane
            .mark_scm_check_published(
                &payload.tenant_id,
                &payload.publication_id,
                &task.id,
                &self.config.worker_id,
                finish_now,
            )
            .map_err(TaskFailure::control)?;
        self.control_plane
            .complete_task(&task.id, &self.config.worker_id, finish_now)
            .map_err(TaskFailure::control)?;
        self.metrics
            .checks_published
            .fetch_add(1, Ordering::Relaxed);
        if published.reconciled {
            self.metrics
                .check_reconciliations
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(ScmWorkerTick::Completed {
            task_id: task.id.clone(),
            run_id: Some(payload.run_id),
            replayed: published.reconciled || reservation.replayed,
        })
    }

    fn execution_revision(
        &self,
        event: &EventEnvelope,
        repository: &RepositoryRecord,
        installation: Option<&ScmInstallationRecord>,
        repository_link: Option<&ScmRepositoryLinkRecord>,
    ) -> Result<GitRevision, ProcessError> {
        if !matches!(
            event.event_type,
            EventType::IssueComment { .. } | EventType::CheckRun { .. }
        ) {
            return Ok(event.source.clone());
        }
        let identity = StableIdentity::new(event, repository);
        let fetch_id = identity.id("scm-fetch", b"source-fetch", b"");
        match self
            .control_plane
            .scm_source_fetch(&repository.tenant_id, &fetch_id)
        {
            Ok(existing) => {
                if existing.repository_id != repository.id
                    || existing.normalized_event_digest != event.normalized_digest
                {
                    return Err(TaskFailure::terminal(
                        "durable default-branch resolution identity changed",
                    )
                    .into());
                }
                return Ok(GitRevision {
                    commit: existing.source_commit,
                    ref_name: Some(format!("refs/heads/{}", repository.default_branch)),
                    repository_full_name: Some(event.repository.full_name.clone()),
                });
            }
            Err(ControlPlaneError::NotFound { .. }) => {}
            Err(error) => return Err(TaskFailure::control(error).into()),
        }
        let fetcher = self.source_fetcher.as_ref().ok_or_else(|| {
            TaskFailure::terminal("trusted default-branch resolution is not configured")
        })?;
        let installation = installation
            .ok_or_else(|| TaskFailure::terminal("SCM installation binding is missing"))?;
        let repository_link = repository_link
            .ok_or_else(|| TaskFailure::terminal("SCM repository binding is missing"))?;
        let commit = fetcher
            .resolve_default_branch_head(
                &ScmSourceFetchRequest {
                    installation: installation.clone(),
                    repository: repository_link.clone(),
                    tenant_id: repository.tenant_id.clone(),
                    repository_id: repository.id.clone(),
                    owner: repository.owner.clone(),
                    name: repository.name.clone(),
                    source_commit: event.source.commit.clone(),
                    base_commit: None,
                },
                &repository.default_branch,
            )
            .map_err(TaskFailure::from_source_fetch)?;
        Ok(GitRevision {
            commit,
            ref_name: Some(format!("refs/heads/{}", repository.default_branch)),
            repository_full_name: Some(event.repository.full_name.clone()),
        })
    }

    fn handle_proposed_workflow_action<F>(
        &self,
        task: &DurableTask,
        event: &EventEnvelope,
        repository: &RepositoryRecord,
        installation: Option<&ScmInstallationRecord>,
        repository_link: Option<&ScmRepositoryLinkRecord>,
        finish_clock: &F,
    ) -> Result<Option<ScmWorkerTick>, ProcessError>
    where
        F: Fn() -> Result<u64, ScmWorkerError>,
    {
        if !matches!(
            event.event_type,
            EventType::CheckRun {
                action: runtrue_scm::CheckRunEventAction::RequestedAction
            }
        ) {
            return Ok(None);
        }
        let check = event
            .check_run
            .as_ref()
            .ok_or_else(|| TaskFailure::terminal("requested check action has no check run"))?;
        let identifier = check
            .requested_action_identifier
            .as_deref()
            .ok_or_else(|| TaskFailure::terminal("requested check action has no identifier"))?;
        let decision = match identifier {
            "approve_proposed" => ApprovalDecisionKind::Approve,
            "reject_proposed" => ApprovalDecisionKind::Deny,
            _ => {
                return Err(
                    TaskFailure::terminal("requested check action is not owned by Runtrue").into(),
                )
            }
        };
        if event.actor.is_bot || check.pull_requests.len() != 1 {
            return Err(TaskFailure::terminal(
                "proposed workflow action requires one PR and a human actor",
            )
            .into());
        }
        let installation = installation
            .ok_or_else(|| TaskFailure::terminal("SCM installation binding is missing"))?;
        let repository_link = repository_link
            .ok_or_else(|| TaskFailure::terminal("SCM repository binding is missing"))?;
        let publication = self
            .control_plane
            .scm_check_publication_by_provider_run(
                &repository.tenant_id,
                &repository.id,
                &installation.id,
                check.check_run_id,
            )
            .map_err(TaskFailure::control)?;
        if publication.state != ScmCheckPublicationState::Published
            || !publication.logical_name.starts_with("proposed-workflow:")
        {
            return Err(TaskFailure::terminal(
                "requested check action is not a published proposed-workflow check",
            )
            .into());
        }
        let check_task = self
            .control_plane
            .task(&publication.task_id)
            .map_err(TaskFailure::control)?;
        let payload: ScmCheckPublishTask = serde_json::from_value(check_task.payload)
            .map_err(|_| TaskFailure::terminal("proposed-workflow check payload is invalid"))?;
        if payload.commit_sha != publication.commit_sha
            || payload.logical_name != publication.logical_name
            || !payload
                .actions
                .iter()
                .any(|action| action.identifier == identifier)
        {
            return Err(TaskFailure::terminal(
                "requested check action does not match its durable projection",
            )
            .into());
        }
        let approval_id = publication
            .logical_name
            .strip_prefix("proposed-workflow:")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TaskFailure::terminal("proposed-workflow approval id is invalid"))?;
        let approval = self
            .control_plane
            .approval_request(approval_id)
            .map_err(TaskFailure::control)?;
        if approval.kind != ApprovalKind::WorkflowDefinition
            || payload.external_id != format!("runtrue:proposed-workflow:{approval_id}")
        {
            return Err(
                TaskFailure::terminal("proposed-workflow approval binding is invalid").into(),
            );
        }
        let authorizer = self.approval_authorizer.as_ref().ok_or_else(|| {
            TaskFailure::terminal("GitHub workflow approval authorization is not configured")
        })?;
        let authorized = authorizer
            .actor_can_approve_workflow(GitHubWorkflowApprovalRequest {
                installation,
                repository: repository_link,
                owner: &repository.owner,
                name: &repository.name,
                actor_external_id: &event.actor.external_id,
                actor_login: &event.actor.login,
                pull_request_number: check.pull_requests[0].number,
                expected_head_commit: &publication.commit_sha,
            })
            .map_err(|error| match error {
                ScmSourceFetchError::Unavailable => {
                    TaskFailure::retryable("GitHub actor permission lookup is unavailable")
                }
                _ => TaskFailure::terminal(
                    "GitHub actor or current pull-request state is not authorized",
                ),
            })?;
        if !authorized {
            return Err(TaskFailure::terminal(
                "GitHub actor lacks write permission for workflow approval",
            )
            .into());
        }
        let finish_now = finish_clock()?;
        let idempotency_key = format!("github-check-action:{}", event.normalized_digest);
        let decision_result = self
            .control_plane
            .decide_approval_idempotent(
                &idempotency_key,
                approval_id,
                ApprovalDecision {
                    actor_id: "github-repository-writer".to_owned(),
                    decision,
                    reason: format!(
                        "GitHub user {} ({}) selected `{identifier}` on check run {}",
                        event.actor.login, event.actor.external_id, check.check_run_id
                    ),
                    rule_id: approval.rule.id.clone(),
                    subject_digest: approval.subject_digest.clone(),
                    decided_unix_ms: finish_now,
                },
                finish_now,
            )
            .map_err(TaskFailure::control)?;
        let approved = decision_result.value.status == ApprovalStatus::Approved;
        let revision = ContentDigest::sha256(format!(
            "{}\0{}\0{}",
            publication.id, identifier, event.normalized_digest
        ));
        let suffix = revision
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(revision.as_str());
        let mut updated_payload = payload;
        updated_payload.publication_id = format!("scm-check-{suffix}");
        updated_payload.status = "completed".to_owned();
        updated_payload.conclusion = Some(if approved { "success" } else { "neutral" }.to_owned());
        updated_payload.title = if approved {
            "Proposed workflow approved and queued".to_owned()
        } else {
            "Proposed workflow rejected".to_owned()
        };
        updated_payload.summary = format!(
            "### {}\n\n| | |\n|---|---|\n| **Commit** | `{}` |\n| **Approval subject** | `{}` |\n| **Decision by** | `{}` |\n\n{}",
            if approved {
                "Proposed workflow approved"
            } else {
                "Proposed workflow rejected"
            },
            publication.commit_sha,
            approval.subject_digest,
            event.actor.login,
            if approved {
                "The exact proposed workflow has been queued. Its jobs publish separate `(proposed)` checks."
            } else {
                "The proposed workflow will not run."
            }
        );
        updated_payload.actions.clear();
        self.control_plane
            .enqueue_task(&DurableTask {
                id: format!("scm-check-task-{suffix}"),
                kind: SCM_CHECK_TASK_KIND.to_owned(),
                payload: serde_json::to_value(updated_payload).map_err(|_| {
                    TaskFailure::terminal("proposed-workflow check update is invalid")
                })?,
                status: DurableTaskStatus::Pending,
                available_unix_ms: finish_now,
                attempts: 0,
                lease_owner: None,
                lease_expires_unix_ms: None,
                last_error: None,
                created_unix_ms: finish_now,
                completed_unix_ms: None,
            })
            .map_err(TaskFailure::control)?;
        self.control_plane
            .complete_task(&task.id, &self.config.worker_id, finish_now)
            .map_err(TaskFailure::control)?;
        Ok(Some(ScmWorkerTick::Completed {
            task_id: task.id.clone(),
            run_id: None,
            replayed: false,
        }))
    }

    fn prepare_event_source(
        &self,
        task: &DurableTask,
        event: &EventEnvelope,
        execution_revision: &GitRevision,
        repository: &RepositoryRecord,
        installation: Option<ScmInstallationRecord>,
        repository_link: Option<ScmRepositoryLinkRecord>,
    ) -> Result<PreparedEventSource, ProcessError> {
        let Some(fetcher) = &self.source_fetcher else {
            let git_repository = self
                .mirror_root
                .as_ref()
                .ok_or_else(|| TaskFailure::terminal("SCM mirror source is not configured"))?
                .open_repository(&repository.owner, &repository.name)
                .map_err(|_| {
                    TaskFailure::retryable("Git mirror repository is unavailable or unsafe")
                })?;
            return Ok(PreparedEventSource {
                repository: EventGitRepository::Legacy(git_repository),
                source_snapshot: None,
                fetch_id: None,
            });
        };
        let installation = installation
            .ok_or_else(|| TaskFailure::terminal("SCM installation binding is missing"))?;
        let repository_link = repository_link
            .ok_or_else(|| TaskFailure::terminal("SCM repository binding is missing"))?;
        let cas = self
            .source_cas
            .as_ref()
            .ok_or_else(|| TaskFailure::terminal("SCM source CAS is not configured"))?;
        let identity = StableIdentity::new(event, repository);
        let fetch_id = identity.id("scm-fetch", b"source-fetch", b"");
        let reservation = self
            .control_plane
            .reserve_scm_source_fetch(&ReserveScmSourceFetch {
                id: fetch_id.clone(),
                tenant_id: repository.tenant_id.clone(),
                repository_id: repository.id.clone(),
                installation_id: installation.id.clone(),
                origin_task_id: task.id.clone(),
                normalized_event_digest: event.normalized_digest.clone(),
                source_commit: execution_revision.commit.clone(),
                base_commit: event.base.as_ref().map(|base| base.commit.clone()),
                origin_digest: ContentDigest::sha256(repository_link.clone_url.as_bytes()),
                now_unix_ms: task.created_unix_ms,
            })
            .map_err(TaskFailure::control)?;
        self.metrics
            .source_fetch_attempts
            .fetch_add(1, Ordering::Relaxed);
        if reservation.replayed {
            self.metrics
                .source_fetch_replays
                .fetch_add(1, Ordering::Relaxed);
        }
        let fetched = match fetcher.fetch(&ScmSourceFetchRequest {
            installation,
            repository: repository_link,
            tenant_id: repository.tenant_id.clone(),
            repository_id: repository.id.clone(),
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            source_commit: execution_revision.commit.clone(),
            base_commit: event.base.as_ref().map(|base| base.commit.clone()),
        }) {
            Ok(fetched) => fetched,
            Err(error) => {
                if matches!(
                    error,
                    ScmSourceFetchError::BindingMismatch | ScmSourceFetchError::Rejected
                ) {
                    self.metrics
                        .source_fetch_rejections
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Err(TaskFailure::from_source_fetch(error).into());
            }
        };
        let manifest = fetched
            .repository
            .build_source_manifest(
                &repository.id,
                &execution_revision.commit,
                self.config.source_snapshot_limits,
                |digest, bytes| {
                    cas.put_verified_reader(
                        bytes,
                        digest,
                        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    )
                    .map(|_| ())
                    .map_err(|_| GitError::InvalidGitOutput("source CAS publication"))
                },
            )
            .map_err(TaskFailure::from_git_snapshot)?;
        if manifest.commit != execution_revision.commit || manifest.repository_id != repository.id {
            return Err(TaskFailure::terminal(
                "authenticated Git commit changed during source snapshot",
            )
            .into());
        }
        let manifest_bytes = manifest
            .canonical_bytes()
            .map_err(TaskFailure::from_git_snapshot)?;
        let manifest_digest = manifest.digest().map_err(TaskFailure::from_git_snapshot)?;
        let snapshot_id = source_snapshot_id(
            &repository.tenant_id,
            &repository.id,
            &execution_revision.commit,
            &manifest_digest,
        );
        cas.put_verified_reader(
            manifest_bytes.as_slice(),
            &manifest_digest,
            u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX),
            u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX),
        )
        .map_err(|_| TaskFailure::retryable("source manifest CAS publication failed"))?;
        let building = SourceSnapshotRecord {
            id: snapshot_id.clone(),
            tenant_id: repository.tenant_id.clone(),
            repository_id: repository.id.clone(),
            commit_sha: execution_revision.commit.clone(),
            tree_manifest_digest: manifest_digest.clone(),
            state: SourceSnapshotState::Building,
            created_unix_ms: task.created_unix_ms,
            verified_unix_ms: None,
        };
        let snapshot = match self
            .control_plane
            .source_snapshot(&repository.tenant_id, &snapshot_id)
        {
            Ok(existing) => existing,
            Err(ControlPlaneError::NotFound { .. }) => {
                self.control_plane
                    .create_source_snapshot(&building)
                    .map_err(TaskFailure::control)?
                    .value
            }
            Err(error) => return Err(TaskFailure::control(error).into()),
        };
        if snapshot.repository_id != repository.id
            || snapshot.commit_sha != execution_revision.commit
            || snapshot.tree_manifest_digest != manifest_digest
        {
            return Err(TaskFailure::terminal("durable source snapshot identity changed").into());
        }
        let ready = match snapshot.state {
            SourceSnapshotState::Building => self
                .control_plane
                .mark_source_snapshot_ready(
                    &repository.tenant_id,
                    &snapshot_id,
                    &manifest_digest,
                    task.created_unix_ms,
                )
                .map_err(TaskFailure::control)?,
            SourceSnapshotState::Ready => snapshot,
            SourceSnapshotState::Failed | SourceSnapshotState::Retired => {
                return Err(TaskFailure::terminal("durable source snapshot is unavailable").into())
            }
        };
        self.control_plane
            .record_scm_fetch_snapshot_ready(&RecordScmFetchSnapshotReady {
                tenant_id: repository.tenant_id.clone(),
                fetch_id: fetch_id.clone(),
                token_scope_digest: fetched.token_scope_digest.clone(),
                mirror_identity_digest: fetched.mirror_identity_digest.clone(),
                tree_manifest_digest: manifest_digest.clone(),
                source_snapshot_id: snapshot_id.clone(),
                now_unix_ms: task.created_unix_ms,
            })
            .map_err(TaskFailure::control)?;
        let mut requested_commits = vec![execution_revision.commit.clone()];
        if let Some(base) = &event.base {
            requested_commits.push(base.commit.clone());
        }
        Ok(PreparedEventSource {
            repository: EventGitRepository::Fetched {
                repository: fetched.repository,
                requested_commits,
            },
            source_snapshot: Some(ready),
            fetch_id: Some(fetch_id),
        })
    }

    fn prepare_event_and_commit<F>(
        &self,
        task: &DurableTask,
        finish_clock: &F,
    ) -> Result<ScmWorkerTick, ProcessError>
    where
        F: Fn() -> Result<u64, ScmWorkerError>,
    {
        let payload = serde_json::to_vec(&task.payload)
            .map_err(|_| TaskFailure::terminal("invalid normalized SCM event payload"))?;
        if payload.len() > MAX_TASK_PAYLOAD_BYTES {
            return Err(TaskFailure::terminal("normalized SCM event payload is oversized").into());
        }
        let workflow_payload = serde_json::from_slice::<ScmWorkflowTaskPayload>(&payload).ok();
        let (event, requested_workflow_path) = if let Some(payload) = workflow_payload {
            (payload.event, Some(payload.workflow_path))
        } else {
            (
                serde_json::from_slice::<EventEnvelope>(&payload)
                    .map_err(|_| TaskFailure::terminal("invalid normalized SCM event payload"))?,
                None,
            )
        };
        event
            .verify(Default::default())
            .map_err(|_| TaskFailure::terminal("normalized SCM event digest is invalid"))?;
        if event.provider != ProviderKind::GitHub {
            return Err(TaskFailure::terminal("normalized SCM event provider mismatch").into());
        }
        let (repository, installation, repository_link) = if self.source_fetcher.is_some() {
            let (repository, installation, link) = self
                .control_plane
                .github_repository_for_event(
                    &event.installation_id,
                    &event.repository.external_id,
                    &event.repository.owner,
                    &event.repository.name,
                )
                .map_err(TaskFailure::from_repository_lookup)?;
            (repository, Some(installation), Some(link))
        } else {
            if event.installation_id != self.control_plane.installation_id() {
                return Err(
                    TaskFailure::terminal("normalized SCM event installation mismatch").into(),
                );
            }
            (
                self.control_plane
                    .repository_by_owner_name(&event.repository.owner, &event.repository.name)
                    .map_err(TaskFailure::from_repository_lookup)?,
                None,
                None,
            )
        };
        if repository.owner != event.repository.owner
            || repository.name != event.repository.name
            || event.repository.full_name != format!("{}/{}", repository.owner, repository.name)
        {
            return Err(
                TaskFailure::terminal("normalized SCM repository identity mismatch").into(),
            );
        }
        let configured_workflow_directory = self
            .control_plane
            .repository_workflow_directory(&repository.tenant_id, &repository.id)
            .map_err(TaskFailure::control)?
            .unwrap_or_else(|| self.config.workflow_directory.clone());
        if requested_workflow_path
            .as_deref()
            .is_some_and(|path| !workflow_path_allowed(&configured_workflow_directory, path))
        {
            return Err(TaskFailure::terminal("SCM workflow task path is not allowed").into());
        }

        if let Some(result) = self.handle_proposed_workflow_action(
            task,
            &event,
            &repository,
            installation.as_ref(),
            repository_link.as_ref(),
            finish_clock,
        )? {
            return Ok(result);
        }

        if matches!(event.event_type, EventType::Ping) {
            let finish_now = finish_clock()?;
            if self.control_plane.recovery_state()?.safe_mode {
                return Err(TaskFailure::control(ControlPlaneError::InstallationSafeMode).into());
            }
            self.control_plane
                .complete_task(&task.id, &self.config.worker_id, finish_now)
                .map_err(TaskFailure::control)?;
            return Ok(ScmWorkerTick::Completed {
                task_id: task.id.clone(),
                run_id: None,
                replayed: false,
            });
        }

        let execution_revision = self.execution_revision(
            &event,
            &repository,
            installation.as_ref(),
            repository_link.as_ref(),
        )?;
        let prepared_source = self.prepare_event_source(
            task,
            &event,
            &execution_revision,
            &repository,
            installation,
            repository_link,
        )?;
        let workflow_path = if let Some(path) = requested_workflow_path {
            path
        } else {
            let discovery_commit = if matches!(event.event_type, EventType::PullRequest { .. }) {
                event
                    .base
                    .as_ref()
                    .ok_or_else(|| {
                        TaskFailure::terminal(
                            "pull request event has no trusted base revision for workflow discovery",
                        )
                    })?
                    .commit
                    .as_str()
            } else {
                execution_revision.commit.as_str()
            };
            let paths = discover_workflow_paths(
                prepared_source.repository.repository(),
                discovery_commit,
                &configured_workflow_directory,
            )?;
            if paths.len() > 1 {
                let identity = StableIdentity::new(&event, &repository);
                let followups = paths
                    .into_iter()
                    .map(|workflow_path| {
                        let suffix = workflow_identity_suffix(&workflow_path);
                        Ok(DurableTask {
                            id: identity.id("scm-workflow-task", b"workflow-task", suffix),
                            kind: SCM_TASK_KIND.to_owned(),
                            payload: serde_json::to_value(ScmWorkflowTaskPayload {
                                event: event.clone(),
                                workflow_path,
                            })
                            .map_err(|_| {
                                TaskFailure::terminal("SCM workflow task encoding failed")
                            })?,
                            status: DurableTaskStatus::Pending,
                            available_unix_ms: task.created_unix_ms,
                            attempts: 0,
                            lease_owner: None,
                            lease_expires_unix_ms: None,
                            last_error: None,
                            created_unix_ms: task.created_unix_ms,
                            completed_unix_ms: None,
                        })
                    })
                    .collect::<Result<Vec<_>, TaskFailure>>()?;
                let finish_now = finish_clock()?;
                if self.control_plane.recovery_state()?.safe_mode {
                    return Err(
                        TaskFailure::control(ControlPlaneError::InstallationSafeMode).into(),
                    );
                }
                self.control_plane
                    .complete_task_with_followups(
                        &task.id,
                        &self.config.worker_id,
                        &followups,
                        finish_now,
                    )
                    .map_err(TaskFailure::control)?;
                return Ok(ScmWorkerTick::Completed {
                    task_id: task.id.clone(),
                    run_id: None,
                    replayed: false,
                });
            }
            paths
                .into_iter()
                .next()
                .ok_or_else(|| TaskFailure::terminal("repository has no SCM workflows"))?
        };
        let reusable_source_provider = MirrorReusableSourceProvider {
            mirror_root: self.mirror_root.as_ref(),
            current_repository: prepared_source.repository.repository(),
            current_owner: &repository.owner,
            current_name: &repository.name,
            endpoints: &self.config.github_provider_endpoints,
        };
        let mut planner = TrustedPlanner::new(prepared_source.repository.repository())
            .with_source_frontends(workflow_frontends())
            .with_reusable_source_provider(&reusable_source_provider)
            .with_scm_api_url(self.config.github_provider_endpoints.api_origin());
        if let Some(image) = &self.config.default_job_container_image {
            planner = planner.with_default_job_container_image(image.clone());
        }
        if let Some(snapshot) = &prepared_source.source_snapshot {
            planner = planner.with_source_snapshot_digest(snapshot.tree_manifest_digest.clone());
        }
        let planned = if matches!(
            event.event_type,
            EventType::IssueComment { .. } | EventType::CheckRun { .. }
        ) {
            planner.capsule_trusted_default_revision(
                &event,
                &execution_revision,
                &workflow_path,
                self.control_plane.installation_id(),
                &repository.tenant_id,
                &repository.id,
                &repository.default_branch,
                self.config.policy_version_ids.clone(),
            )
        } else {
            planner.capsule(
                &event,
                &workflow_path,
                self.control_plane.installation_id(),
                &repository.tenant_id,
                &repository.id,
                &repository.default_branch,
                self.config.policy_version_ids.clone(),
                None,
                &RejectWorkflowApproval,
                task.created_unix_ms,
            )
        }
        .map_err(TaskFailure::from_planner)?;
        prepared_source
            .repository
            .revalidate()
            .map_err(|_| TaskFailure::retryable("Git mirror repository changed while planning"))?;

        if !workflow_watches_event(&planned.execution.triggers, &event) {
            let finish_now = finish_clock()?;
            if self.control_plane.recovery_state()?.safe_mode {
                return Err(TaskFailure::control(ControlPlaneError::InstallationSafeMode).into());
            }
            self.control_plane
                .complete_task(&task.id, &self.config.worker_id, finish_now)
                .map_err(TaskFailure::control)?;
            return Ok(ScmWorkerTick::Completed {
                task_id: task.id.clone(),
                run_id: None,
                replayed: false,
            });
        }

        // No approval evidence is admitted on this path. Preserve the safe PR
        // default even if a future planner implementation regresses.
        if matches!(event.event_type, EventType::PullRequest { .. })
            && !planned.selection.trusted_base_workflow_executed
        {
            return Err(TaskFailure::terminal(
                "unapproved pull request did not select the trusted base workflow",
            )
            .into());
        }

        let identity = StableIdentity::new(&event, &repository);
        let workflow_suffix = workflow_identity_suffix(&workflow_path);
        let analysis_id = identity.id("scm-analysis", b"analysis", workflow_suffix);
        let primary_role = if matches!(event.event_type, EventType::PullRequest { .. }) {
            ScmExecutionRole::TrustedBase
        } else {
            ScmExecutionRole::Direct
        };
        let mut executions = vec![self.prepare_scm_execution(
            task,
            &event,
            &repository,
            &identity,
            &planned.execution,
            &planned.source_inputs,
            primary_role,
            workflow_suffix,
            None,
            prepared_source.source_snapshot.as_ref(),
            prepared_source.fetch_id.as_deref(),
        )?];
        let proposed_analysis = if matches!(event.event_type, EventType::PullRequest { .. })
            && planned.selection.workflow_definition_approval_required
        {
            match &planned.proposed_analysis {
                ProposedWorkflowAnalysis::Valid {
                    compilation,
                    semantic_risk,
                } => {
                    let workflow_diff = workflow_definition_diff(
                        prepared_source.repository.repository(),
                        &event,
                        &workflow_path,
                    );
                    let lockfile_diff = workflow_definition_diff(
                        prepared_source.repository.repository(),
                        &event,
                        DEFAULT_LOCKFILE_PATH,
                    );
                    let proposed = self.prepare_scm_execution(
                        task,
                        &event,
                        &repository,
                        &identity,
                        compilation,
                        &planned.source_inputs,
                        ScmExecutionRole::ProposedDefinition,
                        &proposed_identity_suffix(workflow_suffix),
                        Some(analysis_id.clone()),
                        prepared_source.source_snapshot.as_ref(),
                        prepared_source.fetch_id.as_deref(),
                    )?;
                    let source_identity = proposed
                        .continuation
                        .as_ref()
                        .ok_or_else(|| {
                            TaskFailure::terminal(
                                "changed proposed workflow did not produce an approval gate",
                            )
                        })?
                        .source_identity
                        .clone();
                    let proposed_capsule_id = proposed.capsule.id.clone();
                    executions.push(proposed);
                    Some(ScmProposedAnalysisRecord {
                        id: analysis_id.clone(),
                        origin_task_id: task.id.clone(),
                        repository_id: repository.id.clone(),
                        status: ScmProposedAnalysisStatus::Valid,
                        source_identity,
                        analysis: Some(serde_json::json!({
                            "semantic_risk": semantic_risk,
                            "trusted_base_workflow_executed": true,
                            "workflow_diff": workflow_diff,
                            "lockfile_diff": lockfile_diff,
                        })),
                        failure: None,
                        proposed_capsule_id: Some(proposed_capsule_id),
                        created_unix_ms: task.created_unix_ms,
                    })
                }
                ProposedWorkflowAnalysis::Invalid { failure, .. } => {
                    Some(ScmProposedAnalysisRecord {
                        id: analysis_id,
                        origin_task_id: task.id.clone(),
                        repository_id: repository.id.clone(),
                        status: ScmProposedAnalysisStatus::Invalid,
                        source_identity: scm_source_identity(
                            &event,
                            &planned.source_inputs,
                            &[],
                            &event.source.commit,
                            event.base.as_ref().map(|base| base.commit.as_str()),
                        ),
                        analysis: None,
                        failure: Some(proposed_analysis_failure_name(*failure).to_owned()),
                        proposed_capsule_id: None,
                        created_unix_ms: task.created_unix_ms,
                    })
                }
                ProposedWorkflowAnalysis::Deleted { .. } => Some(ScmProposedAnalysisRecord {
                    id: analysis_id,
                    origin_task_id: task.id.clone(),
                    repository_id: repository.id.clone(),
                    status: ScmProposedAnalysisStatus::Deleted,
                    source_identity: scm_source_identity(
                        &event,
                        &planned.source_inputs,
                        &[],
                        &event.source.commit,
                        event.base.as_ref().map(|base| base.commit.as_str()),
                    ),
                    analysis: None,
                    failure: None,
                    proposed_capsule_id: None,
                    created_unix_ms: task.created_unix_ms,
                }),
                ProposedWorkflowAnalysis::NotApplicable => {
                    return Err(
                        TaskFailure::terminal("pull request proposed analysis is missing").into(),
                    )
                }
            }
        } else {
            None
        };
        let idempotency_key = identity.id("scm", b"idempotency", workflow_suffix);
        let finish_now = finish_clock()?;
        let result = self
            .control_plane
            .complete_scm_task_with_executions_idempotent(
                &task.id,
                &self.config.worker_id,
                finish_now,
                &idempotency_key,
                &executions,
                proposed_analysis.as_ref(),
                &self.signing_key.verifying_key(),
            )
            .map_err(TaskFailure::control)?;
        if prepared_source.fetch_id.is_some() {
            self.metrics
                .source_snapshots_committed
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(ScmWorkerTick::Completed {
            task_id: task.id.clone(),
            run_id: result.value.run_ids.first().cloned(),
            replayed: result.replayed,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_scm_execution(
        &self,
        task: &DurableTask,
        event: &EventEnvelope,
        repository: &RepositoryRecord,
        identity: &StableIdentity<'_>,
        compilation: &Compilation,
        source_inputs: &WorkflowSourceInputs,
        role: ScmExecutionRole,
        identity_suffix: &[u8],
        analysis_id: Option<String>,
        source_snapshot: Option<&SourceSnapshotRecord>,
        scm_fetch_id: Option<&str>,
    ) -> Result<PreparedScmExecution, ProcessError> {
        let canonical_capsule = compilation
            .capsule
            .canonical_bytes()
            .map_err(|_| TaskFailure::terminal("execution capsule canonicalization failed"))?;
        let signature = self
            .signing_key
            .sign_capsule(&compilation.capsule)
            .map_err(|_| TaskFailure::terminal("execution capsule signing failed"))?;
        let capsule_id = identity.id("capsule", b"capsule", identity_suffix);
        let run_id = identity.id("run", b"run", identity_suffix);
        let capsule = SignedCapsuleRecord {
            id: capsule_id.clone(),
            repository_id: repository.id.clone(),
            digest: signature.capsule_digest.clone(),
            canonical_capsule,
            signature,
            created_unix_ms: task.created_unix_ms,
        };
        let metadata = CapsuleApiMetadata {
            capsule_id: capsule_id.clone(),
            approval_subject_digest: compilation.approval_subject_digest.clone(),
            risk_score: compilation.risk_report.score,
        };
        let jobs = compilation
            .capsule
            .jobs
            .iter()
            .map(|planned_job| {
                let mut suffix = identity_suffix.to_vec();
                suffix.push(0);
                suffix.extend_from_slice(planned_job.id.as_bytes());
                NewJob {
                    id: identity.id("job", b"job", &suffix),
                    job_key: planned_job.id.clone(),
                    attempt: 1,
                    requirements: SchedulingRequirements {
                        os: planned_job.runner.os,
                        arch: planned_job.runner.arch,
                        isolation: planned_job.runner.isolation,
                        cpu: u32::from(planned_job.runner.cpu),
                        memory_bytes: planned_job.runner.memory_bytes,
                        storage_bytes: planned_job.runner.storage_bytes.unwrap_or(0),
                        region: planned_job.runner.region.clone(),
                        required_capabilities: planned_job
                            .runner
                            .capabilities
                            .iter()
                            .cloned()
                            .collect(),
                        allowed_pools: BTreeSet::new(),
                    },
                }
            })
            .collect();
        let run = CreateRunRequest {
            id: run_id,
            repository_id: repository.id.clone(),
            capsule_id,
            priority: 0,
            remote: true,
            created_unix_ms: task.created_unix_ms,
            jobs,
        };
        let expires_unix_ms = task
            .created_unix_ms
            .checked_add(APPROVAL_LIFETIME_MS)
            .ok_or_else(|| TaskFailure::terminal("SCM approval expiry is out of range"))?;
        let mut approvals = Vec::new();
        for kind in [
            compilation
                .capsule
                .approval
                .workflow_definition
                .then_some(ApprovalKind::WorkflowDefinition),
            compilation
                .capsule
                .approval
                .privileged_execution
                .then_some(ApprovalKind::PrivilegedExecution),
        ]
        .into_iter()
        .flatten()
        {
            let kind_suffix = match kind {
                ApprovalKind::WorkflowDefinition => b"workflow-definition".as_slice(),
                ApprovalKind::PrivilegedExecution => b"privileged-execution".as_slice(),
                _ => unreachable!("SCM capsules expose only two independent gates"),
            };
            let mut suffix = identity_suffix.to_vec();
            suffix.push(0);
            suffix.extend_from_slice(kind_suffix);
            let approval = ApprovalRequest::create(
                identity.id("approval", b"approval", &suffix),
                kind,
                compilation.approval_subject_digest.clone(),
                compilation.risk_report.score,
                task.created_unix_ms,
                expires_unix_ms,
                ApprovalRule {
                    id: "bootstrap-security-review".to_owned(),
                    required_approvals: 1,
                    eligible_approvers: BTreeSet::from([
                        "runtrue-workflow-approver".to_owned(),
                        "bootstrap".to_owned(),
                        "github-repository-writer".to_owned(),
                    ]),
                    forbidden_approvers: BTreeSet::new(),
                    one_shot: true,
                },
            )
            .map_err(|_| TaskFailure::terminal("SCM approval request construction failed"))?;
            approvals.push(approval);
        }
        let continuation = if approvals.is_empty() {
            None
        } else {
            Some(ScmContinuationContext {
                pending_execution_id: identity.id(
                    "scm-pending",
                    b"pending-execution",
                    identity_suffix,
                ),
                event: serde_json::to_value(event)
                    .map_err(|_| TaskFailure::terminal("SCM continuation event encoding failed"))?,
                role,
                source_identity: scm_source_identity(
                    event,
                    source_inputs,
                    &compilation.approval_subject.reusable_workflow_digests,
                    &compilation.capsule.context.source_commit,
                    compilation.capsule.context.base_commit.as_deref(),
                ),
                analysis_id,
                source_snapshot_id: source_snapshot.map(|snapshot| snapshot.id.clone()),
            })
        };
        Ok(PreparedScmExecution {
            capsule,
            metadata,
            approvals,
            run,
            continuation,
            source_snapshot: source_snapshot.cloned(),
            scm_fetch_id: scm_fetch_id.map(str::to_owned),
        })
    }

    fn prepare_continuation_and_commit<F>(
        &self,
        task: &DurableTask,
        finish_clock: &F,
    ) -> Result<ScmWorkerTick, ProcessError>
    where
        F: Fn() -> Result<u64, ScmWorkerError>,
    {
        let payload: ScmContinuationPayload = serde_json::from_value(task.payload.clone())
            .map_err(|_| TaskFailure::terminal("invalid SCM continuation task payload"))?;
        if payload.approval_id.is_empty() {
            return Err(TaskFailure::terminal("invalid SCM continuation approval id").into());
        }
        let begin_now = finish_clock()?;
        let pending = match self.control_plane.begin_scm_continuation(
            &task.id,
            &self.config.worker_id,
            &payload.pending_execution_id,
            begin_now,
        )? {
            ScmContinuationResolution::Ready(pending) => pending,
            ScmContinuationResolution::RunCreated(run) => {
                return Ok(ScmWorkerTick::Completed {
                    task_id: task.id.clone(),
                    run_id: Some(run.id),
                    replayed: true,
                })
            }
            ScmContinuationResolution::Waiting(_) | ScmContinuationResolution::Closed(_) => {
                return Ok(ScmWorkerTick::Completed {
                    task_id: task.id.clone(),
                    run_id: None,
                    replayed: false,
                })
            }
        };
        let pending_repository = self
            .control_plane
            .repository(&pending.repository_id)
            .map_err(TaskFailure::control)?;
        let configured_workflow_directory = self
            .control_plane
            .repository_workflow_directory(&pending_repository.tenant_id, &pending_repository.id)
            .map_err(TaskFailure::control)?
            .unwrap_or_else(|| self.config.workflow_directory.clone());
        if pending.context.source_identity.policy_version_ids != self.config.policy_version_ids
            || !workflow_path_allowed(
                &configured_workflow_directory,
                &pending.context.source_identity.workflow_path,
            )
        {
            return self.close_stale_continuation(
                task,
                &pending.id,
                "SCM policy or workflow configuration changed after approval request",
                finish_clock()?,
            );
        }
        let event: EventEnvelope = serde_json::from_value(pending.context.event.clone())
            .map_err(|_| TaskFailure::terminal("invalid durable SCM continuation event"))?;
        event
            .verify(Default::default())
            .map_err(|_| TaskFailure::terminal("durable SCM continuation event is invalid"))?;
        if event.provider != ProviderKind::GitHub
            || event.normalized_digest != pending.context.source_identity.normalized_event_digest
        {
            return self.close_stale_continuation(
                task,
                &pending.id,
                "SCM event identity changed after approval request",
                finish_clock()?,
            );
        }
        let (repository, continuation_repository, source_snapshot) =
            if let Some(fetcher) = &self.source_fetcher {
                let (repository, installation, link) = self
                    .control_plane
                    .github_repository_for_event(
                        &event.installation_id,
                        &event.repository.external_id,
                        &event.repository.owner,
                        &event.repository.name,
                    )
                    .map_err(TaskFailure::from_repository_lookup)?;
                let fetched = fetcher
                    .fetch(&ScmSourceFetchRequest {
                        installation,
                        repository: link,
                        tenant_id: repository.tenant_id.clone(),
                        repository_id: repository.id.clone(),
                        owner: repository.owner.clone(),
                        name: repository.name.clone(),
                        source_commit: pending.context.source_identity.source_commit.clone(),
                        base_commit: pending.context.source_identity.base_commit.clone(),
                    })
                    .map_err(TaskFailure::from_source_fetch)?;
                let snapshot_id = pending.context.source_snapshot_id.as_ref().ok_or_else(|| {
                    TaskFailure::terminal("SCM continuation lost its source snapshot")
                })?;
                let snapshot = self
                    .control_plane
                    .source_snapshot(&repository.tenant_id, snapshot_id)
                    .map_err(TaskFailure::control)?;
                if snapshot.state != SourceSnapshotState::Ready
                    || snapshot.repository_id != repository.id
                    || snapshot.commit_sha != pending.context.source_identity.source_commit
                {
                    return self.close_stale_continuation(
                        task,
                        &pending.id,
                        "SCM source snapshot changed after approval request",
                        finish_clock()?,
                    );
                }
                let mut commits = vec![pending.context.source_identity.source_commit.clone()];
                if let Some(base) = &pending.context.source_identity.base_commit {
                    commits.push(base.clone());
                }
                (
                    repository,
                    EventGitRepository::Fetched {
                        repository: fetched.repository,
                        requested_commits: commits,
                    },
                    Some(snapshot),
                )
            } else {
                if event.installation_id != self.control_plane.installation_id() {
                    return self.close_stale_continuation(
                        task,
                        &pending.id,
                        "SCM installation changed after approval request",
                        finish_clock()?,
                    );
                }
                let repository = self
                    .control_plane
                    .repository_by_owner_name(&event.repository.owner, &event.repository.name)
                    .map_err(TaskFailure::from_repository_lookup)?;
                let git = self
                    .mirror_root
                    .as_ref()
                    .ok_or_else(|| TaskFailure::terminal("SCM mirror source is not configured"))?
                    .open_repository(&repository.owner, &repository.name)
                    .map_err(|_| {
                        TaskFailure::retryable("Git mirror repository is unavailable or unsafe")
                    })?;
                (repository, EventGitRepository::Legacy(git), None)
            };
        if repository.id != pending.repository_id
            || event.repository.full_name != format!("{}/{}", repository.owner, repository.name)
        {
            return self.close_stale_continuation(
                task,
                &pending.id,
                "SCM repository binding changed after approval request",
                finish_clock()?,
            );
        }
        let reusable_source_provider = MirrorReusableSourceProvider {
            mirror_root: self.mirror_root.as_ref(),
            current_repository: continuation_repository.repository(),
            current_owner: &repository.owner,
            current_name: &repository.name,
            endpoints: &self.config.github_provider_endpoints,
        };
        let mut planner = TrustedPlanner::new(continuation_repository.repository())
            .with_source_frontends(workflow_frontends())
            .with_reusable_source_provider(&reusable_source_provider)
            .with_scm_api_url(self.config.github_provider_endpoints.api_origin());
        if let Some(image) = &self.config.default_job_container_image {
            planner = planner.with_default_job_container_image(image.clone());
        }
        if let Some(snapshot) = &source_snapshot {
            planner = planner.with_source_snapshot_digest(snapshot.tree_manifest_digest.clone());
        }
        let initial = if matches!(
            event.event_type,
            EventType::IssueComment { .. } | EventType::CheckRun { .. }
        ) {
            planner.capsule_trusted_default_revision(
                &event,
                &GitRevision {
                    commit: pending.context.source_identity.source_commit.clone(),
                    ref_name: Some(format!("refs/heads/{}", repository.default_branch)),
                    repository_full_name: Some(event.repository.full_name.clone()),
                },
                &pending.context.source_identity.workflow_path,
                self.control_plane.installation_id(),
                &repository.tenant_id,
                &repository.id,
                &repository.default_branch,
                self.config.policy_version_ids.clone(),
            )
        } else {
            planner.capsule(
                &event,
                &pending.context.source_identity.workflow_path,
                self.control_plane.installation_id(),
                &repository.tenant_id,
                &repository.id,
                &repository.default_branch,
                self.config.policy_version_ids.clone(),
                None,
                &RejectWorkflowApproval,
                pending.created_unix_ms,
            )
        }
        .map_err(TaskFailure::from_planner)?;
        let replanned = if pending.role == ScmExecutionRole::ProposedDefinition {
            let approvals = self
                .control_plane
                .scm_pending_execution_approvals(&pending.id)
                .map_err(TaskFailure::control)?;
            let workflow_approval = approvals
                .iter()
                .find(|approval| approval.kind == ApprovalKind::WorkflowDefinition)
                .ok_or_else(|| {
                    TaskFailure::terminal(
                        "proposed SCM continuation lost workflow-definition approval",
                    )
                })?;
            let evidence =
                workflow_approval_evidence(&event, &initial.source_inputs, workflow_approval)?;
            let verifier = ExactWorkflowApprovalVerifier {
                approval: workflow_approval,
            };
            let mut planner = TrustedPlanner::new(continuation_repository.repository())
                .with_source_frontends(workflow_frontends())
                .with_reusable_source_provider(&reusable_source_provider)
                .with_scm_api_url(self.config.github_provider_endpoints.api_origin());
            if let Some(image) = &self.config.default_job_container_image {
                planner = planner.with_default_job_container_image(image.clone());
            }
            if let Some(snapshot) = &source_snapshot {
                planner =
                    planner.with_source_snapshot_digest(snapshot.tree_manifest_digest.clone());
            }
            planner
                .capsule(
                    &event,
                    &pending.context.source_identity.workflow_path,
                    self.control_plane.installation_id(),
                    &repository.tenant_id,
                    &repository.id,
                    &repository.default_branch,
                    self.config.policy_version_ids.clone(),
                    Some(&evidence),
                    &verifier,
                    begin_now,
                )
                .map_err(TaskFailure::from_planner)?
        } else {
            initial
        };
        continuation_repository
            .revalidate()
            .map_err(|_| TaskFailure::retryable("Git mirror repository changed while planning"))?;
        if pending.role == ScmExecutionRole::ProposedDefinition
            && replanned.selection.trusted_base_workflow_executed
        {
            return self.close_stale_continuation(
                task,
                &pending.id,
                "approved proposed workflow was not selected during re-planning",
                finish_clock()?,
            );
        }
        let source_identity = scm_source_identity(
            &event,
            &replanned.source_inputs,
            &replanned
                .execution
                .approval_subject
                .reusable_workflow_digests,
            &replanned.execution.capsule.context.source_commit,
            replanned.execution.capsule.context.base_commit.as_deref(),
        );
        let revalidated_context = ScmContinuationContext {
            pending_execution_id: pending.id.clone(),
            event: serde_json::to_value(&event)
                .map_err(|_| TaskFailure::terminal("SCM event encoding failed"))?,
            role: pending.role,
            source_identity,
            analysis_id: pending.context.analysis_id.clone(),
            source_snapshot_id: pending.context.source_snapshot_id.clone(),
        };
        if revalidated_context != pending.context {
            return self.close_stale_continuation(
                task,
                &pending.id,
                "SCM source, lock, reusable workflow, or policy identity changed",
                finish_clock()?,
            );
        }
        let signature = self
            .signing_key
            .sign_capsule(&replanned.execution.capsule)
            .map_err(|_| TaskFailure::terminal("execution capsule signing failed"))?;
        let record =
            SignedCapsuleRecord {
                id: pending.capsule_id.clone(),
                repository_id: pending.repository_id.clone(),
                digest: signature.capsule_digest.clone(),
                canonical_capsule: replanned.execution.capsule.canonical_bytes().map_err(|_| {
                    TaskFailure::terminal("execution capsule canonicalization failed")
                })?,
                signature,
                created_unix_ms: pending.created_unix_ms,
            };
        let metadata = CapsuleApiMetadata {
            capsule_id: pending.capsule_id.clone(),
            approval_subject_digest: replanned.execution.approval_subject_digest,
            risk_score: replanned.execution.risk_report.score,
        };
        let finish_now = finish_clock()?;
        match self
            .control_plane
            .complete_scm_continuation_with_run_idempotent(
                &task.id,
                &self.config.worker_id,
                &pending.id,
                finish_now,
                &record,
                &self.signing_key.verifying_key(),
                &metadata,
                &revalidated_context,
                &pending.run,
            )
            .map_err(TaskFailure::control)?
        {
            ScmContinuationCommit::Run(result) => Ok(ScmWorkerTick::Completed {
                task_id: task.id.clone(),
                run_id: Some(result.value.id),
                replayed: result.replayed,
            }),
            ScmContinuationCommit::Waiting(_) | ScmContinuationCommit::Closed(_) => {
                Ok(ScmWorkerTick::Completed {
                    task_id: task.id.clone(),
                    run_id: None,
                    replayed: false,
                })
            }
        }
    }

    fn close_stale_continuation(
        &self,
        task: &DurableTask,
        pending_execution_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<ScmWorkerTick, ProcessError> {
        self.control_plane
            .close_scm_continuation_as_stale(
                &task.id,
                &self.config.worker_id,
                pending_execution_id,
                reason,
                now_unix_ms,
            )
            .map_err(TaskFailure::control)?;
        Ok(ScmWorkerTick::Completed {
            task_id: task.id.clone(),
            run_id: None,
            replayed: false,
        })
    }

    fn record_failure(
        &self,
        task: &DurableTask,
        failure: TaskFailure,
        now_unix_ms: u64,
    ) -> Result<ScmWorkerTick, ScmWorkerError> {
        if matches!(
            failure.source.as_ref(),
            Some(ControlPlaneError::TaskLeaseExpired)
        ) {
            return Err(failure.source.expect("checked source").into());
        }
        let retry_at =
            if failure.retryable && task.attempts < self.config.max_attempts {
                let exponential = self.retry_delay_ms(task.attempts)?;
                let requested = failure.retry_after_ms.unwrap_or(exponential);
                let bounded_delay = requested.min(duration_ms(self.config.retry_max)?);
                Some(now_unix_ms.checked_add(bounded_delay).ok_or(
                    ControlPlaneError::IntegerRange {
                        field: "SCM task retry time",
                    },
                )?)
            } else {
                None
            };
        let error = bounded_failure_message(failure.message);
        if task.kind == SCM_CONTINUATION_TASK_KIND && retry_at.is_none() {
            let payload: ScmContinuationPayload = serde_json::from_value(task.payload.clone())
                .map_err(|_| ControlPlaneError::InvalidInput("invalid SCM continuation payload"))?;
            self.control_plane.close_scm_continuation_as_stale(
                &task.id,
                &self.config.worker_id,
                &payload.pending_execution_id,
                &error,
                now_unix_ms,
            )?;
            return Ok(ScmWorkerTick::Completed {
                task_id: task.id.clone(),
                run_id: None,
                replayed: false,
            });
        }
        self.control_plane.fail_task(
            &task.id,
            &self.config.worker_id,
            &error,
            now_unix_ms,
            retry_at,
        )?;
        if retry_at.is_some() {
            self.metrics.task_retries.fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .task_terminal_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(if let Some(retry_at_unix_ms) = retry_at {
            ScmWorkerTick::Retried {
                task_id: task.id.clone(),
                attempt: task.attempts,
                retry_at_unix_ms,
            }
        } else {
            ScmWorkerTick::Failed {
                task_id: task.id.clone(),
                attempts: task.attempts,
            }
        })
    }

    fn retry_delay_ms(&self, attempts: u32) -> Result<u64, ScmWorkerError> {
        let exponent = attempts.saturating_sub(1).min(31);
        let multiplier = 1_u64 << exponent;
        let base = duration_ms(self.config.retry_base)?;
        let maximum = duration_ms(self.config.retry_max)?;
        Ok(base.saturating_mul(multiplier).min(maximum))
    }
}

fn workflow_definition_diff(
    repository: &GitRepository,
    event: &EventEnvelope,
    workflow_path: &str,
) -> Option<String> {
    let base = event.base.as_ref()?;
    let trusted = repository.read_blob(&base.commit, workflow_path).ok()?;
    let proposed = repository
        .read_blob(&event.source.commit, workflow_path)
        .ok()?;
    let trusted = std::str::from_utf8(&trusted.bytes).ok()?;
    let proposed = std::str::from_utf8(&proposed.bytes).ok()?;
    bounded_unified_definition_diff(trusted, proposed)
}

fn bounded_unified_definition_diff(trusted: &str, proposed: &str) -> Option<String> {
    if trusted == proposed {
        return None;
    }
    let trusted_lines = trusted.lines().collect::<Vec<_>>();
    let proposed_lines = proposed.lines().collect::<Vec<_>>();
    let common_prefix = trusted_lines
        .iter()
        .zip(&proposed_lines)
        .take_while(|(left, right)| left == right)
        .count();
    let maximum_suffix = trusted_lines
        .len()
        .saturating_sub(common_prefix)
        .min(proposed_lines.len().saturating_sub(common_prefix));
    let common_suffix = trusted_lines
        .iter()
        .rev()
        .zip(proposed_lines.iter().rev())
        .take(maximum_suffix)
        .take_while(|(left, right)| left == right)
        .count();
    let trusted_end = trusted_lines.len().saturating_sub(common_suffix);
    let proposed_end = proposed_lines.len().saturating_sub(common_suffix);
    let trusted_changes = &trusted_lines[common_prefix..trusted_end];
    let proposed_changes = &proposed_lines[common_prefix..proposed_end];
    let context_start = common_prefix.saturating_sub(3);
    let context_end = (common_suffix.min(3) + trusted_end).min(trusted_lines.len());
    let mut output = format!(
        "@@ -{},{} +{},{} @@\n",
        common_prefix + 1,
        trusted_changes.len(),
        common_prefix + 1,
        proposed_changes.len()
    );
    for line in &trusted_lines[context_start..common_prefix] {
        push_bounded_diff_line(&mut output, ' ', line);
    }
    let mut truncated = false;
    for line in trusted_changes
        .iter()
        .take(MAX_DEFINITION_DIFF_LINES_PER_SIDE)
    {
        truncated |= !push_bounded_diff_line(&mut output, '-', line);
    }
    truncated |= trusted_changes.len() > MAX_DEFINITION_DIFF_LINES_PER_SIDE;
    for line in proposed_changes
        .iter()
        .take(MAX_DEFINITION_DIFF_LINES_PER_SIDE)
    {
        truncated |= !push_bounded_diff_line(&mut output, '+', line);
    }
    truncated |= proposed_changes.len() > MAX_DEFINITION_DIFF_LINES_PER_SIDE;
    if !truncated {
        for line in &trusted_lines[trusted_end..context_end] {
            truncated |= !push_bounded_diff_line(&mut output, ' ', line);
        }
    }
    if truncated {
        const MARKER: &str = "... definition diff truncated ...\n";
        while output.len().saturating_add(MARKER.len()) > MAX_DEFINITION_DIFF_BYTES {
            if output.pop().is_none() {
                break;
            }
        }
        output.push_str(MARKER);
    }
    Some(output)
}

fn push_bounded_diff_line(output: &mut String, prefix: char, line: &str) -> bool {
    let safe_line = line.replace("````", "```\u{200b}`");
    let required = prefix.len_utf8() + safe_line.len() + 1;
    if output.len().saturating_add(required) > MAX_DEFINITION_DIFF_BYTES {
        return false;
    }
    output.push(prefix);
    output.push_str(&safe_line);
    output.push('\n');
    true
}

fn workflow_watches_event(
    triggers: &runtrue_workflow_ast::Triggers,
    event: &EventEnvelope,
) -> bool {
    match &event.event_type {
        EventType::Push => triggers
            .push
            .as_ref()
            .is_some_and(|trigger| git_trigger_matches(trigger, event)),
        EventType::PullRequest { .. } => {
            triggers
                .pull_request_target
                .as_ref()
                .is_some_and(|trigger| webhook_trigger_matches(trigger, event))
                || triggers
                    .pull_request
                    .as_ref()
                    .is_some_and(|trigger| git_trigger_matches(trigger, event))
        }
        EventType::MergeGroup => triggers.merge_queue.is_some(),
        EventType::IssueComment { .. } => triggers
            .issue_comment
            .as_ref()
            .is_some_and(|trigger| webhook_trigger_matches(trigger, event)),
        EventType::CheckRun { .. } => triggers
            .check_run
            .as_ref()
            .is_some_and(|trigger| webhook_trigger_matches(trigger, event)),
        EventType::Ping => false,
    }
}

fn webhook_trigger_matches(
    trigger: &runtrue_workflow_ast::WebhookTrigger,
    event: &EventEnvelope,
) -> bool {
    if trigger.types.is_empty() {
        return true;
    }
    let action = match event.event_type {
        EventType::PullRequest { action } => match action {
            runtrue_scm::PullRequestAction::Opened => "opened",
            runtrue_scm::PullRequestAction::Synchronize => "synchronize",
            runtrue_scm::PullRequestAction::Reopened => "reopened",
            runtrue_scm::PullRequestAction::Edited => "edited",
            runtrue_scm::PullRequestAction::Labeled => "labeled",
            runtrue_scm::PullRequestAction::Unlabeled => "unlabeled",
            runtrue_scm::PullRequestAction::ReadyForReview => "ready_for_review",
            runtrue_scm::PullRequestAction::ConvertedToDraft => "converted_to_draft",
            runtrue_scm::PullRequestAction::Closed => "closed",
        },
        EventType::IssueComment { action } => match action {
            runtrue_scm::IssueCommentAction::Created => "created",
            runtrue_scm::IssueCommentAction::Edited => "edited",
        },
        EventType::CheckRun { action } => match action {
            runtrue_scm::CheckRunEventAction::Completed => "completed",
            runtrue_scm::CheckRunEventAction::Rerequested => "rerequested",
            runtrue_scm::CheckRunEventAction::RequestedAction => "requested_action",
        },
        EventType::Push | EventType::MergeGroup | EventType::Ping => return false,
    };
    trigger.types.iter().any(|candidate| candidate == action)
}

fn git_trigger_matches(trigger: &runtrue_workflow_ast::GitTrigger, event: &EventEnvelope) -> bool {
    let branch = event
        .ref_name
        .as_deref()
        .unwrap_or_default()
        .strip_prefix("refs/heads/")
        .unwrap_or_else(|| event.ref_name.as_deref().unwrap_or_default());
    if (!trigger.branches.is_empty()
        && !trigger
            .branches
            .iter()
            .any(|pattern| github_pattern_matches(pattern, branch)))
        || trigger
            .branches_ignore
            .iter()
            .any(|pattern| github_pattern_matches(pattern, branch))
    {
        return false;
    }
    if trigger.paths.is_empty() && trigger.paths_ignore.is_empty() {
        return true;
    }
    if event.changed_paths.is_empty() {
        return false;
    }
    event.changed_paths.iter().any(|path| {
        (trigger.paths.is_empty()
            || trigger
                .paths
                .iter()
                .any(|pattern| github_pattern_matches(pattern, path)))
            && !trigger
                .paths_ignore
                .iter()
                .any(|pattern| github_pattern_matches(pattern, path))
    })
}

/// Bounded GitHub-style wildcard subset: `*` and `?` do not cross `/`, while
/// `**` may. Unsupported or oversized patterns fail closed as non-matches.
fn github_pattern_matches(pattern: &str, value: &str) -> bool {
    const MAX_PATTERN_BYTES: usize = 512;
    const MAX_VALUE_BYTES: usize = 4096;
    if pattern.is_empty()
        || pattern.len() > MAX_PATTERN_BYTES
        || value.len() > MAX_VALUE_BYTES
        || pattern
            .chars()
            .any(|character| matches!(character, '[' | ']' | '!' | '\\'))
    {
        return false;
    }
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut current = vec![false; value.len() + 1];
    current[0] = true;
    let mut index = 0;
    while index < pattern.len() {
        let mut next = vec![false; value.len() + 1];
        match pattern[index] {
            b'*' if pattern.get(index + 1) == Some(&b'*') => {
                while pattern.get(index + 1) == Some(&b'*') {
                    index += 1;
                }
                next[0] = current[0];
                for position in 1..=value.len() {
                    next[position] = current[position] || next[position - 1];
                }
            }
            b'*' => {
                next[0] = current[0];
                for position in 1..=value.len() {
                    next[position] =
                        current[position] || (value[position - 1] != b'/' && next[position - 1]);
                }
            }
            b'?' => {
                for position in 1..=value.len() {
                    next[position] = value[position - 1] != b'/' && current[position - 1];
                }
            }
            literal => {
                for position in 1..=value.len() {
                    next[position] = literal == value[position - 1] && current[position - 1];
                }
            }
        }
        current = next;
        index += 1;
    }
    current[value.len()]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScmContinuationPayload {
    pending_execution_id: String,
    approval_id: String,
}

fn scm_source_identity(
    event: &EventEnvelope,
    inputs: &WorkflowSourceInputs,
    reusable_workflow_digests: &[String],
    source_commit: &str,
    base_commit: Option<&str>,
) -> ScmSourceIdentity {
    let mut reusable_workflow_digests = reusable_workflow_digests.to_vec();
    reusable_workflow_digests.sort();
    reusable_workflow_digests.dedup();
    ScmSourceIdentity {
        normalized_event_digest: event.normalized_digest.clone(),
        source_commit: source_commit.to_owned(),
        base_commit: base_commit.map(str::to_owned),
        workflow_path: inputs.workflow_path.clone(),
        proposed_workflow_digest: inputs.proposed_workflow_digest.clone(),
        base_workflow_digest: inputs.base_workflow_digest.clone(),
        proposed_lockfile_digest: inputs.proposed_lockfile_digest.clone(),
        base_lockfile_digest: inputs.base_lockfile_digest.clone(),
        proposed_approval_subject_digest: inputs.proposed_approval_subject_digest.clone(),
        reusable_workflow_digests,
        policy_version_ids: inputs.policy_version_ids.clone(),
    }
}

const fn proposed_analysis_failure_name(failure: ProposedAnalysisFailure) -> &'static str {
    match failure {
        ProposedAnalysisFailure::WorkflowNotUtf8 => "workflow-not-utf8",
        ProposedAnalysisFailure::LockfileInvalid => "lockfile-invalid",
        ProposedAnalysisFailure::WorkflowInvalid => "workflow-invalid",
    }
}

fn workflow_approval_evidence(
    event: &EventEnvelope,
    inputs: &WorkflowSourceInputs,
    approval: &ApprovalRequest,
) -> Result<WorkflowDefinitionApprovalEvidence, TaskFailure> {
    if approval.status != ApprovalStatus::Approved
        || approval.kind != ApprovalKind::WorkflowDefinition
    {
        return Err(TaskFailure::terminal(
            "workflow-definition approval is not currently approved",
        ));
    }
    let approved_unix_ms = approval
        .decisions
        .values()
        .filter(|decision| decision.decision == ApprovalDecisionKind::Approve)
        .map(|decision| decision.decided_unix_ms)
        .max()
        .ok_or_else(|| {
            TaskFailure::terminal("approved workflow request has no approval decision")
        })?;
    let base = event.base.as_ref().ok_or_else(|| {
        TaskFailure::terminal("workflow-definition approval requires a pull request base")
    })?;
    let base_workflow_digest = inputs.base_workflow_digest.clone().ok_or_else(|| {
        TaskFailure::terminal("workflow-definition approval lost its base workflow identity")
    })?;
    let proposed_approval_subject_digest = inputs
        .proposed_approval_subject_digest
        .clone()
        .ok_or_else(|| {
            TaskFailure::terminal("workflow-definition approval lost its proposed subject")
        })?;
    if proposed_approval_subject_digest != approval.subject_digest {
        return Err(TaskFailure::terminal(
            "workflow-definition approval subject changed during re-planning",
        ));
    }
    Ok(WorkflowDefinitionApprovalEvidence {
        approval_id: approval.id.clone(),
        normalized_event_digest: event.normalized_digest.clone(),
        event_received_unix_ms: event.received_unix_ms,
        repository_full_name: event.repository.full_name.clone(),
        source_commit: event.source.commit.clone(),
        base_commit: base.commit.clone(),
        workflow_path: inputs.workflow_path.clone(),
        proposed_workflow_digest: inputs.proposed_workflow_digest.clone(),
        base_workflow_digest,
        proposed_lockfile_digest: inputs.proposed_lockfile_digest.clone(),
        base_lockfile_digest: inputs.base_lockfile_digest.clone(),
        proposed_approval_subject_digest,
        policy_version_ids: inputs.policy_version_ids.clone(),
        approved_unix_ms,
        expires_unix_ms: approval.expires_unix_ms,
    })
}

struct ExactWorkflowApprovalVerifier<'a> {
    approval: &'a ApprovalRequest,
}

impl WorkflowDefinitionApprovalVerifier for ExactWorkflowApprovalVerifier<'_> {
    fn verify(
        &self,
        evidence: &WorkflowDefinitionApprovalEvidence,
    ) -> Result<(), WorkflowSourceError> {
        let approved_unix_ms = self
            .approval
            .decisions
            .values()
            .filter(|decision| decision.decision == ApprovalDecisionKind::Approve)
            .map(|decision| decision.decided_unix_ms)
            .max();
        if self.approval.status != ApprovalStatus::Approved
            || self.approval.kind != ApprovalKind::WorkflowDefinition
            || self.approval.id != evidence.approval_id
            || self.approval.subject_digest != evidence.proposed_approval_subject_digest
            || approved_unix_ms != Some(evidence.approved_unix_ms)
            || self.approval.expires_unix_ms != evidence.expires_unix_ms
        {
            return Err(WorkflowSourceError::ApprovalInvalid);
        }
        Ok(())
    }
}

enum ProcessError {
    Task(TaskFailure),
    Worker(ScmWorkerError),
}

impl From<TaskFailure> for ProcessError {
    fn from(value: TaskFailure) -> Self {
        Self::Task(value)
    }
}

impl From<ScmWorkerError> for ProcessError {
    fn from(value: ScmWorkerError) -> Self {
        Self::Worker(value)
    }
}

impl From<ControlPlaneError> for ProcessError {
    fn from(value: ControlPlaneError) -> Self {
        Self::Worker(value.into())
    }
}

#[derive(Debug)]
struct TaskFailure {
    message: &'static str,
    retryable: bool,
    retry_after_ms: Option<u64>,
    source: Option<ControlPlaneError>,
}

impl TaskFailure {
    const fn terminal(message: &'static str) -> Self {
        Self {
            message,
            retryable: false,
            retry_after_ms: None,
            source: None,
        }
    }

    const fn retryable(message: &'static str) -> Self {
        Self {
            message,
            retryable: true,
            retry_after_ms: None,
            source: None,
        }
    }

    fn rate_limited(message: &'static str, retry_after_seconds: u64) -> Self {
        Self {
            message,
            retryable: true,
            retry_after_ms: retry_after_seconds.checked_mul(1_000),
            source: None,
        }
    }

    fn control(source: ControlPlaneError) -> Self {
        let retryable = matches!(
            &source,
            ControlPlaneError::Sqlite(_)
                | ControlPlaneError::Poisoned
                | ControlPlaneError::InstallationSafeMode
                | ControlPlaneError::TaskLeaseExpired
        );
        let message = match &source {
            ControlPlaneError::InvalidInput(message) => message,
            ControlPlaneError::IdempotencyConflict => {
                "SCM event conflicts with an existing durable result"
            }
            ControlPlaneError::TaskNotOwned => "SCM task ownership was lost before commit",
            ControlPlaneError::TaskLeaseExpired => "SCM task lease expired before commit",
            ControlPlaneError::InstallationSafeMode => {
                "restore safe mode blocked the SCM event commit"
            }
            _ => "control-plane commit for SCM event failed",
        };
        Self {
            message,
            retryable,
            retry_after_ms: None,
            source: Some(source),
        }
    }

    fn from_repository_lookup(source: ControlPlaneError) -> Self {
        match source {
            ControlPlaneError::NotFound { .. } => {
                Self::retryable("SCM repository is not registered")
            }
            ControlPlaneError::AmbiguousRepositoryIdentity { .. } => {
                Self::terminal("SCM repository identity is ambiguous")
            }
            source => Self::control(source),
        }
    }

    fn from_planner(source: TrustedPlannerError) -> Self {
        match source {
            TrustedPlannerError::Git(_) | TrustedPlannerError::RequiredPathMissing { .. } => {
                Self::retryable("exact Git revision or trusted workflow is unavailable")
            }
            TrustedPlannerError::ReusableSource(
                ReusableWorkflowProviderError::Unavailable | ReusableWorkflowProviderError::Git(_),
            ) => Self::retryable("exact reusable workflow mirror or object is unavailable"),
            TrustedPlannerError::NoExecutableRevision => {
                Self::terminal("SCM event has no executable revision")
            }
            _ => Self::terminal("trusted workflow planning failed"),
        }
    }

    fn from_source_fetch(source: ScmSourceFetchError) -> Self {
        match source {
            ScmSourceFetchError::Unavailable | ScmSourceFetchError::CredentialUnavailable => {
                Self::retryable("authenticated SCM source fetch is temporarily unavailable")
            }
            ScmSourceFetchError::BindingMismatch | ScmSourceFetchError::Rejected => {
                Self::terminal("authenticated SCM source fetch was rejected")
            }
        }
    }

    fn from_git_snapshot(source: GitError) -> Self {
        match source {
            GitError::Timeout | GitError::Filesystem(_, _) | GitError::Capture(_) => {
                Self::retryable("source snapshot construction is temporarily unavailable")
            }
            _ => Self::terminal("source snapshot construction rejected repository contents"),
        }
    }
}

struct RejectWorkflowApproval;

impl WorkflowDefinitionApprovalVerifier for RejectWorkflowApproval {
    fn verify(
        &self,
        _evidence: &WorkflowDefinitionApprovalEvidence,
    ) -> Result<(), WorkflowSourceError> {
        Err(WorkflowSourceError::ApprovalInvalid)
    }
}

#[derive(Clone)]
struct SecureMirrorRoot {
    canonical: PathBuf,
    identity: DirectoryIdentity,
}

impl std::fmt::Debug for SecureMirrorRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureMirrorRoot")
            .field("canonical", &self.canonical)
            .finish()
    }
}

impl SecureMirrorRoot {
    fn open(path: &Path) -> Result<Self, MirrorPathError> {
        reject_lexical_traversal(path)?;
        reject_symlink_components(path)?;
        let metadata = secure_directory_metadata(path)?;
        let canonical = path
            .canonicalize()
            .map_err(|source| MirrorPathError::Io(path.to_owned(), source))?;
        reject_symlink_components(&canonical)?;
        let canonical_metadata = secure_directory_metadata(&canonical)?;
        let identity = DirectoryIdentity::new(&metadata);
        if identity != DirectoryIdentity::new(&canonical_metadata) {
            return Err(MirrorPathError::Changed(path.to_owned()));
        }
        Ok(Self {
            canonical,
            identity,
        })
    }

    fn open_repository(
        &self,
        owner: &str,
        name: &str,
    ) -> Result<SecureGitRepository, MirrorPathError> {
        validate_component(owner)?;
        validate_component(name)?;
        self.revalidate()?;
        let owner_path = self.canonical.join(owner);
        let repository_path = owner_path.join(name);
        let owner_identity = DirectoryIdentity::new(&secure_directory_metadata(&owner_path)?);
        let repository_identity =
            DirectoryIdentity::new(&secure_directory_metadata(&repository_path)?);
        let git_directory = repository_path.join(".git");
        let git_metadata = fs::symlink_metadata(&git_directory)
            .map_err(|source| MirrorPathError::Io(git_directory.clone(), source))?;
        if git_metadata.file_type().is_symlink() || !git_metadata.is_dir() {
            return Err(MirrorPathError::Unsafe(git_directory));
        }
        let git_identity = DirectoryIdentity::new(&git_metadata);
        let canonical_repository = repository_path
            .canonicalize()
            .map_err(|source| MirrorPathError::Io(repository_path.clone(), source))?;
        if canonical_repository != repository_path {
            return Err(MirrorPathError::Unsafe(repository_path));
        }
        let repository = GitRepository::open(&canonical_repository, GitLimits::default())
            .map_err(MirrorPathError::Git)?;
        self.revalidate()?;
        let secured = SecureGitRepository {
            root: self.clone(),
            repository,
            owner_path,
            repository_path: canonical_repository,
            git_directory,
            owner_identity,
            repository_identity,
            git_identity,
        };
        secured.revalidate()?;
        Ok(secured)
    }

    fn revalidate(&self) -> Result<(), MirrorPathError> {
        reject_symlink_components(&self.canonical)?;
        let metadata = secure_directory_metadata(&self.canonical)?;
        if DirectoryIdentity::new(&metadata) != self.identity {
            return Err(MirrorPathError::Changed(self.canonical.clone()));
        }
        Ok(())
    }
}

struct SecureGitRepository {
    root: SecureMirrorRoot,
    repository: GitRepository,
    owner_path: PathBuf,
    repository_path: PathBuf,
    git_directory: PathBuf,
    owner_identity: DirectoryIdentity,
    repository_identity: DirectoryIdentity,
    git_identity: DirectoryIdentity,
}

impl SecureGitRepository {
    const fn repository(&self) -> &GitRepository {
        &self.repository
    }

    fn revalidate(&self) -> Result<(), MirrorPathError> {
        self.root.revalidate()?;
        require_directory_identity(&self.owner_path, self.owner_identity, true)?;
        require_directory_identity(&self.repository_path, self.repository_identity, true)?;
        require_directory_identity(&self.git_directory, self.git_identity, false)
    }
}

struct MirrorReusableSourceProvider<'a> {
    mirror_root: Option<&'a SecureMirrorRoot>,
    current_repository: &'a GitRepository,
    current_owner: &'a str,
    current_name: &'a str,
    endpoints: &'a GitHubProviderEndpoints,
}

impl ReusableWorkflowSourceProvider for MirrorReusableSourceProvider<'_> {
    fn load_exact(
        &self,
        reference: &str,
        commit: &str,
        _digest: &ContentDigest,
    ) -> Result<Vec<u8>, ReusableWorkflowProviderError> {
        let location = parse_github_workflow_reference(reference, self.endpoints)?;
        if location.owner == self.current_owner && location.name == self.current_name {
            authenticate_github_mirror(
                self.current_repository,
                &location.owner,
                &location.name,
                self.endpoints,
            )?;
            let blob = self
                .current_repository
                .read_blob(commit, &location.path)
                .map_err(classify_reusable_git_error)?;
            return Ok(blob.bytes);
        }

        let repository = self
            .mirror_root
            .ok_or(ReusableWorkflowProviderError::Unavailable)?
            .open_repository(&location.owner, &location.name)
            .map_err(classify_reusable_mirror_error)?;
        authenticate_github_mirror(
            repository.repository(),
            &location.owner,
            &location.name,
            self.endpoints,
        )?;
        let blob = repository
            .repository()
            .read_blob(commit, &location.path)
            .map_err(classify_reusable_git_error)?;
        repository
            .revalidate()
            .map_err(classify_reusable_mirror_error)?;
        Ok(blob.bytes)
    }
}

fn authenticate_github_mirror(
    repository: &GitRepository,
    owner: &str,
    name: &str,
    endpoints: &GitHubProviderEndpoints,
) -> Result<(), ReusableWorkflowProviderError> {
    let origin = repository
        .remote_origin_url()
        .map_err(|_| ReusableWorkflowProviderError::ForeignOrigin)?;
    let expected = endpoints
        .repository_clone_url(owner, name)
        .map_err(|_| ReusableWorkflowProviderError::ForeignOrigin)?;
    let github_dot_com_legacy_ssh = endpoints.web_origin() == "https://github.com"
        && (origin == format!("ssh://git@github.com/{owner}/{name}.git")
            || origin == format!("git@github.com:{owner}/{name}.git"));
    if origin == expected || github_dot_com_legacy_ssh {
        Ok(())
    } else {
        Err(ReusableWorkflowProviderError::ForeignOrigin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitHubWorkflowLocation {
    owner: String,
    name: String,
    path: String,
}

fn parse_github_workflow_reference(
    reference: &str,
    endpoints: &GitHubProviderEndpoints,
) -> Result<GitHubWorkflowLocation, ReusableWorkflowProviderError> {
    if reference.is_empty()
        || reference.chars().any(char::is_whitespace)
        || reference.chars().any(char::is_control)
    {
        return Err(ReusableWorkflowProviderError::UnsupportedReference);
    }
    let locator = reference
        .rsplit_once('@')
        .filter(|(_, selector)| !selector.is_empty())
        .map(|(locator, _)| locator)
        .ok_or(ReusableWorkflowProviderError::UnsupportedReference)?;
    let https_prefix = format!("git+{}/", endpoints.web_origin());
    let repository_and_path = if let Some(value) = locator.strip_prefix(&https_prefix) {
        value
    } else if endpoints.web_origin() == "https://github.com" {
        locator
            .strip_prefix("git+ssh://git@github.com/")
            .ok_or(ReusableWorkflowProviderError::ForeignOrigin)?
    } else {
        return Err(ReusableWorkflowProviderError::ForeignOrigin);
    };
    let (repository, path) = repository_and_path
        .rsplit_once("//")
        .ok_or(ReusableWorkflowProviderError::UnsupportedReference)?;
    let (owner, name) = repository
        .split_once('/')
        .ok_or(ReusableWorkflowProviderError::UnsupportedReference)?;
    if owner.contains('/') || name.contains('/') {
        return Err(ReusableWorkflowProviderError::UnsupportedReference);
    }
    let name = name
        .strip_suffix(".git")
        .ok_or(ReusableWorkflowProviderError::UnsupportedReference)?;
    validate_component(owner).map_err(|_| ReusableWorkflowProviderError::UnsafePath)?;
    validate_component(name).map_err(|_| ReusableWorkflowProviderError::UnsafePath)?;
    let normalized =
        normalize_relative_path(path).map_err(|_| ReusableWorkflowProviderError::UnsafePath)?;
    if normalized != path
        || !matches!(
            path.rsplit_once('.').map(|(_, extension)| extension),
            Some("yaml" | "yml")
        )
    {
        return Err(ReusableWorkflowProviderError::UnsafePath);
    }
    Ok(GitHubWorkflowLocation {
        owner: owner.to_owned(),
        name: name.to_owned(),
        path: normalized,
    })
}

fn classify_reusable_git_error(error: runtrue_git::GitError) -> ReusableWorkflowProviderError {
    match error {
        runtrue_git::GitError::PathNotFound | runtrue_git::GitError::CommandFailed { .. } => {
            ReusableWorkflowProviderError::Unavailable
        }
        error => ReusableWorkflowProviderError::Git(error),
    }
}

fn classify_reusable_mirror_error(error: MirrorPathError) -> ReusableWorkflowProviderError {
    match error {
        MirrorPathError::Unsafe(_) => ReusableWorkflowProviderError::UnsafePath,
        MirrorPathError::Changed(_) => ReusableWorkflowProviderError::Unavailable,
        MirrorPathError::Io(_, source) if source.kind() == io::ErrorKind::NotFound => {
            ReusableWorkflowProviderError::Unavailable
        }
        MirrorPathError::Git(error) => classify_reusable_git_error(error),
        MirrorPathError::Io(_, _) => ReusableWorkflowProviderError::Unavailable,
    }
}

#[derive(Debug, Error)]
pub enum MirrorPathError {
    #[error("path `{0}` contains traversal or a symbolic link")]
    Unsafe(PathBuf),
    #[error("directory `{0}` changed during validation")]
    Changed(PathBuf),
    #[error("filesystem access for `{0}` failed: {1}")]
    Io(PathBuf, #[source] io::Error),
    #[error("Git repository validation failed: {0}")]
    Git(#[source] runtrue_git::GitError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl DirectoryIdentity {
    fn new(metadata: &fs::Metadata) -> Self {
        Self {
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }
}

struct StableIdentity<'a> {
    event: &'a EventEnvelope,
    repository: &'a RepositoryRecord,
}

impl<'a> StableIdentity<'a> {
    const fn new(event: &'a EventEnvelope, repository: &'a RepositoryRecord) -> Self {
        Self { event, repository }
    }

    fn id(&self, prefix: &str, domain: &[u8], suffix: &[u8]) -> String {
        let mut hash = Sha256::new();
        hash.update(b"runtrue.server.scm-worker.identity.v1\0");
        hash.update(domain);
        hash.update([0]);
        hash.update(self.event.normalized_digest.as_str().as_bytes());
        hash.update([0]);
        hash.update(self.event.repository.full_name.as_bytes());
        hash.update([0]);
        hash.update(self.repository.id.as_bytes());
        hash.update([0]);
        hash.update(suffix);
        format!("{prefix}-{}", hex::encode(hash.finalize()))
    }
}

fn workflow_path_allowed(configured_workflow_directory: &str, path: &str) -> bool {
    if normalize_relative_path(path).ok().as_deref() != Some(path) {
        return false;
    }
    let in_configured_directory = path
        .strip_prefix(configured_workflow_directory)
        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1);
    if !in_configured_directory || !(path.ends_with(".yml") || path.ends_with(".yaml")) {
        return false;
    }
    workflow_frontends().frontend_for(path).is_ok()
}

fn workflow_identity_suffix(path: &str) -> &[u8] {
    path.as_bytes()
}

fn proposed_identity_suffix(workflow_suffix: &[u8]) -> Vec<u8> {
    if workflow_suffix.is_empty() {
        return b"proposed".to_vec();
    }
    let mut suffix = Vec::with_capacity(workflow_suffix.len() + 1 + b"proposed".len());
    suffix.extend_from_slice(workflow_suffix);
    suffix.push(0);
    suffix.extend_from_slice(b"proposed");
    suffix
}

fn discover_workflow_paths(
    repository: &GitRepository,
    trusted_commit: &str,
    configured_workflow_directory: &str,
) -> Result<Vec<String>, TaskFailure> {
    let paths = repository
        .regular_files_under(
            trusted_commit,
            configured_workflow_directory,
            MAX_SCM_WORKFLOWS,
        )
        .map_err(TaskFailure::from_git_snapshot)?
        .into_iter()
        .filter(|path| workflow_path_allowed(configured_workflow_directory, path))
        .collect::<BTreeSet<_>>();
    if paths.is_empty() {
        return Err(TaskFailure::terminal(
            "repository contains no workflows supported by the configured frontends",
        ));
    }
    if paths.len() > MAX_SCM_WORKFLOWS {
        return Err(TaskFailure::terminal(
            "repository contains too many SCM workflows",
        ));
    }
    Ok(paths.into_iter().collect())
}

fn source_snapshot_id(
    tenant_id: &str,
    repository_id: &str,
    commit: &str,
    tree_manifest_digest: &ContentDigest,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"runtrue.server.scm-source-snapshot.identity.v1\0");
    for value in [
        tenant_id,
        repository_id,
        commit,
        tree_manifest_digest.as_str(),
    ] {
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    format!("source-snapshot-{}", hex::encode(hash.finalize()))
}

fn validate_config(config: &ScmWorkerConfig) -> Result<(), ScmWorkerBuildError> {
    let normalized = normalize_relative_path(&config.workflow_directory)
        .map_err(|_| ScmWorkerBuildError::InvalidConfiguration("invalid workflow directory"))?;
    if normalized != config.workflow_directory
        || config.worker_id.is_empty()
        || config.worker_id.len() > 512
        || config.worker_id.bytes().any(|byte| byte.is_ascii_control())
        || config.policy_version_ids.is_empty()
        || config.policy_version_ids.len() > 128
        || config.policy_version_ids.iter().any(|value| {
            value.is_empty()
                || value.len() > 512
                || value.bytes().any(|byte| byte.is_ascii_control())
        })
        || config
            .policy_version_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || config.max_attempts == 0
        || config.max_attempts > 32
        || config.lease_duration.is_zero()
        || config.retry_base.is_zero()
        || config.retry_max < config.retry_base
        || config.poll_interval.is_zero()
    {
        return Err(ScmWorkerBuildError::InvalidConfiguration(
            "invalid bounds, worker identity, workflow, or policy versions",
        ));
    }
    Ok(())
}

fn validate_component(value: &str) -> Result<(), MirrorPathError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(MirrorPathError::Unsafe(PathBuf::from(value)));
    }
    Ok(())
}

fn reject_lexical_traversal(path: &Path) -> Result<(), MirrorPathError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(MirrorPathError::Unsafe(path.to_owned()));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), MirrorPathError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|source| MirrorPathError::Io(PathBuf::from("."), source))?
            .join(path)
    };
    let mut checked = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                checked.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => return Err(MirrorPathError::Unsafe(path.to_owned())),
        }
        let metadata = fs::symlink_metadata(&checked)
            .map_err(|source| MirrorPathError::Io(checked.clone(), source))?;
        if metadata.file_type().is_symlink() {
            return Err(MirrorPathError::Unsafe(checked));
        }
    }
    Ok(())
}

fn secure_directory_metadata(path: &Path) -> Result<fs::Metadata, MirrorPathError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| MirrorPathError::Io(path.to_owned(), source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(MirrorPathError::Unsafe(path.to_owned()));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(MirrorPathError::Unsafe(path.to_owned()));
    }
    Ok(metadata)
}

fn require_directory_identity(
    path: &Path,
    expected: DirectoryIdentity,
    require_private_mode: bool,
) -> Result<(), MirrorPathError> {
    let metadata = if require_private_mode {
        secure_directory_metadata(path)?
    } else {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| MirrorPathError::Io(path.to_owned(), source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(MirrorPathError::Unsafe(path.to_owned()));
        }
        metadata
    };
    if DirectoryIdentity::new(&metadata) != expected {
        return Err(MirrorPathError::Changed(path.to_owned()));
    }
    Ok(())
}

fn bounded_failure_message(message: &'static str) -> String {
    message.chars().take(MAX_FAILURE_BYTES).collect()
}

fn duration_ms(duration: Duration) -> Result<u64, ScmWorkerError> {
    u64::try_from(duration.as_millis()).map_err(|_| {
        ControlPlaneError::IntegerRange {
            field: "SCM worker duration",
        }
        .into()
    })
}

fn unix_ms() -> Result<u64, ScmWorkerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(ScmWorkerError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_control_plane::{DurableTaskStatus, RepositoryRecord};
    use runtrue_policy::{ApprovalDecision, Decision};
    use runtrue_scm::{
        ActorIdentity, GitRevision, PullRequestAction, PullRequestEvent, RepositoryIdentity,
    };
    use std::process::Command;

    #[cfg(unix)]
    fn private_directory(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn git(root: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn proposed_workflow_diff_is_bounded_and_excludes_unchanged_edges() {
        let trusted = "name: CI\non: [pull_request]\njobs:\n  build:\n    steps:\n      - run: echo old\nfooter: stable\n";
        let proposed = "name: CI\non: [pull_request]\njobs:\n  build:\n    steps:\n      - run: echo new\n      - run: echo added\nfooter: stable\n";
        let diff = bounded_unified_definition_diff(trusted, proposed).unwrap();

        assert!(diff.contains("-      - run: echo old"));
        assert!(diff.contains("+      - run: echo new"));
        assert!(diff.contains("+      - run: echo added"));
        assert!(diff.contains(" footer: stable"));
        assert!(diff.len() <= MAX_DEFINITION_DIFF_BYTES);
    }

    #[test]
    fn unchanged_definition_has_no_diff() {
        let definition = "name: unchanged\non: [pull_request]\n";
        assert_eq!(
            bounded_unified_definition_diff(definition, definition),
            None
        );
    }

    #[test]
    fn github_repository_token_is_short_lived_scoped_and_redacted() {
        let now = unix_ms().unwrap();
        let canary = "github-installation-token-canary";
        let token = GitHubRepositoryAccessToken::new("9001", "42", canary, now + 60_000).unwrap();
        let debug = format!("{token:?}");
        assert!(!debug.contains(canary));
        assert!(debug.contains("[REDACTED]"));
        assert!(GitHubRepositoryAccessToken::new("9001", "42", canary, now + 1,).is_err());
    }

    #[test]
    fn enterprise_repository_origin_is_exact_host_port_owner_and_name() {
        let endpoints = GitHubProviderEndpoints::new(
            "https://github.example.com:8443",
            "https://github.example.com:8443/api/v3",
        )
        .unwrap();
        let mut repository = ScmRepositoryLinkRecord {
            repository_id: "repository-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            installation_id: "installation-1".to_owned(),
            external_repository_id: "42".to_owned(),
            clone_url: "https://github.example.com:8443/octo/runtrue.git".to_owned(),
            status: "active".to_owned(),
            created_unix_ms: 1,
            updated_unix_ms: 1,
        };
        assert!(exact_github_repository_origin(
            &endpoints,
            &repository,
            "octo",
            "runtrue"
        ));
        for substituted in [
            "https://github.example.com/octo/runtrue.git",
            "https://github.example.com:8443/octo/other.git",
            "https://github.com/octo/runtrue.git",
            "ssh://git@github.example.com/octo/runtrue.git",
        ] {
            repository.clone_url = substituted.to_owned();
            assert!(!exact_github_repository_origin(
                &endpoints,
                &repository,
                "octo",
                "runtrue"
            ));
        }
    }

    fn repository(root: &Path, owner: &str, name: &str, source: Option<&[u8]>) -> String {
        let owner_path = root.join(owner);
        let repository_path = owner_path.join(name);
        private_directory(&owner_path);
        private_directory(&repository_path);
        git(&repository_path, &["init", "--quiet"]);
        git(
            &repository_path,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository_path, &["config", "user.name", "Worker Test"]);
        git(
            &repository_path,
            &[
                "remote",
                "add",
                "origin",
                &format!("https://github.com/{owner}/{name}.git"),
            ],
        );
        if let Some(source) = source {
            fs::write(repository_path.join("ci.yaml"), source).unwrap();
            git(&repository_path, &["add", "ci.yaml"]);
            git(&repository_path, &["commit", "--quiet", "-m", "source"]);
            git(&repository_path, &["rev-parse", "HEAD"])
        } else {
            String::new()
        }
    }

    #[test]
    fn standard_github_actions_workflow_is_discovered_without_native_default() {
        let directory = tempfile::tempdir().unwrap();
        private_directory(directory.path());
        let repository_path = directory.path().join("repository");
        private_directory(&repository_path);
        git(&repository_path, &["init", "--quiet"]);
        git(
            &repository_path,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository_path, &["config", "user.name", "Worker Test"]);
        let workflow_directory = repository_path.join(".github/workflows");
        fs::create_dir_all(&workflow_directory).unwrap();
        fs::write(
            workflow_directory.join("ci.yml"),
            "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n",
        )
        .unwrap();
        git(&repository_path, &["add", ".github/workflows/ci.yml"]);
        git(&repository_path, &["commit", "--quiet", "-m", "workflow"]);
        let commit = git(&repository_path, &["rev-parse", "HEAD"]);
        let repository = GitRepository::open(&repository_path, GitLimits::default()).unwrap();
        assert_eq!(
            discover_workflow_paths(&repository, &commit, ".github/workflows").unwrap(),
            vec![".github/workflows/ci.yml"]
        );
    }

    #[test]
    fn configured_directory_discovers_every_supported_workflow_beneath_it() {
        let directory = tempfile::tempdir().unwrap();
        let repository_path = directory.path().join("repository");
        private_directory(&repository_path);
        git(&repository_path, &["init", "--quiet"]);
        git(
            &repository_path,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository_path, &["config", "user.name", "Worker Test"]);
        let workflow_directory = repository_path.join("automation/workflows/nested");
        fs::create_dir_all(&workflow_directory).unwrap();
        fs::write(workflow_directory.join("build.yaml"), "version: 1\n").unwrap();
        fs::write(
            workflow_directory.join("review.github.yml"),
            "name: Review\n",
        )
        .unwrap();
        fs::write(workflow_directory.join("notes.txt"), "not a workflow\n").unwrap();
        git(&repository_path, &["add", "."]);
        git(&repository_path, &["commit", "--quiet", "-m", "workflows"]);
        let commit = git(&repository_path, &["rev-parse", "HEAD"]);
        let repository = GitRepository::open(&repository_path, GitLimits::default()).unwrap();

        assert_eq!(
            discover_workflow_paths(&repository, &commit, "automation/workflows").unwrap(),
            vec![
                "automation/workflows/nested/build.yaml",
                "automation/workflows/nested/review.github.yml",
            ]
        );
    }

    #[test]
    fn github_reference_parser_rejects_foreign_origins_and_traversal() {
        let endpoints = GitHubProviderEndpoints::github_dot_com();
        assert_eq!(
            parse_github_workflow_reference(
                "git+https://github.com/octo/shared.git//workflows/ci.yaml@v1",
                &endpoints,
            )
            .unwrap(),
            GitHubWorkflowLocation {
                owner: "octo".to_owned(),
                name: "shared".to_owned(),
                path: "workflows/ci.yaml".to_owned(),
            }
        );
        assert!(parse_github_workflow_reference(
            "git+ssh://git@github.com/octo/shared.git//ci.yml@main",
            &endpoints,
        )
        .is_ok());
        assert!(matches!(
            parse_github_workflow_reference(
                "git+https://gitlab.example/octo/shared.git//ci.yaml@v1",
                &endpoints,
            ),
            Err(ReusableWorkflowProviderError::ForeignOrigin)
        ));
        for unsafe_reference in [
            "git+https://github.com/octo/shared.git//../ci.yaml@v1",
            "git+https://github.com/octo/shared.git//workflows//ci.yaml@v1",
            "git+https://github.com/octo/../../shared.git//ci.yaml@v1",
        ] {
            assert!(
                parse_github_workflow_reference(unsafe_reference, &endpoints).is_err(),
                "{unsafe_reference}"
            );
        }

        let enterprise = GitHubProviderEndpoints::new(
            "https://github.example.com",
            "https://github.example.com/api/v3",
        )
        .unwrap();
        assert!(parse_github_workflow_reference(
            "git+https://github.example.com/octo/shared.git//ci.yml@main",
            &enterprise,
        )
        .is_ok());
        assert!(matches!(
            parse_github_workflow_reference(
                "git+https://github.com/octo/shared.git//ci.yml@main",
                &enterprise,
            ),
            Err(ReusableWorkflowProviderError::ForeignOrigin)
        ));
    }

    #[test]
    fn cross_repository_provider_reads_only_authenticated_exact_mirror_objects() {
        let directory = tempfile::tempdir().unwrap();
        private_directory(directory.path());
        let source =
            b"version: 1\njobs:\n  build:\n    steps: [{ run: { command: [\"true\"] } }]\n";
        let current_commit = repository(directory.path(), "octo", "runtrue", Some(source));
        let commit = repository(directory.path(), "octo", "shared", Some(source));
        let root = SecureMirrorRoot::open(directory.path()).unwrap();
        let current = root.open_repository("octo", "runtrue").unwrap();
        let provider = MirrorReusableSourceProvider {
            mirror_root: Some(&root),
            current_repository: current.repository(),
            current_owner: "octo",
            current_name: "runtrue",
            endpoints: &GitHubProviderEndpoints::github_dot_com(),
        };
        let reference = "git+https://github.com/octo/shared.git//ci.yaml@v1";
        assert_eq!(
            provider
                .load_exact(
                    "git+https://github.com/octo/runtrue.git//ci.yaml@v1",
                    &current_commit,
                    &ContentDigest::sha256(source)
                )
                .unwrap(),
            source
        );
        assert_eq!(
            provider
                .load_exact(reference, &commit, &ContentDigest::sha256(source))
                .unwrap(),
            source
        );

        git(
            &directory.path().join("octo/shared"),
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.com/foreign/repository.git",
            ],
        );
        assert!(matches!(
            provider.load_exact(reference, &commit, &ContentDigest::sha256(source)),
            Err(ReusableWorkflowProviderError::ForeignOrigin)
        ));
        assert!(matches!(
            provider.load_exact(
                "git+https://github.com/octo/missing.git//ci.yaml@v1",
                &commit,
                &ContentDigest::sha256(source)
            ),
            Err(ReusableWorkflowProviderError::Unavailable)
        ));
    }

    #[test]
    fn enterprise_reusable_provider_accepts_only_configured_https_origin() {
        let directory = tempfile::tempdir().unwrap();
        private_directory(directory.path());
        let source = b"version: 1\njobs: {}\n";
        let commit = repository(directory.path(), "octo", "runtrue", Some(source));
        let repository_path = directory.path().join("octo").join("runtrue");
        git(
            &repository_path,
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.example.com:8443/octo/runtrue.git",
            ],
        );
        let root = SecureMirrorRoot::open(directory.path()).unwrap();
        let current = root.open_repository("octo", "runtrue").unwrap();
        let endpoints = GitHubProviderEndpoints::new(
            "https://github.example.com:8443",
            "https://github.example.com:8443/api/v3",
        )
        .unwrap();
        let provider = MirrorReusableSourceProvider {
            mirror_root: Some(&root),
            current_repository: current.repository(),
            current_owner: "octo",
            current_name: "runtrue",
            endpoints: &endpoints,
        };
        assert_eq!(
            provider
                .load_exact(
                    "git+https://github.example.com:8443/octo/runtrue.git//ci.yaml@v1",
                    &commit,
                    &ContentDigest::sha256(source),
                )
                .unwrap(),
            source
        );
        assert!(matches!(
            provider.load_exact(
                "git+https://github.com/octo/runtrue.git//ci.yaml@v1",
                &commit,
                &ContentDigest::sha256(source),
            ),
            Err(ReusableWorkflowProviderError::ForeignOrigin)
        ));
    }

    #[test]
    fn changed_pull_request_is_persisted_then_exactly_continued_once_after_dual_approval() {
        const NOW: u64 = 10_000;
        let directory = tempfile::tempdir().unwrap();
        private_directory(directory.path());
        let owner_path = directory.path().join("octo");
        let repository_path = owner_path.join("runtrue");
        private_directory(&owner_path);
        private_directory(&repository_path);
        git(&repository_path, &["init", "--quiet"]);
        git(
            &repository_path,
            &["config", "user.email", "worker@runtrue.invalid"],
        );
        git(&repository_path, &["config", "user.name", "Worker Test"]);
        git(
            &repository_path,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/octo/runtrue.git",
            ],
        );
        fs::create_dir_all(repository_path.join(DEFAULT_SCM_WORKFLOW_DIRECTORY)).unwrap();
        fs::write(
            repository_path.join(DEFAULT_SCM_WORKFLOW_DIRECTORY).join("ci.yaml"),
            b"version: 1\nname: base\non:\n  pull_request: {}\njobs:\n  build:\n    runner: { isolation: microvm }\n    steps:\n      - run: { command: [\"true\"] }\n",
        )
        .unwrap();
        git(&repository_path, &["add", ".runtrue/workflows/ci.yaml"]);
        git(&repository_path, &["commit", "--quiet", "-m", "base"]);
        let base = git(&repository_path, &["rev-parse", "HEAD"]);
        fs::write(
            repository_path.join(DEFAULT_SCM_WORKFLOW_DIRECTORY).join("ci.yaml"),
            b"version: 1\nname: proposed\non:\n  pull_request: {}\njobs:\n  build:\n    trust: trusted-only\n    runner: { isolation: native }\n    steps:\n      - run: { command: [\"true\"] }\n",
        )
        .unwrap();
        git(&repository_path, &["add", ".runtrue/workflows/ci.yaml"]);
        git(&repository_path, &["commit", "--quiet", "-m", "proposed"]);
        let source = git(&repository_path, &["rev-parse", "HEAD"]);

        let mut event = EventEnvelope {
            version: 1,
            provider: ProviderKind::GitHub,
            installation_id: "installation-1".to_owned(),
            repository: RepositoryIdentity {
                external_id: "42".to_owned(),
                owner: "octo".to_owned(),
                name: "runtrue".to_owned(),
                full_name: "octo/runtrue".to_owned(),
                private: false,
                default_branch: Some("main".to_owned()),
            },
            event_id: "delivery-1".to_owned(),
            event_type: EventType::PullRequest {
                action: PullRequestAction::Synchronize,
            },
            actor: ActorIdentity {
                external_id: "7".to_owned(),
                login: "contributor".to_owned(),
                is_bot: false,
            },
            source: GitRevision {
                commit: source,
                ref_name: Some("feature".to_owned()),
                repository_full_name: Some("octo/runtrue".to_owned()),
            },
            base: Some(GitRevision {
                commit: base,
                ref_name: Some("main".to_owned()),
                repository_full_name: Some("octo/runtrue".to_owned()),
            }),
            ref_name: Some("main".to_owned()),
            pull_request: Some(PullRequestEvent {
                number: 17,
                draft: false,
                merged: false,
            }),
            issue_comment: None,
            check_run: None,
            changed_paths: vec![".runtrue/workflows/ci.yaml".to_owned()],
            received_unix_ms: NOW - 100,
            raw_payload_digest: ContentDigest::sha256(b"raw"),
            normalized_digest: ContentDigest::sha256(b"placeholder"),
        };
        event.normalized_digest =
            ContentDigest::sha256(event.canonical_normalized_bytes().unwrap());

        let control = Arc::new(ControlPlane::open_in_memory("installation-1", NOW).unwrap());
        control
            .create_repository(&RepositoryRecord {
                id: "repo-1".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                owner: "octo".to_owned(),
                name: "runtrue".to_owned(),
                default_branch: "main".to_owned(),
                visibility: "public".to_owned(),
                created_unix_ms: NOW,
            })
            .unwrap();
        control
            .enqueue_task(&DurableTask {
                id: "scm-event-task".to_owned(),
                kind: SCM_TASK_KIND.to_owned(),
                payload: serde_json::to_value(&event).unwrap(),
                status: DurableTaskStatus::Pending,
                available_unix_ms: NOW,
                attempts: 0,
                lease_owner: None,
                lease_expires_unix_ms: None,
                last_error: None,
                created_unix_ms: NOW,
                completed_unix_ms: None,
            })
            .unwrap();
        let mut config = ScmWorkerConfig::new(directory.path(), "scm-worker");
        config.policy_version_ids = vec!["policy-v1".to_owned()];
        let worker = ScmTaskWorker::new(
            Arc::clone(&control),
            Arc::new(CapsuleSigningKey::from_seed([71_u8; 32])),
            config,
            None,
            None,
        )
        .unwrap();
        let first = worker.process_once_at(NOW).unwrap();
        assert!(matches!(
            first,
            ScmWorkerTick::Completed {
                run_id: Some(_),
                replayed: false,
                ..
            }
        ));
        let analysis = control
            .scm_proposed_analysis_for_task("scm-event-task")
            .unwrap();
        assert_eq!(
            analysis.status,
            ScmProposedAnalysisStatus::Valid,
            "{analysis:?}"
        );
        let proposed_capsule_id = analysis.proposed_capsule_id.unwrap();
        let approvals = control
            .approval_requests_for_capsule(&proposed_capsule_id)
            .unwrap();
        assert_eq!(approvals.len(), 2);
        for (index, approval) in approvals.iter().enumerate() {
            control
                .decide_approval_idempotent(
                    &format!("approve-{index}"),
                    &approval.id,
                    ApprovalDecision {
                        actor_id: "bootstrap".to_owned(),
                        decision: Decision::Approve,
                        reason: "reviewed exact proposed capsule".to_owned(),
                        rule_id: "bootstrap-security-review".to_owned(),
                        subject_digest: approval.subject_digest.clone(),
                        decided_unix_ms: NOW + 1 + index as u64,
                    },
                    NOW + 1 + index as u64,
                )
                .unwrap();
        }
        let continued = worker.process_once_at(NOW + 3).unwrap();
        let proposed_run_id = match continued {
            ScmWorkerTick::Completed {
                run_id: Some(run_id),
                replayed: false,
                ..
            } => run_id,
            other => panic!("unexpected continuation tick: {other:?}"),
        };
        let raced = worker.process_once_at(NOW + 4).unwrap();
        assert!(matches!(
            raced,
            ScmWorkerTick::Completed {
                run_id: Some(run_id),
                replayed: true,
                ..
            } if run_id == proposed_run_id
        ));
        assert_eq!(control.jobs_for_run(&proposed_run_id).unwrap().len(), 1);
        assert!(control
            .approval_requests_for_capsule(&proposed_capsule_id)
            .unwrap()
            .into_iter()
            .all(|approval| approval.status == ApprovalStatus::Consumed));
    }
}
#[test]
fn github_provider_ids_and_permissions_fail_closed() {
    assert_eq!(parse_github_external_id("9001").unwrap(), 9001);
    for invalid in ["", "0", "installation-1", "-1", "42.0"] {
        assert!(parse_github_external_id(invalid).is_err(), "{invalid}");
    }
    assert!(github_read_permissions(&serde_json::json!({
        "metadata": "read",
        "contents": "write",
        "checks": "write",
        "issues": "write",
        "statuses": "write"
    })));
    assert!(github_check_permissions(&serde_json::json!({
        "metadata": "read",
        "contents": "read",
        "checks": "write"
    })));
    assert!(!github_read_permissions(
        &serde_json::json!({"metadata": "read"})
    ));
    assert!(!github_check_permissions(&serde_json::json!({
        "metadata": "read",
        "checks": "read"
    })));
}

#[test]
fn source_snapshot_identity_converges_across_event_fanout() {
    let tree = ContentDigest::sha256(b"tree");
    let expected = source_snapshot_id("tenant", "repository", "aabbcc", &tree);
    assert_eq!(
        source_snapshot_id("tenant", "repository", "aabbcc", &tree),
        expected
    );
    assert_ne!(
        source_snapshot_id(
            "tenant",
            "repository",
            "ddeeff",
            &ContentDigest::sha256(b"tree")
        ),
        expected
    );
    assert_ne!(
        source_snapshot_id(
            "tenant",
            "repository",
            "aabbcc",
            &ContentDigest::sha256(b"other-tree")
        ),
        expected
    );
}

#[test]
fn github_trigger_patterns_are_bounded_and_path_aware() {
    assert!(github_pattern_matches("main", "main"));
    assert!(github_pattern_matches("release/*", "release/v1"));
    assert!(!github_pattern_matches("release/*", "release/v1/patch"));
    assert!(github_pattern_matches("docs/**", "docs/guide/start.md"));
    assert!(github_pattern_matches("src/?.rs", "src/a.rs"));
    assert!(!github_pattern_matches("src/?.rs", "src/ab.rs"));
    assert!(!github_pattern_matches("[ab]", "a"));
}
