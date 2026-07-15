mod api_tokens;
mod artifacts;
mod cache;
mod database;
mod decode;
mod durable;
mod installation;
mod lifecycle;
mod repositories;
mod runners;
mod runs;
mod scm;
mod validation;
mod workflow;

use api_tokens::*;
use artifacts::*;
pub use artifacts::{artifact_promotion_subject_digest, artifact_scan_subject_digest};
pub use cache::cache_promotion_subject_digest;
use durable::*;
use installation::*;
use repositories::*;
use runners::*;
use runs::*;
use scm::*;

use crate::error::{ControlPlaneError, DecodeError};
#[cfg(test)]
use database::*;
use decode::{
    bounded_json_blob_column, conversion, digest_column, from_i64, json_blob_column, json_column,
    optional_digest_column, optional_u64_column, to_i64, token_digest_column, u64_column,
};
use validation::{validate_idempotency_key, validate_page, validate_text};

use crate::types::{
    AcquireEnvironmentGate, AppendRunnerLogsRequest, ArtifactCatalogRecord,
    ArtifactDownloadTicketRecord, ArtifactMetrics, ArtifactPromotionIntent,
    ArtifactScanJournalRecord, ArtifactScanState, AuthenticatedRunnerCertificate,
    AuthorizeRunnerOidcRequest, BackupPinRecord, BeginGitHubSetupTransaction, BindDeploymentLease,
    CacheAccessObservation, CachePromotionRecord, CachePromotionState, CacheTrustGenerationRecord,
    CacheTrustMetrics, CapsuleApiMetadata, ClaimGitHubLifecycleDelivery,
    CompleteGitHubLifecycleDelivery, CompleteGitHubSetupTransaction, CreateGitHubSetupTransaction,
    CreateRunRequest, CredentialTaintState, DeliveredRunnerSecret, DeploymentMetrics,
    DeploymentRecord, DeploymentRequestRecord, DeploymentRequestStatus, DurableTask,
    DurableTaskStatus, EnrollmentToken, EnrollmentTokenIssueResult, EnrollmentTokenRecord,
    EnvironmentConcurrencyLeaseRecord, EnvironmentRecord, ExpandedJobMaterialization,
    ExpandedJobSetRecord, FailGitHubLifecycleDelivery, GitHubAccountKind,
    GitHubInstallationReconciliationResult, GitHubInstallationRecord,
    GitHubLifecycleDeliveryRecord, GitHubLifecycleDeliveryState, GitHubRepositoryCatalogRecord,
    GitHubRepositoryReconciliationSummary, GitHubRepositorySelection, GitHubSelectedRepository,
    GitHubSetupStatus, GitHubSetupTransactionRecord, HumanIdentityRecord, HumanUserRecord,
    IdempotentResult, InstallationRecoveryState, IssueRunnerSecretRequest, IssueRunnerSourceTicket,
    IssuedEnrollmentToken, JobRecord, LifecycleGcLease, LifecycleGcMetrics, LifecycleGcRoot,
    LifecyclePruneSummary, LinkSelectedGitHubRepository, MaterializeExpandedJobSet,
    NewScmWebhookEvent, NormalizedTriggerEventRecord, PersistedRunner, PolicyVersionRecord,
    PreparedScmExecution, PromotionRequestRecord, PublicSigningResult, R9AuditMetadata,
    ReconcileGitHubInstallation, RecordRunnerBlobUpload, RecordRunnerOidcIssuance,
    RecordScmCheckFailure, RecordScmCheckProgress, RecordScmFetchSnapshotReady, ReplayBundleRecord,
    RepositoryRecord, ReserveGitHubLifecycleDelivery, ReserveScmCheckPublication,
    ReserveScmSourceFetch, RunRecord, RunSourceSnapshotRecord, RunnerCertificateRecord,
    RunnerCertificateRotationRecord, RunnerCertificateStatus, RunnerDataCommit,
    RunnerDataCommitKind, RunnerLogFrameRecord, RunnerPoolRecord, RunnerPoolStatus,
    RunnerSecretLeaseRecord, RunnerSourceDownload, RunnerSourceTicketRecord,
    ScheduleReconciliationSummary, ScheduleTriggerCursor, ScmCheckPublicationRecord,
    ScmCheckPublicationState, ScmCheckPublishTask, ScmContinuationCommit, ScmContinuationContext,
    ScmContinuationResolution, ScmExecutionRole, ScmInstallationRecord, ScmPendingExecution,
    ScmPendingExecutionState, ScmProposedAnalysisRecord, ScmProposedAnalysisStatus,
    ScmRepositoryLinkRecord, ScmSourceFetchRecord, ScmSourceFetchState, ScmSourceIdentity,
    ScmTaskCompletion, ScmWebhookEventRecord, SecretMetadataReference, SetGitHubInstallationStatus,
    SignedCapsuleRecord, SignerPolicyRecord, SigningResultJournalRecord, SigningResultReservation,
    SigningResultState, SourceSnapshotRecord, SourceSnapshotState, StorageReservationState,
    StorageTicketBinding, StorageTicketBindingState, TenantIdentityRecord, TenantMembershipRecord,
    TenantOidcProviderConfiguration, TenantProviderConfiguration, TenantStorageQuota,
    TenantStorageReservation, TenantStorageUsage, VariableRecord, VariableSnapshot,
    WorkflowSemanticsMetrics,
};
use rand_core::{OsRng, RngCore};
use runtrue_attest::CapsuleVerifyingKey;
use runtrue_audit::{
    verify_chain, AuditEvent, AuditEventData, AuditPrincipal, AuditResource, AuditValue,
};
use runtrue_auth::{
    ApiTokenRecord, AuthContext, AuthError, OidcAuthorizationTransaction, OidcTransactionStatus,
    SessionRecord, TokenHasher,
};
use runtrue_lifecycle::{JobState, RunState};
use runtrue_model::ContentDigest;
use runtrue_oidc::OidcGrant;
use runtrue_policy::{
    ActivatePolicyBundle, ActivePolicyBundleState, ApprovalDecision, ApprovalRequest,
    ApprovalStatus, DenyFirstPolicy, PolicyBundleDraft, PolicyBundleDraftStatus, PolicyError,
    PolicyShadowReport, PolicySimulationReport,
};
use runtrue_scheduler::{Lease, LeaseState, RunnerRecord, RunnerStatus, SchedulingRequirements};
use runtrue_secrets::{
    AuthorizedExternalSecretRelease, ExternalSecretBrokerError, ExternalSecretLeaseMetadata,
    ExternalSecretReleaseAuthority, ExternalSecretReleaseJournal,
    ExternalSecretReleaseJournalEntry, ExternalSecretReleaseReservation,
    ExternalSecretReleaseState, ExternalSecretReserveOutcome, ExternalSecretRevokeOutcome,
    MasterKey, RunnerExternalSecretRequest, SecretIdentity, SecretPlaintext, SecretStatus,
    SecretVault, SecretVaultSnapshot,
};
use runtrue_workflow_ir::ExecutionCapsule;
use rusqlite::{params, Connection, OptionalExtension as _, Row, Transaction, TransactionBehavior};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroize as _;

const MAX_TEXT_BYTES: usize = 8 * 1024;
const MAX_SECRET_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SCM_EXECUTIONS_PER_EVENT: usize = 2;
const MAX_SCM_CONTINUATIONS_PER_DECISION: usize = 64;
const MAX_SCM_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_SCM_REUSABLE_IDENTITIES: usize = 256;
const MAX_CAPSULE_APPROVAL_QUERY: usize = 32;
const MAX_API_TOKEN_ANCESTRY: usize = 32;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 200;
const MAX_R9_IDENTITY_JSON_BYTES: usize = 1024 * 1024;
const MAX_R9_AUTH_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_R9_OIDC_SCOPES: usize = 64;
const MAX_R9_POLICY_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_R10_RECORD_BYTES: usize = 1024 * 1024;
const MAX_R10_IDENTIFIERS: usize = 128;
const MAX_R10_GATE_LEASE_MS: u64 = 15 * 60 * 1_000;
const MAX_R10_SIGNING_RESULT_BYTES: usize = 1024 * 1024;
const MAX_GITHUB_SETUP_LIFETIME_MS: u64 = 15 * 60 * 1_000;
const MAX_GITHUB_SETUP_ATTEMPTS: u32 = 8;
const MAX_GITHUB_SELECTED_REPOSITORIES: usize = 1_000;
const MAX_GITHUB_LIFECYCLE_ATTEMPTS: u32 = 8;
const MAX_GITHUB_LIFECYCLE_LEASE_MS: u64 = 5 * 60 * 1_000;
const MAX_GITHUB_LIFECYCLE_BACKOFF_MS: u64 = 60 * 60 * 1_000;
const MAX_RUNNER_OPEN_LEASE_QUERY: usize = 64;
const MAX_RUNNER_COMPLETION_ARTIFACT_CLAIMS: usize = 128;
const MAX_SCHEDULER_CANDIDATES: usize = 128;
const MAX_MAINTENANCE_LEASES: usize = 64;
const MAX_MAINTENANCE_RUNNERS: usize = 64;
const DEFAULT_TENANT_MAXIMUM_RUNNING_JOBS: u64 = 1_000;
const DEFAULT_TENANT_MAXIMUM_STORED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_TENANT_MAXIMUM_OBJECT_COUNT: u64 = 100_000;
const DEFAULT_RUNNER_OFFLINE_AFTER_MS: u64 = 60_000;
const DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS: u64 = 5 * 60_000;
const LEASE_ACCEPT_WINDOW_MS: u64 = runtrue_scheduler::DEFAULT_ACCEPT_WINDOW_MS;
const LEASE_EXTENSION_MS: u64 = runtrue_scheduler::DEFAULT_LEASE_DURATION_MS;
const LEASE_SETUP_GRACE_MS: u64 = 5 * 60 * 1_000;
const MAX_RUNNER_CERTIFICATE_CHAIN_BYTES: usize = 256 * 1024;
const MAX_EXPANDED_JOB_SET_BYTES: usize = 8 * 1024 * 1024;
const MAX_REMOTE_WORKFLOW_JOBS: usize = 1_024;
const MAX_DUE_SCHEDULES_PER_TICK: usize = 100;
const MAX_CRON_SEARCH_MINUTES: u64 = 366 * 24 * 60;
const MIN_RUN_PRIORITY: i32 = -1_000;
const MAX_RUN_PRIORITY: i32 = 1_000;
const ENROLLMENT_TOKEN_BYTES: usize = 32;
const ENROLLMENT_HASH_DOMAIN: &[u8] = b"runtrue.runner.enrollment-token.v1\0";

/// Canonical posture used for scheduling and workload identity. Deliberately
/// excludes self-reported capabilities, mutable utilization/locality, and
/// connection status.
pub fn authoritative_runner_posture_digest(
    runner: &RunnerRecord,
    inventory_digest: &ContentDigest,
) -> Result<ContentDigest, ControlPlaneError> {
    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct Posture<'a> {
        version: u32,
        runner_id: &'a str,
        tenant_id: &'a str,
        pool_id: &'a str,
        os: runtrue_workflow_ir::OperatingSystem,
        arch: runtrue_workflow_ir::Architecture,
        isolation_backends: &'a BTreeSet<runtrue_workflow_ir::Isolation>,
        logical_cpus: u32,
        memory_bytes: u64,
        storage_bytes: u64,
        region: &'a Option<String>,
        verified_capabilities: &'a BTreeSet<String>,
    }

    validate_runner_record(runner)?;
    let durable = serde_json::to_vec(&Posture {
        version: 1,
        runner_id: &runner.id,
        tenant_id: &runner.tenant_id,
        pool_id: &runner.pool_id,
        os: runner.os,
        arch: runner.arch,
        isolation_backends: &runner.isolation_backends,
        logical_cpus: runner.logical_cpus,
        memory_bytes: runner.memory_bytes,
        storage_bytes: runner.storage_bytes,
        region: &runner.region,
        verified_capabilities: &runner.verified_capabilities,
    })?;
    let mut binding = Vec::with_capacity(durable.len() + inventory_digest.as_str().len() + 64);
    binding.extend_from_slice(b"runtrue.runner.authoritative-posture.v1\0");
    binding.extend_from_slice(&(inventory_digest.as_str().len() as u64).to_be_bytes());
    binding.extend_from_slice(inventory_digest.as_str().as_bytes());
    binding.extend_from_slice(&(durable.len() as u64).to_be_bytes());
    binding.extend_from_slice(&durable);
    Ok(ContentDigest::sha256(binding))
}

pub struct ControlPlane {
    connection: Mutex<Connection>,
    installation_id: String,
}

impl ControlPlane {
    fn connection(&self) -> Result<MutexGuard<'_, Connection>, ControlPlaneError> {
        self.connection
            .lock()
            .map_err(|_| ControlPlaneError::Poisoned)
    }
}

impl fmt::Debug for ControlPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlane")
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

fn hash_serializable(value: &impl Serialize) -> Result<ContentDigest, ControlPlaneError> {
    Ok(ContentDigest::sha256(serde_json::to_vec(value)?))
}

fn create_run_request_hash(request: &CreateRunRequest) -> Result<ContentDigest, ControlPlaneError> {
    #[derive(Serialize)]
    struct IdempotentJob<'a> {
        job_key: &'a str,
        attempt: u32,
        requirements: &'a runtrue_scheduler::SchedulingRequirements,
    }

    #[derive(Serialize)]
    struct IdempotentRun<'a> {
        repository_id: &'a str,
        capsule_id: &'a str,
        priority: i32,
        remote: bool,
        jobs: Vec<IdempotentJob<'a>>,
    }

    hash_serializable(&IdempotentRun {
        repository_id: &request.repository_id,
        capsule_id: &request.capsule_id,
        priority: request.priority,
        remote: request.remote,
        jobs: request
            .jobs
            .iter()
            .map(|job| IdempotentJob {
                job_key: &job.job_key,
                attempt: job.attempt,
                requirements: &job.requirements,
            })
            .collect(),
    })
}

fn require_same_idempotency(
    stored: &ContentDigest,
    requested: &ContentDigest,
) -> Result<(), ControlPlaneError> {
    if stored != requested {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    Ok(())
}

fn idempotency_tx(
    transaction: &Transaction<'_>,
    operation: &str,
    key: &str,
) -> Result<Option<(ContentDigest, String)>, ControlPlaneError> {
    let raw = transaction
        .query_row(
            "SELECT request_hash, resource_id FROM idempotency_records
             WHERE operation = ?1 AND idempotency_key = ?2",
            params![operation, key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    raw.map(|(hash, resource)| Ok((ContentDigest::parse(hash)?, resource)))
        .transpose()
}

fn signed_capsule_row(row: &Row<'_>) -> rusqlite::Result<SignedCapsuleRecord> {
    Ok(SignedCapsuleRecord {
        id: row.get(0)?,
        repository_id: row.get(1)?,
        digest: digest_column(row, 2)?,
        canonical_capsule: row.get(3)?,
        signature: json_column(row, 4)?,
        created_unix_ms: u64_column(row, 5, "created_unix_ms")?,
    })
}

fn invalid_transition(
    entity: &'static str,
    from: &'static str,
    to: &'static str,
) -> ControlPlaneError {
    ControlPlaneError::InvalidTransition { entity, from, to }
}

fn not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

mod deployment;
mod identity;
mod policy;

use deployment::*;
use identity::*;

#[cfg(test)]
mod tests;
