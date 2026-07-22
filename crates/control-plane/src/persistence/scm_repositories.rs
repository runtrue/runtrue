#[cfg(feature = "postgres")]
use super::PostgresInstallationStore;
use super::StoreFuture;
#[cfg(any(feature = "postgres", test))]
use crate::ControlPlaneError;
use crate::{
    BeginGitHubSetupTransaction, CapsuleApiMetadata, ClaimGitHubLifecycleDelivery,
    CompleteGitHubLifecycleDelivery, CompleteGitHubSetupTransaction, ControlPlane,
    CreateGitHubSetupTransaction, CreateRunRequest, FailGitHubLifecycleDelivery,
    GitHubInstallationReconciliationResult, GitHubInstallationRecord,
    GitHubLifecycleDeliveryRecord, GitHubRepositoryCatalogRecord, GitHubSetupTransactionRecord,
    IdempotentResult, LinkSelectedGitHubRepository, NewScmWebhookEvent, PreparedScmExecution,
    ReconcileGitHubInstallation, RecordScmCheckFailure, RecordScmCheckProgress,
    RecordScmFetchSnapshotReady, RepositoryRecord, ReserveGitHubLifecycleDelivery,
    ReserveScmCheckPublication, ReserveScmSourceFetch, RunRecord, ScmCheckPublicationRecord,
    ScmContinuationCommit, ScmContinuationContext, ScmContinuationResolution,
    ScmInstallationRecord, ScmPendingExecution, ScmProposedAnalysisRecord, ScmRepositoryLinkRecord,
    ScmSourceFetchRecord, ScmTaskCompletion, ScmWebhookEventRecord, SetGitHubInstallationStatus,
    SignedCapsuleRecord, WorkflowFrontendReportRecord,
};
#[cfg(feature = "postgres")]
use crate::{
    GitHubAccountKind, GitHubLifecycleDeliveryState, GitHubRepositoryReconciliationSummary,
    GitHubRepositorySelection, GitHubSetupStatus, ScmCheckPublicationState, ScmSourceFetchState,
};
#[cfg(all(test, not(feature = "postgres")))]
use crate::{
    GitHubAccountKind, GitHubRepositorySelection, GitHubSetupStatus, ScmCheckPublicationState,
    ScmSourceFetchState,
};
use runtrue_policy::ApprovalRequest;

#[cfg(feature = "postgres")]
use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource, AuditValue};
#[cfg(feature = "postgres")]
use runtrue_model::normalize_relative_path;
#[cfg(any(feature = "postgres", test))]
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use serde_json::Value;
#[cfg(feature = "postgres")]
use sqlx::{Connection as _, Row as _};
#[cfg(feature = "postgres")]
use std::collections::BTreeMap;

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0005_scm_repositories.sql");

/// Repository registration and provider-neutral SCM linking form one durable
/// boundary. Implementations preserve exact replay and tenant authorization
/// behavior across the embedded and PostgreSQL backends.
pub trait ScmRepositoryStore: Send + Sync {
    fn create_repository<'a>(&'a self, record: &'a RepositoryRecord) -> StoreFuture<'a, ()>;
    fn repository<'a>(&'a self, id: &'a str) -> StoreFuture<'a, RepositoryRecord>;
    fn repository_by_owner_name<'a>(
        &'a self,
        owner: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, RepositoryRecord>;
    fn repositories(&self) -> StoreFuture<'_, Vec<RepositoryRecord>>;
    fn repositories_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<RepositoryRecord>>;
    fn repository_workflow_directory<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
    ) -> StoreFuture<'a, Option<String>>;
    fn set_repository_workflow_directory<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        workflow_directory: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, String>;
    fn create_scm_installation<'a>(
        &'a self,
        record: &'a ScmInstallationRecord,
    ) -> StoreFuture<'a, IdempotentResult<ScmInstallationRecord>>;
    fn scm_installation_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        installation_id: &'a str,
    ) -> StoreFuture<'a, ScmInstallationRecord>;
    fn link_scm_repository<'a>(
        &'a self,
        record: &'a ScmRepositoryLinkRecord,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>>;
    fn record_scm_webhook_event<'a>(
        &'a self,
        event: &'a NewScmWebhookEvent,
    ) -> StoreFuture<'a, IdempotentResult<ScmWebhookEventRecord>>;
    fn scm_webhook_events_for_repository<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        before_unix_ms: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ScmWebhookEventRecord>>;
    fn reserve_scm_source_fetch<'a>(
        &'a self,
        request: &'a ReserveScmSourceFetch,
    ) -> StoreFuture<'a, IdempotentResult<ScmSourceFetchRecord>>;
    fn record_scm_fetch_snapshot_ready<'a>(
        &'a self,
        request: &'a RecordScmFetchSnapshotReady,
    ) -> StoreFuture<'a, ScmSourceFetchRecord>;
    fn mark_scm_fetch_committed<'a>(
        &'a self,
        tenant_id: &'a str,
        fetch_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ScmSourceFetchRecord>;
    fn scm_source_fetch<'a>(
        &'a self,
        tenant_id: &'a str,
        fetch_id: &'a str,
    ) -> StoreFuture<'a, ScmSourceFetchRecord>;
    fn scm_source_fetch_for_task<'a>(
        &'a self,
        tenant_id: &'a str,
        task_id: &'a str,
    ) -> StoreFuture<'a, ScmSourceFetchRecord>;
    fn reserve_scm_check_publication<'a>(
        &'a self,
        request: &'a ReserveScmCheckPublication,
    ) -> StoreFuture<'a, IdempotentResult<ScmCheckPublicationRecord>>;
    fn record_scm_check_progress<'a>(
        &'a self,
        request: &'a RecordScmCheckProgress,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord>;
    fn mark_scm_check_published<'a>(
        &'a self,
        tenant_id: &'a str,
        publication_id: &'a str,
        task_id: &'a str,
        worker_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord>;
    fn record_scm_check_failure<'a>(
        &'a self,
        request: &'a RecordScmCheckFailure,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord>;
    fn scm_check_publication<'a>(
        &'a self,
        tenant_id: &'a str,
        publication_id: &'a str,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord>;
    fn scm_check_publication_by_provider_run<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        installation_id: &'a str,
        provider_check_run_id: u64,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord>;
    fn github_account_id_for_repository<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
    ) -> StoreFuture<'a, String>;
    fn reconcile_github_installation<'a>(
        &'a self,
        request: &'a ReconcileGitHubInstallation,
    ) -> StoreFuture<'a, IdempotentResult<GitHubInstallationReconciliationResult>>;
    fn set_github_installation_status<'a>(
        &'a self,
        request: &'a SetGitHubInstallationStatus,
    ) -> StoreFuture<'a, IdempotentResult<GitHubInstallationRecord>>;
    fn github_installation_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        installation_id: &'a str,
    ) -> StoreFuture<'a, GitHubInstallationRecord>;
    fn github_installation_by_external_id<'a>(
        &'a self,
        web_origin: &'a str,
        api_origin: &'a str,
        external_id: &'a str,
    ) -> StoreFuture<'a, GitHubInstallationRecord>;
    fn github_installations_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<GitHubInstallationRecord>>;
    fn github_repository_catalog_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        installation_id: &'a str,
        include_removed: bool,
        after_external_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<GitHubRepositoryCatalogRecord>>;
    fn link_selected_github_repository<'a>(
        &'a self,
        request: &'a LinkSelectedGitHubRepository,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>>;
    fn github_repository_links_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        installation_id: &'a str,
        after_repository_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ScmRepositoryLinkRecord>>;
    fn suspend_github_repository_link<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        actor_id: &'a str,
        request_id: &'a str,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>>;
    fn create_github_setup_transaction<'a>(
        &'a self,
        r: &'a CreateGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>>;
    fn begin_github_setup_by_state<'a>(
        &'a self,
        state: &'a runtrue_model::ContentDigest,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>>;
    fn begin_github_setup_transaction<'a>(
        &'a self,
        r: &'a BeginGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>>;
    fn reject_github_setup_transaction<'a>(
        &'a self,
        r: &'a BeginGitHubSetupTransaction,
        error: &'a str,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>>;
    fn complete_github_setup_transaction<'a>(
        &'a self,
        r: &'a CompleteGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>>;
    fn reserve_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a ReserveGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>>;
    fn claim_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a ClaimGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, Option<IdempotentResult<GitHubLifecycleDeliveryRecord>>>;
    fn claim_next_github_lifecycle_delivery<'a>(
        &'a self,
        worker_id: &'a str,
        now: u64,
        lease_duration_ms: u64,
    ) -> StoreFuture<'a, Option<GitHubLifecycleDeliveryRecord>>;
    fn complete_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a CompleteGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>>;
    fn fail_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a FailGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>>;
    fn github_repository_for_event<'a>(
        &'a self,
        installation_external_id: &'a str,
        repository_external_id: &'a str,
        owner: &'a str,
        name: &'a str,
    ) -> StoreFuture<
        'a,
        (
            RepositoryRecord,
            ScmInstallationRecord,
            ScmRepositoryLinkRecord,
        ),
    >;
    #[allow(clippy::too_many_arguments)]
    fn complete_scm_task_with_run_idempotent<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        now: u64,
        idempotency_key: &'a str,
        capsule: &'a SignedCapsuleRecord,
        verifying_key: &'a runtrue_attest::CapsuleVerifyingKey,
        metadata: &'a CapsuleApiMetadata,
        request: &'a CreateRunRequest,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>>;
    #[allow(clippy::too_many_arguments)]
    fn complete_scm_task_with_executions_idempotent<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        now: u64,
        idempotency_key: &'a str,
        executions: &'a [PreparedScmExecution],
        analysis: Option<&'a ScmProposedAnalysisRecord>,
        verifying_key: &'a runtrue_attest::CapsuleVerifyingKey,
    ) -> StoreFuture<'a, IdempotentResult<ScmTaskCompletion>>;
    fn scm_pending_execution<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ScmPendingExecution>;
    fn scm_proposed_analysis_for_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> StoreFuture<'a, ScmProposedAnalysisRecord>;
    fn scm_pending_execution_approvals<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>>;
    fn begin_scm_continuation<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        pending_id: &'a str,
        now: u64,
    ) -> StoreFuture<'a, ScmContinuationResolution>;
    fn close_scm_continuation_as_stale<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        pending_id: &'a str,
        reason: &'a str,
        now: u64,
    ) -> StoreFuture<'a, ScmPendingExecution>;
    #[allow(clippy::too_many_arguments)]
    fn complete_scm_continuation_with_run_idempotent<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        pending_id: &'a str,
        now: u64,
        replanned: &'a SignedCapsuleRecord,
        verifying_key: &'a runtrue_attest::CapsuleVerifyingKey,
        metadata: &'a CapsuleApiMetadata,
        context: &'a ScmContinuationContext,
        run: &'a CreateRunRequest,
    ) -> StoreFuture<'a, ScmContinuationCommit>;
    fn store_workflow_frontend_report<'a>(
        &'a self,
        record: &'a WorkflowFrontendReportRecord,
    ) -> StoreFuture<'a, ()>;
    fn workflow_frontend_report<'a>(
        &'a self,
        capsule_id: &'a str,
    ) -> StoreFuture<'a, WorkflowFrontendReportRecord>;
}

#[cfg(feature = "postgres")]
async fn require_scm_task_owner_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    task_id: &str,
    worker: &str,
    now: u64,
    expected_kind: &str,
) -> Result<(), ControlPlaneError> {
    validate_text("task.id", task_id)?;
    validate_text("task.worker", worker)?;
    let row=sqlx::query("SELECT kind,status,lease_owner,lease_expires_unix_ms FROM durable_tasks WHERE id=$1 FOR UPDATE").bind(task_id).fetch_optional(&mut **tx).await?.ok_or_else(||not_found("task",task_id))?;
    let kind: String = row.try_get("kind")?;
    let status: String = row.try_get("status")?;
    let owner: Option<String> = row.try_get("lease_owner")?;
    let expiry: Option<i64> = row.try_get("lease_expires_unix_ms")?;
    if kind != expected_kind
        || status != "claimed"
        || owner.as_deref() != Some(worker)
        || expiry.is_none_or(|x| x <= i64::try_from(now).unwrap_or(i64::MAX))
    {
        return Err(ControlPlaneError::TaskLeaseExpired);
    }
    let safe: bool =
        sqlx::query_scalar("SELECT safe_mode FROM installation_state WHERE singleton=TRUE")
            .fetch_one(&mut **tx)
            .await?;
    if safe {
        return Err(ControlPlaneError::InstallationSafeMode);
    }
    Ok(())
}
#[cfg(feature = "postgres")]
async fn mark_scm_task_completed_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    task_id: &str,
    now: u64,
) -> Result<(), ControlPlaneError> {
    sqlx::query("UPDATE durable_tasks SET status='completed',lease_owner=NULL,lease_expires_unix_ms=NULL,completed_unix_ms=$2 WHERE id=$1").bind(task_id).bind(to_i64(now,"SCM task completion")?).execute(&mut **tx).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn require_scm_continuation_binding_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    task_id: &str,
    pending_id: &str,
) -> Result<(), ControlPlaneError> {
    let payload: Vec<u8> = sqlx::query_scalar("SELECT payload_json FROM durable_tasks WHERE id=$1")
        .bind(task_id)
        .fetch_one(&mut **tx)
        .await?;
    let value: Value = serde_json::from_slice(&payload)?;
    let approval =
        value
            .get("approval_id")
            .and_then(Value::as_str)
            .ok_or(ControlPlaneError::InvalidInput(
                "SCM continuation task is not bound to this pending approval",
            ))?;
    if value.get("pending_execution_id").and_then(Value::as_str) != Some(pending_id) {
        return Err(ControlPlaneError::InvalidInput(
            "SCM continuation task is not bound to this pending approval",
        ));
    }
    let bound:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM scm_pending_executions WHERE id=$1 AND (workflow_approval_id=$2 OR privileged_approval_id=$2))").bind(pending_id).bind(approval).fetch_one(&mut **tx).await?;
    if bound {
        Ok(())
    } else {
        Err(ControlPlaneError::InvalidInput(
            "SCM continuation task is not bound to this pending approval",
        ))
    }
}

#[cfg(feature = "postgres")]
fn validate_signed_capsule_pg(
    c: &SignedCapsuleRecord,
    v: &runtrue_attest::CapsuleVerifyingKey,
) -> Result<(runtrue_workflow_ir::ExecutionCapsule, Vec<u8>), ControlPlaneError> {
    validate_text("capsule.id", &c.id)?;
    validate_text("capsule.repository_id", &c.repository_id)?;
    let decoded: runtrue_workflow_ir::ExecutionCapsule =
        serde_json::from_slice(&c.canonical_capsule)?;
    if decoded.canonical_bytes()? != c.canonical_capsule {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let actual = ContentDigest::sha256(&c.canonical_capsule);
    if actual != c.digest || c.signature.capsule_digest != c.digest {
        return Err(ControlPlaneError::CapsuleDigestMismatch {
            expected: c.digest.clone(),
            actual,
        });
    }
    v.verify_capsule(&decoded, &c.signature)?;
    Ok((decoded, serde_json::to_vec(&c.signature)?))
}
#[cfg(feature = "postgres")]
async fn insert_capsule_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    c: &SignedCapsuleRecord,
    m: &CapsuleApiMetadata,
    signature: &[u8],
) -> Result<(), ControlPlaneError> {
    if m.capsule_id != c.id || m.risk_score > 100 {
        return Err(ControlPlaneError::InvalidInput(
            "capsule API metadata does not match the signed capsule",
        ));
    }
    sqlx::query("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&c.id).bind(&c.repository_id).bind(c.digest.as_str()).bind(&c.canonical_capsule).bind(signature).bind(c.signature.key_id.as_str()).bind(to_i64(c.created_unix_ms,"capsule creation")?).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO capsule_api_metadata(capsule_id,approval_subject_digest,risk_score) VALUES($1,$2,$3)").bind(&c.id).bind(m.approval_subject_digest.as_str()).bind(i32::try_from(m.risk_score).map_err(|_|ControlPlaneError::IntegerRange{field:"capsule risk score"})?).execute(&mut **tx).await?;
    Ok(())
}
#[cfg(feature = "postgres")]
async fn insert_run_jobs_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    r: &CreateRunRequest,
) -> Result<(), ControlPlaneError> {
    validate_text("run.id", &r.id)?;
    validate_text("run.repository_id", &r.repository_id)?;
    validate_text("run.capsule_id", &r.capsule_id)?;
    if !r.remote || r.jobs.is_empty() || r.priority < -1000 || r.priority > 1000 {
        return Err(ControlPlaneError::InvalidInput(
            "invalid remote run request",
        ));
    }
    sqlx::query("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES($1,$2,$3,'created',$4,TRUE,$5)").bind(&r.id).bind(&r.repository_id).bind(&r.capsule_id).bind(r.priority).bind(to_i64(r.created_unix_ms,"run creation")?).execute(&mut **tx).await?;
    for j in &r.jobs {
        validate_text("job.id", &j.id)?;
        validate_text("job.key", &j.job_key)?;
        if j.attempt == 0 {
            return Err(ControlPlaneError::InvalidInput("invalid job attempt"));
        }
        sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES($1,$2,$3,$4,'created',$5,$6)").bind(&j.id).bind(&r.id).bind(&j.job_key).bind(i32::try_from(j.attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"job attempt"})?).bind(serde_json::to_vec(&j.requirements)?).bind(to_i64(r.created_unix_ms,"job creation")?).execute(&mut **tx).await?;
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn run_row_pg(row: &sqlx::postgres::PgRow) -> Result<RunRecord, ControlPlaneError> {
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "created" => runtrue_lifecycle::RunState::Created,
        "running" => runtrue_lifecycle::RunState::Running,
        "succeeded" => runtrue_lifecycle::RunState::Succeeded,
        "failed" => runtrue_lifecycle::RunState::Failed,
        "canceled" => runtrue_lifecycle::RunState::Canceled,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown run state `{other}`"
            )))
        }
    };
    Ok(RunRecord {
        id: row.try_get("id")?,
        repository_id: row.try_get("repository_id")?,
        capsule_id: row.try_get("capsule_id")?,
        status,
        priority: row.try_get("priority")?,
        remote: row.try_get("remote")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "run creation")?,
        started_unix_ms: row
            .try_get::<Option<i64>, _>("started_unix_ms")?
            .map(|x| from_i64(x, "run start"))
            .transpose()?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|x| from_i64(x, "run completion"))
            .transpose()?,
        cancel_reason: row.try_get("cancel_reason")?,
    })
}
#[cfg(feature = "postgres")]
async fn run_by_id_pg<'e, E: sqlx::Executor<'e, Database = sqlx::Postgres>>(
    e: E,
    id: &str,
) -> Result<RunRecord, ControlPlaneError> {
    let row = sqlx::query("SELECT * FROM runs WHERE id=$1")
        .bind(id)
        .fetch_optional(e)
        .await?
        .ok_or_else(|| not_found("run", id))?;
    run_row_pg(&row)
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn complete_scm_single_pg(
    store: &PostgresInstallationStore,
    task: &str,
    worker: &str,
    now: u64,
    key: &str,
    c: &SignedCapsuleRecord,
    v: &runtrue_attest::CapsuleVerifyingKey,
    m: &CapsuleApiMetadata,
    r: &CreateRunRequest,
) -> Result<IdempotentResult<RunRecord>, ControlPlaneError> {
    validate_text("SCM idempotency key", key)?;
    if key.len() > 200 {
        return Err(ControlPlaneError::InvalidInput("invalid idempotency key"));
    }
    let (_, signature) = validate_signed_capsule_pg(c, v)?;
    if r.capsule_id != c.id
        || r.repository_id != c.repository_id
        || r.created_unix_ms != c.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput(
            "SCM capsule, metadata, and remote run do not match",
        ));
    }
    let mut material = b"runtrue.scm.event.run.create.pg.v1\0".to_vec();
    material.extend_from_slice(c.digest.as_str().as_bytes());
    material.extend_from_slice(m.approval_subject_digest.as_str().as_bytes());
    material.extend_from_slice(&serde_json::to_vec(r)?);
    let hash = ContentDigest::sha256(material);
    let mut tx = store.pool().begin().await?;
    require_scm_task_owner_pg(&mut tx, task, worker, now, "scm.event").await?;
    if let Some(row)=sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation='scm.event.run.create' AND idempotency_key=$1").bind(key).fetch_optional(&mut *tx).await?{if row.try_get::<String,_>("request_hash")?!=hash.as_str(){return Err(ControlPlaneError::IdempotencyConflict)}let id:String=row.try_get("resource_id")?;mark_scm_task_completed_pg(&mut tx,task,now).await?;let value=run_by_id_pg(&mut *tx,&id).await?;tx.commit().await?;return Ok(IdempotentResult{value,replayed:true})}
    insert_capsule_pg(&mut tx, c, m, &signature).await?;
    insert_run_jobs_pg(&mut tx, r).await?;
    sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES('scm.event.run.create',$1,$2,$3,$4)").bind(key).bind(hash.as_str()).bind(&r.id).bind(to_i64(r.created_unix_ms,"SCM idempotency")?).execute(&mut *tx).await?;
    mark_scm_task_completed_pg(&mut tx, task, now).await?;
    let value = run_by_id_pg(&mut *tx, &r.id).await?;
    tx.commit().await?;
    Ok(IdempotentResult {
        value,
        replayed: false,
    })
}

#[cfg(feature = "postgres")]
fn scm_pending_row_pg(
    row: &sqlx::postgres::PgRow,
) -> Result<ScmPendingExecution, ControlPlaneError> {
    let role = match row.try_get::<String, _>("role")?.as_str() {
        "direct" => crate::ScmExecutionRole::Direct,
        "trusted-base" => crate::ScmExecutionRole::TrustedBase,
        "proposed-definition" => crate::ScmExecutionRole::ProposedDefinition,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown SCM execution role `{other}`"
            )))
        }
    };
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "awaiting-approval" => crate::ScmPendingExecutionState::AwaitingApproval,
        "continuation-pending" => crate::ScmPendingExecutionState::ContinuationPending,
        "run-created" => crate::ScmPendingExecutionState::RunCreated,
        "denied" => crate::ScmPendingExecutionState::Denied,
        "expired" => crate::ScmPendingExecutionState::Expired,
        "stale" => crate::ScmPendingExecutionState::Stale,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown SCM pending state `{other}`"
            )))
        }
    };
    Ok(ScmPendingExecution {
        id: row.try_get("id")?,
        origin_task_id: row.try_get("origin_task_id")?,
        repository_id: row.try_get("repository_id")?,
        capsule_id: row.try_get("capsule_id")?,
        role,
        state,
        context: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("context_json")?)?,
        run: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("run_request_json")?)?,
        workflow_approval_id: row.try_get("workflow_approval_id")?,
        privileged_approval_id: row.try_get("privileged_approval_id")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "SCM pending creation")?,
        expires_unix_ms: from_i64(row.try_get("expires_unix_ms")?, "SCM pending expiry")?,
        run_id: row.try_get("run_id")?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|x| from_i64(x, "SCM pending completion"))
            .transpose()?,
        last_error: row.try_get("last_error")?,
    })
}
#[cfg(feature = "postgres")]
async fn scm_pending_pool(
    pool: &sqlx::PgPool,
    id: &str,
) -> Result<ScmPendingExecution, ControlPlaneError> {
    let row = sqlx::query("SELECT * FROM scm_pending_executions WHERE id=$1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| not_found("SCM pending execution", id))?;
    scm_pending_row_pg(&row)
}
#[cfg(feature = "postgres")]
async fn scm_pending_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    lock: bool,
) -> Result<ScmPendingExecution, ControlPlaneError> {
    let sql = if lock {
        "SELECT * FROM scm_pending_executions WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM scm_pending_executions WHERE id=$1"
    };
    let row = sqlx::query(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| not_found("SCM pending execution", id))?;
    scm_pending_row_pg(&row)
}
#[cfg(feature = "postgres")]
fn scm_analysis_row_pg(
    row: &sqlx::postgres::PgRow,
) -> Result<ScmProposedAnalysisRecord, ControlPlaneError> {
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "valid" => crate::ScmProposedAnalysisStatus::Valid,
        "invalid" => crate::ScmProposedAnalysisStatus::Invalid,
        "deleted" => crate::ScmProposedAnalysisStatus::Deleted,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown SCM analysis state `{other}`"
            )))
        }
    };
    Ok(ScmProposedAnalysisRecord {
        id: row.try_get("id")?,
        origin_task_id: row.try_get("origin_task_id")?,
        repository_id: row.try_get("repository_id")?,
        status,
        source_identity: serde_json::from_slice(
            &row.try_get::<Vec<u8>, _>("source_identity_json")?,
        )?,
        analysis: row
            .try_get::<Option<Vec<u8>>, _>("analysis_json")?
            .map(|x| serde_json::from_slice(&x))
            .transpose()?,
        failure: row.try_get("failure")?,
        proposed_capsule_id: row.try_get("proposed_capsule_id")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "SCM analysis creation")?,
    })
}
#[cfg(feature = "postgres")]
async fn pending_approvals_pg<'e, E: sqlx::Executor<'e, Database = sqlx::Postgres>>(
    e: E,
    p: &ScmPendingExecution,
) -> Result<Vec<ApprovalRequest>, ControlPlaneError> {
    let ids = [
        p.workflow_approval_id.as_deref(),
        p.privileged_approval_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows =
        sqlx::query("SELECT request_json FROM approval_requests WHERE id=ANY($1) ORDER BY id")
            .bind(&ids)
            .fetch_all(e)
            .await?;
    rows.iter()
        .map(|r| {
            serde_json::from_slice(&r.try_get::<Vec<u8>, _>("request_json")?).map_err(Into::into)
        })
        .collect()
}

#[cfg(feature = "postgres")]
async fn validate_frontend_report_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    r: &WorkflowFrontendReportRecord,
) -> Result<(), ControlPlaneError> {
    validate_text("capsule.id", &r.capsule_id)?;
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT canonical_capsule FROM capsules WHERE id=$1")
        .bind(&r.capsule_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| not_found("capsule", &r.capsule_id))?;
    let c: runtrue_workflow_ir::ExecutionCapsule = serde_json::from_slice(&bytes)?;
    let signed = c
        .context
        .workflow_frontend
        .as_ref()
        .and_then(|p| p.report_digest.as_ref());
    if signed != Some(&ContentDigest::sha256(&r.bytes))
        || r.bytes.len() > 1024 * 1024
        || r.media_type.is_empty()
        || r.media_type.len() > 255
        || !r.media_type.contains('/')
        || r.media_type
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'*' | b','))
    {
        return Err(ControlPlaneError::InvalidInput(
            "workflow frontend report does not match its signed capsule provenance",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn continuation_approval_state(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    p: &ScmPendingExecution,
    now: u64,
) -> Result<&'static str, ControlPlaneError> {
    let ids = [
        p.workflow_approval_id.as_deref(),
        p.privileged_approval_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let rows = sqlx::query("SELECT status,expires_unix_ms FROM approval_requests WHERE id=ANY($1)")
        .bind(&ids)
        .fetch_all(&mut **tx)
        .await?;
    if rows.len() != ids.len() {
        return Ok("stale");
    }
    if rows.iter().any(|r| {
        r.try_get::<String, _>("status")
            .is_ok_and(|s| s == "denied")
    }) {
        return Ok("denied");
    }
    if now >= p.expires_unix_ms
        || rows.iter().any(|r| {
            r.try_get::<i64, _>("expires_unix_ms")
                .is_ok_and(|x| x <= i64::try_from(now).unwrap_or(i64::MAX))
        })
    {
        return Ok("expired");
    }
    if rows.iter().all(|r| {
        r.try_get::<String, _>("status")
            .is_ok_and(|s| s == "approved")
    }) {
        Ok("ready")
    } else {
        Ok("waiting")
    }
}
#[cfg(feature = "postgres")]
async fn begin_scm_continuation_pg(
    store: &PostgresInstallationStore,
    task: &str,
    worker: &str,
    pending_id: &str,
    now: u64,
) -> Result<ScmContinuationResolution, ControlPlaneError> {
    validate_text("SCM pending execution id", pending_id)?;
    let mut tx = store.pool().begin().await?;
    require_scm_task_owner_pg(&mut tx, task, worker, now, "scm.approval.continue").await?;
    require_scm_continuation_binding_pg(&mut tx, task, pending_id).await?;
    let p = scm_pending_tx(&mut tx, pending_id, true).await?;
    let out = match p.state {
        crate::ScmPendingExecutionState::RunCreated => {
            let id = p.run_id.as_deref().ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "completed SCM continuation is missing its run".to_owned(),
                )
            })?;
            mark_scm_task_completed_pg(&mut tx, task, now).await?;
            ScmContinuationResolution::RunCreated(run_by_id_pg(&mut *tx, id).await?)
        }
        crate::ScmPendingExecutionState::Denied
        | crate::ScmPendingExecutionState::Expired
        | crate::ScmPendingExecutionState::Stale => {
            mark_scm_task_completed_pg(&mut tx, task, now).await?;
            ScmContinuationResolution::Closed(p)
        }
        _ => match continuation_approval_state(&mut tx, &p, now).await? {
            "ready" => ScmContinuationResolution::Ready(p),
            "waiting" => {
                sqlx::query(
                    "UPDATE scm_pending_executions SET state='awaiting-approval' WHERE id=$1",
                )
                .bind(pending_id)
                .execute(&mut *tx)
                .await?;
                mark_scm_task_completed_pg(&mut tx, task, now).await?;
                ScmContinuationResolution::Waiting(
                    scm_pending_tx(&mut tx, pending_id, false).await?,
                )
            }
            state => {
                let target = if state == "denied" {
                    "denied"
                } else if state == "expired" {
                    "expired"
                } else {
                    "stale"
                };
                sqlx::query("UPDATE scm_pending_executions SET state=$2,completed_unix_ms=$3,last_error=CASE WHEN $2='stale' THEN 'approval was consumed outside its exact SCM continuation' ELSE NULL END WHERE id=$1").bind(pending_id).bind(target).bind(to_i64(now,"SCM continuation close")?).execute(&mut *tx).await?;
                mark_scm_task_completed_pg(&mut tx, task, now).await?;
                ScmContinuationResolution::Closed(scm_pending_tx(&mut tx, pending_id, false).await?)
            }
        },
    };
    tx.commit().await?;
    Ok(out)
}
#[cfg(feature = "postgres")]
async fn close_scm_continuation_pg(
    store: &PostgresInstallationStore,
    task: &str,
    worker: &str,
    pending_id: &str,
    reason: &str,
    now: u64,
) -> Result<ScmPendingExecution, ControlPlaneError> {
    validate_text("SCM stale reason", reason)?;
    let mut tx = store.pool().begin().await?;
    require_scm_task_owner_pg(&mut tx, task, worker, now, "scm.approval.continue").await?;
    require_scm_continuation_binding_pg(&mut tx, task, pending_id).await?;
    let p = scm_pending_tx(&mut tx, pending_id, true).await?;
    if matches!(
        p.state,
        crate::ScmPendingExecutionState::AwaitingApproval
            | crate::ScmPendingExecutionState::ContinuationPending
    ) {
        sqlx::query("UPDATE scm_pending_executions SET state='stale',completed_unix_ms=$2,last_error=$3 WHERE id=$1").bind(pending_id).bind(to_i64(now,"SCM stale close")?).bind(reason).execute(&mut *tx).await?;
    }
    mark_scm_task_completed_pg(&mut tx, task, now).await?;
    let p = scm_pending_tx(&mut tx, pending_id, false).await?;
    tx.commit().await?;
    Ok(p)
}

#[cfg(feature = "postgres")]
fn approval_status_pg(s: runtrue_policy::ApprovalStatus) -> &'static str {
    match s {
        runtrue_policy::ApprovalStatus::Pending => "pending",
        runtrue_policy::ApprovalStatus::Approved => "approved",
        runtrue_policy::ApprovalStatus::Denied => "denied",
        runtrue_policy::ApprovalStatus::Expired => "expired",
        runtrue_policy::ApprovalStatus::Consumed => "consumed",
    }
}

#[cfg(feature = "postgres")]
async fn insert_or_reuse_scm_approval_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repository_id: &str,
    capsule_id: &str,
    approval: &ApprovalRequest,
    now: u64,
) -> Result<ApprovalRequest, ControlPlaneError> {
    if approval.kind == runtrue_policy::ApprovalKind::PrivilegedExecution && !approval.rule.one_shot
    {
        let rows = sqlx::query(
            "SELECT request_json FROM approval_requests
             WHERE repository_id=$1 AND subject_digest=$2
               AND status IN ('pending','approved') AND expires_unix_ms>$3
             ORDER BY created_unix_ms,id",
        )
        .bind(repository_id)
        .bind(approval.subject_digest.as_str())
        .bind(to_i64(now, "approval reuse")?)
        .fetch_all(&mut **tx)
        .await?;
        for row in rows {
            let candidate: ApprovalRequest =
                serde_json::from_slice(&row.try_get::<Vec<u8>, _>("request_json")?)?;
            if candidate.kind == approval.kind
                && candidate.subject_digest == approval.subject_digest
                && candidate.risk_score == approval.risk_score
                && candidate.rule == approval.rule
                && matches!(
                    candidate.status,
                    runtrue_policy::ApprovalStatus::Pending
                        | runtrue_policy::ApprovalStatus::Approved
                )
            {
                return Ok(candidate);
            }
        }
    }
    sqlx::query("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&approval.id)
        .bind(repository_id)
        .bind(capsule_id)
        .bind(approval.subject_digest.as_str())
        .bind(approval_status_pg(approval.status))
        .bind(serde_json::to_vec(approval)?)
        .bind(to_i64(approval.created_unix_ms, "approval creation")?)
        .bind(to_i64(approval.expires_unix_ms, "approval expiry")?)
        .execute(&mut **tx)
        .await?;
    Ok(approval.clone())
}

#[cfg(feature = "postgres")]
async fn enqueue_preapproved_continuation_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pending_id: &str,
    approval_id: &str,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let digest = ContentDigest::sha256(
        [
            b"runtrue.scm.preapproved.v1\0".as_slice(),
            pending_id.as_bytes(),
            b"\0",
            approval_id.as_bytes(),
        ]
        .concat(),
    );
    let task_id = format!(
        "scm-continuation-{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let payload = serde_json::to_vec(&serde_json::json!({
        "pending_execution_id": pending_id,
        "approval_id": approval_id,
    }))?;
    sqlx::query("INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,created_unix_ms) VALUES($1,'scm.approval.continue',$2,'pending',$3,0,$3)")
        .bind(task_id)
        .bind(payload)
        .bind(to_i64(now, "preapproved continuation")?)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE scm_pending_executions SET state='continuation-pending' WHERE id=$1")
        .bind(pending_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
struct AuthorizedScmApproval {
    id: String,
    kind: runtrue_policy::ApprovalKind,
    subject_digest: ContentDigest,
    one_shot: bool,
}

#[cfg(feature = "postgres")]
fn approval_kind_pg(kind: runtrue_policy::ApprovalKind) -> &'static str {
    match kind {
        runtrue_policy::ApprovalKind::WorkflowDefinition => "workflow-definition",
        runtrue_policy::ApprovalKind::PrivilegedExecution => "privileged-execution",
        runtrue_policy::ApprovalKind::EnvironmentDeployment => "environment-deployment",
        runtrue_policy::ApprovalKind::ArtifactPromotion => "artifact-promotion",
        runtrue_policy::ApprovalKind::BreakGlass => "break-glass",
    }
}

#[cfg(feature = "postgres")]
async fn authorize_required_scm_approval_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    capsule_id: &str,
    approval_subject: &ContentDigest,
    run_subject: &ContentDigest,
    kind: runtrue_policy::ApprovalKind,
    now: u64,
) -> Result<AuthorizedScmApproval, ControlPlaneError> {
    let repository_id: String =
        sqlx::query_scalar("SELECT repository_id FROM capsules WHERE id=$1")
            .bind(capsule_id)
            .fetch_one(&mut **tx)
            .await?;
    let rows = sqlx::query(
        "SELECT id,capsule_id,request_json FROM approval_requests
         WHERE subject_digest=$2 AND status='approved'
           AND (capsule_id=$1 OR repository_id=$3)
         ORDER BY created_unix_ms,id FOR UPDATE",
    )
    .bind(capsule_id)
    .bind(approval_subject.as_str())
    .bind(&repository_id)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        let approval_id: String = row.try_get("id")?;
        let approval_capsule_id: String = row.try_get("capsule_id")?;
        let mut approval: ApprovalRequest =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("request_json")?)?;
        let reusable_repository_grant =
            kind == runtrue_policy::ApprovalKind::PrivilegedExecution && !approval.rule.one_shot;
        if approval.kind != kind
            || (approval_capsule_id != capsule_id && !reusable_repository_grant)
        {
            continue;
        }
        approval
            .authorize(approval_subject, now)
            .map_err(|_| ControlPlaneError::ApprovalRequired)?;
        sqlx::query("UPDATE approval_requests SET status=$2,request_json=$3 WHERE id=$1")
            .bind(&approval_id)
            .bind(approval_status_pg(approval.status))
            .bind(serde_json::to_vec(&approval)?)
            .execute(&mut **tx)
            .await?;
        return Ok(AuthorizedScmApproval {
            id: approval_id,
            kind,
            subject_digest: run_subject.clone(),
            one_shot: approval.rule.one_shot,
        });
    }
    Err(ControlPlaneError::ApprovalRequired)
}
#[cfg(feature = "postgres")]
fn role_name_pg(r: crate::ScmExecutionRole) -> &'static str {
    match r {
        crate::ScmExecutionRole::Direct => "direct",
        crate::ScmExecutionRole::TrustedBase => "trusted-base",
        crate::ScmExecutionRole::ProposedDefinition => "proposed-definition",
    }
}
#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn complete_scm_executions_pg(
    store: &PostgresInstallationStore,
    task: &str,
    worker: &str,
    now: u64,
    key: &str,
    executions: &[PreparedScmExecution],
    analysis: Option<&ScmProposedAnalysisRecord>,
    verifier: &runtrue_attest::CapsuleVerifyingKey,
) -> Result<IdempotentResult<ScmTaskCompletion>, ControlPlaneError> {
    validate_text("SCM idempotency key", key)?;
    if executions.is_empty() || executions.len() > 2 {
        return Err(ControlPlaneError::InvalidInput(
            "SCM event must produce one or two bounded executions",
        ));
    }
    let material=executions.iter().map(|e|serde_json::json!({"capsule":e.capsule.digest,"metadata":e.metadata,"run":e.run,"approvals":e.approvals,"continuation":e.continuation,"report":e.workflow_frontend_report.as_ref().map(|r|ContentDigest::sha256(&r.bytes))})).collect::<Vec<_>>();
    let hash = ContentDigest::sha256(serde_json::to_vec(&(material, analysis))?);
    let mut tx = store.pool().begin().await?;
    require_scm_task_owner_pg(&mut tx, task, worker, now, "scm.event").await?;
    if let Some(row) =
        sqlx::query("SELECT request_hash,result_json FROM scm_task_results WHERE task_id=$1")
            .bind(task)
            .fetch_optional(&mut *tx)
            .await?
    {
        if row.try_get::<String, _>("request_hash")? != hash.as_str() {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let value = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("result_json")?)?;
        tx.commit().await?;
        return Ok(IdempotentResult {
            value,
            replayed: true,
        });
    }
    let mut run_ids = Vec::new();
    let mut pending_ids = Vec::new();
    for e in executions {
        let (_, signature) = validate_signed_capsule_pg(&e.capsule, verifier)?;
        if e.capsule.created_unix_ms != e.run.created_unix_ms
            || e.run.capsule_id != e.capsule.id
            || e.run.repository_id != e.capsule.repository_id
        {
            return Err(ControlPlaneError::InvalidInput(
                "SCM result timestamps or identities do not match",
            ));
        }
        insert_capsule_pg(&mut tx, &e.capsule, &e.metadata, &signature).await?;
        if let Some(report) = &e.workflow_frontend_report {
            validate_frontend_report_pg(&mut tx, report).await?;
            sqlx::query("INSERT INTO workflow_frontend_reports(capsule_id,media_type,report_bytes) VALUES($1,$2,$3)").bind(&report.capsule_id).bind(&report.media_type).bind(&report.bytes).execute(&mut *tx).await?;
        }
        let mut effective_approvals = Vec::with_capacity(e.approvals.len());
        for approval in &e.approvals {
            effective_approvals.push(
                insert_or_reuse_scm_approval_pg(
                    &mut tx,
                    &e.capsule.repository_id,
                    &e.capsule.id,
                    approval,
                    now,
                )
                .await?,
            );
        }
        if e.approvals.is_empty() {
            insert_run_jobs_pg(&mut tx, &e.run).await?;
            run_ids.push(e.run.id.clone())
        } else {
            let c = e
                .continuation
                .as_ref()
                .ok_or(ControlPlaneError::InvalidInput(
                    "gated SCM execution is missing its continuation context",
                ))?;
            let workflow = effective_approvals
                .iter()
                .find(|a| a.kind == runtrue_policy::ApprovalKind::WorkflowDefinition)
                .map(|a| a.id.as_str());
            let privileged = effective_approvals
                .iter()
                .find(|a| a.kind == runtrue_policy::ApprovalKind::PrivilegedExecution)
                .map(|a| a.id.as_str());
            let expiry = effective_approvals
                .iter()
                .map(|a| a.expires_unix_ms)
                .min()
                .ok_or(ControlPlaneError::ApprovalRequired)?;
            sqlx::query("INSERT INTO scm_pending_executions(id,origin_task_id,repository_id,capsule_id,role,state,context_json,run_request_json,workflow_approval_id,privileged_approval_id,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,'awaiting-approval',$6,$7,$8,$9,$10,$11)").bind(&c.pending_execution_id).bind(task).bind(&e.capsule.repository_id).bind(&e.capsule.id).bind(role_name_pg(c.role)).bind(serde_json::to_vec(c)?).bind(serde_json::to_vec(&e.run)?).bind(workflow).bind(privileged).bind(to_i64(e.capsule.created_unix_ms,"SCM pending creation")?).bind(to_i64(expiry,"SCM pending expiry")?).execute(&mut *tx).await?;
            if effective_approvals
                .iter()
                .all(|approval| approval.status == runtrue_policy::ApprovalStatus::Approved)
            {
                enqueue_preapproved_continuation_pg(
                    &mut tx,
                    &c.pending_execution_id,
                    workflow
                        .or(privileged)
                        .ok_or(ControlPlaneError::ApprovalRequired)?,
                    now,
                )
                .await?;
            }
            pending_ids.push(c.pending_execution_id.clone())
        }
    }
    if let Some(a) = analysis {
        let status = match a.status {
            crate::ScmProposedAnalysisStatus::Valid => "valid",
            crate::ScmProposedAnalysisStatus::Invalid => "invalid",
            crate::ScmProposedAnalysisStatus::Deleted => "deleted",
        };
        sqlx::query("INSERT INTO scm_proposed_analyses(id,origin_task_id,repository_id,status,source_identity_json,analysis_json,failure,proposed_capsule_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(&a.id).bind(&a.origin_task_id).bind(&a.repository_id).bind(status).bind(serde_json::to_vec(&a.source_identity)?).bind(a.analysis.as_ref().map(serde_json::to_vec).transpose()?).bind(&a.failure).bind(&a.proposed_capsule_id).bind(to_i64(a.created_unix_ms,"SCM analysis creation")?).execute(&mut *tx).await?;
    }
    let value = ScmTaskCompletion {
        task_id: task.to_owned(),
        run_ids,
        pending_execution_ids: pending_ids,
        proposed_analysis_id: analysis.map(|a| a.id.clone()),
    };
    let encoded = serde_json::to_vec(&value)?;
    if encoded.len() > 8 * 1024 * 1024 {
        return Err(ControlPlaneError::InvalidInput(
            "SCM durable JSON exceeds its bound",
        ));
    }
    sqlx::query("INSERT INTO scm_task_results(task_id,request_hash,result_json,created_unix_ms) VALUES($1,$2,$3,$4)").bind(task).bind(hash.as_str()).bind(encoded).bind(to_i64(now,"SCM task result")?).execute(&mut *tx).await?;
    mark_scm_task_completed_pg(&mut tx, task, now).await?;
    tx.commit().await?;
    Ok(IdempotentResult {
        value,
        replayed: false,
    })
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn complete_scm_continuation_pg(
    store: &PostgresInstallationStore,
    task: &str,
    worker: &str,
    pending_id: &str,
    now: u64,
    c: &SignedCapsuleRecord,
    v: &runtrue_attest::CapsuleVerifyingKey,
    m: &CapsuleApiMetadata,
    context: &ScmContinuationContext,
    run: &CreateRunRequest,
) -> Result<ScmContinuationCommit, ControlPlaneError> {
    let (supplied_capsule, signature) = validate_signed_capsule_pg(c, v)?;
    let mut tx = store.pool().begin().await?;
    require_scm_task_owner_pg(&mut tx, task, worker, now, "scm.approval.continue").await?;
    require_scm_continuation_binding_pg(&mut tx, task, pending_id).await?;
    let p = scm_pending_tx(&mut tx, pending_id, true).await?;
    if p.state == crate::ScmPendingExecutionState::RunCreated {
        let id = p.run_id.as_deref().ok_or_else(|| {
            ControlPlaneError::CorruptState(
                "completed SCM continuation is missing its run".to_owned(),
            )
        })?;
        mark_scm_task_completed_pg(&mut tx, task, now).await?;
        let value = run_by_id_pg(&mut *tx, id).await?;
        tx.commit().await?;
        return Ok(ScmContinuationCommit::Run(IdempotentResult {
            value,
            replayed: true,
        }));
    }
    if matches!(
        p.state,
        crate::ScmPendingExecutionState::Denied
            | crate::ScmPendingExecutionState::Expired
            | crate::ScmPendingExecutionState::Stale
    ) {
        mark_scm_task_completed_pg(&mut tx, task, now).await?;
        tx.commit().await?;
        return Ok(ScmContinuationCommit::Closed(p));
    }
    match continuation_approval_state(&mut tx, &p, now).await? {
        "waiting" => {
            mark_scm_task_completed_pg(&mut tx, task, now).await?;
            tx.commit().await?;
            return Ok(ScmContinuationCommit::Waiting(p));
        }
        "ready" => {}
        state => {
            let target = if state == "denied" {
                "denied"
            } else if state == "expired" {
                "expired"
            } else {
                "stale"
            };
            sqlx::query("UPDATE scm_pending_executions SET state=$2,completed_unix_ms=$3,last_error=CASE WHEN $2='stale' THEN 'approval was consumed outside its exact SCM continuation' ELSE NULL END WHERE id=$1").bind(pending_id).bind(target).bind(to_i64(now,"SCM continuation close")?).execute(&mut *tx).await?;
            mark_scm_task_completed_pg(&mut tx, task, now).await?;
            let closed = scm_pending_tx(&mut tx, pending_id, false).await?;
            tx.commit().await?;
            return Ok(ScmContinuationCommit::Closed(closed));
        }
    }
    let row=sqlx::query("SELECT c.repository_id,c.digest,c.canonical_capsule,c.signature_json,c.created_unix_ms,m.approval_subject_digest,m.risk_score FROM capsules c JOIN capsule_api_metadata m ON m.capsule_id=c.id WHERE c.id=$1").bind(&p.capsule_id).fetch_one(&mut *tx).await?;
    let exact = row.try_get::<String, _>("repository_id")? == c.repository_id
        && row.try_get::<String, _>("digest")? == c.digest.as_str()
        && row.try_get::<Vec<u8>, _>("canonical_capsule")? == c.canonical_capsule
        && row.try_get::<Vec<u8>, _>("signature_json")? == signature
        && from_i64(row.try_get("created_unix_ms")?, "capsule creation")? == c.created_unix_ms
        && row.try_get::<String, _>("approval_subject_digest")?
            == m.approval_subject_digest.as_str()
        && u32::try_from(row.try_get::<i32, _>("risk_score")?).ok() == Some(m.risk_score)
        && p.context == *context
        && p.run == *run
        && context.pending_execution_id == p.id;
    if !exact {
        sqlx::query("UPDATE scm_pending_executions SET state='stale',completed_unix_ms=$2,last_error='re-planned SCM subject or run request changed' WHERE id=$1").bind(pending_id).bind(to_i64(now,"SCM continuation stale")?).execute(&mut *tx).await?;
        mark_scm_task_completed_pg(&mut tx, task, now).await?;
        let closed = scm_pending_tx(&mut tx, pending_id, false).await?;
        tx.commit().await?;
        return Ok(ScmContinuationCommit::Closed(closed));
    }
    let mut authorizations = Vec::new();
    if supplied_capsule.approval.workflow_definition {
        authorizations.push(
            authorize_required_scm_approval_pg(
                &mut tx,
                &p.capsule_id,
                &m.approval_subject_digest,
                &m.approval_subject_digest,
                runtrue_policy::ApprovalKind::WorkflowDefinition,
                now,
            )
            .await?,
        );
    }
    if supplied_capsule.approval.privileged_execution {
        let capability_digest = context
            .privileged_capability_digest
            .as_ref()
            .unwrap_or(&m.approval_subject_digest);
        authorizations.push(
            authorize_required_scm_approval_pg(
                &mut tx,
                &p.capsule_id,
                capability_digest,
                &m.approval_subject_digest,
                runtrue_policy::ApprovalKind::PrivilegedExecution,
                now,
            )
            .await?,
        );
    }
    insert_run_jobs_pg(&mut tx, run).await?;
    for authorization in authorizations {
        sqlx::query("INSERT INTO run_approval_authorizations(run_id,approval_id,kind,subject_digest,one_shot,authorized_unix_ms) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(&run.id)
            .bind(authorization.id)
            .bind(approval_kind_pg(authorization.kind))
            .bind(authorization.subject_digest.as_str())
            .bind(authorization.one_shot)
            .bind(to_i64(now, "SCM approval authorization")?)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE scm_pending_executions SET state='run-created',run_id=$2,completed_unix_ms=$3 WHERE id=$1").bind(pending_id).bind(&run.id).bind(to_i64(now,"SCM continuation completion")?).execute(&mut *tx).await?;
    mark_scm_task_completed_pg(&mut tx, task, now).await?;
    let value = run_by_id_pg(&mut *tx, &run.id).await?;
    tx.commit().await?;
    Ok(ScmContinuationCommit::Run(IdempotentResult {
        value,
        replayed: false,
    }))
}

impl ScmRepositoryStore for ControlPlane {
    fn create_repository<'a>(&'a self, record: &'a RepositoryRecord) -> StoreFuture<'a, ()> {
        let result = ControlPlane::create_repository(self, record);
        Box::pin(async move { result })
    }

    fn repository<'a>(&'a self, id: &'a str) -> StoreFuture<'a, RepositoryRecord> {
        let result = ControlPlane::repository(self, id);
        Box::pin(async move { result })
    }

    fn repository_by_owner_name<'a>(
        &'a self,
        owner: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, RepositoryRecord> {
        let result = ControlPlane::repository_by_owner_name(self, owner, name);
        Box::pin(async move { result })
    }

    fn repositories(&self) -> StoreFuture<'_, Vec<RepositoryRecord>> {
        let result = self.list_repositories();
        Box::pin(async move { result })
    }

    fn repositories_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<RepositoryRecord>> {
        let result = self.list_repositories_for_tenant(tenant_id);
        Box::pin(async move { result })
    }

    fn repository_workflow_directory<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
    ) -> StoreFuture<'a, Option<String>> {
        let result = ControlPlane::repository_workflow_directory(self, tenant_id, repository_id);
        Box::pin(async move { result })
    }

    fn set_repository_workflow_directory<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        workflow_directory: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, String> {
        let result = ControlPlane::set_repository_workflow_directory(
            self,
            tenant_id,
            repository_id,
            workflow_directory,
            now_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn create_scm_installation<'a>(
        &'a self,
        record: &'a ScmInstallationRecord,
    ) -> StoreFuture<'a, IdempotentResult<ScmInstallationRecord>> {
        let result = ControlPlane::create_scm_installation(self, record);
        Box::pin(async move { result })
    }

    fn scm_installation_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        installation_id: &'a str,
    ) -> StoreFuture<'a, ScmInstallationRecord> {
        let result = ControlPlane::scm_installation_for_tenant(self, tenant_id, installation_id);
        Box::pin(async move { result })
    }

    fn link_scm_repository<'a>(
        &'a self,
        record: &'a ScmRepositoryLinkRecord,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>> {
        let result = ControlPlane::link_scm_repository(self, record);
        Box::pin(async move { result })
    }

    fn record_scm_webhook_event<'a>(
        &'a self,
        event: &'a NewScmWebhookEvent,
    ) -> StoreFuture<'a, IdempotentResult<ScmWebhookEventRecord>> {
        let result = ControlPlane::record_scm_webhook_event(self, event);
        Box::pin(async move { result })
    }

    fn scm_webhook_events_for_repository<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        before_unix_ms: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ScmWebhookEventRecord>> {
        let result = ControlPlane::scm_webhook_events_for_repository(
            self,
            tenant_id,
            repository_id,
            before_unix_ms,
            limit,
        );
        Box::pin(async move { result })
    }

    fn reserve_scm_source_fetch<'a>(
        &'a self,
        request: &'a ReserveScmSourceFetch,
    ) -> StoreFuture<'a, IdempotentResult<ScmSourceFetchRecord>> {
        let result = ControlPlane::reserve_scm_source_fetch(self, request);
        Box::pin(async move { result })
    }

    fn record_scm_fetch_snapshot_ready<'a>(
        &'a self,
        request: &'a RecordScmFetchSnapshotReady,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        let result = ControlPlane::record_scm_fetch_snapshot_ready(self, request);
        Box::pin(async move { result })
    }

    fn mark_scm_fetch_committed<'a>(
        &'a self,
        tenant_id: &'a str,
        fetch_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        let result = ControlPlane::mark_scm_fetch_committed(self, tenant_id, fetch_id, now_unix_ms);
        Box::pin(async move { result })
    }

    fn scm_source_fetch<'a>(
        &'a self,
        tenant_id: &'a str,
        fetch_id: &'a str,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        let result = ControlPlane::scm_source_fetch(self, tenant_id, fetch_id);
        Box::pin(async move { result })
    }

    fn scm_source_fetch_for_task<'a>(
        &'a self,
        tenant_id: &'a str,
        task_id: &'a str,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        let result = ControlPlane::scm_source_fetch_for_task(self, tenant_id, task_id);
        Box::pin(async move { result })
    }

    fn reserve_scm_check_publication<'a>(
        &'a self,
        request: &'a ReserveScmCheckPublication,
    ) -> StoreFuture<'a, IdempotentResult<ScmCheckPublicationRecord>> {
        let result = ControlPlane::reserve_scm_check_publication(self, request);
        Box::pin(async move { result })
    }

    fn record_scm_check_progress<'a>(
        &'a self,
        request: &'a RecordScmCheckProgress,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        let result = ControlPlane::record_scm_check_progress(self, request);
        Box::pin(async move { result })
    }

    fn mark_scm_check_published<'a>(
        &'a self,
        tenant_id: &'a str,
        publication_id: &'a str,
        task_id: &'a str,
        worker_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        let result = ControlPlane::mark_scm_check_published(
            self,
            tenant_id,
            publication_id,
            task_id,
            worker_id,
            now_unix_ms,
        );
        Box::pin(async move { result })
    }

    fn record_scm_check_failure<'a>(
        &'a self,
        request: &'a RecordScmCheckFailure,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        let result = ControlPlane::record_scm_check_failure(self, request);
        Box::pin(async move { result })
    }

    fn scm_check_publication<'a>(
        &'a self,
        tenant_id: &'a str,
        publication_id: &'a str,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        let result = ControlPlane::scm_check_publication(self, tenant_id, publication_id);
        Box::pin(async move { result })
    }

    fn scm_check_publication_by_provider_run<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        installation_id: &'a str,
        provider_check_run_id: u64,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        let result = ControlPlane::scm_check_publication_by_provider_run(
            self,
            tenant_id,
            repository_id,
            installation_id,
            provider_check_run_id,
        );
        Box::pin(async move { result })
    }
    fn github_account_id_for_repository<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
    ) -> StoreFuture<'a, String> {
        let x = ControlPlane::github_account_id_for_repository(self, t, r);
        Box::pin(async move { x })
    }
    fn reconcile_github_installation<'a>(
        &'a self,
        r: &'a ReconcileGitHubInstallation,
    ) -> StoreFuture<'a, IdempotentResult<GitHubInstallationReconciliationResult>> {
        let x = ControlPlane::reconcile_github_installation(self, r);
        Box::pin(async move { x })
    }
    fn set_github_installation_status<'a>(
        &'a self,
        r: &'a SetGitHubInstallationStatus,
    ) -> StoreFuture<'a, IdempotentResult<GitHubInstallationRecord>> {
        let x = ControlPlane::set_github_installation_status(self, r);
        Box::pin(async move { x })
    }
    fn github_installation_for_tenant<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
    ) -> StoreFuture<'a, GitHubInstallationRecord> {
        let x = ControlPlane::github_installation_for_tenant(self, t, i);
        Box::pin(async move { x })
    }
    fn github_installation_by_external_id<'a>(
        &'a self,
        w: &'a str,
        a: &'a str,
        e: &'a str,
    ) -> StoreFuture<'a, GitHubInstallationRecord> {
        let x = ControlPlane::github_installation_by_external_id(self, w, a, e);
        Box::pin(async move { x })
    }
    fn github_installations_for_tenant<'a>(
        &'a self,
        t: &'a str,
        a: Option<&'a str>,
        l: usize,
    ) -> StoreFuture<'a, Vec<GitHubInstallationRecord>> {
        let x = self.list_github_installations_for_tenant(t, a, l);
        Box::pin(async move { x })
    }
    fn github_repository_catalog_for_tenant<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
        r: bool,
        a: Option<&'a str>,
        l: usize,
    ) -> StoreFuture<'a, Vec<GitHubRepositoryCatalogRecord>> {
        let x = self.list_github_repository_catalog_for_tenant(t, i, r, a, l);
        Box::pin(async move { x })
    }
    fn link_selected_github_repository<'a>(
        &'a self,
        r: &'a LinkSelectedGitHubRepository,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>> {
        let x = ControlPlane::link_selected_github_repository(self, r);
        Box::pin(async move { x })
    }
    fn github_repository_links_for_tenant<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
        a: Option<&'a str>,
        l: usize,
    ) -> StoreFuture<'a, Vec<ScmRepositoryLinkRecord>> {
        let x = self.list_github_repository_links_for_tenant(t, i, a, l);
        Box::pin(async move { x })
    }
    fn suspend_github_repository_link<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
        a: &'a str,
        q: &'a str,
        n: u64,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>> {
        let x = ControlPlane::suspend_github_repository_link(self, t, r, a, q, n);
        Box::pin(async move { x })
    }
    fn create_github_setup_transaction<'a>(
        &'a self,
        r: &'a CreateGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        let x = ControlPlane::create_github_setup_transaction(self, r);
        Box::pin(async move { x })
    }
    fn begin_github_setup_by_state<'a>(
        &'a self,
        s: &'a runtrue_model::ContentDigest,
        n: u64,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        let x = ControlPlane::begin_github_setup_by_state(self, s, n);
        Box::pin(async move { x })
    }
    fn begin_github_setup_transaction<'a>(
        &'a self,
        r: &'a BeginGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        let x = ControlPlane::begin_github_setup_transaction(self, r);
        Box::pin(async move { x })
    }
    fn reject_github_setup_transaction<'a>(
        &'a self,
        r: &'a BeginGitHubSetupTransaction,
        e: &'a str,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        let x = ControlPlane::reject_github_setup_transaction(self, r, e);
        Box::pin(async move { x })
    }
    fn complete_github_setup_transaction<'a>(
        &'a self,
        r: &'a CompleteGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        let x = ControlPlane::complete_github_setup_transaction(self, r);
        Box::pin(async move { x })
    }
    fn reserve_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a ReserveGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>> {
        let x = ControlPlane::reserve_github_lifecycle_delivery(self, r);
        Box::pin(async move { x })
    }
    fn claim_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a ClaimGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, Option<IdempotentResult<GitHubLifecycleDeliveryRecord>>> {
        let x = ControlPlane::claim_github_lifecycle_delivery(self, r);
        Box::pin(async move { x })
    }
    fn claim_next_github_lifecycle_delivery<'a>(
        &'a self,
        w: &'a str,
        n: u64,
        d: u64,
    ) -> StoreFuture<'a, Option<GitHubLifecycleDeliveryRecord>> {
        let x = ControlPlane::claim_next_github_lifecycle_delivery(self, w, n, d);
        Box::pin(async move { x })
    }
    fn complete_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a CompleteGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>> {
        let x = ControlPlane::complete_github_lifecycle_delivery(self, r);
        Box::pin(async move { x })
    }
    fn fail_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a FailGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>> {
        let x = ControlPlane::fail_github_lifecycle_delivery(self, r);
        Box::pin(async move { x })
    }
    fn github_repository_for_event<'a>(
        &'a self,
        i: &'a str,
        r: &'a str,
        o: &'a str,
        n: &'a str,
    ) -> StoreFuture<
        'a,
        (
            RepositoryRecord,
            ScmInstallationRecord,
            ScmRepositoryLinkRecord,
        ),
    > {
        let x = ControlPlane::github_repository_for_event(self, i, r, o, n);
        Box::pin(async move { x })
    }
    fn complete_scm_task_with_run_idempotent<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        n: u64,
        k: &'a str,
        c: &'a SignedCapsuleRecord,
        v: &'a runtrue_attest::CapsuleVerifyingKey,
        m: &'a CapsuleApiMetadata,
        r: &'a CreateRunRequest,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>> {
        let x = ControlPlane::complete_scm_task_with_run_idempotent(self, t, w, n, k, c, v, m, r);
        Box::pin(async move { x })
    }
    fn complete_scm_task_with_executions_idempotent<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        n: u64,
        k: &'a str,
        e: &'a [PreparedScmExecution],
        a: Option<&'a ScmProposedAnalysisRecord>,
        v: &'a runtrue_attest::CapsuleVerifyingKey,
    ) -> StoreFuture<'a, IdempotentResult<ScmTaskCompletion>> {
        let x =
            ControlPlane::complete_scm_task_with_executions_idempotent(self, t, w, n, k, e, a, v);
        Box::pin(async move { x })
    }
    fn scm_pending_execution<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ScmPendingExecution> {
        let x = ControlPlane::scm_pending_execution(self, id);
        Box::pin(async move { x })
    }
    fn scm_proposed_analysis_for_task<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, ScmProposedAnalysisRecord> {
        let x = ControlPlane::scm_proposed_analysis_for_task(self, id);
        Box::pin(async move { x })
    }
    fn scm_pending_execution_approvals<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        let x = ControlPlane::scm_pending_execution_approvals(self, id);
        Box::pin(async move { x })
    }
    fn begin_scm_continuation<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        p: &'a str,
        n: u64,
    ) -> StoreFuture<'a, ScmContinuationResolution> {
        let x = ControlPlane::begin_scm_continuation(self, t, w, p, n);
        Box::pin(async move { x })
    }
    fn close_scm_continuation_as_stale<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        p: &'a str,
        r: &'a str,
        n: u64,
    ) -> StoreFuture<'a, ScmPendingExecution> {
        let x = ControlPlane::close_scm_continuation_as_stale(self, t, w, p, r, n);
        Box::pin(async move { x })
    }
    fn complete_scm_continuation_with_run_idempotent<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        p: &'a str,
        n: u64,
        c: &'a SignedCapsuleRecord,
        v: &'a runtrue_attest::CapsuleVerifyingKey,
        m: &'a CapsuleApiMetadata,
        x: &'a ScmContinuationContext,
        r: &'a CreateRunRequest,
    ) -> StoreFuture<'a, ScmContinuationCommit> {
        let o = ControlPlane::complete_scm_continuation_with_run_idempotent(
            self, t, w, p, n, c, v, m, x, r,
        );
        Box::pin(async move { o })
    }
    fn store_workflow_frontend_report<'a>(
        &'a self,
        r: &'a WorkflowFrontendReportRecord,
    ) -> StoreFuture<'a, ()> {
        let x = ControlPlane::store_workflow_frontend_report(self, r);
        Box::pin(async move { x })
    }
    fn workflow_frontend_report<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, WorkflowFrontendReportRecord> {
        let x = ControlPlane::workflow_frontend_report(self, id);
        Box::pin(async move { x })
    }
}

#[cfg(feature = "postgres")]
impl ScmRepositoryStore for PostgresInstallationStore {
    fn create_repository<'a>(&'a self, record: &'a RepositoryRecord) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            validate_repository(record)?;
            sqlx::query(
                "INSERT INTO repositories
                 (id, tenant_id, owner, name, default_branch, visibility, created_unix_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&record.id)
            .bind(&record.tenant_id)
            .bind(&record.owner)
            .bind(&record.name)
            .bind(&record.default_branch)
            .bind(&record.visibility)
            .bind(to_i64(record.created_unix_ms, "repository creation")?)
            .execute(self.pool())
            .await?;
            Ok(())
        })
    }

    fn repository<'a>(&'a self, id: &'a str) -> StoreFuture<'a, RepositoryRecord> {
        Box::pin(async move {
            validate_text("repository.id", id)?;
            repository_by_id(self.pool(), id).await
        })
    }

    fn repository_by_owner_name<'a>(
        &'a self,
        owner: &'a str,
        name: &'a str,
    ) -> StoreFuture<'a, RepositoryRecord> {
        Box::pin(async move {
            validate_text("repository.owner", owner)?;
            validate_text("repository.name", name)?;
            let rows = sqlx::query(
                "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
                 FROM repositories WHERE owner = $1 AND name = $2
                 ORDER BY tenant_id, id LIMIT 2",
            )
            .bind(owner)
            .bind(name)
            .fetch_all(self.pool())
            .await?;
            match rows.len() {
                0 => Err(not_found("repository", &format!("{owner}/{name}"))),
                1 => repository_row(&rows[0]),
                _ => Err(ControlPlaneError::AmbiguousRepositoryIdentity {
                    owner: owner.to_owned(),
                    name: name.to_owned(),
                }),
            }
        })
    }

    fn repositories(&self) -> StoreFuture<'_, Vec<RepositoryRecord>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
                 FROM repositories ORDER BY id",
            )
            .fetch_all(self.pool())
            .await?;
            rows.iter().map(repository_row).collect()
        })
    }

    fn repositories_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, Vec<RepositoryRecord>> {
        Box::pin(async move {
            validate_text("repository tenant", tenant_id)?;
            sqlx::query(
                "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
                 FROM repositories WHERE tenant_id = $1 ORDER BY id",
            )
            .bind(tenant_id)
            .fetch_all(self.pool())
            .await?
            .iter()
            .map(repository_row)
            .collect()
        })
    }

    fn repository_workflow_directory<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
    ) -> StoreFuture<'a, Option<String>> {
        Box::pin(async move {
            validate_text("repository workflow tenant", tenant_id)?;
            validate_text("repository workflow repository", repository_id)?;
            let directory: Option<String> = sqlx::query_scalar(
                "SELECT workflow_directory FROM repository_workflow_settings
                 WHERE tenant_id = $1 AND repository_id = $2",
            )
            .bind(tenant_id)
            .bind(repository_id)
            .fetch_optional(self.pool())
            .await?;
            match directory {
                Some(value)
                    if value.len() <= 1024
                        && normalize_relative_path(&value).ok().as_deref()
                            == Some(value.as_str()) =>
                {
                    Ok(Some(value))
                }
                Some(_) => Err(ControlPlaneError::CorruptState(
                    "repository workflow directory".to_owned(),
                )),
                None => Ok(None),
            }
        })
    }

    fn set_repository_workflow_directory<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        workflow_directory: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, String> {
        Box::pin(async move {
            validate_text("repository workflow tenant", tenant_id)?;
            validate_text("repository workflow repository", repository_id)?;
            let normalized = normalize_relative_path(workflow_directory).map_err(|_| {
                ControlPlaneError::InvalidInput("workflow directory must be repository-relative")
            })?;
            if normalized != workflow_directory || normalized.len() > 1024 {
                return Err(ControlPlaneError::InvalidInput(
                    "workflow directory must be a normalized repository-relative path",
                ));
            }
            let changed = sqlx::query(
                "INSERT INTO repository_workflow_settings
                 (repository_id, tenant_id, workflow_directory, updated_unix_ms)
                 SELECT id, tenant_id, $3, $4 FROM repositories
                 WHERE tenant_id = $1 AND id = $2
                 ON CONFLICT(repository_id) DO UPDATE SET
                     workflow_directory = excluded.workflow_directory,
                     updated_unix_ms = excluded.updated_unix_ms
                 WHERE repository_workflow_settings.tenant_id = excluded.tenant_id",
            )
            .bind(tenant_id)
            .bind(repository_id)
            .bind(&normalized)
            .bind(to_i64(now_unix_ms, "repository workflow update")?)
            .execute(self.pool())
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(not_found("repository", repository_id));
            }
            Ok(normalized)
        })
    }

    fn create_scm_installation<'a>(
        &'a self,
        record: &'a ScmInstallationRecord,
    ) -> StoreFuture<'a, IdempotentResult<ScmInstallationRecord>> {
        Box::pin(async move {
            validate_scm_installation(record)?;
            let permissions = serde_json::to_vec(&canonicalize_json(record.permissions.clone()))?;
            if permissions.len() > 1024 * 1024 {
                return Err(ControlPlaneError::InvalidInput("invalid SCM installation"));
            }
            let inserted = sqlx::query(
                "INSERT INTO scm_installations
                 (id, tenant_id, provider, external_id, credential_reference, permissions_json,
                  status, created_unix_ms, updated_unix_ms)
                 VALUES ($1, $2, 'github', $3, $4, $5, $6, $7, $8)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.id)
            .bind(&record.tenant_id)
            .bind(&record.external_id)
            .bind(&record.credential_reference)
            .bind(permissions)
            .bind(&record.status)
            .bind(to_i64(record.created_unix_ms, "SCM installation creation")?)
            .bind(to_i64(record.updated_unix_ms, "SCM installation update")?)
            .execute(self.pool())
            .await?
            .rows_affected();
            let existing = scm_installation_by_id(self.pool(), &record.id).await?;
            if existing != *record {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            Ok(IdempotentResult {
                value: existing,
                replayed: inserted == 0,
            })
        })
    }

    fn scm_installation_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        installation_id: &'a str,
    ) -> StoreFuture<'a, ScmInstallationRecord> {
        Box::pin(async move {
            validate_text("SCM installation tenant", tenant_id)?;
            validate_text("SCM installation id", installation_id)?;
            let row = sqlx::query(
                "SELECT id, tenant_id, provider, external_id, credential_reference,
                        permissions_json, status, created_unix_ms, updated_unix_ms
                 FROM scm_installations WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(installation_id)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| not_found("SCM installation", installation_id))?;
            scm_installation_row(&row)
        })
    }

    fn link_scm_repository<'a>(
        &'a self,
        record: &'a ScmRepositoryLinkRecord,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>> {
        Box::pin(async move {
            validate_scm_repository_link(record)?;
            let mut connection = self.pool().acquire().await?;
            let mut transaction = connection.begin().await?;
            let authorized: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM repositories r
                    JOIN scm_installations i ON i.id = $2
                    WHERE r.id = $1 AND r.tenant_id = $3 AND i.tenant_id = $3
                      AND i.provider = 'github' AND i.status = 'active'
                 )",
            )
            .bind(&record.repository_id)
            .bind(&record.installation_id)
            .bind(&record.tenant_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !authorized {
                return Err(ControlPlaneError::NotFound {
                    kind: "SCM repository authorization",
                    id: record.repository_id.clone(),
                });
            }
            let inserted = sqlx::query(
                "INSERT INTO scm_repository_links
                 (repository_id, tenant_id, installation_id, external_repository_id, clone_url,
                  status, created_unix_ms, updated_unix_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&record.repository_id)
            .bind(&record.tenant_id)
            .bind(&record.installation_id)
            .bind(&record.external_repository_id)
            .bind(&record.clone_url)
            .bind(&record.status)
            .bind(to_i64(
                record.created_unix_ms,
                "SCM repository link creation",
            )?)
            .bind(to_i64(
                record.updated_unix_ms,
                "SCM repository link update",
            )?)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let existing =
                scm_repository_link_by_id(&mut transaction, &record.repository_id).await?;
            if existing != *record {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit().await?;
            Ok(IdempotentResult {
                value: existing,
                replayed: inserted == 0,
            })
        })
    }

    fn record_scm_webhook_event<'a>(
        &'a self,
        event: &'a NewScmWebhookEvent,
    ) -> StoreFuture<'a, IdempotentResult<ScmWebhookEventRecord>> {
        Box::pin(async move {
            for value in [
                event.delivery_id.as_str(),
                event.installation_external_id.as_str(),
                event.external_repository_id.as_str(),
                event.provider_event_name.as_str(),
                event.event_kind.as_str(),
                event.actor_login.as_str(),
            ] {
                validate_text("SCM webhook event field", value)?;
            }
            if event
                .ref_name
                .as_ref()
                .is_some_and(|value| validate_text("SCM webhook ref", value).is_err())
            {
                return Err(ControlPlaneError::InvalidInput("invalid SCM webhook ref"));
            }
            let mut transaction = self.pool().begin().await?;
            let binding: Option<(String, String, String)> = sqlx::query_as(
                "SELECT i.tenant_id, l.repository_id, i.id
                   FROM scm_installations i
                   JOIN scm_repository_links l
                     ON l.tenant_id = i.tenant_id AND l.installation_id = i.id
                  WHERE i.provider = 'github' AND i.external_id = $1
                    AND i.status = 'active' AND l.external_repository_id = $2
                    AND l.status = 'active'",
            )
            .bind(&event.installation_external_id)
            .bind(&event.external_repository_id)
            .fetch_optional(&mut *transaction)
            .await?;
            let (tenant_id, repository_id, installation_id) = binding.ok_or_else(|| {
                not_found(
                    "active GitHub repository binding",
                    &event.external_repository_id,
                )
            })?;
            let record = ScmWebhookEventRecord {
                delivery_id: event.delivery_id.clone(),
                tenant_id,
                repository_id,
                installation_id,
                external_repository_id: event.external_repository_id.clone(),
                provider_event_name: event.provider_event_name.clone(),
                event_kind: event.event_kind.clone(),
                actor_login: event.actor_login.clone(),
                ref_name: event.ref_name.clone(),
                normalized_digest: event.normalized_digest.clone(),
                payload_digest: event.payload_digest.clone(),
                received_unix_ms: event.received_unix_ms,
            };
            let inserted = sqlx::query(
                "INSERT INTO scm_webhook_events
                 (delivery_id, tenant_id, repository_id, installation_id,
                  external_repository_id, provider_event_name, event_kind,
                  actor_login, ref_name, normalized_digest, payload_digest,
                  received_unix_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                 ON CONFLICT(delivery_id) DO NOTHING",
            )
            .bind(&record.delivery_id)
            .bind(&record.tenant_id)
            .bind(&record.repository_id)
            .bind(&record.installation_id)
            .bind(&record.external_repository_id)
            .bind(&record.provider_event_name)
            .bind(&record.event_kind)
            .bind(&record.actor_login)
            .bind(&record.ref_name)
            .bind(record.normalized_digest.as_str())
            .bind(record.payload_digest.as_str())
            .bind(to_i64(record.received_unix_ms, "webhook event time")?)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if inserted == 0 {
                let existing =
                    scm_webhook_event_by_id(&mut transaction, &record.delivery_id).await?;
                if existing.tenant_id != record.tenant_id
                    || existing.repository_id != record.repository_id
                    || existing.installation_id != record.installation_id
                    || existing.external_repository_id != record.external_repository_id
                    || existing.provider_event_name != record.provider_event_name
                    || existing.event_kind != record.event_kind
                    || existing.actor_login != record.actor_login
                    || existing.ref_name != record.ref_name
                    || existing.payload_digest != record.payload_digest
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                transaction.commit().await?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            transaction.commit().await?;
            Ok(IdempotentResult {
                value: record,
                replayed: false,
            })
        })
    }

    fn scm_webhook_events_for_repository<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        before_unix_ms: Option<u64>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ScmWebhookEventRecord>> {
        Box::pin(async move {
            validate_text("webhook event tenant", tenant_id)?;
            validate_text("webhook event repository", repository_id)?;
            if limit == 0 || limit > 100 {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid webhook event page limit",
                ));
            }
            let authorized: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM repositories WHERE tenant_id = $1 AND id = $2)",
            )
            .bind(tenant_id)
            .bind(repository_id)
            .fetch_one(self.pool())
            .await?;
            if !authorized {
                return Err(not_found("repository", repository_id));
            }
            let before = before_unix_ms
                .map(|value| to_i64(value, "webhook event page time"))
                .transpose()?
                .unwrap_or(i64::MAX);
            let limit = i64::try_from(limit)
                .map_err(|_| ControlPlaneError::InvalidInput("invalid webhook event page limit"))?;
            let rows = sqlx::query(
                "SELECT delivery_id, tenant_id, repository_id, installation_id,
                        external_repository_id, provider_event_name, event_kind,
                        actor_login, ref_name, normalized_digest, payload_digest,
                        received_unix_ms
                   FROM scm_webhook_events
                  WHERE tenant_id = $1 AND repository_id = $2
                    AND received_unix_ms < $3
                  ORDER BY received_unix_ms DESC, delivery_id DESC LIMIT $4",
            )
            .bind(tenant_id)
            .bind(repository_id)
            .bind(before)
            .bind(limit)
            .fetch_all(self.pool())
            .await?;
            rows.iter().map(scm_webhook_event_row).collect()
        })
    }

    fn reserve_scm_source_fetch<'a>(
        &'a self,
        request: &'a ReserveScmSourceFetch,
    ) -> StoreFuture<'a, IdempotentResult<ScmSourceFetchRecord>> {
        Box::pin(async move {
            for (field, value) in [
                ("SCM fetch id", request.id.as_str()),
                ("SCM fetch tenant", request.tenant_id.as_str()),
                ("SCM fetch repository", request.repository_id.as_str()),
                ("SCM fetch installation", request.installation_id.as_str()),
                ("SCM fetch task", request.origin_task_id.as_str()),
                ("SCM fetch source commit", request.source_commit.as_str()),
            ] {
                validate_text(field, value)?;
            }
            let mut transaction = self.pool().begin().await?;
            let authorized: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM durable_tasks t
                    JOIN repositories r ON r.id = $2 AND r.tenant_id = $1
                    JOIN scm_repository_links l
                      ON l.repository_id = r.id AND l.tenant_id = r.tenant_id
                    JOIN scm_installations i
                      ON i.id = l.installation_id AND i.tenant_id = l.tenant_id
                    WHERE t.id = $4 AND t.kind = 'scm.event' AND l.installation_id = $3
                      AND i.status = 'active' AND l.status = 'active'
                 )",
            )
            .bind(&request.tenant_id)
            .bind(&request.repository_id)
            .bind(&request.installation_id)
            .bind(&request.origin_task_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !authorized {
                return Err(ControlPlaneError::NotFound {
                    kind: "SCM fetch authorization",
                    id: request.id.clone(),
                });
            }
            let inserted = sqlx::query(
                "INSERT INTO scm_source_fetches
                 (id, tenant_id, repository_id, installation_id, origin_task_id,
                  normalized_event_digest, source_commit, base_commit, origin_digest,
                  state, attempts, created_unix_ms, updated_unix_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'reserved', 1, $10, $10)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&request.id)
            .bind(&request.tenant_id)
            .bind(&request.repository_id)
            .bind(&request.installation_id)
            .bind(&request.origin_task_id)
            .bind(request.normalized_event_digest.as_str())
            .bind(&request.source_commit)
            .bind(&request.base_commit)
            .bind(request.origin_digest.as_str())
            .bind(to_i64(request.now_unix_ms, "SCM fetch update")?)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let mut existing =
                scm_source_fetch_tx(&mut transaction, &request.tenant_id, &request.id).await?;
            if existing.repository_id != request.repository_id
                || existing.installation_id != request.installation_id
                || existing.normalized_event_digest != request.normalized_event_digest
                || existing.source_commit != request.source_commit
                || existing.base_commit != request.base_commit
                || existing.origin_digest != request.origin_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if inserted == 0 {
                sqlx::query(
                    "UPDATE scm_source_fetches SET attempts = attempts + 1, updated_unix_ms = $3
                     WHERE id = $1 AND tenant_id = $2",
                )
                .bind(&request.id)
                .bind(&request.tenant_id)
                .bind(to_i64(request.now_unix_ms, "SCM fetch update")?)
                .execute(&mut *transaction)
                .await?;
                existing =
                    scm_source_fetch_tx(&mut transaction, &request.tenant_id, &request.id).await?;
            }
            transaction.commit().await?;
            Ok(IdempotentResult {
                value: existing,
                replayed: inserted == 0,
            })
        })
    }

    fn record_scm_fetch_snapshot_ready<'a>(
        &'a self,
        request: &'a RecordScmFetchSnapshotReady,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        Box::pin(async move {
            let mut transaction = self.pool().begin().await?;
            let current =
                scm_source_fetch_tx(&mut transaction, &request.tenant_id, &request.fetch_id)
                    .await?;
            let changed = current
                .token_scope_digest
                .as_ref()
                .is_some_and(|value| value != &request.token_scope_digest)
                || current
                    .mirror_identity_digest
                    .as_ref()
                    .is_some_and(|value| value != &request.mirror_identity_digest)
                || current
                    .tree_manifest_digest
                    .as_ref()
                    .is_some_and(|value| value != &request.tree_manifest_digest)
                || current
                    .source_snapshot_id
                    .as_deref()
                    .is_some_and(|value| value != request.source_snapshot_id);
            if changed || matches!(current.state, ScmSourceFetchState::Failed) {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "UPDATE scm_source_fetches
                 SET token_scope_digest = $3, mirror_identity_digest = $4,
                     tree_manifest_digest = $5, source_snapshot_id = $6,
                     state = CASE WHEN state = 'committed' THEN state ELSE 'snapshot-ready' END,
                     updated_unix_ms = $7
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(&request.fetch_id)
            .bind(&request.tenant_id)
            .bind(request.token_scope_digest.as_str())
            .bind(request.mirror_identity_digest.as_str())
            .bind(request.tree_manifest_digest.as_str())
            .bind(&request.source_snapshot_id)
            .bind(to_i64(request.now_unix_ms, "SCM fetch update")?)
            .execute(&mut *transaction)
            .await?;
            let record =
                scm_source_fetch_tx(&mut transaction, &request.tenant_id, &request.fetch_id)
                    .await?;
            transaction.commit().await?;
            Ok(record)
        })
    }

    fn mark_scm_fetch_committed<'a>(
        &'a self,
        tenant_id: &'a str,
        fetch_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        Box::pin(async move {
            let changed = sqlx::query(
                "UPDATE scm_source_fetches SET state = 'committed', updated_unix_ms = $3
                 WHERE id = $1 AND tenant_id = $2
                   AND state IN ('snapshot-ready', 'committed')",
            )
            .bind(fetch_id)
            .bind(tenant_id)
            .bind(to_i64(now_unix_ms, "SCM fetch update")?)
            .execute(self.pool())
            .await?
            .rows_affected();
            if changed == 0 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            scm_source_fetch_by_id(self.pool(), tenant_id, fetch_id).await
        })
    }

    fn scm_source_fetch<'a>(
        &'a self,
        tenant_id: &'a str,
        fetch_id: &'a str,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        Box::pin(async move { scm_source_fetch_by_id(self.pool(), tenant_id, fetch_id).await })
    }

    fn scm_source_fetch_for_task<'a>(
        &'a self,
        tenant_id: &'a str,
        task_id: &'a str,
    ) -> StoreFuture<'a, ScmSourceFetchRecord> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id, tenant_id, repository_id, installation_id, origin_task_id,
                        normalized_event_digest, source_commit, base_commit, origin_digest,
                        token_scope_digest, mirror_identity_digest, tree_manifest_digest,
                        source_snapshot_id, state, attempts, last_error_code,
                        created_unix_ms, updated_unix_ms
                 FROM scm_source_fetches WHERE origin_task_id = $1 AND tenant_id = $2",
            )
            .bind(task_id)
            .bind(tenant_id)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| not_found("SCM source fetch", task_id))?;
            scm_source_fetch_row(&row)
        })
    }

    fn reserve_scm_check_publication<'a>(
        &'a self,
        request: &'a ReserveScmCheckPublication,
    ) -> StoreFuture<'a, IdempotentResult<ScmCheckPublicationRecord>> {
        Box::pin(async move {
            for (field, value) in [
                ("SCM check publication id", request.id.as_str()),
                ("SCM check tenant", request.tenant_id.as_str()),
                ("SCM check repository", request.repository_id.as_str()),
                ("SCM check installation", request.installation_id.as_str()),
                ("SCM check run", request.run_id.as_str()),
                ("SCM check task", request.task_id.as_str()),
                ("SCM check worker", request.worker_id.as_str()),
                ("SCM check commit", request.commit_sha.as_str()),
                ("SCM check logical name", request.logical_name.as_str()),
                ("SCM check external id", request.external_id.as_str()),
            ] {
                validate_text(field, value)?;
            }
            if !matches!(request.commit_sha.len(), 40 | 64)
                || !request
                    .commit_sha
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(ControlPlaneError::InvalidInput("invalid SCM check commit"));
            }
            let mut transaction = self.pool().begin().await?;
            require_postgres_task_owner(
                &mut transaction,
                &request.task_id,
                &request.worker_id,
                request.now_unix_ms,
            )
            .await?;
            let authorized: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM durable_tasks t
                    JOIN repositories r ON r.id = $2 AND r.tenant_id = $1
                    JOIN scm_repository_links l ON l.repository_id = r.id
                        AND l.tenant_id = r.tenant_id AND l.installation_id = $3
                    JOIN scm_installations i ON i.id = l.installation_id
                        AND i.tenant_id = l.tenant_id
                    JOIN runs run ON run.id = $4 AND run.repository_id = r.id
                    WHERE t.id = $5 AND t.kind = 'scm.check.publish'
                        AND i.provider = 'github' AND i.status = 'active'
                        AND l.status = 'active')",
            )
            .bind(&request.tenant_id)
            .bind(&request.repository_id)
            .bind(&request.installation_id)
            .bind(&request.run_id)
            .bind(&request.task_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !authorized {
                return Err(ControlPlaneError::NotFound {
                    kind: "SCM check authorization",
                    id: request.id.clone(),
                });
            }
            let now = to_i64(request.now_unix_ms, "SCM check update")?;
            let inserted = sqlx::query(
                "INSERT INTO scm_check_publications
                 (id,tenant_id,repository_id,installation_id,run_id,task_id,provider,
                  commit_sha,logical_name,external_id,request_digest,annotation_count,
                  state,attempts,created_unix_ms,updated_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,'github',$7,$8,$9,$10,$11,'reserved',1,$12,$12)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&request.id)
            .bind(&request.tenant_id)
            .bind(&request.repository_id)
            .bind(&request.installation_id)
            .bind(&request.run_id)
            .bind(&request.task_id)
            .bind(&request.commit_sha)
            .bind(&request.logical_name)
            .bind(&request.external_id)
            .bind(request.request_digest.as_str())
            .bind(i32::try_from(request.annotation_count).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "SCM check annotation count",
                }
            })?)
            .bind(now)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let mut existing =
                scm_check_publication_tx(&mut transaction, &request.tenant_id, &request.id).await?;
            if existing.repository_id != request.repository_id
                || existing.installation_id != request.installation_id
                || existing.run_id != request.run_id
                || existing.task_id != request.task_id
                || existing.commit_sha != request.commit_sha
                || existing.logical_name != request.logical_name
                || existing.external_id != request.external_id
                || existing.request_digest != request.request_digest
                || existing.annotation_count != request.annotation_count
                || request.now_unix_ms < existing.updated_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if inserted == 0 {
                sqlx::query("UPDATE scm_check_publications SET attempts=attempts+1,updated_unix_ms=$3 WHERE id=$1 AND tenant_id=$2")
                    .bind(&request.id).bind(&request.tenant_id).bind(now).execute(&mut *transaction).await?;
                existing =
                    scm_check_publication_tx(&mut transaction, &request.tenant_id, &request.id)
                        .await?;
            }
            transaction.commit().await?;
            Ok(IdempotentResult {
                value: existing,
                replayed: inserted == 0,
            })
        })
    }

    fn record_scm_check_progress<'a>(
        &'a self,
        request: &'a RecordScmCheckProgress,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        Box::pin(async move {
            if request.provider_check_run_id == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid provider check run id",
                ));
            }
            let mut tx = self.pool().begin().await?;
            require_postgres_task_owner(
                &mut tx,
                &request.task_id,
                &request.worker_id,
                request.now_unix_ms,
            )
            .await?;
            let current =
                scm_check_publication_tx(&mut tx, &request.tenant_id, &request.publication_id)
                    .await?;
            if current.task_id != request.task_id
                || matches!(current.state, ScmCheckPublicationState::Failed)
                || current
                    .provider_check_run_id
                    .is_some_and(|id| id != request.provider_check_run_id)
                || request.confirmed_annotations < current.confirmed_annotations
                || request.confirmed_annotations > current.annotation_count
                || request.now_unix_ms < current.updated_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if current.state == ScmCheckPublicationState::Published {
                tx.commit().await?;
                return Ok(current);
            }
            sqlx::query("UPDATE scm_check_publications SET provider_check_run_id=$3,confirmed_annotations=$4,state=CASE WHEN state='published' THEN state ELSE 'reconciling' END,last_error_code=NULL,updated_unix_ms=$5 WHERE id=$1 AND tenant_id=$2")
            .bind(&request.publication_id).bind(&request.tenant_id).bind(to_i64(request.provider_check_run_id,"provider check run id")?).bind(i32::try_from(request.confirmed_annotations).map_err(|_|ControlPlaneError::IntegerRange{field:"SCM check confirmed annotations"})?).bind(to_i64(request.now_unix_ms,"SCM check update")?).execute(&mut *tx).await?;
            let record =
                scm_check_publication_tx(&mut tx, &request.tenant_id, &request.publication_id)
                    .await?;
            tx.commit().await?;
            Ok(record)
        })
    }

    fn mark_scm_check_published<'a>(
        &'a self,
        tenant_id: &'a str,
        publication_id: &'a str,
        task_id: &'a str,
        worker_id: &'a str,
        now: u64,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            require_postgres_task_owner(&mut tx, task_id, worker_id, now).await?;
            let current = scm_check_publication_tx(&mut tx, tenant_id, publication_id).await?;
            if current.task_id != task_id
                || current.provider_check_run_id.is_none()
                || current.confirmed_annotations != current.annotation_count
                || matches!(current.state, ScmCheckPublicationState::Failed)
                || now < current.updated_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if current.state == ScmCheckPublicationState::Published {
                tx.commit().await?;
                return Ok(current);
            }
            sqlx::query("UPDATE scm_check_publications SET state='published',last_error_code=NULL,updated_unix_ms=$3 WHERE id=$1 AND tenant_id=$2").bind(publication_id).bind(tenant_id).bind(to_i64(now,"SCM check update")?).execute(&mut *tx).await?;
            let record = scm_check_publication_tx(&mut tx, tenant_id, publication_id).await?;
            super::api_tokens::append(
                &mut tx,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: now,
                    tenant_id: tenant_id.to_owned(),
                    actor: AuditPrincipal {
                        kind: "scm-worker".to_owned(),
                        id: "scm-check-reconciler".to_owned(),
                    },
                    action: "scm.check.publish".to_owned(),
                    resource: AuditResource {
                        kind: "scm-check-publication".to_owned(),
                        id: publication_id.to_owned(),
                    },
                    result: "success".to_owned(),
                    request_id: record.task_id.clone(),
                    decision_id: None,
                    metadata: BTreeMap::from([
                        (
                            "request_digest".to_owned(),
                            AuditValue::Digest(record.request_digest.clone()),
                        ),
                        (
                            "provider_check_run_id".to_owned(),
                            AuditValue::Integer(
                                i64::try_from(record.provider_check_run_id.ok_or_else(|| {
                                    ControlPlaneError::CorruptState(
                                        "published SCM check has no provider id".to_owned(),
                                    )
                                })?)
                                .map_err(|_| {
                                    ControlPlaneError::IntegerRange {
                                        field: "provider check run id",
                                    }
                                })?,
                            ),
                        ),
                    ]),
                },
            )
            .await?;
            tx.commit().await?;
            Ok(record)
        })
    }

    fn record_scm_check_failure<'a>(
        &'a self,
        request: &'a RecordScmCheckFailure,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        Box::pin(async move {
            validate_text("SCM check failure code", &request.error_code)?;
            let mut tx = self.pool().begin().await?;
            require_postgres_task_owner(
                &mut tx,
                &request.task_id,
                &request.worker_id,
                request.now_unix_ms,
            )
            .await?;
            let current =
                scm_check_publication_tx(&mut tx, &request.tenant_id, &request.publication_id)
                    .await?;
            if current.task_id != request.task_id
                || matches!(current.state, ScmCheckPublicationState::Published)
                || request.now_unix_ms < current.updated_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("UPDATE scm_check_publications SET state=CASE WHEN $4 THEN 'failed' ELSE 'reconciling' END,last_error_code=$3,updated_unix_ms=$5 WHERE id=$1 AND tenant_id=$2").bind(&request.publication_id).bind(&request.tenant_id).bind(&request.error_code).bind(request.terminal).bind(to_i64(request.now_unix_ms,"SCM check update")?).execute(&mut *tx).await?;
            let record =
                scm_check_publication_tx(&mut tx, &request.tenant_id, &request.publication_id)
                    .await?;
            tx.commit().await?;
            Ok(record)
        })
    }

    fn scm_check_publication<'a>(
        &'a self,
        tenant_id: &'a str,
        publication_id: &'a str,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        Box::pin(async move {
            validate_text("SCM check tenant", tenant_id)?;
            validate_text("SCM check publication", publication_id)?;
            scm_check_publication_by_id(self.pool(), tenant_id, publication_id).await
        })
    }

    fn scm_check_publication_by_provider_run<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        installation_id: &'a str,
        provider_check_run_id: u64,
    ) -> StoreFuture<'a, ScmCheckPublicationRecord> {
        Box::pin(async move {
            validate_text("SCM check tenant", tenant_id)?;
            validate_text("SCM check repository", repository_id)?;
            validate_text("SCM check installation", installation_id)?;
            if provider_check_run_id == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid provider check run id",
                ));
            }
            let row=sqlx::query("SELECT * FROM scm_check_publications WHERE tenant_id=$1 AND repository_id=$2 AND installation_id=$3 AND provider='github' AND provider_check_run_id=$4 ORDER BY created_unix_ms DESC,id DESC LIMIT 1").bind(tenant_id).bind(repository_id).bind(installation_id).bind(to_i64(provider_check_run_id,"provider check run id")?).fetch_optional(self.pool()).await?.ok_or_else(||not_found("SCM provider check run",&provider_check_run_id.to_string()))?;
            scm_check_publication_row(&row)
        })
    }

    fn github_account_id_for_repository<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
    ) -> StoreFuture<'a, String> {
        Box::pin(async move {
            validate_text("GitHub account tenant", t)?;
            validate_text("GitHub account repository", r)?;
            sqlx::query_scalar("SELECT p.account_external_id FROM scm_repository_links l JOIN scm_installations i ON i.id=l.installation_id AND i.tenant_id=l.tenant_id JOIN github_installation_profiles p ON p.installation_id=i.id AND p.tenant_id=i.tenant_id WHERE l.tenant_id=$1 AND l.repository_id=$2 AND l.status='active' AND i.status='active'").bind(t).bind(r).fetch_optional(self.pool()).await?.ok_or_else(||not_found("GitHub account repository",r))
        })
    }

    fn reconcile_github_installation<'a>(
        &'a self,
        request: &'a ReconcileGitHubInstallation,
    ) -> StoreFuture<'a, IdempotentResult<GitHubInstallationReconciliationResult>> {
        Box::pin(async move {
            validate_github_reconciliation_pg(request)?;
            let incoming = &request.installation;
            let i = &incoming.installation;
            let mut tx = self.pool().begin().await?;
            let current = github_installation_optional(&mut tx, &i.tenant_id, &i.id).await?;
            let base = scm_installation_optional_tx(&mut tx, &i.tenant_id, &i.id).await?;
            let mut replayed = false;
            match current.as_ref() {
                Some(c) if c == incoming => replayed = true,
                Some(c) => {
                    if request.expected_version != Some(c.version)
                        || incoming.version != c.version + 1
                        || incoming.lifecycle_generation != c.lifecycle_generation + 1
                        || i.id != c.installation.id
                        || i.tenant_id != c.installation.tenant_id
                        || i.external_id != c.installation.external_id
                        || i.provider != c.installation.provider
                        || i.credential_reference != c.installation.credential_reference
                        || i.created_unix_ms != c.installation.created_unix_ms
                        || incoming.web_origin != c.web_origin
                        || incoming.api_origin != c.api_origin
                        || incoming.account_external_id != c.account_external_id
                        || incoming.account_kind != c.account_kind
                        || !valid_status_transition(&c.installation.status, &i.status)
                    {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    };
                    sqlx::query("UPDATE scm_installations SET permissions_json=$3,status=$4,updated_unix_ms=$5 WHERE tenant_id=$1 AND id=$2").bind(&i.tenant_id).bind(&i.id).bind(serde_json::to_vec(&canonicalize_json(i.permissions.clone()))?).bind(&i.status).bind(to_i64(i.updated_unix_ms,"GitHub installation update")?).execute(&mut *tx).await?;
                    sqlx::query("UPDATE github_installation_profiles SET account_login=$3,repository_selection=$4,lifecycle_generation=$5,synchronized_unix_ms=$6,suspended_unix_ms=$7,revoked_unix_ms=$8,version=$9 WHERE tenant_id=$1 AND installation_id=$2 AND version=$10").bind(&i.tenant_id).bind(&i.id).bind(&incoming.account_login).bind(selection_name(incoming.repository_selection)).bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?).bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).bind(opt_i64_pg(incoming.suspended_unix_ms,"GitHub suspension")?).bind(opt_i64_pg(incoming.revoked_unix_ms,"GitHub revocation")?).bind(to_i64(incoming.version,"GitHub version")?).bind(to_i64(c.version,"GitHub version")?).execute(&mut *tx).await?;
                }
                None => {
                    if request.expected_version.is_some()
                        || incoming.version != 1
                        || incoming.lifecycle_generation != 1
                    {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    };
                    if let Some(base) = base {
                        if i.id != base.id
                            || i.tenant_id != base.tenant_id
                            || i.provider != base.provider
                            || i.external_id != base.external_id
                            || i.credential_reference != base.credential_reference
                            || i.created_unix_ms != base.created_unix_ms
                        {
                            return Err(ControlPlaneError::IdempotencyConflict);
                        }
                        sqlx::query("UPDATE scm_installations SET permissions_json=$3,status=$4,updated_unix_ms=$5 WHERE tenant_id=$1 AND id=$2").bind(&i.tenant_id).bind(&i.id).bind(serde_json::to_vec(&canonicalize_json(i.permissions.clone()))?).bind(&i.status).bind(to_i64(i.updated_unix_ms,"GitHub installation update")?).execute(&mut *tx).await?;
                    } else {
                        let inserted=sqlx::query("INSERT INTO scm_installations(id,tenant_id,provider,external_id,credential_reference,permissions_json,status,created_unix_ms,updated_unix_ms) VALUES($1,$2,'github',$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING").bind(&i.id).bind(&i.tenant_id).bind(&i.external_id).bind(&i.credential_reference).bind(serde_json::to_vec(&canonicalize_json(i.permissions.clone()))?).bind(&i.status).bind(to_i64(i.created_unix_ms,"GitHub creation")?).bind(to_i64(i.updated_unix_ms,"GitHub update")?).execute(&mut *tx).await?.rows_affected();
                        if inserted != 1 {
                            return Err(not_found("GitHub installation authorization", &i.id));
                        }
                    }
                    insert_github_profile(&mut tx, incoming).await?;
                }
            }
            let mut summary = GitHubRepositoryReconciliationSummary {
                selected: u64::try_from(request.selected_repositories.len()).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "GitHub selected repository count",
                    }
                })?,
                ..Default::default()
            };
            let selected = request
                .selected_repositories
                .iter()
                .map(|r| r.external_repository_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            for r in &request.selected_repositories {
                let old = github_catalog_optional(
                    &mut tx,
                    &i.tenant_id,
                    &i.id,
                    &r.external_repository_id,
                )
                .await?;
                match old {
                    None => {
                        sqlx::query("INSERT INTO github_repository_catalog(installation_id,external_repository_id,tenant_id,web_origin,api_origin,owner,name,full_name,clone_url,visibility,default_branch,status,selection_generation,first_seen_unix_ms,last_seen_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'selected',$12,$13,$13,1)").bind(&i.id).bind(&r.external_repository_id).bind(&i.tenant_id).bind(&incoming.web_origin).bind(&incoming.api_origin).bind(&r.owner).bind(&r.name).bind(&r.full_name).bind(&r.clone_url).bind(&r.visibility).bind(&r.default_branch).bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?).bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut *tx).await?;
                        summary.inserted += 1
                    }
                    Some(o) => {
                        let exact = o.owner == r.owner
                            && o.name == r.name
                            && o.full_name == r.full_name
                            && o.clone_url == r.clone_url
                            && o.visibility == r.visibility
                            && o.default_branch == r.default_branch
                            && o.status == "selected"
                            && o.selection_generation == incoming.lifecycle_generation
                            && o.last_seen_unix_ms == incoming.synchronized_unix_ms;
                        if !exact {
                            if o.selection_generation >= incoming.lifecycle_generation {
                                return Err(ControlPlaneError::IdempotencyConflict);
                            };
                            sqlx::query("UPDATE github_repository_catalog SET owner=$4,name=$5,full_name=$6,clone_url=$7,visibility=$8,default_branch=$9,status='selected',selection_generation=$10,last_seen_unix_ms=$11,removed_unix_ms=NULL,version=version+1 WHERE tenant_id=$1 AND installation_id=$2 AND external_repository_id=$3").bind(&i.tenant_id).bind(&i.id).bind(&r.external_repository_id).bind(&r.owner).bind(&r.name).bind(&r.full_name).bind(&r.clone_url).bind(&r.visibility).bind(&r.default_branch).bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?).bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut *tx).await?;
                            summary.updated += 1
                        }
                    }
                }
            }
            let ids:Vec<String>=sqlx::query_scalar("SELECT external_repository_id FROM github_repository_catalog WHERE tenant_id=$1 AND installation_id=$2 AND status='selected'").bind(&i.tenant_id).bind(&i.id).fetch_all(&mut *tx).await?;
            for id in ids {
                if !selected.contains(id.as_str()) {
                    sqlx::query("UPDATE github_repository_catalog SET status='removed',selection_generation=$4,last_seen_unix_ms=$5,removed_unix_ms=$5,version=version+1 WHERE tenant_id=$1 AND installation_id=$2 AND external_repository_id=$3").bind(&i.tenant_id).bind(&i.id).bind(id).bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?).bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut *tx).await?;
                    summary.removed += 1
                }
            }
            sqlx::query("UPDATE scm_repository_links SET status=CASE WHEN $3='active' THEN status ELSE $3 END,updated_unix_ms=$4 WHERE tenant_id=$1 AND installation_id=$2").bind(&i.tenant_id).bind(&i.id).bind(&i.status).bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut *tx).await?;
            let durable = github_installation_required(&mut tx, &i.tenant_id, &i.id).await?;
            let final_replayed =
                replayed && summary.inserted == 0 && summary.updated == 0 && summary.removed == 0;
            if !final_replayed {
                append_github_audit_pg(
                    &mut tx,
                    &self.installation_id,
                    request.now_unix_ms,
                    &i.tenant_id,
                    "github-installation-reconciler",
                    "github.installation.reconcile",
                    "github-installation",
                    &i.id,
                    &format!("{}:{}", i.id, incoming.lifecycle_generation),
                    BTreeMap::from([
                        (
                            "external_installation_id".to_owned(),
                            AuditValue::String(i.external_id.clone()),
                        ),
                        (
                            "selected_repository_count".to_owned(),
                            AuditValue::Integer(to_i64(
                                summary.selected,
                                "GitHub selected repository count",
                            )?),
                        ),
                        (
                            "inserted_repository_count".to_owned(),
                            AuditValue::Integer(to_i64(
                                summary.inserted,
                                "GitHub inserted repository count",
                            )?),
                        ),
                        (
                            "updated_repository_count".to_owned(),
                            AuditValue::Integer(to_i64(
                                summary.updated,
                                "GitHub updated repository count",
                            )?),
                        ),
                        (
                            "removed_repository_count".to_owned(),
                            AuditValue::Integer(to_i64(
                                summary.removed,
                                "GitHub removed repository count",
                            )?),
                        ),
                    ]),
                )
                .await?;
            }
            tx.commit().await?;
            Ok(IdempotentResult {
                value: GitHubInstallationReconciliationResult {
                    installation: durable,
                    repositories: summary,
                },
                replayed: final_replayed,
            })
        })
    }

    fn set_github_installation_status<'a>(
        &'a self,
        r: &'a SetGitHubInstallationStatus,
    ) -> StoreFuture<'a, IdempotentResult<GitHubInstallationRecord>> {
        Box::pin(async move {
            validate_text("GitHub installation tenant", &r.tenant_id)?;
            validate_text("GitHub installation id", &r.installation_id)?;
            if r.expected_version == 0
                || r.lifecycle_generation == 0
                || !matches!(r.status.as_str(), "active" | "suspended" | "revoked")
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid GitHub installation status transition",
                ));
            }
            let mut tx = self.pool().begin().await?;
            let c = github_installation_required(&mut tx, &r.tenant_id, &r.installation_id).await?;
            if c.installation.status == r.status && c.lifecycle_generation == r.lifecycle_generation
            {
                return Ok(IdempotentResult {
                    value: c,
                    replayed: true,
                });
            }
            if c.installation.status == "revoked"
                || c.version != r.expected_version
                || r.lifecycle_generation != c.lifecycle_generation + 1
                || r.now_unix_ms < c.synchronized_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let nv = c.version + 1;
            sqlx::query("UPDATE scm_installations SET status=$3,updated_unix_ms=$4 WHERE tenant_id=$1 AND id=$2").bind(&r.tenant_id).bind(&r.installation_id).bind(&r.status).bind(to_i64(r.now_unix_ms,"GitHub status")?).execute(&mut *tx).await?;
            sqlx::query("UPDATE github_installation_profiles SET lifecycle_generation=$3,synchronized_unix_ms=$4,suspended_unix_ms=CASE WHEN $5='suspended' THEN $4 ELSE NULL END,revoked_unix_ms=CASE WHEN $5='revoked' THEN $4 ELSE revoked_unix_ms END,version=$6 WHERE tenant_id=$1 AND installation_id=$2 AND version=$7").bind(&r.tenant_id).bind(&r.installation_id).bind(to_i64(r.lifecycle_generation,"GitHub generation")?).bind(to_i64(r.now_unix_ms,"GitHub status")?).bind(&r.status).bind(to_i64(nv,"GitHub version")?).bind(to_i64(r.expected_version,"GitHub version")?).execute(&mut *tx).await?;
            sqlx::query("UPDATE scm_repository_links SET status=$3,updated_unix_ms=$4 WHERE tenant_id=$1 AND installation_id=$2 AND $3<>'active'").bind(&r.tenant_id).bind(&r.installation_id).bind(&r.status).bind(to_i64(r.now_unix_ms,"GitHub status")?).execute(&mut *tx).await?;
            let v = github_installation_required(&mut tx, &r.tenant_id, &r.installation_id).await?;
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                r.now_unix_ms,
                &r.tenant_id,
                "github-installation-reconciler",
                "github.installation.status",
                "github-installation",
                &r.installation_id,
                &format!("{}:{}", r.installation_id, r.lifecycle_generation),
                BTreeMap::from([
                    (
                        "lifecycle_generation".to_owned(),
                        AuditValue::Integer(to_i64(
                            r.lifecycle_generation,
                            "GitHub lifecycle generation",
                        )?),
                    ),
                    ("status".to_owned(), AuditValue::String(r.status.clone())),
                ]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: v,
                replayed: false,
            })
        })
    }

    fn github_installation_for_tenant<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
    ) -> StoreFuture<'a, GitHubInstallationRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let v = github_installation_required(&mut tx, t, i).await?;
            tx.commit().await?;
            Ok(v)
        })
    }
    fn github_installation_by_external_id<'a>(
        &'a self,
        w: &'a str,
        a: &'a str,
        e: &'a str,
    ) -> StoreFuture<'a, GitHubInstallationRecord> {
        Box::pin(async move {
            validate_origins(w, a)?;
            let row=sqlx::query("SELECT i.*,p.* FROM scm_installations i JOIN github_installation_profiles p ON p.installation_id=i.id AND p.tenant_id=i.tenant_id WHERE i.provider='github' AND i.external_id=$1 AND p.web_origin=$2 AND p.api_origin=$3").bind(e).bind(w).bind(a).fetch_optional(self.pool()).await?.ok_or_else(||not_found("GitHub installation",e))?;
            github_installation_row(&row)
        })
    }
    fn github_installations_for_tenant<'a>(
        &'a self,
        t: &'a str,
        a: Option<&'a str>,
        l: usize,
    ) -> StoreFuture<'a, Vec<GitHubInstallationRecord>> {
        Box::pin(async move {
            validate_page_pg(l, a)?;
            let rows=sqlx::query("SELECT i.*,p.* FROM scm_installations i JOIN github_installation_profiles p ON p.installation_id=i.id AND p.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.id>$2 ORDER BY i.id LIMIT $3").bind(t).bind(a.unwrap_or("")).bind(i64::try_from(l).map_err(|_|ControlPlaneError::InvalidInput("invalid page limit"))?).fetch_all(self.pool()).await?;
            rows.iter().map(github_installation_row).collect()
        })
    }
    fn github_repository_catalog_for_tenant<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
        removed: bool,
        a: Option<&'a str>,
        l: usize,
    ) -> StoreFuture<'a, Vec<GitHubRepositoryCatalogRecord>> {
        Box::pin(async move {
            validate_page_pg(l, a)?;
            if github_installation_optional_pool(self.pool(), t, i)
                .await?
                .is_none()
            {
                return Err(not_found("GitHub installation", i));
            }
            let rows=sqlx::query("SELECT * FROM github_repository_catalog WHERE tenant_id=$1 AND installation_id=$2 AND ($3 OR status='selected') AND external_repository_id>$4 ORDER BY external_repository_id LIMIT $5").bind(t).bind(i).bind(removed).bind(a.unwrap_or("")).bind(i64::try_from(l).map_err(|_|ControlPlaneError::InvalidInput("invalid page limit"))?).fetch_all(self.pool()).await?;
            rows.iter().map(github_catalog_row).collect()
        })
    }
    fn link_selected_github_repository<'a>(
        &'a self,
        r: &'a LinkSelectedGitHubRepository,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>> {
        Box::pin(async move {
            validate_repository(&r.repository)?;
            for value in [&r.tenant_id, &r.installation_id, &r.external_repository_id] {
                validate_text("GitHub repository link binding", value)?;
            }
            if r.repository.tenant_id != r.tenant_id {
                return Err(ControlPlaneError::InvalidInput(
                    "GitHub repository tenant binding differs",
                ));
            }
            let mut tx = self.pool().begin().await?;
            require_tenant_pg(&mut tx, &r.tenant_id).await?;
            let installation =
                github_installation_optional(&mut tx, &r.tenant_id, &r.installation_id)
                    .await?
                    .filter(|x| x.installation.status == "active")
                    .ok_or_else(|| {
                        not_found("GitHub repository authorization", &r.repository.id)
                    })?;
            let c = github_catalog_optional(
                &mut tx,
                &r.tenant_id,
                &r.installation_id,
                &r.external_repository_id,
            )
            .await?
            .filter(|x| x.status == "selected")
            .ok_or_else(|| not_found("GitHub repository authorization", &r.repository.id))?;
            if installation.web_origin != c.web_origin
                || installation.api_origin != c.api_origin
                || r.repository.owner != c.owner
                || r.repository.name != c.name
                || r.repository.default_branch != c.default_branch
                || r.repository.visibility != c.visibility
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if let Some(existing_repository) =
                repository_optional_tx(&mut tx, &r.repository.id).await?
            {
                if existing_repository != r.repository {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else {
                sqlx::query("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&r.repository.id).bind(&r.repository.tenant_id).bind(&r.repository.owner).bind(&r.repository.name).bind(&r.repository.default_branch).bind(&r.repository.visibility).bind(to_i64(r.repository.created_unix_ms,"repository creation")?).execute(&mut *tx).await?;
            }
            if let Some(existing) = scm_repository_link_optional(&mut tx, &r.repository.id).await? {
                if existing.tenant_id != r.tenant_id
                    || existing.installation_id != r.installation_id
                    || existing.external_repository_id != r.external_repository_id
                    || existing.clone_url != c.clone_url
                    || existing.status == "revoked"
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                if existing.status == "active" {
                    tx.commit().await?;
                    return Ok(IdempotentResult {
                        value: existing,
                        replayed: true,
                    });
                }
                sqlx::query("UPDATE scm_repository_links SET status='active',updated_unix_ms=$3 WHERE tenant_id=$1 AND repository_id=$2 AND status='suspended'").bind(&r.tenant_id).bind(&r.repository.id).bind(to_i64(r.now_unix_ms,"GitHub link reactivation")?).execute(&mut *tx).await?;
                let value = scm_repository_link_by_id(&mut tx, &r.repository.id).await?;
                append_github_audit_pg(
                    &mut tx,
                    &self.installation_id,
                    r.now_unix_ms,
                    &r.tenant_id,
                    "github-installation-reconciler",
                    "github.repository.link",
                    "repository",
                    &r.repository.id,
                    &format!("{}:{}", r.installation_id, r.external_repository_id),
                    BTreeMap::from([(
                        "external_repository_id".to_owned(),
                        AuditValue::String(r.external_repository_id.clone()),
                    )]),
                )
                .await?;
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value,
                    replayed: false,
                });
            }
            let conflicting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM scm_repository_links WHERE installation_id=$1 AND external_repository_id=$2)").bind(&r.installation_id).bind(&r.external_repository_id).fetch_one(&mut *tx).await?;
            if conflicting {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO scm_repository_links(repository_id,tenant_id,installation_id,external_repository_id,clone_url,status,created_unix_ms,updated_unix_ms) VALUES($1,$2,$3,$4,$5,'active',$6,$6)").bind(&r.repository.id).bind(&r.tenant_id).bind(&r.installation_id).bind(&r.external_repository_id).bind(&c.clone_url).bind(to_i64(r.now_unix_ms,"GitHub link")?).execute(&mut *tx).await?;
            let existing = scm_repository_link_by_id(&mut tx, &r.repository.id).await?;
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                r.now_unix_ms,
                &r.tenant_id,
                "github-installation-reconciler",
                "github.repository.link",
                "repository",
                &r.repository.id,
                &format!("{}:{}", r.installation_id, r.external_repository_id),
                BTreeMap::from([(
                    "external_repository_id".to_owned(),
                    AuditValue::String(r.external_repository_id.clone()),
                )]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: existing,
                replayed: false,
            })
        })
    }
    fn github_repository_links_for_tenant<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
        a: Option<&'a str>,
        l: usize,
    ) -> StoreFuture<'a, Vec<ScmRepositoryLinkRecord>> {
        Box::pin(async move {
            validate_text("GitHub repository link tenant", t)?;
            validate_text("GitHub installation id", i)?;
            validate_page_pg(l, a)?;
            if github_installation_optional_pool(self.pool(), t, i)
                .await?
                .is_none()
            {
                return Err(not_found("GitHub installation", i));
            }
            let rows=sqlx::query("SELECT * FROM scm_repository_links WHERE tenant_id=$1 AND installation_id=$2 AND repository_id>$3 ORDER BY repository_id LIMIT $4").bind(t).bind(i).bind(a.unwrap_or("")).bind(i64::try_from(l).map_err(|_|ControlPlaneError::InvalidInput("invalid page limit"))?).fetch_all(self.pool()).await?;
            rows.iter().map(scm_repository_link_row).collect()
        })
    }
    fn suspend_github_repository_link<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
        a: &'a str,
        q: &'a str,
        n: u64,
    ) -> StoreFuture<'a, IdempotentResult<ScmRepositoryLinkRecord>> {
        Box::pin(async move {
            for (field, value) in [
                ("GitHub repository link tenant", t),
                ("GitHub repository link repository", r),
                ("GitHub repository link actor", a),
                ("GitHub repository link request", q),
            ] {
                validate_text(field, value)?;
            }
            let mut tx = self.pool().begin().await?;
            require_tenant_pg(&mut tx, t).await?;
            let before = scm_repository_link_by_id(&mut tx, r).await?;
            if before.tenant_id != t {
                return Err(not_found("GitHub repository link", r));
            }
            if before.status == "suspended" {
                return Ok(IdempotentResult {
                    value: before,
                    replayed: true,
                });
            }
            if before.status != "active" {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("UPDATE scm_repository_links SET status='suspended',updated_unix_ms=$3 WHERE tenant_id=$1 AND repository_id=$2").bind(t).bind(r).bind(to_i64(n,"GitHub link suspension")?).execute(&mut *tx).await?;
            let v = scm_repository_link_by_id(&mut tx, r).await?;
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                n,
                t,
                a,
                "github.repository.unlink",
                "repository",
                r,
                q,
                BTreeMap::from([
                    (
                        "external_repository_id".to_owned(),
                        AuditValue::String(v.external_repository_id.clone()),
                    ),
                    (
                        "installation_id".to_owned(),
                        AuditValue::String(v.installation_id.clone()),
                    ),
                ]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: v,
                replayed: false,
            })
        })
    }
    fn create_github_setup_transaction<'a>(
        &'a self,
        r: &'a CreateGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        Box::pin(async move {
            validate_setup_request(r)?;
            let mut tx = self.pool().begin().await?;
            require_setup_principal(&mut tx, &r.tenant_id, &r.principal_id, r.created_unix_ms)
                .await?;
            if let Some(x) = setup_by_key(&mut tx, &r.tenant_id, &r.idempotency_key).await? {
                if x.request_digest != r.request_digest
                    || x.principal_id != r.principal_id
                    || x.github_web_origin != r.github_web_origin
                    || x.github_api_origin != r.github_api_origin
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: x,
                    replayed: true,
                });
            }
            let inserted=sqlx::query("INSERT INTO github_app_setup_transactions(id,tenant_id,principal_id,idempotency_key,request_digest,state_digest,github_web_origin,github_api_origin,return_path,status,attempts,expires_unix_ms,created_unix_ms,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',0,$10,$11,$11) ON CONFLICT DO NOTHING").bind(&r.id).bind(&r.tenant_id).bind(&r.principal_id).bind(&r.idempotency_key).bind(r.request_digest.as_str()).bind(r.state_digest.as_str()).bind(&r.github_web_origin).bind(&r.github_api_origin).bind(&r.return_path).bind(to_i64(r.expires_unix_ms,"GitHub setup expiry")?).bind(to_i64(r.created_unix_ms,"GitHub setup creation")?).execute(&mut *tx).await?.rows_affected();
            if inserted != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let x = setup_by_id(&mut tx, &r.tenant_id, &r.id)
                .await?
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState("GitHub setup unreadable".to_owned())
                })?;
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                r.created_unix_ms,
                &r.tenant_id,
                &r.principal_id,
                "github.setup.create",
                "github-setup",
                &r.id,
                &r.idempotency_key,
                BTreeMap::from([
                    (
                        "request_digest".to_owned(),
                        AuditValue::Digest(r.request_digest.clone()),
                    ),
                    (
                        "expires_unix_ms".to_owned(),
                        AuditValue::Integer(to_i64(r.expires_unix_ms, "GitHub setup expiry")?),
                    ),
                ]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: x,
                replayed: false,
            })
        })
    }
    fn begin_github_setup_by_state<'a>(
        &'a self,
        s: &'a runtrue_model::ContentDigest,
        n: u64,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let x = sqlx::query(
                "SELECT * FROM github_app_setup_transactions WHERE state_digest=$1 FOR UPDATE",
            )
            .bind(s.as_str())
            .fetch_optional(&mut *tx)
            .await?
            .as_ref()
            .map(setup_row)
            .transpose()?
            .ok_or(ControlPlaneError::InvalidGitHubSetupState)?;
            if !setup_principal_active(&mut tx, &x.tenant_id, &x.principal_id, n).await? {
                return Err(ControlPlaneError::InvalidGitHubSetupState);
            }
            let out = advance_setup(&mut tx, x, n).await?;
            tx.commit().await?;
            out.ok_or(ControlPlaneError::InvalidGitHubSetupState)
        })
    }
    fn begin_github_setup_transaction<'a>(
        &'a self,
        r: &'a BeginGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            require_setup_principal(&mut tx, &r.tenant_id, &r.principal_id, r.now_unix_ms).await?;
            let x = setup_exact(&mut tx, r)
                .await?
                .ok_or(ControlPlaneError::InvalidGitHubSetupState)?;
            let out = advance_setup(&mut tx, x, r.now_unix_ms).await?;
            tx.commit().await?;
            out.ok_or(ControlPlaneError::InvalidGitHubSetupState)
        })
    }
    fn reject_github_setup_transaction<'a>(
        &'a self,
        r: &'a BeginGitHubSetupTransaction,
        e: &'a str,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        Box::pin(async move {
            validate_text("GitHub setup error code", e)?;
            let mut tx = self.pool().begin().await?;
            require_setup_principal(&mut tx, &r.tenant_id, &r.principal_id, r.now_unix_ms).await?;
            let x = setup_exact(&mut tx, r)
                .await?
                .ok_or(ControlPlaneError::InvalidGitHubSetupState)?;
            if x.status == GitHubSetupStatus::Rejected {
                if x.last_error_code.as_deref() != Some(e) {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                return Ok(IdempotentResult {
                    value: x,
                    replayed: true,
                });
            }
            if !matches!(
                x.status,
                GitHubSetupStatus::Pending | GitHubSetupStatus::Exchanging
            ) || r.now_unix_ms < x.updated_unix_ms
            {
                return Err(ControlPlaneError::InvalidGitHubSetupState);
            }
            sqlx::query("UPDATE github_app_setup_transactions SET status='rejected',last_error_code=$5,updated_unix_ms=$6 WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND state_digest=$4").bind(&r.tenant_id).bind(&r.principal_id).bind(&r.transaction_id).bind(r.state_digest.as_str()).bind(e).bind(to_i64(r.now_unix_ms,"GitHub setup rejection")?).execute(&mut *tx).await?;
            let v = setup_by_id(&mut tx, &r.tenant_id, &r.transaction_id)
                .await?
                .unwrap();
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                r.now_unix_ms,
                &r.tenant_id,
                &r.principal_id,
                "github.setup.reject",
                "github-setup",
                &r.transaction_id,
                &r.transaction_id,
                BTreeMap::from([(
                    "error_digest".to_owned(),
                    AuditValue::Digest(ContentDigest::sha256(e.as_bytes())),
                )]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: v,
                replayed: false,
            })
        })
    }
    fn complete_github_setup_transaction<'a>(
        &'a self,
        r: &'a CompleteGitHubSetupTransaction,
    ) -> StoreFuture<'a, IdempotentResult<GitHubSetupTransactionRecord>> {
        Box::pin(async move {
            if r.now_unix_ms != r.reconciliation.now_unix_ms {
                return Err(ControlPlaneError::InvalidInput(
                    "GitHub setup completion timestamps differ",
                ));
            }
            validate_github_reconciliation_pg(&r.reconciliation)?;
            let completion = github_reconciliation_digest_pg(&r.reconciliation)?;
            let installation = &r.reconciliation.installation.installation;
            let mut tx = self.pool().begin().await?;
            require_setup_principal(&mut tx, &r.tenant_id, &r.principal_id, r.now_unix_ms).await?;
            let x = setup_exact_complete(
                &mut tx,
                &r.tenant_id,
                &r.principal_id,
                &r.transaction_id,
                &r.state_digest,
            )
            .await?
            .ok_or(ControlPlaneError::InvalidGitHubSetupState)?;
            if x.status == GitHubSetupStatus::Completed {
                if x.installation_id.as_deref() != Some(&installation.id)
                    || x.installation_external_id.as_deref() != Some(&installation.external_id)
                    || x.github_web_origin != r.reconciliation.installation.web_origin
                    || x.github_api_origin != r.reconciliation.installation.api_origin
                    || x.completion_digest.as_ref() != Some(&completion)
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                return Ok(IdempotentResult {
                    value: x,
                    replayed: true,
                });
            }
            if x.status != GitHubSetupStatus::Exchanging
                || r.now_unix_ms >= x.expires_unix_ms
                || r.now_unix_ms < x.updated_unix_ms
                || installation.tenant_id != x.tenant_id
                || x.github_web_origin != r.reconciliation.installation.web_origin
                || x.github_api_origin != r.reconciliation.installation.api_origin
            {
                return Err(ControlPlaneError::InvalidGitHubSetupState);
            }
            reconcile_github_installation_pg_tx(&mut tx, &r.reconciliation).await?;
            sqlx::query("UPDATE github_app_setup_transactions SET status='completed',installation_id=$5,installation_external_id=$6,completion_digest=$7,updated_unix_ms=$8,completed_unix_ms=$8 WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND state_digest=$4 AND status='exchanging'").bind(&r.tenant_id).bind(&r.principal_id).bind(&r.transaction_id).bind(r.state_digest.as_str()).bind(&installation.id).bind(&installation.external_id).bind(completion.as_str()).bind(to_i64(r.now_unix_ms,"GitHub setup completion")?).execute(&mut *tx).await?;
            let v = setup_by_id(&mut tx, &r.tenant_id, &r.transaction_id)
                .await?
                .unwrap();
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                r.now_unix_ms,
                &r.tenant_id,
                &r.principal_id,
                "github.setup.complete",
                "github-installation",
                &installation.id,
                &r.transaction_id,
                BTreeMap::from([
                    (
                        "completion_digest".to_owned(),
                        AuditValue::Digest(completion),
                    ),
                    (
                        "external_installation_id".to_owned(),
                        AuditValue::String(installation.external_id.clone()),
                    ),
                    (
                        "selected_repository_count".to_owned(),
                        AuditValue::Integer(
                            i64::try_from(r.reconciliation.selected_repositories.len()).map_err(
                                |_| ControlPlaneError::IntegerRange {
                                    field: "GitHub selected repository count",
                                },
                            )?,
                        ),
                    ),
                ]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: v,
                replayed: false,
            })
        })
    }
    fn reserve_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a ReserveGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>> {
        Box::pin(async move {
            validate_lifecycle_reservation(r)?;
            let mut tx = self.pool().begin().await?;
            require_tenant_pg(&mut tx, &r.tenant_id).await?;
            let installation =
                github_installation_optional(&mut tx, &r.tenant_id, &r.installation_id)
                    .await?
                    .filter(|x| x.installation.external_id == r.installation_external_id)
                    .ok_or_else(|| not_found("GitHub lifecycle authorization", &r.delivery_id))?;
            if installation.installation.id != r.installation_id {
                return Err(not_found("GitHub lifecycle authorization", &r.delivery_id));
            }
            let inserted=sqlx::query("INSERT INTO github_lifecycle_deliveries(delivery_id,tenant_id,installation_id,installation_external_id,event_name,action,payload_digest,state,attempts,available_unix_ms,lease_generation,created_unix_ms,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,'pending',0,$8,0,$8,$8) ON CONFLICT DO NOTHING")
                .bind(&r.delivery_id).bind(&r.tenant_id).bind(&r.installation_id).bind(&r.installation_external_id).bind(&r.event_name).bind(&r.action).bind(r.payload_digest.as_str()).bind(to_i64(r.now_unix_ms,"GitHub lifecycle creation")?).execute(&mut *tx).await?.rows_affected();
            let existing = lifecycle_by_id(&mut tx, &r.tenant_id, &r.delivery_id)
                .await?
                .ok_or_else(|| not_found("GitHub lifecycle authorization", &r.delivery_id))?;
            if existing.installation_id != r.installation_id
                || existing.installation_external_id != r.installation_external_id
                || existing.event_name != r.event_name
                || existing.action != r.action
                || existing.payload_digest != r.payload_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if inserted == 1 {
                append_github_audit_pg(
                    &mut tx,
                    &self.installation_id,
                    r.now_unix_ms,
                    &r.tenant_id,
                    "github-webhook",
                    "github.lifecycle.reserve",
                    "github-lifecycle-delivery",
                    &r.delivery_id,
                    &r.delivery_id,
                    BTreeMap::from([
                        (
                            "payload_digest".to_owned(),
                            AuditValue::Digest(r.payload_digest.clone()),
                        ),
                        (
                            "external_installation_id".to_owned(),
                            AuditValue::String(r.installation_external_id.clone()),
                        ),
                    ]),
                )
                .await?;
            }
            tx.commit().await?;
            Ok(IdempotentResult {
                value: existing,
                replayed: inserted == 0,
            })
        })
    }
    fn claim_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a ClaimGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, Option<IdempotentResult<GitHubLifecycleDeliveryRecord>>> {
        Box::pin(async move {
            validate_lifecycle_claim(&r.worker_id, r.now_unix_ms, r.lease_duration_ms)?;
            validate_text("GitHub lifecycle tenant", &r.tenant_id)?;
            validate_text("GitHub lifecycle delivery", &r.delivery_id)?;
            let mut tx = self.pool().begin().await?;
            require_tenant_pg(&mut tx, &r.tenant_id).await?;
            let record = lifecycle_by_id_locked(&mut tx, &r.tenant_id, &r.delivery_id)
                .await?
                .ok_or_else(|| not_found("GitHub lifecycle delivery", &r.delivery_id))?;
            let claimed = claim_lifecycle_tx(
                &mut tx,
                record,
                &r.worker_id,
                r.now_unix_ms,
                r.lease_duration_ms,
            )
            .await?;
            tx.commit().await?;
            Ok(claimed)
        })
    }
    fn claim_next_github_lifecycle_delivery<'a>(
        &'a self,
        w: &'a str,
        n: u64,
        d: u64,
    ) -> StoreFuture<'a, Option<GitHubLifecycleDeliveryRecord>> {
        Box::pin(async move {
            validate_lifecycle_claim(w, n, d)?;
            let mut tx = self.pool().begin().await?;
            fail_exhausted_lifecycle(&mut tx, n).await?;
            let candidate=sqlx::query("SELECT * FROM github_lifecycle_deliveries WHERE attempts<8 AND ((state='pending' AND available_unix_ms<=$1) OR (state='leased' AND lease_expires_unix_ms<=$1)) ORDER BY available_unix_ms,delivery_id FOR UPDATE SKIP LOCKED LIMIT 1")
                .bind(to_i64(n,"GitHub lifecycle claim")?).fetch_optional(&mut *tx).await?.as_ref().map(lifecycle_row).transpose()?;
            let claimed = if let Some(record) = candidate {
                claim_lifecycle_tx(&mut tx, record, w, n, d)
                    .await?
                    .map(|x| x.value)
            } else {
                None
            };
            tx.commit().await?;
            Ok(claimed)
        })
    }
    fn complete_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a CompleteGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>> {
        Box::pin(async move {
            validate_lifecycle_mutation(
                &r.tenant_id,
                &r.delivery_id,
                &r.worker_id,
                r.lease_generation,
            )?;
            let mut tx = self.pool().begin().await?;
            require_tenant_pg(&mut tx, &r.tenant_id).await?;
            let record = lifecycle_by_id_locked(&mut tx, &r.tenant_id, &r.delivery_id)
                .await?
                .ok_or_else(|| not_found("GitHub lifecycle delivery", &r.delivery_id))?;
            if record.state == GitHubLifecycleDeliveryState::Completed {
                if record.completion_digest.as_ref() != Some(&r.completion_digest)
                    || record.completed_lease_owner.as_deref() != Some(&r.worker_id)
                    || record.completed_lease_generation != Some(r.lease_generation)
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: record,
                    replayed: true,
                });
            }
            require_lifecycle_lease(&record, &r.worker_id, r.lease_generation, r.now_unix_ms)?;
            sqlx::query("UPDATE github_lifecycle_deliveries SET state='completed',lease_owner=NULL,lease_expires_unix_ms=NULL,completion_digest=$3,completed_lease_owner=$4,completed_lease_generation=$5,updated_unix_ms=$6,completed_unix_ms=$6 WHERE tenant_id=$1 AND delivery_id=$2")
                .bind(&r.tenant_id).bind(&r.delivery_id).bind(r.completion_digest.as_str()).bind(&r.worker_id).bind(to_i64(r.lease_generation,"GitHub lifecycle generation")?).bind(to_i64(r.now_unix_ms,"GitHub lifecycle completion")?).execute(&mut *tx).await?;
            let value = lifecycle_by_id(&mut tx, &r.tenant_id, &r.delivery_id)
                .await?
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "completed GitHub lifecycle delivery was not readable".to_owned(),
                    )
                })?;
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                r.now_unix_ms,
                &r.tenant_id,
                &r.worker_id,
                "github.lifecycle.complete",
                "github-lifecycle-delivery",
                &r.delivery_id,
                &r.delivery_id,
                BTreeMap::from([(
                    "completion_digest".to_owned(),
                    AuditValue::Digest(r.completion_digest.clone()),
                )]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }
    fn fail_github_lifecycle_delivery<'a>(
        &'a self,
        r: &'a FailGitHubLifecycleDelivery,
    ) -> StoreFuture<'a, IdempotentResult<GitHubLifecycleDeliveryRecord>> {
        Box::pin(async move {
            validate_lifecycle_mutation(
                &r.tenant_id,
                &r.delivery_id,
                &r.worker_id,
                r.lease_generation,
            )?;
            if let Some(retry) = r.retry_unix_ms {
                let max = r.now_unix_ms.checked_add(60 * 60 * 1_000).ok_or(
                    ControlPlaneError::IntegerRange {
                        field: "GitHub lifecycle retry deadline",
                    },
                )?;
                if retry < r.now_unix_ms || retry > max {
                    return Err(ControlPlaneError::InvalidInput(
                        "GitHub lifecycle retry is outside its bound",
                    ));
                }
            }
            let mut tx = self.pool().begin().await?;
            require_tenant_pg(&mut tx, &r.tenant_id).await?;
            let record = lifecycle_by_id_locked(&mut tx, &r.tenant_id, &r.delivery_id)
                .await?
                .ok_or_else(|| not_found("GitHub lifecycle delivery", &r.delivery_id))?;
            if record.last_failure_generation == Some(r.lease_generation)
                && record.last_failure_lease_owner.as_deref() == Some(&r.worker_id)
            {
                if record.last_error_digest.as_ref() != Some(&r.error_digest)
                    || record.last_retry_unix_ms != r.retry_unix_ms
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: record,
                    replayed: true,
                });
            }
            require_lifecycle_lease(&record, &r.worker_id, r.lease_generation, r.now_unix_ms)?;
            let retry = r.retry_unix_ms.filter(|_| record.attempts < 8);
            let state = if retry.is_some() { "pending" } else { "failed" };
            let available = retry.unwrap_or(r.now_unix_ms);
            sqlx::query("UPDATE github_lifecycle_deliveries SET state=$3,available_unix_ms=$4,lease_owner=NULL,lease_expires_unix_ms=NULL,last_failure_generation=$5,last_failure_lease_owner=$6,last_error_digest=$7,last_retry_unix_ms=$8,updated_unix_ms=$9 WHERE tenant_id=$1 AND delivery_id=$2")
                .bind(&r.tenant_id).bind(&r.delivery_id).bind(state).bind(to_i64(available,"GitHub lifecycle availability")?).bind(to_i64(r.lease_generation,"GitHub lifecycle generation")?).bind(&r.worker_id).bind(r.error_digest.as_str()).bind(opt_i64_pg(retry,"GitHub lifecycle retry")?).bind(to_i64(r.now_unix_ms,"GitHub lifecycle failure")?).execute(&mut *tx).await?;
            let value = lifecycle_by_id(&mut tx, &r.tenant_id, &r.delivery_id)
                .await?
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "failed GitHub lifecycle delivery was not readable".to_owned(),
                    )
                })?;
            append_github_audit_pg(
                &mut tx,
                &self.installation_id,
                r.now_unix_ms,
                &r.tenant_id,
                &r.worker_id,
                "github.lifecycle.fail",
                "github-lifecycle-delivery",
                &r.delivery_id,
                &format!("{}:{}", r.delivery_id, r.lease_generation),
                BTreeMap::from([
                    (
                        "error_digest".to_owned(),
                        AuditValue::Digest(r.error_digest.clone()),
                    ),
                    (
                        "retry_scheduled".to_owned(),
                        AuditValue::Boolean(retry.is_some()),
                    ),
                ]),
            )
            .await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }
    fn github_repository_for_event<'a>(
        &'a self,
        i: &'a str,
        r: &'a str,
        o: &'a str,
        n: &'a str,
    ) -> StoreFuture<
        'a,
        (
            RepositoryRecord,
            ScmInstallationRecord,
            ScmRepositoryLinkRecord,
        ),
    > {
        Box::pin(async move {
            for (field, value) in [
                ("SCM installation external id", i),
                ("SCM repository external id", r),
                ("repository owner", o),
                ("repository name", n),
            ] {
                validate_text(field, value)?;
            }
            let row=sqlx::query("SELECT r.id AS r_id,r.tenant_id AS r_tenant_id,r.owner,r.name,r.default_branch,r.visibility,r.created_unix_ms AS r_created_unix_ms,i.id AS i_id,i.tenant_id AS i_tenant_id,i.provider,i.external_id,i.credential_reference,i.permissions_json,i.status AS i_status,i.created_unix_ms AS i_created_unix_ms,i.updated_unix_ms AS i_updated_unix_ms,l.repository_id,l.tenant_id AS l_tenant_id,l.installation_id,l.external_repository_id,l.clone_url,l.status AS l_status,l.created_unix_ms AS l_created_unix_ms,l.updated_unix_ms AS l_updated_unix_ms FROM scm_installations i JOIN scm_repository_links l ON l.installation_id=i.id AND l.tenant_id=i.tenant_id JOIN repositories r ON r.id=l.repository_id AND r.tenant_id=l.tenant_id WHERE i.provider='github' AND i.external_id=$1 AND l.external_repository_id=$2 AND r.owner=$3 AND r.name=$4 AND i.status='active' AND l.status='active'")
                .bind(i).bind(r).bind(o).bind(n).fetch_optional(self.pool()).await?.ok_or_else(||not_found("SCM repository authorization",&format!("{o}/{n}")))?;
            event_binding_row(&row)
        })
    }
    fn complete_scm_task_with_run_idempotent<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        n: u64,
        k: &'a str,
        c: &'a SignedCapsuleRecord,
        v: &'a runtrue_attest::CapsuleVerifyingKey,
        m: &'a CapsuleApiMetadata,
        r: &'a CreateRunRequest,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>> {
        Box::pin(async move { complete_scm_single_pg(self, t, w, n, k, c, v, m, r).await })
    }
    fn complete_scm_task_with_executions_idempotent<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        n: u64,
        k: &'a str,
        e: &'a [PreparedScmExecution],
        a: Option<&'a ScmProposedAnalysisRecord>,
        v: &'a runtrue_attest::CapsuleVerifyingKey,
    ) -> StoreFuture<'a, IdempotentResult<ScmTaskCompletion>> {
        Box::pin(async move { complete_scm_executions_pg(self, t, w, n, k, e, a, v).await })
    }
    fn scm_pending_execution<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ScmPendingExecution> {
        Box::pin(async move {
            validate_text("SCM pending execution id", id)?;
            scm_pending_pool(self.pool(), id).await
        })
    }
    fn scm_proposed_analysis_for_task<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, ScmProposedAnalysisRecord> {
        Box::pin(async move {
            validate_text("SCM task id", id)?;
            let row = sqlx::query("SELECT * FROM scm_proposed_analyses WHERE origin_task_id=$1")
                .bind(id)
                .fetch_optional(self.pool())
                .await?
                .ok_or_else(|| not_found("SCM proposed analysis", id))?;
            scm_analysis_row_pg(&row)
        })
    }
    fn scm_pending_execution_approvals<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        Box::pin(async move {
            validate_text("SCM pending execution id", id)?;
            let p = scm_pending_pool(self.pool(), id).await?;
            pending_approvals_pg(self.pool(), &p).await
        })
    }
    fn begin_scm_continuation<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        p: &'a str,
        n: u64,
    ) -> StoreFuture<'a, ScmContinuationResolution> {
        Box::pin(async move { begin_scm_continuation_pg(self, t, w, p, n).await })
    }
    fn close_scm_continuation_as_stale<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        p: &'a str,
        r: &'a str,
        n: u64,
    ) -> StoreFuture<'a, ScmPendingExecution> {
        Box::pin(async move { close_scm_continuation_pg(self, t, w, p, r, n).await })
    }
    fn complete_scm_continuation_with_run_idempotent<'a>(
        &'a self,
        t: &'a str,
        w: &'a str,
        p: &'a str,
        n: u64,
        c: &'a SignedCapsuleRecord,
        v: &'a runtrue_attest::CapsuleVerifyingKey,
        m: &'a CapsuleApiMetadata,
        x: &'a ScmContinuationContext,
        r: &'a CreateRunRequest,
    ) -> StoreFuture<'a, ScmContinuationCommit> {
        Box::pin(async move { complete_scm_continuation_pg(self, t, w, p, n, c, v, m, x, r).await })
    }
    fn store_workflow_frontend_report<'a>(
        &'a self,
        r: &'a WorkflowFrontendReportRecord,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            validate_frontend_report_pg(&mut tx, r).await?;
            sqlx::query("INSERT INTO workflow_frontend_reports(capsule_id,media_type,report_bytes) VALUES($1,$2,$3)").bind(&r.capsule_id).bind(&r.media_type).bind(&r.bytes).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(())
        })
    }
    fn workflow_frontend_report<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, WorkflowFrontendReportRecord> {
        Box::pin(async move {
            validate_text("capsule.id", id)?;
            let mut tx = self.pool().begin().await?;
            let row=sqlx::query("SELECT capsule_id,media_type,report_bytes FROM workflow_frontend_reports WHERE capsule_id=$1").bind(id).fetch_optional(&mut *tx).await?.ok_or_else(||not_found("workflow frontend report",id))?;
            let r = WorkflowFrontendReportRecord {
                capsule_id: row.try_get("capsule_id")?,
                media_type: row.try_get("media_type")?,
                bytes: row.try_get("report_bytes")?,
            };
            validate_frontend_report_pg(&mut tx, &r).await?;
            tx.commit().await?;
            Ok(r)
        })
    }
}

#[cfg(feature = "postgres")]
async fn repository_by_id<'e, E>(
    executor: E,
    id: &str,
) -> Result<RepositoryRecord, ControlPlaneError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query(
        "SELECT id, tenant_id, owner, name, default_branch, visibility, created_unix_ms
         FROM repositories WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| not_found("repository", id))?;
    repository_row(&row)
}

#[cfg(feature = "postgres")]
async fn repository_optional_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> Result<Option<RepositoryRecord>, ControlPlaneError> {
    sqlx::query("SELECT id,tenant_id,owner,name,default_branch,visibility,created_unix_ms FROM repositories WHERE id=$1")
        .bind(id).fetch_optional(&mut **tx).await?.as_ref().map(repository_row).transpose()
}

#[cfg(feature = "postgres")]
fn repository_row(row: &sqlx::postgres::PgRow) -> Result<RepositoryRecord, ControlPlaneError> {
    Ok(RepositoryRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        owner: row.try_get("owner")?,
        name: row.try_get("name")?,
        default_branch: row.try_get("default_branch")?,
        visibility: row.try_get("visibility")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "repository creation")?,
    })
}

#[cfg(feature = "postgres")]
async fn scm_installation_by_id<'e, E>(
    executor: E,
    id: &str,
) -> Result<ScmInstallationRecord, ControlPlaneError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query(
        "SELECT id, tenant_id, provider, external_id, credential_reference,
                permissions_json, status, created_unix_ms, updated_unix_ms
         FROM scm_installations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| not_found("SCM installation", id))?;
    scm_installation_row(&row)
}

#[cfg(feature = "postgres")]
fn scm_installation_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ScmInstallationRecord, ControlPlaneError> {
    let permissions: Vec<u8> = row.try_get("permissions_json")?;
    if permissions.len() > 1024 * 1024 {
        return Err(ControlPlaneError::CorruptState(
            "PostgreSQL SCM installation permissions exceed their byte bound".to_owned(),
        ));
    }
    Ok(ScmInstallationRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        provider: row.try_get("provider")?,
        external_id: row.try_get("external_id")?,
        credential_reference: row.try_get("credential_reference")?,
        permissions: serde_json::from_slice(&permissions)?,
        status: row.try_get("status")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "SCM installation creation")?,
        updated_unix_ms: from_i64(row.try_get("updated_unix_ms")?, "SCM installation update")?,
    })
}

#[cfg(feature = "postgres")]
async fn scm_repository_link_by_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repository_id: &str,
) -> Result<ScmRepositoryLinkRecord, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT repository_id, tenant_id, installation_id, external_repository_id,
                clone_url, status, created_unix_ms, updated_unix_ms
         FROM scm_repository_links WHERE repository_id = $1",
    )
    .bind(repository_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| not_found("SCM repository link", repository_id))?;
    Ok(ScmRepositoryLinkRecord {
        repository_id: row.try_get("repository_id")?,
        tenant_id: row.try_get("tenant_id")?,
        installation_id: row.try_get("installation_id")?,
        external_repository_id: row.try_get("external_repository_id")?,
        clone_url: row.try_get("clone_url")?,
        status: row.try_get("status")?,
        created_unix_ms: from_i64(
            row.try_get("created_unix_ms")?,
            "SCM repository link creation",
        )?,
        updated_unix_ms: from_i64(
            row.try_get("updated_unix_ms")?,
            "SCM repository link update",
        )?,
    })
}

#[cfg(feature = "postgres")]
async fn scm_repository_link_optional(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repository_id: &str,
) -> Result<Option<ScmRepositoryLinkRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM scm_repository_links WHERE repository_id=$1")
        .bind(repository_id)
        .fetch_optional(&mut **tx)
        .await?
        .as_ref()
        .map(scm_repository_link_row)
        .transpose()
}

#[cfg(feature = "postgres")]
fn scm_repository_link_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ScmRepositoryLinkRecord, ControlPlaneError> {
    Ok(ScmRepositoryLinkRecord {
        repository_id: row.try_get("repository_id")?,
        tenant_id: row.try_get("tenant_id")?,
        installation_id: row.try_get("installation_id")?,
        external_repository_id: row.try_get("external_repository_id")?,
        clone_url: row.try_get("clone_url")?,
        status: row.try_get("status")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "SCM link creation")?,
        updated_unix_ms: from_i64(row.try_get("updated_unix_ms")?, "SCM link update")?,
    })
}
#[cfg(feature = "postgres")]
async fn github_installation_optional(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    t: &str,
    i: &str,
) -> Result<Option<GitHubInstallationRecord>, ControlPlaneError> {
    sqlx::query("SELECT i.*,p.* FROM scm_installations i JOIN github_installation_profiles p ON p.installation_id=i.id AND p.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.id=$2").bind(t).bind(i).fetch_optional(&mut **tx).await?.as_ref().map(github_installation_row).transpose()
}
#[cfg(feature = "postgres")]
async fn github_installation_optional_pool(
    pool: &sqlx::PgPool,
    t: &str,
    i: &str,
) -> Result<Option<GitHubInstallationRecord>, ControlPlaneError> {
    sqlx::query("SELECT i.*,p.* FROM scm_installations i JOIN github_installation_profiles p ON p.installation_id=i.id AND p.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.id=$2").bind(t).bind(i).fetch_optional(pool).await?.as_ref().map(github_installation_row).transpose()
}
#[cfg(feature = "postgres")]
async fn github_installation_required(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    t: &str,
    i: &str,
) -> Result<GitHubInstallationRecord, ControlPlaneError> {
    github_installation_optional(tx, t, i)
        .await?
        .ok_or_else(|| not_found("GitHub installation", i))
}
#[cfg(feature = "postgres")]
fn github_installation_row(
    row: &sqlx::postgres::PgRow,
) -> Result<GitHubInstallationRecord, ControlPlaneError> {
    let kind: String = row.try_get("account_kind")?;
    let sel: String = row.try_get("repository_selection")?;
    let p: Vec<u8> = row.try_get("permissions_json")?;
    Ok(GitHubInstallationRecord {
        installation: ScmInstallationRecord {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            provider: row.try_get("provider")?,
            external_id: row.try_get("external_id")?,
            credential_reference: row.try_get("credential_reference")?,
            permissions: serde_json::from_slice(&p)?,
            status: row.try_get("status")?,
            created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "GitHub creation")?,
            updated_unix_ms: from_i64(row.try_get("updated_unix_ms")?, "GitHub update")?,
        },
        web_origin: row.try_get("web_origin")?,
        api_origin: row.try_get("api_origin")?,
        account_external_id: row.try_get("account_external_id")?,
        account_login: row.try_get("account_login")?,
        account_kind: match kind.as_str() {
            "organization" => GitHubAccountKind::Organization,
            "user" => GitHubAccountKind::User,
            _ => {
                return Err(ControlPlaneError::CorruptState(
                    "invalid GitHub account kind".to_owned(),
                ))
            }
        },
        repository_selection: match sel.as_str() {
            "all" => GitHubRepositorySelection::All,
            "selected" => GitHubRepositorySelection::Selected,
            _ => {
                return Err(ControlPlaneError::CorruptState(
                    "invalid GitHub selection".to_owned(),
                ))
            }
        },
        lifecycle_generation: from_i64(row.try_get("lifecycle_generation")?, "GitHub generation")?,
        synchronized_unix_ms: from_i64(row.try_get("synchronized_unix_ms")?, "GitHub sync")?,
        suspended_unix_ms: row
            .try_get::<Option<i64>, _>("suspended_unix_ms")?
            .map(|v| from_i64(v, "GitHub suspension"))
            .transpose()?,
        revoked_unix_ms: row
            .try_get::<Option<i64>, _>("revoked_unix_ms")?
            .map(|v| from_i64(v, "GitHub revocation"))
            .transpose()?,
        version: from_i64(row.try_get("version")?, "GitHub version")?,
    })
}
#[cfg(feature = "postgres")]
async fn insert_github_profile(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    r: &GitHubInstallationRecord,
) -> Result<(), ControlPlaneError> {
    sqlx::query("INSERT INTO github_installation_profiles(installation_id,tenant_id,web_origin,api_origin,account_external_id,account_login,account_kind,repository_selection,lifecycle_generation,synchronized_unix_ms,suspended_unix_ms,revoked_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)").bind(&r.installation.id).bind(&r.installation.tenant_id).bind(&r.web_origin).bind(&r.api_origin).bind(&r.account_external_id).bind(&r.account_login).bind(match r.account_kind{GitHubAccountKind::Organization=>"organization",GitHubAccountKind::User=>"user"}).bind(selection_name(r.repository_selection)).bind(to_i64(r.lifecycle_generation,"GitHub generation")?).bind(to_i64(r.synchronized_unix_ms,"GitHub sync")?).bind(opt_i64_pg(r.suspended_unix_ms,"GitHub suspension")?).bind(opt_i64_pg(r.revoked_unix_ms,"GitHub revocation")?).bind(to_i64(r.version,"GitHub version")?).execute(&mut **tx).await?;
    Ok(())
}
#[cfg(feature = "postgres")]
fn selection_name(v: GitHubRepositorySelection) -> &'static str {
    match v {
        GitHubRepositorySelection::All => "all",
        GitHubRepositorySelection::Selected => "selected",
    }
}
#[cfg(feature = "postgres")]
fn opt_i64_pg(v: Option<u64>, f: &'static str) -> Result<Option<i64>, ControlPlaneError> {
    v.map(|v| to_i64(v, f)).transpose()
}
#[cfg(feature = "postgres")]
fn valid_status_transition(a: &str, b: &str) -> bool {
    matches!(
        (a, b),
        ("active", "active" | "suspended" | "revoked")
            | ("suspended", "suspended" | "active" | "revoked")
            | ("revoked", "revoked")
    )
}
#[cfg(feature = "postgres")]
async fn github_catalog_optional(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    t: &str,
    i: &str,
    e: &str,
) -> Result<Option<GitHubRepositoryCatalogRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM github_repository_catalog WHERE tenant_id=$1 AND installation_id=$2 AND external_repository_id=$3").bind(t).bind(i).bind(e).fetch_optional(&mut **tx).await?.as_ref().map(github_catalog_row).transpose()
}
#[cfg(feature = "postgres")]
fn github_catalog_row(
    row: &sqlx::postgres::PgRow,
) -> Result<GitHubRepositoryCatalogRecord, ControlPlaneError> {
    Ok(GitHubRepositoryCatalogRecord {
        installation_id: row.try_get("installation_id")?,
        external_repository_id: row.try_get("external_repository_id")?,
        tenant_id: row.try_get("tenant_id")?,
        web_origin: row.try_get("web_origin")?,
        api_origin: row.try_get("api_origin")?,
        owner: row.try_get("owner")?,
        name: row.try_get("name")?,
        full_name: row.try_get("full_name")?,
        clone_url: row.try_get("clone_url")?,
        visibility: row.try_get("visibility")?,
        default_branch: row.try_get("default_branch")?,
        status: row.try_get("status")?,
        selection_generation: from_i64(
            row.try_get("selection_generation")?,
            "GitHub catalog generation",
        )?,
        first_seen_unix_ms: from_i64(row.try_get("first_seen_unix_ms")?, "GitHub first seen")?,
        last_seen_unix_ms: from_i64(row.try_get("last_seen_unix_ms")?, "GitHub last seen")?,
        removed_unix_ms: row
            .try_get::<Option<i64>, _>("removed_unix_ms")?
            .map(|v| from_i64(v, "GitHub removal"))
            .transpose()?,
        version: from_i64(row.try_get("version")?, "GitHub catalog version")?,
    })
}
#[cfg(feature = "postgres")]
fn validate_page_pg(l: usize, a: Option<&str>) -> Result<(), ControlPlaneError> {
    if l == 0 || l > 100 {
        Err(ControlPlaneError::InvalidInput("invalid page limit"))
    } else {
        if let Some(v) = a {
            validate_text("page cursor", v)?
        }
        Ok(())
    }
}
#[cfg(feature = "postgres")]
fn validate_origins(w: &str, a: &str) -> Result<(), ControlPlaneError> {
    fn one(v: &str, path: bool) -> bool {
        let Some(x) = v.strip_prefix("https://") else {
            return false;
        };
        !x.is_empty()
            && !v.ends_with('/')
            && !x.contains(['?', '#', '@', '\\'])
            && (path || !x.contains('/'))
            && !x
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b.is_ascii_uppercase())
    }
    if one(w, false) && one(a, true) {
        Ok(())
    } else {
        Err(ControlPlaneError::InvalidInput(
            "invalid canonical GitHub origin",
        ))
    }
}
#[cfg(feature = "postgres")]
fn validate_github_reconciliation_pg(
    r: &ReconcileGitHubInstallation,
) -> Result<(), ControlPlaneError> {
    let record = &r.installation;
    let i = &record.installation;
    for value in [
        &i.id,
        &i.tenant_id,
        &i.external_id,
        &i.credential_reference,
        &record.web_origin,
        &record.api_origin,
        &record.account_external_id,
        &record.account_login,
    ] {
        validate_text("GitHub installation identity", value)?;
    }
    validate_origins(&record.web_origin, &record.api_origin)?;
    let status_timestamps_valid = match i.status.as_str() {
        "active" => record.suspended_unix_ms.is_none() && record.revoked_unix_ms.is_none(),
        "suspended" => record.suspended_unix_ms.is_some() && record.revoked_unix_ms.is_none(),
        "revoked" => record.revoked_unix_ms.is_some(),
        _ => false,
    };
    if r.now_unix_ms != r.installation.synchronized_unix_ms
        || i.updated_unix_ms != r.now_unix_ms
        || i.provider != "github"
        || !matches!(i.status.as_str(), "active" | "suspended" | "revoked")
        || i.updated_unix_ms < i.created_unix_ms
        || i.external_id
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        || record
            .account_external_id
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        || record.account_login.contains('/')
        || record
            .account_login
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || !valid_github_permissions_pg(&i.permissions)
        || !status_timestamps_valid
        || r.installation.version == 0
        || r.installation.lifecycle_generation == 0
        || record.synchronized_unix_ms < i.created_unix_ms
        || record
            .suspended_unix_ms
            .is_some_and(|value| value > record.synchronized_unix_ms)
        || record
            .revoked_unix_ms
            .is_some_and(|value| value > record.synchronized_unix_ms)
        || r.selected_repositories.len() > 1000
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub installation reconciliation",
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    for x in &r.selected_repositories {
        for v in [
            &x.external_repository_id,
            &x.owner,
            &x.name,
            &x.full_name,
            &x.clone_url,
            &x.default_branch,
        ] {
            validate_text("GitHub selected repository", v)?
        }
        if x.external_repository_id
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
            || !ids.insert(&x.external_repository_id)
            || !names.insert((&x.owner, &x.name))
            || x.owner.contains('/')
            || x.name.contains('/')
            || x.full_name != format!("{}/{}", x.owner, x.name)
            || x.clone_url != format!("{}/{}/{}.git", r.installation.web_origin, x.owner, x.name)
            || !matches!(x.visibility.as_str(), "public" | "private" | "internal")
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid GitHub selected repository",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn valid_github_permissions_pg(value: &Value) -> bool {
    let Some(permissions) = value.as_object() else {
        return false;
    };
    permissions.get("metadata").and_then(Value::as_str) == Some("read")
        && permissions.iter().all(|(name, level)| {
            let Some(level) = level.as_str() else {
                return false;
            };
            match name.as_str() {
                "metadata" => level == "read",
                "contents" | "pull_requests" | "actions" | "merge_queues" | "checks"
                | "statuses" | "issues" => matches!(level, "read" | "write"),
                _ => false,
            }
        })
}

#[cfg(feature = "postgres")]
fn validate_setup_request(r: &CreateGitHubSetupTransaction) -> Result<(), ControlPlaneError> {
    for value in [&r.id, &r.tenant_id, &r.principal_id] {
        validate_text("GitHub setup identity", value)?;
    }
    validate_origins(&r.github_web_origin, &r.github_api_origin)?;
    validate_text("GitHub setup idempotency key", &r.idempotency_key)?;
    let lifetime = r
        .expires_unix_ms
        .checked_sub(r.created_unix_ms)
        .filter(|lifetime| *lifetime > 0 && *lifetime <= 15 * 60 * 1_000)
        .ok_or(ControlPlaneError::InvalidInput(
            "invalid GitHub setup expiry",
        ))?;
    if lifetime == 0
        || r.idempotency_key.len() > 200
        || r.return_path.is_empty()
        || r.return_path.len() > 2_048
        || !r.return_path.starts_with('/')
        || r.return_path.starts_with("//")
        || r.return_path.contains('\0')
        || r.return_path.contains('\\')
        || r.return_path.bytes().any(|byte| byte.is_ascii_control())
        || r.expected_request_digest()? != r.request_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub setup request",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn setup_principal_active(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    principal_id: &str,
    now: u64,
) -> Result<bool, ControlPlaneError> {
    let tenant: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)")
        .bind(tenant_id)
        .fetch_one(&mut **tx)
        .await?;
    if !tenant {
        return Err(not_found("tenant", tenant_id));
    }
    if principal_id == "bootstrap" {
        return Ok(true);
    }
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM human_users u
             JOIN human_user_tenant_bindings b ON b.user_id=u.id
             JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=b.tenant_id
             WHERE b.tenant_id=$1 AND u.id=$2 AND u.status='active' AND m.status='active'
             UNION ALL
             SELECT 1 FROM api_tokens t WHERE t.tenant_id=$1 AND t.principal_id=$2
               AND t.revoked_unix_ms IS NULL AND t.expires_unix_ms>$3
         )",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(to_i64(now, "GitHub setup authorization time")?)
    .fetch_one(&mut **tx)
    .await
    .map_err(Into::into)
}

#[cfg(feature = "postgres")]
async fn require_setup_principal(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    principal_id: &str,
    now: u64,
) -> Result<(), ControlPlaneError> {
    validate_text("GitHub setup tenant", tenant_id)?;
    validate_text("GitHub setup principal", principal_id)?;
    if setup_principal_active(tx, tenant_id, principal_id, now).await? {
        Ok(())
    } else {
        Err(not_found("GitHub setup authorization", principal_id))
    }
}

#[cfg(feature = "postgres")]
fn setup_row(
    row: &sqlx::postgres::PgRow,
) -> Result<GitHubSetupTransactionRecord, ControlPlaneError> {
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "pending" => GitHubSetupStatus::Pending,
        "exchanging" => GitHubSetupStatus::Exchanging,
        "completed" => GitHubSetupStatus::Completed,
        "rejected" => GitHubSetupStatus::Rejected,
        "expired" => GitHubSetupStatus::Expired,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown GitHub setup status `{other}`"
            )))
        }
    };
    let attempts: i32 = row.try_get("attempts")?;
    Ok(GitHubSetupTransactionRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        principal_id: row.try_get("principal_id")?,
        idempotency_key: row.try_get("idempotency_key")?,
        request_digest: ContentDigest::parse(row.try_get::<String, _>("request_digest")?)?,
        state_digest: ContentDigest::parse(row.try_get::<String, _>("state_digest")?)?,
        github_web_origin: row.try_get("github_web_origin")?,
        github_api_origin: row.try_get("github_api_origin")?,
        return_path: row.try_get("return_path")?,
        status,
        attempts: u32::try_from(attempts).map_err(|_| ControlPlaneError::IntegerRange {
            field: "GitHub setup attempts",
        })?,
        expires_unix_ms: from_i64(row.try_get("expires_unix_ms")?, "GitHub setup expiry")?,
        installation_id: row.try_get("installation_id")?,
        installation_external_id: row.try_get("installation_external_id")?,
        completion_digest: row
            .try_get::<Option<String>, _>("completion_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        last_error_code: row.try_get("last_error_code")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "GitHub setup creation")?,
        updated_unix_ms: from_i64(row.try_get("updated_unix_ms")?, "GitHub setup update")?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|v| from_i64(v, "GitHub setup completion"))
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
async fn setup_by_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    id: &str,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM github_app_setup_transactions WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .as_ref()
        .map(setup_row)
        .transpose()
}

#[cfg(feature = "postgres")]
async fn setup_by_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    key: &str,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    sqlx::query(
        "SELECT * FROM github_app_setup_transactions WHERE tenant_id=$1 AND idempotency_key=$2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?
    .as_ref()
    .map(setup_row)
    .transpose()
}

#[cfg(feature = "postgres")]
async fn setup_exact(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    r: &BeginGitHubSetupTransaction,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    setup_exact_complete(
        tx,
        &r.tenant_id,
        &r.principal_id,
        &r.transaction_id,
        &r.state_digest,
    )
    .await
}

#[cfg(feature = "postgres")]
async fn setup_exact_complete(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    principal_id: &str,
    id: &str,
    state: &ContentDigest,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM github_app_setup_transactions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND state_digest=$4 FOR UPDATE")
        .bind(tenant_id).bind(principal_id).bind(id).bind(state.as_str())
        .fetch_optional(&mut **tx).await?.as_ref().map(setup_row).transpose()
}

#[cfg(feature = "postgres")]
async fn advance_setup(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record: GitHubSetupTransactionRecord,
    now: u64,
) -> Result<Option<IdempotentResult<GitHubSetupTransactionRecord>>, ControlPlaneError> {
    if now < record.updated_unix_ms
        || !matches!(
            record.status,
            GitHubSetupStatus::Pending | GitHubSetupStatus::Exchanging
        )
    {
        return Ok(None);
    }
    if now >= record.expires_unix_ms {
        sqlx::query("UPDATE github_app_setup_transactions SET status='expired',updated_unix_ms=$3,last_error_code='expired' WHERE tenant_id=$1 AND id=$2 AND status IN ('pending','exchanging')")
            .bind(&record.tenant_id).bind(&record.id).bind(to_i64(now,"GitHub setup expiry")?).execute(&mut **tx).await?;
        return Ok(None);
    }
    if record.attempts >= 8 {
        sqlx::query("UPDATE github_app_setup_transactions SET status='rejected',updated_unix_ms=$3,last_error_code='attempt-limit' WHERE tenant_id=$1 AND id=$2 AND status IN ('pending','exchanging')")
            .bind(&record.tenant_id).bind(&record.id).bind(to_i64(now,"GitHub setup rejection")?).execute(&mut **tx).await?;
        return Ok(None);
    }
    let replayed = record.status == GitHubSetupStatus::Exchanging;
    sqlx::query("UPDATE github_app_setup_transactions SET status='exchanging',attempts=attempts+1,updated_unix_ms=$3 WHERE tenant_id=$1 AND id=$2 AND status IN ('pending','exchanging')")
        .bind(&record.tenant_id).bind(&record.id).bind(to_i64(now,"GitHub setup exchange")?).execute(&mut **tx).await?;
    let value = setup_by_id(tx, &record.tenant_id, &record.id)
        .await?
        .ok_or_else(|| {
            ControlPlaneError::CorruptState("advanced GitHub setup was not readable".to_owned())
        })?;
    Ok(Some(IdempotentResult { value, replayed }))
}

#[cfg(feature = "postgres")]
fn github_reconciliation_digest_pg(
    request: &ReconcileGitHubInstallation,
) -> Result<ContentDigest, ControlPlaneError> {
    #[derive(serde::Serialize)]
    struct Material<'a> {
        version: u32,
        installation: &'a GitHubInstallationRecord,
        selected_repositories: Vec<&'a crate::GitHubSelectedRepository>,
    }
    let mut selected_repositories = request.selected_repositories.iter().collect::<Vec<_>>();
    selected_repositories.sort_by(|a, b| a.external_repository_id.cmp(&b.external_repository_id));
    let mut bytes = b"runtrue.github-app.reconciliation.v2\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&Material {
        version: 2,
        installation: &request.installation,
        selected_repositories,
    })?);
    Ok(ContentDigest::sha256(bytes))
}

#[cfg(feature = "postgres")]
async fn reconcile_github_installation_pg_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ReconcileGitHubInstallation,
) -> Result<IdempotentResult<GitHubInstallationReconciliationResult>, ControlPlaneError> {
    validate_github_reconciliation_pg(request)?;
    let incoming = &request.installation;
    let installation = &incoming.installation;
    let current =
        github_installation_optional(tx, &installation.tenant_id, &installation.id).await?;
    let base = scm_installation_optional_tx(tx, &installation.tenant_id, &installation.id).await?;
    let installation_replayed = if let Some(current) = current {
        if current == *incoming {
            true
        } else {
            if request.expected_version != Some(current.version)
                || incoming.version
                    != current
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "GitHub installation version",
                        })?
                || incoming.lifecycle_generation
                    != current.lifecycle_generation.checked_add(1).ok_or(
                        ControlPlaneError::IntegerRange {
                            field: "GitHub installation lifecycle generation",
                        },
                    )?
                || installation.id != current.installation.id
                || installation.tenant_id != current.installation.tenant_id
                || installation.provider != current.installation.provider
                || installation.external_id != current.installation.external_id
                || installation.credential_reference != current.installation.credential_reference
                || installation.created_unix_ms != current.installation.created_unix_ms
                || incoming.web_origin != current.web_origin
                || incoming.api_origin != current.api_origin
                || incoming.account_external_id != current.account_external_id
                || incoming.account_kind != current.account_kind
                || !valid_status_transition(&current.installation.status, &installation.status)
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("UPDATE scm_installations SET permissions_json=$3,status=$4,updated_unix_ms=$5 WHERE tenant_id=$1 AND id=$2")
                .bind(&installation.tenant_id).bind(&installation.id)
                .bind(serde_json::to_vec(&canonicalize_json(installation.permissions.clone()))?)
                .bind(&installation.status).bind(to_i64(installation.updated_unix_ms,"GitHub installation update")?)
                .execute(&mut **tx).await?;
            let changed = sqlx::query("UPDATE github_installation_profiles SET account_login=$3,repository_selection=$4,lifecycle_generation=$5,synchronized_unix_ms=$6,suspended_unix_ms=$7,revoked_unix_ms=$8,version=$9 WHERE tenant_id=$1 AND installation_id=$2 AND version=$10")
                .bind(&installation.tenant_id).bind(&installation.id).bind(&incoming.account_login)
                .bind(selection_name(incoming.repository_selection)).bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?)
                .bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).bind(opt_i64_pg(incoming.suspended_unix_ms,"GitHub suspension")?)
                .bind(opt_i64_pg(incoming.revoked_unix_ms,"GitHub revocation")?).bind(to_i64(incoming.version,"GitHub version")?)
                .bind(to_i64(current.version,"GitHub version")?).execute(&mut **tx).await?.rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            false
        }
    } else if let Some(base) = base {
        if request.expected_version.is_some()
            || incoming.version != 1
            || incoming.lifecycle_generation != 1
            || installation.id != base.id
            || installation.tenant_id != base.tenant_id
            || installation.provider != base.provider
            || installation.external_id != base.external_id
            || installation.credential_reference != base.credential_reference
            || installation.created_unix_ms != base.created_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        sqlx::query("UPDATE scm_installations SET permissions_json=$3,status=$4,updated_unix_ms=$5 WHERE tenant_id=$1 AND id=$2")
            .bind(&installation.tenant_id).bind(&installation.id)
            .bind(serde_json::to_vec(&canonicalize_json(installation.permissions.clone()))?)
            .bind(&installation.status).bind(to_i64(installation.updated_unix_ms,"GitHub installation update")?)
            .execute(&mut **tx).await?;
        insert_github_profile(tx, incoming).await?;
        false
    } else {
        if request.expected_version.is_some()
            || incoming.version != 1
            || incoming.lifecycle_generation != 1
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let inserted=sqlx::query("INSERT INTO scm_installations(id,tenant_id,provider,external_id,credential_reference,permissions_json,status,created_unix_ms,updated_unix_ms) VALUES($1,$2,'github',$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
            .bind(&installation.id).bind(&installation.tenant_id).bind(&installation.external_id).bind(&installation.credential_reference)
            .bind(serde_json::to_vec(&canonicalize_json(installation.permissions.clone()))?).bind(&installation.status)
            .bind(to_i64(installation.created_unix_ms,"GitHub creation")?).bind(to_i64(installation.updated_unix_ms,"GitHub update")?)
            .execute(&mut **tx).await?.rows_affected();
        if inserted != 1 {
            return Err(not_found(
                "GitHub installation authorization",
                &installation.id,
            ));
        }
        insert_github_profile(tx, incoming).await?;
        false
    };

    let mut selected = request.selected_repositories.iter().collect::<Vec<_>>();
    selected.sort_by(|a, b| a.external_repository_id.cmp(&b.external_repository_id));
    let selected_ids = selected
        .iter()
        .map(|r| r.external_repository_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut summary = GitHubRepositoryReconciliationSummary {
        selected: u64::try_from(selected.len()).map_err(|_| ControlPlaneError::IntegerRange {
            field: "GitHub selected repository count",
        })?,
        ..Default::default()
    };
    for selected in selected {
        match github_catalog_optional(
            tx,
            &installation.tenant_id,
            &installation.id,
            &selected.external_repository_id,
        )
        .await?
        {
            None => {
                sqlx::query("INSERT INTO github_repository_catalog(installation_id,external_repository_id,tenant_id,web_origin,api_origin,owner,name,full_name,clone_url,visibility,default_branch,status,selection_generation,first_seen_unix_ms,last_seen_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'selected',$12,$13,$13,1)")
                    .bind(&installation.id).bind(&selected.external_repository_id).bind(&installation.tenant_id).bind(&incoming.web_origin).bind(&incoming.api_origin)
                    .bind(&selected.owner).bind(&selected.name).bind(&selected.full_name).bind(&selected.clone_url).bind(&selected.visibility).bind(&selected.default_branch)
                    .bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?).bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut **tx).await?;
                summary.inserted += 1;
            }
            Some(current) => {
                if current.web_origin != incoming.web_origin
                    || current.api_origin != incoming.api_origin
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let exact = current.owner == selected.owner
                    && current.name == selected.name
                    && current.full_name == selected.full_name
                    && current.clone_url == selected.clone_url
                    && current.visibility == selected.visibility
                    && current.default_branch == selected.default_branch
                    && current.status == "selected"
                    && current.selection_generation == incoming.lifecycle_generation
                    && current.last_seen_unix_ms == incoming.synchronized_unix_ms;
                if exact {
                    continue;
                }
                if current.selection_generation >= incoming.lifecycle_generation {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                sqlx::query("UPDATE github_repository_catalog SET owner=$4,name=$5,full_name=$6,clone_url=$7,visibility=$8,default_branch=$9,status='selected',selection_generation=$10,last_seen_unix_ms=$11,removed_unix_ms=NULL,version=version+1 WHERE tenant_id=$1 AND installation_id=$2 AND external_repository_id=$3")
                    .bind(&installation.tenant_id).bind(&installation.id).bind(&selected.external_repository_id).bind(&selected.owner).bind(&selected.name).bind(&selected.full_name)
                    .bind(&selected.clone_url).bind(&selected.visibility).bind(&selected.default_branch).bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?)
                    .bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut **tx).await?;
                summary.updated += 1;
            }
        }
    }
    let active:Vec<String>=sqlx::query_scalar("SELECT external_repository_id FROM github_repository_catalog WHERE tenant_id=$1 AND installation_id=$2 AND status='selected'")
        .bind(&installation.tenant_id).bind(&installation.id).fetch_all(&mut **tx).await?;
    for external_id in active {
        if selected_ids.contains(external_id.as_str()) {
            continue;
        }
        sqlx::query("UPDATE github_repository_catalog SET status='removed',selection_generation=$4,last_seen_unix_ms=$5,removed_unix_ms=$5,version=version+1 WHERE tenant_id=$1 AND installation_id=$2 AND external_repository_id=$3 AND status='selected'")
            .bind(&installation.tenant_id).bind(&installation.id).bind(external_id).bind(to_i64(incoming.lifecycle_generation,"GitHub generation")?)
            .bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut **tx).await?;
        summary.removed += 1;
    }
    sqlx::query("UPDATE scm_repository_links SET status=CASE WHEN $3='active' THEN status ELSE $3 END,updated_unix_ms=$4 WHERE tenant_id=$1 AND installation_id=$2")
        .bind(&installation.tenant_id).bind(&installation.id).bind(&installation.status).bind(to_i64(incoming.synchronized_unix_ms,"GitHub sync")?).execute(&mut **tx).await?;
    let durable =
        github_installation_required(tx, &installation.tenant_id, &installation.id).await?;
    Ok(IdempotentResult {
        value: GitHubInstallationReconciliationResult {
            installation: durable,
            repositories: summary,
        },
        replayed: installation_replayed
            && summary.inserted == 0
            && summary.updated == 0
            && summary.removed == 0,
    })
}

#[cfg(feature = "postgres")]
async fn scm_installation_optional_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    installation_id: &str,
) -> Result<Option<ScmInstallationRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM scm_installations WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(installation_id)
        .fetch_optional(&mut **tx)
        .await?
        .as_ref()
        .map(scm_installation_row)
        .transpose()
}

#[cfg(feature = "postgres")]
fn lifecycle_row(
    row: &sqlx::postgres::PgRow,
) -> Result<GitHubLifecycleDeliveryRecord, ControlPlaneError> {
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "pending" => GitHubLifecycleDeliveryState::Pending,
        "leased" => GitHubLifecycleDeliveryState::Leased,
        "completed" => GitHubLifecycleDeliveryState::Completed,
        "failed" => GitHubLifecycleDeliveryState::Failed,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown GitHub lifecycle state `{other}`"
            )))
        }
    };
    let digest = |name| -> Result<Option<ContentDigest>, ControlPlaneError> {
        row.try_get::<Option<String>, _>(name)?
            .map(ContentDigest::parse)
            .transpose()
            .map_err(Into::into)
    };
    let optional_u64 = |name, field| -> Result<Option<u64>, ControlPlaneError> {
        row.try_get::<Option<i64>, _>(name)?
            .map(|v| from_i64(v, field))
            .transpose()
    };
    let attempts: i32 = row.try_get("attempts")?;
    Ok(GitHubLifecycleDeliveryRecord {
        delivery_id: row.try_get("delivery_id")?,
        tenant_id: row.try_get("tenant_id")?,
        installation_id: row.try_get("installation_id")?,
        installation_external_id: row.try_get("installation_external_id")?,
        event_name: row.try_get("event_name")?,
        action: row.try_get("action")?,
        payload_digest: ContentDigest::parse(row.try_get::<String, _>("payload_digest")?)?,
        state,
        attempts: u32::try_from(attempts).map_err(|_| ControlPlaneError::IntegerRange {
            field: "GitHub lifecycle attempts",
        })?,
        available_unix_ms: from_i64(
            row.try_get("available_unix_ms")?,
            "GitHub lifecycle availability",
        )?,
        lease_owner: row.try_get("lease_owner")?,
        lease_generation: from_i64(
            row.try_get("lease_generation")?,
            "GitHub lifecycle generation",
        )?,
        lease_expires_unix_ms: optional_u64(
            "lease_expires_unix_ms",
            "GitHub lifecycle lease expiry",
        )?,
        completion_digest: digest("completion_digest")?,
        completed_lease_owner: row.try_get("completed_lease_owner")?,
        completed_lease_generation: optional_u64(
            "completed_lease_generation",
            "GitHub lifecycle completed generation",
        )?,
        last_failure_generation: optional_u64(
            "last_failure_generation",
            "GitHub lifecycle failure generation",
        )?,
        last_failure_lease_owner: row.try_get("last_failure_lease_owner")?,
        last_error_digest: digest("last_error_digest")?,
        last_retry_unix_ms: optional_u64("last_retry_unix_ms", "GitHub lifecycle retry")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "GitHub lifecycle creation")?,
        updated_unix_ms: from_i64(row.try_get("updated_unix_ms")?, "GitHub lifecycle update")?,
        completed_unix_ms: optional_u64("completed_unix_ms", "GitHub lifecycle completion")?,
    })
}

#[cfg(feature = "postgres")]
async fn lifecycle_by_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<GitHubLifecycleDeliveryRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM github_lifecycle_deliveries WHERE tenant_id=$1 AND delivery_id=$2")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .as_ref()
        .map(lifecycle_row)
        .transpose()
}
#[cfg(feature = "postgres")]
async fn lifecycle_by_id_locked(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<GitHubLifecycleDeliveryRecord>, ControlPlaneError> {
    sqlx::query("SELECT * FROM github_lifecycle_deliveries WHERE tenant_id=$1 AND delivery_id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_optional(&mut **tx).await?.as_ref().map(lifecycle_row).transpose()
}
#[cfg(feature = "postgres")]
async fn require_tenant_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
) -> Result<(), ControlPlaneError> {
    validate_text("tenant", tenant)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)")
        .bind(tenant)
        .fetch_one(&mut **tx)
        .await?;
    if exists {
        Ok(())
    } else {
        Err(not_found("tenant", tenant))
    }
}
#[cfg(feature = "postgres")]
fn validate_lifecycle_reservation(
    r: &ReserveGitHubLifecycleDelivery,
) -> Result<(), ControlPlaneError> {
    for v in [
        &r.delivery_id,
        &r.tenant_id,
        &r.installation_id,
        &r.installation_external_id,
        &r.event_name,
        &r.action,
    ] {
        validate_text("GitHub lifecycle identity", v)?;
    }
    if r.installation_external_id
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
        .is_none()
        || r.event_name.len() > 64
        || r.action.len() > 64
        || !r
            .event_name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || !r
            .action
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        Err(ControlPlaneError::InvalidInput(
            "invalid GitHub lifecycle delivery",
        ))
    } else {
        Ok(())
    }
}
#[cfg(feature = "postgres")]
fn validate_lifecycle_claim(
    worker: &str,
    now: u64,
    duration: u64,
) -> Result<(), ControlPlaneError> {
    validate_text("GitHub lifecycle worker", worker)?;
    if duration == 0 || duration > 5 * 60 * 1_000 {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub lifecycle lease duration",
        ));
    }
    now.checked_add(duration)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "GitHub lifecycle lease expiry",
        })?;
    Ok(())
}
#[cfg(feature = "postgres")]
fn validate_lifecycle_mutation(
    tenant: &str,
    id: &str,
    worker: &str,
    generation: u64,
) -> Result<(), ControlPlaneError> {
    for v in [tenant, id, worker] {
        validate_text("GitHub lifecycle binding", v)?;
    }
    if generation == 0 {
        Err(ControlPlaneError::InvalidInput(
            "invalid GitHub lifecycle lease generation",
        ))
    } else {
        Ok(())
    }
}
#[cfg(feature = "postgres")]
fn require_lifecycle_lease(
    record: &GitHubLifecycleDeliveryRecord,
    worker: &str,
    generation: u64,
    now: u64,
) -> Result<(), ControlPlaneError> {
    if record.state != GitHubLifecycleDeliveryState::Leased
        || record.lease_owner.as_deref() != Some(worker)
        || record.lease_generation != generation
        || record.lease_expires_unix_ms.is_none_or(|x| x <= now)
    {
        Err(ControlPlaneError::GitHubLifecycleLeaseLost)
    } else {
        Ok(())
    }
}
#[cfg(feature = "postgres")]
async fn claim_lifecycle_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record: GitHubLifecycleDeliveryRecord,
    worker: &str,
    now: u64,
    duration: u64,
) -> Result<Option<IdempotentResult<GitHubLifecycleDeliveryRecord>>, ControlPlaneError> {
    if record.state == GitHubLifecycleDeliveryState::Leased
        && record.lease_expires_unix_ms.is_some_and(|x| x > now)
    {
        return if record.lease_owner.as_deref() == Some(worker) {
            Ok(Some(IdempotentResult {
                value: record,
                replayed: true,
            }))
        } else {
            Ok(None)
        };
    }
    if matches!(
        record.state,
        GitHubLifecycleDeliveryState::Completed | GitHubLifecycleDeliveryState::Failed
    ) || (record.state == GitHubLifecycleDeliveryState::Pending
        && record.available_unix_ms > now)
    {
        return Ok(None);
    }
    if record.attempts >= 8 {
        fail_exhausted_one(tx, &record, now).await?;
        return Ok(None);
    }
    let generation =
        record
            .lease_generation
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "GitHub lifecycle lease generation",
            })?;
    let expiry = now
        .checked_add(duration)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "GitHub lifecycle lease expiry",
        })?;
    sqlx::query("UPDATE github_lifecycle_deliveries SET state='leased',attempts=attempts+1,lease_owner=$3,lease_generation=$4,lease_expires_unix_ms=$5,updated_unix_ms=$6 WHERE tenant_id=$1 AND delivery_id=$2")
        .bind(&record.tenant_id).bind(&record.delivery_id).bind(worker).bind(to_i64(generation,"GitHub lifecycle generation")?).bind(to_i64(expiry,"GitHub lifecycle expiry")?).bind(to_i64(now,"GitHub lifecycle claim")?).execute(&mut **tx).await?;
    let value = lifecycle_by_id(tx, &record.tenant_id, &record.delivery_id)
        .await?
        .ok_or_else(|| {
            ControlPlaneError::CorruptState(
                "claimed GitHub lifecycle delivery was not readable".to_owned(),
            )
        })?;
    Ok(Some(IdempotentResult {
        value,
        replayed: false,
    }))
}
#[cfg(feature = "postgres")]
async fn fail_exhausted_one(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record: &GitHubLifecycleDeliveryRecord,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let error = ContentDigest::sha256(b"github lifecycle delivery attempts exhausted");
    sqlx::query("UPDATE github_lifecycle_deliveries SET state='failed',lease_owner=NULL,lease_expires_unix_ms=NULL,last_failure_generation=lease_generation,last_failure_lease_owner=COALESCE(lease_owner,'github-lifecycle-exhaustion'),last_error_digest=$3,last_retry_unix_ms=NULL,updated_unix_ms=$4 WHERE tenant_id=$1 AND delivery_id=$2 AND state IN ('pending','leased')").bind(&record.tenant_id).bind(&record.delivery_id).bind(error.as_str()).bind(to_i64(now,"GitHub lifecycle exhaustion")?).execute(&mut **tx).await?;
    Ok(())
}
#[cfg(feature = "postgres")]
async fn fail_exhausted_lifecycle(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let error = ContentDigest::sha256(b"github lifecycle delivery attempts exhausted");
    sqlx::query("UPDATE github_lifecycle_deliveries SET state='failed',last_failure_generation=lease_generation,last_failure_lease_owner=COALESCE(lease_owner,'github-lifecycle-exhaustion'),last_error_digest=$1,last_retry_unix_ms=NULL,lease_owner=NULL,lease_expires_unix_ms=NULL,updated_unix_ms=$2 WHERE attempts>=8 AND (state='pending' OR (state='leased' AND lease_expires_unix_ms<=$2))").bind(error.as_str()).bind(to_i64(now,"GitHub lifecycle exhaustion")?).execute(&mut **tx).await?;
    Ok(())
}
#[cfg(feature = "postgres")]
fn event_binding_row(
    row: &sqlx::postgres::PgRow,
) -> Result<
    (
        RepositoryRecord,
        ScmInstallationRecord,
        ScmRepositoryLinkRecord,
    ),
    ControlPlaneError,
> {
    let repository = RepositoryRecord {
        id: row.try_get("r_id")?,
        tenant_id: row.try_get("r_tenant_id")?,
        owner: row.try_get("owner")?,
        name: row.try_get("name")?,
        default_branch: row.try_get("default_branch")?,
        visibility: row.try_get("visibility")?,
        created_unix_ms: from_i64(row.try_get("r_created_unix_ms")?, "repository creation")?,
    };
    let permissions = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("permissions_json")?)?;
    let installation = ScmInstallationRecord {
        id: row.try_get("i_id")?,
        tenant_id: row.try_get("i_tenant_id")?,
        provider: row.try_get("provider")?,
        external_id: row.try_get("external_id")?,
        credential_reference: row.try_get("credential_reference")?,
        permissions,
        status: row.try_get("i_status")?,
        created_unix_ms: from_i64(
            row.try_get("i_created_unix_ms")?,
            "SCM installation creation",
        )?,
        updated_unix_ms: from_i64(row.try_get("i_updated_unix_ms")?, "SCM installation update")?,
    };
    let link = ScmRepositoryLinkRecord {
        repository_id: row.try_get("repository_id")?,
        tenant_id: row.try_get("l_tenant_id")?,
        installation_id: row.try_get("installation_id")?,
        external_repository_id: row.try_get("external_repository_id")?,
        clone_url: row.try_get("clone_url")?,
        status: row.try_get("l_status")?,
        created_unix_ms: from_i64(row.try_get("l_created_unix_ms")?, "SCM link creation")?,
        updated_unix_ms: from_i64(row.try_get("l_updated_unix_ms")?, "SCM link update")?,
    };
    Ok((repository, installation, link))
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn append_github_audit_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    installation_id: &str,
    now: u64,
    tenant_id: &str,
    actor_id: &str,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    request_id: &str,
    metadata: BTreeMap<String, AuditValue>,
) -> Result<(), ControlPlaneError> {
    super::api_tokens::append(
        tx,
        installation_id,
        AuditEventData {
            observed_unix_ms: now,
            tenant_id: tenant_id.to_owned(),
            actor: AuditPrincipal {
                kind: "github".to_owned(),
                id: actor_id.to_owned(),
            },
            action: action.to_owned(),
            resource: AuditResource {
                kind: resource_kind.to_owned(),
                id: resource_id.to_owned(),
            },
            result: "success".to_owned(),
            request_id: request_id.to_owned(),
            decision_id: None,
            metadata,
        },
    )
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn scm_webhook_event_by_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery_id: &str,
) -> Result<ScmWebhookEventRecord, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT delivery_id, tenant_id, repository_id, installation_id,
                external_repository_id, provider_event_name, event_kind,
                actor_login, ref_name, normalized_digest, payload_digest,
                received_unix_ms
         FROM scm_webhook_events WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&mut **transaction)
    .await?;
    scm_webhook_event_row(&row)
}

#[cfg(feature = "postgres")]
fn scm_webhook_event_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ScmWebhookEventRecord, ControlPlaneError> {
    Ok(ScmWebhookEventRecord {
        delivery_id: row.try_get("delivery_id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        installation_id: row.try_get("installation_id")?,
        external_repository_id: row.try_get("external_repository_id")?,
        provider_event_name: row.try_get("provider_event_name")?,
        event_kind: row.try_get("event_kind")?,
        actor_login: row.try_get("actor_login")?,
        ref_name: row.try_get("ref_name")?,
        normalized_digest: ContentDigest::parse(row.try_get::<String, _>("normalized_digest")?)?,
        payload_digest: ContentDigest::parse(row.try_get::<String, _>("payload_digest")?)?,
        received_unix_ms: from_i64(row.try_get("received_unix_ms")?, "webhook event time")?,
    })
}

#[cfg(feature = "postgres")]
async fn scm_source_fetch_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    id: &str,
) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, repository_id, installation_id, origin_task_id,
                normalized_event_digest, source_commit, base_commit, origin_digest,
                token_scope_digest, mirror_identity_digest, tree_manifest_digest,
                source_snapshot_id, state, attempts, last_error_code,
                created_unix_ms, updated_unix_ms
         FROM scm_source_fetches WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| not_found("SCM source fetch", id))?;
    scm_source_fetch_row(&row)
}

#[cfg(feature = "postgres")]
async fn scm_source_fetch_by_id<'e, E>(
    executor: E,
    tenant_id: &str,
    id: &str,
) -> Result<ScmSourceFetchRecord, ControlPlaneError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query(
        "SELECT id, tenant_id, repository_id, installation_id, origin_task_id,
                normalized_event_digest, source_commit, base_commit, origin_digest,
                token_scope_digest, mirror_identity_digest, tree_manifest_digest,
                source_snapshot_id, state, attempts, last_error_code,
                created_unix_ms, updated_unix_ms
         FROM scm_source_fetches WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| not_found("SCM source fetch", id))?;
    scm_source_fetch_row(&row)
}

#[cfg(feature = "postgres")]
fn scm_source_fetch_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
    let state: String = row.try_get("state")?;
    let state = match state.as_str() {
        "reserved" => ScmSourceFetchState::Reserved,
        "fetched" => ScmSourceFetchState::Fetched,
        "snapshot-ready" => ScmSourceFetchState::SnapshotReady,
        "committed" => ScmSourceFetchState::Committed,
        "failed" => ScmSourceFetchState::Failed,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown PostgreSQL SCM fetch state `{other}`"
            )))
        }
    };
    let attempts: i32 = row.try_get("attempts")?;
    let attempts = u32::try_from(attempts).map_err(|_| {
        ControlPlaneError::CorruptState("PostgreSQL SCM fetch attempts are invalid".to_owned())
    })?;
    Ok(ScmSourceFetchRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        installation_id: row.try_get("installation_id")?,
        origin_task_id: row.try_get("origin_task_id")?,
        normalized_event_digest: ContentDigest::parse(
            row.try_get::<String, _>("normalized_event_digest")?,
        )?,
        source_commit: row.try_get("source_commit")?,
        base_commit: row.try_get("base_commit")?,
        origin_digest: ContentDigest::parse(row.try_get::<String, _>("origin_digest")?)?,
        token_scope_digest: optional_digest(row.try_get("token_scope_digest")?)?,
        mirror_identity_digest: optional_digest(row.try_get("mirror_identity_digest")?)?,
        tree_manifest_digest: optional_digest(row.try_get("tree_manifest_digest")?)?,
        source_snapshot_id: row.try_get("source_snapshot_id")?,
        state,
        attempts,
        last_error_code: row.try_get("last_error_code")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "SCM fetch creation")?,
        updated_unix_ms: from_i64(row.try_get("updated_unix_ms")?, "SCM fetch update")?,
    })
}

#[cfg(feature = "postgres")]
fn optional_digest(value: Option<String>) -> Result<Option<ContentDigest>, ControlPlaneError> {
    value
        .map(ContentDigest::parse)
        .transpose()
        .map_err(Into::into)
}

#[cfg(feature = "postgres")]
async fn require_postgres_task_owner(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    task_id: &str,
    worker: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let row = sqlx::query(
        "SELECT status, lease_owner, lease_expires_unix_ms FROM durable_tasks WHERE id = $1",
    )
    .bind(task_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| not_found("durable task", task_id))?;
    let status: String = row.try_get("status")?;
    let owner: Option<String> = row.try_get("lease_owner")?;
    if status != "claimed" || owner.as_deref() != Some(worker) {
        return Err(ControlPlaneError::TaskNotOwned);
    }
    let expires: Option<i64> = row.try_get("lease_expires_unix_ms")?;
    if expires
        .is_none_or(|expires| u64::try_from(expires).map_or(true, |expires| now_unix_ms >= expires))
    {
        return Err(ControlPlaneError::TaskLeaseExpired);
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn scm_check_publication_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    id: &str,
) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
    let row = sqlx::query("SELECT * FROM scm_check_publications WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| not_found("SCM check publication", id))?;
    scm_check_publication_row(&row)
}

#[cfg(feature = "postgres")]
async fn scm_check_publication_by_id<'e, E>(
    executor: E,
    tenant_id: &str,
    id: &str,
) -> Result<ScmCheckPublicationRecord, ControlPlaneError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query("SELECT * FROM scm_check_publications WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(executor)
        .await?
        .ok_or_else(|| not_found("SCM check publication", id))?;
    scm_check_publication_row(&row)
}

#[cfg(feature = "postgres")]
fn scm_check_publication_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
    let state: String = row.try_get("state")?;
    let state = match state.as_str() {
        "reserved" => ScmCheckPublicationState::Reserved,
        "reconciling" => ScmCheckPublicationState::Reconciling,
        "published" => ScmCheckPublicationState::Published,
        "failed" => ScmCheckPublicationState::Failed,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown PostgreSQL SCM check state `{other}`"
            )))
        }
    };
    let u32_column = |name: &'static str| -> Result<u32, ControlPlaneError> {
        let value: i32 = row.try_get(name)?;
        u32::try_from(value)
            .map_err(|_| ControlPlaneError::CorruptState(format!("PostgreSQL {name} is negative")))
    };
    Ok(ScmCheckPublicationRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        installation_id: row.try_get("installation_id")?,
        run_id: row.try_get("run_id")?,
        task_id: row.try_get("task_id")?,
        provider: row.try_get("provider")?,
        commit_sha: row.try_get("commit_sha")?,
        logical_name: row.try_get("logical_name")?,
        external_id: row.try_get("external_id")?,
        request_digest: ContentDigest::parse(row.try_get::<String, _>("request_digest")?)?,
        annotation_count: u32_column("annotation_count")?,
        provider_check_run_id: row
            .try_get::<Option<i64>, _>("provider_check_run_id")?
            .map(|v| from_i64(v, "provider check run id"))
            .transpose()?,
        confirmed_annotations: u32_column("confirmed_annotations")?,
        state,
        attempts: u32_column("attempts")?,
        last_error_code: row.try_get("last_error_code")?,
        created_unix_ms: from_i64(row.try_get("created_unix_ms")?, "SCM check creation")?,
        updated_unix_ms: from_i64(row.try_get("updated_unix_ms")?, "SCM check update")?,
    })
}

#[cfg(feature = "postgres")]
fn validate_repository(record: &RepositoryRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("repository.id", record.id.as_str()),
        ("repository.tenant_id", record.tenant_id.as_str()),
        ("repository.owner", record.owner.as_str()),
        ("repository.name", record.name.as_str()),
        ("repository.default_branch", record.default_branch.as_str()),
        ("repository.visibility", record.visibility.as_str()),
    ] {
        validate_text(field, value)?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_scm_installation(record: &ScmInstallationRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("SCM installation id", record.id.as_str()),
        ("SCM installation tenant", record.tenant_id.as_str()),
        ("SCM installation external id", record.external_id.as_str()),
        (
            "SCM credential reference",
            record.credential_reference.as_str(),
        ),
    ] {
        validate_text(field, value)?;
    }
    if record.provider != "github"
        || !matches!(record.status.as_str(), "active" | "suspended" | "revoked")
        || record.updated_unix_ms < record.created_unix_ms
        || record
            .external_id
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0)
            .is_none()
        || !valid_github_installation_permissions(&record.permissions)
        || (record.status == "active"
            && !github_installation_permissions_ready(&record.permissions))
    {
        return Err(ControlPlaneError::InvalidInput("invalid SCM installation"));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_scm_repository_link(record: &ScmRepositoryLinkRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("SCM repository id", record.repository_id.as_str()),
        ("SCM repository tenant", record.tenant_id.as_str()),
        ("SCM installation id", record.installation_id.as_str()),
        (
            "SCM external repository id",
            record.external_repository_id.as_str(),
        ),
        ("SCM clone URL", record.clone_url.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if !matches!(record.status.as_str(), "active" | "suspended" | "revoked")
        || record.updated_unix_ms < record.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid SCM repository link",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn valid_github_installation_permissions(value: &Value) -> bool {
    let Some(permissions) = value.as_object() else {
        return false;
    };
    if permissions.get("metadata").and_then(Value::as_str) != Some("read") {
        return false;
    }
    permissions.iter().all(|(name, level)| {
        let Some(level) = level.as_str() else {
            return false;
        };
        match name.as_str() {
            "metadata" => level == "read",
            "contents" | "pull_requests" | "actions" | "merge_queues" | "checks" | "statuses"
            | "issues" => matches!(level, "read" | "write"),
            _ => false,
        }
    })
}

#[cfg(feature = "postgres")]
fn github_installation_permissions_ready(value: &Value) -> bool {
    let Some(permissions) = value.as_object() else {
        return false;
    };
    permissions.get("metadata").and_then(Value::as_str) == Some("read")
        && matches!(
            permissions.get("contents").and_then(Value::as_str),
            Some("read" | "write")
        )
        && matches!(
            permissions.get("pull_requests").and_then(Value::as_str),
            Some("read" | "write")
        )
        && permissions.get("checks").and_then(Value::as_str) == Some("write")
}

#[cfg(feature = "postgres")]
fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        value => value,
    }
}

#[cfg(feature = "postgres")]
fn validate_text(field: &'static str, value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty()
        || value.len() > 8 * 1024
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ControlPlaneError::InvalidInput(field));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn to_i64(value: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(value).map_err(|_| ControlPlaneError::IntegerRange { field })
}

#[cfg(feature = "postgres")]
fn from_i64(value: i64, field: &'static str) -> Result<u64, ControlPlaneError> {
    u64::try_from(value)
        .map_err(|_| ControlPlaneError::CorruptState(format!("PostgreSQL {field} is negative")))
}

#[cfg(feature = "postgres")]
fn not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(test)]
pub(super) async fn contract<T>(store: &T)
where
    T: ScmRepositoryStore + super::TenantIdentityStore,
{
    let second_tenant = crate::TenantIdentityRecord {
        id: "tenant-scm-secondary".to_owned(),
        slug: "tenant-scm-secondary".to_owned(),
        name: "Secondary SCM tenant".to_owned(),
        status: "active".to_owned(),
        settings: serde_json::json!({}),
        created_unix_ms: 400,
        updated_unix_ms: 401,
        version: 1,
    };
    assert!(store
        .put_tenant_identity(&second_tenant, None)
        .await
        .expect("create secondary SCM tenant"));

    let repository = RepositoryRecord {
        id: "repository-contract".to_owned(),
        tenant_id: "tenant-contract".to_owned(),
        owner: "runtrue-contract".to_owned(),
        name: "runtime".to_owned(),
        default_branch: "main".to_owned(),
        visibility: "private".to_owned(),
        created_unix_ms: 410,
    };
    store
        .create_repository(&repository)
        .await
        .expect("create repository");
    assert_eq!(
        store
            .repository(&repository.id)
            .await
            .expect("load repository"),
        repository
    );
    assert_eq!(
        store
            .repositories_for_tenant(&repository.tenant_id)
            .await
            .expect("list tenant repositories"),
        vec![repository.clone()]
    );
    assert_eq!(
        store
            .repository_by_owner_name(&repository.owner, &repository.name)
            .await
            .expect("resolve unique repository"),
        repository
    );
    assert_eq!(
        store
            .repository_workflow_directory(&repository.tenant_id, &repository.id)
            .await
            .expect("read default workflow directory"),
        None
    );
    assert_eq!(
        store
            .set_repository_workflow_directory(
                &repository.tenant_id,
                &repository.id,
                ".github/workflows",
                420,
            )
            .await
            .expect("set workflow directory"),
        ".github/workflows"
    );
    assert_eq!(
        store
            .repository_workflow_directory(&repository.tenant_id, &repository.id)
            .await
            .expect("read workflow directory"),
        Some(".github/workflows".to_owned())
    );
    assert!(matches!(
        store
            .set_repository_workflow_directory(
                &repository.tenant_id,
                &repository.id,
                "./.github/workflows",
                421,
            )
            .await,
        Err(ControlPlaneError::InvalidInput(_))
    ));

    let ambiguous = RepositoryRecord {
        id: "repository-contract-secondary".to_owned(),
        tenant_id: second_tenant.id.clone(),
        ..repository.clone()
    };
    store
        .create_repository(&ambiguous)
        .await
        .expect("create same provider identity in a second tenant");
    assert!(matches!(
        store
            .repository_by_owner_name(&repository.owner, &repository.name)
            .await,
        Err(ControlPlaneError::AmbiguousRepositoryIdentity { .. })
    ));

    let installation = ScmInstallationRecord {
        id: "scm-installation-contract".to_owned(),
        tenant_id: repository.tenant_id.clone(),
        provider: "github".to_owned(),
        external_id: "900001".to_owned(),
        credential_reference: "github-app:900001".to_owned(),
        permissions: serde_json::json!({
            "checks": "write",
            "contents": "write",
            "metadata": "read",
            "pull_requests": "write"
        }),
        status: "active".to_owned(),
        created_unix_ms: 430,
        updated_unix_ms: 431,
    };
    let created = store
        .create_scm_installation(&installation)
        .await
        .expect("create SCM installation");
    assert!(!created.replayed);
    assert_eq!(created.value, installation);
    let replay = store
        .create_scm_installation(&installation)
        .await
        .expect("replay SCM installation");
    assert!(replay.replayed);
    assert_eq!(
        store
            .scm_installation_for_tenant(&installation.tenant_id, &installation.id)
            .await
            .expect("load tenant SCM installation"),
        installation
    );
    let mut installation_conflict = installation.clone();
    installation_conflict.credential_reference = "github-app:changed".to_owned();
    assert!(matches!(
        store.create_scm_installation(&installation_conflict).await,
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(matches!(
        store
            .scm_installation_for_tenant(&second_tenant.id, &installation.id)
            .await,
        Err(ControlPlaneError::NotFound { .. })
    ));

    let link = ScmRepositoryLinkRecord {
        repository_id: repository.id.clone(),
        tenant_id: repository.tenant_id.clone(),
        installation_id: installation.id.clone(),
        external_repository_id: "910001".to_owned(),
        clone_url: "https://github.com/runtrue-contract/runtime.git".to_owned(),
        status: "active".to_owned(),
        created_unix_ms: 440,
        updated_unix_ms: 441,
    };
    let linked = store
        .link_scm_repository(&link)
        .await
        .expect("link SCM repository");
    assert!(!linked.replayed);
    assert_eq!(linked.value, link);
    let replay = store
        .link_scm_repository(&link)
        .await
        .expect("replay SCM repository link");
    assert!(replay.replayed);
    let mut link_conflict = link.clone();
    link_conflict.clone_url = "https://example.test/conflict.git".to_owned();
    assert!(matches!(
        store.link_scm_repository(&link_conflict).await,
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let webhook = NewScmWebhookEvent {
        delivery_id: "webhook-delivery-contract".to_owned(),
        installation_external_id: installation.external_id.clone(),
        external_repository_id: link.external_repository_id.clone(),
        provider_event_name: "pull_request".to_owned(),
        event_kind: "pull_request.opened".to_owned(),
        actor_login: "octocat".to_owned(),
        ref_name: Some("refs/heads/feature".to_owned()),
        normalized_digest: runtrue_model::ContentDigest::sha256(b"normalized webhook"),
        payload_digest: runtrue_model::ContentDigest::sha256(b"redacted webhook payload"),
        received_unix_ms: 445,
    };
    let recorded = store
        .record_scm_webhook_event(&webhook)
        .await
        .expect("record SCM webhook event");
    assert!(!recorded.replayed);
    assert_eq!(recorded.value.repository_id, repository.id);
    let replay = store
        .record_scm_webhook_event(&webhook)
        .await
        .expect("replay SCM webhook event");
    assert!(replay.replayed);
    assert_eq!(
        store
            .scm_webhook_events_for_repository(&repository.tenant_id, &repository.id, None, 10,)
            .await
            .expect("list repository webhook events"),
        vec![recorded.value]
    );
    let mut webhook_conflict = webhook.clone();
    webhook_conflict.payload_digest =
        runtrue_model::ContentDigest::sha256(b"different redacted payload");
    assert!(matches!(
        store.record_scm_webhook_event(&webhook_conflict).await,
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let suspended = ScmInstallationRecord {
        id: "scm-installation-suspended-contract".to_owned(),
        tenant_id: ambiguous.tenant_id.clone(),
        external_id: "900002".to_owned(),
        credential_reference: "github-app:900002".to_owned(),
        status: "suspended".to_owned(),
        ..installation.clone()
    };
    store
        .create_scm_installation(&suspended)
        .await
        .expect("create suspended SCM installation");
    let unauthorized = ScmRepositoryLinkRecord {
        repository_id: ambiguous.id.clone(),
        tenant_id: ambiguous.tenant_id.clone(),
        installation_id: suspended.id,
        external_repository_id: "910002".to_owned(),
        clone_url: "https://github.com/runtrue-contract/runtime.git".to_owned(),
        status: "active".to_owned(),
        created_unix_ms: 450,
        updated_unix_ms: 451,
    };
    assert!(matches!(
        store.link_scm_repository(&unauthorized).await,
        Err(ControlPlaneError::NotFound {
            kind: "SCM repository authorization",
            ..
        })
    ));
}

#[cfg(test)]
pub(super) async fn github_contract<T>(store: &T)
where
    T: ScmRepositoryStore + super::TenantIdentityStore,
{
    let mut setup = CreateGitHubSetupTransaction {
        id: "github-setup-contract".to_owned(),
        tenant_id: "tenant-contract".to_owned(),
        principal_id: "bootstrap".to_owned(),
        idempotency_key: "github-setup-contract-key".to_owned(),
        request_digest: ContentDigest::sha256(b"placeholder"),
        state_digest: ContentDigest::sha256(b"github setup state"),
        github_web_origin: "https://github.com".to_owned(),
        github_api_origin: "https://api.github.com".to_owned(),
        return_path: "/settings/github".to_owned(),
        expires_unix_ms: 100_000,
        created_unix_ms: 1_000,
    };
    setup.request_digest = setup.expected_request_digest().expect("setup digest");
    let created = store
        .create_github_setup_transaction(&setup)
        .await
        .expect("create GitHub setup");
    assert!(!created.replayed);
    assert!(
        store
            .create_github_setup_transaction(&setup)
            .await
            .expect("replay GitHub setup")
            .replayed
    );
    let begin = BeginGitHubSetupTransaction {
        tenant_id: setup.tenant_id.clone(),
        principal_id: setup.principal_id.clone(),
        transaction_id: setup.id.clone(),
        state_digest: setup.state_digest.clone(),
        now_unix_ms: 1_001,
    };
    let begun = store
        .begin_github_setup_by_state(&setup.state_digest, 1_001)
        .await
        .expect("begin GitHub setup");
    assert_eq!(begun.value.status, GitHubSetupStatus::Exchanging);
    assert!(
        store
            .begin_github_setup_transaction(&begin)
            .await
            .expect("replay bound GitHub setup begin")
            .replayed
    );

    let repository = crate::GitHubSelectedRepository {
        external_repository_id: "920001".to_owned(),
        owner: "runtrue-contract".to_owned(),
        name: "github-runtime".to_owned(),
        full_name: "runtrue-contract/github-runtime".to_owned(),
        clone_url: "https://github.com/runtrue-contract/github-runtime.git".to_owned(),
        visibility: "private".to_owned(),
        default_branch: "main".to_owned(),
    };
    let reconciliation = ReconcileGitHubInstallation {
        installation: GitHubInstallationRecord {
            installation: ScmInstallationRecord {
                id: "github-installation-contract".to_owned(),
                tenant_id: setup.tenant_id.clone(),
                provider: "github".to_owned(),
                external_id: "990001".to_owned(),
                credential_reference: "github-app:990001".to_owned(),
                permissions: serde_json::json!({"metadata":"read","contents":"write","issues":"write"}),
                status: "active".to_owned(),
                created_unix_ms: 1_002,
                updated_unix_ms: 1_002,
            },
            web_origin: setup.github_web_origin.clone(),
            api_origin: setup.github_api_origin.clone(),
            account_external_id: "880001".to_owned(),
            account_login: "runtrue-contract".to_owned(),
            account_kind: GitHubAccountKind::Organization,
            repository_selection: GitHubRepositorySelection::Selected,
            lifecycle_generation: 1,
            synchronized_unix_ms: 1_002,
            suspended_unix_ms: None,
            revoked_unix_ms: None,
            version: 1,
        },
        selected_repositories: vec![repository.clone()],
        expected_version: None,
        now_unix_ms: 1_002,
    };
    let completion = CompleteGitHubSetupTransaction {
        tenant_id: setup.tenant_id.clone(),
        principal_id: setup.principal_id.clone(),
        transaction_id: setup.id.clone(),
        state_digest: setup.state_digest.clone(),
        reconciliation: reconciliation.clone(),
        now_unix_ms: 1_002,
    };
    let completed = store
        .complete_github_setup_transaction(&completion)
        .await
        .expect("complete GitHub setup");
    assert_eq!(completed.value.status, GitHubSetupStatus::Completed);
    assert!(
        store
            .complete_github_setup_transaction(&completion)
            .await
            .expect("replay GitHub setup completion")
            .replayed
    );
    assert_eq!(
        store
            .github_installation_for_tenant(&setup.tenant_id, "github-installation-contract")
            .await
            .expect("load tenant GitHub installation"),
        reconciliation.installation
    );
    assert_eq!(
        store
            .github_installation_by_external_id(
                &setup.github_web_origin,
                &setup.github_api_origin,
                "990001",
            )
            .await
            .expect("load external GitHub installation"),
        reconciliation.installation
    );
    assert_eq!(
        store
            .github_installations_for_tenant(&setup.tenant_id, None, 10)
            .await
            .expect("list GitHub installations")
            .iter()
            .filter(|x| x.installation.id == "github-installation-contract")
            .count(),
        1
    );
    assert_eq!(
        store
            .github_repository_catalog_for_tenant(
                &setup.tenant_id,
                "github-installation-contract",
                false,
                None,
                10,
            )
            .await
            .expect("list GitHub catalog")[0]
            .external_repository_id,
        repository.external_repository_id
    );

    let linked_repository = RepositoryRecord {
        id: "github-repository-contract".to_owned(),
        tenant_id: setup.tenant_id.clone(),
        owner: repository.owner.clone(),
        name: repository.name.clone(),
        default_branch: repository.default_branch.clone(),
        visibility: repository.visibility.clone(),
        created_unix_ms: 1_003,
    };
    let link = LinkSelectedGitHubRepository {
        tenant_id: setup.tenant_id.clone(),
        installation_id: "github-installation-contract".to_owned(),
        external_repository_id: repository.external_repository_id.clone(),
        repository: linked_repository.clone(),
        now_unix_ms: 1_003,
    };
    assert!(
        !store
            .link_selected_github_repository(&link)
            .await
            .expect("link selected GitHub repository")
            .replayed
    );
    assert!(
        store
            .link_selected_github_repository(&link)
            .await
            .expect("replay selected GitHub repository link")
            .replayed
    );
    assert_eq!(
        store
            .github_repository_links_for_tenant(
                &setup.tenant_id,
                "github-installation-contract",
                None,
                10,
            )
            .await
            .expect("list GitHub repository links")
            .len(),
        1
    );
    assert_eq!(
        store
            .github_account_id_for_repository(&setup.tenant_id, &linked_repository.id)
            .await
            .expect("resolve GitHub account"),
        "880001"
    );
    let event = store
        .github_repository_for_event(
            "990001",
            &repository.external_repository_id,
            &repository.owner,
            &repository.name,
        )
        .await
        .expect("resolve GitHub event repository");
    assert_eq!(event.0, linked_repository);

    let reservation = ReserveGitHubLifecycleDelivery {
        delivery_id: "github-lifecycle-contract".to_owned(),
        tenant_id: setup.tenant_id.clone(),
        installation_id: "github-installation-contract".to_owned(),
        installation_external_id: "990001".to_owned(),
        event_name: "installation".to_owned(),
        action: "suspend".to_owned(),
        payload_digest: ContentDigest::sha256(b"lifecycle payload"),
        now_unix_ms: 1_010,
    };
    assert!(
        !store
            .reserve_github_lifecycle_delivery(&reservation)
            .await
            .expect("reserve lifecycle")
            .replayed
    );
    assert!(
        store
            .reserve_github_lifecycle_delivery(&reservation)
            .await
            .expect("replay lifecycle reservation")
            .replayed
    );
    let claim = ClaimGitHubLifecycleDelivery {
        tenant_id: setup.tenant_id.clone(),
        delivery_id: reservation.delivery_id.clone(),
        worker_id: "github-worker-contract".to_owned(),
        now_unix_ms: 1_011,
        lease_duration_ms: 100,
    };
    let claimed = store
        .claim_github_lifecycle_delivery(&claim)
        .await
        .expect("claim lifecycle")
        .expect("available lifecycle");
    assert!(!claimed.replayed);
    let failure = FailGitHubLifecycleDelivery {
        tenant_id: setup.tenant_id.clone(),
        delivery_id: reservation.delivery_id.clone(),
        worker_id: claim.worker_id.clone(),
        lease_generation: claimed.value.lease_generation,
        error_digest: ContentDigest::sha256(b"retryable lifecycle failure"),
        retry_unix_ms: Some(1_020),
        now_unix_ms: 1_012,
    };
    assert!(
        !store
            .fail_github_lifecycle_delivery(&failure)
            .await
            .expect("fail lifecycle")
            .replayed
    );
    assert!(
        store
            .fail_github_lifecycle_delivery(&failure)
            .await
            .expect("replay lifecycle failure")
            .replayed
    );
    assert!(store
        .claim_github_lifecycle_delivery(&ClaimGitHubLifecycleDelivery {
            now_unix_ms: 1_019,
            ..claim.clone()
        })
        .await
        .expect("early lifecycle claim")
        .is_none());
    let reclaimed = store
        .claim_next_github_lifecycle_delivery("github-worker-contract", 1_020, 100)
        .await
        .expect("claim next lifecycle")
        .expect("retry lifecycle available");
    let completion_digest = ContentDigest::sha256(b"lifecycle complete");
    let lifecycle_completion = CompleteGitHubLifecycleDelivery {
        tenant_id: setup.tenant_id.clone(),
        delivery_id: reservation.delivery_id,
        worker_id: "github-worker-contract".to_owned(),
        lease_generation: reclaimed.lease_generation,
        completion_digest,
        now_unix_ms: 1_021,
    };
    assert!(
        !store
            .complete_github_lifecycle_delivery(&lifecycle_completion)
            .await
            .expect("complete lifecycle")
            .replayed
    );
    assert!(
        store
            .complete_github_lifecycle_delivery(&lifecycle_completion)
            .await
            .expect("replay lifecycle completion")
            .replayed
    );

    let suspended = store
        .suspend_github_repository_link(
            &setup.tenant_id,
            &linked_repository.id,
            "bootstrap",
            "github-link-suspend-contract",
            1_030,
        )
        .await
        .expect("suspend GitHub repository link");
    assert!(!suspended.replayed);
    assert!(
        store
            .suspend_github_repository_link(
                &setup.tenant_id,
                &linked_repository.id,
                "bootstrap",
                "github-link-suspend-contract",
                1_030,
            )
            .await
            .expect("replay GitHub repository suspension")
            .replayed
    );

    let mut reconciled = reconciliation.clone();
    reconciled.installation.installation.updated_unix_ms = 1_040;
    reconciled.installation.synchronized_unix_ms = 1_040;
    reconciled.installation.lifecycle_generation = 2;
    reconciled.installation.version = 2;
    reconciled.installation.account_login = "runtrue-contract-renamed".to_owned();
    reconciled.expected_version = Some(1);
    reconciled.now_unix_ms = 1_040;
    let updated = store
        .reconcile_github_installation(&reconciled)
        .await
        .expect("update GitHub installation");
    assert!(!updated.replayed);
    assert_eq!(updated.value.installation.version, 2);
    assert!(
        store
            .reconcile_github_installation(&reconciled)
            .await
            .expect("replay GitHub reconciliation")
            .replayed
    );
    let status = SetGitHubInstallationStatus {
        tenant_id: setup.tenant_id.clone(),
        installation_id: "github-installation-contract".to_owned(),
        expected_version: 2,
        status: "suspended".to_owned(),
        lifecycle_generation: 3,
        now_unix_ms: 1_050,
    };
    let status_changed = store
        .set_github_installation_status(&status)
        .await
        .expect("suspend GitHub installation");
    assert!(!status_changed.replayed);
    assert_eq!(status_changed.value.version, 3);
    assert!(
        store
            .set_github_installation_status(&status)
            .await
            .expect("replay GitHub installation status")
            .replayed
    );

    let mut rejected_setup = setup.clone();
    rejected_setup.id = "github-setup-rejected-contract".to_owned();
    rejected_setup.idempotency_key = "github-setup-rejected-contract-key".to_owned();
    rejected_setup.state_digest = ContentDigest::sha256(b"github rejected setup state");
    rejected_setup.created_unix_ms = 2_000;
    rejected_setup.expires_unix_ms = 100_000;
    rejected_setup.request_digest = rejected_setup
        .expected_request_digest()
        .expect("rejected setup digest");
    store
        .create_github_setup_transaction(&rejected_setup)
        .await
        .expect("create rejected GitHub setup");
    let reject_begin = BeginGitHubSetupTransaction {
        tenant_id: rejected_setup.tenant_id.clone(),
        principal_id: rejected_setup.principal_id.clone(),
        transaction_id: rejected_setup.id.clone(),
        state_digest: rejected_setup.state_digest.clone(),
        now_unix_ms: 2_001,
    };
    store
        .begin_github_setup_transaction(&reject_begin)
        .await
        .expect("begin rejected GitHub setup");
    assert!(
        !store
            .reject_github_setup_transaction(&reject_begin, "github-denied")
            .await
            .expect("reject GitHub setup")
            .replayed
    );
    assert!(
        store
            .reject_github_setup_transaction(&reject_begin, "github-denied")
            .await
            .expect("replay GitHub setup rejection")
            .replayed
    );
}

#[cfg(test)]
pub(super) async fn completion_report_contract<T: ScmRepositoryStore>(store: &T) {
    use runtrue_attest::CapsuleSigningKey;
    use runtrue_workflow_ir::{
        ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
        OperatingSystem, ParityGrade, PermissionSet, PlannedJob, RunnerRequirements, Trust,
        WorkflowFrontendProvenance, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
        ENGINE_COMPATIBILITY_VERSION,
    };
    use std::collections::{BTreeMap, BTreeSet};
    let report = br#"{"frontend":"contract"}"#.to_vec();
    let decoded = ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "persistence-contract".to_owned(),
        workflow: WorkflowIdentity {
            name: "ci".to_owned(),
            digest: ContentDigest::sha256(b"workflow contract"),
            source_path: ".runtrue/workflows/ci.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "0123456789abcdef".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: Default::default(),
            normalized_event_digest: ContentDigest::sha256(b"event contract"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: Some(WorkflowFrontendProvenance {
                frontend_id: "github-actions".to_owned(),
                contract_generation: 1,
                frontend_generation: 1,
                configuration_digest: ContentDigest::sha256(b"configuration"),
                input_digest: ContentDigest::sha256(b"input"),
                native_digest: ContentDigest::sha256(b"native"),
                report_digest: Some(ContentDigest::sha256(&report)),
            }),
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: vec![PlannedJob {
            id: "build".to_owned(),
            base_id: "build".to_owned(),
            name: "build".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::UntrustedOk,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Microvm,
                image: None,
                cpu: 1,
                memory_bytes: 1024,
                storage_bytes: Some(1024),
                region: Some("test".to_owned()),
                capabilities: vec!["kvm".to_owned()],
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: Vec::new(),
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::AExact,
    };
    let signer = CapsuleSigningKey::from_seed([71; 32]);
    let signature = signer
        .sign_capsule(&decoded)
        .expect("sign contract capsule");
    let capsule = SignedCapsuleRecord {
        id: "scm-completion-capsule-contract".to_owned(),
        repository_id: "repository-contract".to_owned(),
        digest: signature.capsule_digest.clone(),
        canonical_capsule: decoded
            .canonical_bytes()
            .expect("canonical contract capsule"),
        signature,
        created_unix_ms: 600,
    };
    let metadata = CapsuleApiMetadata {
        capsule_id: capsule.id.clone(),
        approval_subject_digest: ContentDigest::sha256(b"approval subject contract"),
        risk_score: 10,
    };
    let run = CreateRunRequest {
        id: "scm-completion-run-contract".to_owned(),
        repository_id: capsule.repository_id.clone(),
        capsule_id: capsule.id.clone(),
        priority: 0,
        remote: true,
        created_unix_ms: 600,
        jobs: vec![crate::NewJob {
            id: "scm-completion-job-contract".to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements: runtrue_scheduler::SchedulingRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Microvm,
                cpu: 1,
                memory_bytes: 1024,
                storage_bytes: 1024,
                region: Some("test".to_owned()),
                required_capabilities: ["kvm".to_owned()].into_iter().collect::<BTreeSet<_>>(),
                allowed_pools: BTreeSet::new(),
            },
        }],
    };
    let completed = store
        .complete_scm_task_with_run_idempotent(
            "scm-completion-task-contract",
            "scm-completion-worker",
            601,
            "scm-completion-key-contract",
            &capsule,
            &signer.verifying_key(),
            &metadata,
            &run,
        )
        .await
        .expect("complete SCM task");
    assert!(!completed.replayed);
    assert_eq!(completed.value.id, run.id);
    let attachment = WorkflowFrontendReportRecord {
        capsule_id: capsule.id,
        media_type: "application/json".to_owned(),
        bytes: report,
    };
    store
        .store_workflow_frontend_report(&attachment)
        .await
        .expect("store frontend report");
    assert_eq!(
        store
            .workflow_frontend_report(&attachment.capsule_id)
            .await
            .expect("load frontend report"),
        attachment
    );
}

#[cfg(test)]
pub(super) async fn continuation_state_contract<T: ScmRepositoryStore>(store: &T) {
    let pending = store
        .scm_pending_execution("scm-pending-contract")
        .await
        .expect("load SCM pending execution");
    assert_eq!(
        pending.state,
        crate::ScmPendingExecutionState::AwaitingApproval
    );
    assert_eq!(
        store
            .scm_pending_execution_approvals(&pending.id)
            .await
            .expect("load SCM pending approvals")
            .len(),
        1
    );
    assert_eq!(
        store
            .scm_proposed_analysis_for_task("scm-analysis-origin-contract")
            .await
            .expect("load SCM proposed analysis")
            .id,
        "scm-analysis-contract"
    );
    assert!(matches!(
        store
            .begin_scm_continuation(
                "scm-continuation-task-contract",
                "scm-continuation-worker",
                &pending.id,
                701,
            )
            .await
            .expect("begin SCM continuation"),
        ScmContinuationResolution::Ready(_)
    ));
    let stale = store
        .close_scm_continuation_as_stale(
            "scm-continuation-task-contract",
            "scm-continuation-worker",
            &pending.id,
            "contract source changed",
            702,
        )
        .await
        .expect("close stale SCM continuation");
    assert_eq!(stale.state, crate::ScmPendingExecutionState::Stale);
}

#[cfg(test)]
pub(super) async fn dependent_contract<T: ScmRepositoryStore>(store: &T) {
    let fetch = ReserveScmSourceFetch {
        id: "scm-fetch-contract".to_owned(),
        tenant_id: "tenant-contract".to_owned(),
        repository_id: "repository-contract".to_owned(),
        installation_id: "scm-installation-contract".to_owned(),
        origin_task_id: "scm-event-task-contract".to_owned(),
        normalized_event_digest: runtrue_model::ContentDigest::sha256(b"event"),
        source_commit: "a".repeat(40),
        base_commit: None,
        origin_digest: runtrue_model::ContentDigest::sha256(b"origin"),
        now_unix_ms: 500,
    };
    let first = store
        .reserve_scm_source_fetch(&fetch)
        .await
        .expect("reserve source fetch");
    assert!(!first.replayed);
    let replay = store
        .reserve_scm_source_fetch(&fetch)
        .await
        .expect("replay source fetch");
    assert!(replay.replayed);
    assert_eq!(replay.value.attempts, 2);
    let ready = RecordScmFetchSnapshotReady {
        tenant_id: fetch.tenant_id.clone(),
        fetch_id: fetch.id.clone(),
        token_scope_digest: runtrue_model::ContentDigest::sha256(b"scope"),
        mirror_identity_digest: runtrue_model::ContentDigest::sha256(b"mirror"),
        tree_manifest_digest: runtrue_model::ContentDigest::sha256(b"tree"),
        source_snapshot_id: "source-snapshot-contract".to_owned(),
        now_unix_ms: 501,
    };
    assert_eq!(
        store
            .record_scm_fetch_snapshot_ready(&ready)
            .await
            .expect("snapshot ready")
            .state,
        ScmSourceFetchState::SnapshotReady
    );
    assert_eq!(
        store
            .mark_scm_fetch_committed(&fetch.tenant_id, &fetch.id, 502)
            .await
            .expect("commit fetch")
            .state,
        ScmSourceFetchState::Committed
    );
    assert_eq!(
        store
            .scm_source_fetch_for_task(&fetch.tenant_id, &fetch.origin_task_id)
            .await
            .expect("fetch by task")
            .id,
        fetch.id
    );

    let reserve = ReserveScmCheckPublication {
        id: "scm-check-contract".to_owned(),
        tenant_id: fetch.tenant_id.clone(),
        repository_id: fetch.repository_id.clone(),
        installation_id: fetch.installation_id.clone(),
        run_id: "run-contract".to_owned(),
        task_id: "scm-check-task-contract".to_owned(),
        worker_id: "check-worker".to_owned(),
        commit_sha: "b".repeat(40),
        logical_name: "test".to_owned(),
        external_id: "check:test".to_owned(),
        request_digest: runtrue_model::ContentDigest::sha256(b"check"),
        annotation_count: 1,
        now_unix_ms: 510,
    };
    assert!(
        !store
            .reserve_scm_check_publication(&reserve)
            .await
            .expect("reserve check")
            .replayed
    );
    assert!(
        store
            .reserve_scm_check_publication(&reserve)
            .await
            .expect("replay check")
            .replayed
    );
    let progress = RecordScmCheckProgress {
        tenant_id: reserve.tenant_id.clone(),
        publication_id: reserve.id.clone(),
        task_id: reserve.task_id.clone(),
        worker_id: reserve.worker_id.clone(),
        provider_check_run_id: 7001,
        confirmed_annotations: 1,
        now_unix_ms: 511,
    };
    assert_eq!(
        store
            .record_scm_check_progress(&progress)
            .await
            .expect("check progress")
            .state,
        ScmCheckPublicationState::Reconciling
    );
    assert_eq!(
        store
            .mark_scm_check_published(
                &reserve.tenant_id,
                &reserve.id,
                &reserve.task_id,
                &reserve.worker_id,
                512
            )
            .await
            .expect("publish check")
            .state,
        ScmCheckPublicationState::Published
    );
    assert_eq!(
        store
            .scm_check_publication_by_provider_run(
                &reserve.tenant_id,
                &reserve.repository_id,
                &reserve.installation_id,
                7001
            )
            .await
            .expect("provider check")
            .id,
        reserve.id
    );

    let failed = ReserveScmCheckPublication {
        id: "scm-check-failure-contract".to_owned(),
        task_id: "scm-check-failure-task-contract".to_owned(),
        external_id: "check:failure".to_owned(),
        request_digest: runtrue_model::ContentDigest::sha256(b"failure"),
        annotation_count: 0,
        now_unix_ms: 520,
        ..reserve
    };
    store
        .reserve_scm_check_publication(&failed)
        .await
        .expect("reserve failing check");
    let failure = RecordScmCheckFailure {
        tenant_id: failed.tenant_id.clone(),
        publication_id: failed.id.clone(),
        task_id: failed.task_id.clone(),
        worker_id: failed.worker_id.clone(),
        error_code: "provider-error".to_owned(),
        terminal: true,
        now_unix_ms: 521,
    };
    assert_eq!(
        store
            .record_scm_check_failure(&failure)
            .await
            .expect("fail check")
            .state,
        ScmCheckPublicationState::Failed
    );
}
