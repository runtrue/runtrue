//! PostgreSQL run-core boundary. Approval and source-snapshot operations remain
//! outside this module's currently ported contract.

use super::StoreFuture;
#[cfg(feature = "postgres")]
use super::{postgres_i64, postgres_u64, PostgresInstallationStore};
use crate::{
    CapsuleApiMetadata, ControlPlane, CreateRunRequest, ExpandedJobMaterialization,
    ExpandedJobSetRecord, IdempotentResult, IssueRunnerSourceTicket, JobRecord,
    MaterializeExpandedJobSet, NormalizedTriggerEventRecord, ReplayBundleRecord, RunRecord,
    RunSourceSnapshotRecord, RunnerSourceDownload, RunnerSourceTicketRecord,
    ScheduleReconciliationSummary, ScheduleTriggerCursor, SignedCapsuleRecord,
    SourceSnapshotRecord, WorkflowSemanticsMetrics,
};
use runtrue_attest::CapsuleVerifyingKey;
use runtrue_lifecycle::{JobState, RunState};
use runtrue_model::ContentDigest;
use runtrue_policy::{ApprovalDecision, ApprovalRequest};

#[cfg(feature = "postgres")]
use crate::ControlPlaneError;
#[cfg(any(feature = "postgres", test))]
use crate::SourceSnapshotState;
#[cfg(feature = "postgres")]
use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource, AuditValue};
#[cfg(feature = "postgres")]
use serde::Serialize;
#[cfg(feature = "postgres")]
use sha2::{Digest as _, Sha256};
#[cfg(feature = "postgres")]
use sqlx::{Postgres, Row as _, Transaction};
#[cfg(feature = "postgres")]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0009_runs_approvals.sql");

pub trait RunCoreStore: Send + Sync {
    fn store_signed_capsule<'a>(
        &'a self,
        capsule: &'a SignedCapsuleRecord,
        verifying_key: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, ()>;
    fn signed_capsule<'a>(&'a self, id: &'a str) -> StoreFuture<'a, SignedCapsuleRecord>;
    fn signed_capsule_for_lease<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, (String, SignedCapsuleRecord)>;
    fn store_compiled_capsule_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        capsule: &'a SignedCapsuleRecord,
        verifying_key: &'a CapsuleVerifyingKey,
        metadata: &'a CapsuleApiMetadata,
        approvals: &'a [ApprovalRequest],
    ) -> StoreFuture<'a, IdempotentResult<SignedCapsuleRecord>>;
    fn capsule_api_metadata<'a>(
        &'a self,
        capsule_id: &'a str,
    ) -> StoreFuture<'a, CapsuleApiMetadata>;
    fn create_run_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        request: &'a CreateRunRequest,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>>;
    fn run<'a>(&'a self, id: &'a str) -> StoreFuture<'a, RunRecord>;
    fn list_runs_page<'a>(
        &'a self,
        repository_id: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<RunRecord>>;
    fn list_runs_page_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<RunRecord>>;
    fn jobs_for_run<'a>(&'a self, run_id: &'a str) -> StoreFuture<'a, Vec<JobRecord>>;
    fn job<'a>(&'a self, job_id: &'a str) -> StoreFuture<'a, JobRecord>;
    fn transition_run_state<'a>(
        &'a self,
        run_id: &'a str,
        next: RunState,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunRecord>;
    fn transition_job_state<'a>(
        &'a self,
        job_id: &'a str,
        next: JobState,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, JobRecord>;
    fn cancel_run_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        run_id: &'a str,
        reason: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>>;
    fn store_replay_bundle_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        record: &'a ReplayBundleRecord,
    ) -> StoreFuture<'a, IdempotentResult<ReplayBundleRecord>>;
    fn replay_bundle_for_run<'a>(&'a self, run_id: &'a str) -> StoreFuture<'a, ReplayBundleRecord>;
}

pub trait ApprovalStore: Send + Sync {
    fn create_approval_request<'a>(
        &'a self,
        repository_id: &'a str,
        capsule_id: &'a str,
        request: &'a ApprovalRequest,
    ) -> StoreFuture<'a, ()>;
    fn approval_request<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ApprovalRequest>;
    fn approval_requests_for_capsule<'a>(
        &'a self,
        capsule_id: &'a str,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>>;
    fn decide_approval<'a>(
        &'a self,
        approval_id: &'a str,
        decision: ApprovalDecision,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ApprovalRequest>;
    fn decide_approval_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        approval_id: &'a str,
        decision: ApprovalDecision,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<ApprovalRequest>>;
    fn authorize_approval<'a>(
        &'a self,
        approval_id: &'a str,
        subject_digest: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ApprovalRequest>;
    fn list_approval_requests_page<'a>(
        &'a self,
        status: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>>;
    fn list_approval_requests_page_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        status: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>>;
    fn approval_request_tenant<'a>(&'a self, id: &'a str) -> StoreFuture<'a, String>;
    fn approval_request_binding<'a>(&'a self, id: &'a str) -> StoreFuture<'a, (String, String)>;
    fn approval_pending_execution_count<'a>(&'a self, id: &'a str) -> StoreFuture<'a, u64>;
    fn approval_pending_execution_events<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<serde_json::Value>>;
}

pub trait SourceSnapshotStore: Send + Sync {
    fn create_source_snapshot<'a>(
        &'a self,
        snapshot: &'a SourceSnapshotRecord,
    ) -> StoreFuture<'a, IdempotentResult<SourceSnapshotRecord>>;
    fn source_snapshot<'a>(
        &'a self,
        tenant_id: &'a str,
        snapshot_id: &'a str,
    ) -> StoreFuture<'a, SourceSnapshotRecord>;
    fn mark_source_snapshot_ready<'a>(
        &'a self,
        tenant_id: &'a str,
        snapshot_id: &'a str,
        manifest_digest: &'a ContentDigest,
        verified_unix_ms: u64,
    ) -> StoreFuture<'a, SourceSnapshotRecord>;
    fn bind_run_source_snapshot<'a>(
        &'a self,
        tenant_id: &'a str,
        run_id: &'a str,
        snapshot_id: &'a str,
        capsule_digest: &'a ContentDigest,
        bound_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunSourceSnapshotRecord>>;
    fn run_source_snapshot<'a>(
        &'a self,
        tenant_id: &'a str,
        run_id: &'a str,
    ) -> StoreFuture<'a, RunSourceSnapshotRecord>;
    fn issue_runner_source_ticket<'a>(
        &'a self,
        request: &'a IssueRunnerSourceTicket,
    ) -> StoreFuture<'a, IdempotentResult<RunnerSourceTicketRecord>>;
    fn runner_source_ticket<'a>(
        &'a self,
        ticket_id: &'a str,
    ) -> StoreFuture<'a, RunnerSourceTicketRecord>;
    fn begin_runner_source_download<'a>(
        &'a self,
        request: &'a RunnerSourceDownload,
    ) -> StoreFuture<'a, bool>;
    fn finish_runner_source_download<'a>(
        &'a self,
        request: &'a RunnerSourceDownload,
    ) -> StoreFuture<'a, ()>;
}

impl SourceSnapshotStore for ControlPlane {
    fn create_source_snapshot<'a>(
        &'a self,
        s: &'a SourceSnapshotRecord,
    ) -> StoreFuture<'a, IdempotentResult<SourceSnapshotRecord>> {
        Box::pin(async move { ControlPlane::create_source_snapshot(self, s) })
    }
    fn source_snapshot<'a>(
        &'a self,
        t: &'a str,
        s: &'a str,
    ) -> StoreFuture<'a, SourceSnapshotRecord> {
        Box::pin(async move { ControlPlane::source_snapshot(self, t, s) })
    }
    fn mark_source_snapshot_ready<'a>(
        &'a self,
        t: &'a str,
        s: &'a str,
        d: &'a ContentDigest,
        n: u64,
    ) -> StoreFuture<'a, SourceSnapshotRecord> {
        Box::pin(async move { ControlPlane::mark_source_snapshot_ready(self, t, s, d, n) })
    }
    fn bind_run_source_snapshot<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
        s: &'a str,
        d: &'a ContentDigest,
        n: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunSourceSnapshotRecord>> {
        Box::pin(async move { ControlPlane::bind_run_source_snapshot(self, t, r, s, d, n) })
    }
    fn run_source_snapshot<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
    ) -> StoreFuture<'a, RunSourceSnapshotRecord> {
        Box::pin(async move { ControlPlane::run_source_snapshot(self, t, r) })
    }
    fn issue_runner_source_ticket<'a>(
        &'a self,
        r: &'a IssueRunnerSourceTicket,
    ) -> StoreFuture<'a, IdempotentResult<RunnerSourceTicketRecord>> {
        Box::pin(async move { ControlPlane::issue_runner_source_ticket(self, r) })
    }
    fn runner_source_ticket<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, RunnerSourceTicketRecord> {
        Box::pin(async move { ControlPlane::runner_source_ticket(self, id) })
    }
    fn begin_runner_source_download<'a>(
        &'a self,
        r: &'a RunnerSourceDownload,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move { ControlPlane::begin_runner_source_download(self, r) })
    }
    fn finish_runner_source_download<'a>(
        &'a self,
        r: &'a RunnerSourceDownload,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move { ControlPlane::finish_runner_source_download(self, r) })
    }
}

pub trait WorkflowSemanticsStore: Send + Sync {
    fn record_normalized_trigger<'a>(
        &'a self,
        record: &'a NormalizedTriggerEventRecord,
    ) -> StoreFuture<'a, bool>;
    fn put_schedule_cursor<'a>(
        &'a self,
        cursor: &'a ScheduleTriggerCursor,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, ()>;
    fn reconcile_due_schedules<'a>(
        &'a self,
        now_unix_ms: u64,
        limit: usize,
    ) -> StoreFuture<'a, ScheduleReconciliationSummary>;
    fn schedule_cursor<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: &'a str,
        workflow_identity: &'a str,
        schedule_key: &'a str,
    ) -> StoreFuture<'a, ScheduleTriggerCursor>;
    fn workflow_semantics_metrics<'a>(
        &'a self,
        tenant_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, WorkflowSemanticsMetrics>;
    fn record_expanded_job_set<'a>(
        &'a self,
        record: &'a ExpandedJobSetRecord,
        verifying_key: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, bool>;
    fn materialize_expanded_job_set<'a>(
        &'a self,
        request: &'a MaterializeExpandedJobSet,
        verifying_key: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, ExpandedJobMaterialization>;
}

impl WorkflowSemanticsStore for ControlPlane {
    fn record_normalized_trigger<'a>(
        &'a self,
        r: &'a NormalizedTriggerEventRecord,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move { ControlPlane::record_normalized_trigger(self, r) })
    }
    fn put_schedule_cursor<'a>(
        &'a self,
        c: &'a ScheduleTriggerCursor,
        v: Option<u64>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move { ControlPlane::put_schedule_cursor(self, c, v) })
    }
    fn reconcile_due_schedules<'a>(
        &'a self,
        n: u64,
        l: usize,
    ) -> StoreFuture<'a, ScheduleReconciliationSummary> {
        Box::pin(async move { ControlPlane::reconcile_due_schedules(self, n, l) })
    }
    fn schedule_cursor<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
        w: &'a str,
        k: &'a str,
    ) -> StoreFuture<'a, ScheduleTriggerCursor> {
        Box::pin(async move { ControlPlane::schedule_cursor(self, t, r, w, k) })
    }
    fn workflow_semantics_metrics<'a>(
        &'a self,
        t: &'a str,
        n: u64,
    ) -> StoreFuture<'a, WorkflowSemanticsMetrics> {
        Box::pin(async move { ControlPlane::workflow_semantics_metrics(self, t, n) })
    }
    fn record_expanded_job_set<'a>(
        &'a self,
        r: &'a ExpandedJobSetRecord,
        k: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move { ControlPlane::record_expanded_job_set(self, r, k) })
    }
    fn materialize_expanded_job_set<'a>(
        &'a self,
        r: &'a MaterializeExpandedJobSet,
        k: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, ExpandedJobMaterialization> {
        Box::pin(async move { ControlPlane::materialize_expanded_job_set(self, r, k) })
    }
}

impl ApprovalStore for ControlPlane {
    fn create_approval_request<'a>(
        &'a self,
        repository_id: &'a str,
        capsule_id: &'a str,
        request: &'a ApprovalRequest,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            ControlPlane::create_approval_request(self, repository_id, capsule_id, request)
        })
    }
    fn approval_request<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ApprovalRequest> {
        Box::pin(async move { ControlPlane::approval_request(self, id) })
    }
    fn approval_requests_for_capsule<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        Box::pin(async move { ControlPlane::approval_requests_for_capsule(self, id) })
    }
    fn decide_approval<'a>(
        &'a self,
        id: &'a str,
        decision: ApprovalDecision,
        now: u64,
    ) -> StoreFuture<'a, ApprovalRequest> {
        Box::pin(async move { ControlPlane::decide_approval(self, id, decision, now) })
    }
    fn decide_approval_idempotent<'a>(
        &'a self,
        key: &'a str,
        id: &'a str,
        decision: ApprovalDecision,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<ApprovalRequest>> {
        Box::pin(
            async move { ControlPlane::decide_approval_idempotent(self, key, id, decision, now) },
        )
    }
    fn authorize_approval<'a>(
        &'a self,
        id: &'a str,
        subject: &'a ContentDigest,
        now: u64,
    ) -> StoreFuture<'a, ApprovalRequest> {
        Box::pin(async move { ControlPlane::authorize_approval(self, id, subject, now) })
    }
    fn list_approval_requests_page<'a>(
        &'a self,
        status: Option<&'a str>,
        after: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        Box::pin(
            async move { ControlPlane::list_approval_requests_page(self, status, after, limit) },
        )
    }
    fn list_approval_requests_page_for_tenant<'a>(
        &'a self,
        tenant: &'a str,
        status: Option<&'a str>,
        after: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        Box::pin(async move {
            ControlPlane::list_approval_requests_page_for_tenant(self, tenant, status, after, limit)
        })
    }
    fn approval_request_tenant<'a>(&'a self, id: &'a str) -> StoreFuture<'a, String> {
        Box::pin(async move { ControlPlane::approval_request_tenant(self, id) })
    }
    fn approval_request_binding<'a>(&'a self, id: &'a str) -> StoreFuture<'a, (String, String)> {
        Box::pin(async move { ControlPlane::approval_request_binding(self, id) })
    }
    fn approval_pending_execution_count<'a>(&'a self, id: &'a str) -> StoreFuture<'a, u64> {
        Box::pin(async move { ControlPlane::approval_pending_execution_count(self, id) })
    }
    fn approval_pending_execution_events<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<serde_json::Value>> {
        Box::pin(async move { ControlPlane::approval_pending_execution_events(self, id) })
    }
}

impl RunCoreStore for ControlPlane {
    fn store_signed_capsule<'a>(
        &'a self,
        capsule: &'a SignedCapsuleRecord,
        verifying_key: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move { ControlPlane::store_signed_capsule(self, capsule, verifying_key) })
    }
    fn signed_capsule<'a>(&'a self, id: &'a str) -> StoreFuture<'a, SignedCapsuleRecord> {
        Box::pin(async move { ControlPlane::signed_capsule(self, id) })
    }
    fn signed_capsule_for_lease<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, (String, SignedCapsuleRecord)> {
        Box::pin(async move { ControlPlane::signed_capsule_for_lease(self, lease_id) })
    }
    fn store_compiled_capsule_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        capsule: &'a SignedCapsuleRecord,
        verifying_key: &'a CapsuleVerifyingKey,
        metadata: &'a CapsuleApiMetadata,
        approvals: &'a [ApprovalRequest],
    ) -> StoreFuture<'a, IdempotentResult<SignedCapsuleRecord>> {
        Box::pin(async move {
            ControlPlane::store_compiled_capsule_idempotent(
                self,
                idempotency_key,
                capsule,
                verifying_key,
                metadata,
                approvals,
            )
        })
    }
    fn capsule_api_metadata<'a>(
        &'a self,
        capsule_id: &'a str,
    ) -> StoreFuture<'a, CapsuleApiMetadata> {
        Box::pin(async move { ControlPlane::capsule_api_metadata(self, capsule_id) })
    }
    fn create_run_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        request: &'a CreateRunRequest,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>> {
        Box::pin(async move { ControlPlane::create_run_idempotent(self, idempotency_key, request) })
    }
    fn run<'a>(&'a self, id: &'a str) -> StoreFuture<'a, RunRecord> {
        Box::pin(async move { ControlPlane::run(self, id) })
    }
    fn list_runs_page<'a>(
        &'a self,
        repository_id: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<RunRecord>> {
        Box::pin(async move { ControlPlane::list_runs_page(self, repository_id, after_id, limit) })
    }
    fn list_runs_page_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<RunRecord>> {
        Box::pin(async move {
            ControlPlane::list_runs_page_for_tenant(self, tenant_id, repository_id, after_id, limit)
        })
    }
    fn jobs_for_run<'a>(&'a self, run_id: &'a str) -> StoreFuture<'a, Vec<JobRecord>> {
        Box::pin(async move { ControlPlane::jobs_for_run(self, run_id) })
    }
    fn job<'a>(&'a self, job_id: &'a str) -> StoreFuture<'a, JobRecord> {
        Box::pin(async move { ControlPlane::job(self, job_id) })
    }
    fn transition_run_state<'a>(
        &'a self,
        run_id: &'a str,
        next: RunState,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, RunRecord> {
        Box::pin(async move { ControlPlane::transition_run_state(self, run_id, next, now_unix_ms) })
    }
    fn transition_job_state<'a>(
        &'a self,
        job_id: &'a str,
        next: JobState,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, JobRecord> {
        Box::pin(async move { ControlPlane::transition_job_state(self, job_id, next, now_unix_ms) })
    }
    fn cancel_run_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        run_id: &'a str,
        reason: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>> {
        Box::pin(async move {
            ControlPlane::cancel_run_idempotent(self, idempotency_key, run_id, reason, now_unix_ms)
        })
    }
    fn store_replay_bundle_idempotent<'a>(
        &'a self,
        idempotency_key: &'a str,
        record: &'a ReplayBundleRecord,
    ) -> StoreFuture<'a, IdempotentResult<ReplayBundleRecord>> {
        Box::pin(async move {
            ControlPlane::store_replay_bundle_idempotent(self, idempotency_key, record)
        })
    }
    fn replay_bundle_for_run<'a>(&'a self, run_id: &'a str) -> StoreFuture<'a, ReplayBundleRecord> {
        Box::pin(async move { ControlPlane::replay_bundle_for_run(self, run_id) })
    }
}

#[cfg(feature = "postgres")]
fn invalid_text(value: &str) -> bool {
    value.is_empty() || value.len() > 4096 || value.contains('\0')
}

#[cfg(feature = "postgres")]
fn validate_text(value: &str) -> Result<(), ControlPlaneError> {
    if invalid_text(value) {
        Err(ControlPlaneError::InvalidInput(
            "empty, oversized, or NUL text",
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "postgres")]
fn validate_idempotency_key(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 200 || value.contains('\0') {
        Err(ControlPlaneError::InvalidInput("invalid idempotency key"))
    } else {
        Ok(())
    }
}

#[cfg(feature = "postgres")]
fn not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(feature = "postgres")]
fn run_state_name(state: RunState) -> &'static str {
    match state {
        RunState::Created => "created",
        RunState::Running => "running",
        RunState::Succeeded => "succeeded",
        RunState::Failed => "failed",
        RunState::Canceled => "canceled",
    }
}

#[cfg(feature = "postgres")]
fn parse_run_state(value: &str) -> Result<RunState, ControlPlaneError> {
    match value {
        "created" => Ok(RunState::Created),
        "running" => Ok(RunState::Running),
        "succeeded" => Ok(RunState::Succeeded),
        "failed" => Ok(RunState::Failed),
        "canceled" => Ok(RunState::Canceled),
        other => Err(ControlPlaneError::CorruptState(format!(
            "unknown run state `{other}`"
        ))),
    }
}

#[cfg(feature = "postgres")]
fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Created => "created",
        JobState::BlockedPolicy => "blocked_policy",
        JobState::AwaitingApproval => "awaiting_approval",
        JobState::Queued => "queued",
        JobState::Leased => "leased",
        JobState::Preparing => "preparing",
        JobState::Running => "running",
        JobState::Finalizing => "finalizing",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Canceled => "canceled",
        JobState::TimedOut => "timed_out",
        JobState::Lost => "lost",
        JobState::Rejected => "rejected",
        JobState::Skipped => "skipped",
    }
}

#[cfg(feature = "postgres")]
fn approval_status_name(status: runtrue_policy::ApprovalStatus) -> &'static str {
    match status {
        runtrue_policy::ApprovalStatus::Pending => "pending",
        runtrue_policy::ApprovalStatus::Approved => "approved",
        runtrue_policy::ApprovalStatus::Denied => "denied",
        runtrue_policy::ApprovalStatus::Expired => "expired",
        runtrue_policy::ApprovalStatus::Consumed => "consumed",
    }
}

#[cfg(feature = "postgres")]
fn approval_kind_name(kind: runtrue_policy::ApprovalKind) -> &'static str {
    match kind {
        runtrue_policy::ApprovalKind::WorkflowDefinition => "workflow-definition",
        runtrue_policy::ApprovalKind::PrivilegedExecution => "privileged-execution",
        runtrue_policy::ApprovalKind::EnvironmentDeployment => "environment-deployment",
        runtrue_policy::ApprovalKind::ArtifactPromotion => "artifact-promotion",
        runtrue_policy::ApprovalKind::BreakGlass => "break-glass",
    }
}

#[cfg(feature = "postgres")]
fn parse_job_state(value: &str) -> Result<JobState, ControlPlaneError> {
    match value {
        "created" => Ok(JobState::Created),
        "blocked_policy" => Ok(JobState::BlockedPolicy),
        "awaiting_approval" => Ok(JobState::AwaitingApproval),
        "queued" => Ok(JobState::Queued),
        "leased" => Ok(JobState::Leased),
        "preparing" => Ok(JobState::Preparing),
        "running" => Ok(JobState::Running),
        "finalizing" => Ok(JobState::Finalizing),
        "succeeded" => Ok(JobState::Succeeded),
        "failed" => Ok(JobState::Failed),
        "canceled" => Ok(JobState::Canceled),
        "timed_out" => Ok(JobState::TimedOut),
        "lost" => Ok(JobState::Lost),
        "rejected" => Ok(JobState::Rejected),
        "skipped" => Ok(JobState::Skipped),
        other => Err(ControlPlaneError::CorruptState(format!(
            "unknown job state `{other}`"
        ))),
    }
}

#[cfg(feature = "postgres")]
fn validate_signed_capsule(
    capsule: &SignedCapsuleRecord,
    verifying_key: &CapsuleVerifyingKey,
) -> Result<Vec<u8>, ControlPlaneError> {
    validate_text(&capsule.id)?;
    validate_text(&capsule.repository_id)?;
    let decoded: runtrue_workflow_ir::ExecutionCapsule =
        serde_json::from_slice(&capsule.canonical_capsule)?;
    if decoded.canonical_bytes()? != capsule.canonical_capsule {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let actual = ContentDigest::sha256(&capsule.canonical_capsule);
    if actual != capsule.digest || capsule.signature.capsule_digest != capsule.digest {
        return Err(ControlPlaneError::CapsuleDigestMismatch {
            expected: capsule.digest.clone(),
            actual,
        });
    }
    verifying_key.verify_capsule(&decoded, &capsule.signature)?;
    Ok(serde_json::to_vec(&capsule.signature)?)
}

#[cfg(feature = "postgres")]
fn create_run_hash(request: &CreateRunRequest) -> Result<ContentDigest, ControlPlaneError> {
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
    Ok(ContentDigest::sha256(serde_json::to_vec(&IdempotentRun {
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
    })?))
}

#[cfg(feature = "postgres")]
fn validate_create_run(request: &CreateRunRequest) -> Result<(), ControlPlaneError> {
    validate_text(&request.id)?;
    validate_text(&request.repository_id)?;
    validate_text(&request.capsule_id)?;
    if !(-1000..=1000).contains(&request.priority) || request.jobs.is_empty() {
        return Err(ControlPlaneError::InvalidInput(
            "run priority or job set is invalid",
        ));
    }
    let mut ids = BTreeSet::new();
    for job in &request.jobs {
        validate_text(&job.id)?;
        validate_text(&job.job_key)?;
        if job.attempt == 0 || !ids.insert(&job.id) {
            return Err(ControlPlaneError::InvalidInput(
                "job ids must be unique and attempts must start at one",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn run_row(row: &sqlx::postgres::PgRow) -> Result<RunRecord, ControlPlaneError> {
    Ok(RunRecord {
        id: row.try_get("id")?,
        repository_id: row.try_get("repository_id")?,
        capsule_id: row.try_get("capsule_id")?,
        status: parse_run_state(&row.try_get::<String, _>("status")?)?,
        priority: row.try_get("priority")?,
        remote: row.try_get("remote")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "run creation")?,
        started_unix_ms: row
            .try_get::<Option<i64>, _>("started_unix_ms")?
            .map(|value| postgres_u64(value, "run start"))
            .transpose()?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|value| postgres_u64(value, "run completion"))
            .transpose()?,
        cancel_reason: row.try_get("cancel_reason")?,
    })
}

#[cfg(feature = "postgres")]
fn job_row(row: &sqlx::postgres::PgRow) -> Result<JobRecord, ControlPlaneError> {
    Ok(JobRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        job_key: row.try_get("job_key")?,
        attempt: u32::try_from(row.try_get::<i32, _>("attempt")?).map_err(|_| {
            ControlPlaneError::IntegerRange {
                field: "job attempt",
            }
        })?,
        status: parse_job_state(&row.try_get::<String, _>("status")?)?,
        requirements: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("requirements_json")?)?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "job creation")?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|value| postgres_u64(value, "job completion"))
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
async fn run_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    lock: bool,
) -> Result<RunRecord, ControlPlaneError> {
    let sql = if lock {
        "SELECT * FROM runs WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM runs WHERE id=$1"
    };
    let row = sqlx::query(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| not_found("run", id))?;
    run_row(&row)
}

#[cfg(feature = "postgres")]
async fn job_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    lock: bool,
) -> Result<JobRecord, ControlPlaneError> {
    let sql = if lock {
        "SELECT * FROM jobs WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM jobs WHERE id=$1"
    };
    let row = sqlx::query(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| not_found("job", id))?;
    job_row(&row)
}

#[cfg(feature = "postgres")]
async fn conclude_run_if_terminal(
    tx: &mut Transaction<'_, Postgres>,
    job_id: &str,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let row = sqlx::query("SELECT run_id FROM jobs WHERE id=$1")
        .bind(job_id)
        .fetch_one(&mut **tx)
        .await?;
    let run_id: String = row.try_get("run_id")?;
    let rows = sqlx::query("SELECT job_key,status FROM jobs WHERE run_id=$1 ORDER BY job_key")
        .bind(&run_id)
        .fetch_all(&mut **tx)
        .await?;
    let mut states = rows
        .iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("job_key")?,
                parse_job_state(&row.try_get::<String, _>("status")?)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ControlPlaneError>>()?;
    let capsule_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT c.canonical_capsule FROM runs r JOIN capsules c ON c.id=r.capsule_id WHERE r.id=$1",
    )
    .bind(&run_id)
    .fetch_one(&mut **tx)
    .await?;
    let capsule: runtrue_workflow_ir::ExecutionCapsule = serde_json::from_slice(&capsule_bytes)?;
    loop {
        let mut changes = Vec::new();
        for planned in &capsule.jobs {
            if states.get(&planned.id) != Some(&JobState::Created) {
                continue;
            }
            if planned
                .needs
                .iter()
                .all(|need| states.get(need) == Some(&JobState::Succeeded))
            {
                changes.push((planned.id.clone(), JobState::Queued));
            } else if planned.needs.iter().all(|need| {
                states
                    .get(need)
                    .is_some_and(|state| state.is_terminal() || *state == JobState::BlockedPolicy)
            }) {
                changes.push((planned.id.clone(), JobState::Skipped));
            }
        }
        if changes.is_empty() {
            break;
        }
        for (key, state) in changes {
            sqlx::query(
                "UPDATE jobs SET status=$3,completed_unix_ms=$4 WHERE run_id=$1 AND job_key=$2",
            )
            .bind(&run_id)
            .bind(&key)
            .bind(job_state_name(state))
            .bind(
                state
                    .is_terminal()
                    .then_some(postgres_i64(now, "job completion")?),
            )
            .execute(&mut **tx)
            .await?;
            states.insert(key, state);
        }
    }
    if states
        .values()
        .any(|state| !state.is_terminal() && *state != JobState::BlockedPolicy)
    {
        return Ok(());
    }
    let run = run_tx(tx, &run_id, true).await?;
    let final_state =
        if run.cancel_reason.is_some() || states.values().any(|s| *s == JobState::Canceled) {
            RunState::Canceled
        } else if states.values().any(|state| {
            matches!(
                state,
                JobState::BlockedPolicy
                    | JobState::Failed
                    | JobState::TimedOut
                    | JobState::Lost
                    | JobState::Rejected
            )
        }) {
            RunState::Failed
        } else {
            RunState::Succeeded
        };
    if run.status.can_transition_to(final_state) {
        sqlx::query("UPDATE runs SET status=$2,completed_unix_ms=$3 WHERE id=$1")
            .bind(&run_id)
            .bind(run_state_name(final_state))
            .bind(postgres_i64(now, "run completion")?)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn replay_row(row: &sqlx::postgres::PgRow) -> Result<ReplayBundleRecord, ControlPlaneError> {
    Ok(ReplayBundleRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        digest: ContentDigest::parse(row.try_get::<String, _>("digest")?)?,
        canonical_bundle: row.try_get("bundle_json")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "replay creation")?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "replay expiry")?,
    })
}

#[cfg(feature = "postgres")]
impl RunCoreStore for PostgresInstallationStore {
    fn store_signed_capsule<'a>(
        &'a self,
        capsule: &'a SignedCapsuleRecord,
        verifying_key: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let signature = validate_signed_capsule(capsule, verifying_key)?;
            sqlx::query("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(&capsule.id).bind(&capsule.repository_id).bind(capsule.digest.as_str())
                .bind(&capsule.canonical_capsule).bind(signature).bind(capsule.signature.key_id.as_str())
                .bind(postgres_i64(capsule.created_unix_ms,"capsule creation")?).execute(self.pool()).await?;
            Ok(())
        })
    }
    fn signed_capsule<'a>(&'a self, id: &'a str) -> StoreFuture<'a, SignedCapsuleRecord> {
        Box::pin(async move {
            validate_text(id)?;
            let row=sqlx::query("SELECT id,repository_id,digest,canonical_capsule,signature_json,created_unix_ms FROM capsules WHERE id=$1").bind(id).fetch_optional(self.pool()).await?.ok_or_else(||not_found("capsule",id))?;
            Ok(SignedCapsuleRecord {
                id: row.try_get("id")?,
                repository_id: row.try_get("repository_id")?,
                digest: ContentDigest::parse(row.try_get::<String, _>("digest")?)?,
                canonical_capsule: row.try_get("canonical_capsule")?,
                signature: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("signature_json")?)?,
                created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "capsule creation")?,
            })
        })
    }
    fn signed_capsule_for_lease<'a>(
        &'a self,
        lease_id: &'a str,
    ) -> StoreFuture<'a, (String, SignedCapsuleRecord)> {
        Box::pin(async move {
            validate_text(lease_id)?;
            let mut tx = self.pool().begin().await?;
            let row = sqlx::query(
                "SELECT j.job_key,l.capsule_digest,c.id,c.repository_id,c.digest,
                        c.canonical_capsule,c.signature_json,c.created_unix_ms
                 FROM leases l JOIN jobs j ON j.id=l.job_id
                 JOIN runs r ON r.id=j.run_id JOIN capsules c ON c.id=r.capsule_id
                 WHERE l.id=$1",
            )
            .bind(lease_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| not_found("lease capsule", lease_id))?;
            let capsule = SignedCapsuleRecord {
                id: row.try_get("id")?,
                repository_id: row.try_get("repository_id")?,
                digest: ContentDigest::parse(row.try_get::<String, _>("digest")?)?,
                canonical_capsule: row.try_get("canonical_capsule")?,
                signature: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("signature_json")?)?,
                created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "capsule creation")?,
            };
            let lease_digest = ContentDigest::parse(row.try_get::<String, _>("capsule_digest")?)?;
            if lease_digest != capsule.digest || capsule.signature.capsule_digest != capsule.digest
            {
                return Err(ControlPlaneError::CorruptState(
                    "lease capsule digest does not match its signed capsule".to_owned(),
                ));
            }
            let job_key = row.try_get("job_key")?;
            tx.commit().await?;
            Ok((job_key, capsule))
        })
    }
    fn store_compiled_capsule_idempotent<'a>(
        &'a self,
        key: &'a str,
        capsule: &'a SignedCapsuleRecord,
        verifying_key: &'a CapsuleVerifyingKey,
        metadata: &'a CapsuleApiMetadata,
        approvals: &'a [ApprovalRequest],
    ) -> StoreFuture<'a, IdempotentResult<SignedCapsuleRecord>> {
        Box::pin(async move {
            validate_idempotency_key(key)?;
            let signature = validate_signed_capsule(capsule, verifying_key)?;
            if metadata.capsule_id != capsule.id || metadata.risk_score > 100 {
                return Err(ControlPlaneError::InvalidInput(
                    "capsule API metadata does not match the signed capsule",
                ));
            }
            let decoded: runtrue_workflow_ir::ExecutionCapsule =
                serde_json::from_slice(&capsule.canonical_capsule)?;
            let workflow = approvals
                .iter()
                .filter(|approval| {
                    approval.kind == runtrue_policy::ApprovalKind::WorkflowDefinition
                })
                .count();
            let privileged = approvals
                .iter()
                .filter(|approval| {
                    approval.kind == runtrue_policy::ApprovalKind::PrivilegedExecution
                })
                .count();
            let expected = usize::from(decoded.approval.workflow_definition)
                + usize::from(decoded.approval.privileged_execution);
            if workflow != usize::from(decoded.approval.workflow_definition)
                || privileged != usize::from(decoded.approval.privileged_execution)
                || approvals.len() != expected
            {
                return Err(ControlPlaneError::InvalidInput(
                    "capsule approval requests do not match its independent gates",
                ));
            }
            for approval in approvals {
                let recreated = ApprovalRequest::create(
                    approval.id.clone(),
                    approval.kind,
                    approval.subject_digest.clone(),
                    approval.risk_score,
                    approval.created_unix_ms,
                    approval.expires_unix_ms,
                    approval.rule.clone(),
                )?;
                if recreated != *approval
                    || approval.subject_digest != metadata.approval_subject_digest
                    || approval.risk_score != metadata.risk_score
                {
                    return Err(ControlPlaneError::InvalidInput(
                        "approval request does not match capsule metadata",
                    ));
                }
            }
            #[derive(Serialize)]
            struct Subject<'a> {
                repository_id: &'a str,
                digest: &'a ContentDigest,
                approval_subject_digest: &'a ContentDigest,
                risk_score: u32,
            }
            let hash = ContentDigest::sha256(serde_json::to_vec(&Subject {
                repository_id: &capsule.repository_id,
                digest: &capsule.digest,
                approval_subject_digest: &metadata.approval_subject_digest,
                risk_score: metadata.risk_score,
            })?);
            let operation = format!("capsule.create:{}", capsule.repository_id);
            let mut tx = self.pool().begin().await?;
            if let Some(row) = sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation=$1 AND idempotency_key=$2")
                .bind(&operation).bind(key).fetch_optional(&mut *tx).await?
            {
                if row.try_get::<String,_>("request_hash")? != hash.as_str() {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let id: String = row.try_get("resource_id")?;
                let row=sqlx::query("SELECT id,repository_id,digest,canonical_capsule,signature_json,created_unix_ms FROM capsules WHERE id=$1").bind(&id).fetch_one(&mut *tx).await?;
                let value=SignedCapsuleRecord{id:row.try_get("id")?,repository_id:row.try_get("repository_id")?,digest:ContentDigest::parse(row.try_get::<String,_>("digest")?)?,canonical_capsule:row.try_get("canonical_capsule")?,signature:serde_json::from_slice(&row.try_get::<Vec<u8>,_>("signature_json")?)?,created_unix_ms:postgres_u64(row.try_get("created_unix_ms")?,"capsule creation")?};
                tx.commit().await?;
                return Ok(IdempotentResult{value,replayed:true});
            }
            sqlx::query("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(&capsule.id).bind(&capsule.repository_id).bind(capsule.digest.as_str()).bind(&capsule.canonical_capsule).bind(signature).bind(capsule.signature.key_id.as_str()).bind(postgres_i64(capsule.created_unix_ms,"capsule creation")?).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO capsule_api_metadata(capsule_id,approval_subject_digest,risk_score) VALUES($1,$2,$3)")
                .bind(&metadata.capsule_id).bind(metadata.approval_subject_digest.as_str()).bind(i32::try_from(metadata.risk_score).map_err(|_|ControlPlaneError::IntegerRange{field:"capsule risk score"})?).execute(&mut *tx).await?;
            for approval in approvals {
                sqlx::query("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                    .bind(&approval.id).bind(&capsule.repository_id).bind(&capsule.id).bind(approval.subject_digest.as_str()).bind(approval_status_name(approval.status)).bind(serde_json::to_vec(approval)?).bind(postgres_i64(approval.created_unix_ms,"approval creation")?).bind(postgres_i64(approval.expires_unix_ms,"approval expiry")?).execute(&mut *tx).await?;
            }
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)")
                .bind(&operation).bind(key).bind(hash.as_str()).bind(&capsule.id).bind(postgres_i64(capsule.created_unix_ms,"capsule idempotency")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: capsule.clone(),
                replayed: false,
            })
        })
    }
    fn capsule_api_metadata<'a>(&'a self, id: &'a str) -> StoreFuture<'a, CapsuleApiMetadata> {
        Box::pin(async move {
            validate_text(id)?;
            let row=sqlx::query("SELECT capsule_id,approval_subject_digest,risk_score FROM capsule_api_metadata WHERE capsule_id=$1").bind(id).fetch_optional(self.pool()).await?.ok_or_else(||not_found("capsule API metadata",id))?;
            Ok(CapsuleApiMetadata {
                capsule_id: row.try_get("capsule_id")?,
                approval_subject_digest: ContentDigest::parse(
                    row.try_get::<String, _>("approval_subject_digest")?,
                )?,
                risk_score: u32::try_from(row.try_get::<i32, _>("risk_score")?).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "capsule risk score",
                    }
                })?,
            })
        })
    }
    fn create_run_idempotent<'a>(
        &'a self,
        key: &'a str,
        request: &'a CreateRunRequest,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>> {
        Box::pin(async move {
            validate_idempotency_key(key)?;
            validate_create_run(request)?;
            let hash = create_run_hash(request)?;
            let mut tx = self.pool().begin().await?;
            if let Some(row)=sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation='run.create' AND idempotency_key=$1").bind(key).fetch_optional(&mut *tx).await? {
                if row.try_get::<String,_>("request_hash")? != hash.as_str(){return Err(ControlPlaneError::IdempotencyConflict)}
                let id:String=row.try_get("resource_id")?; let value=run_tx(&mut tx,&id,false).await?; tx.commit().await?; return Ok(IdempotentResult{value,replayed:true});
            }
            let row =
                sqlx::query("SELECT repository_id,canonical_capsule FROM capsules WHERE id=$1")
                    .bind(&request.capsule_id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or_else(|| not_found("capsule", &request.capsule_id))?;
            if row.try_get::<String, _>("repository_id")? != request.repository_id {
                return Err(ControlPlaneError::InvalidInput(
                    "capsule does not belong to the requested repository",
                ));
            }
            let capsule: runtrue_workflow_ir::ExecutionCapsule =
                serde_json::from_slice(&row.try_get::<Vec<u8>, _>("canonical_capsule")?)?;
            let mut authorized = Vec::new();
            if capsule.approval.workflow_definition || capsule.approval.privileged_execution {
                let subject: Option<String> = sqlx::query_scalar(
                    "SELECT approval_subject_digest FROM capsule_api_metadata WHERE capsule_id=$1",
                )
                .bind(&request.capsule_id)
                .fetch_optional(&mut *tx)
                .await?;
                let Some(subject) = subject else {
                    return Err(ControlPlaneError::ApprovalRequired);
                };
                let subject = ContentDigest::parse(subject)?;
                for (kind, required) in [
                    (
                        runtrue_policy::ApprovalKind::WorkflowDefinition,
                        capsule.approval.workflow_definition,
                    ),
                    (
                        runtrue_policy::ApprovalKind::PrivilegedExecution,
                        capsule.approval.privileged_execution,
                    ),
                ] {
                    if !required {
                        continue;
                    }
                    let rows=sqlx::query("SELECT request_json FROM approval_requests WHERE capsule_id=$1 AND subject_digest=$2 AND status='approved' ORDER BY created_unix_ms,id")
                        .bind(&request.capsule_id).bind(subject.as_str()).fetch_all(&mut *tx).await?;
                    let mut selected = None;
                    for row in rows {
                        let mut approval: ApprovalRequest =
                            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("request_json")?)?;
                        if approval.kind == kind
                            && approval
                                .authorize(&subject, request.created_unix_ms)
                                .is_ok()
                        {
                            update_approval_pg(&mut tx, &approval).await?;
                            selected =
                                Some((approval.id, kind, subject.clone(), approval.rule.one_shot));
                            break;
                        }
                    }
                    authorized.push(selected.ok_or(ControlPlaneError::ApprovalRequired)?);
                }
            }
            if request.remote {
                if capsule.jobs.len() != request.jobs.len() {
                    return Err(ControlPlaneError::InvalidInput(
                        "SCM run jobs do not match the signed capsule",
                    ));
                }
                for (planned, job) in capsule.jobs.iter().zip(&request.jobs) {
                    let expected = runtrue_scheduler::SchedulingRequirements {
                        os: planned.runner.os,
                        arch: planned.runner.arch,
                        isolation: planned.runner.isolation,
                        cpu: u32::from(planned.runner.cpu),
                        memory_bytes: planned.runner.memory_bytes,
                        storage_bytes: planned.runner.storage_bytes.unwrap_or(0),
                        region: planned.runner.region.clone(),
                        required_capabilities: planned
                            .runner
                            .capabilities
                            .iter()
                            .cloned()
                            .collect(),
                        allowed_pools: BTreeSet::new(),
                    };
                    if job.job_key != planned.id || job.attempt != 1 || job.requirements != expected
                    {
                        return Err(ControlPlaneError::InvalidInput(
                            "SCM run jobs do not match the signed capsule",
                        ));
                    }
                }
            }
            sqlx::query("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES($1,$2,$3,'created',$4,$5,$6)").bind(&request.id).bind(&request.repository_id).bind(&request.capsule_id).bind(request.priority).bind(request.remote).bind(postgres_i64(request.created_unix_ms,"run creation")?).execute(&mut *tx).await?;
            for (approval_id, kind, subject, one_shot) in authorized {
                sqlx::query("INSERT INTO run_approval_authorizations(run_id,approval_id,kind,subject_digest,one_shot,authorized_unix_ms) VALUES($1,$2,$3,$4,$5,$6)")
                    .bind(&request.id).bind(approval_id).bind(approval_kind_name(kind)).bind(subject.as_str()).bind(one_shot).bind(postgres_i64(request.created_unix_ms,"run authorization")?).execute(&mut *tx).await?;
            }
            for (index, job) in request.jobs.iter().enumerate() {
                let (status, group) = if request.remote {
                    let planned = &capsule.jobs[index];
                    let ready = capsule.context.source_tree_digest.is_none()
                        && capsule.context.source_trust.satisfies(planned.trust);
                    (
                        if !capsule.context.source_trust.satisfies(planned.trust) {
                            JobState::BlockedPolicy
                        } else if ready && planned.needs.is_empty() {
                            JobState::Queued
                        } else {
                            JobState::Created
                        },
                        planned.concurrency.as_deref(),
                    )
                } else {
                    (JobState::Created, None)
                };
                sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms,completed_unix_ms,concurrency_group) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(&job.id).bind(&request.id).bind(&job.job_key).bind(i32::try_from(job.attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"job attempt"})?).bind(job_state_name(status)).bind(serde_json::to_vec(&job.requirements)?).bind(postgres_i64(request.created_unix_ms,"job creation")?).bind(matches!(status,JobState::BlockedPolicy|JobState::Skipped).then_some(postgres_i64(request.created_unix_ms,"job completion")?)).bind(group).execute(&mut *tx).await?;
                sqlx::query("INSERT INTO job_fencing(job_id,last_generation) VALUES($1,0)")
                    .bind(&job.id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES('run.create',$1,$2,$3,$4)").bind(key).bind(hash.as_str()).bind(&request.id).bind(postgres_i64(request.created_unix_ms,"run idempotency")?).execute(&mut *tx).await?;
            let value = run_tx(&mut tx, &request.id, false).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }
    fn run<'a>(&'a self, id: &'a str) -> StoreFuture<'a, RunRecord> {
        Box::pin(async move {
            validate_text(id)?;
            let row = sqlx::query("SELECT * FROM runs WHERE id=$1")
                .bind(id)
                .fetch_optional(self.pool())
                .await?
                .ok_or_else(|| not_found("run", id))?;
            run_row(&row)
        })
    }
    fn list_runs_page<'a>(
        &'a self,
        repository_id: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<RunRecord>> {
        Box::pin(async move {
            if limit == 0 || limit > 100 {
                return Err(ControlPlaneError::InvalidInput(
                    "page limit must be between one and one hundred",
                ));
            }
            if let Some(value) = repository_id {
                validate_text(value)?;
            }
            if let Some(value) = after_id {
                validate_text(value)?;
            }
            let rows = sqlx::query(
                "SELECT id,repository_id,capsule_id,status,priority,remote,created_unix_ms,
                        started_unix_ms,completed_unix_ms,cancel_reason
                 FROM runs
                 WHERE ($1='' OR repository_id=$1)
                   AND ($2=''
                        OR created_unix_ms < (SELECT created_unix_ms FROM runs WHERE id=$2)
                        OR (created_unix_ms = (SELECT created_unix_ms FROM runs WHERE id=$2)
                            AND id < $2))
                 ORDER BY created_unix_ms DESC,id DESC LIMIT $3",
            )
            .bind(repository_id.unwrap_or(""))
            .bind(after_id.unwrap_or(""))
            .bind(
                i64::try_from(limit)
                    .map_err(|_| ControlPlaneError::InvalidInput("page limit is out of range"))?,
            )
            .fetch_all(self.pool())
            .await?;
            rows.iter().map(run_row).collect()
        })
    }
    fn list_runs_page_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        repository_id: Option<&'a str>,
        after_id: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<RunRecord>> {
        Box::pin(async move {
            validate_text(tenant_id)?;
            if limit == 0 || limit > 100 {
                return Err(ControlPlaneError::InvalidInput(
                    "page limit must be between one and one hundred",
                ));
            }
            if let Some(value) = repository_id {
                validate_text(value)?;
            }
            if let Some(value) = after_id {
                validate_text(value)?;
            }
            let rows = sqlx::query(
                "SELECT run.id,run.repository_id,run.capsule_id,run.status,run.priority,
                        run.remote,run.created_unix_ms,run.started_unix_ms,
                        run.completed_unix_ms,run.cancel_reason
                 FROM runs run JOIN repositories repo ON repo.id=run.repository_id
                 WHERE repo.tenant_id=$1
                   AND ($2='' OR run.repository_id=$2)
                   AND ($3=''
                        OR run.created_unix_ms < (SELECT created_unix_ms FROM runs WHERE id=$3)
                        OR (run.created_unix_ms = (SELECT created_unix_ms FROM runs WHERE id=$3)
                            AND run.id < $3))
                 ORDER BY run.created_unix_ms DESC,run.id DESC LIMIT $4",
            )
            .bind(tenant_id)
            .bind(repository_id.unwrap_or(""))
            .bind(after_id.unwrap_or(""))
            .bind(
                i64::try_from(limit)
                    .map_err(|_| ControlPlaneError::InvalidInput("page limit is out of range"))?,
            )
            .fetch_all(self.pool())
            .await?;
            rows.iter().map(run_row).collect()
        })
    }
    fn jobs_for_run<'a>(&'a self, id: &'a str) -> StoreFuture<'a, Vec<JobRecord>> {
        Box::pin(async move {
            validate_text(id)?;
            let rows = sqlx::query("SELECT * FROM jobs WHERE run_id=$1 ORDER BY id")
                .bind(id)
                .fetch_all(self.pool())
                .await?;
            rows.iter().map(job_row).collect()
        })
    }
    fn job<'a>(&'a self, id: &'a str) -> StoreFuture<'a, JobRecord> {
        Box::pin(async move {
            validate_text(id)?;
            let row = sqlx::query("SELECT * FROM jobs WHERE id=$1")
                .bind(id)
                .fetch_optional(self.pool())
                .await?
                .ok_or_else(|| not_found("job", id))?;
            job_row(&row)
        })
    }
    fn transition_run_state<'a>(
        &'a self,
        id: &'a str,
        next: RunState,
        now: u64,
    ) -> StoreFuture<'a, RunRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let current = run_tx(&mut tx, id, true).await?;
            if !current.status.can_transition_to(next) {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "run",
                    from: run_state_name(current.status),
                    to: run_state_name(next),
                });
            }
            sqlx::query("UPDATE runs SET status=$2,started_unix_ms=COALESCE(started_unix_ms,$3),completed_unix_ms=COALESCE(completed_unix_ms,$4) WHERE id=$1").bind(id).bind(run_state_name(next)).bind((next==RunState::Running).then_some(postgres_i64(now,"run start")?)).bind(next.is_terminal().then_some(postgres_i64(now,"run completion")?)).execute(&mut *tx).await?;
            let value = run_tx(&mut tx, id, false).await?;
            tx.commit().await?;
            Ok(value)
        })
    }
    fn transition_job_state<'a>(
        &'a self,
        id: &'a str,
        next: JobState,
        now: u64,
    ) -> StoreFuture<'a, JobRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let current = job_tx(&mut tx, id, true).await?;
            if current.status != next {
                if !current.status.can_transition_to(next) {
                    return Err(ControlPlaneError::InvalidTransition {
                        entity: "job",
                        from: job_state_name(current.status),
                        to: job_state_name(next),
                    });
                }
                sqlx::query("UPDATE jobs SET status=$2,completed_unix_ms=$3 WHERE id=$1")
                    .bind(id)
                    .bind(job_state_name(next))
                    .bind(
                        next.is_terminal()
                            .then_some(postgres_i64(now, "job completion")?),
                    )
                    .execute(&mut *tx)
                    .await?;
            }
            if next.is_terminal() || next == JobState::BlockedPolicy {
                conclude_run_if_terminal(&mut tx, id, now).await?;
            }
            let value = job_tx(&mut tx, id, false).await?;
            tx.commit().await?;
            Ok(value)
        })
    }
    fn cancel_run_idempotent<'a>(
        &'a self,
        key: &'a str,
        id: &'a str,
        reason: &'a str,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunRecord>> {
        Box::pin(async move {
            validate_idempotency_key(key)?;
            validate_text(reason)?;
            #[derive(Serialize)]
            struct Cancel<'a> {
                run_id: &'a str,
                reason: &'a str,
            }
            let hash = ContentDigest::sha256(serde_json::to_vec(&Cancel { run_id: id, reason })?);
            let mut tx = self.pool().begin().await?;
            if let Some(row)=sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation='run.cancel' AND idempotency_key=$1").bind(key).fetch_optional(&mut *tx).await?{if row.try_get::<String,_>("request_hash")?!=hash.as_str(){return Err(ControlPlaneError::IdempotencyConflict)}let resource:String=row.try_get("resource_id")?;let value=run_tx(&mut tx,&resource,false).await?;tx.commit().await?;return Ok(IdempotentResult{value,replayed:true})}
            let run = run_tx(&mut tx, id, true).await?;
            if run.status != RunState::Canceled {
                if run.status.is_terminal() {
                    return Err(ControlPlaneError::InvalidTransition {
                        entity: "run",
                        from: run_state_name(run.status),
                        to: "canceled",
                    });
                }
                sqlx::query("UPDATE runs SET cancel_reason=COALESCE(cancel_reason,$2) WHERE id=$1")
                    .bind(id)
                    .bind(reason)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE jobs SET status='canceled',completed_unix_ms=$2 WHERE run_id=$1 AND status NOT IN ('succeeded','failed','canceled','timed_out','lost','rejected','skipped') AND NOT EXISTS(SELECT 1 FROM leases l WHERE l.job_id=jobs.id AND l.state IN ('active','cancel_requested'))").bind(id).bind(postgres_i64(now,"job cancellation")?).execute(&mut *tx).await?;
                sqlx::query("UPDATE leases SET state=CASE WHEN state='offered' THEN 'rejected' ELSE 'cancel_requested' END WHERE job_id IN(SELECT id FROM jobs WHERE run_id=$1) AND state IN('offered','active')").bind(id).execute(&mut *tx).await?;
                let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM leases l JOIN jobs j ON j.id=l.job_id WHERE j.run_id=$1 AND l.state IN('active','cancel_requested'))").bind(id).fetch_one(&mut *tx).await?;
                if !active {
                    sqlx::query(
                        "UPDATE runs SET status='canceled',completed_unix_ms=$2 WHERE id=$1",
                    )
                    .bind(id)
                    .bind(postgres_i64(now, "run cancellation")?)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES('run.cancel',$1,$2,$3,$4)").bind(key).bind(hash.as_str()).bind(id).bind(postgres_i64(now,"run cancellation idempotency")?).execute(&mut *tx).await?;
            let value = run_tx(&mut tx, id, false).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: false,
            })
        })
    }
    fn store_replay_bundle_idempotent<'a>(
        &'a self,
        key: &'a str,
        record: &'a ReplayBundleRecord,
    ) -> StoreFuture<'a, IdempotentResult<ReplayBundleRecord>> {
        Box::pin(async move {
            validate_idempotency_key(key)?;
            validate_text(&record.id)?;
            validate_text(&record.run_id)?;
            if record.expires_unix_ms <= record.created_unix_ms {
                return Err(ControlPlaneError::InvalidInput(
                    "replay bundle expiry must be in the future",
                ));
            }
            let actual = ContentDigest::sha256(&record.canonical_bundle);
            if actual != record.digest {
                return Err(ControlPlaneError::CapsuleDigestMismatch {
                    expected: record.digest.clone(),
                    actual,
                });
            }
            #[derive(Serialize)]
            struct Subject<'a> {
                run_id: &'a str,
                digest: &'a ContentDigest,
            }
            let hash = ContentDigest::sha256(serde_json::to_vec(&Subject {
                run_id: &record.run_id,
                digest: &record.digest,
            })?);
            let mut tx = self.pool().begin().await?;
            if let Some(row)=sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation='replay.create' AND idempotency_key=$1").bind(key).fetch_optional(&mut *tx).await?{if row.try_get::<String,_>("request_hash")?!=hash.as_str(){return Err(ControlPlaneError::IdempotencyConflict)}let id:String=row.try_get("resource_id")?;let row=sqlx::query("SELECT * FROM replay_bundles WHERE id=$1").bind(id).fetch_one(&mut *tx).await?;let value=replay_row(&row)?;tx.commit().await?;return Ok(IdempotentResult{value,replayed:true})}
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runs WHERE id=$1)")
                .bind(&record.run_id)
                .fetch_one(&mut *tx)
                .await?;
            if !exists {
                return Err(not_found("run", &record.run_id));
            }
            sqlx::query("INSERT INTO replay_bundles(id,run_id,digest,bundle_json,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,$6)").bind(&record.id).bind(&record.run_id).bind(record.digest.as_str()).bind(&record.canonical_bundle).bind(postgres_i64(record.created_unix_ms,"replay creation")?).bind(postgres_i64(record.expires_unix_ms,"replay expiry")?).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES('replay.create',$1,$2,$3,$4)").bind(key).bind(hash.as_str()).bind(&record.id).bind(postgres_i64(record.created_unix_ms,"replay idempotency")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: record.clone(),
                replayed: false,
            })
        })
    }
    fn replay_bundle_for_run<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ReplayBundleRecord> {
        Box::pin(async move {
            validate_text(id)?;
            let row = sqlx::query("SELECT * FROM replay_bundles WHERE run_id=$1")
                .bind(id)
                .fetch_optional(self.pool())
                .await?
                .ok_or_else(|| not_found("replay bundle", id))?;
            replay_row(&row)
        })
    }
}

#[cfg(feature = "postgres")]
async fn approval_tx_pg(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    lock: bool,
) -> Result<ApprovalRequest, ControlPlaneError> {
    let sql = if lock {
        "SELECT request_json FROM approval_requests WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT request_json FROM approval_requests WHERE id=$1"
    };
    let encoded: Vec<u8> = sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| not_found("approval", id))?;
    Ok(serde_json::from_slice(&encoded)?)
}

#[cfg(feature = "postgres")]
async fn update_approval_pg(
    tx: &mut Transaction<'_, Postgres>,
    request: &ApprovalRequest,
) -> Result<(), ControlPlaneError> {
    sqlx::query("UPDATE approval_requests SET status=$2,request_json=$3 WHERE id=$1")
        .bind(&request.id)
        .bind(approval_status_name(request.status))
        .bind(serde_json::to_vec(request)?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn enqueue_approval_continuations_pg(
    tx: &mut Transaction<'_, Postgres>,
    approval_id: &str,
    decision: &ApprovalDecision,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let rows = sqlx::query("SELECT id FROM scm_pending_executions WHERE state IN('awaiting-approval','continuation-pending') AND (workflow_approval_id=$1 OR privileged_approval_id=$1) ORDER BY id LIMIT 65")
        .bind(approval_id).fetch_all(&mut **tx).await?;
    if rows.len() > 64 {
        return Err(ControlPlaneError::InvalidInput(
            "approval is bound to too many pending SCM executions",
        ));
    }
    #[derive(Serialize)]
    struct TaskIdentity<'a> {
        pending_execution_id: &'a str,
        approval_id: &'a str,
        actor_id: &'a str,
        decision: runtrue_policy::Decision,
        decided_unix_ms: u64,
        subject_digest: &'a ContentDigest,
    }
    #[derive(Serialize)]
    struct Payload<'a> {
        pending_execution_id: &'a str,
        approval_id: &'a str,
    }
    for row in rows {
        let pending_id: String = row.try_get("id")?;
        let digest = ContentDigest::sha256(serde_json::to_vec(&TaskIdentity {
            pending_execution_id: &pending_id,
            approval_id,
            actor_id: &decision.actor_id,
            decision: decision.decision,
            decided_unix_ms: decision.decided_unix_ms,
            subject_digest: &decision.subject_digest,
        })?);
        let task_id = format!(
            "scm-continuation-{}",
            digest.as_str().trim_start_matches("sha256:")
        );
        let payload = serde_json::to_vec(&Payload {
            pending_execution_id: &pending_id,
            approval_id,
        })?;
        sqlx::query("INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,created_unix_ms) VALUES($1,'scm.approval.continue',$2,'pending',$3,0,$3)")
            .bind(task_id).bind(payload).bind(postgres_i64(now,"approval continuation")?).execute(&mut **tx).await?;
        sqlx::query("UPDATE scm_pending_executions SET state='continuation-pending' WHERE id=$1 AND state='awaiting-approval'")
            .bind(&pending_id).execute(&mut **tx).await?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
impl ApprovalStore for PostgresInstallationStore {
    fn create_approval_request<'a>(
        &'a self,
        repository: &'a str,
        capsule: &'a str,
        request: &'a ApprovalRequest,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let expected = ApprovalRequest::create(
                request.id.clone(),
                request.kind,
                request.subject_digest.clone(),
                request.risk_score,
                request.created_unix_ms,
                request.expires_unix_ms,
                request.rule.clone(),
            )?;
            if expected != *request {
                return Err(ControlPlaneError::InvalidInput(
                    "new approval request must be pending and decision-free",
                ));
            }
            let owner: Option<String> =
                sqlx::query_scalar("SELECT repository_id FROM capsules WHERE id=$1")
                    .bind(capsule)
                    .fetch_optional(self.pool())
                    .await?;
            if owner.as_deref() != Some(repository) {
                return if owner.is_none() {
                    Err(not_found("capsule", capsule))
                } else {
                    Err(ControlPlaneError::InvalidInput(
                        "approval capsule does not belong to repository",
                    ))
                };
            }
            sqlx::query("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&request.id).bind(repository).bind(capsule).bind(request.subject_digest.as_str()).bind(approval_status_name(request.status)).bind(serde_json::to_vec(request)?).bind(postgres_i64(request.created_unix_ms,"approval creation")?).bind(postgres_i64(request.expires_unix_ms,"approval expiry")?).execute(self.pool()).await?;
            Ok(())
        })
    }
    fn approval_request<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ApprovalRequest> {
        Box::pin(async move {
            validate_text(id)?;
            let encoded: Vec<u8> =
                sqlx::query_scalar("SELECT request_json FROM approval_requests WHERE id=$1")
                    .bind(id)
                    .fetch_optional(self.pool())
                    .await?
                    .ok_or_else(|| not_found("approval", id))?;
            Ok(serde_json::from_slice(&encoded)?)
        })
    }
    fn approval_requests_for_capsule<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        Box::pin(async move {
            validate_text(id)?;
            let rows=sqlx::query("SELECT request_json FROM approval_requests WHERE capsule_id=$1 ORDER BY id LIMIT 33").bind(id).fetch_all(self.pool()).await?;
            if rows.len() > 32 {
                return Err(ControlPlaneError::CorruptState(
                    "capsule has too many durable approval requests".to_owned(),
                ));
            }
            rows.iter()
                .map(|r| {
                    serde_json::from_slice(&r.try_get::<Vec<u8>, _>("request_json")?)
                        .map_err(Into::into)
                })
                .collect()
        })
    }
    fn decide_approval<'a>(
        &'a self,
        id: &'a str,
        decision: ApprovalDecision,
        now: u64,
    ) -> StoreFuture<'a, ApprovalRequest> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let mut request = approval_tx_pg(&mut tx, id, true).await?;
            request.refresh_expiry(now);
            if request.status == runtrue_policy::ApprovalStatus::Expired {
                update_approval_pg(&mut tx, &request).await?;
                tx.commit().await?;
                return Err(runtrue_policy::PolicyError::RequestNotPending(
                    runtrue_policy::ApprovalStatus::Expired,
                )
                .into());
            }
            request.decide(decision.clone(), now)?;
            sqlx::query("INSERT INTO approval_decisions(approval_id,actor_id,decision_json,decided_unix_ms) VALUES($1,$2,$3,$4)").bind(id).bind(&decision.actor_id).bind(serde_json::to_vec(&decision)?).bind(postgres_i64(decision.decided_unix_ms,"approval decision")?).execute(&mut *tx).await?;
            update_approval_pg(&mut tx, &request).await?;
            tx.commit().await?;
            Ok(request)
        })
    }
    fn decide_approval_idempotent<'a>(
        &'a self,
        key: &'a str,
        id: &'a str,
        decision: ApprovalDecision,
        now: u64,
    ) -> StoreFuture<'a, IdempotentResult<ApprovalRequest>> {
        Box::pin(async move {
            validate_idempotency_key(key)?;
            validate_text(id)?;
            #[derive(Serialize)]
            struct Subject<'a> {
                approval_id: &'a str,
                actor_id: &'a str,
                decision: runtrue_policy::Decision,
                reason: &'a str,
                rule_id: &'a str,
                subject_digest: &'a ContentDigest,
            }
            let hash = ContentDigest::sha256(serde_json::to_vec(&Subject {
                approval_id: id,
                actor_id: &decision.actor_id,
                decision: decision.decision,
                reason: &decision.reason,
                rule_id: &decision.rule_id,
                subject_digest: &decision.subject_digest,
            })?);
            let operation = format!("approval.decide:{id}");
            let mut tx = self.pool().begin().await?;
            if let Some(row)=sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation=$1 AND idempotency_key=$2").bind(&operation).bind(key).fetch_optional(&mut *tx).await?{if row.try_get::<String,_>("request_hash")?!=hash.as_str(){return Err(ControlPlaneError::IdempotencyConflict)}let resource:String=row.try_get("resource_id")?;let value=approval_tx_pg(&mut tx,&resource,false).await?;tx.commit().await?;return Ok(IdempotentResult{value,replayed:true})}
            let mut request = approval_tx_pg(&mut tx, id, true).await?;
            request.refresh_expiry(now);
            if request.status == runtrue_policy::ApprovalStatus::Expired {
                update_approval_pg(&mut tx, &request).await?;
                tx.commit().await?;
                return Err(runtrue_policy::PolicyError::RequestNotPending(
                    runtrue_policy::ApprovalStatus::Expired,
                )
                .into());
            }
            request.decide(decision.clone(), now)?;
            sqlx::query("INSERT INTO approval_decisions(approval_id,actor_id,decision_json,decided_unix_ms) VALUES($1,$2,$3,$4)").bind(id).bind(&decision.actor_id).bind(serde_json::to_vec(&decision)?).bind(postgres_i64(decision.decided_unix_ms,"approval decision")?).execute(&mut *tx).await?;
            update_approval_pg(&mut tx, &request).await?;
            enqueue_approval_continuations_pg(&mut tx, id, &decision, now).await?;
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)").bind(&operation).bind(key).bind(hash.as_str()).bind(id).bind(postgres_i64(now,"approval decision idempotency")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: request,
                replayed: false,
            })
        })
    }
    fn authorize_approval<'a>(
        &'a self,
        id: &'a str,
        subject: &'a ContentDigest,
        now: u64,
    ) -> StoreFuture<'a, ApprovalRequest> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let mut request = approval_tx_pg(&mut tx, id, true).await?;
            request.refresh_expiry(now);
            if request.status == runtrue_policy::ApprovalStatus::Expired {
                update_approval_pg(&mut tx, &request).await?;
                tx.commit().await?;
                return Err(runtrue_policy::PolicyError::NotAuthorized(
                    runtrue_policy::ApprovalStatus::Expired,
                )
                .into());
            }
            request.authorize(subject, now)?;
            update_approval_pg(&mut tx, &request).await?;
            tx.commit().await?;
            Ok(request)
        })
    }
    fn list_approval_requests_page<'a>(
        &'a self,
        status: Option<&'a str>,
        after: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        Box::pin(async move {
            if limit == 0 || limit > 100 {
                return Err(ControlPlaneError::InvalidInput(
                    "page limit must be between one and one hundred",
                ));
            }
            if let Some(v) = status {
                validate_text(v)?
            }
            if let Some(v) = after {
                validate_text(v)?
            }
            let rows=sqlx::query("SELECT request_json FROM approval_requests WHERE ($1='' OR status=$1) AND id>$2 ORDER BY id LIMIT $3").bind(status.unwrap_or("")).bind(after.unwrap_or("")).bind(i64::try_from(limit).map_err(|_|ControlPlaneError::InvalidInput("page limit is out of range"))?).fetch_all(self.pool()).await?;
            rows.iter()
                .map(|r| {
                    serde_json::from_slice(&r.try_get::<Vec<u8>, _>("request_json")?)
                        .map_err(Into::into)
                })
                .collect()
        })
    }
    fn list_approval_requests_page_for_tenant<'a>(
        &'a self,
        tenant: &'a str,
        status: Option<&'a str>,
        after: Option<&'a str>,
        limit: usize,
    ) -> StoreFuture<'a, Vec<ApprovalRequest>> {
        Box::pin(async move {
            validate_text(tenant)?;
            if limit == 0 || limit > 100 {
                return Err(ControlPlaneError::InvalidInput(
                    "page limit must be between one and one hundred",
                ));
            }
            if let Some(v) = status {
                validate_text(v)?
            }
            if let Some(v) = after {
                validate_text(v)?
            }
            let rows=sqlx::query("SELECT a.request_json FROM approval_requests a JOIN repositories r ON r.id=a.repository_id WHERE r.tenant_id=$1 AND ($2='' OR a.status=$2) AND a.id>$3 ORDER BY a.id LIMIT $4").bind(tenant).bind(status.unwrap_or("")).bind(after.unwrap_or("")).bind(i64::try_from(limit).map_err(|_|ControlPlaneError::InvalidInput("page limit is out of range"))?).fetch_all(self.pool()).await?;
            rows.iter()
                .map(|r| {
                    serde_json::from_slice(&r.try_get::<Vec<u8>, _>("request_json")?)
                        .map_err(Into::into)
                })
                .collect()
        })
    }
    fn approval_request_tenant<'a>(&'a self, id: &'a str) -> StoreFuture<'a, String> {
        Box::pin(async move {
            validate_text(id)?;
            sqlx::query_scalar("SELECT r.tenant_id FROM approval_requests a JOIN repositories r ON r.id=a.repository_id WHERE a.id=$1").bind(id).fetch_optional(self.pool()).await?.ok_or_else(||not_found("approval",id))
        })
    }
    fn approval_request_binding<'a>(&'a self, id: &'a str) -> StoreFuture<'a, (String, String)> {
        Box::pin(async move {
            validate_text(id)?;
            let row =
                sqlx::query("SELECT repository_id,capsule_id FROM approval_requests WHERE id=$1")
                    .bind(id)
                    .fetch_optional(self.pool())
                    .await?
                    .ok_or_else(|| not_found("approval", id))?;
            Ok((row.try_get("repository_id")?, row.try_get("capsule_id")?))
        })
    }
    fn approval_pending_execution_count<'a>(&'a self, id: &'a str) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            validate_text(id)?;
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM scm_pending_executions
                 WHERE state IN ('awaiting-approval','continuation-pending')
                   AND (workflow_approval_id=$1 OR privileged_approval_id=$1)",
            )
            .bind(id)
            .fetch_one(self.pool())
            .await?;
            postgres_u64(count, "approval pending execution count")
        })
    }
    fn approval_pending_execution_events<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, Vec<serde_json::Value>> {
        Box::pin(async move {
            validate_text(id)?;
            let rows = sqlx::query(
                "SELECT context_json FROM scm_pending_executions
                 WHERE state IN ('awaiting-approval','continuation-pending')
                   AND (workflow_approval_id=$1 OR privileged_approval_id=$1)
                 ORDER BY created_unix_ms,id LIMIT 100",
            )
            .bind(id)
            .fetch_all(self.pool())
            .await?;
            rows.into_iter()
                .map(|row| {
                    let context_json: Vec<u8> = row.try_get("context_json")?;
                    let context: crate::ScmContinuationContext =
                        serde_json::from_slice(&context_json)?;
                    Ok(context.event)
                })
                .collect()
        })
    }
}

#[cfg(feature = "postgres")]
fn snapshot_row(row: &sqlx::postgres::PgRow) -> Result<SourceSnapshotRecord, ControlPlaneError> {
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "building" => SourceSnapshotState::Building,
        "ready" => SourceSnapshotState::Ready,
        "failed" => SourceSnapshotState::Failed,
        "retired" => SourceSnapshotState::Retired,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "unknown source snapshot state `{other}`"
            )))
        }
    };
    Ok(SourceSnapshotRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        commit_sha: row.try_get("commit_sha")?,
        tree_manifest_digest: ContentDigest::parse(
            row.try_get::<String, _>("tree_manifest_digest")?,
        )?,
        state,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "source snapshot creation")?,
        verified_unix_ms: row
            .try_get::<Option<i64>, _>("verified_unix_ms")?
            .map(|v| postgres_u64(v, "source snapshot verification"))
            .transpose()?,
    })
}

#[cfg(feature = "postgres")]
fn run_snapshot_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RunSourceSnapshotRecord, ControlPlaneError> {
    Ok(RunSourceSnapshotRecord {
        run_id: row.try_get("run_id")?,
        source_snapshot_id: row.try_get("source_snapshot_id")?,
        capsule_digest: ContentDigest::parse(row.try_get::<String, _>("capsule_digest")?)?,
        bound_unix_ms: postgres_u64(row.try_get("bound_unix_ms")?, "source snapshot binding")?,
    })
}

#[cfg(feature = "postgres")]
fn source_ticket_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RunnerSourceTicketRecord, ControlPlaneError> {
    Ok(RunnerSourceTicketRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        runner_id: row.try_get("runner_id")?,
        execution_lease_id: row.try_get("execution_lease_id")?,
        fencing_generation: postgres_u64(
            row.try_get("fencing_generation")?,
            "source ticket fence",
        )?,
        job_id: row.try_get("job_id")?,
        job_attempt: u32::try_from(row.try_get::<i32, _>("job_attempt")?).map_err(|_| {
            ControlPlaneError::IntegerRange {
                field: "source ticket job attempt",
            }
        })?,
        source_snapshot_id: row.try_get("source_snapshot_id")?,
        tree_manifest_digest: ContentDigest::parse(
            row.try_get::<String, _>("tree_manifest_digest")?,
        )?,
        maximum_bytes: postgres_u64(row.try_get("maximum_bytes")?, "source ticket maximum")?,
        issued_unix_ms: postgres_u64(row.try_get("issued_unix_ms")?, "source ticket issue")?,
        expires_unix_ms: postgres_u64(row.try_get("expires_unix_ms")?, "source ticket expiry")?,
    })
}

#[cfg(feature = "postgres")]
async fn validate_source_lease_pg(
    tx: &mut Transaction<'_, Postgres>,
    lease_id: &str,
    runner_id: &str,
    generation: u64,
    now: u64,
) -> Result<String, ControlPlaneError> {
    let state =
        sqlx::query("SELECT fencing_epoch,safe_mode FROM installation_state WHERE singleton=TRUE")
            .fetch_one(&mut **tx)
            .await?;
    let epoch: i64 = state.try_get("fencing_epoch")?;
    let safe: bool = state.try_get("safe_mode")?;
    let lease=sqlx::query("SELECT job_id,runner_id,fencing_generation,installation_fencing_epoch,state,issued_unix_ms,expires_unix_ms,hard_deadline_unix_ms FROM leases WHERE id=$1 FOR UPDATE").bind(lease_id).fetch_optional(&mut **tx).await?.ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
    if safe
        || lease.try_get::<String, _>("runner_id")? != runner_id
        || lease.try_get::<i64, _>("fencing_generation")?
            != postgres_i64(generation, "source lease fence")?
        || lease.try_get::<i64, _>("installation_fencing_epoch")? != epoch
        || lease.try_get::<String, _>("state")? != "active"
        || now < postgres_u64(lease.try_get("issued_unix_ms")?, "lease issue")?
        || now >= postgres_u64(lease.try_get("expires_unix_ms")?, "lease expiry")?
        || now >= postgres_u64(lease.try_get("hard_deadline_unix_ms")?, "lease deadline")?
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(lease.try_get("job_id")?)
}

#[cfg(feature = "postgres")]
impl SourceSnapshotStore for PostgresInstallationStore {
    fn create_source_snapshot<'a>(
        &'a self,
        s: &'a SourceSnapshotRecord,
    ) -> StoreFuture<'a, IdempotentResult<SourceSnapshotRecord>> {
        Box::pin(async move {
            for v in [&s.id, &s.tenant_id, &s.repository_id, &s.commit_sha] {
                validate_text(v)?
            }
            if s.state != SourceSnapshotState::Building || s.verified_unix_ms.is_some() {
                return Err(ControlPlaneError::InvalidInput(
                    "new source snapshot must be building",
                ));
            }
            let mut tx = self.pool().begin().await?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1 AND tenant_id=$2)",
            )
            .bind(&s.repository_id)
            .bind(&s.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
            if !exists {
                return Err(not_found("repository", &s.repository_id));
            }
            let inserted=sqlx::query("INSERT INTO source_snapshots(id,tenant_id,repository_id,commit_sha,tree_manifest_digest,state,created_unix_ms,verified_unix_ms) VALUES($1,$2,$3,$4,$5,'building',$6,NULL) ON CONFLICT DO NOTHING").bind(&s.id).bind(&s.tenant_id).bind(&s.repository_id).bind(&s.commit_sha).bind(s.tree_manifest_digest.as_str()).bind(postgres_i64(s.created_unix_ms,"source snapshot creation")?).execute(&mut *tx).await?.rows_affected();
            let row = sqlx::query("SELECT * FROM source_snapshots WHERE id=$1 AND tenant_id=$2")
                .bind(&s.id)
                .bind(&s.tenant_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| not_found("source snapshot", &s.id))?;
            let value = snapshot_row(&row)?;
            if value != *s {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: inserted == 0,
            })
        })
    }
    fn source_snapshot<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, SourceSnapshotRecord> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM source_snapshots WHERE id=$1 AND tenant_id=$2")
                .bind(id)
                .bind(t)
                .fetch_optional(self.pool())
                .await?
                .ok_or_else(|| not_found("source snapshot", id))?;
            snapshot_row(&row)
        })
    }
    fn mark_source_snapshot_ready<'a>(
        &'a self,
        t: &'a str,
        id: &'a str,
        d: &'a ContentDigest,
        n: u64,
    ) -> StoreFuture<'a, SourceSnapshotRecord> {
        Box::pin(async move {
            validate_text(t)?;
            validate_text(id)?;
            let mut tx = self.pool().begin().await?;
            let row = sqlx::query(
                "SELECT * FROM source_snapshots WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
            )
            .bind(id)
            .bind(t)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| not_found("source snapshot", id))?;
            let current = snapshot_row(&row)?;
            if current.tree_manifest_digest != *d {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            match current.state {
                SourceSnapshotState::Building => {
                    sqlx::query("UPDATE source_snapshots SET state='ready',verified_unix_ms=$3 WHERE id=$1 AND tenant_id=$2 AND state='building'").bind(id).bind(t).bind(postgres_i64(n,"source snapshot verification")?).execute(&mut *tx).await?;
                }
                SourceSnapshotState::Ready if current.verified_unix_ms == Some(n) => {}
                _ => return Err(ControlPlaneError::IdempotencyConflict),
            }
            let row = sqlx::query("SELECT * FROM source_snapshots WHERE id=$1 AND tenant_id=$2")
                .bind(id)
                .bind(t)
                .fetch_one(&mut *tx)
                .await?;
            let value = snapshot_row(&row)?;
            tx.commit().await?;
            Ok(value)
        })
    }
    fn bind_run_source_snapshot<'a>(
        &'a self,
        t: &'a str,
        run: &'a str,
        snapshot: &'a str,
        digest: &'a ContentDigest,
        n: u64,
    ) -> StoreFuture<'a, IdempotentResult<RunSourceSnapshotRecord>> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let row=sqlx::query("SELECT c.canonical_capsule,s.tree_manifest_digest,s.commit_sha FROM runs r JOIN repositories repo ON repo.id=r.repository_id JOIN capsules c ON c.id=r.capsule_id JOIN source_snapshots s ON s.id=$3 WHERE r.id=$1 AND repo.tenant_id=$2 AND s.tenant_id=$2 AND s.repository_id=r.repository_id AND s.state='ready' AND c.digest=$4").bind(run).bind(t).bind(snapshot).bind(digest.as_str()).fetch_optional(&mut *tx).await?.ok_or_else(||not_found("ready run source snapshot",snapshot))?;
            let capsule: runtrue_workflow_ir::ExecutionCapsule =
                serde_json::from_slice(&row.try_get::<Vec<u8>, _>("canonical_capsule")?)?;
            if capsule
                .context
                .source_tree_digest
                .as_ref()
                .map(ContentDigest::as_str)
                != Some(row.try_get::<String, _>("tree_manifest_digest")?.as_str())
                || capsule.context.source_commit != row.try_get::<String, _>("commit_sha")?
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let inserted=sqlx::query("INSERT INTO run_source_snapshots(run_id,source_snapshot_id,capsule_digest,bound_unix_ms) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(run).bind(snapshot).bind(digest.as_str()).bind(postgres_i64(n,"source snapshot binding")?).execute(&mut *tx).await?.rows_affected();
            let row = sqlx::query("SELECT * FROM run_source_snapshots WHERE run_id=$1")
                .bind(run)
                .fetch_one(&mut *tx)
                .await?;
            let value = run_snapshot_row(&row)?;
            if value.source_snapshot_id != snapshot || value.capsule_digest != *digest {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            for planned in capsule
                .jobs
                .iter()
                .filter(|j| j.needs.is_empty() && capsule.context.source_trust.satisfies(j.trust))
            {
                sqlx::query("UPDATE jobs SET status='queued' WHERE run_id=$1 AND job_key=$2 AND status='created'").bind(run).bind(&planned.id).execute(&mut *tx).await?;
            }
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: inserted == 0,
            })
        })
    }
    fn run_source_snapshot<'a>(
        &'a self,
        t: &'a str,
        run: &'a str,
    ) -> StoreFuture<'a, RunSourceSnapshotRecord> {
        Box::pin(async move {
            let row=sqlx::query("SELECT rss.* FROM run_source_snapshots rss JOIN runs r ON r.id=rss.run_id JOIN repositories repo ON repo.id=r.repository_id WHERE rss.run_id=$1 AND repo.tenant_id=$2").bind(run).bind(t).fetch_optional(self.pool()).await?.ok_or_else(||not_found("run source snapshot",run))?;
            run_snapshot_row(&row)
        })
    }
    fn issue_runner_source_ticket<'a>(
        &'a self,
        r: &'a IssueRunnerSourceTicket,
    ) -> StoreFuture<'a, IdempotentResult<RunnerSourceTicketRecord>> {
        Box::pin(async move {
            if r.maximum_bytes == 0 || r.expires_unix_ms <= r.issued_unix_ms {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid source ticket bounds",
                ));
            }
            let mut tx = self.pool().begin().await?;
            if validate_source_lease_pg(
                &mut tx,
                &r.execution_lease_id,
                &r.runner_id,
                r.fencing_generation,
                r.issued_unix_ms,
            )
            .await?
                != r.job_id
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let row=sqlx::query("SELECT rss.source_snapshot_id,s.tree_manifest_digest FROM jobs j JOIN runs run ON run.id=j.run_id JOIN repositories repo ON repo.id=run.repository_id JOIN run_source_snapshots rss ON rss.run_id=run.id JOIN source_snapshots s ON s.id=rss.source_snapshot_id WHERE j.id=$1 AND j.attempt=$2 AND repo.tenant_id=$3 AND s.tenant_id=$3 AND s.state='ready'").bind(&r.job_id).bind(i32::try_from(r.job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"source ticket job attempt"})?).bind(&r.tenant_id).fetch_optional(&mut *tx).await?.ok_or_else(||not_found("ready run source snapshot",&r.job_id))?;
            let snapshot: String = row.try_get("source_snapshot_id")?;
            let tree: String = row.try_get("tree_manifest_digest")?;
            let inserted=sqlx::query("INSERT INTO runner_source_tickets(id,tenant_id,runner_id,execution_lease_id,fencing_generation,job_id,job_attempt,source_snapshot_id,tree_manifest_digest,maximum_bytes,issued_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING").bind(&r.id).bind(&r.tenant_id).bind(&r.runner_id).bind(&r.execution_lease_id).bind(postgres_i64(r.fencing_generation,"source ticket fence")?).bind(&r.job_id).bind(i32::try_from(r.job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"source ticket job attempt"})?).bind(&snapshot).bind(&tree).bind(postgres_i64(r.maximum_bytes,"source ticket maximum")?).bind(postgres_i64(r.issued_unix_ms,"source ticket issue")?).bind(postgres_i64(r.expires_unix_ms,"source ticket expiry")?).execute(&mut *tx).await?.rows_affected();
            let row = sqlx::query("SELECT * FROM runner_source_tickets WHERE id=$1")
                .bind(&r.id)
                .fetch_one(&mut *tx)
                .await?;
            let value = source_ticket_row(&row)?;
            let expected = RunnerSourceTicketRecord {
                id: r.id.clone(),
                tenant_id: r.tenant_id.clone(),
                runner_id: r.runner_id.clone(),
                execution_lease_id: r.execution_lease_id.clone(),
                fencing_generation: r.fencing_generation,
                job_id: r.job_id.clone(),
                job_attempt: r.job_attempt,
                source_snapshot_id: snapshot,
                tree_manifest_digest: ContentDigest::parse(tree)?,
                maximum_bytes: r.maximum_bytes,
                issued_unix_ms: r.issued_unix_ms,
                expires_unix_ms: r.expires_unix_ms,
            };
            if value != expected {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            tx.commit().await?;
            Ok(IdempotentResult {
                value,
                replayed: inserted == 0,
            })
        })
    }
    fn runner_source_ticket<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, RunnerSourceTicketRecord> {
        Box::pin(async move {
            validate_text(id)?;
            let row = sqlx::query("SELECT * FROM runner_source_tickets WHERE id=$1")
                .bind(id)
                .fetch_optional(self.pool())
                .await?
                .ok_or_else(|| not_found("runner source ticket", id))?;
            source_ticket_row(&row)
        })
    }
    fn begin_runner_source_download<'a>(
        &'a self,
        r: &'a RunnerSourceDownload,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            if r.job_attempt == 0 || r.fencing_generation == 0 {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let mut tx = self.pool().begin().await?;
            validate_source_lease_pg(
                &mut tx,
                &r.execution_lease_id,
                &r.runner_id,
                r.fencing_generation,
                r.recorded_unix_ms,
            )
            .await?;
            let row = sqlx::query("SELECT * FROM runner_source_tickets WHERE id=$1")
                .bind(&r.ticket_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| not_found("runner source ticket", &r.ticket_id))?;
            let ticket = source_ticket_row(&row)?;
            if ticket.runner_id != r.runner_id
                || ticket.execution_lease_id != r.execution_lease_id
                || ticket.fencing_generation != r.fencing_generation
                || ticket.job_id != r.job_id
                || ticket.job_attempt != r.job_attempt
                || ticket.expires_unix_ms <= r.recorded_unix_ms
                || r.size_bytes > ticket.maximum_bytes
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            if let Some(row)=sqlx::query("SELECT expected_size_bytes,maximum_ticket_bytes,state FROM runner_object_transfers WHERE ticket_id=$1 AND object_digest=$2 AND direction='download'").bind(&r.ticket_id).bind(r.object_digest.as_str()).fetch_optional(&mut *tx).await?{if postgres_u64(row.try_get("expected_size_bytes")?,"source object size")?!=r.size_bytes||postgres_u64(row.try_get("maximum_ticket_bytes")?,"source ticket maximum")?!=ticket.maximum_bytes{return Err(ControlPlaneError::RunnerBrokerBindingMismatch)}let state:String=row.try_get("state")?;sqlx::query("UPDATE runner_object_transfers SET state='transferring',updated_unix_ms=$3,transferred_size_bytes=0,verified_unix_ms=NULL WHERE ticket_id=$1 AND object_digest=$2 AND direction='download' AND state!='verified'").bind(&r.ticket_id).bind(r.object_digest.as_str()).bind(postgres_i64(r.recorded_unix_ms,"source transfer update")?).execute(&mut *tx).await?;tx.commit().await?;return Ok(state=="verified")}
            let reserved:i64=sqlx::query_scalar("SELECT COALESCE(SUM(expected_size_bytes),0)::BIGINT FROM runner_object_transfers WHERE ticket_id=$1 AND direction='download'").bind(&r.ticket_id).fetch_one(&mut *tx).await?;
            if postgres_u64(reserved, "source reserved bytes")?
                .checked_add(r.size_bytes)
                .is_none_or(|sum| sum > ticket.maximum_bytes)
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            sqlx::query("INSERT INTO runner_object_transfers(ticket_id,object_digest,ticket_kind,direction,execution_lease_id,fencing_generation,job_attempt,expected_size_bytes,transferred_size_bytes,maximum_ticket_bytes,state,reserved_unix_ms,updated_unix_ms,verified_unix_ms) VALUES($1,$2,'source','download',$3,$4,$5,$6,0,$7,'transferring',$8,$8,NULL)").bind(&r.ticket_id).bind(r.object_digest.as_str()).bind(&r.execution_lease_id).bind(postgres_i64(r.fencing_generation,"source transfer fence")?).bind(i32::try_from(r.job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"source transfer job attempt"})?).bind(postgres_i64(r.size_bytes,"source transfer size")?).bind(postgres_i64(ticket.maximum_bytes,"source ticket maximum")?).bind(postgres_i64(r.recorded_unix_ms,"source transfer reservation")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(false)
        })
    }
    fn finish_runner_source_download<'a>(
        &'a self,
        r: &'a RunnerSourceDownload,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            validate_source_lease_pg(
                &mut tx,
                &r.execution_lease_id,
                &r.runner_id,
                r.fencing_generation,
                r.recorded_unix_ms,
            )
            .await?;
            let changed=sqlx::query("UPDATE runner_object_transfers SET state='verified',transferred_size_bytes=$3,updated_unix_ms=$4,verified_unix_ms=$4 WHERE ticket_id=$1 AND object_digest=$2 AND direction='download' AND ticket_kind='source' AND expected_size_bytes=$3 AND execution_lease_id=$5 AND fencing_generation=$6 AND job_attempt=$7 AND state IN('transferring','verified')").bind(&r.ticket_id).bind(r.object_digest.as_str()).bind(postgres_i64(r.size_bytes,"source transfer size")?).bind(postgres_i64(r.recorded_unix_ms,"source transfer completion")?).bind(&r.execution_lease_id).bind(postgres_i64(r.fencing_generation,"source transfer fence")?).bind(i32::try_from(r.job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"source transfer job attempt"})?).execute(&mut *tx).await?.rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            tx.commit().await?;
            Ok(())
        })
    }
}

#[cfg(feature = "postgres")]
fn schedule_row(row: &sqlx::postgres::PgRow) -> Result<ScheduleTriggerCursor, ControlPlaneError> {
    Ok(ScheduleTriggerCursor {
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        workflow_identity: row.try_get("workflow_identity")?,
        schedule_key: row.try_get("schedule_key")?,
        cron_utc: row.try_get("cron_utc")?,
        catch_up_policy: row.try_get("catch_up_policy")?,
        maximum_catch_up: u64::try_from(row.try_get::<i32, _>("maximum_catch_up")?).map_err(
            |_| ControlPlaneError::IntegerRange {
                field: "maximum catch up",
            },
        )?,
        next_fire_unix_ms: postgres_u64(row.try_get("next_fire_unix_ms")?, "next fire")?,
        last_fire_unix_ms: row
            .try_get::<Option<i64>, _>("last_fire_unix_ms")?
            .map(|v| postgres_u64(v, "last fire"))
            .transpose()?,
        version: postgres_u64(row.try_get("version")?, "schedule version")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "schedule update")?,
    })
}

#[cfg(feature = "postgres")]
fn validate_cron_pg(value: &str) -> Result<(), ControlPlaneError> {
    if value.len() > 128 {
        return Err(ControlPlaneError::InvalidInput("UTC cron is too long"));
    }
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    let ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];
    if fields.len() != ranges.len()
        || fields
            .iter()
            .zip(ranges)
            .any(|(field, (minimum, maximum))| !valid_cron_field_pg(field, minimum, maximum))
    {
        return Err(ControlPlaneError::InvalidInput(
            "schedule cron must be a five-field UTC numeric expression",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn valid_cron_field_pg(field: &str, minimum: u32, maximum: u32) -> bool {
    if field.is_empty() {
        return false;
    }
    field.split(',').all(|part| {
        let mut stepped = part.split('/');
        let base = stepped.next().unwrap_or_default();
        let step = stepped.next();
        if stepped.next().is_some()
            || step.is_some_and(|step| {
                step.parse::<u32>()
                    .map_or(true, |step| step == 0 || step > maximum)
            })
        {
            return false;
        }
        if base == "*" {
            return true;
        }
        if let Some((start, end)) = base.split_once('-') {
            return start.parse::<u32>().is_ok_and(|value| value >= minimum)
                && end.parse::<u32>().is_ok_and(|value| value <= maximum)
                && start.parse::<u32>().unwrap_or(maximum)
                    <= end.parse::<u32>().unwrap_or(minimum);
        }
        base.parse::<u32>()
            .is_ok_and(|value| (minimum..=maximum).contains(&value))
    })
}

#[cfg(feature = "postgres")]
fn cron_field_matches_pg(field: &str, value: u32, minimum: u32, maximum: u32) -> bool {
    field.split(',').any(|part| {
        let (base, step) = part.split_once('/').map_or((part, 1), |(base, step)| {
            (
                base,
                step.parse::<u32>().unwrap_or(maximum.saturating_add(1)),
            )
        });
        let (start, end) = if base == "*" {
            (minimum, maximum)
        } else if let Some((start, end)) = base.split_once('-') {
            (
                start.parse::<u32>().unwrap_or(maximum.saturating_add(1)),
                end.parse::<u32>().unwrap_or(minimum.saturating_sub(1)),
            )
        } else {
            let exact = base.parse::<u32>().unwrap_or(maximum.saturating_add(1));
            (exact, exact)
        };
        value >= start && value <= end && value.saturating_sub(start).is_multiple_of(step)
    })
}

#[cfg(feature = "postgres")]
fn civil_date_from_unix_days_pg(days: u64) -> Result<(u32, u32), ControlPlaneError> {
    let days = i64::try_from(days).map_err(|_| ControlPlaneError::IntegerRange {
        field: "UTC schedule day",
    })?;
    let shifted = days
        .checked_add(719_468)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "UTC civil date",
        })?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let _year = year + i64::from(month <= 2);
    Ok((
        u32::try_from(month).map_err(|_| ControlPlaneError::IntegerRange { field: "UTC month" })?,
        u32::try_from(day).map_err(|_| ControlPlaneError::IntegerRange { field: "UTC day" })?,
    ))
}

#[cfg(feature = "postgres")]
fn cron_matches_unix_ms_pg(value: &str, unix_ms: u64) -> Result<bool, ControlPlaneError> {
    validate_cron_pg(value)?;
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    let seconds = unix_ms / 1_000;
    let minute =
        u32::try_from((seconds / 60) % 60).map_err(|_| ControlPlaneError::IntegerRange {
            field: "UTC minute",
        })?;
    let hour = u32::try_from((seconds / 3_600) % 24)
        .map_err(|_| ControlPlaneError::IntegerRange { field: "UTC hour" })?;
    let days = seconds / 86_400;
    let (month, day) = civil_date_from_unix_days_pg(days)?;
    let weekday = u32::try_from((days + 4) % 7).map_err(|_| ControlPlaneError::IntegerRange {
        field: "UTC weekday",
    })?;
    let day_of_month = cron_field_matches_pg(fields[2], day, 1, 31);
    let day_of_week = cron_field_matches_pg(fields[4], weekday, 0, 6);
    let day_matches = match (fields[2] == "*", fields[4] == "*") {
        (true, true) => true,
        (true, false) => day_of_week,
        (false, true) => day_of_month,
        (false, false) => day_of_month || day_of_week,
    };
    Ok(cron_field_matches_pg(fields[0], minute, 0, 59)
        && cron_field_matches_pg(fields[1], hour, 0, 23)
        && day_matches
        && cron_field_matches_pg(fields[3], month, 1, 12))
}

#[cfg(feature = "postgres")]
fn next_fire_pg(cron: &str, after: u64) -> Result<u64, ControlPlaneError> {
    const MAX_CRON_SEARCH_MINUTES: u64 = 366 * 24 * 60;
    let first_minute = after
        .checked_div(60_000)
        .and_then(|minute| minute.checked_add(1))
        .ok_or(ControlPlaneError::IntegerRange {
            field: "next UTC schedule minute",
        })?;
    for offset in 0..MAX_CRON_SEARCH_MINUTES {
        let candidate = first_minute
            .checked_add(offset)
            .and_then(|minute| minute.checked_mul(60_000))
            .ok_or(ControlPlaneError::IntegerRange {
                field: "next UTC schedule fire",
            })?;
        if cron_matches_unix_ms_pg(cron, candidate)? {
            return Ok(candidate);
        }
    }
    Err(ControlPlaneError::InvalidInput(
        "UTC cron has no fire within the bounded search horizon",
    ))
}

#[cfg(feature = "postgres")]
fn previous_fire_pg(cron: &str, at: u64) -> Result<u64, ControlPlaneError> {
    const MAX_CRON_SEARCH_MINUTES: u64 = 366 * 24 * 60;
    let minute = at / 60_000;
    for offset in 0..MAX_CRON_SEARCH_MINUTES {
        let Some(candidate_minute) = minute.checked_sub(offset) else {
            break;
        };
        let candidate =
            candidate_minute
                .checked_mul(60_000)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "previous UTC schedule fire",
                })?;
        if cron_matches_unix_ms_pg(cron, candidate)? {
            return Ok(candidate);
        }
    }
    Err(ControlPlaneError::InvalidInput(
        "UTC cron has no prior fire within the bounded search horizon",
    ))
}

#[cfg(feature = "postgres")]
async fn persist_trigger_pg(
    tx: &mut Transaction<'_, Postgres>,
    record: &NormalizedTriggerEventRecord,
) -> Result<bool, ControlPlaneError> {
    for v in [
        &record.id,
        &record.tenant_id,
        &record.repository_id,
        &record.trigger_kind,
        &record.idempotency_identity,
        &record.actor_identity,
    ] {
        validate_text(v)?
    }
    if !matches!(
        record.trigger_kind.as_str(),
        "tag" | "schedule" | "manual" | "api" | "repository-dispatch" | "dependent-workflow"
    ) {
        return Err(ControlPlaneError::InvalidInput("unsupported trigger kind"));
    }
    let canonical = serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(
        record.normalized_envelope.clone(),
    ))?;
    if canonical.len() > 256 * 1024 || ContentDigest::sha256(&canonical) != record.normalized_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "normalized trigger envelope is oversized or has the wrong digest",
        ));
    }
    let inserted=sqlx::query("INSERT INTO normalized_trigger_events(id,tenant_id,repository_id,trigger_kind,idempotency_identity,normalized_digest,normalized_envelope_json,actor_identity,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,repository_id,trigger_kind,idempotency_identity) DO NOTHING").bind(&record.id).bind(&record.tenant_id).bind(&record.repository_id).bind(&record.trigger_kind).bind(&record.idempotency_identity).bind(record.normalized_digest.as_str()).bind(&canonical).bind(&record.actor_identity).bind(postgres_i64(record.created_unix_ms,"trigger creation")?).execute(&mut **tx).await?.rows_affected();
    if inserted == 1 {
        return Ok(false);
    }
    let row=sqlx::query("SELECT id,normalized_digest,normalized_envelope_json,actor_identity,created_unix_ms FROM normalized_trigger_events WHERE tenant_id=$1 AND repository_id=$2 AND trigger_kind=$3 AND idempotency_identity=$4").bind(&record.tenant_id).bind(&record.repository_id).bind(&record.trigger_kind).bind(&record.idempotency_identity).fetch_one(&mut **tx).await?;
    if row.try_get::<String, _>("id")? == record.id
        && row.try_get::<String, _>("normalized_digest")? == record.normalized_digest.as_str()
        && row.try_get::<Vec<u8>, _>("normalized_envelope_json")? == canonical
        && row.try_get::<String, _>("actor_identity")? == record.actor_identity
        && postgres_u64(row.try_get("created_unix_ms")?, "trigger creation")?
            == record.created_unix_ms
    {
        Ok(true)
    } else {
        Err(ControlPlaneError::IdempotencyConflict)
    }
}

#[cfg(feature = "postgres")]
async fn append_trigger_audit_pg(
    tx: &mut Transaction<'_, Postgres>,
    installation_id: &str,
    record: &NormalizedTriggerEventRecord,
) -> Result<(), ControlPlaneError> {
    super::api_tokens::append(
        tx,
        installation_id,
        AuditEventData {
            observed_unix_ms: record.created_unix_ms,
            tenant_id: record.tenant_id.clone(),
            actor: AuditPrincipal {
                kind: "trigger".to_owned(),
                id: record.actor_identity.clone(),
            },
            action: "workflow.trigger.normalize".to_owned(),
            resource: AuditResource {
                kind: "normalized-trigger".to_owned(),
                id: record.id.clone(),
            },
            result: "persisted".to_owned(),
            request_id: record.idempotency_identity.clone(),
            decision_id: None,
            metadata: BTreeMap::from([(
                "normalized_digest".to_owned(),
                AuditValue::Digest(record.normalized_digest.clone()),
            )]),
        },
    )
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn append_expansion_audit_pg(
    tx: &mut Transaction<'_, Postgres>,
    installation_id: &str,
    record: &ExpandedJobSetRecord,
) -> Result<(), ControlPlaneError> {
    super::api_tokens::append(
        tx,
        installation_id,
        AuditEventData {
            observed_unix_ms: record.created_unix_ms,
            tenant_id: record.tenant_id.clone(),
            actor: AuditPrincipal {
                kind: "worker".to_owned(),
                id: "workflow-expander".to_owned(),
            },
            action: "workflow.expand".to_owned(),
            resource: AuditResource {
                kind: "expanded-job-set".to_owned(),
                id: record.id.clone(),
            },
            result: "persisted".to_owned(),
            request_id: record.id.clone(),
            decision_id: Some(record.parent_capsule_digest.to_string()),
            metadata: BTreeMap::from([
                (
                    "job_set_digest".to_owned(),
                    AuditValue::Digest(record.job_set_digest.clone()),
                ),
                (
                    "matrix_input_digest".to_owned(),
                    AuditValue::Digest(record.matrix_input_digest.clone()),
                ),
                (
                    "generated_job_count".to_owned(),
                    AuditValue::Integer(postgres_i64(
                        record.generated_job_count,
                        "generated job count",
                    )?),
                ),
            ]),
        },
    )
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
fn schedule_trigger_pg(
    c: &ScheduleTriggerCursor,
    at: u64,
) -> Result<NormalizedTriggerEventRecord, ControlPlaneError> {
    let envelope = runtrue_workflow_ir::canonicalize_value(
        serde_json::json!({"cron_utc":c.cron_utc,"repository_id":c.repository_id,"schedule_key":c.schedule_key,"scheduled_unix_ms":at,"trigger_kind":"schedule","version":1,"workflow_identity":c.workflow_identity}),
    );
    let digest = ContentDigest::sha256(serde_json::to_vec(&envelope)?);
    let identity = format!("{}:{}:{}", c.workflow_identity, c.schedule_key, at);
    let mut h = Sha256::new();
    h.update(b"runtrue.normalized-schedule-trigger.v1\0");
    h.update(c.tenant_id.as_bytes());
    h.update([0]);
    h.update(c.repository_id.as_bytes());
    h.update([0]);
    h.update(identity.as_bytes());
    Ok(NormalizedTriggerEventRecord {
        id: format!("schedule-trigger-{}", hex::encode(h.finalize())),
        tenant_id: c.tenant_id.clone(),
        repository_id: c.repository_id.clone(),
        trigger_kind: "schedule".to_owned(),
        idempotency_identity: identity,
        normalized_digest: digest,
        normalized_envelope: envelope,
        actor_identity: "schedule-reconciler".to_owned(),
        created_unix_ms: at,
    })
}

#[cfg(feature = "postgres")]
async fn validate_expansion_pg(
    tx: &mut Transaction<'_, Postgres>,
    r: &ExpandedJobSetRecord,
    key: &CapsuleVerifyingKey,
) -> Result<
    (
        runtrue_workflow_ir::ExpandedJobSet,
        runtrue_workflow_ir::ExecutionCapsule,
        runtrue_workflow_ir::DynamicJobTemplate,
    ),
    ControlPlaneError,
> {
    for value in [
        &r.id,
        &r.tenant_id,
        &r.repository_id,
        &r.run_id,
        &r.template_id,
        &r.producer_job_id,
        &r.producer_output_name,
        &r.signing_key_id,
    ] {
        validate_text(value)?;
    }
    if r.generated_job_count == 0
        || r.generated_job_count > 1024
        || r.canonical_job_set.is_empty()
        || r.canonical_job_set.len() > 8 * 1024 * 1024
        || r.signature.len() != 64
    {
        return Err(ControlPlaneError::InvalidInput(
            "expanded job set exceeds its signed resource bounds",
        ));
    }
    let set: runtrue_workflow_ir::ExpandedJobSet = serde_json::from_slice(&r.canonical_job_set)?;
    if set.canonical_bytes()? != r.canonical_job_set {
        return Err(ControlPlaneError::InvalidInput(
            "expanded job set is not canonical",
        ));
    }
    if ContentDigest::sha256(&r.canonical_job_set) != r.job_set_digest
        || set.parent_capsule_digest != r.parent_capsule_digest
        || set.producer_job_id != r.producer_job_id
        || set.producer_output_name != r.producer_output_name
        || set.matrix_input_digest != r.matrix_input_digest
        || set.policy_epoch != r.policy_epoch
        || u64::try_from(set.jobs.len()).unwrap_or(u64::MAX) != r.generated_job_count
        || set
            .generated_job_ids
            .iter()
            .ne(set.jobs.iter().map(|j| &j.id))
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let signature = runtrue_attest::ExpandedJobSetSignature {
        signature_version: 1,
        algorithm: runtrue_attest::CAPSULE_SIGNATURE_ALGORITHM.to_owned(),
        key_id: ContentDigest::parse(&r.signing_key_id)?,
        job_set_digest: r.job_set_digest.clone(),
        signature: r.signature.clone(),
    };
    key.verify_expanded_job_set(&set, &signature)?;
    let bytes:Vec<u8>=sqlx::query_scalar("SELECT c.canonical_capsule FROM runs run JOIN repositories repo ON repo.id=run.repository_id JOIN capsules c ON c.id=run.capsule_id WHERE run.id=$1 AND run.repository_id=$2 AND repo.tenant_id=$3 AND c.digest=$4").bind(&r.run_id).bind(&r.repository_id).bind(&r.tenant_id).bind(r.parent_capsule_digest.as_str()).fetch_optional(&mut **tx).await?.ok_or_else(||not_found("run",&r.run_id))?;
    let capsule: runtrue_workflow_ir::ExecutionCapsule = serde_json::from_slice(&bytes)?;
    let template = capsule
        .dynamic_jobs
        .iter()
        .find(|t| t.id == r.template_id)
        .cloned()
        .ok_or(ControlPlaneError::IdempotencyConflict)?;
    if template.source.producer_job_id != set.producer_job_id
        || template.source.output_name != set.producer_output_name
        || template.source.maximum_jobs < set.jobs.len()
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    for expanded in &set.jobs {
        let mut normalized = expanded.clone();
        normalized.id = template.template.id.clone();
        normalized.matrix.clear();
        if normalized != template.template {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
    }
    Ok((set, capsule, template))
}

#[cfg(feature = "postgres")]
async fn persist_expansion_pg(
    tx: &mut Transaction<'_, Postgres>,
    r: &ExpandedJobSetRecord,
) -> Result<bool, ControlPlaneError> {
    if let Some(row)=sqlx::query("SELECT * FROM expanded_job_sets WHERE tenant_id=$1 AND repository_id=$2 AND run_id=$3 AND template_id=$4").bind(&r.tenant_id).bind(&r.repository_id).bind(&r.run_id).bind(&r.template_id).fetch_optional(&mut **tx).await? {
        let exact=row.try_get::<String,_>("id")?==r.id && row.try_get::<String,_>("parent_capsule_digest")?==r.parent_capsule_digest.as_str() && row.try_get::<String,_>("producer_job_id")?==r.producer_job_id && row.try_get::<String,_>("producer_output_name")?==r.producer_output_name && row.try_get::<String,_>("matrix_input_digest")?==r.matrix_input_digest.as_str() && postgres_u64(row.try_get("policy_epoch")?,"expansion policy epoch")?==r.policy_epoch && u64::try_from(row.try_get::<i32,_>("generated_job_count")?).ok()==Some(r.generated_job_count) && row.try_get::<Vec<u8>,_>("canonical_job_set")?==r.canonical_job_set && row.try_get::<String,_>("job_set_digest")?==r.job_set_digest.as_str() && row.try_get::<String,_>("signing_key_id")?==r.signing_key_id && row.try_get::<Vec<u8>,_>("signature")?==r.signature && postgres_u64(row.try_get("created_unix_ms")?,"expansion creation")?==r.created_unix_ms;
        return if exact{Ok(true)}else{Err(ControlPlaneError::IdempotencyConflict)};
    }
    sqlx::query("INSERT INTO expanded_job_sets(id,tenant_id,repository_id,run_id,parent_capsule_digest,template_id,producer_job_id,producer_output_name,matrix_input_digest,policy_epoch,generated_job_count,canonical_job_set,job_set_digest,signing_key_id,signature,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)").bind(&r.id).bind(&r.tenant_id).bind(&r.repository_id).bind(&r.run_id).bind(r.parent_capsule_digest.as_str()).bind(&r.template_id).bind(&r.producer_job_id).bind(&r.producer_output_name).bind(r.matrix_input_digest.as_str()).bind(postgres_i64(r.policy_epoch,"expansion policy epoch")?).bind(i32::try_from(r.generated_job_count).map_err(|_|ControlPlaneError::IntegerRange{field:"generated jobs"})?).bind(&r.canonical_job_set).bind(r.job_set_digest.as_str()).bind(&r.signing_key_id).bind(&r.signature).bind(postgres_i64(r.created_unix_ms,"expansion creation")?).execute(&mut **tx).await?;
    Ok(false)
}

#[cfg(feature = "postgres")]
fn expanded_job_id(record: &str, key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"runtrue.expanded-scheduler-job.v1\0");
    for value in [record.as_bytes(), key.as_bytes()] {
        h.update((value.len() as u64).to_be_bytes());
        h.update(value)
    }
    format!("expanded-job-{}", hex::encode(h.finalize()))
}

#[cfg(feature = "postgres")]
impl WorkflowSemanticsStore for PostgresInstallationStore {
    fn record_normalized_trigger<'a>(
        &'a self,
        r: &'a NormalizedTriggerEventRecord,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let authorized: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1 AND tenant_id=$2)",
            )
            .bind(&r.repository_id)
            .bind(&r.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
            if !authorized {
                return Err(not_found("repository", &r.repository_id));
            }
            let replay = persist_trigger_pg(&mut tx, r).await?;
            if !replay {
                append_trigger_audit_pg(&mut tx, self.installation_id(), r).await?;
            }
            tx.commit().await?;
            Ok(replay)
        })
    }
    fn put_schedule_cursor<'a>(
        &'a self,
        c: &'a ScheduleTriggerCursor,
        expected: Option<u64>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            for v in [
                &c.tenant_id,
                &c.repository_id,
                &c.workflow_identity,
                &c.schedule_key,
            ] {
                validate_text(v)?
            }
            validate_cron_pg(&c.cron_utc)?;
            if !matches!(
                c.catch_up_policy.as_str(),
                "skip" | "latest" | "all-bounded"
            ) || c.maximum_catch_up > 100
                || (c.catch_up_policy == "all-bounded" && c.maximum_catch_up == 0)
                || c.version == 0
                || c.last_fire_unix_ms
                    .is_some_and(|last| c.next_fire_unix_ms <= last)
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid durable schedule cursor bounds",
                ));
            }
            let mut tx = self.pool().begin().await?;
            let authorized: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1 AND tenant_id=$2)",
            )
            .bind(&c.repository_id)
            .bind(&c.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
            if !authorized {
                return Err(not_found("repository", &c.repository_id));
            }
            let changed=match expected{None if c.version==1=>sqlx::query("INSERT INTO schedule_trigger_cursors(tenant_id,repository_id,workflow_identity,schedule_key,cron_utc,catch_up_policy,maximum_catch_up,next_fire_unix_ms,last_fire_unix_ms,version,updated_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING").bind(&c.tenant_id).bind(&c.repository_id).bind(&c.workflow_identity).bind(&c.schedule_key).bind(&c.cron_utc).bind(&c.catch_up_policy).bind(postgres_i64(c.maximum_catch_up,"maximum catch up")?).bind(postgres_i64(c.next_fire_unix_ms,"next fire")?).bind(c.last_fire_unix_ms.map(|v|postgres_i64(v,"last fire")).transpose()?).bind(postgres_i64(c.version,"schedule version")?).bind(postgres_i64(c.updated_unix_ms,"schedule update")?).execute(&mut *tx).await?.rows_affected(),None=>return Err(ControlPlaneError::IdempotencyConflict),Some(v)=>sqlx::query("UPDATE schedule_trigger_cursors SET cron_utc=$5,catch_up_policy=$6,maximum_catch_up=$7,next_fire_unix_ms=$8,last_fire_unix_ms=$9,version=$10,updated_unix_ms=$11 WHERE tenant_id=$1 AND repository_id=$2 AND workflow_identity=$3 AND schedule_key=$4 AND version=$12 AND $10=$12+1").bind(&c.tenant_id).bind(&c.repository_id).bind(&c.workflow_identity).bind(&c.schedule_key).bind(&c.cron_utc).bind(&c.catch_up_policy).bind(postgres_i64(c.maximum_catch_up,"maximum catch up")?).bind(postgres_i64(c.next_fire_unix_ms,"next fire")?).bind(c.last_fire_unix_ms.map(|x|postgres_i64(x,"last fire")).transpose()?).bind(postgres_i64(c.version,"schedule version")?).bind(postgres_i64(c.updated_unix_ms,"schedule update")?).bind(postgres_i64(v,"expected schedule version")?).execute(&mut *tx).await?.rows_affected()};
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            super::api_tokens::append(
                &mut tx,
                self.installation_id(),
                AuditEventData {
                    observed_unix_ms: c.updated_unix_ms,
                    tenant_id: c.tenant_id.clone(),
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: "schedule-reconciler".to_owned(),
                    },
                    action: "workflow.schedule.cursor".to_owned(),
                    resource: AuditResource {
                        kind: "schedule-cursor".to_owned(),
                        id: c.schedule_key.clone(),
                    },
                    result: "persisted".to_owned(),
                    request_id: format!("{}:{}", c.schedule_key, c.version),
                    decision_id: None,
                    metadata: BTreeMap::from([(
                        "next_fire_unix_ms".to_owned(),
                        AuditValue::Integer(postgres_i64(c.next_fire_unix_ms, "next fire")?),
                    )]),
                },
            )
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }
    fn reconcile_due_schedules<'a>(
        &'a self,
        now: u64,
        limit: usize,
    ) -> StoreFuture<'a, ScheduleReconciliationSummary> {
        Box::pin(async move {
            if limit == 0 || limit > 100 {
                return Err(ControlPlaneError::InvalidInput(
                    "due schedule reconciliation limit is invalid",
                ));
            }
            let mut tx = self.pool().begin().await?;
            let rows=sqlx::query("SELECT * FROM schedule_trigger_cursors WHERE next_fire_unix_ms<=$1 ORDER BY next_fire_unix_ms,tenant_id,repository_id,workflow_identity,schedule_key FOR UPDATE LIMIT $2").bind(postgres_i64(now,"schedule reconciliation")?).bind(i64::try_from(limit).map_err(|_|ControlPlaneError::InvalidInput("due schedule reconciliation limit is invalid"))?).fetch_all(&mut *tx).await?;
            let mut summary = ScheduleReconciliationSummary {
                cursors_considered: u64::try_from(rows.len()).unwrap_or(u64::MAX),
                ..Default::default()
            };
            for row in rows {
                let c = schedule_row(&row)?;
                validate_cron_pg(&c.cron_utc)?;
                if !c.next_fire_unix_ms.is_multiple_of(60_000)
                    || !cron_matches_unix_ms_pg(&c.cron_utc, c.next_fire_unix_ms)?
                {
                    return Err(ControlPlaneError::CorruptState(
                        "durable schedule cursor is not on its UTC cron".to_owned(),
                    ));
                }
                let fires = match c.catch_up_policy.as_str() {
                    "skip" => Vec::new(),
                    "latest" => vec![previous_fire_pg(&c.cron_utc, now)?],
                    "all-bounded" if c.maximum_catch_up != 0 => {
                        let mut out = Vec::new();
                        let mut fire = c.next_fire_unix_ms;
                        while fire <= now
                            && out.len()
                                < usize::try_from(c.maximum_catch_up.min(100)).unwrap_or(100)
                        {
                            out.push(fire);
                            fire = next_fire_pg(&c.cron_utc, fire)?
                        }
                        out
                    }
                    _ => {
                        return Err(ControlPlaneError::CorruptState(
                            "durable schedule catch-up policy is invalid".to_owned(),
                        ))
                    }
                };
                let next = if c.catch_up_policy == "all-bounded" {
                    fires
                        .last()
                        .copied()
                        .map(|v| next_fire_pg(&c.cron_utc, v))
                        .transpose()?
                        .unwrap_or(c.next_fire_unix_ms)
                } else {
                    next_fire_pg(&c.cron_utc, now)?
                };
                let mut last = c.last_fire_unix_ms;
                for fire in fires {
                    let trigger = schedule_trigger_pg(&c, fire)?;
                    let replay = persist_trigger_pg(&mut tx, &trigger).await?;
                    if replay {
                        summary.trigger_replays += 1
                    } else {
                        summary.triggers_inserted += 1;
                        append_trigger_audit_pg(&mut tx, self.installation_id(), &trigger).await?;
                    }
                    last = Some(fire)
                }
                let changed=sqlx::query("UPDATE schedule_trigger_cursors SET next_fire_unix_ms=$6,last_fire_unix_ms=$7,version=version+1,updated_unix_ms=$8 WHERE tenant_id=$1 AND repository_id=$2 AND workflow_identity=$3 AND schedule_key=$4 AND version=$5").bind(&c.tenant_id).bind(&c.repository_id).bind(&c.workflow_identity).bind(&c.schedule_key).bind(postgres_i64(c.version,"schedule version")?).bind(postgres_i64(next,"next fire")?).bind(last.map(|v|postgres_i64(v,"last fire")).transpose()?).bind(postgres_i64(now,"schedule update")?).execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                super::api_tokens::append(
                    &mut tx,
                    self.installation_id(),
                    AuditEventData {
                        observed_unix_ms: now,
                        tenant_id: c.tenant_id.clone(),
                        actor: AuditPrincipal {
                            kind: "worker".to_owned(),
                            id: "schedule-reconciler".to_owned(),
                        },
                        action: "workflow.schedule.reconcile".to_owned(),
                        resource: AuditResource {
                            kind: "schedule-cursor".to_owned(),
                            id: c.schedule_key.clone(),
                        },
                        result: "persisted".to_owned(),
                        request_id: format!("schedule-reconcile:{}", c.version),
                        decision_id: None,
                        metadata: BTreeMap::from([
                            (
                                "next_fire_unix_ms".to_owned(),
                                AuditValue::Integer(postgres_i64(next, "next fire")?),
                            ),
                            (
                                "triggers_inserted".to_owned(),
                                AuditValue::Integer(postgres_i64(
                                    summary.triggers_inserted,
                                    "inserted triggers",
                                )?),
                            ),
                        ]),
                    },
                )
                .await?;
                summary.cursors_advanced += 1
            }
            summary.due_cursors_remaining = postgres_u64(
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM schedule_trigger_cursors WHERE next_fire_unix_ms<=$1",
                )
                .bind(postgres_i64(now, "schedule due count")?)
                .fetch_one(&mut *tx)
                .await?,
                "schedule due count",
            )?;
            tx.commit().await?;
            Ok(summary)
        })
    }
    fn schedule_cursor<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
        w: &'a str,
        k: &'a str,
    ) -> StoreFuture<'a, ScheduleTriggerCursor> {
        Box::pin(async move {
            let row=sqlx::query("SELECT * FROM schedule_trigger_cursors WHERE tenant_id=$1 AND repository_id=$2 AND workflow_identity=$3 AND schedule_key=$4").bind(t).bind(r).bind(w).bind(k).fetch_optional(self.pool()).await?.ok_or_else(||not_found("schedule cursor",k))?;
            schedule_row(&row)
        })
    }
    fn workflow_semantics_metrics<'a>(
        &'a self,
        t: &'a str,
        now: u64,
    ) -> StoreFuture<'a, WorkflowSemanticsMetrics> {
        Box::pin(async move {
            validate_text(t)?;
            let expanded: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM expanded_job_sets WHERE tenant_id=$1")
                    .bind(t)
                    .fetch_one(self.pool())
                    .await?;
            let triggers: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM normalized_trigger_events WHERE tenant_id=$1",
            )
            .bind(t)
            .fetch_one(self.pool())
            .await?;
            let due:i64=sqlx::query_scalar("SELECT COUNT(*) FROM schedule_trigger_cursors WHERE tenant_id=$1 AND next_fire_unix_ms<=$2").bind(t).bind(postgres_i64(now,"workflow metrics")?).fetch_one(self.pool()).await?;
            Ok(WorkflowSemanticsMetrics {
                expanded_job_sets: postgres_u64(expanded, "expanded job metric")?,
                normalized_triggers: postgres_u64(triggers, "trigger metric")?,
                due_schedules: postgres_u64(due, "schedule metric")?,
            })
        })
    }
    fn record_expanded_job_set<'a>(
        &'a self,
        record: &'a ExpandedJobSetRecord,
        key: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            validate_expansion_pg(&mut tx, record, key).await?;
            let replayed = persist_expansion_pg(&mut tx, record).await?;
            if !replayed {
                append_expansion_audit_pg(&mut tx, self.installation_id(), record).await?;
            }
            tx.commit().await?;
            Ok(replayed)
        })
    }
    fn materialize_expanded_job_set<'a>(
        &'a self,
        request: &'a MaterializeExpandedJobSet,
        key: &'a CapsuleVerifyingKey,
    ) -> StoreFuture<'a, ExpandedJobMaterialization> {
        Box::pin(async move {
            validate_text(&request.execution_lease_id)?;
            validate_text(&request.runner_id)?;
            if request.fencing_generation == 0
                || request.installation_fencing_epoch == 0
                || request.producer_job_attempt == 0
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let mut tx = self.pool().begin().await?;
            let (set, capsule, template) =
                validate_expansion_pg(&mut tx, &request.record, key).await?;
            let epoch: i64 = sqlx::query_scalar(
                "SELECT fencing_epoch FROM installation_state WHERE singleton=TRUE",
            )
            .fetch_one(&mut *tx)
            .await?;
            if postgres_u64(epoch, "installation fence")? != request.installation_fencing_epoch {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let lease_job = validate_source_lease_pg(
                &mut tx,
                &request.execution_lease_id,
                &request.runner_id,
                request.fencing_generation,
                request.record.created_unix_ms,
            )
            .await?;
            let authorized:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM jobs j JOIN job_fencing jf ON jf.job_id=j.id JOIN runs r ON r.id=j.run_id JOIN repositories repo ON repo.id=r.repository_id WHERE j.id=$1 AND repo.tenant_id=$2 AND r.repository_id=$3 AND r.id=$4 AND j.job_key=$5 AND j.attempt=$6 AND jf.last_generation=$7)").bind(&lease_job).bind(&request.record.tenant_id).bind(&request.record.repository_id).bind(&request.record.run_id).bind(&request.record.producer_job_id).bind(i32::try_from(request.producer_job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"producer attempt"})?).bind(postgres_i64(request.fencing_generation,"producer fence")?).fetch_one(&mut *tx).await?;
            if !authorized {
                return Err(not_found("run", &request.record.run_id));
            }
            let record_replayed = persist_expansion_pg(&mut tx, &request.record).await?;
            if !record_replayed {
                append_expansion_audit_pg(&mut tx, self.installation_id(), &request.record).await?;
            }
            let expanded_total: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(generated_job_count), 0)::BIGINT
                 FROM expanded_job_sets WHERE run_id=$1",
            )
            .bind(&request.record.run_id)
            .fetch_one(&mut *tx)
            .await?;
            let expanded_total = usize::try_from(expanded_total).map_err(|_| {
                ControlPlaneError::CorruptState("expanded job count is negative".to_owned())
            })?;
            if capsule.jobs.len().saturating_add(expanded_total) > 1_024 {
                return Err(ControlPlaneError::InvalidInput(
                    "materialized run exceeds the signed workflow job bound",
                ));
            }
            let rows = sqlx::query("SELECT job_key,status FROM jobs WHERE run_id=$1")
                .bind(&request.record.run_id)
                .fetch_all(&mut *tx)
                .await?;
            let states = rows
                .iter()
                .map(|row| {
                    Ok((
                        row.try_get::<String, _>("job_key")?,
                        parse_job_state(&row.try_get::<String, _>("status")?)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, ControlPlaneError>>()?;
            let mut existing = 0usize;
            for planned in &set.jobs {
                let id = expanded_job_id(&request.record.id, &planned.id);
                if let Some(row)=sqlx::query("SELECT id,attempt,requirements_json,concurrency_group FROM jobs WHERE run_id=$1 AND job_key=$2").bind(&request.record.run_id).bind(&planned.id).fetch_optional(&mut *tx).await?{let expected=runtrue_scheduler::SchedulingRequirements{os:planned.runner.os,arch:planned.runner.arch,isolation:planned.runner.isolation,cpu:u32::from(planned.runner.cpu),memory_bytes:planned.runner.memory_bytes,storage_bytes:planned.runner.storage_bytes.unwrap_or(0),region:planned.runner.region.clone(),required_capabilities:planned.runner.capabilities.iter().cloned().collect(),allowed_pools:BTreeSet::new()};if row.try_get::<String,_>("id")?!=id||row.try_get::<i32,_>("attempt")?!=1||serde_json::from_slice::<runtrue_scheduler::SchedulingRequirements>(&row.try_get::<Vec<u8>,_>("requirements_json")?)?!=expected||row.try_get::<Option<String>,_>("concurrency_group")?!=planned.concurrency{return Err(ControlPlaneError::IdempotencyConflict)}existing+=1}
            }
            if existing != 0 && existing != set.jobs.len() {
                return Err(ControlPlaneError::CorruptState(
                    "expanded scheduler job materialization is partial".to_owned(),
                ));
            }
            let mut inserted = 0u64;
            if existing == 0 {
                for planned in &set.jobs {
                    if planned.needs != template.template.needs {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                    let deps = planned
                        .needs
                        .iter()
                        .map(|n| {
                            states.get(n).copied().ok_or_else(|| {
                                ControlPlaneError::CorruptState(
                                    "expanded job dependency is absent from its run".to_owned(),
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let status = if !capsule.context.source_trust.satisfies(planned.trust) {
                        JobState::BlockedPolicy
                    } else if deps.iter().all(|s| *s == JobState::Succeeded) {
                        JobState::Queued
                    } else if deps.iter().any(|s| {
                        (*s != JobState::Succeeded && s.is_terminal())
                            || *s == JobState::BlockedPolicy
                    }) {
                        JobState::Skipped
                    } else {
                        JobState::Created
                    };
                    let requirements = runtrue_scheduler::SchedulingRequirements {
                        os: planned.runner.os,
                        arch: planned.runner.arch,
                        isolation: planned.runner.isolation,
                        cpu: u32::from(planned.runner.cpu),
                        memory_bytes: planned.runner.memory_bytes,
                        storage_bytes: planned.runner.storage_bytes.unwrap_or(0),
                        region: planned.runner.region.clone(),
                        required_capabilities: planned
                            .runner
                            .capabilities
                            .iter()
                            .cloned()
                            .collect(),
                        allowed_pools: BTreeSet::new(),
                    };
                    let id = expanded_job_id(&request.record.id, &planned.id);
                    sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms,completed_unix_ms,concurrency_group) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8)").bind(&id).bind(&request.record.run_id).bind(&planned.id).bind(job_state_name(status)).bind(serde_json::to_vec(&requirements)?).bind(postgres_i64(request.record.created_unix_ms,"expanded job creation")?).bind((status.is_terminal()||status==JobState::BlockedPolicy).then_some(postgres_i64(request.record.created_unix_ms,"expanded job completion")?)).bind(&planned.concurrency).execute(&mut *tx).await?;
                    sqlx::query("INSERT INTO job_fencing(job_id,last_generation) VALUES($1,0)")
                        .bind(&id)
                        .execute(&mut *tx)
                        .await?;
                    inserted += 1
                }
            }
            if inserted != 0 {
                super::api_tokens::append(
                    &mut tx,
                    self.installation_id(),
                    AuditEventData {
                        observed_unix_ms: request.record.created_unix_ms,
                        tenant_id: request.record.tenant_id.clone(),
                        actor: AuditPrincipal {
                            kind: "runner".to_owned(),
                            id: request.runner_id.clone(),
                        },
                        action: "workflow.expand.materialize".to_owned(),
                        resource: AuditResource {
                            kind: "expanded-job-set".to_owned(),
                            id: request.record.id.clone(),
                        },
                        result: "persisted".to_owned(),
                        request_id: request.execution_lease_id.clone(),
                        decision_id: Some(request.record.job_set_digest.to_string()),
                        metadata: BTreeMap::from([
                            (
                                "fencing_generation".to_owned(),
                                AuditValue::Integer(postgres_i64(
                                    request.fencing_generation,
                                    "fencing generation",
                                )?),
                            ),
                            (
                                "jobs_inserted".to_owned(),
                                AuditValue::Integer(postgres_i64(inserted, "inserted jobs")?),
                            ),
                        ]),
                    },
                )
                .await?;
            }
            tx.commit().await?;
            Ok(ExpandedJobMaterialization {
                record_replayed,
                jobs_inserted: inserted,
            })
        })
    }
}

#[cfg(test)]
pub(super) async fn core_contract<T: RunCoreStore>(store: &T) {
    use crate::NewJob;
    use runtrue_attest::CapsuleSigningKey;
    use std::collections::BTreeSet;

    let existing = store
        .signed_capsule("scm-completion-capsule-contract")
        .await
        .expect("load SCM contract capsule through run core");
    let metadata = store
        .capsule_api_metadata(&existing.id)
        .await
        .expect("load capsule API metadata through run core");
    assert_eq!(metadata.capsule_id, existing.id);

    let mut decoded: runtrue_workflow_ir::ExecutionCapsule =
        serde_json::from_slice(&existing.canonical_capsule).expect("decode run core capsule");
    decoded.compiler_version = "run-core-contract".to_owned();
    let signer = CapsuleSigningKey::from_seed([71; 32]);
    let signature = signer
        .sign_capsule(&decoded)
        .expect("sign run core capsule");
    let capsule = SignedCapsuleRecord {
        id: "run-core-capsule-contract".to_owned(),
        repository_id: existing.repository_id,
        digest: signature.capsule_digest.clone(),
        canonical_capsule: decoded.canonical_bytes().expect("encode run core capsule"),
        signature,
        created_unix_ms: 800,
    };
    store
        .store_signed_capsule(&capsule, &signer.verifying_key())
        .await
        .expect("store signed run core capsule");
    assert_eq!(
        store
            .signed_capsule(&capsule.id)
            .await
            .expect("reload signed run core capsule"),
        capsule
    );

    decoded.compiler_version = "run-core-compiled-contract".to_owned();
    let compiled_signature = signer
        .sign_capsule(&decoded)
        .expect("sign compiled run core capsule");
    let compiled = SignedCapsuleRecord {
        id: "run-core-compiled-capsule-contract".to_owned(),
        repository_id: capsule.repository_id.clone(),
        digest: compiled_signature.capsule_digest.clone(),
        canonical_capsule: decoded
            .canonical_bytes()
            .expect("encode compiled run core capsule"),
        signature: compiled_signature,
        created_unix_ms: 800,
    };
    let compiled_metadata = CapsuleApiMetadata {
        capsule_id: compiled.id.clone(),
        approval_subject_digest: ContentDigest::sha256(b"run core approval subject"),
        risk_score: 5,
    };
    let stored = store
        .store_compiled_capsule_idempotent(
            "run-core-compiled-contract",
            &compiled,
            &signer.verifying_key(),
            &compiled_metadata,
            &[],
        )
        .await
        .expect("store compiled run core capsule");
    assert!(!stored.replayed);
    assert!(
        store
            .store_compiled_capsule_idempotent(
                "run-core-compiled-contract",
                &compiled,
                &signer.verifying_key(),
                &compiled_metadata,
                &[],
            )
            .await
            .expect("replay compiled run core capsule")
            .replayed
    );
    assert_eq!(
        store
            .capsule_api_metadata(&compiled.id)
            .await
            .expect("load compiled capsule metadata"),
        compiled_metadata
    );

    let requirements = runtrue_scheduler::SchedulingRequirements {
        os: runtrue_workflow_ir::OperatingSystem::Linux,
        arch: runtrue_workflow_ir::Architecture::Amd64,
        isolation: runtrue_workflow_ir::Isolation::Microvm,
        cpu: 1,
        memory_bytes: 1024,
        storage_bytes: 1024,
        region: Some("test".to_owned()),
        required_capabilities: ["kvm".to_owned()].into_iter().collect::<BTreeSet<_>>(),
        allowed_pools: BTreeSet::new(),
    };
    let request = CreateRunRequest {
        id: "run-core-run-contract".to_owned(),
        repository_id: compiled.repository_id.clone(),
        capsule_id: compiled.id.clone(),
        priority: 0,
        remote: true,
        created_unix_ms: 800,
        jobs: vec![NewJob {
            id: "run-core-job-contract".to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements: requirements.clone(),
        }],
    };
    let created = store
        .create_run_idempotent("run-core-create-contract", &request)
        .await
        .expect("create run core run");
    assert!(!created.replayed);
    assert_eq!(created.value.status, RunState::Created);
    assert!(
        store
            .create_run_idempotent("run-core-create-contract", &request)
            .await
            .expect("replay run core creation")
            .replayed
    );
    assert_eq!(
        store.run(&request.id).await.expect("load run core run"),
        created.value
    );
    let jobs = store
        .jobs_for_run(&request.id)
        .await
        .expect("list run core jobs");
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        store
            .job("run-core-job-contract")
            .await
            .expect("load run core job"),
        jobs[0]
    );
    store
        .transition_run_state(&request.id, RunState::Running, 801)
        .await
        .expect("start run core run");
    for (state, at) in [
        (JobState::Preparing, 802),
        (JobState::Running, 803),
        (JobState::Finalizing, 804),
        (JobState::Succeeded, 805),
    ] {
        store
            .transition_job_state("run-core-job-contract", state, at)
            .await
            .expect("transition run core job");
    }
    assert_eq!(
        store
            .run(&request.id)
            .await
            .expect("load concluded run core run")
            .status,
        RunState::Succeeded
    );

    let bundle_bytes = br#"{"run":"run-core-run-contract"}"#.to_vec();
    let bundle = ReplayBundleRecord {
        id: "run-core-replay-contract".to_owned(),
        run_id: request.id.clone(),
        digest: ContentDigest::sha256(&bundle_bytes),
        canonical_bundle: bundle_bytes,
        created_unix_ms: 806,
        expires_unix_ms: 1806,
    };
    assert!(
        !store
            .store_replay_bundle_idempotent("run-core-replay-key-contract", &bundle)
            .await
            .expect("store replay bundle")
            .replayed
    );
    assert!(
        store
            .store_replay_bundle_idempotent("run-core-replay-key-contract", &bundle)
            .await
            .expect("replay replay bundle storage")
            .replayed
    );
    assert_eq!(
        store
            .replay_bundle_for_run(&request.id)
            .await
            .expect("load replay bundle"),
        bundle
    );

    let cancel = CreateRunRequest {
        id: "run-core-cancel-run-contract".to_owned(),
        jobs: vec![NewJob {
            id: "run-core-cancel-job-contract".to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements,
        }],
        ..request
    };
    store
        .create_run_idempotent("run-core-cancel-create-contract", &cancel)
        .await
        .expect("create cancelable run");
    let canceled = store
        .cancel_run_idempotent(
            "run-core-cancel-contract",
            &cancel.id,
            "contract cancellation",
            810,
        )
        .await
        .expect("cancel run core run");
    assert!(!canceled.replayed);
    assert_eq!(canceled.value.status, RunState::Canceled);
    assert!(
        store
            .cancel_run_idempotent(
                "run-core-cancel-contract",
                &cancel.id,
                "contract cancellation",
                811,
            )
            .await
            .expect("replay run cancellation")
            .replayed
    );

    let first_page = store
        .list_runs_page(Some("repository-contract"), None, 2)
        .await
        .expect("list first run page");
    assert_eq!(
        first_page
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec!["run-core-run-contract", "run-core-cancel-run-contract"]
    );
    let second_page = store
        .list_runs_page(Some("repository-contract"), Some(&first_page[1].id), 1)
        .await
        .expect("continue run page");
    assert!(!second_page.is_empty());
    assert!(second_page
        .iter()
        .all(|record| !first_page.iter().any(|first| first.id == record.id)));
    assert_eq!(
        store
            .list_runs_page_for_tenant("tenant-contract", Some("repository-contract"), None, 2,)
            .await
            .expect("list tenant run page"),
        first_page
    );
    assert!(store
        .list_runs_page_for_tenant("missing-tenant", None, None, 100)
        .await
        .expect("isolate missing tenant run page")
        .is_empty());
    assert!(store.list_runs_page(None, None, 0).await.is_err());
}

#[cfg(test)]
pub(super) async fn approval_contract<T: ApprovalStore + RunCoreStore>(store: &T) {
    use crate::NewJob;
    use runtrue_attest::CapsuleSigningKey;
    use runtrue_policy::{ApprovalKind, ApprovalRule, ApprovalStatus, Decision};
    use std::collections::BTreeSet;

    let capsule = store
        .signed_capsule("run-core-compiled-capsule-contract")
        .await
        .expect("load approval contract base capsule");
    let subject = ContentDigest::sha256(b"approval lifecycle contract");
    let rule = ApprovalRule {
        id: "approval-rule-contract".to_owned(),
        required_approvals: 1,
        eligible_approvers: ["reviewer".to_owned()].into_iter().collect(),
        forbidden_approvers: BTreeSet::new(),
        one_shot: true,
    };
    let denied = ApprovalRequest::create(
        "approval-denied-contract",
        ApprovalKind::WorkflowDefinition,
        subject.clone(),
        10,
        820,
        900,
        rule.clone(),
    )
    .expect("build denied approval request");
    store
        .create_approval_request(&capsule.repository_id, &capsule.id, &denied)
        .await
        .expect("create approval request");
    assert_eq!(
        store
            .approval_request(&denied.id)
            .await
            .expect("load approval request"),
        denied
    );
    let denied_decision = ApprovalDecision {
        actor_id: "reviewer".to_owned(),
        decision: Decision::Deny,
        reason: "contract denial".to_owned(),
        rule_id: rule.id.clone(),
        subject_digest: subject.clone(),
        decided_unix_ms: 821,
    };
    assert_eq!(
        store
            .decide_approval(&denied.id, denied_decision, 821)
            .await
            .expect("deny approval request")
            .status,
        ApprovalStatus::Denied
    );

    let expired = ApprovalRequest::create(
        "approval-expired-contract",
        ApprovalKind::WorkflowDefinition,
        subject.clone(),
        10,
        820,
        825,
        rule.clone(),
    )
    .expect("build expiring approval request");
    store
        .create_approval_request(&capsule.repository_id, &capsule.id, &expired)
        .await
        .expect("create expiring approval request");
    let expired_decision = ApprovalDecision {
        actor_id: "reviewer".to_owned(),
        decision: Decision::Approve,
        reason: "too late".to_owned(),
        rule_id: rule.id.clone(),
        subject_digest: subject.clone(),
        decided_unix_ms: 824,
    };
    assert!(store
        .decide_approval(&expired.id, expired_decision, 826)
        .await
        .is_err());
    assert_eq!(
        store
            .approval_request(&expired.id)
            .await
            .expect("load expired approval")
            .status,
        ApprovalStatus::Expired
    );

    let mut reusable_rule = rule.clone();
    reusable_rule.one_shot = false;
    let reusable = ApprovalRequest::create(
        "approval-authorize-contract",
        ApprovalKind::WorkflowDefinition,
        subject.clone(),
        10,
        820,
        900,
        reusable_rule.clone(),
    )
    .expect("build reusable approval request");
    store
        .create_approval_request(&capsule.repository_id, &capsule.id, &reusable)
        .await
        .expect("create reusable approval request");
    store
        .decide_approval(
            &reusable.id,
            ApprovalDecision {
                actor_id: "reviewer".to_owned(),
                decision: Decision::Approve,
                reason: "reusable approval".to_owned(),
                rule_id: reusable_rule.id,
                subject_digest: subject.clone(),
                decided_unix_ms: 822,
            },
            822,
        )
        .await
        .expect("approve reusable request");
    assert_eq!(
        store
            .authorize_approval(&reusable.id, &subject, 823)
            .await
            .expect("authorize reusable request")
            .status,
        ApprovalStatus::Approved
    );

    let signer = CapsuleSigningKey::from_seed([71; 32]);
    let mut decoded: runtrue_workflow_ir::ExecutionCapsule =
        serde_json::from_slice(&capsule.canonical_capsule).expect("decode gated capsule");
    decoded.compiler_version = "approval-gated-contract".to_owned();
    decoded.approval.workflow_definition = true;
    decoded
        .approval
        .reasons
        .push("approval contract".to_owned());
    let signature = signer.sign_capsule(&decoded).expect("sign gated capsule");
    let gated = SignedCapsuleRecord {
        id: "approval-gated-capsule-contract".to_owned(),
        repository_id: capsule.repository_id,
        digest: signature.capsule_digest.clone(),
        canonical_capsule: decoded.canonical_bytes().expect("encode gated capsule"),
        signature,
        created_unix_ms: 830,
    };
    let metadata = CapsuleApiMetadata {
        capsule_id: gated.id.clone(),
        approval_subject_digest: subject.clone(),
        risk_score: 10,
    };
    let approval = ApprovalRequest::create(
        "approval-approved-contract",
        ApprovalKind::WorkflowDefinition,
        subject.clone(),
        10,
        830,
        930,
        rule.clone(),
    )
    .expect("build gated approval request");
    store
        .store_compiled_capsule_idempotent(
            "approval-gated-capsule-key-contract",
            &gated,
            &signer.verifying_key(),
            &metadata,
            std::slice::from_ref(&approval),
        )
        .await
        .expect("store gated capsule and approval");
    assert_eq!(
        store
            .approval_requests_for_capsule(&gated.id)
            .await
            .expect("list capsule approvals"),
        vec![approval.clone()]
    );
    let approve = ApprovalDecision {
        actor_id: "reviewer".to_owned(),
        decision: Decision::Approve,
        reason: "contract approval".to_owned(),
        rule_id: rule.id,
        subject_digest: subject.clone(),
        decided_unix_ms: 831,
    };
    let decided = store
        .decide_approval_idempotent(
            "approval-decision-key-contract",
            &approval.id,
            approve.clone(),
            831,
        )
        .await
        .expect("approve gated request");
    assert!(!decided.replayed);
    assert_eq!(decided.value.status, ApprovalStatus::Approved);
    assert!(
        store
            .decide_approval_idempotent(
                "approval-decision-key-contract",
                &approval.id,
                approve,
                832,
            )
            .await
            .expect("replay approval decision")
            .replayed
    );
    assert_eq!(
        store
            .approval_request_tenant(&approval.id)
            .await
            .expect("load approval tenant"),
        "tenant-contract"
    );
    assert!(store
        .list_approval_requests_page(Some("approved"), None, 100)
        .await
        .expect("list approved requests")
        .iter()
        .any(|item| item.id == approval.id));
    assert!(store
        .list_approval_requests_page_for_tenant("tenant-contract", Some("approved"), None, 100,)
        .await
        .expect("list tenant approvals")
        .iter()
        .any(|item| item.id == approval.id));

    let requirements = runtrue_scheduler::SchedulingRequirements {
        os: runtrue_workflow_ir::OperatingSystem::Linux,
        arch: runtrue_workflow_ir::Architecture::Amd64,
        isolation: runtrue_workflow_ir::Isolation::Microvm,
        cpu: 1,
        memory_bytes: 1024,
        storage_bytes: 1024,
        region: Some("test".to_owned()),
        required_capabilities: ["kvm".to_owned()].into_iter().collect(),
        allowed_pools: BTreeSet::new(),
    };
    let run = CreateRunRequest {
        id: "approval-authorized-run-contract".to_owned(),
        repository_id: gated.repository_id,
        capsule_id: gated.id,
        priority: 0,
        remote: true,
        created_unix_ms: 833,
        jobs: vec![NewJob {
            id: "approval-authorized-job-contract".to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements,
        }],
    };
    store
        .create_run_idempotent("approval-authorized-run-key-contract", &run)
        .await
        .expect("create approval-authorized run");
    assert_eq!(
        store
            .approval_request(&approval.id)
            .await
            .expect("load consumed approval")
            .status,
        ApprovalStatus::Consumed
    );
}

#[cfg(test)]
pub(super) async fn source_snapshot_contract<T: SourceSnapshotStore + RunCoreStore>(store: &T) {
    use crate::NewJob;
    use runtrue_attest::CapsuleSigningKey;
    use std::collections::BTreeSet;
    let base = store
        .signed_capsule("run-core-compiled-capsule-contract")
        .await
        .expect("load source base capsule");
    let mut decoded: runtrue_workflow_ir::ExecutionCapsule =
        serde_json::from_slice(&base.canonical_capsule).unwrap();
    let tree = ContentDigest::sha256(b"source tree contract");
    decoded.compiler_version = "source-snapshot-contract".to_owned();
    decoded.context.source_commit = "source-contract-commit".to_owned();
    decoded.context.source_tree_digest = Some(tree.clone());
    let signer = CapsuleSigningKey::from_seed([71; 32]);
    let signature = signer.sign_capsule(&decoded).unwrap();
    let capsule = SignedCapsuleRecord {
        id: "source-capsule-contract".to_owned(),
        repository_id: base.repository_id,
        digest: signature.capsule_digest.clone(),
        canonical_capsule: decoded.canonical_bytes().unwrap(),
        signature,
        created_unix_ms: 840,
    };
    let metadata = CapsuleApiMetadata {
        capsule_id: capsule.id.clone(),
        approval_subject_digest: ContentDigest::sha256(b"source approval subject"),
        risk_score: 0,
    };
    store
        .store_compiled_capsule_idempotent(
            "source-capsule-key-contract",
            &capsule,
            &signer.verifying_key(),
            &metadata,
            &[],
        )
        .await
        .unwrap();
    let requirements = runtrue_scheduler::SchedulingRequirements {
        os: runtrue_workflow_ir::OperatingSystem::Linux,
        arch: runtrue_workflow_ir::Architecture::Amd64,
        isolation: runtrue_workflow_ir::Isolation::Microvm,
        cpu: 1,
        memory_bytes: 1024,
        storage_bytes: 1024,
        region: Some("test".to_owned()),
        required_capabilities: ["kvm".to_owned()].into_iter().collect::<BTreeSet<_>>(),
        allowed_pools: BTreeSet::new(),
    };
    let run = CreateRunRequest {
        id: "source-run-contract".to_owned(),
        repository_id: capsule.repository_id.clone(),
        capsule_id: capsule.id.clone(),
        priority: 0,
        remote: true,
        created_unix_ms: 840,
        jobs: vec![NewJob {
            id: "source-job-contract".to_owned(),
            job_key: "build".to_owned(),
            attempt: 1,
            requirements,
        }],
    };
    store
        .create_run_idempotent("source-run-key-contract", &run)
        .await
        .unwrap();
    assert_eq!(
        store.job("source-job-contract").await.unwrap().status,
        JobState::Created
    );
    let snapshot = SourceSnapshotRecord {
        id: "source-snapshot-core-contract".to_owned(),
        tenant_id: "tenant-contract".to_owned(),
        repository_id: capsule.repository_id,
        commit_sha: "source-contract-commit".to_owned(),
        tree_manifest_digest: tree.clone(),
        state: SourceSnapshotState::Building,
        created_unix_ms: 841,
        verified_unix_ms: None,
    };
    assert!(
        !store
            .create_source_snapshot(&snapshot)
            .await
            .unwrap()
            .replayed
    );
    assert!(
        store
            .create_source_snapshot(&snapshot)
            .await
            .unwrap()
            .replayed
    );
    assert_eq!(
        store
            .source_snapshot(&snapshot.tenant_id, &snapshot.id)
            .await
            .unwrap(),
        snapshot
    );
    let ready = store
        .mark_source_snapshot_ready(&snapshot.tenant_id, &snapshot.id, &tree, 842)
        .await
        .unwrap();
    assert_eq!(ready.state, SourceSnapshotState::Ready);
    let binding = store
        .bind_run_source_snapshot(
            &snapshot.tenant_id,
            &run.id,
            &snapshot.id,
            &capsule.digest,
            843,
        )
        .await
        .unwrap();
    assert!(!binding.replayed);
    assert!(
        store
            .bind_run_source_snapshot(
                &snapshot.tenant_id,
                &run.id,
                &snapshot.id,
                &capsule.digest,
                844
            )
            .await
            .unwrap()
            .replayed
    );
    assert_eq!(
        store
            .run_source_snapshot(&snapshot.tenant_id, &run.id)
            .await
            .unwrap(),
        binding.value
    );
    assert_eq!(
        store.job("source-job-contract").await.unwrap().status,
        JobState::Queued
    );
}

#[cfg(test)]
pub(super) async fn source_ticket_contract<T: SourceSnapshotStore>(store: &T) {
    let issue = IssueRunnerSourceTicket {
        id: "source-ticket-contract".to_owned(),
        tenant_id: "tenant-contract".to_owned(),
        runner_id: "source-runner-contract".to_owned(),
        execution_lease_id: "source-lease-contract".to_owned(),
        fencing_generation: 1,
        job_id: "source-job-contract".to_owned(),
        job_attempt: 1,
        maximum_bytes: 1024,
        issued_unix_ms: 860,
        expires_unix_ms: 940,
    };
    let created = store.issue_runner_source_ticket(&issue).await.unwrap();
    assert!(!created.replayed);
    assert!(
        store
            .issue_runner_source_ticket(&issue)
            .await
            .unwrap()
            .replayed
    );
    assert_eq!(
        store.runner_source_ticket(&issue.id).await.unwrap(),
        created.value
    );
    let download = RunnerSourceDownload {
        ticket_id: issue.id,
        object_digest: ContentDigest::sha256(b"source object contract"),
        runner_id: issue.runner_id,
        execution_lease_id: issue.execution_lease_id,
        fencing_generation: 1,
        job_id: issue.job_id,
        job_attempt: 1,
        size_bytes: 512,
        recorded_unix_ms: 870,
    };
    assert!(!store.begin_runner_source_download(&download).await.unwrap());
    let mut finished = download.clone();
    finished.recorded_unix_ms = 871;
    store
        .finish_runner_source_download(&finished)
        .await
        .unwrap();
    let mut replay = download.clone();
    replay.recorded_unix_ms = 872;
    assert!(store.begin_runner_source_download(&replay).await.unwrap());
    let mut stale = replay;
    stale.fencing_generation = 2;
    assert!(store.begin_runner_source_download(&stale).await.is_err());
}

#[cfg(test)]
async fn prepare_expansion<T: RunCoreStore>(
    store: &T,
) -> (ExpandedJobSetRecord, runtrue_attest::CapsuleSigningKey) {
    use crate::NewJob;
    use std::collections::BTreeSet;
    let base = store
        .signed_capsule("run-core-compiled-capsule-contract")
        .await
        .unwrap();
    let mut capsule: runtrue_workflow_ir::ExecutionCapsule =
        serde_json::from_slice(&base.canonical_capsule).unwrap();
    capsule.compiler_version = "workflow-expansion-contract".to_owned();
    let mut template_job = capsule.jobs[0].clone();
    template_job.id = "dynamic".to_owned();
    template_job.base_id = "dynamic".to_owned();
    template_job.needs = vec!["build".to_owned()];
    let template = runtrue_workflow_ir::DynamicJobTemplate {
        id: "dynamic".to_owned(),
        source: runtrue_workflow_ir::DynamicMatrixSource {
            producer_job_id: "build".to_owned(),
            output_name: "axes".to_owned(),
            maximum_jobs: 4,
        },
        template: template_job,
    };
    capsule.dynamic_jobs = vec![template.clone()];
    let signer = runtrue_attest::CapsuleSigningKey::from_seed([71; 32]);
    let signature = signer.sign_capsule(&capsule).unwrap();
    let signed = SignedCapsuleRecord {
        id: "workflow-expansion-capsule-contract".to_owned(),
        repository_id: base.repository_id,
        digest: signature.capsule_digest.clone(),
        canonical_capsule: capsule.canonical_bytes().unwrap(),
        signature,
        created_unix_ms: 880,
    };
    let metadata = CapsuleApiMetadata {
        capsule_id: signed.id.clone(),
        approval_subject_digest: ContentDigest::sha256(b"expansion approval"),
        risk_score: 0,
    };
    store
        .store_compiled_capsule_idempotent(
            "workflow-expansion-capsule-key",
            &signed,
            &signer.verifying_key(),
            &metadata,
            &[],
        )
        .await
        .unwrap();
    let requirements = runtrue_scheduler::SchedulingRequirements {
        os: runtrue_workflow_ir::OperatingSystem::Linux,
        arch: runtrue_workflow_ir::Architecture::Amd64,
        isolation: runtrue_workflow_ir::Isolation::Microvm,
        cpu: 1,
        memory_bytes: 1024,
        storage_bytes: 1024,
        region: Some("test".to_owned()),
        required_capabilities: ["kvm".to_owned()].into_iter().collect::<BTreeSet<_>>(),
        allowed_pools: BTreeSet::new(),
    };
    store
        .create_run_idempotent(
            "workflow-expansion-run-key",
            &CreateRunRequest {
                id: "workflow-expansion-run-contract".to_owned(),
                repository_id: signed.repository_id.clone(),
                capsule_id: signed.id,
                priority: 0,
                remote: true,
                created_unix_ms: 880,
                jobs: vec![NewJob {
                    id: "workflow-producer-job-contract".to_owned(),
                    job_key: "build".to_owned(),
                    attempt: 1,
                    requirements,
                }],
            },
        )
        .await
        .unwrap();
    let set = runtrue_workflow_ir::expand_dynamic_job_set(
        signed.digest.clone(),
        &template,
        &serde_json::json!({"shard":[1,2]}),
        9,
    )
    .unwrap();
    let sig = signer.sign_expanded_job_set(&set).unwrap();
    let record = ExpandedJobSetRecord {
        id: "workflow-expanded-contract".to_owned(),
        tenant_id: "tenant-contract".to_owned(),
        repository_id: signed.repository_id,
        run_id: "workflow-expansion-run-contract".to_owned(),
        parent_capsule_digest: signed.digest,
        template_id: template.id,
        producer_job_id: set.producer_job_id.clone(),
        producer_output_name: set.producer_output_name.clone(),
        matrix_input_digest: set.matrix_input_digest.clone(),
        policy_epoch: set.policy_epoch,
        generated_job_count: set.jobs.len() as u64,
        canonical_job_set: set.canonical_bytes().unwrap(),
        job_set_digest: sig.job_set_digest,
        signing_key_id: sig.key_id.to_string(),
        signature: sig.signature,
        created_unix_ms: 890,
    };
    (record, signer)
}

#[cfg(test)]
pub(super) async fn workflow_record_contract<T: WorkflowSemanticsStore + RunCoreStore>(store: &T) {
    let envelope = serde_json::json!({"inputs":{"release":false},"type":"manual"});
    let canonical =
        serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(envelope.clone())).unwrap();
    let trigger = NormalizedTriggerEventRecord {
        id: "workflow-trigger-contract".to_owned(),
        tenant_id: "tenant-contract".to_owned(),
        repository_id: "repository-contract".to_owned(),
        trigger_kind: "manual".to_owned(),
        idempotency_identity: "principal:workflow-contract".to_owned(),
        normalized_digest: ContentDigest::sha256(canonical),
        normalized_envelope: envelope,
        actor_identity: "principal-contract".to_owned(),
        created_unix_ms: 900,
    };
    assert!(!store.record_normalized_trigger(&trigger).await.unwrap());
    assert!(store.record_normalized_trigger(&trigger).await.unwrap());
    let cursor = ScheduleTriggerCursor {
        tenant_id: "tenant-contract".to_owned(),
        repository_id: "repository-contract".to_owned(),
        workflow_identity: "ci".to_owned(),
        schedule_key: "every-minute".to_owned(),
        cron_utc: "* * * * *".to_owned(),
        catch_up_policy: "latest".to_owned(),
        maximum_catch_up: 1,
        next_fire_unix_ms: 60_000,
        last_fire_unix_ms: None,
        version: 1,
        updated_unix_ms: 900,
    };
    store.put_schedule_cursor(&cursor, None).await.unwrap();
    assert_eq!(
        store
            .schedule_cursor(
                &cursor.tenant_id,
                &cursor.repository_id,
                &cursor.workflow_identity,
                &cursor.schedule_key
            )
            .await
            .unwrap(),
        cursor
    );
    let summary = store.reconcile_due_schedules(120_000, 10).await.unwrap();
    assert_eq!(summary.cursors_advanced, 1);
    assert_eq!(summary.triggers_inserted, 1);
    let metrics = store
        .workflow_semantics_metrics("tenant-contract", 120_000)
        .await
        .unwrap();
    assert!(metrics.normalized_triggers >= 2);
    let (record, signer) = prepare_expansion(store).await;
    assert!(!store
        .record_expanded_job_set(&record, &signer.verifying_key())
        .await
        .unwrap());
    assert!(store
        .record_expanded_job_set(&record, &signer.verifying_key())
        .await
        .unwrap());
}

#[cfg(test)]
pub(super) async fn workflow_materialize_contract<T: WorkflowSemanticsStore + RunCoreStore>(
    store: &T,
) {
    let (record, signer) = prepare_expansion(store).await;
    let request = MaterializeExpandedJobSet {
        record,
        execution_lease_id: "workflow-expansion-lease-contract".to_owned(),
        runner_id: "source-runner-contract".to_owned(),
        fencing_generation: 1,
        installation_fencing_epoch: 3,
        producer_job_attempt: 1,
    };
    let first = store
        .materialize_expanded_job_set(&request, &signer.verifying_key())
        .await
        .unwrap();
    assert!(first.record_replayed);
    assert_eq!(first.jobs_inserted, 2);
    let replay = store
        .materialize_expanded_job_set(&request, &signer.verifying_key())
        .await
        .unwrap();
    assert!(replay.record_replayed);
    assert_eq!(replay.jobs_inserted, 0);
}
