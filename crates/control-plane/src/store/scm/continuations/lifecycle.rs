// Approval continuation lifecycle dependencies are explicit.
use super::super::{
    approval_kind_name, authorize_required_approval_tx, bind_run_source_snapshot_tx,
    capsule_api_metadata_tx, close_pending_execution_tx, enqueue_initial_scm_check_task_tx,
    insert_jobs_for_capsule_tx, insert_run_tx, mark_task_completed_tx, not_found, params,
    pending_approvals_conn, pending_resolution_state, refresh_pending_approvals_tx,
    require_not_safe_mode_tx, require_scm_continuation_task_tx, run_tx, scm_pending_execution_conn,
    scm_pending_execution_tx, scm_proposed_analysis_row, signed_capsule_tx, source_snapshot_tx,
    to_i64, validate_create_run, validate_run_jobs, validate_signed_capsule, validate_text,
    ApprovalRequest, ApprovalStatus, CapsuleApiMetadata, CapsuleVerifyingKey, ControlPlane,
    ControlPlaneError, CreateRunRequest, ExecutionCapsule, IdempotentResult,
    PendingApprovalResolution, PreparedScmExecution, ScmContinuationCommit, ScmContinuationContext,
    ScmContinuationResolution, ScmPendingExecution, ScmPendingExecutionState,
    ScmProposedAnalysisRecord, SignedCapsuleRecord, TransactionBehavior,
};
use rusqlite::OptionalExtension as _;

impl ControlPlane {
    pub fn scm_pending_execution(
        &self,
        id: &str,
    ) -> Result<ScmPendingExecution, ControlPlaneError> {
        validate_text("SCM pending execution id", id)?;
        let connection = self.connection()?;
        scm_pending_execution_conn(&connection, id)
    }

    pub fn scm_proposed_analysis_for_task(
        &self,
        task_id: &str,
    ) -> Result<ScmProposedAnalysisRecord, ControlPlaneError> {
        validate_text("SCM origin task id", task_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, origin_task_id, repository_id, status,
                        source_identity_json, analysis_json, failure,
                        proposed_capsule_id, created_unix_ms
                 FROM scm_proposed_analyses WHERE origin_task_id = ?1",
                [task_id],
                scm_proposed_analysis_row,
            )
            .optional()?
            .ok_or_else(|| not_found("SCM proposed analysis", task_id))
    }

    pub fn scm_pending_execution_approvals(
        &self,
        id: &str,
    ) -> Result<Vec<ApprovalRequest>, ControlPlaneError> {
        validate_text("SCM pending execution id", id)?;
        let connection = self.connection()?;
        let pending = scm_pending_execution_conn(&connection, id)?;
        pending_approvals_conn(&connection, &pending)
    }

    /// Resolve the database-only part of an approval continuation before the
    /// worker performs repository I/O. Non-ready tasks are completed here;
    /// ready tasks remain leased and are rechecked by the final commit.
    pub fn begin_scm_continuation(
        &self,
        task_id: &str,
        worker: &str,
        pending_execution_id: &str,
        now_unix_ms: u64,
    ) -> Result<ScmContinuationResolution, ControlPlaneError> {
        validate_text("task.id", task_id)?;
        validate_text("task.worker", worker)?;
        validate_text("SCM pending execution id", pending_execution_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_scm_continuation_task_tx(
            &transaction,
            task_id,
            worker,
            pending_execution_id,
            now_unix_ms,
        )?;
        require_not_safe_mode_tx(&transaction)?;
        let mut pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
        match pending.state {
            ScmPendingExecutionState::RunCreated => {
                let run_id = pending.run_id.as_deref().ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "completed SCM continuation is missing its run".to_owned(),
                    )
                })?;
                let run = run_tx(&transaction, run_id)?;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(ScmContinuationResolution::RunCreated(run));
            }
            ScmPendingExecutionState::Denied
            | ScmPendingExecutionState::Expired
            | ScmPendingExecutionState::Stale => {
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(ScmContinuationResolution::Closed(pending));
            }
            ScmPendingExecutionState::AwaitingApproval
            | ScmPendingExecutionState::ContinuationPending => {}
        }

        let approvals = refresh_pending_approvals_tx(&transaction, &pending, now_unix_ms)?;
        let next = pending_resolution_state(&approvals, now_unix_ms, pending.expires_unix_ms);
        match next {
            PendingApprovalResolution::Ready => {
                transaction.commit()?;
                Ok(ScmContinuationResolution::Ready(pending))
            }
            PendingApprovalResolution::Waiting => {
                transaction.execute(
                    "UPDATE scm_pending_executions
                     SET state = 'awaiting-approval' WHERE id = ?1",
                    [pending_execution_id],
                )?;
                pending.state = ScmPendingExecutionState::AwaitingApproval;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                Ok(ScmContinuationResolution::Waiting(pending))
            }
            PendingApprovalResolution::Denied | PendingApprovalResolution::Expired => {
                let state = if next == PendingApprovalResolution::Denied {
                    ScmPendingExecutionState::Denied
                } else {
                    ScmPendingExecutionState::Expired
                };
                close_pending_execution_tx(
                    &transaction,
                    pending_execution_id,
                    state,
                    None,
                    now_unix_ms,
                )?;
                pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                Ok(ScmContinuationResolution::Closed(pending))
            }
            PendingApprovalResolution::Stale => {
                close_pending_execution_tx(
                    &transaction,
                    pending_execution_id,
                    ScmPendingExecutionState::Stale,
                    Some("approval was consumed outside its exact SCM continuation"),
                    now_unix_ms,
                )?;
                pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                Ok(ScmContinuationResolution::Closed(pending))
            }
        }
    }

    /// Close a claimed continuation after trusted re-planning detects changed
    /// policy, source identities, canonical capsule, or exact run/job request.
    pub fn close_scm_continuation_as_stale(
        &self,
        task_id: &str,
        worker: &str,
        pending_execution_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<ScmPendingExecution, ControlPlaneError> {
        validate_text("SCM stale reason", reason)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_scm_continuation_task_tx(
            &transaction,
            task_id,
            worker,
            pending_execution_id,
            now_unix_ms,
        )?;
        require_not_safe_mode_tx(&transaction)?;
        let pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
        if matches!(
            pending.state,
            ScmPendingExecutionState::AwaitingApproval
                | ScmPendingExecutionState::ContinuationPending
        ) {
            close_pending_execution_tx(
                &transaction,
                pending_execution_id,
                ScmPendingExecutionState::Stale,
                Some(reason),
                now_unix_ms,
            )?;
        }
        mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
        let pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
        transaction.commit()?;
        Ok(pending)
    }

    /// Atomically recheck every independent approval, consume/link it for the
    /// exact run, create jobs, close the pending state, and complete the
    /// continuation task. Races converge on the already-created run or a
    /// safely closed pending record.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_scm_continuation_with_run_idempotent(
        &self,
        task_id: &str,
        worker: &str,
        pending_execution_id: &str,
        now_unix_ms: u64,
        replanned: &SignedCapsuleRecord,
        verifying_key: &CapsuleVerifyingKey,
        metadata: &CapsuleApiMetadata,
        context: &ScmContinuationContext,
        run: &CreateRunRequest,
    ) -> Result<ScmContinuationCommit, ControlPlaneError> {
        validate_text("task.id", task_id)?;
        validate_text("task.worker", worker)?;
        validate_text("SCM pending execution id", pending_execution_id)?;
        validate_create_run(run)?;
        let supplied_signature = validate_signed_capsule(replanned, verifying_key)?;
        let supplied_capsule: ExecutionCapsule =
            serde_json::from_slice(&replanned.canonical_capsule)?;
        validate_run_jobs(&supplied_capsule, run)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_scm_continuation_task_tx(
            &transaction,
            task_id,
            worker,
            pending_execution_id,
            now_unix_ms,
        )?;
        require_not_safe_mode_tx(&transaction)?;
        let mut pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
        match pending.state {
            ScmPendingExecutionState::RunCreated => {
                let run_id = pending.run_id.as_deref().ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "completed SCM continuation is missing its run".to_owned(),
                    )
                })?;
                let record = run_tx(&transaction, run_id)?;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(ScmContinuationCommit::Run(IdempotentResult {
                    value: record,
                    replayed: true,
                }));
            }
            ScmPendingExecutionState::Denied
            | ScmPendingExecutionState::Expired
            | ScmPendingExecutionState::Stale => {
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(ScmContinuationCommit::Closed(pending));
            }
            ScmPendingExecutionState::AwaitingApproval
            | ScmPendingExecutionState::ContinuationPending => {}
        }

        let approvals = refresh_pending_approvals_tx(&transaction, &pending, now_unix_ms)?;
        match pending_resolution_state(&approvals, now_unix_ms, pending.expires_unix_ms) {
            PendingApprovalResolution::Waiting => {
                transaction.execute(
                    "UPDATE scm_pending_executions
                     SET state = 'awaiting-approval' WHERE id = ?1",
                    [pending_execution_id],
                )?;
                pending.state = ScmPendingExecutionState::AwaitingApproval;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(ScmContinuationCommit::Waiting(pending));
            }
            PendingApprovalResolution::Denied | PendingApprovalResolution::Expired => {
                let state = if approvals
                    .iter()
                    .any(|approval| approval.status == ApprovalStatus::Denied)
                {
                    ScmPendingExecutionState::Denied
                } else {
                    ScmPendingExecutionState::Expired
                };
                close_pending_execution_tx(
                    &transaction,
                    pending_execution_id,
                    state,
                    None,
                    now_unix_ms,
                )?;
                pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(ScmContinuationCommit::Closed(pending));
            }
            PendingApprovalResolution::Stale => {
                close_pending_execution_tx(
                    &transaction,
                    pending_execution_id,
                    ScmPendingExecutionState::Stale,
                    Some("approval was consumed outside its exact SCM continuation"),
                    now_unix_ms,
                )?;
                pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(ScmContinuationCommit::Closed(pending));
            }
            PendingApprovalResolution::Ready => {}
        }

        let stored_capsule = signed_capsule_tx(&transaction, &pending.capsule_id)?;
        let stored_signature = serde_json::to_string(&stored_capsule.signature)?;
        let stored_metadata = capsule_api_metadata_tx(&transaction, &pending.capsule_id)?;
        let exact_match = stored_capsule.id == replanned.id
            && stored_capsule.repository_id == replanned.repository_id
            && stored_capsule.digest == replanned.digest
            && stored_capsule.canonical_capsule == replanned.canonical_capsule
            && stored_capsule.created_unix_ms == replanned.created_unix_ms
            && stored_signature == supplied_signature
            && &stored_metadata == metadata
            && &pending.context == context
            && &pending.run == run
            && context.pending_execution_id == pending.id;
        if !exact_match {
            close_pending_execution_tx(
                &transaction,
                pending_execution_id,
                ScmPendingExecutionState::Stale,
                Some("re-planned SCM subject or run request changed"),
                now_unix_ms,
            )?;
            pending = scm_pending_execution_tx(&transaction, pending_execution_id)?;
            mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
            transaction.commit()?;
            return Ok(ScmContinuationCommit::Closed(pending));
        }

        let mut authorized_approvals = Vec::new();
        if supplied_capsule.approval.workflow_definition {
            authorized_approvals.push(authorize_required_approval_tx(
                &transaction,
                &pending.capsule_id,
                &metadata.approval_subject_digest,
                runtrue_policy::ApprovalKind::WorkflowDefinition,
                now_unix_ms,
            )?);
        }
        if supplied_capsule.approval.privileged_execution {
            authorized_approvals.push(authorize_required_approval_tx(
                &transaction,
                &pending.capsule_id,
                &metadata.approval_subject_digest,
                runtrue_policy::ApprovalKind::PrivilegedExecution,
                now_unix_ms,
            )?);
        }
        insert_run_tx(&transaction, run)?;
        if let Some(snapshot_id) = &context.source_snapshot_id {
            let tenant_id: String = transaction.query_row(
                "SELECT tenant_id FROM repositories WHERE id = ?1",
                [&run.repository_id],
                |row| row.get(0),
            )?;
            let snapshot = source_snapshot_tx(&transaction, &tenant_id, snapshot_id)?;
            bind_run_source_snapshot_tx(
                &transaction,
                run,
                &snapshot,
                &replanned.digest,
                &supplied_capsule,
                now_unix_ms,
            )?;
        }
        for authorization in authorized_approvals {
            transaction.execute(
                "INSERT INTO run_approval_authorizations
                 (run_id, approval_id, kind, subject_digest, one_shot,
                  authorized_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    run.id,
                    authorization.approval_id,
                    approval_kind_name(authorization.kind),
                    authorization.subject_digest.as_str(),
                    authorization.one_shot,
                    to_i64(now_unix_ms)?,
                ],
            )?;
        }
        insert_jobs_for_capsule_tx(&transaction, run, &supplied_capsule)?;
        let check_execution = PreparedScmExecution {
            capsule: replanned.clone(),
            metadata: metadata.clone(),
            approvals: Vec::new(),
            run: run.clone(),
            continuation: Some(context.clone()),
            source_snapshot: None,
            scm_fetch_id: None,
        };
        enqueue_initial_scm_check_task_tx(
            &transaction,
            &context.event,
            &check_execution,
            now_unix_ms,
        )?;
        transaction.execute(
            "UPDATE scm_pending_executions
             SET state = 'run-created', run_id = ?2, completed_unix_ms = ?3
             WHERE id = ?1",
            params![pending_execution_id, run.id, to_i64(now_unix_ms)?],
        )?;
        mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
        let record = run_tx(&transaction, &run.id)?;
        transaction.commit()?;
        Ok(ScmContinuationCommit::Run(IdempotentResult {
            value: record,
            replayed: false,
        }))
    }
}
