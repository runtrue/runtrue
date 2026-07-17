// Initial SCM task completion dependencies are explicit.
use super::super::{
    append_audit_event_tx, approval_id_for_kind, bind_run_source_snapshot_tx, bounded_scm_json,
    create_run_request_hash, enqueue_initial_scm_check_task_tx,
    enqueue_proposed_workflow_check_task_tx, enqueue_scm_expiry_task_tx, hash_serializable,
    idempotency_tx, insert_capsule_metadata_tx, insert_jobs_for_capsule_tx,
    insert_or_reuse_scm_approval_tx, insert_run_and_jobs_for_capsule_tx, insert_run_tx,
    insert_signed_capsule_tx, mark_task_completed_tx, params, require_same_idempotency,
    require_task_owner_tx, run_tx, scm_analysis_status_name, scm_execution_role_name, task_tx,
    to_i64, validate_create_run, validate_idempotency_key, validate_run_jobs,
    validate_scm_analysis, validate_scm_prepared_execution, validate_signed_capsule, validate_text,
    ApprovalRequest, AuditEventData, AuditPrincipal, AuditResource, AuditValue, BTreeMap, BTreeSet,
    CapsuleApiMetadata, CapsuleVerifyingKey, ContentDigest, ControlPlane, ControlPlaneError,
    CreateRunRequest, ExecutionCapsule, IdempotentResult, PreparedScmExecution, RunRecord,
    ScmContinuationContext, ScmExecutionRole, ScmProposedAnalysisRecord, ScmTaskCompletion,
    Serialize, SignedCapsuleRecord, SourceSnapshotRecord, TransactionBehavior,
    MAX_SCM_EXECUTIONS_PER_EVENT,
};
use rusqlite::OptionalExtension as _;

impl ControlPlane {
    /// Atomically commit the trusted output of one claimed SCM task.
    ///
    /// Capsule storage, API metadata, remote run/job creation, idempotency, and
    /// durable task completion share one immediate SQLite transaction. A
    /// worker crash can therefore expose either all of the result or none of
    /// it. Restore safe mode and task lease ownership are checked inside that
    /// same transaction immediately before any result is written.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_scm_task_with_run_idempotent(
        &self,
        task_id: &str,
        worker: &str,
        now_unix_ms: u64,
        idempotency_key: &str,
        capsule: &SignedCapsuleRecord,
        verifying_key: &CapsuleVerifyingKey,
        metadata: &CapsuleApiMetadata,
        request: &CreateRunRequest,
    ) -> Result<IdempotentResult<RunRecord>, ControlPlaneError> {
        validate_text("task.id", task_id)?;
        validate_text("task.worker", worker)?;
        validate_idempotency_key(idempotency_key)?;
        validate_create_run(request)?;
        let signature_json = validate_signed_capsule(capsule, verifying_key)?;
        let decoded_capsule: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule)?;
        if metadata.capsule_id != capsule.id
            || metadata.risk_score > 100
            || request.capsule_id != capsule.id
            || request.repository_id != capsule.repository_id
            || request.created_unix_ms != capsule.created_unix_ms
            || !request.remote
        {
            return Err(ControlPlaneError::InvalidInput(
                "SCM capsule, metadata, and remote run do not match",
            ));
        }
        if decoded_capsule.approval.workflow_definition
            || decoded_capsule.approval.privileged_execution
        {
            return Err(ControlPlaneError::ApprovalRequired);
        }
        validate_run_jobs(&decoded_capsule, request)?;

        #[derive(Serialize)]
        struct ScmRunSubject<'a> {
            repository_id: &'a str,
            capsule_digest: &'a ContentDigest,
            approval_subject_digest: &'a ContentDigest,
            risk_score: u32,
            run_request_digest: ContentDigest,
        }
        let request_hash = hash_serializable(&ScmRunSubject {
            repository_id: &capsule.repository_id,
            capsule_digest: &capsule.digest,
            approval_subject_digest: &metadata.approval_subject_digest,
            risk_score: metadata.risk_score,
            run_request_digest: create_run_request_hash(request)?,
        })?;
        const OPERATION: &str = "scm.event.run.create";

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = task_tx(&transaction, task_id)?;
        require_task_owner_tx(&transaction, task_id, worker, now_unix_ms)?;
        if task.kind != "scm.event" {
            return Err(ControlPlaneError::InvalidInput(
                "SCM result can complete only an scm.event task",
            ));
        }
        let safe_mode: bool = transaction.query_row(
            "SELECT safe_mode FROM installation_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if safe_mode {
            return Err(ControlPlaneError::InstallationSafeMode);
        }

        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, OPERATION, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = run_tx(&transaction, &resource_id)?;
            mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }

        transaction.execute(
            "INSERT INTO capsules
             (id, repository_id, digest, canonical_capsule, signature_json, key_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                capsule.id,
                capsule.repository_id,
                capsule.digest.as_str(),
                capsule.canonical_capsule,
                signature_json,
                capsule.signature.key_id.as_str(),
                to_i64(capsule.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO capsule_api_metadata(capsule_id, approval_subject_digest, risk_score)
             VALUES (?1, ?2, ?3)",
            params![
                capsule.id,
                metadata.approval_subject_digest.as_str(),
                metadata.risk_score,
            ],
        )?;
        insert_run_and_jobs_for_capsule_tx(&transaction, request, &decoded_capsule)?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                OPERATION,
                idempotency_key,
                request_hash.as_str(),
                request.id,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
        let value = run_tx(&transaction, &request.id)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value,
            replayed: false,
        })
    }

    /// Atomically commit every result of one trusted SCM planning pass.
    ///
    /// An event may produce an immediate trusted-base run and, independently,
    /// a signed proposed-definition candidate awaiting exact approvals. Capsules,
    /// metadata, approval requests, proposed analysis, pending continuations,
    /// any gate-free run/jobs, and task completion are one transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_scm_task_with_executions_idempotent(
        &self,
        task_id: &str,
        worker: &str,
        now_unix_ms: u64,
        idempotency_key: &str,
        executions: &[PreparedScmExecution],
        analysis: Option<&ScmProposedAnalysisRecord>,
        verifying_key: &CapsuleVerifyingKey,
    ) -> Result<IdempotentResult<ScmTaskCompletion>, ControlPlaneError> {
        validate_text("task.id", task_id)?;
        validate_text("task.worker", worker)?;
        validate_idempotency_key(idempotency_key)?;
        if executions.is_empty() || executions.len() > MAX_SCM_EXECUTIONS_PER_EVENT {
            return Err(ControlPlaneError::InvalidInput(
                "SCM event must produce one or two bounded executions",
            ));
        }

        let mut signatures = Vec::with_capacity(executions.len());
        let mut decoded_capsules = Vec::with_capacity(executions.len());
        let mut capsule_ids = BTreeSet::new();
        let mut run_ids = BTreeSet::new();
        let mut pending_ids = BTreeSet::new();
        for execution in executions {
            if !capsule_ids.insert(execution.capsule.id.clone())
                || !run_ids.insert(execution.run.id.clone())
            {
                return Err(ControlPlaneError::InvalidInput(
                    "SCM executions must have distinct capsule and run identities",
                ));
            }
            validate_create_run(&execution.run)?;
            let signature_json = validate_signed_capsule(&execution.capsule, verifying_key)?;
            let decoded_capsule: ExecutionCapsule =
                serde_json::from_slice(&execution.capsule.canonical_capsule)?;
            validate_scm_prepared_execution(execution, &decoded_capsule)?;
            if let Some(context) = &execution.continuation {
                if !pending_ids.insert(context.pending_execution_id.clone()) {
                    return Err(ControlPlaneError::InvalidInput(
                        "SCM pending execution identities must be distinct",
                    ));
                }
            }
            signatures.push(signature_json);
            decoded_capsules.push(decoded_capsule);
        }
        validate_scm_analysis(task_id, executions, analysis)?;

        #[derive(Serialize)]
        struct ExecutionSubject<'a> {
            capsule_id: &'a str,
            repository_id: &'a str,
            capsule_digest: &'a ContentDigest,
            approval_subject_digest: &'a ContentDigest,
            risk_score: u32,
            run_request_digest: ContentDigest,
            approvals: &'a [ApprovalRequest],
            continuation: &'a Option<ScmContinuationContext>,
            source_snapshot: &'a Option<SourceSnapshotRecord>,
            scm_fetch_id: &'a Option<String>,
        }
        #[derive(Serialize)]
        struct TaskSubject<'a> {
            executions: Vec<ExecutionSubject<'a>>,
            analysis_digest: Option<ContentDigest>,
        }
        let execution_subjects = executions
            .iter()
            .map(|execution| {
                Ok(ExecutionSubject {
                    capsule_id: &execution.capsule.id,
                    repository_id: &execution.capsule.repository_id,
                    capsule_digest: &execution.capsule.digest,
                    approval_subject_digest: &execution.metadata.approval_subject_digest,
                    risk_score: execution.metadata.risk_score,
                    run_request_digest: create_run_request_hash(&execution.run)?,
                    approvals: &execution.approvals,
                    continuation: &execution.continuation,
                    source_snapshot: &execution.source_snapshot,
                    scm_fetch_id: &execution.scm_fetch_id,
                })
            })
            .collect::<Result<Vec<_>, ControlPlaneError>>()?;
        let analysis_digest = analysis.map(hash_serializable).transpose()?;
        let request_hash = hash_serializable(&TaskSubject {
            executions: execution_subjects,
            analysis_digest,
        })?;
        const OPERATION: &str = "scm.event.complete.v2";

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, encoded)) = transaction
            .query_row(
                "SELECT request_hash, result_json FROM scm_task_results WHERE task_id = ?1",
                [task_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
        {
            let stored_hash = ContentDigest::parse(stored_hash)?;
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value: ScmTaskCompletion = serde_json::from_slice(&encoded)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        let task = task_tx(&transaction, task_id)?;
        require_task_owner_tx(&transaction, task_id, worker, now_unix_ms)?;
        if task.kind != "scm.event" {
            return Err(ControlPlaneError::InvalidInput(
                "SCM planning result can complete only an scm.event task",
            ));
        }
        let safe_mode: bool = transaction.query_row(
            "SELECT safe_mode FROM installation_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if safe_mode {
            return Err(ControlPlaneError::InstallationSafeMode);
        }
        if executions.iter().any(|execution| {
            execution.capsule.created_unix_ms != task.created_unix_ms
                || execution.run.created_unix_ms != task.created_unix_ms
        }) || analysis.is_some_and(|analysis| {
            analysis.origin_task_id != task.id || analysis.created_unix_ms != task.created_unix_ms
        }) {
            return Err(ControlPlaneError::InvalidInput(
                "SCM result timestamps or origin do not match the claimed task",
            ));
        }
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, OPERATION, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            if resource_id != task_id {
                let encoded: Vec<u8> = transaction
                    .query_row(
                        "SELECT result_json FROM scm_task_results WHERE task_id = ?1",
                        [&resource_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or_else(|| {
                        ControlPlaneError::CorruptState(
                            "SCM idempotency record has no matching durable result".to_owned(),
                        )
                    })?;
                let mut value: ScmTaskCompletion = serde_json::from_slice(&encoded)?;
                value.task_id = task_id.to_owned();
                let replay_result = bounded_scm_json(&value)?;
                transaction.execute(
                    "INSERT INTO scm_task_results
                     (task_id, request_hash, result_json, created_unix_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        task_id,
                        request_hash.as_str(),
                        replay_result,
                        to_i64(now_unix_ms)?,
                    ],
                )?;
                mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
                transaction.commit()?;
                return Ok(IdempotentResult {
                    value,
                    replayed: true,
                });
            }
            return Err(ControlPlaneError::CorruptState(
                "SCM idempotency record has no matching durable result".to_owned(),
            ));
        }

        let mut immediate_run_ids = Vec::new();
        let mut durable_pending_ids = Vec::new();
        for ((execution, signature_json), decoded_capsule) in executions
            .iter()
            .zip(signatures.iter())
            .zip(decoded_capsules.iter())
        {
            insert_signed_capsule_tx(&transaction, &execution.capsule, signature_json)?;
            insert_capsule_metadata_tx(&transaction, &execution.metadata)?;
            let mut effective_approvals = Vec::with_capacity(execution.approvals.len());
            for approval in &execution.approvals {
                effective_approvals.push(insert_or_reuse_scm_approval_tx(
                    &transaction,
                    &execution.capsule.repository_id,
                    &execution.capsule.id,
                    approval,
                    now_unix_ms,
                )?);
            }
            if execution.approvals.is_empty() {
                insert_run_tx(&transaction, &execution.run)?;
                if let Some(snapshot) = &execution.source_snapshot {
                    bind_run_source_snapshot_tx(
                        &transaction,
                        &execution.run,
                        snapshot,
                        &execution.capsule.digest,
                        decoded_capsule,
                        now_unix_ms,
                    )?;
                }
                insert_jobs_for_capsule_tx(&transaction, &execution.run, decoded_capsule)?;
                enqueue_initial_scm_check_task_tx(
                    &transaction,
                    &task.payload,
                    execution,
                    now_unix_ms,
                )?;
                immediate_run_ids.push(execution.run.id.clone());
            } else {
                let context =
                    execution
                        .continuation
                        .as_ref()
                        .ok_or(ControlPlaneError::InvalidInput(
                            "gated SCM execution is missing its continuation context",
                        ))?;
                let workflow_approval_id = approval_id_for_kind(
                    &effective_approvals,
                    runtrue_policy::ApprovalKind::WorkflowDefinition,
                );
                let privileged_approval_id = approval_id_for_kind(
                    &effective_approvals,
                    runtrue_policy::ApprovalKind::PrivilegedExecution,
                );
                let expires_unix_ms = effective_approvals
                    .iter()
                    .map(|approval| approval.expires_unix_ms)
                    .min()
                    .ok_or(ControlPlaneError::ApprovalRequired)?;
                transaction.execute(
                    "INSERT INTO scm_pending_executions
                     (id, origin_task_id, repository_id, capsule_id, role, state,
                      context_json, run_request_json, workflow_approval_id,
                      privileged_approval_id, created_unix_ms, expires_unix_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'awaiting-approval', ?6, ?7,
                             ?8, ?9, ?10, ?11)",
                    params![
                        context.pending_execution_id,
                        task_id,
                        execution.capsule.repository_id,
                        execution.capsule.id,
                        scm_execution_role_name(context.role),
                        bounded_scm_json(context)?,
                        bounded_scm_json(&execution.run)?,
                        workflow_approval_id,
                        privileged_approval_id,
                        to_i64(task.created_unix_ms)?,
                        to_i64(expires_unix_ms)?,
                    ],
                )?;
                enqueue_scm_expiry_task_tx(
                    &transaction,
                    &context.pending_execution_id,
                    workflow_approval_id
                        .or(privileged_approval_id)
                        .ok_or(ControlPlaneError::ApprovalRequired)?,
                    task.created_unix_ms,
                    expires_unix_ms,
                )?;
                durable_pending_ids.push(context.pending_execution_id.clone());
                if effective_approvals
                    .iter()
                    .all(|approval| approval.status == runtrue_policy::ApprovalStatus::Approved)
                {
                    super::enqueue_preapproved_scm_continuation_tx(
                        &transaction,
                        &context.pending_execution_id,
                        workflow_approval_id
                            .or(privileged_approval_id)
                            .ok_or(ControlPlaneError::ApprovalRequired)?,
                        now_unix_ms,
                    )?;
                }
            }
            // Keep this explicit assertion next to the insert boundary: no
            // gated capsule may accidentally take the immediate path.
            if !(execution.approvals.is_empty()
                || decoded_capsule.approval.workflow_definition
                || decoded_capsule.approval.privileged_execution)
            {
                return Err(ControlPlaneError::CorruptState(
                    "SCM approval validation diverged before commit".to_owned(),
                ));
            }
        }

        let proposed = executions.iter().find(|execution| {
            execution
                .continuation
                .as_ref()
                .is_some_and(|context| context.role == ScmExecutionRole::ProposedDefinition)
        });
        if let Some(proposed) = proposed {
            // Provider-backed changed-workflow planning emits a trusted-base
            // execution beside the gated proposal. Database-only callers may
            // intentionally persist a standalone proposal and have no remote
            // check surface to update.
            if let Some(trusted) = executions
                .iter()
                .find(|execution| execution.approvals.is_empty())
            {
                let approval = proposed
                    .approvals
                    .iter()
                    .find(|approval| {
                        approval.kind == runtrue_policy::ApprovalKind::WorkflowDefinition
                    })
                    .ok_or(ControlPlaneError::CorruptState(
                        "proposed workflow has no workflow-definition approval".to_owned(),
                    ))?;
                enqueue_proposed_workflow_check_task_tx(
                    &transaction,
                    &task.payload,
                    trusted,
                    proposed,
                    approval,
                    analysis,
                    now_unix_ms,
                )?;
            }
        }

        if let Some(analysis) = analysis {
            transaction.execute(
                "INSERT INTO scm_proposed_analyses
                 (id, origin_task_id, repository_id, status, source_identity_json,
                  analysis_json, failure, proposed_capsule_id, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    analysis.id,
                    analysis.origin_task_id,
                    analysis.repository_id,
                    scm_analysis_status_name(analysis.status),
                    bounded_scm_json(&analysis.source_identity)?,
                    analysis
                        .analysis
                        .as_ref()
                        .map(bounded_scm_json)
                        .transpose()?,
                    analysis.failure,
                    analysis.proposed_capsule_id,
                    to_i64(analysis.created_unix_ms)?,
                ],
            )?;
        }
        let fetch_ids = executions
            .iter()
            .filter_map(|execution| execution.scm_fetch_id.as_deref())
            .collect::<BTreeSet<_>>();
        if fetch_ids.len() > 1 {
            return Err(ControlPlaneError::InvalidInput(
                "one SCM event cannot commit multiple source fetches",
            ));
        }
        if let Some(fetch_id) = fetch_ids.first() {
            let repository_id = &executions[0].capsule.repository_id;
            let normalized_event_digest = &decoded_capsules[0].context.normalized_event_digest;
            let tenant_id: String = transaction.query_row(
                "SELECT tenant_id FROM repositories WHERE id = ?1",
                [repository_id],
                |row| row.get(0),
            )?;
            let changed = transaction.execute(
                "UPDATE scm_source_fetches
                 SET state = 'committed', updated_unix_ms = ?4
                 WHERE id = ?1 AND repository_id = ?2
                   AND normalized_event_digest = ?3
                   AND state IN ('snapshot-ready', 'committed')",
                params![
                    fetch_id,
                    repository_id,
                    normalized_event_digest.as_str(),
                    to_i64(now_unix_ms)?,
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            append_audit_event_tx(
                &transaction,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: now_unix_ms,
                    tenant_id,
                    actor: AuditPrincipal {
                        kind: "scm-worker".to_owned(),
                        id: worker.to_owned(),
                    },
                    action: "scm.source-fetch.commit".to_owned(),
                    resource: AuditResource {
                        kind: "scm-source-fetch".to_owned(),
                        id: (*fetch_id).to_owned(),
                    },
                    result: "success".to_owned(),
                    request_id: task_id.to_owned(),
                    decision_id: None,
                    metadata: BTreeMap::from([
                        (
                            "normalized_event_digest".to_owned(),
                            AuditValue::Digest(normalized_event_digest.clone()),
                        ),
                        (
                            "source_tree_digest".to_owned(),
                            AuditValue::Digest(
                                decoded_capsules[0]
                                    .context
                                    .source_tree_digest
                                    .clone()
                                    .ok_or(ControlPlaneError::InvalidInput(
                                        "SCM source fetch capsule has no tree digest",
                                    ))?,
                            ),
                        ),
                    ]),
                },
            )?;
        }
        immediate_run_ids.sort();
        durable_pending_ids.sort();
        let result = ScmTaskCompletion {
            task_id: task_id.to_owned(),
            run_ids: immediate_run_ids,
            pending_execution_ids: durable_pending_ids,
            proposed_analysis_id: analysis.map(|analysis| analysis.id.clone()),
        };
        let encoded_result = bounded_scm_json(&result)?;
        transaction.execute(
            "INSERT INTO scm_task_results(task_id, request_hash, result_json, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                task_id,
                request_hash.as_str(),
                encoded_result,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                OPERATION,
                idempotency_key,
                request_hash.as_str(),
                task_id,
                to_i64(now_unix_ms)?,
            ],
        )?;
        mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: result,
            replayed: false,
        })
    }
}
