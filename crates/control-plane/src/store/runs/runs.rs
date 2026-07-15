use super::*;
use rusqlite::params;

pub(in crate::store) fn validate_create_run(
    request: &CreateRunRequest,
) -> Result<(), ControlPlaneError> {
    validate_text("run.id", &request.id)?;
    validate_text("run.repository_id", &request.repository_id)?;
    validate_text("run.capsule_id", &request.capsule_id)?;
    if !(MIN_RUN_PRIORITY..=MAX_RUN_PRIORITY).contains(&request.priority) {
        return Err(ControlPlaneError::InvalidInput(
            "run priority must be between -1000 and 1000",
        ));
    }
    if request.jobs.is_empty() {
        return Err(ControlPlaneError::InvalidInput("run must contain jobs"));
    }
    let mut ids = BTreeSet::new();
    for job in &request.jobs {
        validate_text("job.id", &job.id)?;
        validate_text("job.job_key", &job.job_key)?;
        if job.attempt == 0 || !ids.insert(job.id.as_str()) {
            return Err(ControlPlaneError::InvalidInput(
                "job ids must be unique and attempts must start at one",
            ));
        }
    }
    Ok(())
}

pub(in crate::store) fn planned_scheduling_requirements(
    planned: &runtrue_workflow_ir::PlannedJob,
) -> SchedulingRequirements {
    SchedulingRequirements {
        os: planned.runner.os,
        arch: planned.runner.arch,
        isolation: planned.runner.isolation,
        cpu: u32::from(planned.runner.cpu),
        memory_bytes: planned.runner.memory_bytes,
        storage_bytes: planned.runner.storage_bytes.unwrap_or(0),
        region: planned.runner.region.clone(),
        required_capabilities: planned.runner.capabilities.iter().cloned().collect(),
        // Pool admission is policy state. Until it becomes part of the signed
        // capsule, callers may not inject it through a run request.
        allowed_pools: BTreeSet::new(),
    }
}

pub(in crate::store) fn validate_run_jobs(
    capsule: &ExecutionCapsule,
    request: &CreateRunRequest,
) -> Result<(), ControlPlaneError> {
    if capsule.jobs.len() != request.jobs.len() {
        return Err(ControlPlaneError::InvalidInput(
            "SCM run jobs do not match the signed capsule",
        ));
    }
    for (planned, requested) in capsule.jobs.iter().zip(&request.jobs) {
        let expected = planned_scheduling_requirements(planned);
        if requested.job_key != planned.id
            || requested.attempt != 1
            || requested.requirements != expected
        {
            return Err(ControlPlaneError::InvalidInput(
                "SCM run jobs do not match the signed capsule",
            ));
        }
    }
    Ok(())
}

pub(in crate::store) fn validate_scm_prepared_execution(
    execution: &PreparedScmExecution,
    capsule: &ExecutionCapsule,
) -> Result<(), ControlPlaneError> {
    if execution.metadata.capsule_id != execution.capsule.id
        || execution.metadata.risk_score > 100
        || execution.run.capsule_id != execution.capsule.id
        || execution.run.repository_id != execution.capsule.repository_id
        || execution.run.created_unix_ms != execution.capsule.created_unix_ms
        || !execution.run.remote
    {
        return Err(ControlPlaneError::InvalidInput(
            "SCM capsule, metadata, and exact remote run do not match",
        ));
    }
    validate_run_jobs(capsule, &execution.run)?;
    match (
        &capsule.context.source_tree_digest,
        &execution.source_snapshot,
    ) {
        (None, None) => {}
        (Some(expected), Some(snapshot))
            if snapshot.repository_id == execution.capsule.repository_id
                && snapshot.commit_sha == capsule.context.source_commit
                && snapshot.tree_manifest_digest == *expected
                && snapshot.state == SourceSnapshotState::Ready
                && snapshot.verified_unix_ms.is_some() => {}
        _ => {
            return Err(ControlPlaneError::InvalidInput(
                "SCM source snapshot does not match the signed capsule",
            ))
        }
    }
    if execution.source_snapshot.is_some() != execution.scm_fetch_id.is_some() {
        return Err(ControlPlaneError::InvalidInput(
            "SCM source snapshot and fetch journal must be bound together",
        ));
    }
    validate_exact_capsule_approvals(capsule, &execution.metadata, &execution.approvals)?;
    let gated = capsule.approval.workflow_definition || capsule.approval.privileged_execution;
    if gated != execution.continuation.is_some() {
        return Err(ControlPlaneError::InvalidInput(
            "SCM continuation must exist exactly when its capsule is gated",
        ));
    }
    if let Some(context) = &execution.continuation {
        validate_text("SCM pending execution id", &context.pending_execution_id)?;
        validate_scm_source_identity(&context.source_identity)?;
        if !context.event.is_object()
            || context.source_identity.normalized_event_digest
                != capsule.context.normalized_event_digest
            || context.source_identity.source_commit != capsule.context.source_commit
            || context.source_identity.base_commit != capsule.context.base_commit
            || context.source_identity.workflow_path != capsule.workflow.source_path
            || context.source_identity.policy_version_ids != capsule.context.policy_version_ids
            || context.source_snapshot_id
                != execution
                    .source_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.id.clone())
            || context.role == ScmExecutionRole::ProposedDefinition
                && context
                    .source_identity
                    .proposed_approval_subject_digest
                    .as_ref()
                    != Some(&execution.metadata.approval_subject_digest)
            || context.role != ScmExecutionRole::ProposedDefinition
                && capsule.approval.workflow_definition
        {
            return Err(ControlPlaneError::InvalidInput(
                "SCM continuation identities do not match the signed capsule",
            ));
        }
        bounded_scm_json(context)?;
    }
    Ok(())
}

pub(in crate::store) fn run_conn(
    connection: &Connection,
    id: &str,
) -> Result<RunRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, repository_id, capsule_id, status, priority, remote, created_unix_ms,
                    started_unix_ms, completed_unix_ms, cancel_reason
             FROM runs WHERE id = ?1",
            [id],
            run_row,
        )
        .optional()?
        .ok_or_else(|| not_found("run", id))
}

pub(in crate::store) fn run_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<RunRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, repository_id, capsule_id, status, priority, remote, created_unix_ms,
                    started_unix_ms, completed_unix_ms, cancel_reason
             FROM runs WHERE id = ?1",
            [id],
            run_row,
        )
        .optional()?
        .ok_or_else(|| not_found("run", id))
}

pub(in crate::store) fn run_row(row: &Row<'_>) -> rusqlite::Result<RunRecord> {
    let status: String = row.get(3)?;
    Ok(RunRecord {
        id: row.get(0)?,
        repository_id: row.get(1)?,
        capsule_id: row.get(2)?,
        status: parse_run_state(&status).map_err(|error| conversion(3, error))?,
        priority: row.get(4)?,
        remote: row.get(5)?,
        created_unix_ms: u64_column(row, 6, "created_unix_ms")?,
        started_unix_ms: optional_u64_column(row, 7, "started_unix_ms")?,
        completed_unix_ms: optional_u64_column(row, 8, "completed_unix_ms")?,
        cancel_reason: row.get(9)?,
    })
}

impl ControlPlane {
    pub fn create_run_idempotent(
        &self,
        idempotency_key: &str,
        request: &CreateRunRequest,
    ) -> Result<IdempotentResult<RunRecord>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        validate_create_run(request)?;
        let request_hash = create_run_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, "run.create", idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = run_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }

        let (capsule_repository, canonical_capsule): (String, Vec<u8>) = transaction
            .query_row(
                "SELECT repository_id, canonical_capsule FROM capsules WHERE id = ?1",
                [&request.capsule_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| not_found("capsule", &request.capsule_id))?;
        if capsule_repository != request.repository_id {
            return Err(ControlPlaneError::InvalidInput(
                "capsule does not belong to the requested repository",
            ));
        }
        let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
        if request.remote {
            validate_run_jobs(&capsule, request)?;
        }
        let mut authorized_approvals = Vec::new();
        if capsule.approval.workflow_definition || capsule.approval.privileged_execution {
            let subject_digest: Option<String> = transaction
                .query_row(
                    "SELECT approval_subject_digest FROM capsule_api_metadata WHERE capsule_id = ?1",
                    [&request.capsule_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(subject_digest) = subject_digest else {
                return Err(ControlPlaneError::ApprovalRequired);
            };
            let subject_digest = ContentDigest::parse(subject_digest)?;
            if capsule.approval.workflow_definition {
                authorized_approvals.push(authorize_required_approval_tx(
                    &transaction,
                    &request.capsule_id,
                    &subject_digest,
                    runtrue_policy::ApprovalKind::WorkflowDefinition,
                    request.created_unix_ms,
                )?);
            }
            if capsule.approval.privileged_execution {
                authorized_approvals.push(authorize_required_approval_tx(
                    &transaction,
                    &request.capsule_id,
                    &subject_digest,
                    runtrue_policy::ApprovalKind::PrivilegedExecution,
                    request.created_unix_ms,
                )?);
            }
        }
        transaction.execute(
            "INSERT INTO runs
             (id, repository_id, capsule_id, status, priority, remote, created_unix_ms)
             VALUES (?1, ?2, ?3, 'created', ?4, ?5, ?6)",
            params![
                request.id,
                request.repository_id,
                request.capsule_id,
                request.priority,
                request.remote,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        for authorization in authorized_approvals {
            transaction.execute(
                "INSERT INTO run_approval_authorizations
                 (run_id, approval_id, kind, subject_digest, one_shot,
                  authorized_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    request.id,
                    authorization.approval_id,
                    approval_kind_name(authorization.kind),
                    authorization.subject_digest.as_str(),
                    authorization.one_shot,
                    to_i64(request.created_unix_ms)?,
                ],
            )?;
        }
        if request.remote {
            insert_jobs_for_capsule_tx(&transaction, request, &capsule)?;
        } else {
            insert_jobs_tx(&transaction, request)?;
        }
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES ('run.create', ?1, ?2, ?3, ?4)",
            params![
                idempotency_key,
                request_hash.as_str(),
                request.id,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        let value = run_tx(&transaction, &request.id)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value,
            replayed: false,
        })
    }
}
