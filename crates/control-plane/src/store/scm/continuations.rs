// Shared SCM pending-state and continuation dependencies are explicit.
use super::{
    approval_status_name, canonicalize_json, conversion, hash_serializable, json_blob_column,
    not_found, optional_u64_column, require_task_owner_tx, task_tx, to_i64, u64_column,
    validate_create_run, validate_text, ApprovalDecision, ApprovalRequest, ApprovalStatus,
    BTreeSet, CapsuleApiMetadata, Connection, ContentDigest, ControlPlaneError, DecodeError,
    ExecutionCapsule, PreparedScmExecution, Row, ScmCheckPublishTask, ScmExecutionRole,
    ScmPendingExecution, ScmPendingExecutionState, ScmProposedAnalysisRecord,
    ScmProposedAnalysisStatus, ScmSourceIdentity, Sha256, Transaction, Value,
    MAX_SCM_CONTINUATIONS_PER_DECISION, MAX_SCM_REUSABLE_IDENTITIES, MAX_SCM_SNAPSHOT_BYTES,
};
use crate::ScmCheckAction;
use rusqlite::params;
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

pub(in crate::store) fn validate_exact_capsule_approvals(
    capsule: &ExecutionCapsule,
    metadata: &CapsuleApiMetadata,
    approvals: &[ApprovalRequest],
    privileged_capability_digest: Option<&ContentDigest>,
) -> Result<(), ControlPlaneError> {
    let workflow = approvals
        .iter()
        .filter(|approval| approval.kind == runtrue_policy::ApprovalKind::WorkflowDefinition)
        .count();
    let privileged = approvals
        .iter()
        .filter(|approval| approval.kind == runtrue_policy::ApprovalKind::PrivilegedExecution)
        .count();
    let expected = usize::from(capsule.approval.workflow_definition)
        + usize::from(capsule.approval.privileged_execution);
    let mut ids = BTreeSet::new();
    if workflow != usize::from(capsule.approval.workflow_definition)
        || privileged != usize::from(capsule.approval.privileged_execution)
        || approvals.len() != expected
    {
        return Err(ControlPlaneError::InvalidInput(
            "capsule approval requests do not match its independent gates",
        ));
    }
    for approval in approvals {
        let expected = ApprovalRequest::create(
            approval.id.clone(),
            approval.kind,
            approval.subject_digest.clone(),
            approval.risk_score,
            approval.created_unix_ms,
            approval.expires_unix_ms,
            approval.rule.clone(),
        )?;
        let expected_subject = if approval.kind == runtrue_policy::ApprovalKind::PrivilegedExecution
        {
            privileged_capability_digest.ok_or(ControlPlaneError::InvalidInput(
                "privileged SCM approval is missing its capability identity",
            ))?
        } else {
            &metadata.approval_subject_digest
        };
        if &expected != approval
            || &approval.subject_digest != expected_subject
            || approval.risk_score != metadata.risk_score
            || !ids.insert(approval.id.as_str())
        {
            return Err(ControlPlaneError::InvalidInput(
                "approval request does not match exact capsule metadata",
            ));
        }
    }
    if capsule.approval.privileged_execution != privileged_capability_digest.is_some() {
        return Err(ControlPlaneError::InvalidInput(
            "SCM privileged capability identity does not match its gate",
        ));
    }
    Ok(())
}

pub(in crate::store) fn validate_scm_source_identity(
    identity: &ScmSourceIdentity,
) -> Result<(), ControlPlaneError> {
    validate_text("SCM source commit", &identity.source_commit)?;
    if let Some(base) = &identity.base_commit {
        validate_text("SCM base commit", base)?;
    }
    validate_text("SCM workflow path", &identity.workflow_path)?;
    if identity.policy_version_ids.is_empty()
        || identity.policy_version_ids.len() > 128
        || identity
            .policy_version_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || identity
            .policy_version_ids
            .iter()
            .any(|value| validate_text("SCM policy version", value).is_err())
        || identity.reusable_workflow_digests.len() > MAX_SCM_REUSABLE_IDENTITIES
        || identity
            .reusable_workflow_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || identity.reusable_workflow_digests.iter().any(|value| {
            validate_text("SCM reusable workflow digest", value).is_err()
                || ContentDigest::parse(value).is_err()
        })
    {
        return Err(ControlPlaneError::InvalidInput(
            "SCM source identity is unbounded or non-canonical",
        ));
    }
    Ok(())
}

pub(in crate::store) fn validate_scm_analysis(
    task_id: &str,
    executions: &[PreparedScmExecution],
    analysis: Option<&ScmProposedAnalysisRecord>,
) -> Result<(), ControlPlaneError> {
    let repository_id = &executions[0].capsule.repository_id;
    if executions
        .iter()
        .any(|execution| &execution.capsule.repository_id != repository_id)
    {
        return Err(ControlPlaneError::InvalidInput(
            "one SCM event cannot span repositories",
        ));
    }
    let Some(analysis) = analysis else {
        return Ok(());
    };
    validate_text("SCM analysis id", &analysis.id)?;
    validate_scm_source_identity(&analysis.source_identity)?;
    if analysis.origin_task_id != task_id || &analysis.repository_id != repository_id {
        return Err(ControlPlaneError::InvalidInput(
            "SCM proposed analysis origin does not match the event",
        ));
    }
    match analysis.status {
        ScmProposedAnalysisStatus::Valid => {
            let Some(capsule_id) = analysis.proposed_capsule_id.as_deref() else {
                return Err(ControlPlaneError::InvalidInput(
                    "valid SCM analysis must name its proposed capsule",
                ));
            };
            let Some(proposed) = executions
                .iter()
                .find(|execution| execution.capsule.id == capsule_id)
            else {
                return Err(ControlPlaneError::InvalidInput(
                    "valid SCM analysis proposed capsule is not in the atomic result",
                ));
            };
            let Some(context) = proposed.continuation.as_ref() else {
                return Err(ControlPlaneError::InvalidInput(
                    "valid proposed SCM capsule must await approval",
                ));
            };
            if context.role != ScmExecutionRole::ProposedDefinition
                || context.analysis_id.as_deref() != Some(analysis.id.as_str())
                || context.source_identity != analysis.source_identity
                || analysis.analysis.is_none()
                || analysis.failure.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "valid SCM analysis does not exactly match its proposed continuation",
                ));
            }
            bounded_scm_json(analysis.analysis.as_ref().expect("checked"))?;
        }
        ScmProposedAnalysisStatus::Invalid => {
            if analysis.proposed_capsule_id.is_some()
                || analysis.analysis.is_some()
                || analysis.failure.as_deref().is_none_or(str::is_empty)
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid SCM analysis must carry only a bounded failure",
                ));
            }
            validate_text(
                "SCM proposed analysis failure",
                analysis.failure.as_deref().expect("checked"),
            )?;
        }
        ScmProposedAnalysisStatus::Deleted => {
            if analysis.proposed_capsule_id.is_some()
                || analysis.analysis.is_some()
                || analysis.failure.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "deleted SCM analysis cannot carry a capsule, risk report, or failure",
                ));
            }
        }
    }
    bounded_scm_json(analysis)?;
    Ok(())
}

pub(in crate::store) fn bounded_scm_json<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, ControlPlaneError> {
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() > MAX_SCM_SNAPSHOT_BYTES {
        return Err(ControlPlaneError::InvalidInput(
            "SCM durable snapshot exceeds its bound",
        ));
    }
    Ok(encoded)
}

pub(in crate::store) fn scm_pending_execution_conn(
    connection: &Connection,
    id: &str,
) -> Result<ScmPendingExecution, ControlPlaneError> {
    let pending = connection
        .query_row(
            "SELECT id, origin_task_id, repository_id, capsule_id, role, state,
                    context_json, run_request_json, workflow_approval_id,
                    privileged_approval_id, created_unix_ms, expires_unix_ms,
                    run_id, completed_unix_ms, last_error
             FROM scm_pending_executions WHERE id = ?1",
            [id],
            scm_pending_execution_row,
        )
        .optional()?
        .ok_or_else(|| not_found("SCM pending execution", id))?;
    validate_loaded_scm_pending(&pending)?;
    Ok(pending)
}

pub(in crate::store) fn scm_pending_execution_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<ScmPendingExecution, ControlPlaneError> {
    scm_pending_execution_conn(transaction, id)
}

pub(in crate::store) fn scm_pending_execution_row(
    row: &Row<'_>,
) -> rusqlite::Result<ScmPendingExecution> {
    let role: String = row.get(4)?;
    let state: String = row.get(5)?;
    Ok(ScmPendingExecution {
        id: row.get(0)?,
        origin_task_id: row.get(1)?,
        repository_id: row.get(2)?,
        capsule_id: row.get(3)?,
        role: parse_scm_execution_role(&role).map_err(|error| conversion(4, error))?,
        state: parse_scm_pending_state(&state).map_err(|error| conversion(5, error))?,
        context: json_blob_column(row, 6)?,
        run: json_blob_column(row, 7)?,
        workflow_approval_id: row.get(8)?,
        privileged_approval_id: row.get(9)?,
        created_unix_ms: u64_column(row, 10, "SCM pending creation")?,
        expires_unix_ms: u64_column(row, 11, "SCM pending expiry")?,
        run_id: row.get(12)?,
        completed_unix_ms: optional_u64_column(row, 13, "SCM pending completion")?,
        last_error: row.get(14)?,
    })
}

pub(in crate::store) fn validate_loaded_scm_pending(
    pending: &ScmPendingExecution,
) -> Result<(), ControlPlaneError> {
    validate_text("SCM pending execution id", &pending.id)?;
    validate_scm_source_identity(&pending.context.source_identity)?;
    validate_create_run(&pending.run)?;
    if pending.context.pending_execution_id != pending.id
        || pending.context.role != pending.role
        || pending.run.repository_id != pending.repository_id
        || pending.run.capsule_id != pending.capsule_id
        || !pending.run.remote
        || pending.expires_unix_ms <= pending.created_unix_ms
        || pending.workflow_approval_id.is_none() && pending.privileged_approval_id.is_none()
    {
        return Err(ControlPlaneError::CorruptState(
            "invalid durable SCM pending execution".to_owned(),
        ));
    }
    bounded_scm_json(&pending.context).map_err(|_| {
        ControlPlaneError::CorruptState("SCM continuation context exceeds its bound".to_owned())
    })?;
    bounded_scm_json(&pending.run).map_err(|_| {
        ControlPlaneError::CorruptState("SCM run request exceeds its bound".to_owned())
    })?;
    Ok(())
}

pub(in crate::store) fn scm_proposed_analysis_row(
    row: &Row<'_>,
) -> rusqlite::Result<ScmProposedAnalysisRecord> {
    let status: String = row.get(3)?;
    let analysis_bytes: Option<Vec<u8>> = row.get(5)?;
    Ok(ScmProposedAnalysisRecord {
        id: row.get(0)?,
        origin_task_id: row.get(1)?,
        repository_id: row.get(2)?,
        status: parse_scm_analysis_status(&status).map_err(|error| conversion(3, error))?,
        source_identity: json_blob_column(row, 4)?,
        analysis: analysis_bytes
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(|error| conversion(5, error))?,
        failure: row.get(6)?,
        proposed_capsule_id: row.get(7)?,
        created_unix_ms: u64_column(row, 8, "SCM analysis creation")?,
    })
}

pub(in crate::store) fn pending_approvals_conn(
    connection: &Connection,
    pending: &ScmPendingExecution,
) -> Result<Vec<ApprovalRequest>, ControlPlaneError> {
    let mut approvals = Vec::new();
    for (id, kind) in [
        (
            pending.workflow_approval_id.as_deref(),
            runtrue_policy::ApprovalKind::WorkflowDefinition,
        ),
        (
            pending.privileged_approval_id.as_deref(),
            runtrue_policy::ApprovalKind::PrivilegedExecution,
        ),
    ] {
        let Some(id) = id else { continue };
        let (capsule_id, repository_id, subject_digest, encoded): (String, String, String, String) =
            connection
                .query_row(
                    "SELECT capsule_id, repository_id, subject_digest, request_json
                     FROM approval_requests WHERE id = ?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?
                .ok_or_else(|| not_found("approval", id))?;
        let approval: ApprovalRequest = serde_json::from_str(&encoded)?;
        let reusable_repository_grant =
            kind == runtrue_policy::ApprovalKind::PrivilegedExecution && !approval.rule.one_shot;
        if approval.id != id
            || approval.kind != kind
            || approval.subject_digest.as_str() != subject_digest
            || capsule_id != pending.capsule_id && !reusable_repository_grant
            || repository_id != pending.repository_id
        {
            return Err(ControlPlaneError::CorruptState(
                "SCM pending approval binding is inconsistent".to_owned(),
            ));
        }
        approvals.push(approval);
    }
    if approvals.is_empty() {
        return Err(ControlPlaneError::CorruptState(
            "SCM pending execution has no approvals".to_owned(),
        ));
    }
    Ok(approvals)
}

pub(in crate::store) fn refresh_pending_approvals_tx(
    transaction: &Transaction<'_>,
    pending: &ScmPendingExecution,
    now_unix_ms: u64,
) -> Result<Vec<ApprovalRequest>, ControlPlaneError> {
    let mut approvals = pending_approvals_conn(transaction, pending)?;
    for approval in &mut approvals {
        let previous = approval.status;
        approval.refresh_expiry(now_unix_ms);
        if approval.status != previous {
            transaction.execute(
                "UPDATE approval_requests SET status = ?2, request_json = ?3 WHERE id = ?1",
                params![
                    approval.id,
                    approval_status_name(approval.status),
                    serde_json::to_string(approval)?,
                ],
            )?;
        }
    }
    Ok(approvals)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::store) enum PendingApprovalResolution {
    Ready,
    Waiting,
    Denied,
    Expired,
    Stale,
}

pub(in crate::store) fn pending_resolution_state(
    approvals: &[ApprovalRequest],
    now_unix_ms: u64,
    expires_unix_ms: u64,
) -> PendingApprovalResolution {
    if approvals
        .iter()
        .any(|approval| approval.status == ApprovalStatus::Denied)
    {
        PendingApprovalResolution::Denied
    } else if now_unix_ms >= expires_unix_ms
        || approvals
            .iter()
            .any(|approval| approval.status == ApprovalStatus::Expired)
    {
        PendingApprovalResolution::Expired
    } else if approvals
        .iter()
        .any(|approval| approval.status == ApprovalStatus::Consumed)
    {
        PendingApprovalResolution::Stale
    } else if approvals
        .iter()
        .all(|approval| approval.status == ApprovalStatus::Approved)
    {
        PendingApprovalResolution::Ready
    } else {
        PendingApprovalResolution::Waiting
    }
}

pub(in crate::store) fn close_pending_execution_tx(
    transaction: &Transaction<'_>,
    id: &str,
    state: ScmPendingExecutionState,
    reason: Option<&str>,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let state = match state {
        ScmPendingExecutionState::Denied => "denied",
        ScmPendingExecutionState::Expired => "expired",
        ScmPendingExecutionState::Stale => "stale",
        _ => {
            return Err(ControlPlaneError::InvalidInput(
                "SCM pending close requires a terminal state",
            ))
        }
    };
    transaction.execute(
        "UPDATE scm_pending_executions
         SET state = ?2, completed_unix_ms = ?3, last_error = ?4
         WHERE id = ?1 AND state IN ('awaiting-approval', 'continuation-pending')",
        params![id, state, to_i64(now_unix_ms)?, reason],
    )?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store) struct ScmContinuationTaskPayload {
    pending_execution_id: String,
    approval_id: String,
}

pub(in crate::store) fn enqueue_initial_scm_check_task_tx(
    transaction: &Transaction<'_>,
    event: &Value,
    execution: &PreparedScmExecution,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let provider_backed: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM scm_repository_links l
             JOIN scm_installations i ON i.id = l.installation_id
                AND i.tenant_id = l.tenant_id
             WHERE l.repository_id = ?1 AND i.provider = 'github'
                AND i.status = 'active' AND l.status = 'active'
         )",
        [&execution.capsule.repository_id],
        |row| row.get(0),
    )?;
    if !provider_backed {
        return Ok(());
    }
    let field = |pointer: &str| {
        event
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or(ControlPlaneError::InvalidInput(
                "SCM event cannot produce a check task",
            ))
    };
    let installation_external_id = field("/installation_id")?;
    let event_repository_external_id = field("/repository/external_id")?;
    let owner = field("/repository/owner")?;
    let repository = field("/repository/name")?;
    let commit_sha = field("/source/commit")?;
    if !matches!(commit_sha.len(), 40 | 64)
        || !commit_sha.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ControlPlaneError::InvalidInput(
            "SCM event has invalid check commit",
        ));
    }
    let link: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT r.tenant_id, i.id, l.external_repository_id
             FROM repositories r
             JOIN scm_repository_links l ON l.repository_id = r.id
                AND l.tenant_id = r.tenant_id
             JOIN scm_installations i ON i.id = l.installation_id
                AND i.tenant_id = l.tenant_id
             WHERE r.id = ?1 AND r.owner = ?2 AND r.name = ?3
                AND i.provider = 'github' AND i.external_id = ?4
                AND l.external_repository_id = ?5
                AND i.status = 'active' AND l.status = 'active'",
            params![
                execution.capsule.repository_id,
                owner,
                repository,
                installation_external_id,
                event_repository_external_id,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    // Explicit local/air-gapped mirror mode has no provider installation and
    // therefore no external check side effect to reconcile.
    let Some((tenant_id, installation_id, external_repository_id)) = link else {
        return Ok(());
    };
    let capsule: ExecutionCapsule = serde_json::from_slice(&execution.capsule.canonical_capsule)?;
    let proposed_workflow = execution
        .continuation
        .as_ref()
        .is_some_and(|continuation| continuation.role == ScmExecutionRole::ProposedDefinition);
    let trusted_base_workflow = !proposed_workflow
        && event.pointer("/event_type/kind").and_then(Value::as_str) == Some("pull_request");
    for job in &execution.run.jobs {
        let display_name = capsule
            .jobs
            .iter()
            .find(|planned| planned.id == job.job_key)
            .map(|planned| planned.name.as_str())
            .unwrap_or(&job.job_key);
        let logical_name = format!("job:{}", job.id);
        let mut identity = Sha256::new();
        identity.update(b"runtrue.scm-check-publication.v1\0");
        for component in [
            execution.capsule.repository_id.as_str(),
            execution.run.id.as_str(),
            commit_sha,
            logical_name.as_str(),
        ] {
            identity.update(component.as_bytes());
            identity.update([0]);
        }
        let suffix = hex::encode(identity.finalize());
        let publication_id = format!("scm-check-{suffix}");
        let task_id = format!("scm-check-task-{suffix}");
        let external_id = format!("runtrue:{}:{logical_name}", execution.run.id);
        let proposed_suffix = if proposed_workflow { " (proposed)" } else { "" };
        let check_name = if job.attempt > 1 {
            format!(
                "Runtrue / {display_name} (attempt {}){proposed_suffix}",
                job.attempt
            )
        } else {
            format!("Runtrue / {display_name}{proposed_suffix}")
        };
        let payload = ScmCheckPublishTask {
            publication_id,
            tenant_id: tenant_id.clone(),
            repository_id: execution.capsule.repository_id.clone(),
            installation_id: installation_id.clone(),
            installation_external_id: installation_external_id.to_owned(),
            run_id: execution.run.id.clone(),
            commit_sha: commit_sha.to_owned(),
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            external_repository_id: external_repository_id.clone(),
            logical_name,
            external_id,
            check_name,
            status: "queued".to_owned(),
            conclusion: None,
            title: "Runtrue job queued".to_owned(),
            summary: format!(
                "Workflow: `{}`\nJob: `{display_name}` (`{}`, attempt {})\nRun: `{}`\nCommit: `{commit_sha}`\n\nThe exact signed job was accepted and queued.",
                capsule.workflow.name, job.job_key, job.attempt, execution.run.id
            ),
            render_markdown: false,
            actions: Vec::new(),
            trusted_base_workflow,
        };
        let payload = serde_json::to_value(payload)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO durable_tasks
             (id, kind, payload_json, status, available_unix_ms, attempts,
              last_error, created_unix_ms)
             VALUES (?1, 'scm.check.publish', ?2, 'pending', ?3, 0, NULL, ?3)",
            params![
                task_id,
                serde_json::to_string(&canonicalize_json(payload.clone()))?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        if inserted == 0 {
            let existing: String = transaction.query_row(
                "SELECT payload_json FROM durable_tasks
                 WHERE id = ?1 AND kind = 'scm.check.publish'",
                [&task_id],
                |row| row.get(0),
            )?;
            let existing: Value = serde_json::from_str(&existing)?;
            if existing != canonicalize_json(payload) {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
        }
    }
    Ok(())
}

pub(in crate::store) fn enqueue_proposed_workflow_check_task_tx(
    transaction: &Transaction<'_>,
    event: &Value,
    trusted: &PreparedScmExecution,
    proposed: &PreparedScmExecution,
    approval: &ApprovalRequest,
    analysis: Option<&ScmProposedAnalysisRecord>,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let field = |pointer: &str| {
        event
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or(ControlPlaneError::InvalidInput(
                "SCM event cannot produce a proposed workflow check",
            ))
    };
    let installation_external_id = field("/installation_id")?;
    let event_repository_external_id = field("/repository/external_id")?;
    let owner = field("/repository/owner")?;
    let repository = field("/repository/name")?;
    let commit_sha = field("/source/commit")?;
    let link: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT r.tenant_id, i.id, l.external_repository_id
             FROM repositories r
             JOIN scm_repository_links l ON l.repository_id = r.id
                AND l.tenant_id = r.tenant_id
             JOIN scm_installations i ON i.id = l.installation_id
                AND i.tenant_id = l.tenant_id
             WHERE r.id = ?1 AND r.owner = ?2 AND r.name = ?3
                AND i.provider = 'github' AND i.external_id = ?4
                AND l.external_repository_id = ?5
                AND i.status = 'active' AND l.status = 'active'",
            params![
                proposed.capsule.repository_id,
                owner,
                repository,
                installation_external_id,
                event_repository_external_id,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((tenant_id, installation_id, external_repository_id)) = link else {
        return Ok(());
    };
    let logical_name = format!("proposed-workflow:{}", approval.id);
    let mut identity = Sha256::new();
    identity.update(b"runtrue.scm-check-publication.v1\0");
    for component in [
        proposed.capsule.repository_id.as_str(),
        trusted.run.id.as_str(),
        commit_sha,
        logical_name.as_str(),
    ] {
        identity.update(component.as_bytes());
        identity.update([0]);
    }
    let suffix = hex::encode(identity.finalize());
    let task_id = format!("scm-check-task-{suffix}");
    let input_changes = render_proposed_input_changes(analysis, commit_sha);
    let payload = ScmCheckPublishTask {
        publication_id: format!("scm-check-{suffix}"),
        tenant_id,
        repository_id: proposed.capsule.repository_id.clone(),
        installation_id,
        installation_external_id: installation_external_id.to_owned(),
        run_id: trusted.run.id.clone(),
        commit_sha: commit_sha.to_owned(),
        owner: owner.to_owned(),
        repository: repository.to_owned(),
        external_repository_id,
        logical_name,
        external_id: format!("runtrue:proposed-workflow:{}", approval.id),
        check_name: "Runtrue / Proposed workflow".to_owned(),
        status: "completed".to_owned(),
        conclusion: Some("action_required".to_owned()),
        title: "Proposed workflow inputs require approval".to_owned(),
        summary: format!(
            "### Proposed workflow testing\n\nThis pull request changes workflow execution inputs (the workflow definition, the shared lockfile, or both). The trusted `main` workflow ran normally; the proposed inputs will run only after an authorized maintainer approves this exact subject.\n\n| | |\n|---|---|\n| **Commit** | `{commit_sha}` |\n| **Approval subject** | `{}` |\n| **Risk score** | `{}` |{input_changes}\n\nA new push invalidates this approval.",
            approval.subject_digest, approval.risk_score
        ),
        render_markdown: true,
        actions: vec![
            ScmCheckAction {
                label: "Approve & run".to_owned(),
                description: "Run these exact proposed workflow inputs".to_owned(),
                identifier: "approve_proposed".to_owned(),
            },
            ScmCheckAction {
                label: "Reject".to_owned(),
                description: "Reject these proposed workflow inputs".to_owned(),
                identifier: "reject_proposed".to_owned(),
            },
        ],
        trusted_base_workflow: true,
    };
    let canonical = canonicalize_json(serde_json::to_value(payload)?);
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO durable_tasks
         (id, kind, payload_json, status, available_unix_ms, attempts,
          last_error, created_unix_ms)
         VALUES (?1, 'scm.check.publish', ?2, 'pending', ?3, 0, NULL, ?3)",
        params![
            task_id,
            serde_json::to_string(&canonical)?,
            to_i64(now_unix_ms)?,
        ],
    )?;
    if inserted == 0 {
        let existing: String = transaction.query_row(
            "SELECT payload_json FROM durable_tasks
             WHERE id = ?1 AND kind = 'scm.check.publish'",
            [&task_id],
            |row| row.get(0),
        )?;
        if serde_json::from_str::<Value>(&existing)? != canonical {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
    }
    Ok(())
}

fn render_proposed_input_changes(
    analysis: Option<&ScmProposedAnalysisRecord>,
    commit_sha: &str,
) -> String {
    let base_commit = analysis
        .and_then(|record| record.source_identity.base_commit.as_deref())
        .unwrap_or("trusted base");
    let workflow_path = analysis
        .map(|record| record.source_identity.workflow_path.as_str())
        .unwrap_or("workflow definition");
    let workflow_diff = analysis
        .and_then(|record| record.analysis.as_ref())
        .and_then(|value| value.get("workflow_diff"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let lockfile_diff = analysis
        .and_then(|record| record.analysis.as_ref())
        .and_then(|value| value.get("lockfile_diff"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    render_proposed_diff_sections(
        base_commit,
        commit_sha,
        workflow_path,
        workflow_diff,
        lockfile_diff,
    )
}

fn render_proposed_diff_sections(
    base_commit: &str,
    commit_sha: &str,
    workflow_path: &str,
    workflow_diff: Option<&str>,
    lockfile_diff: Option<&str>,
) -> String {
    let mut changes = String::new();
    if let Some(diff) = workflow_diff {
        changes.push_str(&format!(
            "\n\n### Workflow definition diff\n\n`{base_commit}` → `{commit_sha}` · `{workflow_path}`\n\n````diff\n{diff}````"
        ));
    } else {
        changes.push_str(&format!(
            "\n\n### Workflow definition\n\n`{workflow_path}` is unchanged."
        ));
    }
    if let Some(diff) = lockfile_diff {
        changes.push_str(&format!(
            "\n\n### Shared lockfile diff\n\n`{base_commit}` → `{commit_sha}` · `.runtrue.lock`\n\n````diff\n{diff}````"
        ));
    }
    changes
}

pub(in crate::store) fn enqueue_scm_expiry_task_tx(
    transaction: &Transaction<'_>,
    pending_execution_id: &str,
    approval_id: &str,
    created_unix_ms: u64,
    expires_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let payload = ScmContinuationTaskPayload {
        pending_execution_id: pending_execution_id.to_owned(),
        approval_id: approval_id.to_owned(),
    };
    let digest = hash_serializable(&(
        "scm-approval-expiry-v1",
        pending_execution_id,
        approval_id,
        expires_unix_ms,
    ))?;
    let task_id = format!(
        "scm-continuation-expiry-{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let payload_json = serde_json::to_string(&canonicalize_json(serde_json::to_value(payload)?))?;
    transaction.execute(
        "INSERT INTO durable_tasks
         (id, kind, payload_json, status, available_unix_ms, attempts, created_unix_ms)
         VALUES (?1, 'scm.approval.continue', ?2, 'pending', ?3, 0, ?4)",
        params![
            task_id,
            payload_json,
            to_i64(expires_unix_ms)?,
            to_i64(created_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn enqueue_scm_continuations_for_approval_tx(
    transaction: &Transaction<'_>,
    approval_id: &str,
    decision: &ApprovalDecision,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let mut statement = transaction.prepare(
        "SELECT id FROM scm_pending_executions
         WHERE state IN ('awaiting-approval', 'continuation-pending')
           AND (workflow_approval_id = ?1 OR privileged_approval_id = ?1)
         ORDER BY id LIMIT ?2",
    )?;
    let limit = i64::try_from(MAX_SCM_CONTINUATIONS_PER_DECISION + 1).map_err(|_| {
        ControlPlaneError::IntegerRange {
            field: "SCM continuations per decision",
        }
    })?;
    let pending_ids = statement
        .query_map(params![approval_id, limit], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    if pending_ids.len() > MAX_SCM_CONTINUATIONS_PER_DECISION {
        return Err(ControlPlaneError::InvalidInput(
            "approval is bound to too many pending SCM executions",
        ));
    }
    for pending_execution_id in pending_ids {
        let payload = ScmContinuationTaskPayload {
            pending_execution_id: pending_execution_id.clone(),
            approval_id: approval_id.to_owned(),
        };
        #[derive(Serialize)]
        struct TaskIdentity<'a> {
            pending_execution_id: &'a str,
            approval_id: &'a str,
            actor_id: &'a str,
            decision: runtrue_policy::Decision,
            decided_unix_ms: u64,
            subject_digest: &'a ContentDigest,
        }
        let digest = hash_serializable(&TaskIdentity {
            pending_execution_id: &pending_execution_id,
            approval_id,
            actor_id: &decision.actor_id,
            decision: decision.decision,
            decided_unix_ms: decision.decided_unix_ms,
            subject_digest: &decision.subject_digest,
        })?;
        let task_id = format!(
            "scm-continuation-{}",
            digest.as_str().trim_start_matches("sha256:")
        );
        let payload_json =
            serde_json::to_string(&canonicalize_json(serde_json::to_value(&payload)?))?;
        if payload_json.len() > MAX_SCM_SNAPSHOT_BYTES {
            return Err(ControlPlaneError::InvalidInput(
                "SCM continuation task payload exceeds its bound",
            ));
        }
        transaction.execute(
            "INSERT INTO durable_tasks
             (id, kind, payload_json, status, available_unix_ms, attempts,
              created_unix_ms)
             VALUES (?1, 'scm.approval.continue', ?2, 'pending', ?3, 0, ?3)",
            params![task_id, payload_json, to_i64(now_unix_ms)?],
        )?;
        transaction.execute(
            "UPDATE scm_pending_executions SET state = 'continuation-pending'
             WHERE id = ?1 AND state = 'awaiting-approval'",
            [pending_execution_id],
        )?;
    }
    Ok(())
}

pub(in crate::store) fn enqueue_preapproved_scm_continuation_tx(
    transaction: &Transaction<'_>,
    pending_execution_id: &str,
    approval_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let payload = ScmContinuationTaskPayload {
        pending_execution_id: pending_execution_id.to_owned(),
        approval_id: approval_id.to_owned(),
    };
    let digest = hash_serializable(&(
        "scm-reusable-approval-v1",
        pending_execution_id,
        approval_id,
    ))?;
    let task_id = format!(
        "scm-continuation-{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let payload_json = serde_json::to_string(&canonicalize_json(serde_json::to_value(payload)?))?;
    transaction.execute(
        "INSERT OR IGNORE INTO durable_tasks
         (id, kind, payload_json, status, available_unix_ms, attempts, created_unix_ms)
         VALUES (?1, 'scm.approval.continue', ?2, 'pending', ?3, 0, ?3)",
        params![task_id, payload_json, to_i64(now_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE scm_pending_executions SET state = 'continuation-pending'
         WHERE id = ?1 AND state = 'awaiting-approval'",
        [pending_execution_id],
    )?;
    Ok(())
}

pub(in crate::store) fn require_scm_continuation_task_tx(
    transaction: &Transaction<'_>,
    task_id: &str,
    worker: &str,
    pending_execution_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    require_task_owner_tx(transaction, task_id, worker, now_unix_ms)?;
    let task = task_tx(transaction, task_id)?;
    if task.kind != "scm.approval.continue" {
        return Err(ControlPlaneError::InvalidInput(
            "SCM continuation result requires an scm.approval.continue task",
        ));
    }
    let payload: ScmContinuationTaskPayload = serde_json::from_value(task.payload)?;
    validate_text("SCM continuation approval id", &payload.approval_id)?;
    let bound: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM scm_pending_executions
             WHERE id = ?1 AND (workflow_approval_id = ?2 OR privileged_approval_id = ?2)
         )",
        params![pending_execution_id, payload.approval_id],
        |row| row.get(0),
    )?;
    if payload.pending_execution_id != pending_execution_id || !bound {
        return Err(ControlPlaneError::InvalidInput(
            "SCM continuation task is not bound to this pending approval",
        ));
    }
    Ok(())
}

pub(in crate::store) fn require_not_safe_mode_tx(
    transaction: &Transaction<'_>,
) -> Result<(), ControlPlaneError> {
    let safe_mode: bool = transaction.query_row(
        "SELECT safe_mode FROM installation_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if safe_mode {
        Err(ControlPlaneError::InstallationSafeMode)
    } else {
        Ok(())
    }
}

pub(in crate::store) const fn scm_execution_role_name(role: ScmExecutionRole) -> &'static str {
    match role {
        ScmExecutionRole::Direct => "direct",
        ScmExecutionRole::TrustedBase => "trusted-base",
        ScmExecutionRole::ProposedDefinition => "proposed-definition",
    }
}

pub(in crate::store) fn parse_scm_execution_role(
    value: &str,
) -> Result<ScmExecutionRole, DecodeError> {
    match value {
        "direct" => Ok(ScmExecutionRole::Direct),
        "trusted-base" => Ok(ScmExecutionRole::TrustedBase),
        "proposed-definition" => Ok(ScmExecutionRole::ProposedDefinition),
        _ => Err(DecodeError(format!("unknown SCM execution role `{value}`"))),
    }
}

pub(in crate::store) fn parse_scm_pending_state(
    value: &str,
) -> Result<ScmPendingExecutionState, DecodeError> {
    match value {
        "awaiting-approval" => Ok(ScmPendingExecutionState::AwaitingApproval),
        "continuation-pending" => Ok(ScmPendingExecutionState::ContinuationPending),
        "run-created" => Ok(ScmPendingExecutionState::RunCreated),
        "denied" => Ok(ScmPendingExecutionState::Denied),
        "expired" => Ok(ScmPendingExecutionState::Expired),
        "stale" => Ok(ScmPendingExecutionState::Stale),
        _ => Err(DecodeError(format!("unknown SCM pending state `{value}`"))),
    }
}

pub(in crate::store) const fn scm_analysis_status_name(
    status: ScmProposedAnalysisStatus,
) -> &'static str {
    match status {
        ScmProposedAnalysisStatus::Valid => "valid",
        ScmProposedAnalysisStatus::Invalid => "invalid",
        ScmProposedAnalysisStatus::Deleted => "deleted",
    }
}

pub(in crate::store) fn parse_scm_analysis_status(
    value: &str,
) -> Result<ScmProposedAnalysisStatus, DecodeError> {
    match value {
        "valid" => Ok(ScmProposedAnalysisStatus::Valid),
        "invalid" => Ok(ScmProposedAnalysisStatus::Invalid),
        "deleted" => Ok(ScmProposedAnalysisStatus::Deleted),
        _ => Err(DecodeError(format!(
            "unknown SCM analysis status `{value}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::render_proposed_diff_sections;

    #[test]
    fn lockfile_only_change_does_not_claim_the_workflow_changed() {
        let rendered = render_proposed_diff_sections(
            "base-sha",
            "head-sha",
            ".runtrue/workflows/runtrue-scm-automation.github.yml",
            None,
            Some("-source = \"image:old\"\n+source = \"image:new\"\n"),
        );

        assert!(rendered
            .contains("`.runtrue/workflows/runtrue-scm-automation.github.yml` is unchanged."));
        assert!(rendered.contains("### Shared lockfile diff"));
        assert!(rendered.contains("`base-sha` → `head-sha` · `.runtrue.lock`"));
        assert!(!rendered.contains("### Workflow definition diff"));
    }
}

mod initial_completion;
mod lifecycle;
