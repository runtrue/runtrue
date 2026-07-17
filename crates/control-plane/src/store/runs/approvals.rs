use super::*;
use rusqlite::params;
use serde::Serialize;

pub(in crate::store) fn approval_conn(
    connection: &Connection,
    id: &str,
) -> Result<ApprovalRequest, ControlPlaneError> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT request_json FROM approval_requests WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .optional()?;
    encoded
        .map(|value| serde_json::from_str(&value).map_err(ControlPlaneError::from))
        .transpose()?
        .ok_or_else(|| not_found("approval", id))
}

pub(in crate::store) fn approval_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<ApprovalRequest, ControlPlaneError> {
    let encoded: Option<String> = transaction
        .query_row(
            "SELECT request_json FROM approval_requests WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .optional()?;
    encoded
        .map(|value| serde_json::from_str(&value).map_err(ControlPlaneError::from))
        .transpose()?
        .ok_or_else(|| not_found("approval", id))
}

pub(in crate::store) struct AuthorizedRunApproval {
    pub(in crate::store) approval_id: String,
    pub(in crate::store) kind: runtrue_policy::ApprovalKind,
    pub(in crate::store) subject_digest: ContentDigest,
    pub(in crate::store) one_shot: bool,
}

pub(in crate::store) fn authorize_required_approval_tx(
    transaction: &Transaction<'_>,
    capsule_id: &str,
    approval_subject_digest: &ContentDigest,
    run_subject_digest: &ContentDigest,
    kind: runtrue_policy::ApprovalKind,
    now_unix_ms: u64,
) -> Result<AuthorizedRunApproval, ControlPlaneError> {
    let repository_id: String = transaction.query_row(
        "SELECT repository_id FROM capsules WHERE id = ?1",
        [capsule_id],
        |row| row.get(0),
    )?;
    let mut statement = transaction.prepare(
        "SELECT id, request_json FROM approval_requests
         WHERE subject_digest = ?2 AND status = 'approved'
           AND (capsule_id = ?1 OR repository_id = ?3)
         ORDER BY created_unix_ms, id",
    )?;
    let candidates = statement
        .query_map(
            params![capsule_id, approval_subject_digest.as_str(), repository_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let mut selected = None;
    for (id, encoded) in candidates {
        let approval: ApprovalRequest = serde_json::from_str(&encoded)?;
        let exact_capsule: bool = transaction.query_row(
            "SELECT capsule_id = ?2 FROM approval_requests WHERE id = ?1",
            params![id, capsule_id],
            |row| row.get(0),
        )?;
        let reusable_repository_grant =
            kind == runtrue_policy::ApprovalKind::PrivilegedExecution && !approval.rule.one_shot;
        if approval.kind == kind && (exact_capsule || reusable_repository_grant) {
            selected = Some((id, approval));
            break;
        }
    }
    let Some((approval_id, mut approval)) = selected else {
        return Err(ControlPlaneError::ApprovalRequired);
    };
    approval
        .authorize(approval_subject_digest, now_unix_ms)
        .map_err(|_| ControlPlaneError::ApprovalRequired)?;
    transaction.execute(
        "UPDATE approval_requests SET status = ?2, request_json = ?3 WHERE id = ?1",
        params![
            approval_id,
            approval_status_name(approval.status),
            serde_json::to_string(&approval)?,
        ],
    )?;
    Ok(AuthorizedRunApproval {
        approval_id,
        kind,
        // A reusable approval is selected with its repository capability
        // digest, but every admitted run remains bound to its exact Capsule
        // subject. The scheduler checks this value before leasing work.
        subject_digest: run_subject_digest.clone(),
        one_shot: approval.rule.one_shot,
    })
}

pub(in crate::store) const fn approval_kind_name(
    kind: runtrue_policy::ApprovalKind,
) -> &'static str {
    match kind {
        runtrue_policy::ApprovalKind::WorkflowDefinition => "workflow-definition",
        runtrue_policy::ApprovalKind::PrivilegedExecution => "privileged-execution",
        runtrue_policy::ApprovalKind::EnvironmentDeployment => "environment-deployment",
        runtrue_policy::ApprovalKind::ArtifactPromotion => "artifact-promotion",
        runtrue_policy::ApprovalKind::BreakGlass => "break-glass",
    }
}

pub(in crate::store) fn run_state_name(state: RunState) -> &'static str {
    match state {
        RunState::Created => "created",
        RunState::Running => "running",
        RunState::Succeeded => "succeeded",
        RunState::Failed => "failed",
        RunState::Canceled => "canceled",
    }
}

pub(in crate::store) fn parse_run_state(value: &str) -> Result<RunState, DecodeError> {
    match value {
        "created" => Ok(RunState::Created),
        "running" => Ok(RunState::Running),
        "succeeded" => Ok(RunState::Succeeded),
        "failed" => Ok(RunState::Failed),
        "canceled" => Ok(RunState::Canceled),
        _ => Err(DecodeError(format!("unknown run state `{value}`"))),
    }
}

pub(in crate::store) fn job_state_name(state: JobState) -> &'static str {
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

pub(in crate::store) fn parse_job_state(value: &str) -> Result<JobState, DecodeError> {
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
        _ => Err(DecodeError(format!("unknown job state `{value}`"))),
    }
}

pub(in crate::store) fn approval_status_name(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
        ApprovalStatus::Consumed => "consumed",
    }
}

impl ControlPlane {
    pub fn create_approval_request(
        &self,
        repository_id: &str,
        capsule_id: &str,
        request: &ApprovalRequest,
    ) -> Result<(), ControlPlaneError> {
        let expected = ApprovalRequest::create(
            request.id.clone(),
            request.kind,
            request.subject_digest.clone(),
            request.risk_score,
            request.created_unix_ms,
            request.expires_unix_ms,
            request.rule.clone(),
        )?;
        if &expected != request {
            return Err(ControlPlaneError::InvalidInput(
                "new approval request must be pending and decision-free",
            ));
        }
        let connection = self.connection()?;
        let capsule_repository: String = connection
            .query_row(
                "SELECT repository_id FROM capsules WHERE id = ?1",
                [capsule_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("capsule", capsule_id))?;
        if capsule_repository != repository_id {
            return Err(ControlPlaneError::InvalidInput(
                "approval capsule does not belong to repository",
            ));
        }
        connection.execute(
            "INSERT INTO approval_requests
             (id, repository_id, capsule_id, subject_digest, status, request_json,
              created_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.id,
                repository_id,
                capsule_id,
                request.subject_digest.as_str(),
                approval_status_name(request.status),
                serde_json::to_string(request)?,
                to_i64(request.created_unix_ms)?,
                to_i64(request.expires_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn approval_request(&self, id: &str) -> Result<ApprovalRequest, ControlPlaneError> {
        let connection = self.connection()?;
        approval_conn(&connection, id)
    }

    /// Return the repository and immutable Capsule bound to an approval.
    ///
    /// Approval decisions are exact-subject operations. Keeping this binding
    /// in the control plane lets presentation layers show useful context
    /// without attempting to infer ownership from the approval identifier.
    pub fn approval_request_binding(
        &self,
        id: &str,
    ) -> Result<(String, String), ControlPlaneError> {
        validate_text("approval id", id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT repository_id, capsule_id FROM approval_requests WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| not_found("approval", id))
    }

    pub fn approval_pending_execution_count(&self, id: &str) -> Result<u64, ControlPlaneError> {
        validate_text("approval id", id)?;
        let connection = self.connection()?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM scm_pending_executions
             WHERE state IN ('awaiting-approval', 'continuation-pending')
               AND (workflow_approval_id = ?1 OR privileged_approval_id = ?1)",
            [id],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| ControlPlaneError::IntegerRange {
            field: "approval pending execution count",
        })
    }

    pub fn approval_pending_execution_events(
        &self,
        id: &str,
    ) -> Result<Vec<Value>, ControlPlaneError> {
        validate_text("approval id", id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT context_json FROM scm_pending_executions
             WHERE state IN ('awaiting-approval', 'continuation-pending')
               AND (workflow_approval_id = ?1 OR privileged_approval_id = ?1)
             ORDER BY created_unix_ms, id LIMIT 100",
        )?;
        let contexts = statement
            .query_map([id], |row| {
                json_blob_column::<ScmContinuationContext>(row, 0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(contexts.into_iter().map(|context| context.event).collect())
    }

    pub fn approval_requests_for_capsule(
        &self,
        capsule_id: &str,
    ) -> Result<Vec<ApprovalRequest>, ControlPlaneError> {
        validate_text("capsule id", capsule_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT request_json FROM approval_requests
             WHERE capsule_id = ?1 ORDER BY id LIMIT ?2",
        )?;
        let limit = i64::try_from(MAX_CAPSULE_APPROVAL_QUERY + 1).map_err(|_| {
            ControlPlaneError::IntegerRange {
                field: "capsule approval query limit",
            }
        })?;
        let approvals = statement
            .query_map(params![capsule_id, limit], |row| json_column(row, 0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if approvals.len() > MAX_CAPSULE_APPROVAL_QUERY {
            return Err(ControlPlaneError::CorruptState(
                "capsule has too many durable approval requests".to_owned(),
            ));
        }
        Ok(approvals)
    }

    pub fn decide_approval(
        &self,
        approval_id: &str,
        decision: ApprovalDecision,
        now_unix_ms: u64,
    ) -> Result<ApprovalRequest, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut request = approval_tx(&transaction, approval_id)?;
        request.refresh_expiry(now_unix_ms);
        if request.status == ApprovalStatus::Expired {
            transaction.execute(
                "UPDATE approval_requests SET status = 'expired', request_json = ?2 WHERE id = ?1",
                params![approval_id, serde_json::to_string(&request)?],
            )?;
            transaction.commit()?;
            return Err(PolicyError::RequestNotPending(ApprovalStatus::Expired).into());
        }
        request.decide(decision.clone(), now_unix_ms)?;
        transaction.execute(
            "INSERT INTO approval_decisions
             (approval_id, actor_id, decision_json, decided_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                approval_id,
                decision.actor_id,
                serde_json::to_string(&decision)?,
                to_i64(decision.decided_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "UPDATE approval_requests SET status = ?2, request_json = ?3 WHERE id = ?1",
            params![
                approval_id,
                approval_status_name(request.status),
                serde_json::to_string(&request)?,
            ],
        )?;
        transaction.commit()?;
        Ok(request)
    }

    pub fn decide_approval_idempotent(
        &self,
        idempotency_key: &str,
        approval_id: &str,
        decision: ApprovalDecision,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<ApprovalRequest>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        validate_text("approval id", approval_id)?;
        #[derive(Serialize)]
        struct Subject<'a> {
            approval_id: &'a str,
            actor_id: &'a str,
            decision: runtrue_policy::Decision,
            reason: &'a str,
            rule_id: &'a str,
            subject_digest: &'a ContentDigest,
        }
        let request_hash = hash_serializable(&Subject {
            approval_id,
            actor_id: &decision.actor_id,
            decision: decision.decision,
            reason: &decision.reason,
            rule_id: &decision.rule_id,
            subject_digest: &decision.subject_digest,
        })?;
        let operation = format!("approval.decide:{approval_id}");
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = approval_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        let mut request = approval_tx(&transaction, approval_id)?;
        request.refresh_expiry(now_unix_ms);
        if request.status == ApprovalStatus::Expired {
            transaction.execute(
                "UPDATE approval_requests SET status = 'expired', request_json = ?2 WHERE id = ?1",
                params![approval_id, serde_json::to_string(&request)?],
            )?;
            transaction.commit()?;
            return Err(PolicyError::RequestNotPending(ApprovalStatus::Expired).into());
        }
        request.decide(decision.clone(), now_unix_ms)?;
        transaction.execute(
            "INSERT INTO approval_decisions
             (approval_id, actor_id, decision_json, decided_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                approval_id,
                decision.actor_id,
                serde_json::to_string(&decision)?,
                to_i64(decision.decided_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "UPDATE approval_requests SET status = ?2, request_json = ?3 WHERE id = ?1",
            params![
                approval_id,
                approval_status_name(request.status),
                serde_json::to_string(&request)?,
            ],
        )?;
        enqueue_scm_continuations_for_approval_tx(
            &transaction,
            approval_id,
            &decision,
            now_unix_ms,
        )?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
                idempotency_key,
                request_hash.as_str(),
                approval_id,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: request,
            replayed: false,
        })
    }

    pub fn authorize_approval(
        &self,
        approval_id: &str,
        subject_digest: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<ApprovalRequest, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut request = approval_tx(&transaction, approval_id)?;
        request.refresh_expiry(now_unix_ms);
        if request.status == ApprovalStatus::Expired {
            transaction.execute(
                "UPDATE approval_requests SET status = 'expired', request_json = ?2 WHERE id = ?1",
                params![approval_id, serde_json::to_string(&request)?],
            )?;
            transaction.commit()?;
            return Err(PolicyError::NotAuthorized(ApprovalStatus::Expired).into());
        }
        request.authorize(subject_digest, now_unix_ms)?;
        transaction.execute(
            "UPDATE approval_requests SET status = ?2, request_json = ?3 WHERE id = ?1",
            params![
                approval_id,
                approval_status_name(request.status),
                serde_json::to_string(&request)?,
            ],
        )?;
        transaction.commit()?;
        Ok(request)
    }
}
