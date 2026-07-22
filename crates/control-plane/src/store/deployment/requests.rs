// Request persistence and validation dependencies are explicit.
use super::{
    approval_status_name, approval_tx, conversion, digest_column, environment_tx, from_i64,
    hash_serializable, installation_epoch_tx, materialized_planned_jobs_conn, not_found,
    optional_u64_column, params, require_active_policy_epoch_tx, require_environment_version_tx,
    require_r9_tenant_tx, to_i64, u64_column, validate_r10_identifier, ApprovalStatus,
    ControlPlane, ControlPlaneError, DecodeError, DeploymentRequestRecord, DeploymentRequestStatus,
    EnvironmentRecord, ExecutionCapsule, IdempotentResult, Row, Transaction, TransactionBehavior,
};
use rusqlite::OptionalExtension as _;
pub(in crate::store) fn deployment_request_status(
    value: &str,
) -> Result<DeploymentRequestStatus, DecodeError> {
    match value {
        "waiting-timer" => Ok(DeploymentRequestStatus::WaitingTimer),
        "awaiting-approval" => Ok(DeploymentRequestStatus::AwaitingApproval),
        "awaiting-concurrency" => Ok(DeploymentRequestStatus::AwaitingConcurrency),
        "ready" => Ok(DeploymentRequestStatus::Ready),
        "leased" => Ok(DeploymentRequestStatus::Leased),
        "in-progress" => Ok(DeploymentRequestStatus::InProgress),
        "succeeded" => Ok(DeploymentRequestStatus::Succeeded),
        "failed" => Ok(DeploymentRequestStatus::Failed),
        "canceled" => Ok(DeploymentRequestStatus::Canceled),
        _ => Err(DecodeError(format!(
            "unknown deployment request state `{value}`"
        ))),
    }
}

pub(in crate::store) fn deployment_request_row(
    row: &Row<'_>,
) -> rusqlite::Result<DeploymentRequestRecord> {
    let status: String = row.get(23)?;
    Ok(DeploymentRequestRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        environment_id: row.get(2)?,
        environment_version: u64_column(row, 3, "deployment environment version")?,
        policy_epoch: u64_column(row, 4, "deployment policy epoch")?,
        repository_id: row.get(5)?,
        run_id: row.get(6)?,
        job_id: row.get(7)?,
        job_attempt: u32::try_from(u64_column(row, 8, "deployment job attempt")?)
            .map_err(|error| conversion(8, error))?,
        artifact_id: row.get(9)?,
        promoted_artifact_id: row.get(10)?,
        artifact_source_run_id: row.get(11)?,
        artifact_source_job_id: row.get(12)?,
        artifact_source_job_attempt: u32::try_from(u64_column(
            row,
            13,
            "artifact source job attempt",
        )?)
        .map_err(|error| conversion(13, error))?,
        artifact_digest: digest_column(row, 14)?,
        manifest_digest: digest_column(row, 15)?,
        provenance_digest: digest_column(row, 16)?,
        target_digest: digest_column(row, 17)?,
        deployment_capsule_digest: digest_column(row, 18)?,
        request_digest: digest_column(row, 19)?,
        approval_subject_digest: digest_column(row, 20)?,
        approval_request_id: row.get(21)?,
        rollback_of_deployment_id: row.get(22)?,
        status: deployment_request_status(&status).map_err(|error| conversion(23, error))?,
        wait_until_unix_ms: u64_column(row, 24, "deployment wait deadline")?,
        concurrency_fence: optional_u64_column(row, 25, "deployment concurrency fence")?,
        execution_lease_id: row.get(26)?,
        lease_fencing_generation: optional_u64_column(row, 27, "deployment lease fence")?,
        installation_fencing_epoch: optional_u64_column(row, 28, "deployment epoch")?,
        actor_id: row.get(29)?,
        audit_correlation_id: row.get(30)?,
        created_unix_ms: u64_column(row, 31, "deployment request creation")?,
        updated_unix_ms: u64_column(row, 32, "deployment request update")?,
        completed_unix_ms: optional_u64_column(row, 33, "deployment request completion")?,
        version: u64_column(row, 34, "deployment request version")?,
    })
}

const DEPLOYMENT_REQUEST_COLUMNS: &str =
    "id, tenant_id, environment_id, environment_version, policy_epoch,
     repository_id, run_id, job_id, job_attempt, artifact_id, promoted_artifact_id,
     artifact_source_run_id, artifact_source_job_id, artifact_source_job_attempt, artifact_digest,
     manifest_digest, provenance_digest, target_digest, deployment_capsule_digest, request_digest,
     approval_subject_digest, approval_request_id, rollback_of_deployment_id,
     status, wait_until_unix_ms, concurrency_fence, execution_lease_id,
     lease_fencing_generation, installation_fencing_epoch, actor_id,
     audit_correlation_id, created_unix_ms, updated_unix_ms, completed_unix_ms,
     version";

pub(in crate::store) fn deployment_request_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    request_id: &str,
) -> Result<Option<DeploymentRequestRecord>, ControlPlaneError> {
    let sql = format!(
        "SELECT {DEPLOYMENT_REQUEST_COLUMNS} FROM deployment_requests
         WHERE tenant_id = ?1 AND id = ?2"
    );
    Ok(transaction
        .query_row(&sql, params![tenant_id, request_id], deployment_request_row)
        .optional()?)
}

pub(crate) fn validate_deployment_request_shape(
    record: &DeploymentRequestRecord,
) -> Result<(), ControlPlaneError> {
    for value in [
        &record.id,
        &record.tenant_id,
        &record.environment_id,
        &record.repository_id,
        &record.run_id,
        &record.job_id,
        &record.artifact_id,
        &record.artifact_source_run_id,
        &record.artifact_source_job_id,
        &record.actor_id,
        &record.audit_correlation_id,
    ] {
        validate_r10_identifier(value)?;
    }
    if let Some(value) = &record.approval_request_id {
        validate_r10_identifier(value)?;
    }
    if let Some(value) = &record.promoted_artifact_id {
        validate_r10_identifier(value)?;
    }
    if let Some(value) = &record.rollback_of_deployment_id {
        validate_r10_identifier(value)?;
    }
    if record.job_attempt == 0
        || record.artifact_source_job_attempt == 0
        || record.environment_version == 0
        || record.policy_epoch == 0
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
        || record.wait_until_unix_ms < record.created_unix_ms
        || record.expected_request_digest()? != record.request_digest
        || record.expected_approval_subject_digest()? != record.approval_subject_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid deployment request binding",
        ));
    }
    Ok(())
}

pub(in crate::store) fn validate_deployment_inputs_tx(
    transaction: &Transaction<'_>,
    record: &DeploymentRequestRecord,
    environment: &EnvironmentRecord,
) -> Result<(), ControlPlaneError> {
    require_environment_version_tx(transaction, environment)?;
    type ArtifactBinding = (
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
    );
    let binding: Option<ArtifactBinding> = transaction
        .query_row(
            "SELECT a.tenant_id, a.repository_id, a.run_id, a.job_id, a.job_attempt,
                    a.content_digest, a.manifest_digest, a.provenance_digest,
                    a.classification, a.scan_state, a.state, a.retention_until_unix_seconds
             FROM artifacts_catalog a
             JOIN runs r ON r.id = a.run_id
             JOIN jobs j ON j.id = a.job_id AND j.run_id = r.id
             JOIN repositories repo ON repo.id = r.repository_id
             WHERE a.artifact_id = ?1 AND repo.tenant_id = ?2",
            params![record.artifact_id, record.tenant_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        tenant,
        repository,
        run,
        job,
        attempt,
        artifact,
        manifest,
        provenance,
        classification,
        scan_state,
        state,
        retention_until,
    )) = binding
    else {
        return Err(not_found("artifact", &record.artifact_id));
    };
    if tenant != record.tenant_id
        || repository != record.repository_id
        || run != record.artifact_source_run_id
        || job != record.artifact_source_job_id
        || from_i64("artifact job attempt", attempt)?
            != u64::from(record.artifact_source_job_attempt)
        || artifact != record.artifact_digest.as_str()
        || manifest != record.manifest_digest.as_str()
        || provenance != record.provenance_digest.as_str()
        || from_i64("artifact retention", retention_until)? <= record.created_unix_ms / 1_000
        || state != "available"
        || (!environment.protection_rules.require_promotion_evidence
            && classification
                != environment
                    .protection_rules
                    .required_artifact_classification)
        || (environment.protection_rules.require_passed_scan && scan_state != "passed")
        || environment.repository_id != record.repository_id
        || record.target_digest != environment.deployment_target_digest
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let deployment_lineage: Option<(String, String, String, i64)> = transaction
        .query_row(
            "SELECT repo.tenant_id, r.repository_id, j.run_id, j.attempt
             FROM jobs j JOIN runs r ON r.id = j.run_id
             JOIN repositories repo ON repo.id = r.repository_id
             WHERE j.id = ?1 AND j.run_id = ?2",
            params![record.job_id, record.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if deployment_lineage
        != Some((
            record.tenant_id.clone(),
            record.repository_id.clone(),
            record.run_id.clone(),
            i64::from(record.job_attempt),
        ))
    {
        return Err(not_found("deployment job", &record.job_id));
    }
    let (canonical_capsule, job_key): (Vec<u8>, String) = transaction.query_row(
        "SELECT p.canonical_capsule, j.job_key FROM jobs j
         JOIN runs r ON r.id = j.run_id JOIN capsules p ON p.id = r.capsule_id
         WHERE j.id = ?1 AND j.run_id = ?2",
        params![record.job_id, record.run_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
    if capsule.canonical_bytes()? != canonical_capsule {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    if capsule.digest()? != record.deployment_capsule_digest {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let planned_jobs = materialized_planned_jobs_conn(transaction, &record.run_id, &capsule)?;
    let planned = planned_jobs.get(&job_key).ok_or_else(|| {
        ControlPlaneError::CorruptState(
            "deployment job is absent from its signed capsule".to_owned(),
        )
    })?;
    if planned.environment.as_deref() != Some(environment.name.as_str()) {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    if environment.protection_rules.require_promotion_evidence {
        let promoted_id = record
            .promoted_artifact_id
            .as_deref()
            .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
        let promoted: bool = transaction.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM artifact_promotions p
               JOIN artifact_promotion_bindings b ON b.promotion_id = p.id
               WHERE p.tenant_id = ?1 AND p.source_artifact_id = ?2
                 AND p.status = 'succeeded'
                 AND p.promoted_artifact_id = ?3
                 AND p.target_classification = ?4
                 AND b.source_manifest_digest = ?5
                 AND b.source_provenance_digest = ?6
                 AND b.scan_evidence_digest IS NOT NULL
             )",
            params![
                record.tenant_id,
                record.artifact_id,
                promoted_id,
                environment
                    .protection_rules
                    .required_artifact_classification,
                record.manifest_digest.as_str(),
                record.provenance_digest.as_str()
            ],
            |row| row.get(0),
        )?;
        if !promoted {
            return Err(ControlPlaneError::EnvironmentGateNotReady);
        }
    } else if record.promoted_artifact_id.is_some() {
        return Err(ControlPlaneError::InvalidInput(
            "unexpected promoted artifact identity",
        ));
    }
    Ok(())
}

pub(in crate::store) fn require_deployment_approval_tx(
    transaction: &Transaction<'_>,
    record: &DeploymentRequestRecord,
    environment: &EnvironmentRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let approval_id = record
        .approval_request_id
        .as_deref()
        .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
    let repository_tenant: Option<String> = transaction
        .query_row(
            "SELECT repo.tenant_id FROM approval_requests a
             JOIN repositories repo ON repo.id = a.repository_id
             JOIN runs r ON r.id = ?3 AND r.capsule_id = a.capsule_id
             WHERE a.id = ?1 AND a.repository_id = ?2",
            params![approval_id, record.repository_id, record.run_id],
            |row| row.get(0),
        )
        .optional()?;
    if repository_tenant.as_deref() != Some(record.tenant_id.as_str()) {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    let mut approval = approval_tx(transaction, approval_id)
        .map_err(|_| ControlPlaneError::EnvironmentGateNotReady)?;
    if approval.kind != runtrue_policy::ApprovalKind::EnvironmentDeployment
        || approval.subject_digest != record.approval_subject_digest
        || approval.rule.required_approvals
            < u16::try_from(environment.protection_rules.minimum_approvals).map_err(|_| {
                ControlPlaneError::InvalidInput("invalid environment approval threshold")
            })?
        || !approval.rule.one_shot
        || Some(hash_serializable(&approval.rule)?)
            != environment.protection_rules.approval_rule_digest
        || approval.created_unix_ms > record.created_unix_ms
        || approval.expires_unix_ms
            > record
                .created_unix_ms
                .checked_add(environment.protection_rules.approval_ttl_ms)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "environment approval expiry",
                })?
    {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    approval
        .authorize(&record.approval_subject_digest, now_unix_ms)
        .map_err(|_| ControlPlaneError::EnvironmentGateNotReady)?;
    transaction.execute(
        "UPDATE approval_requests SET status = ?2, request_json = ?3 WHERE id = ?1",
        params![
            approval_id,
            approval_status_name(approval.status),
            serde_json::to_string(&approval)?
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn append_deployment_event_tx(
    transaction: &Transaction<'_>,
    record: &DeploymentRequestRecord,
) -> Result<(), ControlPlaneError> {
    let state_digest = hash_serializable(record)?;
    transaction.execute(
        "INSERT INTO deployment_request_events
         (deployment_request_id, tenant_id, version, status, state_digest,
          actor_id, audit_correlation_id, occurred_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            record.id,
            record.tenant_id,
            to_i64(record.version)?,
            record.status.as_str(),
            state_digest.as_str(),
            record.actor_id,
            record.audit_correlation_id,
            to_i64(record.updated_unix_ms)?
        ],
    )?;
    Ok(())
}

impl ControlPlane {
    pub fn reserve_deployment_request(
        &self,
        record: &DeploymentRequestRecord,
    ) -> Result<IdempotentResult<DeploymentRequestRecord>, ControlPlaneError> {
        validate_deployment_request_shape(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        if let Some(existing) = deployment_request_tx(&transaction, &record.tenant_id, &record.id)?
        {
            if existing == *record {
                transaction.commit()?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let environment = environment_tx(&transaction, &record.tenant_id, &record.environment_id)?
            .ok_or_else(|| not_found("environment", &record.environment_id))?;
        if environment.status != "active"
            || environment.version != record.environment_version
            || environment.required_policy_epoch != record.policy_epoch
        {
            return Err(ControlPlaneError::EnvironmentGateNotReady);
        }
        require_active_policy_epoch_tx(&transaction, &record.tenant_id, record.policy_epoch)?;
        validate_deployment_inputs_tx(&transaction, record, &environment)?;
        let expected_wait = record
            .created_unix_ms
            .checked_add(environment.wait_timer_ms)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "deployment wait deadline",
            })?;
        let expected_status = if environment.wait_timer_ms > 0 {
            DeploymentRequestStatus::WaitingTimer
        } else if environment.protection_rules.require_approval {
            DeploymentRequestStatus::AwaitingApproval
        } else {
            DeploymentRequestStatus::AwaitingConcurrency
        };
        if record.version != 1
            || record.status != expected_status
            || record.wait_until_unix_ms != expected_wait
            || record.concurrency_fence.is_some()
            || record.execution_lease_id.is_some()
            || record.lease_fencing_generation.is_some()
            || record.installation_fencing_epoch.is_some()
            || record.completed_unix_ms.is_some()
            || record.updated_unix_ms != record.created_unix_ms
            || environment.protection_rules.require_approval != record.approval_request_id.is_some()
            || (record.rollback_of_deployment_id.is_some() && record.approval_request_id.is_none())
        {
            return Err(ControlPlaneError::InvalidInput(
                "deployment request is not an exact initial reservation",
            ));
        }
        if let Some(approval_id) = &record.approval_request_id {
            let exact_capsule: bool = transaction.query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM approval_requests a JOIN runs r ON r.id = ?2
                   WHERE a.id = ?1 AND a.capsule_id = r.capsule_id
                     AND a.repository_id = ?3
                 )",
                params![approval_id, record.run_id, record.repository_id],
                |row| row.get(0),
            )?;
            let approval = approval_tx(&transaction, approval_id)
                .map_err(|_| ControlPlaneError::EnvironmentGateNotReady)?;
            if !exact_capsule
                || approval.kind != runtrue_policy::ApprovalKind::EnvironmentDeployment
                || approval.subject_digest != record.approval_subject_digest
                || !matches!(
                    approval.status,
                    ApprovalStatus::Pending | ApprovalStatus::Approved
                )
                || approval.rule.required_approvals
                    < u16::try_from(environment.protection_rules.minimum_approvals).map_err(
                        |_| {
                            ControlPlaneError::InvalidInput(
                                "invalid environment approval threshold",
                            )
                        },
                    )?
                || !approval.rule.one_shot
                || Some(hash_serializable(&approval.rule)?)
                    != environment.protection_rules.approval_rule_digest
                || approval.created_unix_ms > record.created_unix_ms
                || approval.expires_unix_ms
                    > record
                        .created_unix_ms
                        .checked_add(environment.protection_rules.approval_ttl_ms)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "environment approval expiry",
                        })?
            {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
        }
        if let Some(parent_id) = &record.rollback_of_deployment_id {
            let parent: Option<(String, Option<String>, String)> = transaction
                .query_row(
                    "SELECT d.environment_id, r.approval_request_id, d.status
                     FROM deployments d JOIN deployment_requests r
                       ON r.id = d.deployment_request_id AND r.tenant_id = d.tenant_id
                     WHERE d.tenant_id = ?1 AND d.id = ?2",
                    params![record.tenant_id, parent_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((parent_environment, parent_approval, parent_status)) = parent else {
                return Err(not_found("deployment", parent_id));
            };
            if parent_environment != record.environment_id
                || parent_status != "succeeded"
                || record.approval_request_id == parent_approval
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
        }
        transaction.execute(
            "INSERT INTO deployment_requests
             (id, tenant_id, environment_id, environment_version, policy_epoch,
              repository_id, run_id, job_id, job_attempt, artifact_id, promoted_artifact_id,
              artifact_source_run_id, artifact_source_job_id, artifact_source_job_attempt,
              artifact_digest, manifest_digest, provenance_digest, target_digest,
              deployment_capsule_digest, request_digest,
              approval_subject_digest, approval_request_id, rollback_of_deployment_id,
              status, wait_until_unix_ms, concurrency_fence, execution_lease_id,
              lease_fencing_generation, installation_fencing_epoch, actor_id,
              audit_correlation_id, created_unix_ms, updated_unix_ms,
              completed_unix_ms, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                     ?24, ?25, NULL, NULL, NULL, NULL, ?26, ?27, ?28, ?28, NULL, 1)",
            params![
                record.id,
                record.tenant_id,
                record.environment_id,
                to_i64(record.environment_version)?,
                to_i64(record.policy_epoch)?,
                record.repository_id,
                record.run_id,
                record.job_id,
                i64::from(record.job_attempt),
                record.artifact_id,
                record.promoted_artifact_id,
                record.artifact_source_run_id,
                record.artifact_source_job_id,
                i64::from(record.artifact_source_job_attempt),
                record.artifact_digest.as_str(),
                record.manifest_digest.as_str(),
                record.provenance_digest.as_str(),
                record.target_digest.as_str(),
                record.deployment_capsule_digest.as_str(),
                record.request_digest.as_str(),
                record.approval_subject_digest.as_str(),
                record.approval_request_id,
                record.rollback_of_deployment_id,
                record.status.as_str(),
                to_i64(record.wait_until_unix_ms)?,
                record.actor_id,
                record.audit_correlation_id,
                to_i64(record.created_unix_ms)?
            ],
        )?;
        append_deployment_event_tx(&transaction, record)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record.clone(),
            replayed: false,
        })
    }

    pub fn deployment_request(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> Result<DeploymentRequestRecord, ControlPlaneError> {
        validate_r10_identifier(request_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = deployment_request_tx(&transaction, tenant_id, request_id)?
            .ok_or_else(|| not_found("deployment request", request_id))?;
        validate_deployment_request_shape(&record)?;
        transaction.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mark_deployment_started(
        &self,
        tenant_id: &str,
        request_id: &str,
        execution_lease_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        actor_id: &str,
        audit_correlation_id: &str,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<DeploymentRequestRecord>, ControlPlaneError> {
        for value in [
            request_id,
            execution_lease_id,
            actor_id,
            audit_correlation_id,
        ] {
            validate_r10_identifier(value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let mut request = deployment_request_tx(&transaction, tenant_id, request_id)?
            .ok_or_else(|| not_found("deployment request", request_id))?;
        if request.status == DeploymentRequestStatus::InProgress
            && request.execution_lease_id.as_deref() == Some(execution_lease_id)
            && request.lease_fencing_generation == Some(fencing_generation)
            && request.installation_fencing_epoch == Some(installation_fencing_epoch)
        {
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: request,
                replayed: true,
            });
        }
        let valid: bool = transaction.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM leases l JOIN jobs j ON j.id = l.job_id
               WHERE l.tenant_id = ?1 AND l.id = ?2 AND l.job_id = ?3
                 AND j.attempt = ?4 AND l.fencing_generation = ?5
                 AND l.installation_fencing_epoch = ?6 AND l.state = 'active'
                 AND l.issued_unix_ms <= ?7 AND l.expires_unix_ms > ?7
                 AND l.hard_deadline_unix_ms > ?7
             )",
            params![
                tenant_id,
                execution_lease_id,
                request.job_id,
                i64::from(request.job_attempt),
                to_i64(fencing_generation)?,
                to_i64(installation_fencing_epoch)?,
                to_i64(now_unix_ms)?
            ],
            |row| row.get(0),
        )?;
        let safe_mode: bool = transaction.query_row(
            "SELECT safe_mode FROM installation_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if request.status != DeploymentRequestStatus::Leased
            || request.execution_lease_id.as_deref() != Some(execution_lease_id)
            || request.lease_fencing_generation != Some(fencing_generation)
            || request.installation_fencing_epoch != Some(installation_fencing_epoch)
            || installation_epoch_tx(&transaction)? != installation_fencing_epoch
            || safe_mode
            || !valid
        {
            return Err(ControlPlaneError::EnvironmentGateNotReady);
        }
        let environment = environment_tx(&transaction, tenant_id, &request.environment_id)?
            .ok_or_else(|| not_found("environment", &request.environment_id))?;
        validate_deployment_inputs_tx(&transaction, &request, &environment)?;
        request.status = DeploymentRequestStatus::InProgress;
        request.actor_id = actor_id.to_owned();
        request.audit_correlation_id = audit_correlation_id.to_owned();
        request.updated_unix_ms = now_unix_ms;
        request.version =
            request
                .version
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "deployment request version",
                })?;
        let changed = transaction.execute(
            "UPDATE deployment_requests SET status = 'in-progress', actor_id = ?3,
                    audit_correlation_id = ?4, updated_unix_ms = ?5, version = ?6
             WHERE tenant_id = ?1 AND id = ?2 AND status = 'leased'",
            params![
                tenant_id,
                request_id,
                actor_id,
                audit_correlation_id,
                to_i64(now_unix_ms)?,
                to_i64(request.version)?
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        append_deployment_event_tx(&transaction, &request)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: request,
            replayed: false,
        })
    }
}

mod gate;
mod results;

pub(in crate::store) use gate::{bind_deployment_gate_offer_tx, deployment_job_gate_ready_tx};
