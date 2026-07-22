use super::*;

pub(in crate::store) fn random_broker_id(prefix: &str) -> Result<String, ControlPlaneError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
    Ok(format!("{prefix}-{}", hex::encode(bytes)))
}

pub(in crate::store) fn insert_runner_secret_lease_tx(
    transaction: &Transaction<'_>,
    record: &RunnerSecretLeaseRecord,
) -> Result<(), ControlPlaneError> {
    transaction
        .execute(
            "INSERT INTO runner_secret_leases
             (id, execution_lease_id, fencing_generation, installation_fencing_epoch,
              runner_id, tenant_id, repository_id, run_id, job_id, job_attempt, step_id,
              secret_metadata_id, secret_version, purpose, guest_key_fingerprint,
              runner_posture_digest, issued_unix_ms, expires_unix_ms, state,
              revoked_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                record.id,
                record.execution_lease_id,
                to_i64(record.fencing_generation)?,
                to_i64(record.installation_fencing_epoch)?,
                record.runner_id,
                record.tenant_id,
                record.repository_id,
                record.run_id,
                record.job_id,
                to_i64(u64::from(record.job_attempt))?,
                record.step_id,
                record.secret_metadata_id,
                to_i64(record.secret_version)?,
                record.purpose,
                record.guest_key_fingerprint.as_str(),
                record.runner_posture_digest.as_str(),
                to_i64(record.issued_unix_ms)?,
                to_i64(record.expires_unix_ms)?,
                record.state,
                record.revoked_unix_ms.map(to_i64).transpose()?,
            ],
        )
        .map_err(map_runner_broker_insert_error)?;
    Ok(())
}

pub(in crate::store) fn runner_secret_lease_conn(
    connection: &Connection,
    id: &str,
) -> Result<RunnerSecretLeaseRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, execution_lease_id, fencing_generation,
                    installation_fencing_epoch, runner_id, tenant_id, repository_id,
                    run_id, job_id, job_attempt, step_id, secret_metadata_id, secret_version,
                    purpose, guest_key_fingerprint, runner_posture_digest,
                    issued_unix_ms, expires_unix_ms, state, revoked_unix_ms
             FROM runner_secret_leases WHERE id = ?1",
            [id],
            runner_secret_lease_row,
        )
        .optional()?
        .ok_or_else(|| not_found("runner secret lease", id))
}

pub(in crate::store) fn runner_secret_lease_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<RunnerSecretLeaseRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, execution_lease_id, fencing_generation,
                    installation_fencing_epoch, runner_id, tenant_id, repository_id,
                    run_id, job_id, job_attempt, step_id, secret_metadata_id, secret_version,
                    purpose, guest_key_fingerprint, runner_posture_digest,
                    issued_unix_ms, expires_unix_ms, state, revoked_unix_ms
             FROM runner_secret_leases WHERE id = ?1",
            [id],
            runner_secret_lease_row,
        )
        .optional()?
        .ok_or_else(|| not_found("runner secret lease", id))
}

pub(in crate::store) fn runner_secret_lease_row(
    row: &Row<'_>,
) -> rusqlite::Result<RunnerSecretLeaseRecord> {
    Ok(RunnerSecretLeaseRecord {
        id: row.get(0)?,
        execution_lease_id: row.get(1)?,
        fencing_generation: u64_column(row, 2, "fencing_generation")?,
        installation_fencing_epoch: u64_column(row, 3, "installation_fencing_epoch")?,
        runner_id: row.get(4)?,
        tenant_id: row.get(5)?,
        repository_id: row.get(6)?,
        run_id: row.get(7)?,
        job_id: row.get(8)?,
        job_attempt: row.get(9)?,
        step_id: row.get(10)?,
        secret_metadata_id: row.get(11)?,
        secret_version: u64_column(row, 12, "secret_version")?,
        purpose: row.get(13)?,
        guest_key_fingerprint: digest_column(row, 14)?,
        runner_posture_digest: digest_column(row, 15)?,
        issued_unix_ms: u64_column(row, 16, "issued_unix_ms")?,
        expires_unix_ms: u64_column(row, 17, "expires_unix_ms")?,
        state: row.get(18)?,
        revoked_unix_ms: optional_u64_column(row, 19, "revoked_unix_ms")?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::store) fn append_runner_broker_audit_tx(
    transaction: &Transaction<'_>,
    installation_id: &str,
    tenant_id: &str,
    runner_id: &str,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    observed_unix_ms: u64,
    metadata: BTreeMap<String, AuditValue>,
) -> Result<(), ControlPlaneError> {
    append_audit_event_tx(
        transaction,
        installation_id,
        AuditEventData {
            observed_unix_ms,
            tenant_id: tenant_id.to_owned(),
            actor: AuditPrincipal {
                kind: "runner".to_owned(),
                id: runner_id.to_owned(),
            },
            action: action.to_owned(),
            resource: AuditResource {
                kind: resource_kind.to_owned(),
                id: resource_id.to_owned(),
            },
            result: "success".to_owned(),
            request_id: format!("runner-broker:{resource_id}"),
            decision_id: None,
            metadata,
        },
    )?;
    Ok(())
}

pub(in crate::store) fn revoke_runner_broker_state_tx(
    transaction: &Transaction<'_>,
    execution_lease_id: &str,
    fencing_generation: u64,
    revoked_unix_ms: u64,
    terminal_state: &str,
) -> Result<(usize, usize), ControlPlaneError> {
    if !matches!(terminal_state, "revoked" | "expired") {
        return Err(ControlPlaneError::InvalidInput(
            "runner broker terminal state is invalid",
        ));
    }
    let secret_count = transaction.execute(
        "UPDATE runner_secret_leases
         SET state = ?3, revoked_unix_ms = ?4
         WHERE execution_lease_id = ?1 AND fencing_generation = ?2
           AND state = 'delivered'",
        params![
            execution_lease_id,
            to_i64(fencing_generation)?,
            terminal_state,
            to_i64(revoked_unix_ms)?,
        ],
    )?;
    let oidc_count = transaction.execute(
        "UPDATE runner_oidc_issuances
         SET state = ?3, revoked_unix_ms = ?4
         WHERE execution_lease_id = ?1 AND fencing_generation = ?2
           AND state = 'issued'",
        params![
            execution_lease_id,
            to_i64(fencing_generation)?,
            terminal_state,
            to_i64(revoked_unix_ms)?,
        ],
    )?;
    transaction.execute(
        "UPDATE oidc_grants SET revoked_unix_ms = ?3
         WHERE revoked_unix_ms IS NULL AND id IN (
             SELECT grant_id FROM runner_oidc_issuances
             WHERE execution_lease_id = ?1 AND fencing_generation = ?2
         )",
        params![
            execution_lease_id,
            to_i64(fencing_generation)?,
            to_i64(revoked_unix_ms)?,
        ],
    )?;
    Ok((secret_count, oidc_count))
}

pub(in crate::store) fn map_runner_broker_insert_error(
    error: rusqlite::Error,
) -> ControlPlaneError {
    if matches!(
        &error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
    ) {
        ControlPlaneError::RunnerBrokerReplay
    } else {
        ControlPlaneError::Sqlite(error)
    }
}

pub(in crate::store) fn validate_runner_secret_request(
    request: &IssueRunnerSecretRequest,
) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("execution lease id", request.execution_lease_id.as_str()),
        ("runner id", request.runner_id.as_str()),
        ("job id", request.job_id.as_str()),
        ("step id", request.step_id.as_str()),
        ("secret metadata id", request.secret_metadata_id.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if request.purpose.len() > MAX_TEXT_BYTES
        || request.purpose.contains('\0')
        || request.fencing_generation == 0
        || request.job_attempt == 0
        || request.expires_unix_ms <= request.issued_unix_ms
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

pub(in crate::store) fn runner_execution_subject_tx(
    transaction: &Transaction<'_>,
    execution_lease_id: &str,
    runner_id: &str,
    fencing_generation: u64,
    job_id: &str,
    now_unix_ms: u64,
) -> Result<RunnerExecutionSubject, ControlPlaneError> {
    let lease = validate_active_runner_broker_lease_tx(
        transaction,
        execution_lease_id,
        runner_id,
        fencing_generation,
        now_unix_ms,
    )?;
    if lease.job_id != job_id {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let row: Option<RunnerExecutionSubjectRow> = transaction
        .query_row(
            "SELECT j.run_id, j.job_key, r.repository_id, repositories.tenant_id,
                    r.capsule_id, p.canonical_capsule, p.digest
             FROM jobs j
             JOIN runs r ON r.id = j.run_id
             JOIN repositories ON repositories.id = r.repository_id
             JOIN capsules p ON p.id = r.capsule_id
             WHERE j.id = ?1",
            [job_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((run_id, job_key, repository_id, tenant_id, capsule_id, bytes, stored_digest)) = row
    else {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    };
    let capsule: ExecutionCapsule = serde_json::from_slice(&bytes)?;
    let canonical = capsule.canonical_bytes()?;
    let digest = capsule.digest()?;
    if canonical != bytes
        || digest != lease.capsule_digest
        || digest.as_str() != stored_digest
        || lease.tenant_id != tenant_id
    {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let planned_jobs = materialized_planned_jobs_conn(transaction, &run_id, &capsule)?;
    let planned_job = planned_jobs
        .get(&job_key)
        .cloned()
        .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
    let (runner_pool_id, runner_posture_digest) =
        authoritative_runner_binding_tx(transaction, runner_id)?;
    Ok(RunnerExecutionSubject {
        lease,
        run_id,
        repository_id,
        tenant_id,
        capsule_id,
        capsule,
        planned_job,
        runner_pool_id,
        runner_posture_digest,
    })
}

pub(in crate::store) fn authoritative_runner_binding_tx(
    transaction: &Transaction<'_>,
    runner_id: &str,
) -> Result<(String, ContentDigest), ControlPlaneError> {
    let persisted = persisted_runner_tx(transaction, runner_id)?;
    let binding: Option<(String, String)> = transaction
        .query_row(
            "SELECT inventory_digest, posture_digest FROM runner_enrollment_postures
             WHERE runner_id = ?1",
            [runner_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((inventory, stored_posture)) = binding else {
        return Err(ControlPlaneError::RunnerReenrollmentRequired);
    };
    let inventory = ContentDigest::parse(inventory)?;
    let posture = authoritative_runner_posture_digest(&persisted.runner, &inventory)?;
    if posture != ContentDigest::parse(stored_posture)? {
        return Err(ControlPlaneError::RunnerInventoryMismatch);
    }
    Ok((persisted.runner.pool_id, posture))
}

pub(in crate::store) fn validate_active_runner_broker_lease_tx(
    transaction: &Transaction<'_>,
    lease_id: &str,
    runner_id: &str,
    fencing_generation: u64,
    now_unix_ms: u64,
) -> Result<Lease, ControlPlaneError> {
    let (installation_epoch, safe_mode): (i64, bool) = transaction.query_row(
        "SELECT fencing_epoch, safe_mode FROM installation_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let installation_epoch = from_i64("fencing_epoch", installation_epoch)?;
    if safe_mode {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let lease = lease_tx(transaction, lease_id)?;
    let hard_deadline = lease_hard_deadline_tx(transaction, lease_id)?;
    if lease.runner_id != runner_id
        || lease.fencing_generation != fencing_generation
        || lease.installation_fencing_epoch != installation_epoch
        || lease.state != LeaseState::Active
        || now_unix_ms < lease.issued_unix_ms
        || now_unix_ms >= lease.expires_unix_ms
        || now_unix_ms >= hard_deadline
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(lease)
}

pub(in crate::store) fn runner_approval_subject_tx(
    transaction: &Transaction<'_>,
    capsule_id: &str,
    run_id: &str,
    capsule: &ExecutionCapsule,
) -> Result<Option<ContentDigest>, ControlPlaneError> {
    if !capsule.approval.workflow_definition && !capsule.approval.privileged_execution {
        return Ok(None);
    }
    let encoded: Option<String> = transaction
        .query_row(
            "SELECT approval_subject_digest FROM capsule_api_metadata WHERE capsule_id = ?1",
            [capsule_id],
            |row| row.get(0),
        )
        .optional()?;
    let digest = encoded
        .map(ContentDigest::parse)
        .transpose()?
        .ok_or(ControlPlaneError::ApprovalRequired)?;
    for (required, kind) in [
        (
            capsule.approval.workflow_definition,
            runtrue_policy::ApprovalKind::WorkflowDefinition,
        ),
        (
            capsule.approval.privileged_execution,
            runtrue_policy::ApprovalKind::PrivilegedExecution,
        ),
    ] {
        if !required {
            continue;
        }
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM run_approval_authorizations
                 WHERE run_id = ?1 AND kind = ?2 AND subject_digest = ?3
             )",
            params![run_id, approval_kind_name(kind), digest.as_str()],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(ControlPlaneError::ApprovalRequired);
        }
    }
    Ok(Some(digest))
}

impl ControlPlane {
    pub fn issue_runner_secret(
        &self,
        request: &IssueRunnerSecretRequest,
        master_key: &MasterKey,
    ) -> Result<DeliveredRunnerSecret, ControlPlaneError> {
        validate_runner_secret_request(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let subject = runner_execution_subject_tx(
            &transaction,
            &request.execution_lease_id,
            &request.runner_id,
            request.fencing_generation,
            &request.job_id,
            request.issued_unix_ms,
        )?;
        if !subject.capsule.approval.privileged_execution
            || runner_approval_subject_tx(
                &transaction,
                &subject.capsule_id,
                &subject.run_id,
                &subject.capsule,
            )?
            .is_none()
        {
            return Err(ControlPlaneError::ApprovalRequired);
        }
        if request.runner_posture_digest != subject.runner_posture_digest
            || request.expires_unix_ms > subject.lease.expires_unix_ms
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let step = (request.job_attempt <= subject.planned_job.retries.saturating_add(1))
            .then_some(&subject.planned_job)
            .and_then(|job| job.steps.iter().find(|step| step.id == request.step_id))
            .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
        let metadata = secret_metadata_tx(&transaction, &request.secret_metadata_id)?;
        let declared = step.capabilities.secrets.iter().find(|secret| {
            secret.metadata_id == metadata.id
                && secret.name == metadata.name
                && secret.purpose.as_deref().unwrap_or_default() == request.purpose
        });
        let binding = declared.and_then(|secret| secret.resolution.as_ref());
        if declared.is_none()
            || binding.is_none_or(|binding| binding.scope != metadata.scope)
            || metadata.tenant_id != subject.tenant_id
            || metadata.provider != "built-in"
            || metadata.provider_reference.is_some()
            || metadata.status != "active"
        {
            return Err(ControlPlaneError::RunnerBrokerCapabilityDenied);
        }
        let secret_version = binding
            .and_then(|binding| binding.metadata_version)
            .filter(|version| {
                metadata
                    .current_version
                    .is_some_and(|current| *version <= current)
            })
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "signed built-in secret binding has no eligible exact version".to_owned(),
                )
            })?;
        let identity = SecretIdentity::new(
            metadata.tenant_id.clone(),
            metadata.scope.clone(),
            metadata.name.clone(),
        )?;
        let vault = load_secret_vault_tx(
            &transaction,
            &metadata.tenant_id,
            &metadata.scope,
            master_key,
            &self.installation_id,
        )?;
        let plaintext = vault.reveal_for_administration(&identity, Some(secret_version))?;
        let id = random_broker_id("secret-lease")?;
        let record = RunnerSecretLeaseRecord {
            id: id.clone(),
            execution_lease_id: subject.lease.id.clone(),
            fencing_generation: subject.lease.fencing_generation,
            installation_fencing_epoch: subject.lease.installation_fencing_epoch,
            runner_id: request.runner_id.clone(),
            tenant_id: subject.tenant_id.clone(),
            repository_id: subject.repository_id.clone(),
            run_id: subject.run_id.clone(),
            job_id: request.job_id.clone(),
            job_attempt: request.job_attempt,
            step_id: request.step_id.clone(),
            secret_metadata_id: metadata.id,
            secret_version,
            purpose: request.purpose.clone(),
            guest_key_fingerprint: request.guest_key_fingerprint.clone(),
            runner_posture_digest: request.runner_posture_digest.clone(),
            issued_unix_ms: request.issued_unix_ms,
            expires_unix_ms: request.expires_unix_ms,
            state: "delivered".to_owned(),
            revoked_unix_ms: None,
        };
        insert_runner_secret_lease_tx(&transaction, &record)?;
        append_runner_broker_audit_tx(
            &transaction,
            &self.installation_id,
            &record.tenant_id,
            &record.runner_id,
            "runner.secret.deliver",
            "secret_lease",
            &record.id,
            request.issued_unix_ms,
            BTreeMap::from([
                (
                    "execution_lease_id".to_owned(),
                    AuditValue::String(record.execution_lease_id.clone()),
                ),
                (
                    "step_id".to_owned(),
                    AuditValue::String(record.step_id.clone()),
                ),
                (
                    "secret_metadata_id".to_owned(),
                    AuditValue::String(record.secret_metadata_id.clone()),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(DeliveredRunnerSecret {
            lease: record,
            plaintext,
        })
    }

    pub fn runner_secret_lease(
        &self,
        id: &str,
    ) -> Result<RunnerSecretLeaseRecord, ControlPlaneError> {
        validate_text("runner secret lease id", id)?;
        let connection = self.connection()?;
        runner_secret_lease_conn(&connection, id)
    }

    /// Idempotently revoke an exact, already-delivered secret lease.
    pub fn revoke_runner_secret(
        &self,
        id: &str,
        execution_lease_id: &str,
        fencing_generation: u64,
        runner_id: &str,
        now_unix_ms: u64,
    ) -> Result<RunnerSecretLeaseRecord, ControlPlaneError> {
        validate_text("runner secret lease id", id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = runner_secret_lease_tx(&transaction, id)?;
        if record.execution_lease_id != execution_lease_id
            || record.fencing_generation != fencing_generation
            || record.runner_id != runner_id
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let lease = validate_active_runner_broker_lease_tx(
            &transaction,
            execution_lease_id,
            runner_id,
            fencing_generation,
            now_unix_ms,
        )?;
        if lease.installation_fencing_epoch != record.installation_fencing_epoch {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        if record.state == "delivered" {
            transaction.execute(
                "UPDATE runner_secret_leases
                 SET state = 'revoked', revoked_unix_ms = ?2 WHERE id = ?1",
                params![id, to_i64(now_unix_ms)?],
            )?;
            append_runner_broker_audit_tx(
                &transaction,
                &self.installation_id,
                &record.tenant_id,
                runner_id,
                "runner.secret.revoke",
                "secret_lease",
                id,
                now_unix_ms,
                BTreeMap::from([(
                    "execution_lease_id".to_owned(),
                    AuditValue::String(execution_lease_id.to_owned()),
                )]),
            )?;
            record.state = "revoked".to_owned();
            record.revoked_unix_ms = Some(now_unix_ms);
        } else if record.state != "revoked" {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transaction.commit()?;
        Ok(record)
    }
}
