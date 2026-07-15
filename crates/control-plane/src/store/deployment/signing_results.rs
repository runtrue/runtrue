use super::*;
pub(in crate::store) fn signing_result_row(
    row: &Row<'_>,
) -> rusqlite::Result<SigningResultJournalRecord> {
    let reservation_bytes: Vec<u8> = row.get(27)?;
    if reservation_bytes.len() > MAX_R10_RECORD_BYTES {
        return Err(conversion(
            27,
            DecodeError("signing reservation exceeds its bound".to_owned()),
        ));
    }
    let reservation: SigningResultReservation =
        serde_json::from_slice(&reservation_bytes).map_err(|error| conversion(27, error))?;
    let canonical = r10_json_bytes(&reservation, MAX_R10_RECORD_BYTES)
        .map_err(|error| conversion(27, error))?;
    let state_name: String = row.get(28)?;
    let result_bytes: Option<Vec<u8>> = row.get(29)?;
    let stored_result_digest = optional_digest_column(row, 30)?;
    let state = match (state_name.as_str(), result_bytes) {
        ("reserved", None) => SigningResultState::Reserved,
        ("aborted", None) => SigningResultState::Aborted,
        ("signed" | "complete", Some(bytes)) if bytes.len() <= MAX_R10_SIGNING_RESULT_BYTES => {
            let result: PublicSigningResult =
                serde_json::from_slice(&bytes).map_err(|error| conversion(29, error))?;
            let result_canonical = r10_json_bytes(&result, MAX_R10_SIGNING_RESULT_BYTES)
                .map_err(|error| conversion(29, error))?;
            if bytes != result_canonical
                || result
                    .expected_result_digest()
                    .map_err(|error| conversion(29, error))?
                    != result.result_digest
                || stored_result_digest.as_ref() != Some(&result.result_digest)
            {
                return Err(conversion(
                    29,
                    DecodeError("signing result digest changed".to_owned()),
                ));
            }
            if state_name == "signed" {
                SigningResultState::Signed(result)
            } else {
                SigningResultState::Complete(result)
            }
        }
        _ => {
            return Err(conversion(
                28,
                DecodeError("invalid signing result state".to_owned()),
            ));
        }
    };
    let retry_attempts = u32::try_from(u64_column(row, 31, "signing retry attempts")?)
        .map_err(|error| conversion(31, error))?;
    let updated_unix_ms = u64_column(row, 34, "signing update")?;
    let completed_unix_ms = optional_u64_column(row, 35, "signing completion")?;
    let request_id: String = row.get(0)?;
    let request_digest = digest_column(row, 26)?;
    if reservation_bytes != canonical
        || reservation.request_id != request_id
        || reservation.request_digest != request_digest
        || reservation
            .expected_request_digest()
            .map_err(|error| conversion(27, error))?
            != reservation.request_digest
        || retry_attempts > 8
        || updated_unix_ms < reservation.requested_unix_ms
        || completed_unix_ms.is_some() != matches!(state, SigningResultState::Complete(_))
    {
        return Err(conversion(
            27,
            DecodeError("signing reservation durable binding changed".to_owned()),
        ));
    }
    Ok(SigningResultJournalRecord {
        reservation,
        state,
        retry_attempts,
        updated_unix_ms,
        completed_unix_ms,
    })
}

const SIGNING_RESULT_COLUMNS: &str = "request_id, tenant_id, provider_configuration_id,
     provider_configuration_digest, provider_configuration_version, environment_id,
     deployment_request_id, repository_id, run_id, job_id, job_attempt, step_id,
     execution_lease_id, fencing_generation, installation_fencing_epoch, policy_epoch,
     environment_version, approval_request_id, approval_subject_digest,
     artifact_digest, provenance_digest, purpose, operation, signer_policy_id,
     signer_policy_digest, signer_policy_version, request_digest, reservation_json,
     state, result_json, result_digest, retry_attempts, requested_unix_ms,
     expires_unix_ms, updated_unix_ms, completed_unix_ms";

pub(in crate::store) fn signing_result_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    request_id: &str,
) -> Result<Option<SigningResultJournalRecord>, ControlPlaneError> {
    let sql = format!(
        "SELECT {SIGNING_RESULT_COLUMNS} FROM signing_result_journal
         WHERE tenant_id = ?1 AND request_id = ?2"
    );
    Ok(transaction
        .query_row(&sql, params![tenant_id, request_id], signing_result_row)
        .optional()?)
}

pub(in crate::store) fn signing_capability_declared_tx(
    transaction: &Transaction<'_>,
    reservation: &SigningResultReservation,
) -> Result<bool, ControlPlaneError> {
    let (canonical_capsule, job_key): (Vec<u8>, String) = transaction.query_row(
        "SELECT p.canonical_capsule, j.job_key FROM jobs j
         JOIN runs r ON r.id = j.run_id JOIN capsules p ON p.id = r.capsule_id
         WHERE j.id = ?1 AND j.run_id = ?2",
        params![reservation.job_id, reservation.run_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
    if capsule.canonical_bytes()? != canonical_capsule {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let jobs = materialized_planned_jobs_conn(transaction, &reservation.run_id, &capsule)?;
    let job = jobs.get(&job_key).ok_or_else(|| {
        ControlPlaneError::CorruptState("signing job is absent from its signed capsule".to_owned())
    })?;
    let step = job
        .steps
        .iter()
        .find(|step| step.id == reservation.step_id)
        .or_else(|| {
            job.finalizers
                .iter()
                .map(|finalizer| &finalizer.step)
                .find(|step| step.id == reservation.step_id)
        });
    let Some(step) = step else {
        return Ok(false);
    };
    Ok(step.capabilities.signing.iter().any(|capability| {
        capability.purpose == reservation.purpose
            && capability.key_policy == reservation.signer_policy_id
            && matches!(
                (capability.operation, reservation.operation.as_str()),
                (
                    runtrue_workflow_ir::SigningOperation::SignDigest,
                    "sign-digest"
                ) | (
                    runtrue_workflow_ir::SigningOperation::SignAttestation,
                    "sign-attestation"
                )
            )
    }))
}

pub(in crate::store) fn validate_signing_reservation_tx(
    transaction: &Transaction<'_>,
    reservation: &SigningResultReservation,
) -> Result<(), ControlPlaneError> {
    for value in [
        &reservation.request_id,
        &reservation.tenant_id,
        &reservation.provider_configuration_id,
        &reservation.environment_id,
        &reservation.deployment_request_id,
        &reservation.repository_id,
        &reservation.run_id,
        &reservation.job_id,
        &reservation.step_id,
        &reservation.execution_lease_id,
        &reservation.approval_request_id,
        &reservation.purpose,
        &reservation.signer_policy_id,
    ] {
        validate_r10_identifier(value)?;
    }
    if reservation.job_attempt == 0
        || reservation.fencing_generation == 0
        || reservation.installation_fencing_epoch == 0
        || reservation.policy_epoch == 0
        || reservation.environment_version == 0
        || reservation.provider_configuration_version == 0
        || reservation.signer_policy_version == 0
        || !matches!(
            reservation.operation.as_str(),
            "sign-digest" | "sign-attestation"
        )
        || reservation.expires_unix_ms <= reservation.requested_unix_ms
        || reservation.expires_unix_ms - reservation.requested_unix_ms > 15 * 60 * 1_000
        || reservation.expected_request_digest()? != reservation.request_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid signing result reservation",
        ));
    }
    require_r9_tenant_tx(transaction, &reservation.tenant_id)?;
    let deployment = deployment_request_tx(
        transaction,
        &reservation.tenant_id,
        &reservation.deployment_request_id,
    )?
    .ok_or_else(|| not_found("deployment request", &reservation.deployment_request_id))?;
    let environment = environment_tx(
        transaction,
        &reservation.tenant_id,
        &reservation.environment_id,
    )?
    .ok_or_else(|| not_found("environment", &reservation.environment_id))?;
    let provider = provider_configuration_tx(
        transaction,
        &reservation.tenant_id,
        &reservation.provider_configuration_id,
    )?
    .ok_or_else(|| {
        not_found(
            "provider configuration",
            &reservation.provider_configuration_id,
        )
    })?;
    let policy = signer_policy_tx(
        transaction,
        &reservation.tenant_id,
        &reservation.signer_policy_id,
    )?
    .ok_or_else(|| not_found("signer policy", &reservation.signer_policy_id))?;
    require_environment_version_tx(transaction, &environment)?;
    require_provider_configuration_version_tx(transaction, &provider)?;
    require_signer_policy_version_tx(transaction, &policy)?;
    if environment.status != "active"
        || !environment.protection_rules.require_signed_artifact
        || environment.version != reservation.environment_version
        || environment.required_policy_epoch != reservation.policy_epoch
        || environment.signing_provider_configuration_id.as_deref()
            != Some(reservation.provider_configuration_id.as_str())
        || environment
            .protection_rules
            .allowed_signer_policy_ids
            .binary_search(&reservation.signer_policy_id)
            .is_err()
        || provider.capability != "signing"
        || provider.status != "active"
        || provider.configuration_digest != reservation.provider_configuration_digest
        || provider.version != reservation.provider_configuration_version
        || policy.status != "active"
        || policy.provider_configuration_id != reservation.provider_configuration_id
        || policy.policy_digest != reservation.signer_policy_digest
        || policy.version != reservation.signer_policy_version
        || policy.purpose != reservation.purpose
        || policy.operation != reservation.operation
        || deployment.environment_id != reservation.environment_id
        || deployment.repository_id != reservation.repository_id
        || deployment.run_id != reservation.run_id
        || deployment.job_id != reservation.job_id
        || deployment.job_attempt != reservation.job_attempt
        || deployment.policy_epoch != reservation.policy_epoch
        || deployment.environment_version != reservation.environment_version
        || deployment.approval_request_id.as_deref()
            != Some(reservation.approval_request_id.as_str())
        || deployment.approval_subject_digest != reservation.approval_subject_digest
        || deployment.artifact_digest != reservation.artifact_digest
        || deployment.provenance_digest != reservation.provenance_digest
        || deployment.execution_lease_id.as_deref() != Some(reservation.execution_lease_id.as_str())
        || deployment.lease_fencing_generation != Some(reservation.fencing_generation)
        || deployment.installation_fencing_epoch != Some(reservation.installation_fencing_epoch)
        || !matches!(
            deployment.status,
            DeploymentRequestStatus::Leased | DeploymentRequestStatus::InProgress
        )
        || !signing_capability_declared_tx(transaction, reservation)?
    {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    let lease_valid: bool = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM leases l JOIN jobs j ON j.id = l.job_id
           JOIN runs r ON r.id = j.run_id JOIN repositories repo ON repo.id = r.repository_id
           WHERE l.tenant_id = ?1 AND l.id = ?2 AND l.job_id = ?3
             AND j.attempt = ?4 AND j.run_id = ?5 AND repo.tenant_id = ?1
             AND l.fencing_generation = ?6 AND l.installation_fencing_epoch = ?7
             AND l.state = 'active' AND l.issued_unix_ms <= ?8
             AND l.expires_unix_ms > ?8 AND l.hard_deadline_unix_ms > ?8
         )",
        params![
            reservation.tenant_id,
            reservation.execution_lease_id,
            reservation.job_id,
            i64::from(reservation.job_attempt),
            reservation.run_id,
            to_i64(reservation.fencing_generation)?,
            to_i64(reservation.installation_fencing_epoch)?,
            to_i64(reservation.requested_unix_ms)?
        ],
        |row| row.get(0),
    )?;
    let safe_mode: bool = transaction.query_row(
        "SELECT safe_mode FROM installation_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if !lease_valid
        || safe_mode
        || installation_epoch_tx(transaction)? != reservation.installation_fencing_epoch
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

impl ControlPlane {
    pub fn reserve_signing_result(
        &self,
        reservation: &SigningResultReservation,
    ) -> Result<IdempotentResult<SigningResultJournalRecord>, ControlPlaneError> {
        let reservation_json = r10_json_bytes(reservation, MAX_R10_RECORD_BYTES)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &reservation.tenant_id)?;
        if let Some(existing) = signing_result_tx(
            &transaction,
            &reservation.tenant_id,
            &reservation.request_id,
        )? {
            if existing.reservation == *reservation {
                transaction.commit()?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        validate_signing_reservation_tx(&transaction, reservation)?;
        transaction.execute(
            "INSERT INTO signing_result_journal
             (request_id, tenant_id, provider_configuration_id,
              provider_configuration_digest, provider_configuration_version,
              environment_id, deployment_request_id, repository_id, run_id,
              job_id, job_attempt, step_id, execution_lease_id, fencing_generation,
              installation_fencing_epoch, policy_epoch, environment_version,
              approval_request_id, approval_subject_digest, artifact_digest,
              provenance_digest, purpose, operation, signer_policy_id,
              signer_policy_digest, signer_policy_version, request_digest,
              reservation_json, state, result_json, result_digest, retry_attempts,
              requested_unix_ms, expires_unix_ms, updated_unix_ms, completed_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                     ?23, ?24, ?25, ?26, ?27, ?28, 'reserved', NULL, NULL, 0,
                     ?29, ?30, ?29, NULL)",
            params![
                reservation.request_id,
                reservation.tenant_id,
                reservation.provider_configuration_id,
                reservation.provider_configuration_digest.as_str(),
                to_i64(reservation.provider_configuration_version)?,
                reservation.environment_id,
                reservation.deployment_request_id,
                reservation.repository_id,
                reservation.run_id,
                reservation.job_id,
                i64::from(reservation.job_attempt),
                reservation.step_id,
                reservation.execution_lease_id,
                to_i64(reservation.fencing_generation)?,
                to_i64(reservation.installation_fencing_epoch)?,
                to_i64(reservation.policy_epoch)?,
                to_i64(reservation.environment_version)?,
                reservation.approval_request_id,
                reservation.approval_subject_digest.as_str(),
                reservation.artifact_digest.as_str(),
                reservation.provenance_digest.as_str(),
                reservation.purpose,
                reservation.operation,
                reservation.signer_policy_id,
                reservation.signer_policy_digest.as_str(),
                to_i64(reservation.signer_policy_version)?,
                reservation.request_digest.as_str(),
                reservation_json,
                to_i64(reservation.requested_unix_ms)?,
                to_i64(reservation.expires_unix_ms)?
            ],
        )?;
        let record = SigningResultJournalRecord {
            reservation: reservation.clone(),
            state: SigningResultState::Reserved,
            retry_attempts: 0,
            updated_unix_ms: reservation.requested_unix_ms,
            completed_unix_ms: None,
        };
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record,
            replayed: false,
        })
    }

    pub fn record_signed_result(
        &self,
        reservation: &SigningResultReservation,
        result: &PublicSigningResult,
    ) -> Result<IdempotentResult<SigningResultJournalRecord>, ControlPlaneError> {
        if result.signature.is_empty()
            || result.signature.len() > 16 * 1024
            || result
                .certificate
                .as_ref()
                .is_some_and(|value| value.len() > 512 * 1024)
            || result
                .attestation
                .as_ref()
                .is_some_and(|value| value.len() > 512 * 1024)
            || result.signed_unix_ms < reservation.requested_unix_ms
            || result.signed_unix_ms >= reservation.expires_unix_ms
            || result.expected_result_digest()? != result.result_digest
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid public signing result",
            ));
        }
        let result_json = r10_json_bytes(result, MAX_R10_SIGNING_RESULT_BYTES)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &reservation.tenant_id)?;
        let existing = signing_result_tx(
            &transaction,
            &reservation.tenant_id,
            &reservation.request_id,
        )?
        .ok_or_else(|| not_found("signing result", &reservation.request_id))?;
        if existing.reservation != *reservation {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        match &existing.state {
            SigningResultState::Signed(stored) | SigningResultState::Complete(stored)
                if stored == result =>
            {
                transaction.commit()?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            SigningResultState::Reserved => {}
            _ => return Err(ControlPlaneError::IdempotencyConflict),
        }
        let changed = transaction.execute(
            "UPDATE signing_result_journal SET state = 'signed', result_json = ?3,
                    result_digest = ?4, retry_attempts = retry_attempts + 1,
                    updated_unix_ms = ?5
             WHERE tenant_id = ?1 AND request_id = ?2 AND state = 'reserved'
               AND retry_attempts < 8",
            params![
                reservation.tenant_id,
                reservation.request_id,
                result_json,
                result.result_digest.as_str(),
                to_i64(result.signed_unix_ms)?
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let value = SigningResultJournalRecord {
            reservation: reservation.clone(),
            state: SigningResultState::Signed(result.clone()),
            retry_attempts: existing.retry_attempts.saturating_add(1),
            updated_unix_ms: result.signed_unix_ms,
            completed_unix_ms: None,
        };
        transaction.commit()?;
        Ok(IdempotentResult {
            value,
            replayed: false,
        })
    }

    pub fn complete_signing_result(
        &self,
        tenant_id: &str,
        request_id: &str,
        request_digest: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<SigningResultJournalRecord>, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let existing = signing_result_tx(&transaction, tenant_id, request_id)?
            .ok_or_else(|| not_found("signing result", request_id))?;
        if existing.reservation.request_digest != *request_digest {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if matches!(existing.state, SigningResultState::Complete(_)) {
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        let SigningResultState::Signed(result) = &existing.state else {
            return Err(ControlPlaneError::InvalidTransition {
                entity: "signing result",
                from: "not-signed",
                to: "complete",
            });
        };
        if now_unix_ms < result.signed_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "signing completion predates signature",
            ));
        }
        let completed_result = result.clone();
        let changed = transaction.execute(
            "UPDATE signing_result_journal SET state = 'complete',
                    updated_unix_ms = ?3, completed_unix_ms = ?3
             WHERE tenant_id = ?1 AND request_id = ?2 AND state = 'signed'",
            params![tenant_id, request_id, to_i64(now_unix_ms)?],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let mut value = existing;
        value.state = SigningResultState::Complete(completed_result);
        value.updated_unix_ms = now_unix_ms;
        value.completed_unix_ms = Some(now_unix_ms);
        transaction.commit()?;
        Ok(IdempotentResult {
            value,
            replayed: false,
        })
    }

    pub fn signing_result(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> Result<SigningResultJournalRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = signing_result_tx(&transaction, tenant_id, request_id)?
            .ok_or_else(|| not_found("signing result", request_id))?;
        transaction.commit()?;
        Ok(record)
    }
}
