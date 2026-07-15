use super::*;

pub(in crate::store) fn validate_runner_oidc_request(
    request: &AuthorizeRunnerOidcRequest,
) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("execution lease id", request.execution_lease_id.as_str()),
        ("runner id", request.runner_id.as_str()),
        ("job id", request.job_id.as_str()),
        ("step id", request.step_id.as_str()),
        ("OIDC audience", request.audience.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if request.fencing_generation == 0 || request.job_attempt == 0 {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

pub(in crate::store) fn validate_record_runner_oidc(
    request: &RecordRunnerOidcIssuance,
) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("OIDC grant id", request.grant_id.as_str()),
        ("OIDC audience", request.audience.as_str()),
        ("OIDC jti", request.jti.as_str()),
        ("runner id", request.runner_id.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if request.job_attempt == 0 || request.expires_unix_ms <= request.issued_unix_ms {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok(())
}

pub(in crate::store) fn runner_oidc_grant_id(
    lease: &Lease,
    job_attempt: u32,
    step_id: &str,
    posture_digest: &ContentDigest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"runtrue.runner.oidc-grant.v1\0");
    let generation = lease.fencing_generation.to_be_bytes();
    for value in [
        lease.id.as_bytes(),
        generation.as_slice(),
        lease.job_id.as_bytes(),
        job_attempt.to_be_bytes().as_slice(),
        step_id.as_bytes(),
        posture_digest.as_str().as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("runner-grant-{}", hex::encode(hasher.finalize()))
}

impl ControlPlane {
    pub fn authorize_runner_oidc(
        &self,
        request: &AuthorizeRunnerOidcRequest,
    ) -> Result<OidcGrant, ControlPlaneError> {
        validate_runner_oidc_request(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let subject = runner_execution_subject_tx(
            &transaction,
            &request.execution_lease_id,
            &request.runner_id,
            request.fencing_generation,
            &request.job_id,
            request.now_unix_ms,
        )?;
        let job = &subject.planned_job;
        if request.runner_posture_digest != subject.runner_posture_digest
            || request.job_attempt > job.retries.saturating_add(1)
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let step = job
            .steps
            .iter()
            .find(|step| step.id == request.step_id)
            .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
        if !step.capabilities.oidc_audiences.contains(&request.audience) {
            return Err(ControlPlaneError::RunnerBrokerCapabilityDenied);
        }
        let approval_subject_digest = runner_approval_subject_tx(
            &transaction,
            &subject.capsule_id,
            &subject.run_id,
            &subject.capsule,
        )?
        .ok_or(ControlPlaneError::ApprovalRequired)?;
        let expected_ref = match subject.capsule.context.event_context.get("event.ref") {
            Some(runtrue_workflow_ir::ScalarValue::String(value)) => Some(value.clone()),
            Some(_) => return Err(ControlPlaneError::RunnerBrokerBindingMismatch),
            None => None,
        };
        let trust = match serde_json::to_value(subject.capsule.context.source_trust)? {
            Value::String(value) => value,
            _ => {
                return Err(ControlPlaneError::CorruptState(
                    "capsule trust is not a string".to_owned(),
                ))
            }
        };
        let grant_id = runner_oidc_grant_id(
            &subject.lease,
            request.job_attempt,
            &request.step_id,
            &request.runner_posture_digest,
        );
        let grant = OidcGrant {
            grant_id: grant_id.clone(),
            tenant_id: subject.tenant_id,
            repository_id: subject.repository_id,
            run_id: subject.run_id,
            job_id: request.job_id.clone(),
            step_id: request.step_id.clone(),
            capsule_digest: subject.lease.capsule_digest,
            execution_lease_id: subject.lease.id,
            fencing_generation: subject.lease.fencing_generation,
            trust,
            runner_pool_id: Some(subject.runner_pool_id.clone()),
            environment: job.environment.clone(),
            ref_name: expected_ref,
            source_commit: subject.capsule.context.source_commit.clone(),
            approval_subject_digest: Some(approval_subject_digest),
            runner_posture_digest: Some(subject.runner_posture_digest.clone()),
            allowed_audiences: step.capabilities.oidc_audiences.iter().cloned().collect(),
            expires_unix_seconds: subject.lease.expires_unix_ms / 1000,
        };
        grant.validate()?;
        transaction.execute(
            "INSERT OR IGNORE INTO oidc_grants(id, grant_json) VALUES (?1, ?2)",
            params![grant_id, serde_json::to_string(&grant)?],
        )?;
        let stored: OidcGrant = transaction
            .query_row(
                "SELECT grant_json FROM oidc_grants
             WHERE id = ?1 AND revoked_unix_ms IS NULL",
                [&grant.grant_id],
                |row| json_column(row, 0),
            )
            .optional()?
            .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
        if stored != grant {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transaction.commit()?;
        Ok(grant)
    }

    /// Record a token minted from a derived runner grant and append its audit
    /// event in the same transaction. A concurrent/replayed audience request
    /// loses the unique insert and no token is returned to the caller.
    pub fn record_runner_oidc_issuance(
        &self,
        request: &RecordRunnerOidcIssuance,
    ) -> Result<(), ControlPlaneError> {
        validate_record_runner_oidc(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let grant: OidcGrant = transaction
            .query_row(
                "SELECT grant_json FROM oidc_grants
                 WHERE id = ?1 AND revoked_unix_ms IS NULL",
                [&request.grant_id],
                |row| json_column(row, 0),
            )
            .optional()?
            .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
        let lease = validate_active_runner_broker_lease_tx(
            &transaction,
            &grant.execution_lease_id,
            &request.runner_id,
            grant.fencing_generation,
            request.issued_unix_ms,
        )?;
        if grant.runner_posture_digest.as_ref() != Some(&request.runner_posture_digest)
            || grant.grant_id
                != runner_oidc_grant_id(
                    &lease,
                    request.job_attempt,
                    &grant.step_id,
                    &request.runner_posture_digest,
                )
            || !grant.allowed_audiences.contains(&request.audience)
            || request.expires_unix_ms > lease.expires_unix_ms
            || request.expires_unix_ms > grant.expires_unix_seconds.saturating_mul(1000)
            || grant.job_id != lease.job_id
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        validate_oidc_subject_conn(&transaction, &grant, &lease)?;
        transaction
            .execute(
                "INSERT INTO oidc_issuances
             (grant_id, audience, jti, issued_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    request.grant_id,
                    request.audience,
                    request.jti,
                    to_i64(request.issued_unix_ms)?,
                    to_i64(request.expires_unix_ms)?,
                ],
            )
            .map_err(map_runner_broker_insert_error)?;
        transaction
            .execute(
                "INSERT INTO runner_oidc_issuances
             (jti, grant_id, execution_lease_id, fencing_generation,
              installation_fencing_epoch, runner_id, tenant_id, repository_id,
              run_id, job_id, job_attempt, step_id, audience, runner_posture_digest,
              issued_unix_ms, expires_unix_ms, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, 'issued')",
                params![
                    request.jti,
                    grant.grant_id,
                    grant.execution_lease_id,
                    to_i64(grant.fencing_generation)?,
                    to_i64(lease.installation_fencing_epoch)?,
                    request.runner_id,
                    grant.tenant_id,
                    grant.repository_id,
                    grant.run_id,
                    grant.job_id,
                    to_i64(u64::from(request.job_attempt))?,
                    grant.step_id,
                    request.audience,
                    request.runner_posture_digest.as_str(),
                    to_i64(request.issued_unix_ms)?,
                    to_i64(request.expires_unix_ms)?,
                ],
            )
            .map_err(map_runner_broker_insert_error)?;
        append_runner_broker_audit_tx(
            &transaction,
            &self.installation_id,
            &grant.tenant_id,
            &request.runner_id,
            "runner.oidc.issue",
            "oidc_grant",
            &grant.grant_id,
            request.issued_unix_ms,
            BTreeMap::from([
                (
                    "execution_lease_id".to_owned(),
                    AuditValue::String(grant.execution_lease_id),
                ),
                ("step_id".to_owned(), AuditValue::String(grant.step_id)),
                (
                    "audience".to_owned(),
                    AuditValue::String(request.audience.clone()),
                ),
                ("jti".to_owned(), AuditValue::String(request.jti.clone())),
            ]),
        )?;
        transaction.commit()?;
        Ok(())
    }
}
impl ControlPlane {
    pub fn store_oidc_grant(&self, grant: &OidcGrant) -> Result<(), ControlPlaneError> {
        grant.validate()?;
        let connection = self.connection()?;
        let lease = lease_conn(&connection, &grant.execution_lease_id)?;
        if lease.state != LeaseState::Active
            || lease.job_id != grant.job_id
            || lease.fencing_generation != grant.fencing_generation
            || lease.capsule_digest != grant.capsule_digest
        {
            return Err(ControlPlaneError::StaleOidcGrant);
        }
        validate_oidc_subject_conn(&connection, grant, &lease)?;
        connection.execute(
            "INSERT INTO oidc_grants(id, grant_json) VALUES (?1, ?2)",
            params![grant.grant_id, serde_json::to_string(grant)?],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_oidc_grant(
        &self,
        grant_id: &str,
        execution_lease_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        job_id: &str,
        step_id: &str,
        now_unix_ms: u64,
    ) -> Result<OidcGrant, ControlPlaneError> {
        let connection = self.connection()?;
        let grant: OidcGrant = connection
            .query_row(
                "SELECT grant_json FROM oidc_grants WHERE id = ?1 AND revoked_unix_ms IS NULL",
                [grant_id],
                |row| json_column(row, 0),
            )
            .optional()?
            .ok_or_else(|| not_found("OIDC grant", grant_id))?;
        let lease = lease_conn(&connection, execution_lease_id)?;
        let hard_deadline = lease_hard_deadline_conn(&connection, execution_lease_id)?;
        if grant.execution_lease_id != execution_lease_id
            || grant.fencing_generation != fencing_generation
            || grant.job_id != job_id
            || grant.step_id != step_id
            || lease.job_id != job_id
            || lease.fencing_generation != fencing_generation
            || lease.installation_fencing_epoch != installation_fencing_epoch
            || lease.capsule_digest != grant.capsule_digest
            || lease.state != LeaseState::Active
            || now_unix_ms >= lease.expires_unix_ms
            || now_unix_ms >= hard_deadline
            || now_unix_ms / 1000 >= grant.expires_unix_seconds
        {
            return Err(ControlPlaneError::StaleOidcGrant);
        }
        validate_oidc_subject_conn(&connection, &grant, &lease)?;
        Ok(grant)
    }

    pub fn record_oidc_issuance(
        &self,
        grant_id: &str,
        audience: &str,
        jti: &str,
        issued_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        for (field, value) in [
            ("OIDC grant id", grant_id),
            ("OIDC audience", audience),
            ("OIDC jti", jti),
        ] {
            validate_text(field, value)?;
        }
        if expires_unix_ms <= issued_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "OIDC issuance expiry must be in the future",
            ));
        }
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO oidc_issuances
             (grant_id, audience, jti, issued_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                grant_id,
                audience,
                jti,
                to_i64(issued_unix_ms)?,
                to_i64(expires_unix_ms)?,
            ],
        )?;
        Ok(())
    }
}
