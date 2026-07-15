// Gate acquisition and binding dependencies are explicit.
use super::super::{
    append_deployment_event_tx, approval_tx, deployment_request_tx, environment_tx, from_i64,
    installation_epoch_tx, not_found, optional_u64_column, params, require_active_policy_epoch_tx,
    require_deployment_approval_tx, require_provider_capability_tx, require_r9_tenant_tx, to_i64,
    u64_column, validate_deployment_inputs_tx, validate_r10_identifier, AcquireEnvironmentGate,
    ApprovalStatus, BindDeploymentLease, ControlPlane, ControlPlaneError, DeploymentRequestRecord,
    DeploymentRequestStatus, EnvironmentConcurrencyLeaseRecord, IdempotentResult, JobRecord, Row,
    Transaction, TransactionBehavior, MAX_R10_GATE_LEASE_MS, MAX_R10_IDENTIFIERS,
};
use rusqlite::OptionalExtension as _;

pub(in crate::store) fn environment_concurrency_lease_row(
    row: &Row<'_>,
) -> rusqlite::Result<EnvironmentConcurrencyLeaseRecord> {
    Ok(EnvironmentConcurrencyLeaseRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        environment_id: row.get(2)?,
        deployment_request_id: row.get(3)?,
        concurrency_fence: u64_column(row, 4, "environment concurrency fence")?,
        execution_lease_id: row.get(5)?,
        lease_fencing_generation: optional_u64_column(row, 6, "deployment lease fence")?,
        installation_fencing_epoch: u64_column(row, 7, "deployment installation epoch")?,
        state: row.get(8)?,
        acquired_unix_ms: u64_column(row, 9, "environment gate acquisition")?,
        expires_unix_ms: u64_column(row, 10, "environment gate expiry")?,
        released_unix_ms: optional_u64_column(row, 11, "environment gate release")?,
    })
}

pub(in crate::store) fn environment_concurrency_lease_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    request_id: &str,
) -> Result<Option<EnvironmentConcurrencyLeaseRecord>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            "SELECT id, tenant_id, environment_id, deployment_request_id,
                    concurrency_fence, execution_lease_id, lease_fencing_generation,
                    installation_fencing_epoch, state, acquired_unix_ms,
                    expires_unix_ms, released_unix_ms
             FROM environment_concurrency_leases
             WHERE tenant_id = ?1 AND deployment_request_id = ?2 AND state = 'active'
             ORDER BY concurrency_fence DESC LIMIT 1",
            params![tenant_id, request_id],
            environment_concurrency_lease_row,
        )
        .optional()?)
}

pub(in crate::store) fn deployment_job_gate_ready_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    job: &JobRecord,
    planned: &runtrue_workflow_ir::PlannedJob,
    now_unix_ms: u64,
) -> Result<bool, ControlPlaneError> {
    let request_id: Option<String> = transaction
        .query_row(
            "SELECT id FROM deployment_requests
             WHERE tenant_id = ?1 AND job_id = ?2 AND job_attempt = ?3",
            params![tenant_id, job.id, i64::from(job.attempt)],
            |row| row.get(0),
        )
        .optional()?;
    let Some(environment_name) = planned.environment.as_deref() else {
        if request_id.is_some() {
            return Err(ControlPlaneError::CorruptState(
                "deployment request targets a job without a signed environment".to_owned(),
            ));
        }
        return Ok(true);
    };
    let Some(request_id) = request_id else {
        return Ok(false);
    };
    let request = deployment_request_tx(transaction, tenant_id, &request_id)?
        .ok_or_else(|| not_found("deployment request", &request_id))?;
    let environment = environment_tx(transaction, tenant_id, &request.environment_id)?
        .ok_or_else(|| not_found("environment", &request.environment_id))?;
    let gate = environment_concurrency_lease_tx(transaction, tenant_id, &request_id)?;
    let current_epoch = installation_epoch_tx(transaction)?;
    if environment.name != environment_name
        || environment.status != "active"
        || environment.version != request.environment_version
        || environment.required_policy_epoch != request.policy_epoch
        || request.status != DeploymentRequestStatus::Ready
        || request.execution_lease_id.is_some()
        || request.installation_fencing_epoch != Some(current_epoch)
        || gate.as_ref().is_none_or(|gate| {
            gate.state != "active"
                || gate.expires_unix_ms <= now_unix_ms
                || gate.execution_lease_id.is_some()
                || gate.installation_fencing_epoch != current_epoch
                || request.concurrency_fence != Some(gate.concurrency_fence)
        })
    {
        return Ok(false);
    }
    require_active_policy_epoch_tx(transaction, tenant_id, request.policy_epoch)?;
    require_provider_capability_tx(
        transaction,
        tenant_id,
        environment.secret_provider_configuration_id.as_deref(),
        "external-secret",
    )?;
    require_provider_capability_tx(
        transaction,
        tenant_id,
        environment.signing_provider_configuration_id.as_deref(),
        "signing",
    )?;
    validate_deployment_inputs_tx(transaction, &request, &environment)?;
    if environment.protection_rules.require_approval {
        let approval_id = request
            .approval_request_id
            .as_deref()
            .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
        let approval = approval_tx(transaction, approval_id)?;
        if approval.status != ApprovalStatus::Consumed
            || approval.subject_digest != request.approval_subject_digest
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(in crate::store) fn bind_deployment_gate_offer_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    job: &JobRecord,
    lease_id: &str,
    fencing_generation: u64,
    installation_fencing_epoch: u64,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let request_id: Option<String> = transaction
        .query_row(
            "SELECT id FROM deployment_requests
             WHERE tenant_id = ?1 AND job_id = ?2 AND job_attempt = ?3",
            params![tenant_id, job.id, i64::from(job.attempt)],
            |row| row.get(0),
        )
        .optional()?;
    let Some(request_id) = request_id else {
        return Ok(());
    };
    let mut request = deployment_request_tx(transaction, tenant_id, &request_id)?
        .ok_or_else(|| not_found("deployment request", &request_id))?;
    let gate = environment_concurrency_lease_tx(transaction, tenant_id, &request_id)?
        .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
    let hard_deadline: i64 = transaction.query_row(
        "SELECT hard_deadline_unix_ms FROM leases
         WHERE tenant_id = ?1 AND id = ?2 AND job_id = ?3
           AND fencing_generation = ?4 AND installation_fencing_epoch = ?5
           AND state = 'offered'",
        params![
            tenant_id,
            lease_id,
            job.id,
            to_i64(fencing_generation)?,
            to_i64(installation_fencing_epoch)?
        ],
        |row| row.get(0),
    )?;
    let hard_deadline = from_i64("deployment lease hard deadline", hard_deadline)?;
    if request.status != DeploymentRequestStatus::Ready
        || request.concurrency_fence != Some(gate.concurrency_fence)
        || gate.state != "active"
        || gate.expires_unix_ms <= now_unix_ms
        || gate.execution_lease_id.is_some()
        || request.installation_fencing_epoch != Some(installation_fencing_epoch)
        || gate.installation_fencing_epoch != installation_fencing_epoch
        || hard_deadline <= now_unix_ms
    {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    let gate_changed = transaction.execute(
        "UPDATE environment_concurrency_leases
         SET execution_lease_id = ?3, lease_fencing_generation = ?4,
             expires_unix_ms = ?5
         WHERE tenant_id = ?1 AND id = ?2 AND state = 'active'
           AND execution_lease_id IS NULL AND concurrency_fence = ?6",
        params![
            tenant_id,
            gate.id,
            lease_id,
            to_i64(fencing_generation)?,
            to_i64(hard_deadline)?,
            to_i64(gate.concurrency_fence)?
        ],
    )?;
    if gate_changed != 1 {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    request.status = DeploymentRequestStatus::Leased;
    request.execution_lease_id = Some(lease_id.to_owned());
    request.lease_fencing_generation = Some(fencing_generation);
    request.updated_unix_ms = now_unix_ms;
    request.version = request
        .version
        .checked_add(1)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "deployment request version",
        })?;
    let request_changed = transaction.execute(
        "UPDATE deployment_requests SET status = 'leased', execution_lease_id = ?3,
                lease_fencing_generation = ?4, updated_unix_ms = ?5, version = ?6
         WHERE tenant_id = ?1 AND id = ?2 AND status = 'ready'
           AND concurrency_fence = ?7 AND execution_lease_id IS NULL",
        params![
            tenant_id,
            request.id,
            lease_id,
            to_i64(fencing_generation)?,
            to_i64(now_unix_ms)?,
            to_i64(request.version)?,
            to_i64(gate.concurrency_fence)?
        ],
    )?;
    if request_changed != 1 {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    append_deployment_event_tx(transaction, &request)?;
    Ok(())
}

impl ControlPlane {
    pub fn acquire_environment_gate(
        &self,
        request: &AcquireEnvironmentGate,
    ) -> Result<IdempotentResult<EnvironmentConcurrencyLeaseRecord>, ControlPlaneError> {
        for value in [
            &request.tenant_id,
            &request.deployment_request_id,
            &request.gate_lease_id,
            &request.actor_id,
            &request.audit_correlation_id,
        ] {
            validate_r10_identifier(value)?;
        }
        if request.installation_fencing_epoch == 0
            || request.gate_expires_unix_ms <= request.now_unix_ms
            || request.gate_expires_unix_ms - request.now_unix_ms > MAX_R10_GATE_LEASE_MS
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid environment gate lease bounds",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.tenant_id)?;
        let (installation_epoch, safe_mode): (i64, bool) = transaction.query_row(
            "SELECT fencing_epoch, safe_mode FROM installation_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if safe_mode {
            return Err(ControlPlaneError::InstallationSafeMode);
        }
        let installation_epoch = from_i64("installation fencing epoch", installation_epoch)?;
        if installation_epoch != request.installation_fencing_epoch {
            return Err(ControlPlaneError::StaleInstallationEpoch {
                expected: installation_epoch,
                actual: request.installation_fencing_epoch,
            });
        }
        let mut deployment = deployment_request_tx(
            &transaction,
            &request.tenant_id,
            &request.deployment_request_id,
        )?
        .ok_or_else(|| not_found("deployment request", &request.deployment_request_id))?;
        if let Some(existing) = environment_concurrency_lease_tx(
            &transaction,
            &request.tenant_id,
            &request.deployment_request_id,
        )? {
            if existing.id == request.gate_lease_id
                && existing.installation_fencing_epoch == request.installation_fencing_epoch
                && existing.state == "active"
                && existing.expires_unix_ms == request.gate_expires_unix_ms
                && existing.expires_unix_ms > request.now_unix_ms
                && deployment.status == DeploymentRequestStatus::Ready
                && deployment.concurrency_fence == Some(existing.concurrency_fence)
            {
                transaction.commit()?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            if existing.expires_unix_ms > request.now_unix_ms {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = transaction.execute(
                "UPDATE environment_concurrency_leases SET state = 'expired',
                        released_unix_ms = ?3
                 WHERE tenant_id = ?1 AND id = ?2 AND state = 'active'",
                params![request.tenant_id, existing.id, to_i64(request.now_unix_ms)?],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if deployment.status == DeploymentRequestStatus::Ready {
                deployment.status = DeploymentRequestStatus::AwaitingConcurrency;
                deployment.concurrency_fence = None;
                deployment.installation_fencing_epoch = None;
                deployment.actor_id.clone_from(&request.actor_id);
                deployment
                    .audit_correlation_id
                    .clone_from(&request.audit_correlation_id);
                deployment.updated_unix_ms = request.now_unix_ms;
                deployment.version =
                    deployment
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "deployment request version",
                        })?;
                transaction.execute(
                    "UPDATE deployment_requests SET status = 'awaiting-concurrency',
                            concurrency_fence = NULL, installation_fencing_epoch = NULL,
                            actor_id = ?3, audit_correlation_id = ?4,
                            updated_unix_ms = ?5, version = ?6
                     WHERE tenant_id = ?1 AND id = ?2 AND status = 'ready'",
                    params![
                        request.tenant_id,
                        deployment.id,
                        request.actor_id,
                        request.audit_correlation_id,
                        to_i64(request.now_unix_ms)?,
                        to_i64(deployment.version)?
                    ],
                )?;
                append_deployment_event_tx(&transaction, &deployment)?;
            }
        }
        let environment =
            environment_tx(&transaction, &request.tenant_id, &deployment.environment_id)?
                .ok_or_else(|| not_found("environment", &deployment.environment_id))?;
        if environment.status != "active"
            || environment.version != deployment.environment_version
            || environment.required_policy_epoch != deployment.policy_epoch
            || request.now_unix_ms < deployment.wait_until_unix_ms
            || !matches!(
                deployment.status,
                DeploymentRequestStatus::WaitingTimer
                    | DeploymentRequestStatus::AwaitingApproval
                    | DeploymentRequestStatus::AwaitingConcurrency
            )
            || (!environment
                .protection_rules
                .allowed_deployment_actors
                .is_empty()
                && environment
                    .protection_rules
                    .allowed_deployment_actors
                    .binary_search(&request.actor_id)
                    .is_err())
        {
            return Err(ControlPlaneError::EnvironmentGateNotReady);
        }
        require_active_policy_epoch_tx(&transaction, &request.tenant_id, deployment.policy_epoch)?;
        require_provider_capability_tx(
            &transaction,
            &request.tenant_id,
            environment.secret_provider_configuration_id.as_deref(),
            "external-secret",
        )?;
        require_provider_capability_tx(
            &transaction,
            &request.tenant_id,
            environment.signing_provider_configuration_id.as_deref(),
            "signing",
        )?;
        validate_deployment_inputs_tx(&transaction, &deployment, &environment)?;
        if environment.protection_rules.require_approval {
            require_deployment_approval_tx(
                &transaction,
                &deployment,
                &environment,
                request.now_unix_ms,
            )?;
        }
        let expired_ids = {
            let mut statement = transaction.prepare(
                "SELECT deployment_request_id FROM environment_concurrency_leases
                 WHERE tenant_id = ?1 AND environment_id = ?2 AND state = 'active'
                   AND expires_unix_ms <= ?3
                 ORDER BY expires_unix_ms, id LIMIT ?4",
            )?;
            let rows = statement
                .query_map(
                    params![
                        request.tenant_id,
                        environment.id,
                        to_i64(request.now_unix_ms)?,
                        i64::try_from(MAX_R10_IDENTIFIERS + 1).map_err(|_| {
                            ControlPlaneError::IntegerRange {
                                field: "expired environment gates limit",
                            }
                        })?
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        if expired_ids.len() > MAX_R10_IDENTIFIERS {
            return Err(ControlPlaneError::CorruptState(
                "environment has too many expired concurrency leases".to_owned(),
            ));
        }
        for expired_id in expired_ids {
            transaction.execute(
                "UPDATE environment_concurrency_leases SET state = 'expired',
                        released_unix_ms = ?3
                 WHERE tenant_id = ?1 AND deployment_request_id = ?2 AND state = 'active'",
                params![request.tenant_id, expired_id, to_i64(request.now_unix_ms)?],
            )?;
            if let Some(mut expired_request) =
                deployment_request_tx(&transaction, &request.tenant_id, &expired_id)?
            {
                if expired_request.status == DeploymentRequestStatus::Ready {
                    expired_request.status = DeploymentRequestStatus::AwaitingConcurrency;
                    expired_request.concurrency_fence = None;
                    expired_request.installation_fencing_epoch = None;
                    expired_request.actor_id.clone_from(&request.actor_id);
                    expired_request
                        .audit_correlation_id
                        .clone_from(&request.audit_correlation_id);
                    expired_request.updated_unix_ms = request.now_unix_ms;
                    expired_request.version = expired_request.version.checked_add(1).ok_or(
                        ControlPlaneError::IntegerRange {
                            field: "deployment request version",
                        },
                    )?;
                    transaction.execute(
                        "UPDATE deployment_requests SET status = 'awaiting-concurrency',
                                concurrency_fence = NULL,
                                installation_fencing_epoch = NULL, actor_id = ?3,
                                audit_correlation_id = ?4, updated_unix_ms = ?5,
                                version = ?6
                         WHERE tenant_id = ?1 AND id = ?2 AND status = 'ready'",
                        params![
                            request.tenant_id,
                            expired_id,
                            request.actor_id,
                            request.audit_correlation_id,
                            to_i64(request.now_unix_ms)?,
                            to_i64(expired_request.version)?
                        ],
                    )?;
                    append_deployment_event_tx(&transaction, &expired_request)?;
                }
            }
        }
        let active: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM environment_concurrency_leases
             WHERE tenant_id = ?1 AND environment_id = ?2 AND state = 'active'",
            params![request.tenant_id, environment.id],
            |row| row.get(0),
        )?;
        if from_i64("active environment concurrency", active)?
            >= u64::from(environment.concurrency_limit)
        {
            return Err(ControlPlaneError::EnvironmentConcurrencyLimit);
        }
        let fence = environment.last_concurrency_fence.checked_add(1).ok_or(
            ControlPlaneError::IntegerRange {
                field: "environment concurrency fence",
            },
        )?;
        let changed = transaction.execute(
            "UPDATE environments SET last_concurrency_fence = ?3,
                    updated_unix_ms = MAX(updated_unix_ms, ?4)
             WHERE tenant_id = ?1 AND id = ?2 AND last_concurrency_fence = ?5",
            params![
                request.tenant_id,
                environment.id,
                to_i64(fence)?,
                to_i64(request.now_unix_ms)?,
                to_i64(environment.last_concurrency_fence)?
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO environment_concurrency_leases
             (id, tenant_id, environment_id, deployment_request_id,
              concurrency_fence, execution_lease_id, lease_fencing_generation,
              installation_fencing_epoch, state, acquired_unix_ms, expires_unix_ms,
              released_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, 'active', ?7, ?8, NULL)",
            params![
                request.gate_lease_id,
                request.tenant_id,
                environment.id,
                deployment.id,
                to_i64(fence)?,
                to_i64(request.installation_fencing_epoch)?,
                to_i64(request.now_unix_ms)?,
                to_i64(request.gate_expires_unix_ms)?
            ],
        )?;
        deployment.status = DeploymentRequestStatus::Ready;
        deployment.concurrency_fence = Some(fence);
        deployment.installation_fencing_epoch = Some(request.installation_fencing_epoch);
        deployment.actor_id.clone_from(&request.actor_id);
        deployment
            .audit_correlation_id
            .clone_from(&request.audit_correlation_id);
        deployment.updated_unix_ms = request.now_unix_ms;
        deployment.version =
            deployment
                .version
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "deployment request version",
                })?;
        let changed = transaction.execute(
            "UPDATE deployment_requests SET status = 'ready', concurrency_fence = ?3,
                    installation_fencing_epoch = ?4, actor_id = ?5,
                    audit_correlation_id = ?6, updated_unix_ms = ?7, version = ?8
             WHERE tenant_id = ?1 AND id = ?2",
            params![
                request.tenant_id,
                deployment.id,
                to_i64(fence)?,
                to_i64(request.installation_fencing_epoch)?,
                request.actor_id,
                request.audit_correlation_id,
                to_i64(request.now_unix_ms)?,
                to_i64(deployment.version)?
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        append_deployment_event_tx(&transaction, &deployment)?;
        let lease = environment_concurrency_lease_tx(
            &transaction,
            &request.tenant_id,
            &request.deployment_request_id,
        )?
        .ok_or_else(|| {
            ControlPlaneError::CorruptState("environment concurrency lease disappeared".to_owned())
        })?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: lease,
            replayed: false,
        })
    }

    pub fn bind_deployment_lease(
        &self,
        binding: &BindDeploymentLease,
    ) -> Result<IdempotentResult<DeploymentRequestRecord>, ControlPlaneError> {
        for value in [
            &binding.tenant_id,
            &binding.deployment_request_id,
            &binding.execution_lease_id,
        ] {
            validate_r10_identifier(value)?;
        }
        if binding.lease_fencing_generation == 0 || binding.installation_fencing_epoch == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "invalid deployment execution lease binding",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &binding.tenant_id)?;
        let (current_epoch, safe_mode): (i64, bool) = transaction.query_row(
            "SELECT fencing_epoch, safe_mode FROM installation_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if safe_mode {
            return Err(ControlPlaneError::InstallationSafeMode);
        }
        let current_epoch = from_i64("installation fencing epoch", current_epoch)?;
        if current_epoch != binding.installation_fencing_epoch {
            return Err(ControlPlaneError::StaleInstallationEpoch {
                expected: current_epoch,
                actual: binding.installation_fencing_epoch,
            });
        }
        let deployment = deployment_request_tx(
            &transaction,
            &binding.tenant_id,
            &binding.deployment_request_id,
        )?
        .ok_or_else(|| not_found("deployment request", &binding.deployment_request_id))?;
        let gate = environment_concurrency_lease_tx(
            &transaction,
            &binding.tenant_id,
            &binding.deployment_request_id,
        )?
        .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
        type LeaseBinding = (String, i64, i64, String, i64, i64, i64, i64, String, String);
        let lease: Option<LeaseBinding> = transaction
            .query_row(
                "SELECT l.tenant_id, l.fencing_generation, l.installation_fencing_epoch,
                        l.state, l.issued_unix_ms, l.accept_by_unix_ms, l.expires_unix_ms,
                        l.hard_deadline_unix_ms, j.id, r.repository_id
                 FROM leases l JOIN jobs j ON j.id = l.job_id
                 JOIN runs r ON r.id = j.run_id
                 JOIN repositories repo ON repo.id = r.repository_id
                 WHERE l.id = ?1 AND repo.tenant_id = ?2 AND j.attempt = ?3",
                params![
                    binding.execution_lease_id,
                    binding.tenant_id,
                    i64::from(deployment.job_attempt)
                ],
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
                    ))
                },
            )
            .optional()?;
        let Some((
            tenant,
            fence,
            epoch,
            state,
            issued,
            accept_by,
            expires,
            hard_deadline,
            job_id,
            repository_id,
        )) = lease
        else {
            return Err(not_found("execution lease", &binding.execution_lease_id));
        };
        if deployment.status != DeploymentRequestStatus::Leased
            || deployment.execution_lease_id.as_deref() != Some(&binding.execution_lease_id)
            || deployment.lease_fencing_generation != Some(binding.lease_fencing_generation)
            || deployment.installation_fencing_epoch != Some(binding.installation_fencing_epoch)
            || gate.execution_lease_id.as_deref() != Some(&binding.execution_lease_id)
            || gate.lease_fencing_generation != Some(binding.lease_fencing_generation)
            || gate.state != "active"
            || gate.expires_unix_ms <= binding.now_unix_ms
            || gate.installation_fencing_epoch != binding.installation_fencing_epoch
            || deployment.concurrency_fence != Some(gate.concurrency_fence)
            || tenant != binding.tenant_id
            || from_i64("deployment lease fence", fence)? != binding.lease_fencing_generation
            || from_i64("deployment lease epoch", epoch)? != binding.installation_fencing_epoch
            || !matches!(state.as_str(), "offered" | "active")
            || from_i64("deployment lease issued", issued)? > binding.now_unix_ms
            || (state == "offered"
                && from_i64("deployment lease accept deadline", accept_by)? <= binding.now_unix_ms)
            || from_i64("deployment lease expiry", expires)? <= binding.now_unix_ms
            || from_i64("deployment lease hard deadline", hard_deadline)? <= binding.now_unix_ms
            || job_id != deployment.job_id
            || repository_id != deployment.repository_id
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value: deployment,
            replayed: true,
        })
    }
}
