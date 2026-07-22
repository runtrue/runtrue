use super::*;

const MAX_FLEET_REQUESTS: u64 = 1_000;
const MAX_AUTOSCALER_LEASE_MS: u64 = 5 * 60 * 1_000;

pub(in crate::store) fn fleet_request_state_name(state: RunnerFleetRequestState) -> &'static str {
    match state {
        RunnerFleetRequestState::Requested => "requested",
        RunnerFleetRequestState::Provisioning => "provisioning",
        RunnerFleetRequestState::Bootstrapping => "bootstrapping",
        RunnerFleetRequestState::Enrolled => "enrolled",
        RunnerFleetRequestState::Online => "online",
        RunnerFleetRequestState::Draining => "draining",
        RunnerFleetRequestState::Terminating => "terminating",
        RunnerFleetRequestState::Terminated => "terminated",
        RunnerFleetRequestState::Failed => "failed",
        RunnerFleetRequestState::Quarantined => "quarantined",
    }
}

pub(in crate::store) fn parse_fleet_request_state(
    value: &str,
) -> Result<RunnerFleetRequestState, ControlPlaneError> {
    match value {
        "requested" => Ok(RunnerFleetRequestState::Requested),
        "provisioning" => Ok(RunnerFleetRequestState::Provisioning),
        "bootstrapping" => Ok(RunnerFleetRequestState::Bootstrapping),
        "enrolled" => Ok(RunnerFleetRequestState::Enrolled),
        "online" => Ok(RunnerFleetRequestState::Online),
        "draining" => Ok(RunnerFleetRequestState::Draining),
        "terminating" => Ok(RunnerFleetRequestState::Terminating),
        "terminated" => Ok(RunnerFleetRequestState::Terminated),
        "failed" => Ok(RunnerFleetRequestState::Failed),
        "quarantined" => Ok(RunnerFleetRequestState::Quarantined),
        _ => Err(ControlPlaneError::InvalidInput(
            "unknown runner fleet request state",
        )),
    }
}

#[must_use]
pub fn runtime_compatibility_digest(requirements: &SchedulingRequirements) -> ContentDigest {
    let mut encoded = b"runtrue.runner.runtime-compatibility.v1\0".to_vec();
    // SchedulingRequirements contains only ordered sets and scalar fields, so
    // serde_json is deterministic for this exact versioned contract.
    encoded.extend_from_slice(
        &serde_json::to_vec(requirements)
            .expect("scheduling requirements serialization is infallible"),
    );
    ContentDigest::sha256(encoded)
}

fn validate_scaling_policy(policy: &RunnerPoolScalingPolicy) -> Result<(), ControlPlaneError> {
    validate_text("runner scaling pool", &policy.pool_id)?;
    if policy.maximum_workers == 0
        || ((policy.minimum_workers > 0 || policy.minimum_idle_workers > 0)
            && policy.baseline_runtime_compatibility_digest.is_none())
        || policy.minimum_workers > policy.maximum_workers
        || policy.minimum_idle_workers > policy.maximum_workers
        || policy.scale_up_batch == 0
        || policy.scale_up_batch > policy.maximum_workers
        || policy.idle_timeout_ms == 0
        || policy.offline_grace_ms == 0
        || policy.cooldown_ms == 0
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid runner scaling policy",
        ));
    }
    Ok(())
}

pub(in crate::store) fn fleet_request_row(
    row: &Row<'_>,
) -> rusqlite::Result<RunnerFleetRequestRecord> {
    let state: String = row.get(6)?;
    Ok(RunnerFleetRequestRecord {
        id: row.get(0)?,
        pool_id: row.get(1)?,
        runtime_compatibility_digest: digest_column(row, 2)?,
        provider: row.get(3)?,
        provider_template_id: row.get(4)?,
        runner_template_digest: digest_column(row, 5)?,
        state: parse_fleet_request_state(&state).map_err(|error| conversion(6, error))?,
        provider_request_id: row.get(7)?,
        provider_instance_id: row.get(8)?,
        runner_id: row.get(9)?,
        failure_code: row.get(10)?,
        created_unix_ms: u64_column(row, 11, "created_unix_ms")?,
        updated_unix_ms: u64_column(row, 12, "updated_unix_ms")?,
    })
}

fn launch_claim_row(row: &Row<'_>) -> rusqlite::Result<RunnerLaunchClaimRecord> {
    Ok(RunnerLaunchClaimRecord {
        id: row.get(0)?,
        fleet_request_id: row.get(1)?,
        enrollment_token_id: row.get(2)?,
        pool_id: row.get(3)?,
        provider: row.get(4)?,
        provider_instance_id: row.get(5)?,
        runner_template_digest: digest_column(row, 6)?,
        identity_proof_digest: digest_column(row, 7)?,
        created_unix_ms: u64_column(row, 8, "created_unix_ms")?,
        expires_unix_ms: u64_column(row, 9, "expires_unix_ms")?,
        consumed_unix_ms: optional_u64_column(row, 10, "consumed_unix_ms")?,
        runner_id: row.get(11)?,
    })
}

fn runner_can_serve(runner: &RunnerRecord, requirements: &SchedulingRequirements) -> bool {
    runner.os == requirements.os
        && runner.arch == requirements.arch
        && runner.isolation_backends.contains(&requirements.isolation)
        && (requirements.allowed_pools.is_empty()
            || requirements.allowed_pools.contains(&runner.pool_id))
        && requirements
            .region
            .as_ref()
            .is_none_or(|region| runner.region.as_ref() == Some(region))
        && requirements
            .required_capabilities
            .is_subset(&runner.verified_capabilities)
        && runner.logical_cpus >= requirements.cpu
        && runner.memory_bytes >= requirements.memory_bytes
        && runner.storage_bytes >= requirements.storage_bytes
}

fn available_slots(
    runner: &RunnerRecord,
    requirements: &SchedulingRequirements,
    reserved: &[SchedulingRequirements],
) -> u64 {
    if !runner_can_serve(runner, requirements) {
        return 0;
    }
    if requirements.isolation != runtrue_workflow_ir::Isolation::Wasm {
        return u64::from(reserved.is_empty());
    }
    if reserved
        .iter()
        .any(|item| item.isolation != runtrue_workflow_ir::Isolation::Wasm)
    {
        return 0;
    }
    let used_cpu = reserved
        .iter()
        .fold(0_u64, |sum, item| sum.saturating_add(u64::from(item.cpu)));
    let used_memory = reserved
        .iter()
        .fold(0_u64, |sum, item| sum.saturating_add(item.memory_bytes));
    let used_storage = reserved
        .iter()
        .fold(0_u64, |sum, item| sum.saturating_add(item.storage_bytes));
    let concurrency =
        u64::from(runner.max_concurrent_wasm_jobs).saturating_sub(reserved.len() as u64);
    let cpu = u64::from(runner.logical_cpus).saturating_sub(used_cpu)
        / u64::from(requirements.cpu.max(1));
    let memory = runner.memory_bytes.saturating_sub(used_memory) / requirements.memory_bytes.max(1);
    let storage = if requirements.storage_bytes == 0 {
        u64::MAX
    } else {
        runner.storage_bytes.saturating_sub(used_storage) / requirements.storage_bytes
    };
    concurrency.min(cpu).min(memory).min(storage)
}

pub(in crate::store) fn require_autoscaler_lease_tx(
    transaction: &Transaction<'_>,
    pool_id: &str,
    owner_id: &str,
    fencing_generation: u64,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM runner_autoscaler_leases
           WHERE pool_id = ?1 AND owner_id = ?2 AND fencing_generation = ?3
             AND expires_unix_ms > ?4
         )",
        params![
            pool_id,
            owner_id,
            to_i64(fencing_generation)?,
            to_i64(now_unix_ms)?,
        ],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(ControlPlaneError::RunnerAutoscalerLeaseLost);
    }
    Ok(())
}

impl ControlPlane {
    pub fn upsert_runner_pool_scaling_policy(
        &self,
        policy: &RunnerPoolScalingPolicy,
    ) -> Result<(), ControlPlaneError> {
        validate_scaling_policy(policy)?;
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO runner_pool_scaling_policies
             (pool_id, baseline_runtime_compatibility_digest, minimum_workers, minimum_idle_workers, maximum_workers,
              scale_up_batch, idle_timeout_ms, offline_grace_ms, cooldown_ms,
              enabled, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(pool_id) DO UPDATE SET
               baseline_runtime_compatibility_digest = excluded.baseline_runtime_compatibility_digest,
               minimum_workers = excluded.minimum_workers,
               minimum_idle_workers = excluded.minimum_idle_workers,
               maximum_workers = excluded.maximum_workers,
               scale_up_batch = excluded.scale_up_batch,
               idle_timeout_ms = excluded.idle_timeout_ms,
               offline_grace_ms = excluded.offline_grace_ms,
               cooldown_ms = excluded.cooldown_ms,
               enabled = excluded.enabled,
               updated_unix_ms = excluded.updated_unix_ms",
            params![
                policy.pool_id,
                policy.baseline_runtime_compatibility_digest.as_ref().map(ContentDigest::as_str),
                policy.minimum_workers,
                policy.minimum_idle_workers,
                policy.maximum_workers,
                policy.scale_up_batch,
                to_i64(policy.idle_timeout_ms)?,
                to_i64(policy.offline_grace_ms)?,
                to_i64(policy.cooldown_ms)?,
                policy.enabled,
                to_i64(policy.updated_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn runner_pool_scaling_policy(
        &self,
        pool_id: &str,
    ) -> Result<RunnerPoolScalingPolicy, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT pool_id, baseline_runtime_compatibility_digest, minimum_workers, minimum_idle_workers, maximum_workers,
                        scale_up_batch, idle_timeout_ms, offline_grace_ms, cooldown_ms,
                        enabled, updated_unix_ms
                 FROM runner_pool_scaling_policies WHERE pool_id = ?1",
                [pool_id],
                |row| {
                    Ok(RunnerPoolScalingPolicy {
                        pool_id: row.get(0)?,
                        baseline_runtime_compatibility_digest: optional_digest_column(row, 1)?,
                        minimum_workers: row.get(2)?,
                        minimum_idle_workers: row.get(3)?,
                        maximum_workers: row.get(4)?,
                        scale_up_batch: row.get(5)?,
                        idle_timeout_ms: u64_column(row, 6, "idle_timeout_ms")?,
                        offline_grace_ms: u64_column(row, 7, "offline_grace_ms")?,
                        cooldown_ms: u64_column(row, 8, "cooldown_ms")?,
                        enabled: row.get(9)?,
                        updated_unix_ms: u64_column(row, 10, "updated_unix_ms")?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool scaling policy", pool_id))
    }

    pub fn upsert_runner_pool_template(
        &self,
        template: &RunnerPoolTemplateRecord,
    ) -> Result<(), ControlPlaneError> {
        validate_text("runner template pool", &template.pool_id)?;
        validate_text("runner template provider", &template.provider)?;
        validate_text(
            "runner provider template id",
            &template.provider_template_id,
        )?;
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO runner_pool_templates
             (pool_id, runtime_compatibility_digest, provider, provider_template_id,
              runner_template_digest, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(pool_id, runtime_compatibility_digest) DO UPDATE SET
               provider = excluded.provider,
               provider_template_id = excluded.provider_template_id,
               runner_template_digest = excluded.runner_template_digest,
               updated_unix_ms = excluded.updated_unix_ms",
            params![
                template.pool_id,
                template.runtime_compatibility_digest.as_str(),
                template.provider,
                template.provider_template_id,
                template.runner_template_digest.as_str(),
                to_i64(template.created_unix_ms)?,
                to_i64(template.updated_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn list_runner_pool_templates(
        &self,
        pool_id: &str,
    ) -> Result<Vec<RunnerPoolTemplateRecord>, ControlPlaneError> {
        validate_text("runner template pool", pool_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT pool_id, runtime_compatibility_digest, provider, provider_template_id,
                    runner_template_digest, created_unix_ms, updated_unix_ms
             FROM runner_pool_templates WHERE pool_id = ?1
             ORDER BY runtime_compatibility_digest",
        )?;
        let values = statement
            .query_map([pool_id], |row| {
                Ok(RunnerPoolTemplateRecord {
                    pool_id: row.get(0)?,
                    runtime_compatibility_digest: digest_column(row, 1)?,
                    provider: row.get(2)?,
                    provider_template_id: row.get(3)?,
                    runner_template_digest: digest_column(row, 4)?,
                    created_unix_ms: u64_column(row, 5, "created_unix_ms")?,
                    updated_unix_ms: u64_column(row, 6, "updated_unix_ms")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(ControlPlaneError::from)?;
        Ok(values)
    }

    pub fn runner_pool_fleet_snapshot(
        &self,
        pool_id: &str,
        observed_unix_ms: u64,
    ) -> Result<RunnerPoolFleetSnapshot, ControlPlaneError> {
        validate_text("runner fleet pool", pool_id)?;
        let connection = self.connection()?;
        let mut requirements_statement = connection.prepare(
            "SELECT j.requirements_json
             FROM jobs j
             JOIN runs r ON r.id = j.run_id
             JOIN repositories repo ON repo.id = r.repository_id
             JOIN runner_pools pool ON pool.tenant_id = repo.tenant_id
             WHERE pool.id = ?1 AND j.status = 'queued' AND r.remote = 1
               AND r.status IN ('created', 'running')
             ORDER BY j.id",
        )?;
        let requirements = requirements_statement
            .query_map([pool_id], |row| {
                json_column::<SchedulingRequirements>(row, 0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut demand = BTreeMap::<ContentDigest, (SchedulingRequirements, u64)>::new();
        for item in requirements {
            if !item.allowed_pools.is_empty() && !item.allowed_pools.contains(pool_id) {
                continue;
            }
            let digest = runtime_compatibility_digest(&item);
            let entry = demand.entry(digest).or_insert((item, 0));
            entry.1 = entry
                .1
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "runner demand count",
                })?;
        }

        let runners = {
            let mut statement = connection.prepare(
                "SELECT runner_json, created_unix_ms, updated_unix_ms
                 FROM runners WHERE pool_id = ?1
                   AND COALESCE(json_extract(runner_json, '$.retired'), 0) = 0
                 ORDER BY id",
            )?;
            let values = statement
                .query_map([pool_id], |row| {
                    Ok(PersistedRunner {
                        runner: json_column(row, 0)?,
                        created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                        updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            values
        };
        let mut reserved_by_runner = BTreeMap::<String, Vec<SchedulingRequirements>>::new();
        let mut reserved_statement = connection.prepare(
            "SELECT l.runner_id, j.requirements_json FROM leases l
             JOIN jobs j ON j.id = l.job_id
             JOIN runners rr ON rr.id = l.runner_id
             WHERE rr.pool_id = ?1 AND l.state IN ('offered', 'active', 'cancel_requested')
             ORDER BY l.runner_id, l.id",
        )?;
        for row in reserved_statement.query_map([pool_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                json_column::<SchedulingRequirements>(row, 1)?,
            ))
        })? {
            let (runner_id, requirements) = row?;
            reserved_by_runner
                .entry(runner_id)
                .or_default()
                .push(requirements);
        }
        let mut pending_by_compatibility = BTreeMap::<ContentDigest, u64>::new();
        let mut pending_statement = connection.prepare(
            "SELECT runtime_compatibility_digest, COUNT(*) FROM runner_fleet_requests
             WHERE pool_id = ?1 AND state IN
               ('requested', 'provisioning', 'bootstrapping', 'enrolled')
             GROUP BY runtime_compatibility_digest
             ORDER BY runtime_compatibility_digest",
        )?;
        for row in pending_statement.query_map([pool_id], |row| {
            Ok((digest_column(row, 0)?, row.get::<_, u64>(1)?))
        })? {
            let (digest, count) = row?;
            pending_by_compatibility.insert(digest, count);
        }
        let mut online_workers = 0_u64;
        let mut draining_workers = 0_u64;
        let mut offline_workers = 0_u64;
        let mut quarantined_workers = 0_u64;
        for persisted in &runners {
            match persisted.runner.status {
                RunnerStatus::Online => online_workers += 1,
                RunnerStatus::Draining => draining_workers += 1,
                RunnerStatus::Probationary | RunnerStatus::Offline | RunnerStatus::Revoked => {
                    offline_workers += 1
                }
                RunnerStatus::Quarantined => quarantined_workers += 1,
            }
        }
        let demand = demand
            .into_iter()
            .map(|(digest, (requirements, queued_jobs))| {
                let active_slots = runners
                    .iter()
                    .filter(|runner| runner.runner.status == RunnerStatus::Online)
                    .map(|runner| {
                        reserved_by_runner
                            .get(&runner.runner.id)
                            .map_or(0, |reserved| {
                                reserved
                                    .iter()
                                    .filter(|item| runtime_compatibility_digest(item) == digest)
                                    .count() as u64
                            })
                    })
                    .sum();
                let available_slots = runners
                    .iter()
                    .filter(|runner| runner.runner.status == RunnerStatus::Online)
                    .map(|runner| {
                        available_slots(
                            &runner.runner,
                            &requirements,
                            reserved_by_runner
                                .get(&runner.runner.id)
                                .map_or(&[], Vec::as_slice),
                        )
                    })
                    .sum();
                let slots_per_worker =
                    if requirements.isolation == runtrue_workflow_ir::Isolation::Wasm {
                        runners
                            .iter()
                            .filter(|runner| runner_can_serve(&runner.runner, &requirements))
                            .map(|runner| u64::from(runner.runner.max_concurrent_wasm_jobs))
                            .min()
                            .unwrap_or(1)
                    } else {
                        1
                    };
                let pending_workers = pending_by_compatibility.get(&digest).copied().unwrap_or(0);
                RunnerDemandGroup {
                    runtime_compatibility_digest: digest,
                    requirements,
                    queued_jobs,
                    active_slots,
                    available_slots,
                    pending_slots: pending_workers.saturating_mul(slots_per_worker),
                    slots_per_worker,
                }
            })
            .collect();
        Ok(RunnerPoolFleetSnapshot {
            pool_id: pool_id.to_owned(),
            observed_unix_ms,
            demand,
            online_workers,
            draining_workers,
            offline_workers,
            quarantined_workers,
        })
    }

    pub fn create_runner_fleet_request(
        &self,
        request: &RunnerFleetRequestRecord,
        owner_id: &str,
        fencing_generation: u64,
    ) -> Result<(), ControlPlaneError> {
        if request.state != RunnerFleetRequestState::Requested
            || request.provider_request_id.is_some()
            || request.provider_instance_id.is_some()
            || request.runner_id.is_some()
            || request.failure_code.is_some()
            || request.created_unix_ms != request.updated_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput(
                "new runner fleet request is not pristine",
            ));
        }
        validate_text("runner fleet request id", &request.id)?;
        validate_text("runner fleet request pool", &request.pool_id)?;
        validate_text("runner fleet provider", &request.provider)?;
        validate_text(
            "runner fleet provider template",
            &request.provider_template_id,
        )?;
        validate_text("runner autoscaler owner", owner_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_autoscaler_lease_tx(
            &transaction,
            &request.pool_id,
            owner_id,
            fencing_generation,
            request.created_unix_ms,
        )?;
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO runner_fleet_requests
             (id, pool_id, runtime_compatibility_digest, provider,
              provider_template_id, runner_template_digest, state,
              created_unix_ms, updated_unix_ms)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, 'requested', ?7, ?7
             WHERE EXISTS (
               SELECT 1 FROM runner_pool_templates
               WHERE pool_id = ?2 AND runtime_compatibility_digest = ?3
                 AND provider = ?4 AND provider_template_id = ?5
                 AND runner_template_digest = ?6
             )",
            params![
                request.id,
                request.pool_id,
                request.runtime_compatibility_digest.as_str(),
                request.provider,
                request.provider_template_id,
                request.runner_template_digest.as_str(),
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        if changed != 1 {
            let existing = transaction
                .query_row(
                    "SELECT id, pool_id, runtime_compatibility_digest, provider,
                            provider_template_id, runner_template_digest, state,
                            provider_request_id, provider_instance_id, runner_id,
                            failure_code, created_unix_ms, updated_unix_ms
                     FROM runner_fleet_requests WHERE id=?1",
                    [&request.id],
                    fleet_request_row,
                )
                .optional()?;
            if existing.as_ref() != Some(request) {
                return Err(ControlPlaneError::InvalidInput(
                    "runner fleet request has no exact registered template or conflicts with an idempotent replay",
                ));
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn list_runner_fleet_requests(
        &self,
        pool_id: &str,
    ) -> Result<Vec<RunnerFleetRequestRecord>, ControlPlaneError> {
        validate_text("runner fleet pool", pool_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, pool_id, runtime_compatibility_digest, provider,
                    provider_template_id, runner_template_digest, state,
                    provider_request_id, provider_instance_id, runner_id,
                    failure_code, created_unix_ms, updated_unix_ms
             FROM runner_fleet_requests WHERE pool_id = ?1
             ORDER BY created_unix_ms, id LIMIT ?2",
        )?;
        let values = statement
            .query_map(
                params![pool_id, to_i64(MAX_FLEET_REQUESTS)?],
                fleet_request_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(ControlPlaneError::from)?;
        Ok(values)
    }

    pub fn runner_fleet_request(
        &self,
        request_id: &str,
    ) -> Result<RunnerFleetRequestRecord, ControlPlaneError> {
        validate_text("runner fleet request id", request_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, pool_id, runtime_compatibility_digest, provider,
                        provider_template_id, runner_template_digest, state,
                        provider_request_id, provider_instance_id, runner_id,
                        failure_code, created_unix_ms, updated_unix_ms
                 FROM runner_fleet_requests WHERE id = ?1",
                [request_id],
                fleet_request_row,
            )
            .optional()?
            .ok_or_else(|| not_found("runner fleet request", request_id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_runner_fleet_request(
        &self,
        request_id: &str,
        expected: RunnerFleetRequestState,
        next: RunnerFleetRequestState,
        provider_request_id: Option<&str>,
        provider_instance_id: Option<&str>,
        runner_id: Option<&str>,
        failure_code: Option<&str>,
        owner_id: &str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> Result<RunnerFleetRequestRecord, ControlPlaneError> {
        if !expected.can_transition_to(next) {
            return Err(ControlPlaneError::InvalidTransition {
                entity: "runner fleet request",
                from: fleet_request_state_name(expected),
                to: fleet_request_state_name(next),
            });
        }
        for (field, value) in [
            ("provider request id", provider_request_id),
            ("provider instance id", provider_instance_id),
            ("runner id", runner_id),
            ("fleet failure code", failure_code),
        ] {
            if let Some(value) = value {
                validate_text(field, value)?;
            }
        }
        validate_text("runner autoscaler owner", owner_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pool_id: String = transaction
            .query_row(
                "SELECT pool_id FROM runner_fleet_requests WHERE id = ?1",
                [request_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("runner fleet request", request_id))?;
        require_autoscaler_lease_tx(
            &transaction,
            &pool_id,
            owner_id,
            fencing_generation,
            now_unix_ms,
        )?;
        if next == RunnerFleetRequestState::Draining {
            let runner_id: String = transaction
                .query_row(
                    "SELECT runner_id FROM runner_fleet_requests
                     WHERE id = ?1 AND state = 'online' AND runner_id IS NOT NULL",
                    [request_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ControlPlaneError::InvalidTransition {
                    entity: "runner fleet request",
                    from: fleet_request_state_name(expected),
                    to: fleet_request_state_name(next),
                })?;
            let mut runner = persisted_runner_tx(&transaction, &runner_id)?;
            if !matches!(
                runner.runner.status,
                RunnerStatus::Online | RunnerStatus::Draining
            ) {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "autoscaled runner",
                    from: runner_status_name(runner.runner.status),
                    to: "draining",
                });
            }
            runner.runner.status = RunnerStatus::Draining;
            transaction.execute(
                "UPDATE runners SET status = 'draining', runner_json = ?2,
                   updated_unix_ms = ?3 WHERE id = ?1",
                params![
                    runner_id,
                    serde_json::to_string(&runner.runner)?,
                    to_i64(now_unix_ms)?,
                ],
            )?;
        }
        if expected == RunnerFleetRequestState::Draining
            && next == RunnerFleetRequestState::Terminating
        {
            let runner_id: String = transaction
                .query_row(
                    "SELECT runner_id FROM runner_fleet_requests
                     WHERE id = ?1 AND state = 'draining' AND runner_id IS NOT NULL",
                    [request_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ControlPlaneError::InvalidTransition {
                    entity: "runner fleet request",
                    from: "draining",
                    to: "terminating",
                })?;
            let runner = persisted_runner_tx(&transaction, &runner_id)?;
            let open_leases: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM leases
                 WHERE runner_id = ?1 AND state IN ('offered','active','cancel_requested')",
                [&runner_id],
                |row| row.get(0),
            )?;
            if runner.runner.status != RunnerStatus::Draining
                || runner.runner.active_jobs != 0
                || open_leases != 0
            {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "autoscaled runner drain",
                    from: "work-or-authority-open",
                    to: "terminating",
                });
            }
        }
        if expected == RunnerFleetRequestState::Terminating
            && next == RunnerFleetRequestState::Terminated
        {
            let bound_runner: Option<String> = transaction.query_row(
                "SELECT runner_id FROM runner_fleet_requests WHERE id=?1 AND state='terminating'",
                [request_id], |row| row.get(0),
            ).optional()?.flatten();
            if let Some(bound_runner) = bound_runner {
                let mut persisted = persisted_runner_tx(&transaction, &bound_runner)?;
                persisted.runner.status = RunnerStatus::Revoked;
                transaction.execute("UPDATE runners SET status='revoked',runner_json=?2,updated_unix_ms=?3 WHERE id=?1",params![bound_runner,serde_json::to_string(&persisted.runner)?,to_i64(now_unix_ms)?])?;
                transaction.execute("UPDATE runner_certificates SET status='revoked',revoked_unix_ms=?2 WHERE runner_id=?1 AND status IN('active','overlap')",params![bound_runner,to_i64(now_unix_ms)?])?;
                transaction.execute("UPDATE runner_replacements SET state='completed',updated_unix_ms=?2 WHERE source_fleet_request_id=?1 AND state='draining-source'",params![request_id,to_i64(now_unix_ms)?])?;
            }
        }
        let changed = transaction.execute(
            "UPDATE runner_fleet_requests SET state = ?3,
               provider_request_id = COALESCE(?4, provider_request_id),
               provider_instance_id = COALESCE(?5, provider_instance_id),
               runner_id = COALESCE(?6, runner_id),
               failure_code = COALESCE(?7, failure_code), updated_unix_ms = ?8
             WHERE id = ?1 AND state = ?2",
            params![
                request_id,
                fleet_request_state_name(expected),
                fleet_request_state_name(next),
                provider_request_id,
                provider_instance_id,
                runner_id,
                failure_code,
                to_i64(now_unix_ms)?,
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::InvalidTransition {
                entity: "runner fleet request",
                from: fleet_request_state_name(expected),
                to: fleet_request_state_name(next),
            });
        }
        if matches!(
            next,
            RunnerFleetRequestState::Failed | RunnerFleetRequestState::Quarantined
        ) {
            transaction.execute("UPDATE runner_replacements SET state='failed',failure_code=COALESCE(?2,'candidate-failed'),updated_unix_ms=?3 WHERE target_fleet_request_id=?1 AND state IN('requested','claim-issued','enrolled','probationary')",params![request_id,failure_code,to_i64(now_unix_ms)?])?;
        }
        let result = transaction
            .query_row(
                "SELECT id, pool_id, runtime_compatibility_digest, provider,
                    provider_template_id, runner_template_digest, state,
                    provider_request_id, provider_instance_id, runner_id,
                    failure_code, created_unix_ms, updated_unix_ms
             FROM runner_fleet_requests WHERE id = ?1",
                [request_id],
                fleet_request_row,
            )
            .map_err(ControlPlaneError::from)?;
        transaction.commit()?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_runner_launch_claim(
        &self,
        fleet_request_id: &str,
        provider_instance_id: &str,
        identity_proof_digest: &ContentDigest,
        owner_id: &str,
        fencing_generation: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<IssuedRunnerLaunchClaim, ControlPlaneError> {
        validate_text("runner fleet request id", fleet_request_id)?;
        validate_text("runner provider instance id", provider_instance_id)?;
        validate_text("runner autoscaler owner", owner_id)?;
        if expires_unix_ms <= now_unix_ms
            || expires_unix_ms.saturating_sub(now_unix_ms) > 15 * 60 * 1_000
        {
            return Err(ControlPlaneError::InvalidInput(
                "launch claim lifetime must be at most fifteen minutes",
            ));
        }
        let mut raw = [0_u8; ENROLLMENT_TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut raw)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let token = RunnerLaunchClaimToken::new(hex::encode(raw));
        raw.zeroize();
        let token_hash = enrollment_token_hash(token.expose());
        let mut id_bytes = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut id_bytes)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let suffix = hex::encode(id_bytes);
        let enrollment_token_id = format!("enroll-{suffix}");
        let claim_id = format!("launch-{suffix}");
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = transaction
            .query_row(
                "SELECT id, pool_id, runtime_compatibility_digest, provider,
                        provider_template_id, runner_template_digest, state,
                        provider_request_id, provider_instance_id, runner_id,
                        failure_code, created_unix_ms, updated_unix_ms
                 FROM runner_fleet_requests WHERE id = ?1",
                [fleet_request_id],
                fleet_request_row,
            )
            .optional()?
            .ok_or_else(|| not_found("runner fleet request", fleet_request_id))?;
        require_autoscaler_lease_tx(
            &transaction,
            &request.pool_id,
            owner_id,
            fencing_generation,
            now_unix_ms,
        )?;
        if request.state != RunnerFleetRequestState::Provisioning {
            return Err(ControlPlaneError::InvalidTransition {
                entity: "runner fleet request",
                from: fleet_request_state_name(request.state),
                to: fleet_request_state_name(RunnerFleetRequestState::Bootstrapping),
            });
        }
        transaction.execute(
            "INSERT INTO enrollment_tokens
             (id, pool_id, token_hash, created_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                enrollment_token_id,
                request.pool_id,
                token_hash.as_str(),
                to_i64(now_unix_ms)?,
                to_i64(expires_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO runner_launch_claims
             (id, fleet_request_id, enrollment_token_id, pool_id, provider,
              provider_instance_id, runner_template_digest, identity_proof_digest,
              created_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                claim_id,
                request.id,
                enrollment_token_id,
                request.pool_id,
                request.provider,
                provider_instance_id,
                request.runner_template_digest.as_str(),
                identity_proof_digest.as_str(),
                to_i64(now_unix_ms)?,
                to_i64(expires_unix_ms)?,
            ],
        )?;
        let replacement_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM runner_replacements WHERE target_fleet_request_id=?1)",
            [&request.id],
            |row| row.get(0),
        )?;
        if replacement_exists {
            let update_claim_id = format!("update-{suffix}");
            let inserted = transaction.execute(
                "INSERT INTO runner_software_update_claims
                 (id,replacement_id,enrollment_token_id,pool_id,mode,source_runner_id,
                  source_posture_digest,fleet_request_id,provider,provider_instance_id,
                  runner_template_digest,identity_proof_digest,generation,artifact_digest,
                  installed_digest,release_id,component_profile_digest,update_root_digest,
                  targets_metadata_digest,snapshot_metadata_digest,timestamp_metadata_digest,
                  policy_version,channel,rollout_ring,protocol_min,protocol_max,
                  required_attestation_grade,attestation_nonce_digest,created_unix_ms,expires_unix_ms)
                 SELECT ?1,r.id,?2,r.pool_id,'autoscaled',r.source_runner_id,
                        r.source_posture_digest,r.target_fleet_request_id,?3,?4,?5,?6,
                        r.generation,u.artifact_digest,u.installed_digest,u.id,
                        u.component_profile_digest,u.update_root_digest,u.targets_metadata_digest,
                        u.snapshot_metadata_digest,u.timestamp_metadata_digest,r.policy_version,
                        r.channel,r.rollout_ring,p.protocol_min,p.protocol_max,
                        p.required_attestation_grade,?6,?7,?8
                 FROM runner_replacements r
                 JOIN runner_update_releases u ON u.id=r.release_id AND u.revoked_unix_ms IS NULL
                 JOIN runner_pool_update_policies p ON p.pool_id=r.pool_id
                    AND p.version=r.policy_version AND p.enabled=1 AND p.paused=0
                 WHERE r.target_fleet_request_id=?9 AND r.state='requested'
                   AND p.runner_template_digest=?5 AND p.channel=r.channel",
                params![update_claim_id,enrollment_token_id,request.provider,provider_instance_id,
                    request.runner_template_digest.as_str(),identity_proof_digest.as_str(),
                    to_i64(now_unix_ms)?,to_i64(expires_unix_ms)?,request.id],
            )?;
            if inserted != 1 {
                return Err(ControlPlaneError::InvalidInput(
                    "software replacement policy or release changed before claim issue",
                ));
            }
            transaction.execute(
                "UPDATE runner_replacements SET state='claim-issued',updated_unix_ms=?2
                 WHERE target_fleet_request_id=?1 AND state='requested'",
                params![request.id, to_i64(now_unix_ms)?],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE runner_fleet_requests SET state = 'bootstrapping',
               provider_instance_id = ?2, updated_unix_ms = ?3
             WHERE id = ?1 AND state = 'provisioning'",
            params![request.id, provider_instance_id, to_i64(now_unix_ms)?,],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::InvalidTransition {
                entity: "runner fleet request",
                from: "provisioning",
                to: "bootstrapping",
            });
        }
        transaction.commit()?;
        Ok(IssuedRunnerLaunchClaim {
            metadata: RunnerLaunchClaimRecord {
                id: claim_id,
                fleet_request_id: request.id,
                enrollment_token_id,
                pool_id: request.pool_id,
                provider: request.provider,
                provider_instance_id: provider_instance_id.to_owned(),
                runner_template_digest: request.runner_template_digest,
                identity_proof_digest: identity_proof_digest.clone(),
                created_unix_ms: now_unix_ms,
                expires_unix_ms,
                consumed_unix_ms: None,
                runner_id: None,
            },
            token,
        })
    }

    pub fn runner_launch_claim_for_enrollment_token(
        &self,
        enrollment_token_id: &str,
    ) -> Result<Option<RunnerLaunchClaimRecord>, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, fleet_request_id, enrollment_token_id, pool_id, provider,
                        provider_instance_id, runner_template_digest, identity_proof_digest,
                        created_unix_ms, expires_unix_ms, consumed_unix_ms, runner_id
                 FROM runner_launch_claims WHERE enrollment_token_id = ?1",
                [enrollment_token_id],
                launch_claim_row,
            )
            .optional()
            .map_err(ControlPlaneError::from)
    }

    pub fn acquire_runner_autoscaler_lease(
        &self,
        pool_id: &str,
        owner_id: &str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<RunnerAutoscalerLease, ControlPlaneError> {
        validate_text("runner autoscaler pool", pool_id)?;
        validate_text("runner autoscaler owner", owner_id)?;
        if expires_unix_ms <= now_unix_ms
            || expires_unix_ms.saturating_sub(now_unix_ms) > MAX_AUTOSCALER_LEASE_MS
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid runner autoscaler lease lifetime",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, u64, u64)> = transaction
            .query_row(
                "SELECT owner_id, fencing_generation, expires_unix_ms
                 FROM runner_autoscaler_leases WHERE pool_id = ?1",
                [pool_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        u64_column(row, 1, "fencing_generation")?,
                        u64_column(row, 2, "expires_unix_ms")?,
                    ))
                },
            )
            .optional()?;
        let generation = match existing {
            Some((existing_owner, _generation, expiry))
                if existing_owner != owner_id && expiry > now_unix_ms =>
            {
                return Err(ControlPlaneError::InvalidInput(
                    "runner autoscaler lease is held by another owner",
                ));
            }
            Some((_, generation, _)) => {
                generation
                    .checked_add(1)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "runner autoscaler fencing generation",
                    })?
            }
            None => 1,
        };
        transaction.execute(
            "INSERT INTO runner_autoscaler_leases
             (pool_id, owner_id, fencing_generation, acquired_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(pool_id) DO UPDATE SET owner_id = excluded.owner_id,
               fencing_generation = excluded.fencing_generation,
               acquired_unix_ms = excluded.acquired_unix_ms,
               expires_unix_ms = excluded.expires_unix_ms",
            params![
                pool_id,
                owner_id,
                to_i64(generation)?,
                to_i64(now_unix_ms)?,
                to_i64(expires_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(RunnerAutoscalerLease {
            pool_id: pool_id.to_owned(),
            owner_id: owner_id.to_owned(),
            fencing_generation: generation,
            acquired_unix_ms: now_unix_ms,
            expires_unix_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
    use std::sync::{Arc, Barrier};

    fn fleet_control() -> Arc<ControlPlane> {
        let control = Arc::new(ControlPlane::open_in_memory("fleet-test", 1).unwrap());
        control
            .create_runner_pool(&RunnerPoolRecord {
                id: "pool-fleet".to_owned(),
                tenant_id: "tenant-fleet".to_owned(),
                name: "fleet".to_owned(),
                region: None,
                status: RunnerPoolStatus::Active,
                created_unix_ms: 1,
            })
            .unwrap();
        control
    }

    fn fleet_template(control: &ControlPlane, now: u64) -> RunnerPoolTemplateRecord {
        let template = RunnerPoolTemplateRecord {
            pool_id: "pool-fleet".to_owned(),
            runtime_compatibility_digest: ContentDigest::sha256(b"compatibility"),
            provider: "fake".to_owned(),
            provider_template_id: "template".to_owned(),
            runner_template_digest: ContentDigest::sha256(b"runner-template"),
            created_unix_ms: now,
            updated_unix_ms: now,
        };
        control.upsert_runner_pool_template(&template).unwrap();
        template
    }

    fn fleet_request(
        template: &RunnerPoolTemplateRecord,
        id: &str,
        now: u64,
    ) -> RunnerFleetRequestRecord {
        RunnerFleetRequestRecord {
            id: id.to_owned(),
            pool_id: template.pool_id.clone(),
            runtime_compatibility_digest: template.runtime_compatibility_digest.clone(),
            provider: template.provider.clone(),
            provider_template_id: template.provider_template_id.clone(),
            runner_template_digest: template.runner_template_digest.clone(),
            state: RunnerFleetRequestState::Requested,
            provider_request_id: None,
            provider_instance_id: None,
            runner_id: None,
            failure_code: None,
            created_unix_ms: now,
            updated_unix_ms: now,
        }
    }

    #[test]
    fn runtime_demand_digest_changes_for_every_hard_requirement() {
        let mut requirements = SchedulingRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation: Isolation::Oci,
            cpu: 2,
            memory_bytes: 1024,
            storage_bytes: 2048,
            region: Some("region-a".to_owned()),
            required_capabilities: BTreeSet::new(),
            allowed_pools: BTreeSet::from(["pool-a".to_owned()]),
        };
        let original = runtime_compatibility_digest(&requirements);
        requirements.cpu = 3;
        assert_ne!(original, runtime_compatibility_digest(&requirements));
    }

    #[test]
    fn lease_takeover_fences_the_previous_autoscaler() {
        let control = fleet_control();
        let template = fleet_template(&control, 10);
        let first = control
            .acquire_runner_autoscaler_lease("pool-fleet", "owner-a", 10, 20)
            .unwrap();
        assert_eq!(first.fencing_generation, 1);
        assert!(matches!(
            control.acquire_runner_autoscaler_lease("pool-fleet", "owner-b", 15, 25),
            Err(ControlPlaneError::InvalidInput(_))
        ));
        let second = control
            .acquire_runner_autoscaler_lease("pool-fleet", "owner-b", 20, 30)
            .unwrap();
        assert_eq!(second.fencing_generation, 2);
        assert_eq!(
            control
                .create_runner_fleet_request(&fleet_request(&template, "stale", 21), "owner-a", 1)
                .unwrap_err()
                .to_string(),
            ControlPlaneError::RunnerAutoscalerLeaseLost.to_string()
        );
        control
            .create_runner_fleet_request(&fleet_request(&template, "current", 21), "owner-b", 2)
            .unwrap();
        let same_principal_replica = control
            .acquire_runner_autoscaler_lease("pool-fleet", "owner-b", 22, 32)
            .unwrap();
        assert_eq!(same_principal_replica.fencing_generation, 3);
        assert!(matches!(
            control.create_runner_fleet_request(
                &fleet_request(&template, "old-replica", 23),
                "owner-b",
                2,
            ),
            Err(ControlPlaneError::RunnerAutoscalerLeaseLost)
        ));
    }

    #[test]
    fn launch_claim_bearer_has_one_concurrent_consumer() {
        let control = fleet_control();
        let template = fleet_template(&control, 10);
        control
            .acquire_runner_autoscaler_lease("pool-fleet", "owner", 10, 1_000)
            .unwrap();
        control
            .create_runner_fleet_request(&fleet_request(&template, "request", 11), "owner", 1)
            .unwrap();
        control
            .transition_runner_fleet_request(
                "request",
                RunnerFleetRequestState::Requested,
                RunnerFleetRequestState::Provisioning,
                Some("provider-request"),
                None,
                None,
                None,
                "owner",
                1,
                12,
            )
            .unwrap();
        let issued = control
            .create_runner_launch_claim(
                "request",
                "instance",
                &ContentDigest::sha256(b"identity"),
                "owner",
                1,
                13,
                900,
            )
            .unwrap();
        let token = Arc::new(issued.token.expose().to_owned());
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let control = Arc::clone(&control);
                let token = Arc::clone(&token);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    control.consume_enrollment_token(&token, 14)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ControlPlaneError::EnrollmentTokenConsumed)))
                .count(),
            1
        );
    }
}
