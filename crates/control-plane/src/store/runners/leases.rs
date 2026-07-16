// Lease lifecycle and execution-binding dependencies are explicit.
use super::{
    authoritative_runner_posture_digest, bind_deployment_gate_offer_tx, conversion, digest_column,
    enqueue_terminal_scm_check_tx, expire_unaccepted_offer_tx, installation_epoch_tx,
    invalid_transition, job_state_name, job_tx, materialized_planned_jobs_conn, not_found,
    optional_digest_column, params, parse_job_state, parse_runner_status,
    revoke_runner_broker_state_tx, run_source_binding_ready_tx, run_state_name, run_tx,
    runner_approval_subject_tx, scheduler_maintenance_tx, signed_capsule_conn, to_i64,
    transition_job_tx, u64_column, validate_text, BTreeMap, Connection, ContentDigest,
    ControlPlane, ControlPlaneError, DecodeError, ExecutionCapsule, JobState, Lease, LeaseState,
    OidcGrant, Row, RunState, RunnerRecord, RunnerStatus, SignedCapsuleRecord, Transaction,
    TransactionBehavior, Value, LEASE_SETUP_GRACE_MS, MAX_RUNNER_OPEN_LEASE_QUERY,
};
use rusqlite::OptionalExtension as _;

pub(in crate::store) fn lease_row(row: &Row<'_>) -> rusqlite::Result<Lease> {
    let state: String = row.get(10)?;
    Ok(Lease {
        id: row.get(0)?,
        job_id: row.get(1)?,
        tenant_id: row.get(2)?,
        runner_id: row.get(3)?,
        fencing_generation: u64_column(row, 4, "fencing_generation")?,
        installation_fencing_epoch: u64_column(row, 5, "installation_fencing_epoch")?,
        capsule_digest: digest_column(row, 6)?,
        issued_unix_ms: u64_column(row, 7, "issued_unix_ms")?,
        accept_by_unix_ms: u64_column(row, 8, "accept_by_unix_ms")?,
        expires_unix_ms: u64_column(row, 9, "expires_unix_ms")?,
        state: parse_lease_state(&state).map_err(|error| conversion(10, error))?,
        terminal_result_digest: optional_digest_column(row, 11)?,
    })
}

pub(in crate::store) fn validate_lease_fence_tx(
    transaction: &Transaction<'_>,
    lease_id: &str,
    runner_id: &str,
    generation: u64,
    epoch: u64,
) -> Result<Lease, ControlPlaneError> {
    let active_epoch = installation_epoch_tx(transaction)?;
    if epoch != active_epoch {
        return Err(ControlPlaneError::StaleInstallationEpoch {
            expected: active_epoch,
            actual: epoch,
        });
    }
    let lease = lease_tx(transaction, lease_id)?;
    if lease.runner_id != runner_id {
        return Err(ControlPlaneError::WrongRunner);
    }
    if lease.fencing_generation != generation {
        return Err(ControlPlaneError::StaleLeaseGeneration {
            expected: lease.fencing_generation,
            actual: generation,
        });
    }
    let authoritative_generation: i64 = transaction.query_row(
        "SELECT last_generation FROM job_fencing WHERE job_id = ?1",
        [&lease.job_id],
        |row| row.get(0),
    )?;
    let authoritative_generation =
        u64::try_from(authoritative_generation).map_err(|_| ControlPlaneError::IntegerRange {
            field: "generation",
        })?;
    if generation != authoritative_generation {
        return Err(ControlPlaneError::StaleLeaseGeneration {
            expected: authoritative_generation,
            actual: generation,
        });
    }
    if lease.installation_fencing_epoch != epoch {
        return Err(ControlPlaneError::StaleInstallationEpoch {
            expected: active_epoch,
            actual: lease.installation_fencing_epoch,
        });
    }
    Ok(lease)
}

pub(in crate::store) fn start_run_for_job_if_created_tx(
    transaction: &Transaction<'_>,
    job_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let run_id: String =
        transaction.query_row("SELECT run_id FROM jobs WHERE id = ?1", [job_id], |row| {
            row.get(0)
        })?;
    if run_tx(transaction, &run_id)?.status == RunState::Created {
        transaction.execute(
            "UPDATE runs SET status = 'running', started_unix_ms = ?2 WHERE id = ?1",
            params![run_id, to_i64(now_unix_ms)?],
        )?;
    }
    Ok(())
}

pub(in crate::store) fn conclude_run_if_terminal_tx(
    transaction: &Transaction<'_>,
    job_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    advance_run_dag_tx(transaction, job_id, now_unix_ms)?;
    let run_id: String =
        transaction.query_row("SELECT run_id FROM jobs WHERE id = ?1", [job_id], |row| {
            row.get(0)
        })?;
    let mut statement = transaction.prepare("SELECT status FROM jobs WHERE run_id = ?1")?;
    let states = statement
        .query_map([&run_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(|state| parse_job_state(&state).map_err(ControlPlaneError::from))
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let canonical_capsule: Vec<u8> = transaction.query_row(
        "SELECT p.canonical_capsule FROM runs r
         JOIN capsules p ON p.id = r.capsule_id WHERE r.id = ?1",
        [&run_id],
        |row| row.get(0),
    )?;
    let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
    if !capsule.dynamic_jobs.is_empty() {
        let mut job_states = transaction
            .prepare("SELECT job_key, status FROM jobs WHERE run_id = ?1 ORDER BY job_key")?;
        let job_states = job_states
            .query_map([&run_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|(key, state)| Ok((key, parse_job_state(&state)?)))
            .collect::<Result<BTreeMap<_, _>, ControlPlaneError>>()?;
        for template in &capsule.dynamic_jobs {
            let producer_state = job_states
                .get(&template.source.producer_job_id)
                .copied()
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "dynamic producer is absent from its run".to_owned(),
                    )
                })?;
            if producer_state != JobState::Succeeded {
                continue;
            }
            let canonical: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT canonical_job_set FROM expanded_job_sets
                     WHERE run_id = ?1 AND template_id = ?2",
                    params![run_id, template.id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(canonical) = canonical else {
                return Ok(());
            };
            let expanded: runtrue_workflow_ir::ExpandedJobSet = serde_json::from_slice(&canonical)?;
            if expanded
                .generated_job_ids
                .iter()
                .any(|job_key| !job_states.contains_key(job_key))
            {
                return Ok(());
            }
        }
    }
    if states
        .iter()
        .any(|state| !state.is_terminal() && *state != JobState::BlockedPolicy)
    {
        return Ok(());
    }
    let run = run_tx(transaction, &run_id)?;
    let final_state = if run.cancel_reason.is_some() || states.contains(&JobState::Canceled) {
        RunState::Canceled
    } else if states.iter().any(|state| {
        matches!(
            state,
            JobState::BlockedPolicy
                | JobState::Failed
                | JobState::TimedOut
                | JobState::Lost
                | JobState::Rejected
        )
    }) {
        RunState::Failed
    } else {
        RunState::Succeeded
    };
    if run.status.can_transition_to(final_state) {
        transaction.execute(
            "UPDATE runs SET status = ?2, completed_unix_ms = ?3 WHERE id = ?1",
            params![run_id, run_state_name(final_state), to_i64(now_unix_ms)?,],
        )?;
    }
    let current = run_tx(transaction, &run_id)?;
    if current.status.is_terminal() {
        enqueue_terminal_scm_check_tx(transaction, &run_id, current.status, now_unix_ms)?;
    }
    Ok(())
}

pub(in crate::store) fn advance_run_dag_tx(
    transaction: &Transaction<'_>,
    changed_job_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let (run_id, canonical_capsule): (String, Vec<u8>) = transaction.query_row(
        "SELECT j.run_id, p.canonical_capsule FROM jobs j
         JOIN runs r ON r.id = j.run_id JOIN capsules p ON p.id = r.capsule_id
         WHERE j.id = ?1",
        [changed_job_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
    let source_ready = run_source_binding_ready_tx(transaction, &run_id, &capsule)?;
    let planned_jobs = materialized_planned_jobs_conn(transaction, &run_id, &capsule)?;
    loop {
        let mut statement = transaction
            .prepare("SELECT job_key, status FROM jobs WHERE run_id = ?1 ORDER BY id")?;
        let states = statement
            .query_map([&run_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|(key, state)| Ok((key, parse_job_state(&state)?)))
            .collect::<Result<BTreeMap<_, _>, ControlPlaneError>>()?;
        drop(statement);
        if states.len() != planned_jobs.len() {
            return Err(ControlPlaneError::CorruptState(
                "run jobs do not match the signed capsule DAG".to_owned(),
            ));
        }
        let mut changes = Vec::new();
        for planned in planned_jobs.values() {
            let current =
                states
                    .get(&planned.id)
                    .copied()
                    .ok_or(ControlPlaneError::CorruptState(
                        "signed capsule job is absent from its run".to_owned(),
                    ))?;
            if current != JobState::Created {
                continue;
            }
            let next = if !capsule.context.source_trust.satisfies(planned.trust) {
                Some(JobState::BlockedPolicy)
            } else if !source_ready {
                None
            } else {
                let dependencies = planned
                    .needs
                    .iter()
                    .map(|need| {
                        states
                            .get(need)
                            .copied()
                            .ok_or(ControlPlaneError::CorruptState(
                                "signed capsule dependency is absent from its run".to_owned(),
                            ))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if dependencies
                    .iter()
                    .all(|state| *state == JobState::Succeeded)
                {
                    Some(JobState::Queued)
                } else if dependencies.iter().any(|state| {
                    (*state != JobState::Succeeded && state.is_terminal())
                        || *state == JobState::BlockedPolicy
                }) {
                    Some(JobState::Skipped)
                } else {
                    None
                }
            };
            if let Some(next) = next {
                changes.push((planned.id.clone(), next));
            }
        }
        if changes.is_empty() {
            break;
        }
        for (job_key, next) in changes {
            let completed = (next.is_terminal() || next == JobState::BlockedPolicy)
                .then_some(to_i64(now_unix_ms)?);
            transaction.execute(
                "UPDATE jobs SET status = ?3, completed_unix_ms = ?4
                 WHERE run_id = ?1 AND job_key = ?2 AND status = 'created'",
                params![run_id, job_key, job_state_name(next), completed,],
            )?;
        }
    }
    Ok(())
}

pub(in crate::store) fn expire_lease_with_state_tx(
    transaction: &Transaction<'_>,
    lease: &Lease,
    preferred_job_state: JobState,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "UPDATE leases SET state = 'expired' WHERE id = ?1",
        [&lease.id],
    )?;
    revoke_runner_broker_state_tx(
        transaction,
        &lease.id,
        lease.fencing_generation,
        now_unix_ms,
        "expired",
    )?;
    let job = job_tx(transaction, &lease.job_id)?;
    let next = if job.status.can_transition_to(preferred_job_state) {
        Some(preferred_job_state)
    } else if job.status.can_transition_to(JobState::Lost) {
        Some(JobState::Lost)
    } else {
        None
    };
    if let Some(next) = next {
        transition_job_tx(transaction, &lease.job_id, next, now_unix_ms)?;
    }
    Ok(())
}

pub(in crate::store) fn lease_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<Lease, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, job_id, tenant_id, runner_id, fencing_generation, installation_fencing_epoch,
                    capsule_digest, issued_unix_ms, accept_by_unix_ms, expires_unix_ms,
                    state, terminal_result_digest
             FROM leases WHERE id = ?1",
            [id],
            lease_row,
        )
        .optional()?
        .ok_or_else(|| not_found("lease", id))
}

pub(in crate::store) fn lease_hard_deadline_conn(
    connection: &Connection,
    id: &str,
) -> Result<u64, ControlPlaneError> {
    connection
        .query_row(
            "SELECT hard_deadline_unix_ms FROM leases WHERE id = ?1",
            [id],
            |row| u64_column(row, 0, "lease hard deadline"),
        )
        .optional()?
        .ok_or_else(|| not_found("lease", id))
}

pub(in crate::store) fn lease_hard_deadline_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<u64, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT hard_deadline_unix_ms FROM leases WHERE id = ?1",
            [id],
            |row| u64_column(row, 0, "lease hard deadline"),
        )
        .optional()?
        .ok_or_else(|| not_found("lease", id))
}

pub(in crate::store) fn lease_state_name(state: LeaseState) -> &'static str {
    match state {
        LeaseState::Offered => "offered",
        LeaseState::Active => "active",
        LeaseState::CancelRequested => "cancel_requested",
        LeaseState::Completed => "completed",
        LeaseState::Rejected => "rejected",
        LeaseState::Expired => "expired",
    }
}

pub(in crate::store) fn transient_runner_rejection(code: &str) -> bool {
    matches!(
        code,
        "capsule_fetch_failed"
            | "image_admission_pending"
            | "unsupported_isolation"
            | "trusted_native_disabled"
            | "job_resource_limit"
            | "executor_preflight_rejected"
            | "accept_deadline_elapsed"
            | "lease_window_too_short"
    )
}

pub(in crate::store) fn parse_lease_state(value: &str) -> Result<LeaseState, DecodeError> {
    match value {
        "offered" => Ok(LeaseState::Offered),
        "active" => Ok(LeaseState::Active),
        "cancel_requested" => Ok(LeaseState::CancelRequested),
        "completed" => Ok(LeaseState::Completed),
        "rejected" => Ok(LeaseState::Rejected),
        "expired" => Ok(LeaseState::Expired),
        _ => Err(DecodeError(format!("unknown lease state `{value}`"))),
    }
}

pub(in crate::store) fn lease_conn(
    connection: &Connection,
    id: &str,
) -> Result<Lease, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, job_id, tenant_id, runner_id, fencing_generation, installation_fencing_epoch,
                    capsule_digest, issued_unix_ms, accept_by_unix_ms, expires_unix_ms,
                    state, terminal_result_digest
             FROM leases WHERE id = ?1",
            [id],
            lease_row,
        )
        .optional()?
        .ok_or_else(|| not_found("lease", id))
}

pub(in crate::store) fn validate_oidc_subject_conn(
    connection: &Connection,
    grant: &OidcGrant,
    lease: &Lease,
) -> Result<(), ControlPlaneError> {
    let subject: Option<(String, String, String, String, Vec<u8>)> = connection
        .query_row(
            "SELECT j.run_id, j.job_key, r.repository_id, repositories.tenant_id,
                    p.canonical_capsule
             FROM jobs j
             JOIN runs r ON r.id = j.run_id
             JOIN repositories ON repositories.id = r.repository_id
             JOIN capsules p ON p.id = r.capsule_id
             WHERE j.id = ?1",
            [&grant.job_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((run_id, job_key, repository_id, tenant_id, canonical_capsule)) = subject else {
        return Err(ControlPlaneError::StaleOidcGrant);
    };
    let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
    let planned_jobs = materialized_planned_jobs_conn(connection, &run_id, &capsule)?;
    let Some(planned_job) = planned_jobs.get(&job_key) else {
        return Err(ControlPlaneError::StaleOidcGrant);
    };
    let Some(planned_step) = planned_job
        .steps
        .iter()
        .find(|step| step.id == grant.step_id)
    else {
        return Err(ControlPlaneError::StaleOidcGrant);
    };
    let expected_trust = match serde_json::to_value(capsule.context.source_trust)? {
        Value::String(value) => value,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "capsule trust is not a string".to_owned(),
            ))
        }
    };
    let expected_ref = match capsule.context.event_context.get("event.ref") {
        Some(runtrue_workflow_ir::ScalarValue::String(value)) => Some(value.as_str()),
        Some(_) => return Err(ControlPlaneError::StaleOidcGrant),
        None => None,
    };
    let audiences_declared = grant
        .allowed_audiences
        .iter()
        .all(|audience| planned_step.capabilities.oidc_audiences.contains(audience));
    let runner_binding: Option<(String, String, String)> = connection
        .query_row(
            "SELECT r.runner_json, b.inventory_digest, b.posture_digest
             FROM runners r JOIN runner_enrollment_postures b ON b.runner_id = r.id
             WHERE r.id = ?1",
            [&lease.runner_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((runner_json, inventory_digest, stored_posture)) = runner_binding else {
        return Err(ControlPlaneError::StaleOidcGrant);
    };
    let runner: RunnerRecord = serde_json::from_str(&runner_json)?;
    let posture =
        authoritative_runner_posture_digest(&runner, &ContentDigest::parse(inventory_digest)?)?;
    if lease.tenant_id != grant.tenant_id
        || run_id != grant.run_id
        || repository_id != grant.repository_id
        || tenant_id != grant.tenant_id
        || capsule.context.source_commit != grant.source_commit
        || expected_trust != grant.trust
        || grant.runner_pool_id.as_deref() != Some(runner.pool_id.as_str())
        || grant.runner_posture_digest.as_ref() != Some(&posture)
        || ContentDigest::parse(stored_posture)? != posture
        || planned_job.environment != grant.environment
        || grant.ref_name.as_deref() != expected_ref
        || !audiences_declared
    {
        return Err(ControlPlaneError::StaleOidcGrant);
    }
    Ok(())
}

pub(in crate::store) struct RunnerExecutionSubject {
    pub(in crate::store) lease: Lease,
    pub(in crate::store) run_id: String,
    pub(in crate::store) repository_id: String,
    pub(in crate::store) tenant_id: String,
    pub(in crate::store) capsule_id: String,
    pub(in crate::store) capsule: ExecutionCapsule,
    pub(in crate::store) planned_job: runtrue_workflow_ir::PlannedJob,
    pub(in crate::store) runner_pool_id: String,
    pub(in crate::store) runner_posture_digest: ContentDigest,
}

pub(in crate::store) type RunnerExecutionSubjectRow =
    (String, String, String, String, String, Vec<u8>, String);

impl ControlPlane {
    pub fn create_lease(
        &self,
        lease_id: &str,
        job_id: &str,
        runner_id: &str,
        issued_unix_ms: u64,
        accept_by_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        validate_text("lease.id", lease_id)?;
        if accept_by_unix_ms <= issued_unix_ms || expires_unix_ms <= accept_by_unix_ms {
            return Err(ControlPlaneError::InvalidInput("invalid lease deadlines"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = job_tx(&transaction, job_id)?;
        if job.status != JobState::Queued {
            return Err(invalid_transition(
                "job",
                job_state_name(job.status),
                job_state_name(JobState::Leased),
            ));
        }
        let (runner_status, runner_tenant, runner_json): (String, String, String) = transaction
            .query_row(
                "SELECT r.status, p.tenant_id, r.runner_json FROM runners r
                 JOIN runner_pools p ON p.id = r.pool_id WHERE r.id = ?1",
                [runner_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| not_found("runner", runner_id))?;
        if parse_runner_status(&runner_status)? != RunnerStatus::Online {
            return Err(ControlPlaneError::InvalidInput("runner is not online"));
        }
        let durable_runner: RunnerRecord = serde_json::from_str(&runner_json)?;
        if durable_runner.id != runner_id || durable_runner.tenant_id != runner_tenant {
            return Err(ControlPlaneError::CorruptState(
                "runner tenant binding does not match its pool".to_owned(),
            ));
        }
        let (capsule_digest, tenant_id, run_id, capsule_id, canonical_capsule): (
            String,
            String,
            String,
            String,
            Vec<u8>,
        ) = transaction.query_row(
            "SELECT p.digest, repo.tenant_id, r.id, p.id, p.canonical_capsule FROM jobs j
             JOIN runs r ON r.id = j.run_id JOIN capsules p ON p.id = r.capsule_id
             JOIN repositories repo ON repo.id = r.repository_id
             WHERE j.id = ?1",
            [job_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
        let planned_jobs = materialized_planned_jobs_conn(&transaction, &run_id, &capsule)?;
        let planned_job = planned_jobs
            .get(&job.job_key)
            .ok_or(ControlPlaneError::CorruptState(
                "test lease job is absent from its signed capsule".to_owned(),
            ))?;
        let hard_deadline_unix_ms = issued_unix_ms
            .checked_add(LEASE_SETUP_GRACE_MS)
            .and_then(|value| value.checked_add(planned_job.timeout_ms))
            .ok_or(ControlPlaneError::IntegerRange {
                field: "lease hard deadline",
            })?;
        if runner_tenant != tenant_id {
            return Err(ControlPlaneError::InvalidInput(
                "runner pool tenant does not match the queued job tenant",
            ));
        }
        runner_approval_subject_tx(&transaction, &capsule_id, &run_id, &capsule)?;
        let current_generation: i64 = transaction.query_row(
            "SELECT last_generation FROM job_fencing WHERE job_id = ?1",
            [job_id],
            |row| row.get(0),
        )?;
        let generation = u64::try_from(current_generation)
            .map_err(|_| ControlPlaneError::IntegerRange {
                field: "generation",
            })?
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "generation",
            })?;
        let epoch = installation_epoch_tx(&transaction)?;
        transaction.execute(
            "UPDATE job_fencing SET last_generation = ?2 WHERE job_id = ?1",
            params![job_id, to_i64(generation)?],
        )?;
        transaction.execute(
            "INSERT INTO leases
             (id, job_id, tenant_id, runner_id, fencing_generation, installation_fencing_epoch,
              capsule_digest, state, issued_unix_ms, accept_by_unix_ms, expires_unix_ms,
              hard_deadline_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'offered', ?8, ?9, ?10, ?11)",
            params![
                lease_id,
                job_id,
                tenant_id,
                runner_id,
                to_i64(generation)?,
                to_i64(epoch)?,
                capsule_digest,
                to_i64(issued_unix_ms)?,
                to_i64(accept_by_unix_ms)?,
                to_i64(expires_unix_ms)?,
                to_i64(hard_deadline_unix_ms)?,
            ],
        )?;
        bind_deployment_gate_offer_tx(
            &transaction,
            &tenant_id,
            &job,
            lease_id,
            generation,
            epoch,
            issued_unix_ms,
        )?;
        transition_job_tx(&transaction, job_id, JobState::Leased, issued_unix_ms)?;
        let lease = lease_tx(&transaction, lease_id)?;
        transaction.commit()?;
        Ok(lease)
    }

    pub fn accept_lease(
        &self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        now_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = validate_lease_fence_tx(&transaction, lease_id, runner_id, generation, epoch)?;
        if lease.state != LeaseState::Offered {
            return Err(ControlPlaneError::InvalidLeaseState {
                expected: "offered",
                actual: lease_state_name(lease.state),
            });
        }
        let hard_deadline = lease_hard_deadline_tx(&transaction, lease_id)?;
        if now_unix_ms >= lease.accept_by_unix_ms
            || now_unix_ms >= lease.expires_unix_ms
            || now_unix_ms >= hard_deadline
        {
            expire_unaccepted_offer_tx(&transaction, &lease, now_unix_ms)?;
            transaction.commit()?;
            return Err(ControlPlaneError::LeaseOfferExpired);
        }
        transaction.execute(
            "UPDATE leases SET state = 'active' WHERE id = ?1",
            [lease_id],
        )?;
        transition_job_tx(
            &transaction,
            &lease.job_id,
            JobState::Preparing,
            now_unix_ms,
        )?;
        let run_id: String = transaction.query_row(
            "SELECT run_id FROM jobs WHERE id = ?1",
            [&lease.job_id],
            |row| row.get(0),
        )?;
        let run = run_tx(&transaction, &run_id)?;
        if run.status == RunState::Created {
            transaction.execute(
                "UPDATE runs SET status = 'running', started_unix_ms = ?2 WHERE id = ?1",
                params![run_id, to_i64(now_unix_ms)?],
            )?;
        }
        let accepted = lease_tx(&transaction, lease_id)?;
        transaction.commit()?;
        Ok(accepted)
    }

    /// Return a bounded, deterministic view of unfinished leases assigned to
    /// one runner. The caller must still validate every fence before acting.
    pub fn open_leases_for_runner(
        &self,
        runner_id: &str,
        limit: usize,
    ) -> Result<Vec<Lease>, ControlPlaneError> {
        validate_text("runner id", runner_id)?;
        if limit == 0 || limit > MAX_RUNNER_OPEN_LEASE_QUERY {
            return Err(ControlPlaneError::InvalidInput(
                "runner open-lease query limit is invalid",
            ));
        }
        let limit = u64::try_from(limit).map_err(|_| ControlPlaneError::IntegerRange {
            field: "runner open-lease query limit",
        })?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, job_id, tenant_id, runner_id, fencing_generation,
                    installation_fencing_epoch, capsule_digest, issued_unix_ms,
                    accept_by_unix_ms, expires_unix_ms, state, terminal_result_digest
             FROM leases WHERE runner_id = ?1
             AND state IN ('offered', 'active', 'cancel_requested')
             ORDER BY issued_unix_ms, id LIMIT ?2",
        )?;
        let leases = statement
            .query_map(params![runner_id, to_i64(limit)?], lease_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(ControlPlaneError::from)?;
        Ok(leases)
    }

    /// Load the immutable job key and signed capsule reached by a lease, while
    /// checking that the lease's stored digest still matches that exact capsule.
    pub fn signed_capsule_for_lease(
        &self,
        lease_id: &str,
    ) -> Result<(String, SignedCapsuleRecord), ControlPlaneError> {
        validate_text("lease id", lease_id)?;
        let connection = self.connection()?;
        let lease = lease_conn(&connection, lease_id)?;
        let (job_key, capsule_id): (String, String) = connection
            .query_row(
                "SELECT j.job_key, r.capsule_id FROM leases l
                 JOIN jobs j ON j.id = l.job_id
                 JOIN runs r ON r.id = j.run_id
                 WHERE l.id = ?1",
                [lease_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| not_found("lease capsule", lease_id))?;
        let capsule = signed_capsule_conn(&connection, &capsule_id)?;
        if lease.capsule_digest != capsule.digest
            || capsule.signature.capsule_digest != capsule.digest
        {
            return Err(ControlPlaneError::CorruptState(
                "lease capsule digest does not match its signed capsule".to_owned(),
            ));
        }
        Ok((job_key, capsule))
    }

    /// Durably reject an exact offered lease. The current durable lifecycle
    /// has no automatic retry-attempt constructor, so the job becomes `lost`
    /// rather than being silently requeued under the same attempt.
    pub fn reject_lease(
        &self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        now_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        self.reject_lease_with_code(
            lease_id,
            runner_id,
            generation,
            epoch,
            "permanent_rejection",
            now_unix_ms,
        )
    }

    pub fn reject_lease_with_code(
        &self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        rejection_code: &str,
        now_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        validate_text("lease rejection code", rejection_code)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = validate_lease_fence_tx(&transaction, lease_id, runner_id, generation, epoch)?;
        if lease.state == LeaseState::Rejected {
            transaction.commit()?;
            return Ok(lease);
        }
        if lease.state != LeaseState::Offered {
            return Err(ControlPlaneError::InvalidLeaseState {
                expected: "offered",
                actual: lease_state_name(lease.state),
            });
        }
        if now_unix_ms >= lease.accept_by_unix_ms {
            expire_unaccepted_offer_tx(&transaction, &lease, now_unix_ms)?;
            transaction.commit()?;
            return Err(ControlPlaneError::LeaseOfferExpired);
        }
        transaction.execute(
            "UPDATE leases SET state = 'rejected' WHERE id = ?1",
            [&lease.id],
        )?;
        if transient_runner_rejection(rejection_code) {
            transaction.execute(
                "INSERT INTO runner_job_rejections
                 (runner_id, job_id, rejection_count, last_code, updated_unix_ms)
                 VALUES (?1, ?2, 1, ?3, ?4)
                 ON CONFLICT(runner_id, job_id) DO UPDATE SET
                   rejection_count = CASE
                     WHEN excluded.last_code = 'image_admission_pending'
                       THEN rejection_count
                     WHEN last_code = 'image_admission_pending' AND rejection_count = 1
                       THEN 1
                     ELSE rejection_count + 1
                   END,
                   last_code = excluded.last_code,
                   updated_unix_ms = excluded.updated_unix_ms",
                params![
                    runner_id,
                    lease.job_id,
                    rejection_code,
                    to_i64(now_unix_ms)?
                ],
            )?;
            transition_job_tx(&transaction, &lease.job_id, JobState::Queued, now_unix_ms)?;
        } else {
            transaction.execute(
                "UPDATE jobs SET status = 'blocked_policy', completed_unix_ms = ?2
                 WHERE id = ?1 AND status = 'leased'",
                params![lease.job_id, to_i64(now_unix_ms)?],
            )?;
            start_run_for_job_if_created_tx(&transaction, &lease.job_id, now_unix_ms)?;
            conclude_run_if_terminal_tx(&transaction, &lease.job_id, now_unix_ms)?;
        }
        let rejected = lease_tx(&transaction, &lease.id)?;
        transaction.commit()?;
        Ok(rejected)
    }

    pub fn heartbeat_lease(
        &self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        now_unix_ms: u64,
        new_expires_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        if new_expires_unix_ms <= now_unix_ms {
            return Err(ControlPlaneError::InvalidInput("invalid heartbeat expiry"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = validate_lease_fence_tx(&transaction, lease_id, runner_id, generation, epoch)?;
        let hard_deadline = lease_hard_deadline_tx(&transaction, lease_id)?;
        if !matches!(
            lease.state,
            LeaseState::Active | LeaseState::CancelRequested
        ) {
            return Err(ControlPlaneError::InvalidLeaseState {
                expected: "active or cancel_requested",
                actual: lease_state_name(lease.state),
            });
        }
        if now_unix_ms >= hard_deadline {
            expire_lease_with_state_tx(
                &transaction,
                &lease,
                if lease.state == LeaseState::CancelRequested {
                    JobState::Canceled
                } else {
                    JobState::TimedOut
                },
                now_unix_ms,
            )?;
            conclude_run_if_terminal_tx(&transaction, &lease.job_id, now_unix_ms)?;
            transaction.commit()?;
            return Err(ControlPlaneError::LeaseExpired);
        }
        if now_unix_ms >= lease.expires_unix_ms {
            expire_lease_with_state_tx(
                &transaction,
                &lease,
                if lease.state == LeaseState::CancelRequested {
                    JobState::Canceled
                } else {
                    JobState::Lost
                },
                now_unix_ms,
            )?;
            conclude_run_if_terminal_tx(&transaction, &lease.job_id, now_unix_ms)?;
            transaction.commit()?;
            return Err(ControlPlaneError::LeaseExpired);
        }
        let new_expires_unix_ms = new_expires_unix_ms.min(hard_deadline);
        if new_expires_unix_ms <= now_unix_ms {
            return Err(ControlPlaneError::LeaseExpired);
        }
        transaction.execute(
            "UPDATE leases SET expires_unix_ms = ?2 WHERE id = ?1",
            params![lease_id, to_i64(new_expires_unix_ms)?],
        )?;
        scheduler_maintenance_tx(&transaction, now_unix_ms)?;
        let value = lease_tx(&transaction, lease_id)?;
        transaction.commit()?;
        Ok(value)
    }

    pub fn request_lease_cancel(
        &self,
        job_id: &str,
        now_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease_id: String = transaction
            .query_row(
                "SELECT id FROM leases WHERE job_id = ?1
                 AND state IN ('offered', 'active', 'cancel_requested')",
                [job_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("active lease for job", job_id))?;
        let lease = lease_tx(&transaction, &lease_id)?;
        revoke_runner_broker_state_tx(
            &transaction,
            &lease.id,
            lease.fencing_generation,
            now_unix_ms,
            "revoked",
        )?;
        if lease.state == LeaseState::Offered {
            transaction.execute(
                "UPDATE leases SET state = 'rejected' WHERE id = ?1",
                [&lease_id],
            )?;
            let job = job_tx(&transaction, job_id)?;
            if job.status.can_transition_to(JobState::Canceled) {
                transition_job_tx(&transaction, job_id, JobState::Canceled, now_unix_ms)?;
            }
            conclude_run_if_terminal_tx(&transaction, job_id, now_unix_ms)?;
        } else if lease.state == LeaseState::Active {
            transaction.execute(
                "UPDATE leases SET state = 'cancel_requested' WHERE id = ?1",
                [&lease_id],
            )?;
        }
        let value = lease_tx(&transaction, &lease_id)?;
        transaction.commit()?;
        Ok(value)
    }
}

mod completion;
