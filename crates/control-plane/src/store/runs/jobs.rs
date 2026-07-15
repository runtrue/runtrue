use super::*;
use rusqlite::params;
use serde::Serialize;

pub(in crate::store) fn job_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<JobRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, run_id, job_key, attempt, status, requirements_json,
                    created_unix_ms, completed_unix_ms FROM jobs WHERE id = ?1",
            [id],
            job_row,
        )
        .optional()?
        .ok_or_else(|| not_found("job", id))
}

pub(in crate::store) fn job_row(row: &Row<'_>) -> rusqlite::Result<JobRecord> {
    let state: String = row.get(4)?;
    let attempt: i64 = row.get(3)?;
    Ok(JobRecord {
        id: row.get(0)?,
        run_id: row.get(1)?,
        job_key: row.get(2)?,
        attempt: u32::try_from(attempt).map_err(|error| conversion(3, error))?,
        status: parse_job_state(&state).map_err(|error| conversion(4, error))?,
        requirements: json_column(row, 5)?,
        created_unix_ms: u64_column(row, 6, "created_unix_ms")?,
        completed_unix_ms: optional_u64_column(row, 7, "completed_unix_ms")?,
    })
}

pub(in crate::store) fn transition_job_tx(
    transaction: &Transaction<'_>,
    job_id: &str,
    next: JobState,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let current = job_tx(transaction, job_id)?;
    if current.status == next {
        return Ok(());
    }
    if !current.status.can_transition_to(next) {
        return Err(invalid_transition(
            "job",
            job_state_name(current.status),
            job_state_name(next),
        ));
    }
    transaction.execute(
        "UPDATE jobs SET status = ?2, completed_unix_ms = ?3 WHERE id = ?1",
        params![
            job_id,
            job_state_name(next),
            next.is_terminal().then_some(to_i64(now_unix_ms)?),
        ],
    )?;
    Ok(())
}

impl ControlPlane {
    pub fn jobs_for_run(&self, run_id: &str) -> Result<Vec<JobRecord>, ControlPlaneError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, run_id, job_key, attempt, status, requirements_json,
                    created_unix_ms, completed_unix_ms
             FROM jobs WHERE run_id = ?1 ORDER BY id",
        )?;
        let jobs = statement
            .query_map([run_id], job_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(jobs)
    }

    pub fn job(&self, job_id: &str) -> Result<JobRecord, ControlPlaneError> {
        validate_text("job id", job_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, run_id, job_key, attempt, status, requirements_json,
                        created_unix_ms, completed_unix_ms
                 FROM jobs WHERE id = ?1",
                [job_id],
                job_row,
            )
            .optional()?
            .ok_or_else(|| not_found("job", job_id))
    }

    pub fn transition_run_state(
        &self,
        run_id: &str,
        next: RunState,
        now_unix_ms: u64,
    ) -> Result<RunRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = run_tx(&transaction, run_id)?;
        if !current.status.can_transition_to(next) {
            return Err(invalid_transition(
                "run",
                run_state_name(current.status),
                run_state_name(next),
            ));
        }
        let started = (next == RunState::Running).then_some(to_i64(now_unix_ms)?);
        let completed = next.is_terminal().then_some(to_i64(now_unix_ms)?);
        transaction.execute(
            "UPDATE runs
             SET status = ?2,
                 started_unix_ms = COALESCE(started_unix_ms, ?3),
                 completed_unix_ms = COALESCE(completed_unix_ms, ?4)
             WHERE id = ?1",
            params![run_id, run_state_name(next), started, completed],
        )?;
        let value = run_tx(&transaction, run_id)?;
        if value.status.is_terminal() {
            enqueue_terminal_scm_check_tx(&transaction, run_id, value.status, now_unix_ms)?;
        }
        transaction.commit()?;
        Ok(value)
    }

    pub fn transition_job_state(
        &self,
        job_id: &str,
        next: JobState,
        now_unix_ms: u64,
    ) -> Result<JobRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transition_job_tx(&transaction, job_id, next, now_unix_ms)?;
        if next.is_terminal() || next == JobState::BlockedPolicy {
            conclude_run_if_terminal_tx(&transaction, job_id, now_unix_ms)?;
        }
        let value = job_tx(&transaction, job_id)?;
        transaction.commit()?;
        Ok(value)
    }

    pub fn cancel_run_idempotent(
        &self,
        idempotency_key: &str,
        run_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<RunRecord>, ControlPlaneError> {
        #[derive(Serialize)]
        struct CancelRequest<'a> {
            run_id: &'a str,
            reason: &'a str,
        }
        validate_idempotency_key(idempotency_key)?;
        validate_text("cancel reason", reason)?;
        let request_hash = hash_serializable(&CancelRequest { run_id, reason })?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, "run.cancel", idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = run_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        let run = run_tx(&transaction, run_id)?;
        if run.status != RunState::Canceled {
            if run.status.is_terminal() {
                return Err(invalid_transition(
                    "run",
                    run_state_name(run.status),
                    run_state_name(RunState::Canceled),
                ));
            }
            transaction.execute(
                "UPDATE runs SET cancel_reason = COALESCE(cancel_reason, ?2) WHERE id = ?1",
                params![run_id, reason],
            )?;
            let mut statement =
                transaction.prepare("SELECT id, status FROM jobs WHERE run_id = ?1 ORDER BY id")?;
            let jobs = statement
                .query_map([run_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            for (job_id, encoded) in jobs {
                let state = parse_job_state(&encoded)?;
                let open_lease: Option<(String, String, i64)> = transaction
                    .query_row(
                        "SELECT id, state, fencing_generation FROM leases
                         WHERE job_id = ?1 AND state IN ('offered', 'active', 'cancel_requested')
                         ORDER BY issued_unix_ms DESC LIMIT 1",
                        [&job_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                if let Some((lease_id, lease_state, generation)) = open_lease {
                    let lease_state = parse_lease_state(&lease_state)?;
                    let generation = from_i64("generation", generation)?;
                    revoke_runner_broker_state_tx(
                        &transaction,
                        &lease_id,
                        generation,
                        now_unix_ms,
                        "revoked",
                    )?;
                    if lease_state == LeaseState::Offered {
                        transaction.execute(
                            "UPDATE leases SET state = 'rejected' WHERE id = ?1",
                            [&lease_id],
                        )?;
                        if state.can_transition_to(JobState::Canceled) {
                            transition_job_tx(
                                &transaction,
                                &job_id,
                                JobState::Canceled,
                                now_unix_ms,
                            )?;
                        }
                    } else {
                        transaction.execute(
                            "UPDATE leases SET state = 'cancel_requested'
                             WHERE id = ?1 AND state = 'active'",
                            [&lease_id],
                        )?;
                    }
                } else if state.can_transition_to(JobState::Canceled) {
                    transaction.execute(
                        "UPDATE jobs SET status = 'canceled', completed_unix_ms = ?2 WHERE id = ?1",
                        params![job_id, to_i64(now_unix_ms)?],
                    )?;
                }
            }
            let active_fences: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM leases l JOIN jobs j ON j.id = l.job_id
                    WHERE j.run_id = ?1 AND l.state IN ('active', 'cancel_requested')
                 )",
                [run_id],
                |row| row.get(0),
            )?;
            if !active_fences {
                transaction.execute(
                    "UPDATE runs SET status = 'canceled', completed_unix_ms = ?2
                     WHERE id = ?1",
                    params![run_id, to_i64(now_unix_ms)?],
                )?;
            }
        }
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES ('run.cancel', ?1, ?2, ?3, ?4)",
            params![
                idempotency_key,
                request_hash.as_str(),
                run_id,
                to_i64(now_unix_ms)?,
            ],
        )?;
        let value = run_tx(&transaction, run_id)?;
        if value.status.is_terminal() {
            enqueue_terminal_scm_check_tx(&transaction, run_id, value.status, now_unix_ms)?;
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value,
            replayed: false,
        })
    }
}
