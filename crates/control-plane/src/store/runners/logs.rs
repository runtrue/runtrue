use super::*;

impl ControlPlane {
    pub fn runner_log_frame_count_for_lease(
        &self,
        execution_lease_id: &str,
    ) -> Result<u64, ControlPlaneError> {
        validate_text("execution lease id", execution_lease_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT COUNT(*) FROM runner_log_frames WHERE execution_lease_id = ?1",
                [execution_lease_id],
                |row| u64_column(row, 0, "runner log frame count"),
            )
            .map_err(Into::into)
    }

    pub fn append_runner_logs(
        &self,
        request: &AppendRunnerLogsRequest,
        now_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        validate_text("execution lease id", &request.execution_lease_id)?;
        validate_text("runner id", &request.runner_id)?;
        if request.fencing_generation == 0
            || request.frames.is_empty()
            || request.frames.len() > 256
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = validate_active_runner_broker_lease_tx(
            &transaction,
            &request.execution_lease_id,
            &request.runner_id,
            request.fencing_generation,
            now_unix_ms,
        )?;
        for frame in &request.frames {
            if frame.execution_lease_id != lease.id
                || frame.fencing_generation != lease.fencing_generation
                || frame.job_attempt == 0
                || frame.payload.len() > 64 * 1024
                || !matches!(frame.stream.as_str(), "stdout" | "stderr")
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            validate_text("step id", &frame.step_id)?;
            validate_text("redaction state", &frame.redaction_state)?;
            let next: u64 = transaction.query_row(
                "SELECT COALESCE(MAX(sequence) + 1, 0) FROM runner_log_frames
                 WHERE execution_lease_id = ?1 AND job_attempt = ?2
                   AND step_id = ?3 AND stream = ?4",
                params![
                    frame.execution_lease_id,
                    i64::from(frame.job_attempt),
                    frame.step_id,
                    frame.stream,
                ],
                |row| u64_column(row, 0, "runner log sequence"),
            )?;
            if frame.sequence != next {
                return Err(ControlPlaneError::RunnerBrokerReplay);
            }
            transaction.execute(
                "INSERT INTO runner_log_frames
                 (execution_lease_id, fencing_generation, job_attempt, step_id,
                  stream, sequence, monotonic_nanoseconds, wall_time_unix_ms,
                  payload, redaction_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    frame.execution_lease_id,
                    to_i64(frame.fencing_generation)?,
                    i64::from(frame.job_attempt),
                    frame.step_id,
                    frame.stream,
                    to_i64(frame.sequence)?,
                    to_i64(frame.monotonic_nanoseconds)?,
                    to_i64(frame.wall_time_unix_ms)?,
                    frame.payload,
                    frame.redaction_state,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn runner_logs_for_run(
        &self,
        run_id: &str,
        maximum_frames: usize,
    ) -> Result<Vec<RunnerLogFrameRecord>, ControlPlaneError> {
        validate_text("run id", run_id)?;
        if maximum_frames == 0 || maximum_frames > 10_000 {
            return Err(ControlPlaneError::InvalidInput(
                "runner log query limit must be between 1 and 10000",
            ));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT f.execution_lease_id, f.fencing_generation, f.job_attempt,
                    f.step_id, f.stream, f.sequence, f.monotonic_nanoseconds,
                    f.wall_time_unix_ms, f.payload, f.redaction_state
             FROM runner_log_frames f
             JOIN leases l ON l.id = f.execution_lease_id
             JOIN jobs j ON j.id = l.job_id
             WHERE j.run_id = ?1
               AND l.state = 'completed'
               AND (l.terminal_credential_taint = 'none'
                    OR f.redaction_state = 'credential_taint_unredacted_operator_opt_in')
             ORDER BY f.wall_time_unix_ms, f.execution_lease_id, f.job_attempt,
                      f.step_id, f.stream, f.sequence
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![run_id, to_i64(maximum_frames as u64)?], |row| {
            Ok(RunnerLogFrameRecord {
                execution_lease_id: row.get(0)?,
                fencing_generation: u64_column(row, 1, "fencing_generation")?,
                job_attempt: row.get(2)?,
                step_id: row.get(3)?,
                stream: row.get(4)?,
                sequence: u64_column(row, 5, "sequence")?,
                monotonic_nanoseconds: u64_column(row, 6, "monotonic_nanoseconds")?,
                wall_time_unix_ms: u64_column(row, 7, "wall_time_unix_ms")?,
                payload: row.get(8)?,
                redaction_state: row.get(9)?,
            })
        })?;
        rows.collect::<rusqlite::Result<_>>().map_err(Into::into)
    }
}
