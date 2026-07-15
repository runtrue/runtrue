use super::*;

impl ControlPlane {
    pub fn record_runner_blob_upload(
        &self,
        request: &RecordRunnerBlobUpload,
        runner_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        for (field, value) in [
            ("ticket id", request.ticket_id.as_str()),
            ("ticket kind", request.ticket_kind.as_str()),
            ("execution lease id", request.execution_lease_id.as_str()),
            ("runner id", runner_id),
        ] {
            validate_text(field, value)?;
        }
        if !matches!(request.ticket_kind.as_str(), "cache" | "artifact")
            || request.fencing_generation == 0
            || request.job_attempt == 0
            || request.maximum_ticket_bytes == 0
            || request.size_bytes > request.maximum_ticket_bytes
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_active_runner_broker_lease_tx(
            &transaction,
            &request.execution_lease_id,
            runner_id,
            request.fencing_generation,
            request.recorded_unix_ms,
        )?;
        let existing: Option<(String, String, i64, i64, i64, i64)> = transaction
            .query_row(
                "SELECT ticket_kind, execution_lease_id, fencing_generation,
                        job_attempt, size_bytes, maximum_ticket_bytes
                 FROM runner_blob_uploads WHERE ticket_id = ?1 AND blob_digest = ?2",
                params![request.ticket_id, request.blob_digest.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some((kind, lease_id, fence, attempt, size, maximum)) = existing {
            if kind != request.ticket_kind
                || lease_id != request.execution_lease_id
                || from_i64("blob fencing generation", fence)? != request.fencing_generation
                || u32::try_from(from_i64("blob job attempt", attempt)?).ok()
                    != Some(request.job_attempt)
                || from_i64("blob size", size)? != request.size_bytes
                || from_i64("blob ticket byte bound", maximum)? != request.maximum_ticket_bytes
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            transaction.commit()?;
            return Ok(true);
        }
        let ticket_scope: Option<(String, String, i64, i64, i64)> = transaction
            .query_row(
                "SELECT ticket_kind, execution_lease_id, fencing_generation,
                        job_attempt, maximum_ticket_bytes
                 FROM runner_blob_uploads WHERE ticket_id = ?1 LIMIT 1",
                [&request.ticket_id],
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
        if let Some((kind, lease_id, fence, attempt, maximum)) = ticket_scope {
            if kind != request.ticket_kind
                || lease_id != request.execution_lease_id
                || from_i64("blob fencing generation", fence)? != request.fencing_generation
                || u32::try_from(from_i64("blob job attempt", attempt)?).ok()
                    != Some(request.job_attempt)
                || from_i64("blob ticket byte bound", maximum)? != request.maximum_ticket_bytes
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
        }
        let used: u64 = transaction.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM runner_blob_uploads WHERE ticket_id = ?1",
            [&request.ticket_id],
            |row| u64_column(row, 0, "ticket uploaded bytes"),
        )?;
        if used
            .checked_add(request.size_bytes)
            .is_none_or(|total| total > request.maximum_ticket_bytes)
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transaction.execute(
            "INSERT INTO runner_blob_uploads
             (ticket_id, blob_digest, ticket_kind, execution_lease_id,
              fencing_generation, job_attempt, size_bytes, maximum_ticket_bytes,
              recorded_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                request.ticket_id,
                request.blob_digest.as_str(),
                request.ticket_kind,
                request.execution_lease_id,
                to_i64(request.fencing_generation)?,
                i64::from(request.job_attempt),
                to_i64(request.size_bytes)?,
                to_i64(request.maximum_ticket_bytes)?,
                to_i64(request.recorded_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO runner_object_transfers
             (ticket_id, object_digest, ticket_kind, direction,
              execution_lease_id, fencing_generation, job_attempt,
              expected_size_bytes, transferred_size_bytes,
              maximum_ticket_bytes, state, reserved_unix_ms,
              updated_unix_ms, verified_unix_ms)
             VALUES (?1, ?2, ?3, 'upload', ?4, ?5, ?6, ?7, ?7, ?8,
                     'verified', ?9, ?9, ?9)",
            params![
                request.ticket_id,
                request.blob_digest.as_str(),
                request.ticket_kind,
                request.execution_lease_id,
                to_i64(request.fencing_generation)?,
                i64::from(request.job_attempt),
                to_i64(request.size_bytes)?,
                to_i64(request.maximum_ticket_bytes)?,
                to_i64(request.recorded_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    pub fn record_runner_blob_download(
        &self,
        request: &RecordRunnerBlobUpload,
        runner_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        if request.ticket_kind != "cache"
            || request.fencing_generation == 0
            || request.job_attempt == 0
            || request.maximum_ticket_bytes == 0
            || request.size_bytes > request.maximum_ticket_bytes
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_active_runner_broker_lease_tx(
            &transaction,
            &request.execution_lease_id,
            runner_id,
            request.fencing_generation,
            request.recorded_unix_ms,
        )?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO runner_object_transfers
             (ticket_id, object_digest, ticket_kind, direction,
              execution_lease_id, fencing_generation, job_attempt,
              expected_size_bytes, transferred_size_bytes,
              maximum_ticket_bytes, state, reserved_unix_ms,
              updated_unix_ms, verified_unix_ms)
             VALUES (?1, ?2, 'cache', 'download', ?3, ?4, ?5, ?6, ?6, ?7,
                     'verified', ?8, ?8, ?8)",
            params![
                request.ticket_id,
                request.blob_digest.as_str(),
                request.execution_lease_id,
                to_i64(request.fencing_generation)?,
                i64::from(request.job_attempt),
                to_i64(request.size_bytes)?,
                to_i64(request.maximum_ticket_bytes)?,
                to_i64(request.recorded_unix_ms)?,
            ],
        )?;
        let exact: bool = transaction.query_row(
            "SELECT ticket_kind = 'cache' AND execution_lease_id = ?3
                    AND fencing_generation = ?4 AND job_attempt = ?5
                    AND transferred_size_bytes = ?6 AND maximum_ticket_bytes = ?7
             FROM runner_object_transfers
             WHERE ticket_id = ?1 AND object_digest = ?2 AND direction = 'download'",
            params![
                request.ticket_id,
                request.blob_digest.as_str(),
                request.execution_lease_id,
                to_i64(request.fencing_generation)?,
                i64::from(request.job_attempt),
                to_i64(request.size_bytes)?,
                to_i64(request.maximum_ticket_bytes)?,
            ],
            |row| row.get(0),
        )?;
        if !exact {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transaction.commit()?;
        Ok(inserted == 0)
    }
}

impl ControlPlane {
    /// Journal an immutable cache/artifact claim before acknowledging its
    /// commit. Exact ticket retries replay; every subject substitution fails.
    pub fn record_runner_data_commit(
        &self,
        request: &RunnerDataCommit,
        runner_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        for (field, value) in [
            ("object id", request.object_id.as_str()),
            ("tenant id", request.tenant_id.as_str()),
            ("repository id", request.repository_id.as_str()),
            ("run id", request.run_id.as_str()),
            ("job id", request.job_id.as_str()),
            ("step id", request.step_id.as_str()),
            ("lease id", request.lease_id.as_str()),
            ("ticket id", request.ticket_id.as_str()),
            ("runner id", runner_id),
        ] {
            validate_text(field, value)?;
        }
        if request.job_attempt == 0 || request.fencing_generation == 0 {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        if let Some(name) = &request.output_name {
            validate_text("output name", name)?;
        }
        if request.kind == RunnerDataCommitKind::Artifact && request.output_name.is_none()
            || request.kind == RunnerDataCommitKind::Cache && request.output_name.is_some()
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_active_runner_broker_lease_tx(
            &transaction,
            &request.lease_id,
            runner_id,
            request.fencing_generation,
            request.committed_unix_ms,
        )?;
        let subject: Option<(String, String, String, u32)> = transaction
            .query_row(
                "SELECT l.tenant_id, r.repository_id, j.run_id, j.attempt
                 FROM leases l JOIN jobs j ON j.id = l.job_id
                 JOIN runs r ON r.id = j.run_id
                 WHERE l.id = ?1 AND l.job_id = ?2",
                params![request.lease_id, request.job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if subject.as_ref()
            != Some(&(
                request.tenant_id.clone(),
                request.repository_id.clone(),
                request.run_id.clone(),
                request.job_attempt,
            ))
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        #[allow(clippy::type_complexity)]
        let existing: Option<(
            String,
            String,
            String,
            String,
            String,
            i64,
            String,
            Option<String>,
            String,
            i64,
        )> = transaction
            .query_row(
                "SELECT kind, object_id, tenant_id, repository_id, run_id, job_attempt,
                        step_id, output_name, lease_id, fencing_generation
                 FROM runner_data_commits WHERE ticket_id = ?1",
                [&request.ticket_id],
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
        if let Some(existing) = existing {
            let matches = existing.0 == request.kind.as_str()
                && existing.1 == request.object_id
                && existing.2 == request.tenant_id
                && existing.3 == request.repository_id
                && existing.4 == request.run_id
                && u32::try_from(existing.5).ok() == Some(request.job_attempt)
                && existing.6 == request.step_id
                && existing.7 == request.output_name
                && existing.8 == request.lease_id
                && u64::try_from(existing.9).ok() == Some(request.fencing_generation);
            if !matches {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            transaction.commit()?;
            return Ok(true);
        }
        transaction.execute(
            "INSERT INTO runner_data_commits
             (kind, object_id, tenant_id, repository_id, run_id, job_id, job_attempt,
              step_id, output_name, lease_id, fencing_generation, ticket_id, committed_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                request.kind.as_str(),
                request.object_id,
                request.tenant_id,
                request.repository_id,
                request.run_id,
                request.job_id,
                i64::from(request.job_attempt),
                request.step_id,
                request.output_name,
                request.lease_id,
                to_i64(request.fencing_generation)?,
                request.ticket_id,
                to_i64(request.committed_unix_ms)?
            ],
        )?;
        append_runner_broker_audit_tx(
            &transaction,
            &self.installation_id,
            &request.tenant_id,
            runner_id,
            "runner.data.commit",
            "runner_data_commit",
            &request.ticket_id,
            request.committed_unix_ms,
            BTreeMap::from([
                (
                    "kind".to_owned(),
                    AuditValue::String(request.kind.as_str().to_owned()),
                ),
                (
                    "lease_id".to_owned(),
                    AuditValue::String(request.lease_id.clone()),
                ),
                (
                    "job_attempt".to_owned(),
                    AuditValue::Integer(i64::from(request.job_attempt)),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(false)
    }
}
