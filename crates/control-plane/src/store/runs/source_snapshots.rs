use super::*;
use rusqlite::params;

pub(in crate::store) fn source_snapshot_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    snapshot_id: &str,
) -> Result<SourceSnapshotRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, repository_id, commit_sha, tree_manifest_digest,
                    state, created_unix_ms, verified_unix_ms
             FROM source_snapshots WHERE id = ?1 AND tenant_id = ?2",
            params![snapshot_id, tenant_id],
            source_snapshot_row,
        )
        .optional()?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "source snapshot",
            id: snapshot_id.to_owned(),
        })
}

pub(in crate::store) fn source_snapshot_conn(
    connection: &Connection,
    tenant_id: &str,
    snapshot_id: &str,
) -> Result<SourceSnapshotRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, tenant_id, repository_id, commit_sha, tree_manifest_digest,
                    state, created_unix_ms, verified_unix_ms
             FROM source_snapshots WHERE id = ?1 AND tenant_id = ?2",
            params![snapshot_id, tenant_id],
            source_snapshot_row,
        )
        .optional()?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "source snapshot",
            id: snapshot_id.to_owned(),
        })
}

pub(in crate::store) fn source_snapshot_row(
    row: &Row<'_>,
) -> rusqlite::Result<SourceSnapshotRecord> {
    let digest: String = row.get(4)?;
    let state: String = row.get(5)?;
    Ok(SourceSnapshotRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        commit_sha: row.get(3)?,
        tree_manifest_digest: ContentDigest::parse(digest).map_err(|error| conversion(4, error))?,
        state: match state.as_str() {
            "building" => SourceSnapshotState::Building,
            "ready" => SourceSnapshotState::Ready,
            "failed" => SourceSnapshotState::Failed,
            "retired" => SourceSnapshotState::Retired,
            _ => {
                return Err(conversion(
                    5,
                    DecodeError(format!("unknown source snapshot state `{state}`")),
                ))
            }
        },
        created_unix_ms: from_i64("created_unix_ms", row.get(6)?)
            .map_err(|error| conversion(6, error))?,
        verified_unix_ms: row
            .get::<_, Option<i64>>(7)?
            .map(|value| from_i64("verified_unix_ms", value).map_err(|error| conversion(7, error)))
            .transpose()?,
    })
}

pub(in crate::store) fn run_source_snapshot_row(
    row: &Row<'_>,
) -> rusqlite::Result<RunSourceSnapshotRecord> {
    let digest: String = row.get(2)?;
    Ok(RunSourceSnapshotRecord {
        run_id: row.get(0)?,
        source_snapshot_id: row.get(1)?,
        capsule_digest: ContentDigest::parse(digest).map_err(|error| conversion(2, error))?,
        bound_unix_ms: from_i64("bound_unix_ms", row.get(3)?)
            .map_err(|error| conversion(3, error))?,
    })
}

pub(in crate::store) fn runner_source_ticket_row(
    row: &Row<'_>,
) -> rusqlite::Result<RunnerSourceTicketRecord> {
    let digest: String = row.get(8)?;
    Ok(RunnerSourceTicketRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        runner_id: row.get(2)?,
        execution_lease_id: row.get(3)?,
        fencing_generation: u64_column(row, 4, "fencing_generation")?,
        job_id: row.get(5)?,
        job_attempt: row.get(6)?,
        source_snapshot_id: row.get(7)?,
        tree_manifest_digest: ContentDigest::parse(digest).map_err(|error| conversion(8, error))?,
        maximum_bytes: u64_column(row, 9, "maximum_bytes")?,
        issued_unix_ms: u64_column(row, 10, "issued_unix_ms")?,
        expires_unix_ms: u64_column(row, 11, "expires_unix_ms")?,
    })
}

impl ControlPlane {
    pub fn run(&self, id: &str) -> Result<RunRecord, ControlPlaneError> {
        let connection = self.connection()?;
        run_conn(&connection, id)
    }

    pub fn create_source_snapshot(
        &self,
        snapshot: &SourceSnapshotRecord,
    ) -> Result<IdempotentResult<SourceSnapshotRecord>, ControlPlaneError> {
        for (field, value) in [
            ("source snapshot id", snapshot.id.as_str()),
            ("tenant id", snapshot.tenant_id.as_str()),
            ("repository id", snapshot.repository_id.as_str()),
            ("source commit", snapshot.commit_sha.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if snapshot.state != SourceSnapshotState::Building || snapshot.verified_unix_ms.is_some() {
            return Err(ControlPlaneError::InvalidInput(
                "new source snapshot must be building",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let repository_tenant: Option<String> = transaction
            .query_row(
                "SELECT tenant_id FROM repositories WHERE id = ?1 AND tenant_id = ?2",
                params![snapshot.repository_id, snapshot.tenant_id],
                |row| row.get(0),
            )
            .optional()?;
        if repository_tenant.is_none() {
            return Err(ControlPlaneError::NotFound {
                kind: "repository",
                id: snapshot.repository_id.clone(),
            });
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO source_snapshots
             (id, tenant_id, repository_id, commit_sha, tree_manifest_digest, state,
              created_unix_ms, verified_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'building', ?6, NULL)",
            params![
                snapshot.id,
                snapshot.tenant_id,
                snapshot.repository_id,
                snapshot.commit_sha,
                snapshot.tree_manifest_digest.as_str(),
                to_i64(snapshot.created_unix_ms)?,
            ],
        )?;
        let existing = source_snapshot_tx(&transaction, &snapshot.tenant_id, &snapshot.id)?;
        if existing != *snapshot {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value: existing,
            replayed: inserted == 0,
        })
    }

    pub fn source_snapshot(
        &self,
        tenant_id: &str,
        snapshot_id: &str,
    ) -> Result<SourceSnapshotRecord, ControlPlaneError> {
        let connection = self.connection()?;
        source_snapshot_conn(&connection, tenant_id, snapshot_id)
    }

    pub fn mark_source_snapshot_ready(
        &self,
        tenant_id: &str,
        snapshot_id: &str,
        manifest_digest: &ContentDigest,
        verified_unix_ms: u64,
    ) -> Result<SourceSnapshotRecord, ControlPlaneError> {
        validate_text("tenant id", tenant_id)?;
        validate_text("source snapshot id", snapshot_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let current = source_snapshot_tx(&transaction, tenant_id, snapshot_id)?;
        if &current.tree_manifest_digest != manifest_digest {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        match current.state {
            SourceSnapshotState::Building => {
                transaction.execute(
                    "UPDATE source_snapshots SET state = 'ready', verified_unix_ms = ?3
                     WHERE id = ?1 AND tenant_id = ?2 AND state = 'building'",
                    params![snapshot_id, tenant_id, to_i64(verified_unix_ms)?],
                )?;
            }
            SourceSnapshotState::Ready if current.verified_unix_ms == Some(verified_unix_ms) => {}
            _ => return Err(ControlPlaneError::IdempotencyConflict),
        }
        let ready = source_snapshot_tx(&transaction, tenant_id, snapshot_id)?;
        transaction.commit()?;
        Ok(ready)
    }

    pub fn bind_run_source_snapshot(
        &self,
        tenant_id: &str,
        run_id: &str,
        snapshot_id: &str,
        capsule_digest: &ContentDigest,
        bound_unix_ms: u64,
    ) -> Result<IdempotentResult<RunSourceSnapshotRecord>, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let binding: Option<(Vec<u8>, String, String)> = transaction
            .query_row(
                "SELECT p.canonical_capsule, s.tree_manifest_digest, s.commit_sha FROM runs r
                JOIN repositories repo ON repo.id = r.repository_id
                JOIN capsules p ON p.id = r.capsule_id
                JOIN source_snapshots s ON s.id = ?3
                WHERE r.id = ?1 AND repo.tenant_id = ?2 AND s.tenant_id = ?2
                  AND s.repository_id = r.repository_id AND s.state = 'ready'
                  AND p.digest = ?4",
                params![run_id, tenant_id, snapshot_id, capsule_digest.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((canonical_capsule, snapshot_digest, snapshot_commit)) = binding else {
            return Err(ControlPlaneError::NotFound {
                kind: "ready run source snapshot",
                id: snapshot_id.to_owned(),
            });
        };
        let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
        if capsule
            .context
            .source_tree_digest
            .as_ref()
            .map(ContentDigest::as_str)
            != Some(snapshot_digest.as_str())
            || capsule.context.source_commit != snapshot_commit
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO run_source_snapshots
             (run_id, source_snapshot_id, capsule_digest, bound_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            params![
                run_id,
                snapshot_id,
                capsule_digest.as_str(),
                to_i64(bound_unix_ms)?
            ],
        )?;
        let record = transaction.query_row(
            "SELECT run_id, source_snapshot_id, capsule_digest, bound_unix_ms
             FROM run_source_snapshots WHERE run_id = ?1",
            [run_id],
            run_source_snapshot_row,
        )?;
        if record.source_snapshot_id != snapshot_id || record.capsule_digest != *capsule_digest {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        queue_source_ready_roots_tx(&transaction, run_id, &capsule)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record,
            replayed: inserted == 0,
        })
    }

    pub fn run_source_snapshot(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<RunSourceSnapshotRecord, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT rss.run_id, rss.source_snapshot_id, rss.capsule_digest, rss.bound_unix_ms
                 FROM run_source_snapshots rss
                 JOIN runs r ON r.id = rss.run_id
                 JOIN repositories repo ON repo.id = r.repository_id
                 WHERE rss.run_id = ?1 AND repo.tenant_id = ?2",
                params![run_id, tenant_id],
                run_source_snapshot_row,
            )
            .optional()?
            .ok_or_else(|| not_found("run source snapshot", run_id))
    }

    pub fn issue_runner_source_ticket(
        &self,
        request: &IssueRunnerSourceTicket,
    ) -> Result<IdempotentResult<RunnerSourceTicketRecord>, ControlPlaneError> {
        if request.maximum_bytes == 0 || request.expires_unix_ms <= request.issued_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "invalid source ticket bounds",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let lease = validate_active_runner_broker_lease_tx(
            &transaction,
            &request.execution_lease_id,
            &request.runner_id,
            request.fencing_generation,
            request.issued_unix_ms,
        )?;
        if lease.job_id != request.job_id {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let binding: Option<(String, String)> = transaction
            .query_row(
                "SELECT rss.source_snapshot_id, s.tree_manifest_digest
                 FROM jobs j
                 JOIN runs r ON r.id = j.run_id
                 JOIN repositories repo ON repo.id = r.repository_id
                 JOIN run_source_snapshots rss ON rss.run_id = r.id
                 JOIN source_snapshots s ON s.id = rss.source_snapshot_id
                 WHERE j.id = ?1 AND j.attempt = ?2 AND repo.tenant_id = ?3
                   AND s.tenant_id = ?3 AND s.state = 'ready'",
                params![request.job_id, request.job_attempt, request.tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((snapshot_id, tree_digest)) = binding else {
            return Err(ControlPlaneError::NotFound {
                kind: "ready run source snapshot",
                id: request.job_id.clone(),
            });
        };
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO runner_source_tickets
             (id, tenant_id, runner_id, execution_lease_id, fencing_generation,
              job_id, job_attempt, source_snapshot_id, tree_manifest_digest,
              maximum_bytes, issued_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                request.id,
                request.tenant_id,
                request.runner_id,
                request.execution_lease_id,
                to_i64(request.fencing_generation)?,
                request.job_id,
                i64::from(request.job_attempt),
                snapshot_id,
                tree_digest,
                to_i64(request.maximum_bytes)?,
                to_i64(request.issued_unix_ms)?,
                to_i64(request.expires_unix_ms)?,
            ],
        )?;
        let record = transaction.query_row(
            "SELECT id, tenant_id, runner_id, execution_lease_id, fencing_generation,
                    job_id, job_attempt, source_snapshot_id, tree_manifest_digest,
                    maximum_bytes, issued_unix_ms, expires_unix_ms
             FROM runner_source_tickets WHERE id = ?1",
            [&request.id],
            runner_source_ticket_row,
        )?;
        let expected = RunnerSourceTicketRecord {
            id: request.id.clone(),
            tenant_id: request.tenant_id.clone(),
            runner_id: request.runner_id.clone(),
            execution_lease_id: request.execution_lease_id.clone(),
            fencing_generation: request.fencing_generation,
            job_id: request.job_id.clone(),
            job_attempt: request.job_attempt,
            source_snapshot_id: snapshot_id,
            tree_manifest_digest: ContentDigest::parse(tree_digest)?,
            maximum_bytes: request.maximum_bytes,
            issued_unix_ms: request.issued_unix_ms,
            expires_unix_ms: request.expires_unix_ms,
        };
        if record != expected {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record,
            replayed: inserted == 0,
        })
    }

    pub fn runner_source_ticket(
        &self,
        ticket_id: &str,
    ) -> Result<RunnerSourceTicketRecord, ControlPlaneError> {
        validate_text("source ticket id", ticket_id)?;
        self.connection()?
            .query_row(
                "SELECT id, tenant_id, runner_id, execution_lease_id, fencing_generation,
                    job_id, job_attempt, source_snapshot_id, tree_manifest_digest,
                    maximum_bytes, issued_unix_ms, expires_unix_ms
             FROM runner_source_tickets WHERE id = ?1",
                [ticket_id],
                runner_source_ticket_row,
            )
            .map_err(|error| map_not_found(error, "runner source ticket", ticket_id))
    }

    /// Reserve a source object download before any bytes are released. Exact
    /// retries reuse the same row; substitutions and aggregate quota overflow
    /// fail while the active lease is still fenced.
    pub fn begin_runner_source_download(
        &self,
        request: &RunnerSourceDownload,
    ) -> Result<bool, ControlPlaneError> {
        if request.job_attempt == 0 || request.fencing_generation == 0 {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_active_runner_broker_lease_tx(
            &transaction,
            &request.execution_lease_id,
            &request.runner_id,
            request.fencing_generation,
            request.recorded_unix_ms,
        )?;
        let ticket: RunnerSourceTicketRecord = transaction
            .query_row(
                "SELECT id, tenant_id, runner_id, execution_lease_id, fencing_generation,
                    job_id, job_attempt, source_snapshot_id, tree_manifest_digest,
                    maximum_bytes, issued_unix_ms, expires_unix_ms
             FROM runner_source_tickets WHERE id = ?1",
                [&request.ticket_id],
                runner_source_ticket_row,
            )
            .map_err(|error| map_not_found(error, "runner source ticket", &request.ticket_id))?;
        if ticket.runner_id != request.runner_id
            || ticket.execution_lease_id != request.execution_lease_id
            || ticket.fencing_generation != request.fencing_generation
            || ticket.job_id != request.job_id
            || ticket.job_attempt != request.job_attempt
            || ticket.expires_unix_ms <= request.recorded_unix_ms
            || request.size_bytes > ticket.maximum_bytes
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let existing: Option<(i64, i64, String)> = transaction
            .query_row(
                "SELECT expected_size_bytes, maximum_ticket_bytes, state
             FROM runner_object_transfers
             WHERE ticket_id = ?1 AND object_digest = ?2 AND direction = 'download'",
                params![request.ticket_id, request.object_digest.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((size, maximum, state)) = existing {
            if from_i64("source object size", size)? != request.size_bytes
                || from_i64("source ticket maximum", maximum)? != ticket.maximum_bytes
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            transaction.execute(
                "UPDATE runner_object_transfers SET state = 'transferring', updated_unix_ms = ?3,
                        transferred_size_bytes = 0, verified_unix_ms = NULL
                 WHERE ticket_id = ?1 AND object_digest = ?2 AND direction = 'download'
                   AND state != 'verified'",
                params![
                    request.ticket_id,
                    request.object_digest.as_str(),
                    to_i64(request.recorded_unix_ms)?
                ],
            )?;
            transaction.commit()?;
            return Ok(state == "verified");
        }
        let reserved: u64 = transaction.query_row(
            "SELECT COALESCE(SUM(expected_size_bytes), 0) FROM runner_object_transfers
             WHERE ticket_id = ?1 AND direction = 'download'",
            [&request.ticket_id],
            |row| u64_column(row, 0, "source reserved bytes"),
        )?;
        if reserved
            .checked_add(request.size_bytes)
            .is_none_or(|sum| sum > ticket.maximum_bytes)
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transaction.execute(
            "INSERT INTO runner_object_transfers
             (ticket_id, object_digest, ticket_kind, direction, execution_lease_id,
              fencing_generation, job_attempt, expected_size_bytes, transferred_size_bytes,
              maximum_ticket_bytes, state, reserved_unix_ms, updated_unix_ms, verified_unix_ms)
             VALUES (?1, ?2, 'source', 'download', ?3, ?4, ?5, ?6, 0, ?7,
                     'transferring', ?8, ?8, NULL)",
            params![
                request.ticket_id,
                request.object_digest.as_str(),
                request.execution_lease_id,
                to_i64(request.fencing_generation)?,
                i64::from(request.job_attempt),
                to_i64(request.size_bytes)?,
                to_i64(ticket.maximum_bytes)?,
                to_i64(request.recorded_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    pub fn finish_runner_source_download(
        &self,
        request: &RunnerSourceDownload,
    ) -> Result<(), ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_active_runner_broker_lease_tx(
            &transaction,
            &request.execution_lease_id,
            &request.runner_id,
            request.fencing_generation,
            request.recorded_unix_ms,
        )?;
        let changed = transaction.execute(
            "UPDATE runner_object_transfers SET state = 'verified', transferred_size_bytes = ?3,
                    updated_unix_ms = ?4, verified_unix_ms = ?4
             WHERE ticket_id = ?1 AND object_digest = ?2 AND direction = 'download'
               AND ticket_kind = 'source' AND expected_size_bytes = ?3
               AND execution_lease_id = ?5 AND fencing_generation = ?6 AND job_attempt = ?7
               AND state IN ('transferring','verified')",
            params![
                request.ticket_id,
                request.object_digest.as_str(),
                to_i64(request.size_bytes)?,
                to_i64(request.recorded_unix_ms)?,
                request.execution_lease_id,
                to_i64(request.fencing_generation)?,
                i64::from(request.job_attempt)
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transaction.commit()?;
        Ok(())
    }
}
