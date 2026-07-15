use super::*;

impl ControlPlane {
    pub fn create_backup_pin(&self, pin: &BackupPinRecord) -> Result<bool, ControlPlaneError> {
        validate_backup_pin(pin)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT id, tenant_id, root_kind, root_id, object_digest,
                        created_unix_ms, expires_unix_ms, released_unix_ms
                 FROM backup_pins WHERE id = ?1",
                [&pin.id],
                backup_pin_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *pin {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO backup_pins
             (id, tenant_id, root_kind, root_id, object_digest, created_unix_ms,
              expires_unix_ms, released_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            params![
                pin.id,
                pin.tenant_id,
                pin.root_kind,
                pin.root_id,
                pin.object_digest.as_str(),
                to_i64(pin.created_unix_ms)?,
                pin.expires_unix_ms.map(to_i64).transpose()?,
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    /// Acquire the installation-wide maintenance fence. A matching token
    /// resumes an interrupted cycle; another owner can proceed only after expiry.
    pub fn acquire_lifecycle_gc(
        &self,
        worker_id: &str,
        lease_token: &str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<LifecycleGcLease, ControlPlaneError> {
        validate_text("GC worker", worker_id)?;
        validate_text("GC lease token", lease_token)?;
        if lease_duration_ms == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "GC lease duration must be positive",
            ));
        }
        let expires =
            now_unix_ms
                .checked_add(lease_duration_ms)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "GC lease expiry",
                })?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: (u64, String, Option<String>, Option<String>, Option<u64>) = transaction
            .query_row(
                "SELECT current_generation, phase, lease_owner, lease_token,
                        lease_expires_unix_ms FROM lifecycle_gc_control WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        u64_column(row, 0, "GC generation")?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        optional_u64_column(row, 4, "GC lease expiry")?,
                    ))
                },
            )?;
        if current.1 != "idle" {
            if current.2.as_deref() == Some(worker_id)
                && current.3.as_deref() == Some(lease_token)
                && current.4.is_some_and(|expiry| expiry > now_unix_ms)
            {
                transaction.execute(
                    "UPDATE lifecycle_gc_control
                     SET lease_expires_unix_ms = ?2, updated_unix_ms = ?3
                     WHERE singleton = 1 AND lease_token = ?1",
                    params![lease_token, to_i64(expires)?, to_i64(now_unix_ms)?],
                )?;
                transaction.commit()?;
                return Ok(LifecycleGcLease {
                    generation: current.0,
                    phase: current.1,
                    lease_owner: worker_id.to_owned(),
                    lease_token: lease_token.to_owned(),
                    expires_unix_ms: expires,
                });
            }
            if current.4.is_some_and(|expiry| expiry > now_unix_ms) {
                return Err(ControlPlaneError::LifecycleGcLeaseBusy);
            }
            transaction.execute(
                "UPDATE lifecycle_gc_cycles SET state = 'failed', completed_unix_ms = ?2
                 WHERE generation = ?1 AND state IN ('marking','sweeping')",
                params![to_i64(current.0)?, to_i64(now_unix_ms)?],
            )?;
        }
        let generation = current
            .0
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "GC generation",
            })?;
        transaction.execute(
            "UPDATE lifecycle_gc_control SET current_generation = ?1, phase = 'marking',
                    lease_owner = ?2, lease_token = ?3, lease_expires_unix_ms = ?4,
                    updated_unix_ms = ?5 WHERE singleton = 1",
            params![
                to_i64(generation)?,
                worker_id,
                lease_token,
                to_i64(expires)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO lifecycle_gc_cycles
             (generation, lease_token, started_unix_ms, state)
             VALUES (?1, ?2, ?3, 'marking')",
            params![to_i64(generation)?, lease_token, to_i64(now_unix_ms)?,],
        )?;
        transaction.commit()?;
        Ok(LifecycleGcLease {
            generation,
            phase: "marking".to_owned(),
            lease_owner: worker_id.to_owned(),
            lease_token: lease_token.to_owned(),
            expires_unix_ms: expires,
        })
    }

    /// Retire only artifacts whose retention elapsed and which are not under
    /// legal hold. The bounded batch runs before a mark generation so catalog
    /// state cannot continue advertising bytes selected for sweep.
    pub fn retire_expired_artifacts(
        &self,
        now_unix_ms: u64,
        maximum_artifacts: usize,
    ) -> Result<usize, ControlPlaneError> {
        if maximum_artifacts == 0 || maximum_artifacts > 100_000 {
            return Err(ControlPlaneError::InvalidInput(
                "artifact retirement bound is invalid",
            ));
        }
        let now_seconds = now_unix_ms / 1_000;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ids = {
            let mut statement = transaction.prepare(
                "SELECT artifact_id FROM artifacts_catalog
                 WHERE state != 'retired' AND legal_hold = 0
                   AND retention_until_unix_seconds <= ?1
                 ORDER BY retention_until_unix_seconds, artifact_id LIMIT ?2",
            )?;
            let values = statement
                .query_map(
                    params![to_i64(now_seconds)?, to_i64(maximum_artifacts as u64)?],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            values
        };
        for id in &ids {
            transaction.execute(
                "UPDATE artifacts_catalog SET state = 'retired'
                 WHERE artifact_id = ?1 AND legal_hold = 0
                   AND retention_until_unix_seconds <= ?2 AND state != 'retired'",
                params![id, to_i64(now_seconds)?],
            )?;
            transaction.execute(
                "UPDATE tenant_storage_objects
                 SET state = 'retired', retired_unix_ms = ?2
                 WHERE object_kind = 'artifact' AND object_id = ?1
                   AND state = 'active'",
                params![id, to_i64(now_unix_ms)?],
            )?;
        }
        if !ids.is_empty() {
            let mut metadata = BTreeMap::new();
            metadata.insert(
                "retired_artifacts".to_owned(),
                AuditValue::Integer(to_i64(ids.len() as u64)?),
            );
            append_audit_event_tx(
                &transaction,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: now_unix_ms,
                    tenant_id: "installation".to_owned(),
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: "output-lifecycle".to_owned(),
                    },
                    action: "artifact.retire".to_owned(),
                    resource: AuditResource {
                        kind: "artifact-catalog".to_owned(),
                        id: "retention-batch".to_owned(),
                    },
                    result: "completed".to_owned(),
                    request_id: format!("artifact-retention-{now_unix_ms}"),
                    decision_id: None,
                    metadata,
                },
            )?;
        }
        transaction.commit()?;
        Ok(ids.len())
    }

    pub fn prune_lifecycle_ledgers(
        &self,
        now_unix_ms: u64,
        retention_ms: u64,
        maximum_rows_per_table: usize,
    ) -> Result<LifecyclePruneSummary, ControlPlaneError> {
        if retention_ms == 0 || maximum_rows_per_table == 0 || maximum_rows_per_table > 100_000 {
            return Err(ControlPlaneError::InvalidInput(
                "lifecycle ledger retention bound is invalid",
            ));
        }
        let cutoff = now_unix_ms.saturating_sub(retention_ms);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let limit = to_i64(maximum_rows_per_table as u64)?;
        let storage_reservations = transaction.execute(
            "UPDATE tenant_storage_reservations SET state = 'expired', completed_unix_ms = ?1
             WHERE rowid IN (
               SELECT rowid FROM tenant_storage_reservations
                WHERE state = 'reserved' AND expires_unix_ms <= ?1
                ORDER BY expires_unix_ms LIMIT ?2
             )",
            params![to_i64(now_unix_ms)?, limit],
        )?;
        transaction.execute(
            "UPDATE tenant_storage_ticket_bindings
             SET state = 'released', updated_unix_ms = ?1, completed_unix_ms = ?1
             WHERE reservation_id IN (
               SELECT id FROM tenant_storage_reservations WHERE state = 'expired'
             ) AND state = 'issued'",
            [to_i64(now_unix_ms)?],
        )?;
        let download_tickets = transaction.execute(
            "DELETE FROM artifact_download_tickets WHERE rowid IN (
               SELECT rowid FROM artifact_download_tickets
                WHERE expires_unix_ms <= ?1 AND (used_unix_ms IS NULL OR used_unix_ms <= ?1)
                ORDER BY expires_unix_ms LIMIT ?2
             )",
            params![to_i64(cutoff)?, limit],
        )?;
        let object_transfers = transaction.execute(
            "DELETE FROM runner_object_transfers WHERE rowid IN (
               SELECT rowid FROM runner_object_transfers
                WHERE state IN ('committed','abandoned') AND updated_unix_ms <= ?1
                ORDER BY updated_unix_ms LIMIT ?2
             )",
            params![to_i64(cutoff)?, limit],
        )?;
        let cache_observations = transaction.execute(
            "DELETE FROM cache_access_observations WHERE rowid IN (
               SELECT rowid FROM cache_access_observations
                WHERE created_unix_ms <= ?1 ORDER BY created_unix_ms LIMIT ?2
             )",
            params![to_i64(cutoff)?, limit],
        )?;
        let log_frames = transaction.execute(
            "DELETE FROM runner_log_frames WHERE rowid IN (
               SELECT f.rowid FROM runner_log_frames f
               JOIN leases l ON l.id = f.execution_lease_id
                WHERE l.state IN ('completed','rejected','expired')
                  AND f.wall_time_unix_ms <= ?1
                ORDER BY f.wall_time_unix_ms LIMIT ?2
             )",
            params![to_i64(cutoff)?, limit],
        )?;
        transaction.commit()?;
        Ok(LifecyclePruneSummary {
            storage_reservations: storage_reservations as u64,
            download_tickets: download_tickets as u64,
            object_transfers: object_transfers as u64,
            cache_observations: cache_observations as u64,
            log_frames: log_frames as u64,
        })
    }

    /// Resolve durable root identities. This deliberately returns digest-only
    /// metadata; graph expansion and object verification happen in the bounded
    /// out-of-process lifecycle worker.
    pub fn lifecycle_gc_roots(
        &self,
        lease: &LifecycleGcLease,
        now_unix_ms: u64,
        maximum_roots: usize,
    ) -> Result<Vec<LifecycleGcRoot>, ControlPlaneError> {
        if maximum_roots == 0 || maximum_roots > 1_000_000 {
            return Err(ControlPlaneError::InvalidInput("GC root bound is invalid"));
        }
        let connection = self.connection()?;
        verify_gc_lease(&connection, lease, now_unix_ms, "marking")?;
        let now_seconds = now_unix_ms / 1_000;
        let sql = "
            SELECT g.manifest_digest, 'cache-manifest', g.cache_entry_id
              FROM cache_trust_current_heads h
              JOIN cache_trust_generations g ON g.cache_entry_id = h.cache_entry_id
            UNION ALL
            SELECT g.tree_manifest_digest, 'cache-tree', g.cache_entry_id
              FROM cache_trust_current_heads h
              JOIN cache_trust_generations g ON g.cache_entry_id = h.cache_entry_id
            UNION ALL
            SELECT a.artifact_id, 'artifact-record', a.artifact_id
              FROM artifacts_catalog a
             WHERE a.state != 'retired'
               AND (a.legal_hold = 1 OR a.retention_until_unix_seconds > ?1)
            UNION ALL
            SELECT t.object_digest, 'pending-transfer', t.ticket_id
              FROM runner_object_transfers t
             WHERE t.state IN ('reserved','transferring','verified')
               AND t.object_digest IS NOT NULL
            UNION ALL
            SELECT c.object_id, 'artifact-pending-commit', c.ticket_id
              FROM runner_data_commits c
              LEFT JOIN job_result_objects o
                ON o.kind = c.kind AND o.object_id = c.object_id
             WHERE o.object_id IS NULL AND c.kind = 'artifact'
            UNION ALL
            SELECT g.manifest_digest, 'cache-manifest', c.ticket_id
              FROM runner_data_commits c
              JOIN cache_trust_generations g ON g.cache_entry_id = c.object_id
              LEFT JOIN job_result_objects o
                ON o.kind = c.kind AND o.object_id = c.object_id
             WHERE o.object_id IS NULL AND c.kind = 'cache'
            UNION ALL
            SELECT p.evidence_digest, 'cache-promotion-evidence', p.id
              FROM cache_promotion_journal p WHERE p.state = 'pending'
            UNION ALL
            SELECT g.tree_manifest_digest, 'cache-promotion-source', p.id
              FROM cache_promotion_journal p
              JOIN cache_trust_generations g
                ON g.cache_entry_id = p.source_cache_entry_id
             WHERE p.state = 'pending'
            UNION ALL
            SELECT a.artifact_id, 'artifact-promotion-source', p.id
              FROM artifact_promotions p
              JOIN artifacts_catalog a ON a.artifact_id = p.source_artifact_id
             WHERE p.status = 'pending'
            UNION ALL
            SELECT p.evidence_digest, 'artifact-promotion-evidence', p.id
              FROM artifact_promotions p
              JOIN artifacts_catalog a ON a.artifact_id = p.source_artifact_id
             WHERE a.state != 'retired'
               AND (a.legal_hold = 1 OR a.retention_until_unix_seconds > ?1)
            UNION ALL
            SELECT p.promoted_artifact_id, 'artifact-promoted-record', p.id
              FROM artifact_promotions p
              JOIN artifacts_catalog a ON a.artifact_id = p.source_artifact_id
             WHERE p.status = 'succeeded' AND p.promoted_artifact_id IS NOT NULL
               AND a.state != 'retired'
               AND (a.legal_hold = 1 OR a.retention_until_unix_seconds > ?1)
            UNION ALL
            SELECT s.tree_manifest_digest, 'source-snapshot', s.id
              FROM source_snapshots s
             WHERE s.state = 'ready'
               AND EXISTS(SELECT 1 FROM run_source_snapshots r WHERE r.source_snapshot_id = s.id)
            UNION ALL
            SELECT b.object_digest,
                   CASE b.root_kind
                     WHEN 'artifact' THEN 'artifact-record'
                     WHEN 'cache' THEN 'cache-manifest'
                     WHEN 'source' THEN 'source-snapshot'
                     ELSE 'opaque-object'
                   END,
                   b.id
              FROM backup_pins b
             WHERE b.released_unix_ms IS NULL
               AND (b.expires_unix_ms IS NULL OR b.expires_unix_ms > ?2)
            UNION ALL
            SELECT r.result_digest, 'scan-evidence', r.artifact_id || ':' || r.scanner
              FROM artifact_scan_results r
        ";
        let mut statement = connection.prepare(sql)?;
        let mut rows = statement.query(params![to_i64(now_seconds)?, to_i64(now_unix_ms)?])?;
        let mut roots = BTreeSet::new();
        while let Some(row) = rows.next()? {
            if roots.len() >= maximum_roots {
                return Err(ControlPlaneError::GcRootLimitExceeded);
            }
            roots.insert(LifecycleGcRoot {
                digest: ContentDigest::parse(row.get::<_, String>(0)?)?,
                root_kind: row.get(1)?,
                root_id: row.get(2)?,
            });
        }
        Ok(roots.into_iter().collect())
    }

    pub fn record_lifecycle_gc_marks(
        &self,
        lease: &LifecycleGcLease,
        roots: &[LifecycleGcRoot],
        now_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        if roots.len() > 1_000_000 {
            return Err(ControlPlaneError::GcRootLimitExceeded);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_gc_lease(&transaction, lease, now_unix_ms, "marking")?;
        for root in roots {
            validate_text("GC root kind", &root.root_kind)?;
            validate_text("GC root id", &root.root_id)?;
            transaction.execute(
                "INSERT OR IGNORE INTO lifecycle_gc_marks
                 (generation, object_digest, root_kind, root_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    to_i64(lease.generation)?,
                    root.digest.as_str(),
                    root.root_kind,
                    root.root_id,
                ],
            )?;
        }
        let marked: i64 = transaction.query_row(
            "SELECT COUNT(DISTINCT object_digest) FROM lifecycle_gc_marks
             WHERE generation = ?1",
            [to_i64(lease.generation)?],
            |row| row.get(0),
        )?;
        transaction.execute(
            "UPDATE lifecycle_gc_cycles SET marked_objects = ?2
             WHERE generation = ?1 AND state = 'marking'",
            params![to_i64(lease.generation)?, marked],
        )?;
        transaction.execute(
            "UPDATE lifecycle_gc_control SET phase = 'sweeping', updated_unix_ms = ?2
             WHERE singleton = 1 AND lease_token = ?1 AND phase = 'marking'",
            params![lease.lease_token, to_i64(now_unix_ms)?],
        )?;
        transaction.execute(
            "UPDATE lifecycle_gc_cycles SET state = 'sweeping'
             WHERE generation = ?1 AND state = 'marking'",
            [to_i64(lease.generation)?],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Record one verified CAS inventory batch. Only objects absent from two
    /// consecutive completed marks and older than the safety horizon are
    /// returned for deletion.
    pub fn observe_lifecycle_gc_inventory(
        &self,
        lease: &LifecycleGcLease,
        objects: &[(ContentDigest, u64, u64)],
        now_unix_ms: u64,
        safety_horizon_ms: u64,
    ) -> Result<Vec<ContentDigest>, ControlPlaneError> {
        if objects.len() > 100_000 || safety_horizon_ms == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "GC inventory bound is invalid",
            ));
        }
        let oldest = now_unix_ms.saturating_sub(safety_horizon_ms);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_gc_lease(&transaction, lease, now_unix_ms, "sweeping")?;
        let mut eligible = Vec::new();
        for (digest, size_bytes, created_unix_ms) in objects {
            let marked: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM lifecycle_gc_marks
                 WHERE generation = ?1 AND object_digest = ?2)",
                params![to_i64(lease.generation)?, digest.as_str()],
                |row| row.get(0),
            )?;
            if marked {
                transaction.execute(
                    "DELETE FROM lifecycle_gc_candidates WHERE object_digest = ?1",
                    [digest.as_str()],
                )?;
                continue;
            }
            let existing: Option<(u64, u64, Option<u64>)> = transaction
                .query_row(
                    "SELECT first_absent_generation, last_absent_generation, swept_unix_ms
                     FROM lifecycle_gc_candidates WHERE object_digest = ?1",
                    [digest.as_str()],
                    |row| {
                        Ok((
                            u64_column(row, 0, "first absent generation")?,
                            u64_column(row, 1, "last absent generation")?,
                            optional_u64_column(row, 2, "swept timestamp")?,
                        ))
                    },
                )
                .optional()?;
            match existing {
                None => {
                    transaction.execute(
                        "INSERT INTO lifecycle_gc_candidates
                         (object_digest, first_absent_generation, last_absent_generation,
                          observed_unix_ms, size_bytes)
                         VALUES (?1, ?2, ?2, ?3, ?4)",
                        params![
                            digest.as_str(),
                            to_i64(lease.generation)?,
                            to_i64(*created_unix_ms)?,
                            to_i64(*size_bytes)?,
                        ],
                    )?;
                }
                Some((first, last, swept)) => {
                    if swept.is_none() && last.saturating_add(1) == lease.generation {
                        transaction.execute(
                            "UPDATE lifecycle_gc_candidates
                             SET last_absent_generation = ?2, size_bytes = ?3
                             WHERE object_digest = ?1",
                            params![
                                digest.as_str(),
                                to_i64(lease.generation)?,
                                to_i64(*size_bytes)?,
                            ],
                        )?;
                        if first < lease.generation && *created_unix_ms <= oldest {
                            eligible.push(digest.clone());
                        }
                    }
                }
            }
        }
        transaction.execute(
            "UPDATE lifecycle_gc_cycles
             SET candidate_objects = (SELECT COUNT(*) FROM lifecycle_gc_candidates
                                      WHERE swept_unix_ms IS NULL)
             WHERE generation = ?1",
            [to_i64(lease.generation)?],
        )?;
        transaction.commit()?;
        Ok(eligible)
    }

    pub fn complete_lifecycle_gc(
        &self,
        lease: &LifecycleGcLease,
        swept: &[(ContentDigest, u64)],
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        if swept.len() > 100_000 {
            return Err(ControlPlaneError::InvalidInput("GC sweep bound is invalid"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cycle_state: Option<String> = transaction
            .query_row(
                "SELECT state FROM lifecycle_gc_cycles
                 WHERE generation = ?1 AND lease_token = ?2",
                params![to_i64(lease.generation)?, lease.lease_token],
                |row| row.get(0),
            )
            .optional()?;
        if cycle_state.as_deref() == Some("completed") {
            transaction.commit()?;
            return Ok(true);
        }
        verify_gc_lease(&transaction, lease, now_unix_ms, "sweeping")?;
        let mut bytes = 0_u64;
        for (digest, size) in swept {
            let changed = transaction.execute(
                "UPDATE lifecycle_gc_candidates SET swept_unix_ms = ?2
                 WHERE object_digest = ?1 AND last_absent_generation = ?3
                   AND swept_unix_ms IS NULL",
                params![
                    digest.as_str(),
                    to_i64(now_unix_ms)?,
                    to_i64(lease.generation)?,
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            bytes = bytes
                .checked_add(*size)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "GC swept bytes",
                })?;
        }
        transaction.execute(
            "UPDATE lifecycle_gc_cycles SET state = 'completed', swept_objects = ?2,
                    swept_bytes = ?3, completed_unix_ms = ?4
             WHERE generation = ?1 AND state = 'sweeping'",
            params![
                to_i64(lease.generation)?,
                to_i64(swept.len() as u64)?,
                to_i64(bytes)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "UPDATE lifecycle_gc_control SET phase = 'idle', lease_owner = NULL,
                    lease_token = NULL, lease_expires_unix_ms = NULL, updated_unix_ms = ?2
             WHERE singleton = 1 AND lease_token = ?1",
            params![lease.lease_token, to_i64(now_unix_ms)?],
        )?;
        transaction.execute(
            "DELETE FROM lifecycle_gc_marks WHERE generation + 2 < ?1",
            [to_i64(lease.generation)?],
        )?;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "generation".to_owned(),
            AuditValue::Integer(to_i64(lease.generation)?),
        );
        metadata.insert(
            "swept_objects".to_owned(),
            AuditValue::Integer(to_i64(swept.len() as u64)?),
        );
        metadata.insert(
            "swept_bytes".to_owned(),
            AuditValue::Integer(to_i64(bytes)?),
        );
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: now_unix_ms,
                tenant_id: "installation".to_owned(),
                actor: AuditPrincipal {
                    kind: "worker".to_owned(),
                    id: lease.lease_owner.clone(),
                },
                action: "storage.gc".to_owned(),
                resource: AuditResource {
                    kind: "gc-cycle".to_owned(),
                    id: lease.generation.to_string(),
                },
                result: "completed".to_owned(),
                request_id: lease.lease_token.clone(),
                decision_id: None,
                metadata,
            },
        )?;
        transaction.commit()?;
        Ok(false)
    }

    /// Return persisted second-generation candidates, including objects that
    /// disappeared after unlink but before the sweep journal committed.
    pub fn lifecycle_gc_sweep_candidates(
        &self,
        lease: &LifecycleGcLease,
        now_unix_ms: u64,
        safety_horizon_ms: u64,
        maximum_candidates: usize,
    ) -> Result<Vec<(ContentDigest, u64)>, ControlPlaneError> {
        if safety_horizon_ms == 0 || maximum_candidates == 0 || maximum_candidates > 100_000 {
            return Err(ControlPlaneError::InvalidInput(
                "GC candidate bound is invalid",
            ));
        }
        let connection = self.connection()?;
        verify_gc_lease(&connection, lease, now_unix_ms, "sweeping")?;
        let oldest = now_unix_ms.saturating_sub(safety_horizon_ms);
        let mut statement = connection.prepare(
            "SELECT object_digest, size_bytes FROM lifecycle_gc_candidates
             WHERE first_absent_generation < ?1 AND last_absent_generation = ?1
               AND observed_unix_ms <= ?2 AND swept_unix_ms IS NULL
             ORDER BY object_digest LIMIT ?3",
        )?;
        let values = statement
            .query_map(
                params![
                    to_i64(lease.generation)?,
                    to_i64(oldest)?,
                    to_i64(maximum_candidates as u64)?,
                ],
                |row| {
                    Ok((
                        digest_column(row, 0)?,
                        u64_column(row, 1, "GC candidate bytes")?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }

    pub fn lifecycle_metrics(&self) -> Result<LifecycleGcMetrics, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT c.current_generation,
                    COALESCE(y.marked_objects, 0), COALESCE(y.candidate_objects, 0),
                    COALESCE(y.swept_objects, 0), COALESCE(y.swept_bytes, 0),
                    (SELECT COUNT(*) FROM tenant_storage_reservations
                     WHERE state IN ('reserved','committed')),
                    (SELECT COUNT(*) FROM artifact_scan_journal
                     WHERE state IN ('pending','claimed')),
                    (SELECT COUNT(*) FROM artifact_scan_journal
                     WHERE state IN ('failed','error'))
             FROM lifecycle_gc_control c
             LEFT JOIN lifecycle_gc_cycles y ON y.generation = c.current_generation
             WHERE c.singleton = 1",
                [],
                |row| {
                    Ok(LifecycleGcMetrics {
                        generation: u64_column(row, 0, "GC generation")?,
                        marked_objects: u64_column(row, 1, "GC marked objects")?,
                        candidate_objects: u64_column(row, 2, "GC candidate objects")?,
                        swept_objects: u64_column(row, 3, "GC swept objects")?,
                        swept_bytes: u64_column(row, 4, "GC swept bytes")?,
                        active_storage_reservations: u64_column(
                            row,
                            5,
                            "active storage reservations",
                        )?,
                        scan_pending: u64_column(row, 6, "pending scans")?,
                        scan_failed_or_error: u64_column(row, 7, "failed scans")?,
                    })
                },
            )
            .map_err(Into::into)
    }
}

fn validate_backup_pin(pin: &BackupPinRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("backup pin id", pin.id.as_str()),
        ("backup root id", pin.root_id.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if let Some(tenant) = &pin.tenant_id {
        validate_text("backup pin tenant", tenant)?;
    }
    if !matches!(
        pin.root_kind.as_str(),
        "artifact" | "cache" | "source" | "evidence" | "object"
    ) || pin.released_unix_ms.is_some()
        || pin
            .expires_unix_ms
            .is_some_and(|expiry| expiry <= pin.created_unix_ms)
    {
        return Err(ControlPlaneError::InvalidInput(
            "backup pin metadata is invalid",
        ));
    }
    Ok(())
}

fn backup_pin_row(row: &Row<'_>) -> rusqlite::Result<BackupPinRecord> {
    Ok(BackupPinRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        root_kind: row.get(2)?,
        root_id: row.get(3)?,
        object_digest: digest_column(row, 4)?,
        created_unix_ms: u64_column(row, 5, "backup pin creation")?,
        expires_unix_ms: optional_u64_column(row, 6, "backup pin expiry")?,
        released_unix_ms: optional_u64_column(row, 7, "backup pin release")?,
    })
}

fn verify_gc_lease(
    connection: &Connection,
    lease: &LifecycleGcLease,
    now_unix_ms: u64,
    required_phase: &str,
) -> Result<(), ControlPlaneError> {
    let valid: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM lifecycle_gc_control
            WHERE singleton = 1 AND current_generation = ?1 AND phase = ?2
              AND lease_owner = ?3 AND lease_token = ?4
              AND lease_expires_unix_ms > ?5
         )",
        params![
            to_i64(lease.generation)?,
            required_phase,
            lease.lease_owner,
            lease.lease_token,
            to_i64(now_unix_ms)?,
        ],
        |row| row.get(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(ControlPlaneError::LifecycleGcLeaseLost)
    }
}
