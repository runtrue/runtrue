use super::*;

pub(in crate::store) fn runner_pool_status_name(status: RunnerPoolStatus) -> &'static str {
    match status {
        RunnerPoolStatus::Active => "active",
        RunnerPoolStatus::Disabled => "disabled",
    }
}

pub(in crate::store) fn parse_runner_pool_status(
    value: &str,
) -> Result<RunnerPoolStatus, ControlPlaneError> {
    match value {
        "active" => Ok(RunnerPoolStatus::Active),
        "disabled" => Ok(RunnerPoolStatus::Disabled),
        _ => Err(ControlPlaneError::InvalidInput(
            "unknown runner pool status",
        )),
    }
}

pub(in crate::store) fn runner_status_name(status: RunnerStatus) -> &'static str {
    match status {
        RunnerStatus::Online => "online",
        RunnerStatus::Draining => "draining",
        RunnerStatus::Quarantined => "quarantined",
        RunnerStatus::Offline => "offline",
        RunnerStatus::Revoked => "revoked",
    }
}

pub(in crate::store) fn parse_runner_status(
    value: &str,
) -> Result<RunnerStatus, ControlPlaneError> {
    match value {
        "online" => Ok(RunnerStatus::Online),
        "draining" => Ok(RunnerStatus::Draining),
        "quarantined" => Ok(RunnerStatus::Quarantined),
        "offline" => Ok(RunnerStatus::Offline),
        "revoked" => Ok(RunnerStatus::Revoked),
        _ => Err(ControlPlaneError::InvalidInput("unknown runner status")),
    }
}

pub(in crate::store) fn runner_pool_row(row: &Row<'_>) -> rusqlite::Result<RunnerPoolRecord> {
    let status: String = row.get(4)?;
    Ok(RunnerPoolRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        name: row.get(2)?,
        region: row.get(3)?,
        status: parse_runner_pool_status(&status).map_err(|error| conversion(4, error))?,
        created_unix_ms: u64_column(row, 5, "created_unix_ms")?,
    })
}

pub(in crate::store) fn validate_runner_record(
    runner: &RunnerRecord,
) -> Result<(), ControlPlaneError> {
    validate_text("runner.id", &runner.id)?;
    validate_text("runner.tenant_id", &runner.tenant_id)?;
    validate_text("runner.pool_id", &runner.pool_id)?;
    if runner.logical_cpus == 0
        || runner.memory_bytes == 0
        || runner.storage_bytes == 0
        || runner.isolation_backends.is_empty()
    {
        return Err(ControlPlaneError::InvalidInput("invalid runner inventory"));
    }
    Ok(())
}

impl ControlPlane {
    pub fn create_runner_pool(&self, pool: &RunnerPoolRecord) -> Result<(), ControlPlaneError> {
        validate_text("runner_pool.id", &pool.id)?;
        validate_text("runner_pool.tenant_id", &pool.tenant_id)?;
        validate_text("runner_pool.name", &pool.name)?;
        if let Some(region) = &pool.region {
            validate_text("runner_pool.region", region)?;
        }
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO runner_pools
             (id, tenant_id, name, region, status, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                pool.id,
                pool.tenant_id,
                pool.name,
                pool.region,
                runner_pool_status_name(pool.status),
                to_i64(pool.created_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn runner_pool(&self, id: &str) -> Result<RunnerPoolRecord, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, tenant_id, name, region, status, created_unix_ms
                 FROM runner_pools WHERE id = ?1",
                [id],
                runner_pool_row,
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool", id))
    }

    pub fn list_runner_pools(&self) -> Result<Vec<RunnerPoolRecord>, ControlPlaneError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, name, region, status, created_unix_ms
             FROM runner_pools ORDER BY id",
        )?;
        let values = statement
            .query_map([], runner_pool_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }

    pub fn list_runner_pools_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<RunnerPoolRecord>, ControlPlaneError> {
        validate_text("runner pool tenant", tenant_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, name, region, status, created_unix_ms
             FROM runner_pools WHERE tenant_id = ?1 ORDER BY id",
        )?;
        let values = statement
            .query_map([tenant_id], runner_pool_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }

    pub fn register_runner(
        &self,
        runner: &RunnerRecord,
        now_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        self.register_runner_bound(runner, None, now_unix_ms)
            .map(|_| ())
    }

    fn register_runner_bound(
        &self,
        runner: &RunnerRecord,
        inventory_digest: Option<&ContentDigest>,
        now_unix_ms: u64,
    ) -> Result<Option<ContentDigest>, ControlPlaneError> {
        validate_runner_record(runner)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (pool_status, pool_tenant, pool_region): (String, String, Option<String>) = transaction
            .query_row(
                "SELECT status, tenant_id, region FROM runner_pools WHERE id = ?1",
                [&runner.pool_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool", &runner.pool_id))?;
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            return Err(ControlPlaneError::InvalidInput("runner pool is disabled"));
        }
        if runner.tenant_id != pool_tenant {
            return Err(ControlPlaneError::InvalidInput(
                "runner tenant does not match its authoritative pool",
            ));
        }
        if pool_region
            .as_ref()
            .is_some_and(|region| runner.region.as_ref() != Some(region))
        {
            return Err(ControlPlaneError::InvalidInput(
                "runner region does not match its authoritative pool",
            ));
        }
        transaction.execute(
            "INSERT INTO runners
             (id, pool_id, status, runner_json, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![
                runner.id,
                runner.pool_id,
                runner_status_name(runner.status),
                serde_json::to_string(runner)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        let posture = inventory_digest
            .map(|inventory| authoritative_runner_posture_digest(runner, inventory))
            .transpose()?;
        if let (Some(inventory), Some(posture)) = (inventory_digest, posture.as_ref()) {
            transaction.execute(
                "INSERT INTO runner_enrollment_postures
                 (runner_id, inventory_digest, posture_digest, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    runner.id,
                    inventory.as_str(),
                    posture.as_str(),
                    to_i64(now_unix_ms)?,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(posture)
    }

    /// Administrative registration with an already authenticated, normalized
    /// inventory snapshot. Plain `register_runner` remains available for
    /// migration/inspection but such a runner cannot open a broker-capable
    /// session until it re-enrolls with this binding.
    pub fn register_runner_with_inventory(
        &self,
        runner: &RunnerRecord,
        inventory_digest: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<ContentDigest, ControlPlaneError> {
        self.register_runner_bound(runner, Some(inventory_digest), now_unix_ms)?
            .ok_or(ControlPlaneError::CorruptState(
                "runner posture binding was not created".to_owned(),
            ))
    }

    pub fn runner(&self, id: &str) -> Result<PersistedRunner, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT runner_json, created_unix_ms, updated_unix_ms
                 FROM runners WHERE id = ?1",
                [id],
                |row| {
                    Ok(PersistedRunner {
                        runner: json_column(row, 0)?,
                        created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                        updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| not_found("runner", id))
    }

    pub fn list_runners(&self) -> Result<Vec<PersistedRunner>, ControlPlaneError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT runner_json, created_unix_ms, updated_unix_ms FROM runners
             WHERE COALESCE(json_extract(runner_json, '$.retired'), 0) = 0 ORDER BY id",
        )?;
        let values = statement
            .query_map([], |row| {
                Ok(PersistedRunner {
                    runner: json_column(row, 0)?,
                    created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                    updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }

    pub fn list_runners_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<PersistedRunner>, ControlPlaneError> {
        validate_text("runner tenant", tenant_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT r.runner_json, r.created_unix_ms, r.updated_unix_ms
             FROM runners r JOIN runner_pools p ON p.id = r.pool_id
             WHERE p.tenant_id = ?1
               AND COALESCE(json_extract(r.runner_json, '$.retired'), 0) = 0
             ORDER BY r.id",
        )?;
        let values = statement
            .query_map([tenant_id], |row| {
                Ok(PersistedRunner {
                    runner: json_column(row, 0)?,
                    created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                    updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }

    pub fn drain_runner(
        &self,
        runner_id: &str,
        now_unix_ms: u64,
    ) -> Result<PersistedRunner, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut persisted = transaction
            .query_row(
                "SELECT runner_json, created_unix_ms, updated_unix_ms FROM runners WHERE id = ?1",
                [runner_id],
                |row| {
                    Ok(PersistedRunner {
                        runner: json_column(row, 0)?,
                        created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                        updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| not_found("runner", runner_id))?;
        if persisted.runner.status == RunnerStatus::Revoked {
            return Err(ControlPlaneError::InvalidInput(
                "a revoked runner cannot enter draining state",
            ));
        }
        persisted.runner.status = RunnerStatus::Draining;
        persisted.updated_unix_ms = now_unix_ms;
        transaction.execute(
            "UPDATE runners SET status = 'draining', runner_json = ?2, updated_unix_ms = ?3
             WHERE id = ?1",
            params![
                runner_id,
                serde_json::to_string(&persisted.runner)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(persisted)
    }
}

impl ControlPlane {
    pub fn update_runner_locality(
        &self,
        runner_id: &str,
        locality: &BTreeSet<ContentDigest>,
        now_unix_ms: u64,
    ) -> Result<PersistedRunner, ControlPlaneError> {
        validate_text("runner id", runner_id)?;
        if locality.len() > 10_000 {
            return Err(ControlPlaneError::InvalidInput(
                "runner locality exceeds its item bound",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut persisted = transaction
            .query_row(
                "SELECT runner_json, created_unix_ms, updated_unix_ms FROM runners WHERE id = ?1",
                [runner_id],
                |row| {
                    Ok(PersistedRunner {
                        runner: json_column(row, 0)?,
                        created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                        updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| not_found("runner", runner_id))?;
        if !matches!(
            persisted.runner.status,
            RunnerStatus::Online | RunnerStatus::Draining
        ) {
            return Err(ControlPlaneError::InvalidInput(
                "offline runner cannot update locality",
            ));
        }
        persisted.runner.locality = locality.clone();
        persisted.updated_unix_ms = now_unix_ms;
        transaction.execute(
            "UPDATE runners SET runner_json = ?2, updated_unix_ms = ?3 WHERE id = ?1",
            params![
                runner_id,
                serde_json::to_string(&persisted.runner)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(persisted)
    }

    pub fn update_runner(
        &self,
        runner: &RunnerRecord,
        now_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        validate_runner_record(runner)?;
        let connection = self.connection()?;
        let (pool_tenant, pool_region): (String, Option<String>) = connection
            .query_row(
                "SELECT tenant_id, region FROM runner_pools WHERE id = ?1",
                [&runner.pool_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool", &runner.pool_id))?;
        if runner.tenant_id != pool_tenant {
            return Err(ControlPlaneError::InvalidInput(
                "runner tenant does not match its authoritative pool",
            ));
        }
        if pool_region
            .as_ref()
            .is_some_and(|region| runner.region.as_ref() != Some(region))
        {
            return Err(ControlPlaneError::InvalidInput(
                "runner region does not match its authoritative pool",
            ));
        }
        let changed = connection.execute(
            "UPDATE runners SET pool_id = ?2, status = ?3, runner_json = ?4,
             updated_unix_ms = ?5 WHERE id = ?1",
            params![
                runner.id,
                runner.pool_id,
                runner_status_name(runner.status),
                serde_json::to_string(runner)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        if changed == 0 {
            return Err(not_found("runner", &runner.id));
        }
        Ok(())
    }

    /// Mark a provisioned runner connected and refresh its trusted registry
    /// heartbeat without changing draining state. Revoked and quarantined
    /// identities fail closed.
    pub fn mark_runner_connected(
        &self,
        runner_id: &str,
        now_unix_ms: u64,
    ) -> Result<PersistedRunner, ControlPlaneError> {
        self.update_runner_connection_state(runner_id, true, now_unix_ms)
    }

    /// Mark a disconnected online runner offline. Administrative draining,
    /// quarantine, and revocation states are never overwritten by cleanup.
    pub fn mark_runner_disconnected(
        &self,
        runner_id: &str,
        now_unix_ms: u64,
    ) -> Result<PersistedRunner, ControlPlaneError> {
        self.update_runner_connection_state(runner_id, false, now_unix_ms)
    }

    fn update_runner_connection_state(
        &self,
        runner_id: &str,
        connected: bool,
        now_unix_ms: u64,
    ) -> Result<PersistedRunner, ControlPlaneError> {
        validate_text("runner id", runner_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut persisted = transaction
            .query_row(
                "SELECT runner_json, created_unix_ms, updated_unix_ms FROM runners WHERE id = ?1",
                [runner_id],
                |row| {
                    Ok(PersistedRunner {
                        runner: json_column(row, 0)?,
                        created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                        updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| not_found("runner", runner_id))?;
        if connected {
            if persisted.runner.retired {
                return Err(ControlPlaneError::InvalidInput(
                    "retired ephemeral runner cannot reconnect",
                ));
            }
            match persisted.runner.status {
                RunnerStatus::Revoked | RunnerStatus::Quarantined => {
                    return Err(ControlPlaneError::InvalidInput(
                        "revoked or quarantined runner cannot connect",
                    ))
                }
                RunnerStatus::Offline => persisted.runner.status = RunnerStatus::Online,
                RunnerStatus::Online | RunnerStatus::Draining => {}
            }
            persisted.runner.last_heartbeat_unix_ms = now_unix_ms;
        } else if persisted.runner.status == RunnerStatus::Online {
            persisted.runner.status = RunnerStatus::Offline;
        }
        persisted.updated_unix_ms = now_unix_ms;
        transaction.execute(
            "UPDATE runners SET status = ?2, runner_json = ?3, updated_unix_ms = ?4
             WHERE id = ?1",
            params![
                runner_id,
                runner_status_name(persisted.runner.status),
                serde_json::to_string(&persisted.runner)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(persisted)
    }
}
