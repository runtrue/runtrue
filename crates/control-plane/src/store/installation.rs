use super::*;
use rusqlite::params;

pub(super) fn installation_epoch_tx(
    transaction: &Transaction<'_>,
) -> Result<u64, ControlPlaneError> {
    let value: i64 = transaction.query_row(
        "SELECT fencing_epoch FROM installation_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    from_i64("fencing_epoch", value)
}

pub(super) fn fence_open_leases_tx(
    transaction: &Transaction<'_>,
    completed_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let mut statement = transaction.prepare(
        "SELECT DISTINCT j.id, j.status
         FROM jobs j JOIN leases l ON l.job_id = j.id
         WHERE l.state IN ('offered', 'active', 'cancel_requested')",
    )?;
    let affected = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (job_id, encoded_state) in affected {
        let state = parse_job_state(&encoded_state)?;
        if state.can_transition_to(JobState::Lost) {
            transaction.execute(
                "UPDATE jobs SET status = 'lost', completed_unix_ms = ?2 WHERE id = ?1",
                params![job_id, to_i64(completed_unix_ms)?],
            )?;
        }
    }
    transaction.execute(
        "UPDATE leases SET state = 'expired'
         WHERE state IN ('offered', 'active', 'cancel_requested')",
        [],
    )?;
    transaction.execute(
        "UPDATE runner_secret_leases
         SET state = 'expired', revoked_unix_ms = ?1 WHERE state = 'delivered'",
        [to_i64(completed_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE runner_oidc_issuances
         SET state = 'expired', revoked_unix_ms = ?1 WHERE state = 'issued'",
        [to_i64(completed_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE oidc_grants SET revoked_unix_ms = ?1
         WHERE revoked_unix_ms IS NULL AND id IN (
             SELECT grant_id FROM runner_oidc_issuances
         )",
        [to_i64(completed_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE runner_object_transfers SET state = 'abandoned', updated_unix_ms = ?1
         WHERE state IN ('reserved', 'transferring')",
        [to_i64(completed_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE enrollment_tokens SET expires_unix_ms = MIN(expires_unix_ms, ?1)
         WHERE consumed_unix_ms IS NULL AND expires_unix_ms > ?1",
        [to_i64(completed_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE runner_launch_claims SET expires_unix_ms = MIN(expires_unix_ms, ?1)
         WHERE consumed_unix_ms IS NULL AND expires_unix_ms > ?1",
        [to_i64(completed_unix_ms)?],
    )?;
    transaction.execute(
        "UPDATE runner_autoscaler_leases SET expires_unix_ms = MIN(expires_unix_ms, ?1)
         WHERE expires_unix_ms > ?1",
        [to_i64(completed_unix_ms)?],
    )?;
    Ok(())
}

impl ControlPlane {
    pub(crate) fn database_readiness(
        &self,
    ) -> Result<crate::persistence::DatabaseReadiness, ControlPlaneError> {
        let connection = self.connection()?;
        // The unified ledger was verified while opening the store. Preserve
        // the backend schema generation in readiness without consulting the
        // retired legacy PRAGMA authority.
        let schema_version = super::database::CURRENT_SCHEMA_VERSION;
        let recovery = connection.query_row(
            "SELECT fencing_epoch, safe_mode, last_restore_unix_ms
             FROM installation_state WHERE singleton = 1",
            [],
            |row| {
                Ok(InstallationRecoveryState {
                    fencing_epoch: u64_column(row, 0, "fencing_epoch")?,
                    safe_mode: row.get(1)?,
                    last_restore_unix_ms: optional_u64_column(row, 2, "last_restore_unix_ms")?,
                })
            },
        )?;
        Ok(crate::persistence::DatabaseReadiness {
            backend: crate::persistence::DatabaseBackendKind::Sqlite,
            schema_version,
            installation_id: self.installation_id.clone(),
            recovery,
        })
    }

    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    pub fn installation_fencing_epoch(&self) -> Result<u64, ControlPlaneError> {
        let connection = self.connection()?;
        let value: i64 = connection.query_row(
            "SELECT fencing_epoch FROM installation_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        from_i64("fencing_epoch", value)
    }

    pub fn recovery_state(&self) -> Result<InstallationRecoveryState, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT fencing_epoch, safe_mode, last_restore_unix_ms
                 FROM installation_state WHERE singleton = 1",
                [],
                |row| {
                    Ok(InstallationRecoveryState {
                        fencing_epoch: u64_column(row, 0, "fencing_epoch")?,
                        safe_mode: row.get(1)?,
                        last_restore_unix_ms: optional_u64_column(row, 2, "last_restore_unix_ms")?,
                    })
                },
            )
            .map_err(ControlPlaneError::from)
    }

    pub fn advance_installation_fencing_epoch(
        &self,
        new_epoch: u64,
        completed_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = installation_epoch_tx(&transaction)?;
        if new_epoch <= current {
            return Err(ControlPlaneError::EpochMustIncrease {
                current,
                proposed: new_epoch,
            });
        }
        transaction.execute(
            "UPDATE installation_state SET fencing_epoch = ?1 WHERE singleton = 1",
            [to_i64(new_epoch)?],
        )?;

        fence_open_leases_tx(&transaction, completed_unix_ms)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically enter recovery safe mode, advance the installation fence,
    /// mark jobs behind open leases lost, and revoke copied runner authority.
    pub fn enter_restore_safe_mode(
        &self,
        restored_unix_ms: u64,
    ) -> Result<InstallationRecoveryState, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = installation_epoch_tx(&transaction)?;
        let new_epoch = current
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "fencing_epoch",
            })?;
        transaction.execute(
            "UPDATE installation_state
             SET fencing_epoch = ?1, safe_mode = 1, last_restore_unix_ms = ?2
             WHERE singleton = 1",
            params![to_i64(new_epoch)?, to_i64(restored_unix_ms)?],
        )?;
        fence_open_leases_tx(&transaction, restored_unix_ms)?;
        transaction.commit()?;
        Ok(InstallationRecoveryState {
            fencing_epoch: new_epoch,
            safe_mode: true,
            last_restore_unix_ms: Some(restored_unix_ms),
        })
    }

    /// Leave recovery safe mode only at the exact post-restore fence.
    pub fn leave_restore_safe_mode(
        &self,
        expected_fencing_epoch: u64,
    ) -> Result<InstallationRecoveryState, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: InstallationRecoveryState = transaction.query_row(
            "SELECT fencing_epoch, safe_mode, last_restore_unix_ms
             FROM installation_state WHERE singleton = 1",
            [],
            |row| {
                Ok(InstallationRecoveryState {
                    fencing_epoch: u64_column(row, 0, "fencing_epoch")?,
                    safe_mode: row.get(1)?,
                    last_restore_unix_ms: optional_u64_column(row, 2, "last_restore_unix_ms")?,
                })
            },
        )?;
        if !state.safe_mode {
            return Err(ControlPlaneError::NotInRestoreSafeMode);
        }
        if state.fencing_epoch != expected_fencing_epoch {
            return Err(ControlPlaneError::RestoreEpochMismatch {
                expected: state.fencing_epoch,
                actual: expected_fencing_epoch,
            });
        }
        let open_leases: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM leases
                 WHERE state IN ('offered', 'active', 'cancel_requested')
             )",
            [],
            |row| row.get(0),
        )?;
        if open_leases {
            return Err(ControlPlaneError::RestoreHasOpenLeases);
        }
        transaction.execute(
            "UPDATE installation_state SET safe_mode = 0 WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        Ok(InstallationRecoveryState {
            safe_mode: false,
            ..state
        })
    }
}
