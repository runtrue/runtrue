use super::*;

pub(in crate::store) fn replay_bundle_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<ReplayBundleRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, run_id, digest, bundle_json, created_unix_ms, expires_unix_ms
             FROM replay_bundles WHERE id = ?1",
            [id],
            replay_bundle_row,
        )
        .optional()?
        .ok_or_else(|| not_found("replay bundle", id))
}

pub(in crate::store) fn replay_bundle_row(row: &Row<'_>) -> rusqlite::Result<ReplayBundleRecord> {
    Ok(ReplayBundleRecord {
        id: row.get(0)?,
        run_id: row.get(1)?,
        digest: digest_column(row, 2)?,
        canonical_bundle: row.get(3)?,
        created_unix_ms: u64_column(row, 4, "created_unix_ms")?,
        expires_unix_ms: u64_column(row, 5, "expires_unix_ms")?,
    })
}

impl ControlPlane {
    pub fn store_replay_bundle_idempotent(
        &self,
        idempotency_key: &str,
        record: &ReplayBundleRecord,
    ) -> Result<IdempotentResult<ReplayBundleRecord>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        validate_text("replay bundle id", &record.id)?;
        validate_text("replay run id", &record.run_id)?;
        if record.expires_unix_ms <= record.created_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "replay bundle expiry must be in the future",
            ));
        }
        let actual = ContentDigest::sha256(&record.canonical_bundle);
        if actual != record.digest {
            return Err(ControlPlaneError::CapsuleDigestMismatch {
                expected: record.digest.clone(),
                actual,
            });
        }
        #[derive(Serialize)]
        struct Subject<'a> {
            run_id: &'a str,
            digest: &'a ContentDigest,
        }
        let request_hash = hash_serializable(&Subject {
            run_id: &record.run_id,
            digest: &record.digest,
        })?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, "replay.create", idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = replay_bundle_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        transaction
            .query_row("SELECT 1 FROM runs WHERE id = ?1", [&record.run_id], |_| {
                Ok(())
            })
            .optional()?
            .ok_or_else(|| not_found("run", &record.run_id))?;
        transaction.execute(
            "INSERT INTO replay_bundles
             (id, run_id, digest, bundle_json, created_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.id,
                record.run_id,
                record.digest.as_str(),
                record.canonical_bundle,
                to_i64(record.created_unix_ms)?,
                to_i64(record.expires_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES ('replay.create', ?1, ?2, ?3, ?4)",
            params![
                idempotency_key,
                request_hash.as_str(),
                record.id,
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record.clone(),
            replayed: false,
        })
    }

    pub fn replay_bundle_for_run(
        &self,
        run_id: &str,
    ) -> Result<ReplayBundleRecord, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, run_id, digest, bundle_json, created_unix_ms, expires_unix_ms
                 FROM replay_bundles WHERE run_id = ?1",
                [run_id],
                replay_bundle_row,
            )
            .optional()?
            .ok_or_else(|| not_found("replay bundle", run_id))
    }
}
