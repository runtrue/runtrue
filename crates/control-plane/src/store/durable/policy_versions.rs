use super::*;

pub(in crate::store) fn promotion_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<PromotionRequestRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, kind, source_id, target_json, evidence_json, status, created_unix_ms
             FROM promotion_requests WHERE id = ?1",
            [id],
            |row| {
                Ok(PromotionRequestRecord {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    source_id: row.get(2)?,
                    target: json_column(row, 3)?,
                    evidence: json_column(row, 4)?,
                    status: row.get(5)?,
                    created_unix_ms: u64_column(row, 6, "created_unix_ms")?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| not_found("promotion request", id))
}

pub(in crate::store) fn policy_version_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<PolicyVersionRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, policy_id, version, source, mode, digest, created_unix_ms
             FROM policy_versions WHERE id = ?1",
            [id],
            |row| {
                Ok(PolicyVersionRecord {
                    id: row.get(0)?,
                    policy_id: row.get(1)?,
                    version: u64_column(row, 2, "policy version")?,
                    source: row.get(3)?,
                    mode: row.get(4)?,
                    digest: digest_column(row, 5)?,
                    created_unix_ms: u64_column(row, 6, "created_unix_ms")?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| not_found("policy version", id))
}

impl ControlPlane {
    pub fn create_promotion_request_idempotent(
        &self,
        idempotency_key: &str,
        request: &PromotionRequestRecord,
    ) -> Result<IdempotentResult<PromotionRequestRecord>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        for (field, value) in [
            ("promotion id", request.id.as_str()),
            ("promotion kind", request.kind.as_str()),
            ("promotion source", request.source_id.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if !matches!(request.kind.as_str(), "cache" | "artifact") || request.status != "pending" {
            return Err(ControlPlaneError::InvalidInput(
                "new promotion must be pending cache or artifact work",
            ));
        }
        let target = serde_json::to_string(&canonicalize_json(request.target.clone()))?;
        let evidence = serde_json::to_string(&canonicalize_json(request.evidence.clone()))?;
        let request_hash = hash_serializable(&(
            request.kind.as_str(),
            request.source_id.as_str(),
            &target,
            &evidence,
        ))?;
        let operation = format!("promotion.create:{}", request.kind);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = promotion_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        transaction.execute(
            "INSERT INTO promotion_requests
             (id, kind, source_id, target_json, evidence_json, status, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
            params![
                request.id,
                request.kind,
                request.source_id,
                target,
                evidence,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO durable_tasks
             (id, kind, payload_json, status, available_unix_ms, attempts,
              created_unix_ms)
             VALUES (?1, ?2, ?3, 'pending', ?4, 0, ?4)",
            params![
                format!("promotion-task:{}", request.id),
                format!("{}.promotion", request.kind),
                serde_json::to_string(request)?,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
                idempotency_key,
                request_hash.as_str(),
                request.id,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: request.clone(),
            replayed: false,
        })
    }

    pub fn create_policy_version_idempotent(
        &self,
        idempotency_key: &str,
        record: &PolicyVersionRecord,
    ) -> Result<IdempotentResult<PolicyVersionRecord>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        for (field, value) in [
            ("policy version id", record.id.as_str()),
            ("policy id", record.policy_id.as_str()),
            ("policy source", record.source.as_str()),
            ("policy mode", record.mode.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if record.version == 0 || !matches!(record.mode.as_str(), "draft" | "shadow" | "enforce") {
            return Err(ControlPlaneError::InvalidInput(
                "policy version or mode is invalid",
            ));
        }
        let actual = ContentDigest::sha256(record.source.as_bytes());
        if actual != record.digest {
            return Err(ControlPlaneError::CapsuleDigestMismatch {
                expected: record.digest.clone(),
                actual,
            });
        }
        let request_hash = hash_serializable(&(
            record.policy_id.as_str(),
            record.source.as_str(),
            record.mode.as_str(),
        ))?;
        let operation = format!("policy.version.create:{}", record.policy_id);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = policy_version_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        let next: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE policy_id = ?1",
            [&record.policy_id],
            |row| row.get(0),
        )?;
        if from_i64("policy version", next)? != record.version {
            return Err(ControlPlaneError::InvalidInput(
                "policy version is not the next durable version",
            ));
        }
        transaction.execute(
            "INSERT INTO policy_versions
             (id, policy_id, version, source, mode, digest, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.id,
                record.policy_id,
                to_i64(record.version)?,
                record.source,
                record.mode,
                record.digest.as_str(),
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
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

    pub fn next_policy_version(&self, policy_id: &str) -> Result<u64, ControlPlaneError> {
        validate_text("policy id", policy_id)?;
        let connection = self.connection()?;
        let next: i64 = connection.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE policy_id = ?1",
            [policy_id],
            |row| row.get(0),
        )?;
        from_i64("policy version", next)
    }
}
