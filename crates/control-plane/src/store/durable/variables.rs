use super::*;

pub(in crate::store) fn variable_snapshot_row(row: &Row<'_>) -> rusqlite::Result<VariableSnapshot> {
    Ok(VariableSnapshot {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        scope: row.get(2)?,
        version: u64_column(row, 3, "version")?,
        values: json_column(row, 4)?,
        digest: digest_column(row, 5)?,
        created_unix_ms: u64_column(row, 6, "created_unix_ms")?,
    })
}

pub(in crate::store) fn variable_row(row: &Row<'_>) -> rusqlite::Result<VariableRecord> {
    Ok(VariableRecord {
        tenant_id: row.get(0)?,
        scope: row.get(1)?,
        name: row.get(2)?,
        value: json_column(row, 3)?,
        version: u64_column(row, 4, "variable version")?,
        updated_unix_ms: u64_column(row, 5, "updated_unix_ms")?,
    })
}

pub(in crate::store) fn variable_version_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    scope: &str,
    name: &str,
    version: u64,
) -> Result<VariableRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT tenant_id, scope, name, value_json, version, updated_unix_ms
             FROM variable_versions
             WHERE tenant_id = ?1 AND scope = ?2 AND name = ?3 AND version = ?4",
            params![tenant_id, scope, name, to_i64(version)?],
            variable_row,
        )
        .optional()?
        .ok_or_else(|| not_found("variable version", &version.to_string()))
}

impl ControlPlane {
    pub fn create_variable_snapshot(
        &self,
        id: &str,
        tenant_id: &str,
        scope: &str,
        version: u64,
        values: BTreeMap<String, Value>,
        created_unix_ms: u64,
    ) -> Result<VariableSnapshot, ControlPlaneError> {
        validate_text("variable_snapshot.id", id)?;
        validate_text("variable_snapshot.tenant_id", tenant_id)?;
        validate_text("variable_snapshot.scope", scope)?;
        if version == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "variable snapshot version starts at one",
            ));
        }
        for name in values.keys() {
            validate_text("variable name", name)?;
        }
        let canonical = canonicalize_json(serde_json::to_value(&values)?);
        let encoded = serde_json::to_vec(&canonical)?;
        let digest = ContentDigest::sha256(&encoded);
        let values: BTreeMap<String, Value> = serde_json::from_value(canonical)?;
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO variable_snapshots
             (id, tenant_id, scope, version, values_json, digest, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                tenant_id,
                scope,
                to_i64(version)?,
                String::from_utf8(encoded).map_err(|_| ControlPlaneError::InvalidInput(
                    "canonical variable JSON must be UTF-8"
                ))?,
                digest.as_str(),
                to_i64(created_unix_ms)?,
            ],
        )?;
        Ok(VariableSnapshot {
            id: id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            scope: scope.to_owned(),
            version,
            values,
            digest,
            created_unix_ms,
        })
    }

    pub fn put_variable_idempotent(
        &self,
        idempotency_key: &str,
        tenant_id: &str,
        scope: &str,
        name: &str,
        value: Value,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<VariableRecord>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        for (field, value) in [
            ("variable tenant", tenant_id),
            ("variable scope", scope),
            ("variable name", name),
        ] {
            validate_text(field, value)?;
        }
        let canonical = canonicalize_json(value);
        let encoded = serde_json::to_string(&canonical)?;
        if encoded.len() > MAX_TEXT_BYTES * 16 {
            return Err(ControlPlaneError::InvalidInput(
                "variable value is too large",
            ));
        }
        let request_hash = ContentDigest::sha256(encoded.as_bytes());
        let operation = format!("variable.put:{tenant_id}:{scope}:{name}");
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let version = resource_id.parse::<u64>().map_err(|_| {
                ControlPlaneError::CorruptState("variable idempotency version".to_owned())
            })?;
            let value = variable_version_tx(&transaction, tenant_id, scope, name, version)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        let current: Option<i64> = transaction
            .query_row(
                "SELECT version FROM variables WHERE tenant_id = ?1 AND scope = ?2 AND name = ?3",
                params![tenant_id, scope, name],
                |row| row.get(0),
            )
            .optional()?;
        let version = current
            .map(|value| from_i64("variable version", value))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "variable version",
            })?;
        transaction.execute(
            "INSERT INTO variables(tenant_id, scope, name, value_json, version, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(tenant_id, scope, name) DO UPDATE SET
                 value_json = excluded.value_json,
                 version = excluded.version,
                 updated_unix_ms = excluded.updated_unix_ms",
            params![
                tenant_id,
                scope,
                name,
                encoded,
                to_i64(version)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO variable_versions
             (tenant_id, scope, name, version, value_json, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                tenant_id,
                scope,
                name,
                to_i64(version)?,
                serde_json::to_string(&canonical)?,
                to_i64(now_unix_ms)?,
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
                version.to_string(),
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: VariableRecord {
                tenant_id: tenant_id.to_owned(),
                scope: scope.to_owned(),
                name: name.to_owned(),
                value: canonical,
                version,
                updated_unix_ms: now_unix_ms,
            },
            replayed: false,
        })
    }

    pub fn variable(
        &self,
        tenant_id: &str,
        scope: &str,
        name: &str,
    ) -> Result<VariableRecord, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT tenant_id, scope, name, value_json, version, updated_unix_ms
                 FROM variables WHERE tenant_id = ?1 AND scope = ?2 AND name = ?3",
                params![tenant_id, scope, name],
                variable_row,
            )
            .optional()?
            .ok_or_else(|| not_found("variable", name))
    }

    pub fn list_variables(
        &self,
        tenant_id: &str,
        scope: &str,
    ) -> Result<Vec<VariableRecord>, ControlPlaneError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT tenant_id, scope, name, value_json, version, updated_unix_ms
             FROM variables WHERE tenant_id = ?1 AND scope = ?2 ORDER BY name",
        )?;
        let rows = statement.query_map(params![tenant_id, scope], variable_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn delete_variable(
        &self,
        tenant_id: &str,
        scope: &str,
        name: &str,
    ) -> Result<(), ControlPlaneError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "DELETE FROM variables WHERE tenant_id = ?1 AND scope = ?2 AND name = ?3",
            params![tenant_id, scope, name],
        )?;
        if changed == 0 {
            return Err(not_found("variable", name));
        }
        Ok(())
    }

    pub fn latest_variable_snapshot(
        &self,
        tenant_id: &str,
        scope: &str,
    ) -> Result<VariableSnapshot, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, tenant_id, scope, version, values_json, digest, created_unix_ms
                 FROM variable_snapshots WHERE tenant_id = ?1 AND scope = ?2
                 ORDER BY version DESC LIMIT 1",
                params![tenant_id, scope],
                variable_snapshot_row,
            )
            .optional()?
            .ok_or_else(|| not_found("variable snapshot", scope))
    }
}
