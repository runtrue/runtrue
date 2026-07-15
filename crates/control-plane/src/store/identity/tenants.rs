use super::*;

impl ControlPlane {
    pub fn put_tenant_identity(
        &self,
        record: &TenantIdentityRecord,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        let settings = validate_tenant_identity(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tenant_identity_tx(&transaction, &record.id)? {
            if existing == *record {
                transaction.commit()?;
                return Ok(false);
            }
            if expected_version != Some(existing.version)
                || record.version
                    != existing
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "tenant version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "UPDATE tenants SET slug = ?2, name = ?3, status = ?4,
                    settings_json = ?5, updated_unix_ms = ?6, version = ?7
                 WHERE id = ?1 AND version = ?8",
                params![
                    record.id,
                    record.slug,
                    record.name,
                    record.status,
                    settings,
                    to_i64(record.updated_unix_ms)?,
                    to_i64(record.version)?,
                    to_i64(existing.version)?
                ],
            )?;
            transaction.commit()?;
            return Ok(true);
        }
        if expected_version.is_some() || record.version != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO tenants
             (id, slug, name, status, settings_json, created_unix_ms,
              updated_unix_ms, version) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            params![
                record.id,
                record.slug,
                record.name,
                record.status,
                settings,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn tenant_identity(
        &self,
        tenant_id: &str,
    ) -> Result<TenantIdentityRecord, ControlPlaneError> {
        validate_r9_identifier(tenant_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, slug, name, status, settings_json, created_unix_ms,
                        updated_unix_ms, version FROM tenants WHERE id = ?1",
                [tenant_id],
                tenant_identity_row,
            )
            .optional()?
            .ok_or_else(|| not_found("tenant", tenant_id))
    }
}
