use super::*;
pub(in crate::store) fn membership_row(row: &Row<'_>) -> rusqlite::Result<TenantMembershipRecord> {
    Ok(TenantMembershipRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        user_id: row.get(2)?,
        role_template: row.get(3)?,
        attributes: bounded_json_blob_column(
            row,
            4,
            MAX_R9_IDENTITY_JSON_BYTES,
            "membership attributes JSON",
        )?,
        attributes_digest: digest_column(row, 5)?,
        status: row.get(6)?,
        created_unix_ms: u64_column(row, 7, "membership creation")?,
        updated_unix_ms: u64_column(row, 8, "membership update")?,
        version: u64_column(row, 9, "membership version")?,
    })
}

impl ControlPlane {
    pub fn put_tenant_membership(
        &self,
        record: &TenantMembershipRecord,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        for value in [
            &record.id,
            &record.tenant_id,
            &record.user_id,
            &record.role_template,
        ] {
            validate_r9_identifier(value)?;
        }
        let attributes = r9_json_bytes(&record.attributes, MAX_R9_IDENTITY_JSON_BYTES)?;
        if record.expected_attributes_digest()? != record.attributes_digest
            || !matches!(record.status.as_str(), "active" | "suspended" | "revoked")
            || record.version == 0
            || record.updated_unix_ms < record.created_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput("invalid tenant membership"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        let user_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM human_user_tenant_bindings
             WHERE tenant_id = ?1 AND user_id = ?2)",
            params![record.tenant_id, record.user_id],
            |row| row.get(0),
        )?;
        if !user_exists {
            return Err(not_found("human user", &record.user_id));
        }
        let existing = transaction
            .query_row(
                "SELECT id, tenant_id, user_id, role_template, attributes_json,
                        attributes_digest, status, created_unix_ms, updated_unix_ms,
                        version FROM tenant_memberships WHERE tenant_id = ?1 AND id = ?2",
                params![record.tenant_id, record.id],
                membership_row,
            )
            .optional()?;
        if let Some(existing) = existing {
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
                            field: "tenant membership version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
                || record.tenant_id != existing.tenant_id
                || record.user_id != existing.user_id
                || record.role_template != existing.role_template
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "UPDATE tenant_memberships SET attributes_json = ?3,
                    attributes_digest = ?4, status = ?5, updated_unix_ms = ?6,
                    version = ?7 WHERE tenant_id = ?1 AND id = ?2 AND version = ?8",
                params![
                    record.tenant_id,
                    record.id,
                    attributes,
                    record.attributes_digest.as_str(),
                    record.status,
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
            "INSERT INTO tenant_memberships
             (id, tenant_id, user_id, role_template, attributes_json,
              attributes_digest, status, created_unix_ms, updated_unix_ms, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)",
            params![
                record.id,
                record.tenant_id,
                record.user_id,
                record.role_template,
                attributes,
                record.attributes_digest.as_str(),
                record.status,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }
}
