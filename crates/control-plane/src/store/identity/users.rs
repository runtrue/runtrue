use super::*;
pub(in crate::store) fn human_user_row(row: &Row<'_>) -> rusqlite::Result<HumanUserRecord> {
    Ok(HumanUserRecord {
        id: row.get(0)?,
        display_name: row.get(1)?,
        primary_email: row.get(2)?,
        status: row.get(3)?,
        created_unix_ms: u64_column(row, 4, "human user creation")?,
        updated_unix_ms: u64_column(row, 5, "human user update")?,
        last_seen_unix_ms: optional_u64_column(row, 6, "human user last seen")?,
        version: u64_column(row, 7, "human user version")?,
    })
}

pub(in crate::store) fn human_identity_row(row: &Row<'_>) -> rusqlite::Result<HumanIdentityRecord> {
    Ok(HumanIdentityRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        user_id: row.get(2)?,
        provider_configuration_id: row.get(3)?,
        issuer: row.get(4)?,
        subject: row.get(5)?,
        provider_kind: row.get(6)?,
        claims_digest: digest_column(row, 7)?,
        created_unix_ms: u64_column(row, 8, "human identity creation")?,
        last_authenticated_unix_ms: u64_column(row, 9, "human identity authentication")?,
    })
}

impl ControlPlane {
    pub fn put_human_user(
        &self,
        tenant_id: &str,
        record: &HumanUserRecord,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        validate_r9_identifier(&record.id)?;
        validate_r9_identifier(&record.display_name)?;
        if record.primary_email.is_empty()
            || record.primary_email.len() > 320
            || !record.primary_email.contains('@')
            || record
                .primary_email
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || !matches!(record.status.as_str(), "active" | "suspended" | "disabled")
            || record.version == 0
            || record.updated_unix_ms < record.created_unix_ms
            || record
                .last_seen_unix_ms
                .is_some_and(|seen| seen < record.created_unix_ms)
        {
            return Err(ControlPlaneError::InvalidInput("invalid human user"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let existing = transaction
            .query_row(
                "SELECT id, display_name, primary_email, status, created_unix_ms,
                        updated_unix_ms, last_seen_unix_ms, version
                 FROM human_users WHERE id = ?1",
                [&record.id],
                human_user_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            let associated: bool = transaction.query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM human_user_tenant_bindings b
                    WHERE b.tenant_id = ?1 AND b.user_id = ?2
                   UNION ALL
                   SELECT 1 FROM tenant_memberships m
                    WHERE m.tenant_id = ?1 AND m.user_id = ?2
                   UNION ALL
                   SELECT 1 FROM human_identities i
                    JOIN tenant_oidc_provider_configs p
                      ON p.id = i.provider_configuration_id
                    WHERE p.tenant_id = ?1 AND i.user_id = ?2
                 )",
                params![tenant_id, record.id],
                |row| row.get(0),
            )?;
            if !associated {
                return Err(not_found("human user", &record.id));
            }
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
                            field: "human user version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "UPDATE human_users SET display_name = ?2, primary_email = ?3,
                    status = ?4, updated_unix_ms = ?5, last_seen_unix_ms = ?6,
                    version = ?7 WHERE id = ?1 AND version = ?8",
                params![
                    record.id,
                    record.display_name,
                    record.primary_email,
                    record.status,
                    to_i64(record.updated_unix_ms)?,
                    record.last_seen_unix_ms.map(to_i64).transpose()?,
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
            "INSERT INTO human_users
             (id, display_name, primary_email, status, created_unix_ms,
              updated_unix_ms, last_seen_unix_ms, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            params![
                record.id,
                record.display_name,
                record.primary_email,
                record.status,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?,
                record.last_seen_unix_ms.map(to_i64).transpose()?
            ],
        )?;
        transaction.execute(
            "INSERT INTO human_user_tenant_bindings
             (tenant_id, user_id, created_unix_ms) VALUES (?1, ?2, ?3)",
            params![tenant_id, record.id, to_i64(record.created_unix_ms)?],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn put_human_identity(
        &self,
        tenant_id: &str,
        record: &HumanIdentityRecord,
    ) -> Result<bool, ControlPlaneError> {
        for value in [
            &record.id,
            &record.tenant_id,
            &record.user_id,
            &record.provider_configuration_id,
            &record.issuer,
            &record.subject,
        ] {
            validate_r9_identifier(value)?;
        }
        if !matches!(
            record.provider_kind.as_str(),
            "oidc" | "github" | "recovery"
        ) || record.last_authenticated_unix_ms < record.created_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput("invalid human identity"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        if record.tenant_id != tenant_id {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let provider =
            oidc_provider_tx(&transaction, tenant_id, &record.provider_configuration_id)?
                .ok_or_else(|| {
                    not_found(
                        "OIDC provider configuration",
                        &record.provider_configuration_id,
                    )
                })?;
        if provider.issuer != record.issuer {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let user_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM human_user_tenant_bindings
             WHERE tenant_id = ?1 AND user_id = ?2)",
            params![tenant_id, record.user_id],
            |row| row.get(0),
        )?;
        if !user_exists {
            return Err(not_found("human user", &record.user_id));
        }
        let existing = transaction
            .query_row(
                "SELECT id, tenant_id, user_id, provider_configuration_id, issuer,
                        subject, provider_kind, claims_digest, created_unix_ms,
                        last_authenticated_unix_ms FROM human_identities
                 WHERE tenant_id = ?1 AND id = ?2",
                params![tenant_id, record.id],
                human_identity_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *record {
                transaction.commit()?;
                return Ok(false);
            }
            if record.tenant_id != existing.tenant_id
                || record.user_id != existing.user_id
                || record.provider_configuration_id != existing.provider_configuration_id
                || record.issuer != existing.issuer
                || record.subject != existing.subject
                || record.provider_kind != existing.provider_kind
                || record.created_unix_ms != existing.created_unix_ms
                || record.last_authenticated_unix_ms <= existing.last_authenticated_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = transaction.execute(
                "UPDATE human_identities SET claims_digest = ?3,
                    last_authenticated_unix_ms = ?4
                 WHERE tenant_id = ?1 AND id = ?2 AND last_authenticated_unix_ms = ?5",
                params![
                    tenant_id,
                    record.id,
                    record.claims_digest.as_str(),
                    to_i64(record.last_authenticated_unix_ms)?,
                    to_i64(existing.last_authenticated_unix_ms)?
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(true);
        }
        transaction.execute(
            "INSERT INTO human_identities
             (id, tenant_id, user_id, provider_configuration_id, issuer, subject,
              provider_kind, claims_digest, created_unix_ms, last_authenticated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.id,
                record.tenant_id,
                record.user_id,
                record.provider_configuration_id,
                record.issuer,
                record.subject,
                record.provider_kind,
                record.claims_digest.as_str(),
                to_i64(record.created_unix_ms)?,
                to_i64(record.last_authenticated_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Resolve one external subject without disclosing identities owned by a
    /// different tenant or configured provider. The tenant/provider gate is
    /// evaluated in the same transaction before the identity row is returned.
    pub fn human_identity_for_subject(
        &self,
        tenant_id: &str,
        provider_configuration_id: &str,
        issuer: &str,
        subject: &str,
    ) -> Result<HumanIdentityRecord, ControlPlaneError> {
        validate_r9_identifier(provider_configuration_id)?;
        validate_r9_https_uri(issuer, false)?;
        validate_r9_identifier(subject)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = transaction
            .query_row(
                "SELECT i.id, i.tenant_id, i.user_id, i.provider_configuration_id,
                        i.issuer, i.subject, i.provider_kind, i.claims_digest,
                        i.created_unix_ms, i.last_authenticated_unix_ms
                 FROM human_identities i
                 JOIN tenant_oidc_provider_configs p
                   ON p.tenant_id = i.tenant_id
                  AND p.id = i.provider_configuration_id
                 WHERE i.tenant_id = ?1 AND i.provider_configuration_id = ?2
                   AND i.issuer = ?3 AND i.subject = ?4
                   AND p.status = 'active' AND p.issuer = ?3",
                params![tenant_id, provider_configuration_id, issuer, subject],
                human_identity_row,
            )
            .optional()?
            .ok_or_else(|| not_found("human identity", subject))?;
        if record.tenant_id != tenant_id
            || record.provider_configuration_id != provider_configuration_id
            || record.issuer != issuer
            || record.subject != subject
        {
            return Err(ControlPlaneError::CorruptState(
                "human identity subject binding is inconsistent".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(record)
    }

    pub fn human_user_for_tenant(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<HumanUserRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let user = transaction
            .query_row(
                "SELECT u.id, u.display_name, u.primary_email, u.status,
                        u.created_unix_ms, u.updated_unix_ms, u.last_seen_unix_ms, u.version
                 FROM human_users u WHERE u.id = ?2 AND (
                   EXISTS(SELECT 1 FROM human_user_tenant_bindings b
                          WHERE b.tenant_id = ?1 AND b.user_id = u.id)
                   OR EXISTS(SELECT 1 FROM tenant_memberships m
                          WHERE m.tenant_id = ?1 AND m.user_id = u.id)
                   OR EXISTS(SELECT 1 FROM human_identities i
                      JOIN tenant_oidc_provider_configs p
                        ON p.id = i.provider_configuration_id
                      WHERE p.tenant_id = ?1 AND i.user_id = u.id)
                 )",
                params![tenant_id, user_id],
                human_user_row,
            )
            .optional()?
            .ok_or_else(|| not_found("human user", user_id))?;
        transaction.commit()?;
        Ok(user)
    }
}
