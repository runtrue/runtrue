use super::*;
// ---- Migration 23: one-use OIDC transactions and browser refresh families. ----

pub(in crate::store) fn oidc_transaction_status_name(
    status: OidcTransactionStatus,
) -> &'static str {
    match status {
        OidcTransactionStatus::Pending => "pending",
        OidcTransactionStatus::Exchanging => "exchanging",
        OidcTransactionStatus::Consumed => "consumed",
        OidcTransactionStatus::Rejected => "rejected",
        OidcTransactionStatus::Expired => "expired",
    }
}

pub(in crate::store) fn r9_record_digest(domain: &[u8], bytes: &[u8]) -> ContentDigest {
    let mut material = Vec::with_capacity(domain.len() + bytes.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(bytes);
    ContentDigest::sha256(material)
}

pub(in crate::store) fn load_oidc_transaction_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    transaction_id: &str,
) -> Result<Option<OidcAuthorizationTransaction>, ControlPlaneError> {
    type DurableOidcTransaction = (
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        Vec<u8>,
        String,
        i64,
    );
    let durable: Option<DurableOidcTransaction> = transaction
        .query_row(
            "SELECT provider_configuration_id, provider_configuration_digest,
                    provider_configuration_version, state_digest, nonce_digest,
                    pkce_verifier_digest, record_digest, record_json, status,
                    expires_unix_ms FROM oidc_browser_transactions
             WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, transaction_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()?;
    durable
        .map(|durable| {
            let (
                provider_id,
                provider_digest,
                provider_version,
                state_digest,
                nonce_digest,
                pkce_digest,
                stored_digest,
                bytes,
                status,
                expires,
            ) = durable;
            if bytes.len() > MAX_R9_AUTH_RECORD_BYTES {
                return Err(ControlPlaneError::CorruptState(
                    "OIDC browser transaction exceeds its durable bound".to_owned(),
                ));
            }
            let record: OidcAuthorizationTransaction = serde_json::from_slice(&bytes)?;
            record.validate()?;
            let digest = r9_record_digest(b"runtrue.oidc-browser-transaction.v1\0", &bytes);
            if record.tenant_id != tenant_id
                || record.id != transaction_id
                || record.provider_configuration_id != provider_id
                || ContentDigest::parse(provider_digest).is_err()
                || from_i64("OIDC provider configuration version", provider_version)? == 0
                || record.state_digest.storage_key() != state_digest
                || record.nonce_digest.storage_key() != nonce_digest
                || record.pkce_verifier_digest.storage_key() != pkce_digest
                || digest.as_str() != stored_digest
                || oidc_transaction_status_name(record.status) != status
                || record.expires_unix_ms != from_i64("OIDC transaction expiry", expires)?
            {
                return Err(ControlPlaneError::CorruptState(
                    "OIDC browser transaction durable binding changed".to_owned(),
                ));
            }
            Ok(record)
        })
        .transpose()
}

pub(in crate::store) fn same_oidc_transaction_binding(
    old: &OidcAuthorizationTransaction,
    new: &OidcAuthorizationTransaction,
) -> bool {
    old.id == new.id
        && old.tenant_id == new.tenant_id
        && old.provider_configuration_id == new.provider_configuration_id
        && old.issuer == new.issuer
        && old.client_id == new.client_id
        && old.redirect_uri == new.redirect_uri
        && old.state_digest == new.state_digest
        && old.nonce_digest == new.nonce_digest
        && old.pkce_verifier_digest == new.pkce_verifier_digest
        && old.pkce_challenge == new.pkce_challenge
        && old.created_unix_ms == new.created_unix_ms
        && old.expires_unix_ms == new.expires_unix_ms
}

pub(in crate::store) fn valid_oidc_transaction_transition(
    old: OidcTransactionStatus,
    new: OidcTransactionStatus,
) -> bool {
    matches!(
        (old, new),
        (
            OidcTransactionStatus::Pending,
            OidcTransactionStatus::Exchanging
        ) | (
            OidcTransactionStatus::Pending,
            OidcTransactionStatus::Rejected
        ) | (
            OidcTransactionStatus::Pending,
            OidcTransactionStatus::Expired
        ) | (
            OidcTransactionStatus::Exchanging,
            OidcTransactionStatus::Consumed
        ) | (
            OidcTransactionStatus::Exchanging,
            OidcTransactionStatus::Rejected
        ) | (
            OidcTransactionStatus::Exchanging,
            OidcTransactionStatus::Expired
        )
    )
}

pub(in crate::store) fn load_browser_session_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    session_id: &str,
) -> Result<Option<SessionRecord>, ControlPlaneError> {
    type DurableBrowserSession = (
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        Vec<u8>,
        i64,
        i64,
        i64,
        Option<i64>,
    );
    let durable: Option<DurableBrowserSession> = transaction
        .query_row(
            "SELECT user_id, device_id, access_generation, access_digest,
                    refresh_digest, csrf_digest, record_digest, record_json,
                    access_expires_unix_ms, refresh_expires_unix_ms,
                    absolute_expires_unix_ms, revoked_unix_ms
             FROM browser_sessions WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, session_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()?;
    durable
        .map(|durable| {
            let (
                user_id,
                device_id,
                generation,
                access_digest,
                refresh_digest,
                csrf_digest,
                stored_digest,
                bytes,
                access_expires,
                refresh_expires,
                absolute_expires,
                revoked,
            ) = durable;
            if bytes.len() > MAX_R9_AUTH_RECORD_BYTES {
                return Err(ControlPlaneError::CorruptState(
                    "browser session exceeds its durable bound".to_owned(),
                ));
            }
            let record: SessionRecord = serde_json::from_slice(&bytes)?;
            record.validate()?;
            let digest = r9_record_digest(b"runtrue.browser-session-record.v1\0", &bytes);
            if record.tenant_id != tenant_id
                || record.id != session_id
                || record.principal_id != user_id
                || record.device_id != device_id
                || record.access_generation != from_i64("browser access generation", generation)?
                || record.access_digest.storage_key() != access_digest
                || record.refresh_digest.storage_key() != refresh_digest
                || record.csrf_digest.storage_key() != csrf_digest
                || digest.as_str() != stored_digest
                || record.access_expires_unix_ms
                    != from_i64("browser access expiry", access_expires)?
                || record.refresh_expires_unix_ms
                    != from_i64("browser refresh expiry", refresh_expires)?
                || record.absolute_expires_unix_ms
                    != from_i64("browser absolute expiry", absolute_expires)?
                || record.revoked_unix_ms
                    != revoked
                        .map(|value| from_i64("browser revocation", value))
                        .transpose()?
            {
                return Err(ControlPlaneError::CorruptState(
                    "browser session durable binding changed".to_owned(),
                ));
            }
            Ok(record)
        })
        .transpose()
}

pub(in crate::store) fn require_active_browser_principal_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    user_id: &str,
) -> Result<(), ControlPlaneError> {
    let active: bool = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM human_users u
           JOIN human_user_tenant_bindings b ON b.user_id = u.id AND b.tenant_id = ?1
           JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = b.tenant_id
           WHERE u.id = ?2 AND u.status = 'active' AND m.status = 'active'
         )",
        params![tenant_id, user_id],
        |row| row.get(0),
    )?;
    if !active {
        return Err(not_found("active browser principal", user_id));
    }
    Ok(())
}

pub(in crate::store) fn validate_session_transition(
    old: &SessionRecord,
    new: &SessionRecord,
) -> Option<&'static str> {
    fn optional_time_monotonic(old: Option<u64>, new: Option<u64>) -> bool {
        match (old, new) {
            (Some(_), None) => false,
            (Some(old), Some(new)) => new >= old,
            (None, _) => true,
        }
    }
    if old.id != new.id
        || old.tenant_id != new.tenant_id
        || old.principal_id != new.principal_id
        || old.device_id != new.device_id
        || old.scopes != new.scopes
        || old.created_unix_ms != new.created_unix_ms
        || old.absolute_expires_unix_ms != new.absolute_expires_unix_ms
        || old.revoked_unix_ms.is_some()
        || !optional_time_monotonic(old.mfa_authenticated_unix_ms, new.mfa_authenticated_unix_ms)
        || !optional_time_monotonic(old.reauthenticated_unix_ms, new.reauthenticated_unix_ms)
    {
        return None;
    }
    let next_generation = old.access_generation.checked_add(1)?;
    let next_used_count = old.used_refresh_digests.len().checked_add(1)?;
    if new.access_generation == next_generation
        && new.revoked_unix_ms.is_none()
        && new.used_refresh_digests.len() == next_used_count
        && new
            .used_refresh_digests
            .starts_with(&old.used_refresh_digests)
        && new.used_refresh_digests.last() == Some(&old.refresh_digest)
    {
        return Some("rotated");
    }
    if new.access_generation == old.access_generation
        && new.access_digest == old.access_digest
        && new.refresh_digest == old.refresh_digest
        && new.csrf_digest == old.csrf_digest
        && new.access_expires_unix_ms == old.access_expires_unix_ms
        && new.refresh_expires_unix_ms == old.refresh_expires_unix_ms
        && new.used_refresh_digests == old.used_refresh_digests
    {
        return if new.revoked_unix_ms.is_some() {
            Some("revoked")
        } else {
            Some("reauthenticated")
        };
    }
    None
}

impl ControlPlane {
    pub fn persist_oidc_browser_transaction(
        &self,
        record: &OidcAuthorizationTransaction,
        audit: &R9AuditMetadata,
    ) -> Result<bool, ControlPlaneError> {
        record.validate()?;
        validate_r9_audit_text(&audit.actor_id)?;
        validate_r9_audit_text(&audit.correlation_id)?;
        if audit.occurred_unix_ms < record.created_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "OIDC transaction audit time precedes creation",
            ));
        }
        if audit.occurred_unix_ms >= record.expires_unix_ms
            && record.status != OidcTransactionStatus::Expired
        {
            return Err(ControlPlaneError::InvalidInput(
                "non-expired OIDC transaction recorded after expiry",
            ));
        }
        let bytes = r9_json_bytes(record, MAX_R9_AUTH_RECORD_BYTES)?;
        let digest = r9_record_digest(b"runtrue.oidc-browser-transaction.v1\0", &bytes);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        let provider = oidc_provider_tx(
            &transaction,
            &record.tenant_id,
            &record.provider_configuration_id,
        )?
        .ok_or_else(|| {
            not_found(
                "OIDC provider configuration",
                &record.provider_configuration_id,
            )
        })?;
        if provider.issuer != record.issuer
            || provider.client_id != record.client_id
            || provider.redirect_uri != record.redirect_uri
            || provider.status != "active"
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let stored_provider_binding: Option<(String, i64)> = transaction
            .query_row(
                "SELECT provider_configuration_digest, provider_configuration_version
                 FROM oidc_browser_transactions WHERE tenant_id = ?1 AND id = ?2",
                params![record.tenant_id, record.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if stored_provider_binding
            .as_ref()
            .is_some_and(|(digest, version)| {
                digest != provider.configuration_digest.as_str()
                    || u64::try_from(*version).ok() != Some(provider.version)
            })
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if let Some(existing) =
            load_oidc_transaction_tx(&transaction, &record.tenant_id, &record.id)?
        {
            if existing == *record {
                transaction.commit()?;
                return Ok(false);
            }
            if !same_oidc_transaction_binding(&existing, record)
                || !valid_oidc_transaction_transition(existing.status, record.status)
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "UPDATE oidc_browser_transactions SET record_digest = ?3,
                    record_json = ?4, status = ?5, updated_unix_ms = ?6,
                    audit_correlation_id = ?7 WHERE tenant_id = ?1 AND id = ?2",
                params![
                    record.tenant_id,
                    record.id,
                    digest.as_str(),
                    bytes,
                    oidc_transaction_status_name(record.status),
                    to_i64(audit.occurred_unix_ms)?,
                    audit.correlation_id
                ],
            )?;
        } else {
            if record.status != OidcTransactionStatus::Pending {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "INSERT INTO oidc_browser_transactions
                 (id, tenant_id, provider_configuration_id,
                  provider_configuration_digest, provider_configuration_version,
                  state_digest, nonce_digest, pkce_verifier_digest, record_digest,
                  record_json, status, expires_unix_ms, audit_correlation_id,
                  created_unix_ms, updated_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                         'pending', ?11, ?12, ?13, ?14)",
                params![
                    record.id,
                    record.tenant_id,
                    record.provider_configuration_id,
                    provider.configuration_digest.as_str(),
                    to_i64(provider.version)?,
                    record.state_digest.storage_key(),
                    record.nonce_digest.storage_key(),
                    record.pkce_verifier_digest.storage_key(),
                    digest.as_str(),
                    bytes,
                    to_i64(record.expires_unix_ms)?,
                    audit.correlation_id,
                    to_i64(record.created_unix_ms)?,
                    to_i64(audit.occurred_unix_ms)?
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO oidc_browser_transaction_events
             (transaction_id, tenant_id, status, record_digest,
              audit_correlation_id, occurred_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.id,
                record.tenant_id,
                oidc_transaction_status_name(record.status),
                digest.as_str(),
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn oidc_browser_transaction(
        &self,
        tenant_id: &str,
        transaction_id: &str,
    ) -> Result<OidcAuthorizationTransaction, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = load_oidc_transaction_tx(&transaction, tenant_id, transaction_id)?
            .ok_or_else(|| not_found("OIDC browser transaction", transaction_id))?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn persist_browser_session(
        &self,
        record: &SessionRecord,
        expected_generation: Option<u64>,
        audit: &R9AuditMetadata,
    ) -> Result<bool, ControlPlaneError> {
        record.validate()?;
        validate_r9_audit_text(&audit.actor_id)?;
        validate_r9_audit_text(&audit.correlation_id)?;
        if audit.occurred_unix_ms < record.created_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "browser session audit time precedes creation",
            ));
        }
        let bytes = r9_json_bytes(record, MAX_R9_AUTH_RECORD_BYTES)?;
        let digest = r9_record_digest(b"runtrue.browser-session-record.v1\0", &bytes);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        require_active_browser_principal_tx(&transaction, &record.tenant_id, &record.principal_id)?;
        let existing = load_browser_session_tx(&transaction, &record.tenant_id, &record.id)?;
        let event_kind;
        if let Some(existing) = existing {
            if existing == *record {
                transaction.commit()?;
                return Ok(false);
            }
            if expected_generation != Some(existing.access_generation) {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            event_kind = validate_session_transition(&existing, record)
                .ok_or(ControlPlaneError::IdempotencyConflict)?;
            if event_kind == "rotated" {
                let changed = transaction.execute(
                    "UPDATE browser_refresh_family_tokens
                     SET status = 'consumed', consumed_unix_ms = ?3
                     WHERE tenant_id = ?1 AND session_id = ?2 AND status = 'active'
                       AND generation = ?4 AND refresh_digest = ?5",
                    params![
                        record.tenant_id,
                        record.id,
                        to_i64(audit.occurred_unix_ms)?,
                        to_i64(existing.access_generation)?,
                        existing.refresh_digest.storage_key()
                    ],
                )?;
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                transaction.execute(
                    "INSERT INTO browser_refresh_family_tokens
                     (session_id, tenant_id, generation, refresh_digest, status,
                      created_unix_ms, consumed_unix_ms)
                     VALUES (?1, ?2, ?3, ?4, 'active', ?5, NULL)",
                    params![
                        record.id,
                        record.tenant_id,
                        to_i64(record.access_generation)?,
                        record.refresh_digest.storage_key(),
                        to_i64(audit.occurred_unix_ms)?
                    ],
                )?;
            } else if event_kind == "revoked" {
                transaction.execute(
                    "UPDATE browser_refresh_family_tokens
                     SET status = 'revoked', consumed_unix_ms = ?3
                     WHERE tenant_id = ?1 AND session_id = ?2 AND status = 'active'",
                    params![
                        record.tenant_id,
                        record.id,
                        to_i64(record.revoked_unix_ms.unwrap_or(audit.occurred_unix_ms))?
                    ],
                )?;
            }
            transaction.execute(
                "UPDATE browser_sessions SET access_generation = ?3,
                    access_digest = ?4, refresh_digest = ?5, csrf_digest = ?6,
                    record_digest = ?7, record_json = ?8, access_expires_unix_ms = ?9,
                    refresh_expires_unix_ms = ?10, revoked_unix_ms = ?11,
                    audit_correlation_id = ?12, updated_unix_ms = ?13
                 WHERE tenant_id = ?1 AND id = ?2 AND access_generation = ?14",
                params![
                    record.tenant_id,
                    record.id,
                    to_i64(record.access_generation)?,
                    record.access_digest.storage_key(),
                    record.refresh_digest.storage_key(),
                    record.csrf_digest.storage_key(),
                    digest.as_str(),
                    bytes,
                    to_i64(record.access_expires_unix_ms)?,
                    to_i64(record.refresh_expires_unix_ms)?,
                    record.revoked_unix_ms.map(to_i64).transpose()?,
                    audit.correlation_id,
                    to_i64(audit.occurred_unix_ms)?,
                    to_i64(existing.access_generation)?
                ],
            )?;
        } else {
            if expected_generation.is_some() || record.access_generation != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            event_kind = "created";
            transaction.execute(
                "INSERT INTO browser_sessions
                 (id, tenant_id, user_id, device_id, access_generation,
                  access_digest, refresh_digest, csrf_digest, record_digest, record_json,
                  access_expires_unix_ms, refresh_expires_unix_ms,
                  absolute_expires_unix_ms, revoked_unix_ms, audit_correlation_id,
                  created_unix_ms, updated_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15, ?16)",
                params![
                    record.id,
                    record.tenant_id,
                    record.principal_id,
                    record.device_id,
                    record.access_digest.storage_key(),
                    record.refresh_digest.storage_key(),
                    record.csrf_digest.storage_key(),
                    digest.as_str(),
                    bytes,
                    to_i64(record.access_expires_unix_ms)?,
                    to_i64(record.refresh_expires_unix_ms)?,
                    to_i64(record.absolute_expires_unix_ms)?,
                    record.revoked_unix_ms.map(to_i64).transpose()?,
                    audit.correlation_id,
                    to_i64(record.created_unix_ms)?,
                    to_i64(audit.occurred_unix_ms)?
                ],
            )?;
            transaction.execute(
                "INSERT INTO browser_refresh_family_tokens
                 (session_id, tenant_id, generation, refresh_digest, status,
                  created_unix_ms, consumed_unix_ms)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6)",
                params![
                    record.id,
                    record.tenant_id,
                    record.refresh_digest.storage_key(),
                    if record.revoked_unix_ms.is_some() {
                        "revoked"
                    } else {
                        "active"
                    },
                    to_i64(record.created_unix_ms)?,
                    record.revoked_unix_ms.map(to_i64).transpose()?
                ],
            )?;
        }
        let event_material = (
            &record.tenant_id,
            &record.id,
            event_kind,
            record.access_generation,
            &digest,
            &audit.correlation_id,
            audit.occurred_unix_ms,
        );
        let event_bytes = r9_json_bytes(&event_material, 64 * 1024)?;
        let event_digest = r9_record_digest(b"runtrue.browser-session-event.v1\0", &event_bytes);
        transaction.execute(
            "INSERT INTO browser_session_events
             (session_id, tenant_id, event_digest, event_kind, access_generation,
              audit_correlation_id, occurred_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.id,
                record.tenant_id,
                event_digest.as_str(),
                event_kind,
                to_i64(record.access_generation)?,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn browser_session(
        &self,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<SessionRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = load_browser_session_tx(&transaction, tenant_id, session_id)?
            .ok_or_else(|| not_found("browser session", session_id))?;
        require_active_browser_principal_tx(&transaction, tenant_id, &record.principal_id)?;
        transaction.commit()?;
        Ok(record)
    }
}
