use super::*;
use rusqlite::params;

pub(super) fn api_token_by_id_conn(
    connection: &Connection,
    id: &str,
) -> Result<ApiTokenRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, principal_id, tenant_id, name, digest, scopes_json,
                    created_unix_ms, expires_unix_ms, last_used_unix_ms, revoked_unix_ms
             FROM api_tokens WHERE id = ?1",
            [id],
            api_token_row,
        )
        .optional()?
        .ok_or_else(|| not_found("API token", id))
}

pub(super) fn api_token_row(row: &Row<'_>) -> rusqlite::Result<ApiTokenRecord> {
    Ok(ApiTokenRecord {
        id: row.get(0)?,
        principal_id: row.get(1)?,
        tenant_id: row.get(2)?,
        name: row.get(3)?,
        digest: token_digest_column(row, 4)?,
        scopes: json_column(row, 5)?,
        created_unix_ms: u64_column(row, 6, "API token creation")?,
        expires_unix_ms: u64_column(row, 7, "API token expiry")?,
        last_used_unix_ms: optional_u64_column(row, 8, "API token last use")?,
        revoked_unix_ms: optional_u64_column(row, 9, "API token revocation")?,
    })
}

pub(super) fn validate_api_token_ancestry_tx(
    transaction: &Transaction<'_>,
    token_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    type ApiTokenAncestryRow = (
        String,
        String,
        String,
        i64,
        i64,
        Option<i64>,
        Option<String>,
    );
    let mut current = Some(token_id.to_owned());
    let mut child_binding: Option<(String, String, BTreeSet<String>, u64, u64)> = None;
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_API_TOKEN_ANCESTRY {
        let Some(id) = current.take() else {
            return Ok(());
        };
        if !seen.insert(id.clone()) {
            return Err(ControlPlaneError::CorruptState(
                "API token delegation ancestry contains a cycle".to_owned(),
            ));
        }
        let row: Option<ApiTokenAncestryRow> = transaction
            .query_row(
                "SELECT principal_id, tenant_id, scopes_json, created_unix_ms,
                        expires_unix_ms, revoked_unix_ms, parent_token_id
                 FROM api_tokens WHERE id = ?1",
                [&id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((principal_id, tenant_id, scopes, created, expires, revoked, parent)) = row else {
            return Err(AuthError::InvalidCredential.into());
        };
        let scopes: BTreeSet<String> = serde_json::from_str(&scopes)?;
        let created = from_i64("API token creation", created)?;
        let expires = from_i64("API token expiry", expires)?;
        if revoked.is_some() {
            return Err(AuthError::Revoked.into());
        }
        if now_unix_ms < created || now_unix_ms >= expires {
            return Err(AuthError::Expired.into());
        }
        if let Some((child_principal, child_tenant, child_scopes, child_created, child_expiry)) =
            child_binding.take()
        {
            if child_principal != principal_id
                || child_tenant != tenant_id
                || !child_scopes.is_subset(&scopes)
                || child_created < created
                || child_expiry > expires
            {
                return Err(ControlPlaneError::CorruptState(
                    "delegated API token ancestry broadens identity or expiry".to_owned(),
                ));
            }
        }
        child_binding = Some((principal_id, tenant_id, scopes, created, expires));
        current = parent;
    }
    if current.is_some() {
        return Err(ControlPlaneError::CorruptState(
            "API token delegation ancestry exceeds its bound".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn append_audit_event_tx(
    transaction: &Transaction<'_>,
    installation_id: &str,
    data: AuditEventData,
) -> Result<AuditEvent, ControlPlaneError> {
    let previous = transaction
        .query_row(
            "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let (sequence, previous_hash) = if let Some((sequence, hash)) = previous {
        let sequence = u64::try_from(sequence)
            .map_err(|_| ControlPlaneError::IntegerRange {
                field: "audit sequence",
            })?
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "audit sequence",
            })?;
        (sequence, Some(ContentDigest::parse(hash)?))
    } else {
        (1, None)
    };
    let event = AuditEvent::create(sequence, installation_id.to_owned(), previous_hash, data)?;
    transaction.execute(
        "INSERT INTO audit_events
         (sequence, installation_id, previous_hash, event_hash, event_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            to_i64(event.sequence)?,
            event.installation_id,
            event.previous_hash.as_ref().map(ContentDigest::as_str),
            event.event_hash.as_str(),
            serde_json::to_string(&event)?,
        ],
    )?;
    Ok(event)
}

impl ControlPlane {
    /// Persist an opaque API token record. Only its installation-keyed digest
    /// is stored; callers return the plaintext credential exactly once.
    pub fn create_api_token(
        &self,
        record: &ApiTokenRecord,
        actor: AuditPrincipal,
        request_id: &str,
    ) -> Result<(), ControlPlaneError> {
        self.create_api_token_bound(record, None, actor, request_id)
    }

    pub fn create_delegated_api_token(
        &self,
        record: &ApiTokenRecord,
        parent_token_id: &str,
        actor: AuditPrincipal,
        request_id: &str,
    ) -> Result<(), ControlPlaneError> {
        validate_text("parent API token id", parent_token_id)?;
        self.create_api_token_bound(record, Some(parent_token_id), actor, request_id)
    }

    fn create_api_token_bound(
        &self,
        record: &ApiTokenRecord,
        parent_token_id: Option<&str>,
        actor: AuditPrincipal,
        request_id: &str,
    ) -> Result<(), ControlPlaneError> {
        record.validate()?;
        validate_text("request id", request_id)?;
        let scopes = serde_json::to_string(&record.scopes)?;
        if scopes.len() > MAX_TEXT_BYTES {
            return Err(ControlPlaneError::InvalidInput(
                "API token scope encoding exceeds its durable bound",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(parent_token_id) = parent_token_id {
            validate_api_token_ancestry_tx(&transaction, parent_token_id, record.created_unix_ms)?;
            let parent = api_token_by_id_conn(&transaction, parent_token_id)?;
            if parent.principal_id != record.principal_id
                || parent.tenant_id != record.tenant_id
                || !record.scopes.is_subset(&parent.scopes)
                || record.expires_unix_ms > parent.expires_unix_ms
            {
                return Err(ControlPlaneError::InvalidInput(
                    "delegated API token exceeds its parent identity, tenant, scopes, or expiry",
                ));
            }
        }
        let token_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM api_tokens WHERE tenant_id = ?1",
            [&record.tenant_id],
            |row| row.get(0),
        )?;
        if token_count >= 10_000 {
            return Err(ControlPlaneError::InvalidInput(
                "API token limit reached for tenant",
            ));
        }
        transaction.execute(
            "INSERT INTO api_tokens
             (id, principal_id, tenant_id, name, digest, scopes_json,
              created_unix_ms, expires_unix_ms, last_used_unix_ms, revoked_unix_ms,
              parent_token_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.id,
                record.principal_id,
                record.tenant_id,
                record.name,
                record.digest.storage_key(),
                scopes,
                to_i64(record.created_unix_ms)?,
                to_i64(record.expires_unix_ms)?,
                record.last_used_unix_ms.map(to_i64).transpose()?,
                record.revoked_unix_ms.map(to_i64).transpose()?,
                parent_token_id,
            ],
        )?;
        let mut metadata = BTreeMap::from([
            (
                "principal_id".to_owned(),
                AuditValue::String(record.principal_id.clone()),
            ),
            (
                "scope_count".to_owned(),
                AuditValue::Integer(i64::try_from(record.scopes.len()).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "API token scope count",
                    }
                })?),
            ),
        ]);
        if let Some(parent_token_id) = parent_token_id {
            metadata.insert(
                "parent_token_id".to_owned(),
                AuditValue::String(parent_token_id.to_owned()),
            );
            metadata.insert(
                "actor_credential_id".to_owned(),
                AuditValue::String(parent_token_id.to_owned()),
            );
        }
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: record.created_unix_ms,
                tenant_id: record.tenant_id.clone(),
                actor,
                action: "api_token.create".to_owned(),
                resource: AuditResource {
                    kind: "api_token".to_owned(),
                    id: record.id.clone(),
                },
                result: "success".to_owned(),
                request_id: request_id.to_owned(),
                decision_id: None,
                metadata,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn api_token(&self, id: &str) -> Result<ApiTokenRecord, ControlPlaneError> {
        validate_text("API token id", id)?;
        let connection = self.connection()?;
        api_token_by_id_conn(&connection, id)
    }

    pub fn list_api_tokens(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ApiTokenRecord>, ControlPlaneError> {
        validate_text("tenant id", tenant_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, principal_id, tenant_id, name, digest, scopes_json,
                    created_unix_ms, expires_unix_ms, last_used_unix_ms, revoked_unix_ms
             FROM api_tokens WHERE tenant_id = ?1
             ORDER BY created_unix_ms, id LIMIT 10000",
        )?;
        let records = statement
            .query_map([tenant_id], api_token_row)?
            .collect::<Result<Vec<_>, _>>()?;
        for record in &records {
            record.validate().map_err(|error| {
                ControlPlaneError::CorruptState(format!("invalid API token record: {error}"))
            })?;
        }
        Ok(records)
    }

    pub fn list_api_tokens_page(
        &self,
        tenant_id: &str,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ApiTokenRecord>, ControlPlaneError> {
        validate_text("tenant id", tenant_id)?;
        validate_page(limit, after_id)?;
        let connection = self.connection()?;
        let sql = if after_id.is_some() {
            "SELECT id, principal_id, tenant_id, name, digest, scopes_json,
                    created_unix_ms, expires_unix_ms, last_used_unix_ms, revoked_unix_ms
             FROM api_tokens WHERE tenant_id = ?1 AND id > ?2
             ORDER BY id LIMIT ?3"
        } else {
            "SELECT id, principal_id, tenant_id, name, digest, scopes_json,
                    created_unix_ms, expires_unix_ms, last_used_unix_ms, revoked_unix_ms
             FROM api_tokens WHERE tenant_id = ?1
             ORDER BY id LIMIT ?3"
        };
        let mut statement = connection.prepare(sql)?;
        let records = statement
            .query_map(
                params![
                    tenant_id,
                    after_id.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| {
                        ControlPlaneError::InvalidInput("page limit is out of range")
                    })?
                ],
                api_token_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        for record in &records {
            record.validate().map_err(|error| {
                ControlPlaneError::CorruptState(format!("invalid API token record: {error}"))
            })?;
        }
        Ok(records)
    }

    /// Authenticate and record use in one immediate transaction. Looking up
    /// by the keyed digest avoids a timing-sensitive scan over token records.
    pub fn authenticate_api_token(
        &self,
        hasher: &TokenHasher,
        token: &str,
        required_scope: &str,
        now_unix_ms: u64,
    ) -> Result<AuthContext, ControlPlaneError> {
        if token.len() != 64
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthError::InvalidCredential.into());
        }
        let digest = hasher.api_token_digest(token).storage_key();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = transaction
            .query_row(
                "SELECT id, principal_id, tenant_id, name, digest, scopes_json,
                        created_unix_ms, expires_unix_ms, last_used_unix_ms, revoked_unix_ms
                 FROM api_tokens WHERE digest = ?1",
                [&digest],
                api_token_row,
            )
            .optional()?
            .ok_or(AuthError::InvalidCredential)?;
        record.validate().map_err(|error| {
            ControlPlaneError::CorruptState(format!("invalid API token record: {error}"))
        })?;
        validate_api_token_ancestry_tx(&transaction, &record.id, now_unix_ms)?;
        let context = record.authenticate(hasher, token, required_scope, now_unix_ms)?;
        transaction.execute(
            "UPDATE api_tokens SET last_used_unix_ms = ?1 WHERE id = ?2 AND digest = ?3",
            params![to_i64(now_unix_ms)?, record.id, digest],
        )?;
        transaction.commit()?;
        Ok(context)
    }

    pub fn revoke_api_token(
        &self,
        id: &str,
        actor: AuditPrincipal,
        request_id: &str,
        now_unix_ms: u64,
    ) -> Result<ApiTokenRecord, ControlPlaneError> {
        self.revoke_api_token_authenticated(id, actor, None, request_id, now_unix_ms)
    }

    pub fn revoke_api_token_authenticated(
        &self,
        id: &str,
        actor: AuditPrincipal,
        actor_credential_id: Option<&str>,
        request_id: &str,
        now_unix_ms: u64,
    ) -> Result<ApiTokenRecord, ControlPlaneError> {
        validate_text("API token id", id)?;
        validate_text("request id", request_id)?;
        if let Some(credential_id) = actor_credential_id {
            validate_text("actor credential id", credential_id)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = api_token_by_id_conn(&transaction, id)?;
        record.validate().map_err(|error| {
            ControlPlaneError::CorruptState(format!("invalid API token record: {error}"))
        })?;
        if now_unix_ms < record.created_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "API token revocation cannot precede creation",
            ));
        }
        if record.revoke(now_unix_ms) {
            transaction.execute(
                "UPDATE api_tokens SET revoked_unix_ms = ?1 WHERE id = ?2",
                params![to_i64(now_unix_ms)?, id],
            )?;
            append_audit_event_tx(
                &transaction,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: now_unix_ms,
                    tenant_id: record.tenant_id.clone(),
                    actor,
                    action: "api_token.revoke".to_owned(),
                    resource: AuditResource {
                        kind: "api_token".to_owned(),
                        id: record.id.clone(),
                    },
                    result: "success".to_owned(),
                    request_id: request_id.to_owned(),
                    decision_id: None,
                    metadata: actor_credential_id.map_or_else(BTreeMap::new, |credential_id| {
                        BTreeMap::from([(
                            "actor_credential_id".to_owned(),
                            AuditValue::String(credential_id.to_owned()),
                        )])
                    }),
                },
            )?;
        }
        transaction.commit()?;
        Ok(record)
    }
}
