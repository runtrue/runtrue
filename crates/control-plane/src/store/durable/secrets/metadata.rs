// Explicit imports are kept local to the metadata/vault responsibility.
use super::super::{
    hash_serializable, idempotency_tx, not_found, optional_u64_column, params,
    require_same_idempotency, to_i64, u64_column, validate_idempotency_key, validate_text,
    BTreeMap, ContentDigest, ControlPlane, ControlPlaneError, IdempotentResult, MasterKey, Row,
    SecretIdentity, SecretMetadataReference, SecretPlaintext, SecretStatus, SecretVault,
    SecretVaultSnapshot, Serialize, Transaction, TransactionBehavior, Value,
    MAX_SECRET_SNAPSHOT_BYTES,
};
use rusqlite::OptionalExtension as _;

pub(in crate::store) fn validate_secret_metadata(
    metadata: &SecretMetadataReference,
) -> Result<(), ControlPlaneError> {
    validate_text("secret.id", &metadata.id)?;
    validate_text("secret.tenant_id", &metadata.tenant_id)?;
    validate_text("secret.scope", &metadata.scope)?;
    validate_text("secret.name", &metadata.name)?;
    validate_text("secret.provider", &metadata.provider)?;
    validate_text("secret.secret_type", &metadata.secret_type)?;
    validate_text("secret.status", &metadata.status)?;
    if let Some(reference) = &metadata.provider_reference {
        validate_text("secret.provider_reference", reference)?;
    }
    if metadata.current_version == Some(0) {
        return Err(ControlPlaneError::InvalidInput(
            "secret current version starts at one",
        ));
    }
    if metadata.updated_unix_ms < metadata.created_unix_ms {
        return Err(ControlPlaneError::InvalidInput(
            "secret update precedes creation",
        ));
    }
    Ok(())
}

pub(in crate::store) fn secret_metadata_row(
    row: &Row<'_>,
) -> rusqlite::Result<SecretMetadataReference> {
    Ok(SecretMetadataReference {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        scope: row.get(2)?,
        name: row.get(3)?,
        provider: row.get(4)?,
        provider_reference: row.get(5)?,
        secret_type: row.get(6)?,
        status: row.get(7)?,
        current_version: optional_u64_column(row, 8, "current_version")?,
        created_unix_ms: u64_column(row, 9, "created_unix_ms")?,
        updated_unix_ms: u64_column(row, 10, "updated_unix_ms")?,
    })
}

pub(in crate::store) fn secret_metadata_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<SecretMetadataReference, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, scope, name, provider, provider_reference,
                    secret_type, status, current_version, created_unix_ms, updated_unix_ms
             FROM secret_metadata WHERE id = ?1",
            [id],
            secret_metadata_row,
        )
        .optional()?
        .ok_or_else(|| not_found("secret metadata", id))
}

pub(in crate::store) fn secret_metadata_by_name_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    scope: &str,
    name: &str,
) -> Result<SecretMetadataReference, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, scope, name, provider, provider_reference,
                    secret_type, status, current_version, created_unix_ms, updated_unix_ms
             FROM secret_metadata WHERE tenant_id = ?1 AND scope = ?2 AND name = ?3",
            params![tenant_id, scope, name],
            secret_metadata_row,
        )
        .optional()?
        .ok_or_else(|| not_found("secret", name))
}

pub(in crate::store) fn insert_secret_metadata_tx(
    transaction: &Transaction<'_>,
    metadata: &SecretMetadataReference,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "INSERT INTO secret_metadata
         (id, tenant_id, scope, name, provider, provider_reference, secret_type,
          status, current_version, created_unix_ms, updated_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            metadata.id,
            metadata.tenant_id,
            metadata.scope,
            metadata.name,
            metadata.provider,
            metadata.provider_reference,
            metadata.secret_type,
            metadata.status,
            metadata.current_version.map(to_i64).transpose()?,
            to_i64(metadata.created_unix_ms)?,
            to_i64(metadata.updated_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn load_secret_vault_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    scope: &str,
    master_key: &MasterKey,
    installation_id: &str,
) -> Result<SecretVault, ControlPlaneError> {
    let bytes: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT snapshot_json FROM secret_vault_snapshots
             WHERE tenant_id = ?1 AND scope = ?2",
            params![tenant_id, scope],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(bytes) = bytes {
        if bytes.len() > MAX_SECRET_SNAPSHOT_BYTES {
            return Err(ControlPlaneError::CorruptState(
                "secret vault snapshot exceeds its durable bound".to_owned(),
            ));
        }
        let snapshot: SecretVaultSnapshot = serde_json::from_slice(&bytes)?;
        Ok(SecretVault::from_snapshot(
            snapshot,
            master_key.duplicate(),
        )?)
    } else {
        Ok(SecretVault::new(
            format!("control-plane:{installation_id}:v1"),
            master_key.duplicate(),
        )?)
    }
}

pub(in crate::store) fn store_secret_vault_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    scope: &str,
    vault: &SecretVault,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let bytes = serde_json::to_vec(&vault.snapshot())?;
    if bytes.len() > MAX_SECRET_SNAPSHOT_BYTES {
        return Err(ControlPlaneError::InvalidInput(
            "secret vault snapshot exceeds its durable bound",
        ));
    }
    transaction.execute(
        "INSERT INTO secret_vault_snapshots(tenant_id, scope, snapshot_json, updated_unix_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(tenant_id, scope) DO UPDATE SET
             snapshot_json = excluded.snapshot_json,
             updated_unix_ms = excluded.updated_unix_ms",
        params![tenant_id, scope, bytes, to_i64(now_unix_ms)?],
    )?;
    Ok(())
}

const fn secret_status_name(status: SecretStatus) -> &'static str {
    match status {
        SecretStatus::Active => "active",
        SecretStatus::Tombstoned => "tombstoned",
    }
}

pub(in crate::store) fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        value => value,
    }
}

impl ControlPlane {
    pub fn create_secret_idempotent(
        &self,
        idempotency_key: &str,
        metadata: &SecretMetadataReference,
        plaintext: Option<&SecretPlaintext>,
        master_key: &MasterKey,
    ) -> Result<IdempotentResult<SecretMetadataReference>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        validate_secret_metadata(metadata)?;
        let built_in = metadata.provider == "built-in";
        if built_in != plaintext.is_some()
            || (built_in && metadata.provider_reference.is_some())
            || (!built_in && metadata.provider_reference.is_none())
        {
            return Err(ControlPlaneError::InvalidInput(
                "built-in secrets require a value; external secrets require only a provider reference",
            ));
        }
        let value_digest = plaintext.map(|value| ContentDigest::sha256(value.as_bytes()));
        #[derive(Serialize)]
        struct Subject<'a> {
            tenant_id: &'a str,
            scope: &'a str,
            name: &'a str,
            provider: &'a str,
            provider_reference: &'a Option<String>,
            secret_type: &'a str,
            value_digest: &'a Option<ContentDigest>,
        }
        let request_hash = hash_serializable(&Subject {
            tenant_id: &metadata.tenant_id,
            scope: &metadata.scope,
            name: &metadata.name,
            provider: &metadata.provider,
            provider_reference: &metadata.provider_reference,
            secret_type: &metadata.secret_type,
            value_digest: &value_digest,
        })?;
        let operation = format!("secret.create:{}:{}", metadata.tenant_id, metadata.scope);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = secret_metadata_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        if built_in {
            let mut vault = load_secret_vault_tx(
                &transaction,
                &metadata.tenant_id,
                &metadata.scope,
                master_key,
                &self.installation_id,
            )?;
            let identity = SecretIdentity::new(
                metadata.tenant_id.clone(),
                metadata.scope.clone(),
                metadata.name.clone(),
            )?;
            let created = vault.create_secret(
                identity,
                plaintext.expect("built-in value was validated as present"),
            )?;
            if metadata.current_version != Some(created.current_version)
                || metadata.status != secret_status_name(created.status)
            {
                return Err(ControlPlaneError::InvalidInput(
                    "secret metadata does not match encrypted value state",
                ));
            }
            store_secret_vault_tx(
                &transaction,
                &metadata.tenant_id,
                &metadata.scope,
                &vault,
                metadata.updated_unix_ms,
            )?;
        }
        insert_secret_metadata_tx(&transaction, metadata)?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
                idempotency_key,
                request_hash.as_str(),
                metadata.id,
                to_i64(metadata.created_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: metadata.clone(),
            replayed: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rotate_secret_idempotent(
        &self,
        idempotency_key: &str,
        tenant_id: &str,
        scope: &str,
        name: &str,
        plaintext: &SecretPlaintext,
        master_key: &MasterKey,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<SecretMetadataReference>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        let request_hash = ContentDigest::sha256(plaintext.as_bytes());
        let operation = format!("secret.rotate:{tenant_id}:{scope}:{name}");
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = secret_metadata_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        let mut metadata = secret_metadata_by_name_tx(&transaction, tenant_id, scope, name)?;
        if metadata.provider != "built-in" || metadata.status != "active" {
            return Err(ControlPlaneError::InvalidInput(
                "only active built-in secrets can rotate values",
            ));
        }
        let mut vault = load_secret_vault_tx(
            &transaction,
            tenant_id,
            scope,
            master_key,
            &self.installation_id,
        )?;
        let identity = SecretIdentity::new(tenant_id, scope, name)?;
        let updated = vault.add_version(&identity, plaintext)?;
        metadata.current_version = Some(updated.current_version);
        metadata.updated_unix_ms = now_unix_ms;
        transaction.execute(
            "UPDATE secret_metadata SET current_version = ?2, updated_unix_ms = ?3 WHERE id = ?1",
            params![
                metadata.id,
                to_i64(updated.current_version)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        store_secret_vault_tx(&transaction, tenant_id, scope, &vault, now_unix_ms)?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
                idempotency_key,
                request_hash.as_str(),
                metadata.id,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: metadata,
            replayed: false,
        })
    }

    pub fn delete_secret(
        &self,
        tenant_id: &str,
        scope: &str,
        name: &str,
        master_key: &MasterKey,
        now_unix_ms: u64,
    ) -> Result<SecretMetadataReference, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut metadata = secret_metadata_by_name_tx(&transaction, tenant_id, scope, name)?;
        if metadata.status == "tombstoned" {
            transaction.commit()?;
            return Ok(metadata);
        }
        if metadata.provider == "built-in" {
            let mut vault = load_secret_vault_tx(
                &transaction,
                tenant_id,
                scope,
                master_key,
                &self.installation_id,
            )?;
            let identity = SecretIdentity::new(tenant_id, scope, name)?;
            vault.tombstone(&identity)?;
            store_secret_vault_tx(&transaction, tenant_id, scope, &vault, now_unix_ms)?;
        }
        "tombstoned".clone_into(&mut metadata.status);
        metadata.updated_unix_ms = now_unix_ms;
        transaction.execute(
            "UPDATE secret_metadata SET status = 'tombstoned', updated_unix_ms = ?2 WHERE id = ?1",
            params![metadata.id, to_i64(now_unix_ms)?],
        )?;
        transaction.commit()?;
        Ok(metadata)
    }

    pub fn secret_metadata_by_name(
        &self,
        tenant_id: &str,
        scope: &str,
        name: &str,
    ) -> Result<SecretMetadataReference, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, tenant_id, scope, name, provider, provider_reference,
                        secret_type, status, current_version, created_unix_ms, updated_unix_ms
                 FROM secret_metadata WHERE tenant_id = ?1 AND scope = ?2 AND name = ?3",
                params![tenant_id, scope, name],
                secret_metadata_row,
            )
            .optional()?
            .ok_or_else(|| not_found("secret", name))
    }

    /// Atomically authorize and consume one built-in secret release. The
    /// durable row is committed before plaintext leaves this adapter, so a
    /// crash or retry can never replay the value.
    pub fn store_secret_metadata(
        &self,
        metadata: &SecretMetadataReference,
    ) -> Result<(), ControlPlaneError> {
        validate_secret_metadata(metadata)?;
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO secret_metadata
             (id, tenant_id, scope, name, provider, provider_reference, secret_type,
              status, current_version, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                metadata.id,
                metadata.tenant_id,
                metadata.scope,
                metadata.name,
                metadata.provider,
                metadata.provider_reference,
                metadata.secret_type,
                metadata.status,
                metadata.current_version.map(to_i64).transpose()?,
                to_i64(metadata.created_unix_ms)?,
                to_i64(metadata.updated_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn secret_metadata(&self, id: &str) -> Result<SecretMetadataReference, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, tenant_id, scope, name, provider, provider_reference,
                        secret_type, status, current_version, created_unix_ms, updated_unix_ms
                 FROM secret_metadata WHERE id = ?1",
                [id],
                secret_metadata_row,
            )
            .optional()?
            .ok_or_else(|| not_found("secret metadata", id))
    }

    pub fn list_secret_metadata(
        &self,
        tenant_id: &str,
        scope: &str,
    ) -> Result<Vec<SecretMetadataReference>, ControlPlaneError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, scope, name, provider, provider_reference,
                    secret_type, status, current_version, created_unix_ms, updated_unix_ms
             FROM secret_metadata WHERE tenant_id = ?1 AND scope = ?2 ORDER BY name",
        )?;
        let values = statement
            .query_map(params![tenant_id, scope], secret_metadata_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }
}
