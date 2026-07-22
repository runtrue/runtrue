use super::*;

// ---- Migration 24: external providers, environments, and deployments. ----

pub(in crate::store) fn r10_json_bytes<T: Serialize + ?Sized>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ControlPlaneError> {
    let canonical = canonicalize_json(serde_json::to_value(value)?);
    let bytes = serde_json::to_vec(&canonical)?;
    if bytes.len() > maximum {
        return Err(ControlPlaneError::InvalidInput(
            "R10 durable record exceeds its byte bound",
        ));
    }
    Ok(bytes)
}

pub(in crate::store) fn validate_r10_identifier(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ControlPlaneError::InvalidInput("invalid R10 identifier"));
    }
    Ok(())
}

pub(in crate::store) fn validate_r10_endpoint(
    capability: &str,
    value: &str,
) -> Result<(), ControlPlaneError> {
    if value.len() > 2048
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.chars().any(char::is_whitespace)
        || value.contains(['?', '#', '\\', '@'])
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid provider endpoint origin",
        ));
    }
    if let Some(authority) = value.strip_prefix("https://") {
        if authority.is_empty()
            || authority.contains('/')
            || authority.starts_with('.')
            || authority.ends_with('.')
            || authority.ends_with(':')
        {
            return Err(ControlPlaneError::InvalidInput(
                "invalid provider HTTPS origin",
            ));
        }
        return Ok(());
    }
    if capability == "signing" {
        if let Some(path) = value.strip_prefix("unix://") {
            if !path.starts_with('/')
                || path.split('/').any(|component| component == "..")
                || path.ends_with('/')
            {
                return Err(ControlPlaneError::InvalidInput(
                    "invalid signer Unix endpoint",
                ));
            }
            return Ok(());
        }
    }
    Err(ControlPlaneError::InvalidInput(
        "provider endpoint must use an allowed explicit transport",
    ))
}

pub(in crate::store) fn provider_configuration_row(
    row: &Row<'_>,
) -> rusqlite::Result<TenantProviderConfiguration> {
    Ok(TenantProviderConfiguration {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        capability: row.get(2)?,
        provider_kind: row.get(3)?,
        endpoint_origin: row.get(4)?,
        credential_reference: row.get(5)?,
        trust_bundle_digest: digest_column(row, 6)?,
        public_key_digest: optional_digest_column(row, 7)?,
        configuration_digest: digest_column(row, 8)?,
        status: row.get(9)?,
        created_unix_ms: u64_column(row, 10, "provider configuration creation")?,
        updated_unix_ms: u64_column(row, 11, "provider configuration update")?,
        version: u64_column(row, 12, "provider configuration version")?,
    })
}

pub(in crate::store) fn provider_configuration_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    provider_id: &str,
) -> Result<Option<TenantProviderConfiguration>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            "SELECT id, tenant_id, capability, provider_kind, endpoint_origin,
                    credential_reference, trust_bundle_digest, public_key_digest,
                    configuration_digest, status, created_unix_ms, updated_unix_ms,
                    version FROM tenant_provider_configurations
             WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, provider_id],
            provider_configuration_row,
        )
        .optional()?)
}

pub(crate) fn validate_provider_configuration(
    record: &TenantProviderConfiguration,
) -> Result<(), ControlPlaneError> {
    for value in [&record.id, &record.tenant_id, &record.provider_kind] {
        validate_r10_identifier(value)?;
    }
    let reference_prefix = match record.capability.as_str() {
        "external-secret" => "secret-metadata://",
        "signing" => "signer-identity://",
        _ => "",
    };
    let reference_id = record
        .credential_reference
        .strip_prefix(reference_prefix)
        .unwrap_or_default();
    if !matches!(record.capability.as_str(), "external-secret" | "signing")
        || !matches!(record.status.as_str(), "active" | "disabled" | "retired")
        || reference_id.is_empty()
        || record.credential_reference.len() > 4096
        || record
            .credential_reference
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || reference_id.len() > 512
        || !reference_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
        || (record.capability == "signing") != record.public_key_digest.is_some()
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid tenant provider configuration",
        ));
    }
    validate_r10_endpoint(&record.capability, &record.endpoint_origin)?;
    if record.expected_configuration_digest()? != record.configuration_digest {
        return Err(ControlPlaneError::InvalidInput(
            "provider configuration digest mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn provider_configuration_snapshot(
    record: &TenantProviderConfiguration,
) -> Result<(Vec<u8>, ContentDigest), ControlPlaneError> {
    let bytes = r10_json_bytes(record, 256 * 1024)?;
    let mut material = b"runtrue.provider-configuration-version.v1\0".to_vec();
    material.extend_from_slice(&bytes);
    Ok((bytes, ContentDigest::sha256(material)))
}

pub(in crate::store) fn insert_provider_configuration_version_tx(
    transaction: &Transaction<'_>,
    record: &TenantProviderConfiguration,
) -> Result<(), ControlPlaneError> {
    let (bytes, digest) = provider_configuration_snapshot(record)?;
    transaction.execute(
        "INSERT INTO tenant_provider_configuration_versions
         (tenant_id, provider_configuration_id, version, snapshot_digest,
          snapshot_json, created_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            record.tenant_id,
            record.id,
            to_i64(record.version)?,
            digest.as_str(),
            bytes,
            to_i64(record.updated_unix_ms)?
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn require_provider_configuration_version_tx(
    transaction: &Transaction<'_>,
    record: &TenantProviderConfiguration,
) -> Result<(), ControlPlaneError> {
    let (bytes, digest) = provider_configuration_snapshot(record)?;
    let durable: Option<(String, Vec<u8>)> = transaction
        .query_row(
            "SELECT snapshot_digest, snapshot_json
             FROM tenant_provider_configuration_versions
             WHERE tenant_id = ?1 AND provider_configuration_id = ?2 AND version = ?3",
            params![record.tenant_id, record.id, to_i64(record.version)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if durable != Some((digest.to_string(), bytes)) {
        return Err(ControlPlaneError::CorruptState(
            "provider configuration version snapshot changed".to_owned(),
        ));
    }
    Ok(())
}

pub(in crate::store) fn validate_sorted_r10_identifiers(
    values: &[String],
) -> Result<(), ControlPlaneError> {
    if values.len() > MAX_R10_IDENTIFIERS {
        return Err(ControlPlaneError::InvalidInput(
            "too many environment rule identifiers",
        ));
    }
    for value in values {
        validate_r10_identifier(value)?;
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ControlPlaneError::InvalidInput(
            "environment rule identifiers must be sorted and unique",
        ));
    }
    Ok(())
}

pub(in crate::store) fn signer_policy_row(row: &Row<'_>) -> rusqlite::Result<SignerPolicyRecord> {
    Ok(SignerPolicyRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        provider_configuration_id: row.get(2)?,
        provider_configuration_digest: digest_column(row, 3)?,
        provider_configuration_version: u64_column(row, 4, "signer provider version")?,
        backend_key_reference: row.get(5)?,
        purpose: row.get(6)?,
        operation: row.get(7)?,
        public_key_digest: digest_column(row, 8)?,
        policy_digest: digest_column(row, 9)?,
        status: row.get(10)?,
        created_unix_ms: u64_column(row, 11, "signer policy creation")?,
        updated_unix_ms: u64_column(row, 12, "signer policy update")?,
        version: u64_column(row, 13, "signer policy version")?,
    })
}

pub(in crate::store) fn signer_policy_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    policy_id: &str,
) -> Result<Option<SignerPolicyRecord>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            "SELECT id, tenant_id, provider_configuration_id,
                    provider_configuration_digest, provider_configuration_version,
                    backend_key_reference, purpose, operation, public_key_digest,
                    policy_digest, status, created_unix_ms, updated_unix_ms, version
             FROM signer_policies WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, policy_id],
            signer_policy_row,
        )
        .optional()?)
}

pub(crate) fn validate_signer_policy(record: &SignerPolicyRecord) -> Result<(), ControlPlaneError> {
    for value in [
        &record.id,
        &record.tenant_id,
        &record.provider_configuration_id,
        &record.purpose,
    ] {
        validate_r10_identifier(value)?;
    }
    let key_id = record
        .backend_key_reference
        .strip_prefix("signer-key://")
        .unwrap_or_default();
    if key_id.is_empty()
        || key_id.len() > 512
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !matches!(
            record.operation.as_str(),
            "sign-digest" | "sign-attestation"
        )
        || !matches!(record.status.as_str(), "active" | "disabled" | "retired")
        || record.provider_configuration_version == 0
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
        || record.expected_policy_digest()? != record.policy_digest
    {
        return Err(ControlPlaneError::InvalidInput("invalid signer policy"));
    }
    Ok(())
}

pub(crate) fn signer_policy_snapshot(
    record: &SignerPolicyRecord,
) -> Result<(Vec<u8>, ContentDigest), ControlPlaneError> {
    let bytes = r10_json_bytes(record, 256 * 1024)?;
    let mut material = b"runtrue.signer-policy-version.v1\0".to_vec();
    material.extend_from_slice(&bytes);
    Ok((bytes, ContentDigest::sha256(material)))
}

pub(in crate::store) fn insert_signer_policy_version_tx(
    transaction: &Transaction<'_>,
    record: &SignerPolicyRecord,
) -> Result<(), ControlPlaneError> {
    let (bytes, digest) = signer_policy_snapshot(record)?;
    transaction.execute(
        "INSERT INTO signer_policy_versions
         (tenant_id, signer_policy_id, version, snapshot_digest, snapshot_json,
          created_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            record.tenant_id,
            record.id,
            to_i64(record.version)?,
            digest.as_str(),
            bytes,
            to_i64(record.updated_unix_ms)?
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn require_signer_policy_version_tx(
    transaction: &Transaction<'_>,
    record: &SignerPolicyRecord,
) -> Result<(), ControlPlaneError> {
    let (bytes, digest) = signer_policy_snapshot(record)?;
    let durable: Option<(String, Vec<u8>)> = transaction
        .query_row(
            "SELECT snapshot_digest, snapshot_json FROM signer_policy_versions
             WHERE tenant_id = ?1 AND signer_policy_id = ?2 AND version = ?3",
            params![record.tenant_id, record.id, to_i64(record.version)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if durable != Some((digest.to_string(), bytes)) {
        return Err(ControlPlaneError::CorruptState(
            "signer policy version snapshot changed".to_owned(),
        ));
    }
    Ok(())
}
