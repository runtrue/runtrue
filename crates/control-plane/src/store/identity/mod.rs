mod memberships;
mod oidc;
mod sessions;
mod tenants;
mod users;

use super::*;
pub(super) use sessions::*;

// ---- Migration 23: tenant, human identity, and provider configuration. ----

pub(in crate::store) fn r9_json_bytes<T: Serialize + ?Sized>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ControlPlaneError> {
    let canonical = canonicalize_json(serde_json::to_value(value)?);
    let bytes = serde_json::to_vec(&canonical)?;
    if bytes.len() > maximum {
        return Err(ControlPlaneError::InvalidInput(
            "R9 durable record exceeds its byte bound",
        ));
    }
    Ok(bytes)
}

pub(in crate::store) fn validate_r9_identifier(value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ControlPlaneError::InvalidInput("invalid R9 identifier"));
    }
    Ok(())
}

pub(in crate::store) fn validate_r9_audit_text(value: &str) -> Result<(), ControlPlaneError> {
    validate_r9_identifier(value)
}

pub(in crate::store) fn validate_r9_https_uri(
    value: &str,
    allow_query: bool,
) -> Result<(), ControlPlaneError> {
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(ControlPlaneError::InvalidInput(
            "OIDC metadata URI must use HTTPS",
        ));
    };
    if rest.is_empty()
        || value.len() > 2048
        || rest.contains('@')
        || rest.contains('#')
        || rest.contains('\\')
        || (!allow_query && rest.contains('?'))
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.chars().any(char::is_whitespace)
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid or ambiguous OIDC metadata URI",
        ));
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty()
        || authority.starts_with('.')
        || authority.ends_with('.')
        || authority.ends_with(':')
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid OIDC metadata URI authority",
        ));
    }
    Ok(())
}

pub(in crate::store) fn require_r9_tenant_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
) -> Result<(), ControlPlaneError> {
    validate_r9_identifier(tenant_id)?;
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM tenants WHERE id = ?1 AND status = 'active')",
        [tenant_id],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(ControlPlaneError::NotFound {
            kind: "tenant",
            id: tenant_id.to_owned(),
        });
    }
    Ok(())
}

pub(in crate::store) fn tenant_identity_row(
    row: &Row<'_>,
) -> rusqlite::Result<TenantIdentityRecord> {
    Ok(TenantIdentityRecord {
        id: row.get(0)?,
        slug: row.get(1)?,
        name: row.get(2)?,
        status: row.get(3)?,
        settings: bounded_json_blob_column(
            row,
            4,
            MAX_R9_IDENTITY_JSON_BYTES,
            "tenant settings JSON",
        )?,
        created_unix_ms: u64_column(row, 5, "tenant creation")?,
        updated_unix_ms: u64_column(row, 6, "tenant update")?,
        version: u64_column(row, 7, "tenant version")?,
    })
}

pub(in crate::store) fn tenant_identity_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
) -> Result<Option<TenantIdentityRecord>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            "SELECT id, slug, name, status, settings_json, created_unix_ms,
                    updated_unix_ms, version FROM tenants WHERE id = ?1",
            [tenant_id],
            tenant_identity_row,
        )
        .optional()?)
}

pub(in crate::store) fn validate_tenant_identity(
    record: &TenantIdentityRecord,
) -> Result<Vec<u8>, ControlPlaneError> {
    validate_r9_identifier(&record.id)?;
    validate_r9_identifier(&record.name)?;
    if record.slug.is_empty()
        || record.slug.len() > 128
        || !record
            .slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !matches!(record.status.as_str(), "active" | "suspended" | "disabled")
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput("invalid tenant identity"));
    }
    r9_json_bytes(&record.settings, MAX_R9_IDENTITY_JSON_BYTES)
}

pub(in crate::store) fn oidc_provider_row(
    row: &Row<'_>,
) -> rusqlite::Result<TenantOidcProviderConfiguration> {
    Ok(TenantOidcProviderConfiguration {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        issuer: row.get(2)?,
        client_id: row.get(3)?,
        authorization_endpoint: row.get(4)?,
        token_endpoint: row.get(5)?,
        jwks_uri: row.get(6)?,
        redirect_uri: row.get(7)?,
        scopes: bounded_json_blob_column(row, 8, 64 * 1024, "OIDC scopes JSON")?,
        mfa_claim: bounded_json_blob_column(row, 9, 64 * 1024, "OIDC MFA claim JSON")?,
        status: row.get(10)?,
        configuration_digest: digest_column(row, 11)?,
        created_unix_ms: u64_column(row, 12, "OIDC provider creation")?,
        updated_unix_ms: u64_column(row, 13, "OIDC provider update")?,
        version: u64_column(row, 14, "OIDC provider version")?,
    })
}

pub(in crate::store) fn oidc_provider_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    provider_id: &str,
) -> Result<Option<TenantOidcProviderConfiguration>, ControlPlaneError> {
    let record = transaction
        .query_row(
            "SELECT id, tenant_id, issuer, client_id, authorization_endpoint,
                    token_endpoint, jwks_uri, redirect_uri, scopes_json,
                    mfa_claim_json, status, configuration_digest,
                    created_unix_ms, updated_unix_ms, version
             FROM tenant_oidc_provider_configs WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, provider_id],
            oidc_provider_row,
        )
        .optional()?;
    if let Some(record) = &record {
        validate_oidc_provider(record).map_err(|_| {
            ControlPlaneError::CorruptState(
                "tenant OIDC provider digest or bounds are invalid".to_owned(),
            )
        })?;
    }
    Ok(record)
}

pub(in crate::store) fn validate_oidc_provider(
    record: &TenantOidcProviderConfiguration,
) -> Result<(Vec<u8>, Vec<u8>), ControlPlaneError> {
    validate_r9_identifier(&record.id)?;
    validate_r9_identifier(&record.tenant_id)?;
    validate_r9_identifier(&record.client_id)?;
    validate_r9_https_uri(&record.issuer, false)?;
    validate_r9_https_uri(&record.authorization_endpoint, true)?;
    validate_r9_https_uri(&record.token_endpoint, false)?;
    validate_r9_https_uri(&record.jwks_uri, false)?;
    validate_r9_https_uri(&record.redirect_uri, true)?;
    if record.scopes.is_empty()
        || record.scopes.len() > MAX_R9_OIDC_SCOPES
        || !record.scopes.windows(2).all(|pair| pair[0] < pair[1])
        || !record
            .scopes
            .iter()
            .all(|scope| validate_r9_identifier(scope).is_ok())
        || !matches!(record.status.as_str(), "active" | "disabled")
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
        || record.expected_configuration_digest()? != record.configuration_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid tenant OIDC provider configuration",
        ));
    }
    Ok((
        r9_json_bytes(&record.scopes, 64 * 1024)?,
        r9_json_bytes(&record.mfa_claim, 64 * 1024)?,
    ))
}
