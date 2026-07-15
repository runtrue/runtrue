use super::*;

impl ControlPlane {
    pub fn put_tenant_oidc_provider_configuration(
        &self,
        record: &TenantOidcProviderConfiguration,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        let (scopes, mfa_claim) = validate_oidc_provider(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        if let Some(existing) = oidc_provider_tx(&transaction, &record.tenant_id, &record.id)? {
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
                            field: "OIDC provider version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
                || record.tenant_id != existing.tenant_id
                || record.issuer != existing.issuer
                || record.client_id != existing.client_id
                || record.redirect_uri != existing.redirect_uri
                || record.authorization_endpoint != existing.authorization_endpoint
                || record.token_endpoint != existing.token_endpoint
                || record.jwks_uri != existing.jwks_uri
                || record.scopes != existing.scopes
                || record.mfa_claim != existing.mfa_claim
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "UPDATE tenant_oidc_provider_configs SET issuer = ?3, client_id = ?4,
                    authorization_endpoint = ?5, token_endpoint = ?6, jwks_uri = ?7,
                    redirect_uri = ?8, scopes_json = ?9, mfa_claim_json = ?10,
                    status = ?11, configuration_digest = ?12, updated_unix_ms = ?13,
                    version = ?14 WHERE tenant_id = ?1 AND id = ?2 AND version = ?15",
                params![
                    record.tenant_id,
                    record.id,
                    record.issuer,
                    record.client_id,
                    record.authorization_endpoint,
                    record.token_endpoint,
                    record.jwks_uri,
                    record.redirect_uri,
                    scopes,
                    mfa_claim,
                    record.status,
                    record.configuration_digest.as_str(),
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
            "INSERT INTO tenant_oidc_provider_configs
             (id, tenant_id, issuer, client_id, authorization_endpoint, token_endpoint,
              jwks_uri, redirect_uri, scopes_json, mfa_claim_json, status,
              configuration_digest, created_unix_ms, updated_unix_ms, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 1)",
            params![
                record.id,
                record.tenant_id,
                record.issuer,
                record.client_id,
                record.authorization_endpoint,
                record.token_endpoint,
                record.jwks_uri,
                record.redirect_uri,
                scopes,
                mfa_claim,
                record.status,
                record.configuration_digest.as_str(),
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn tenant_oidc_provider_configuration(
        &self,
        tenant_id: &str,
        provider_id: &str,
    ) -> Result<TenantOidcProviderConfiguration, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = oidc_provider_tx(&transaction, tenant_id, provider_id)?
            .ok_or_else(|| not_found("OIDC provider configuration", provider_id))?;
        transaction.commit()?;
        Ok(record)
    }
}
