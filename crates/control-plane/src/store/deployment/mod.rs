mod environments;
mod providers;
mod requests;
mod signing_results;

use super::*;
pub(crate) use environments::*;
pub(crate) use providers::*;
pub(crate) use requests::*;
pub(super) use signing_results::*;
impl ControlPlane {
    pub fn put_tenant_provider_configuration(
        &self,
        record: &TenantProviderConfiguration,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        validate_provider_configuration(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        if let Some(existing) =
            provider_configuration_tx(&transaction, &record.tenant_id, &record.id)?
        {
            if existing == *record {
                require_provider_configuration_version_tx(&transaction, &existing)?;
                transaction.commit()?;
                return Ok(false);
            }
            if expected_version != Some(existing.version)
                || record.version
                    != existing
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "provider configuration version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
                || record.tenant_id != existing.tenant_id
                || record.capability != existing.capability
                || record.provider_kind != existing.provider_kind
                || record.endpoint_origin != existing.endpoint_origin
                || record.credential_reference != existing.credential_reference
                || record.trust_bundle_digest != existing.trust_bundle_digest
                || record.public_key_digest != existing.public_key_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = transaction.execute(
                "UPDATE tenant_provider_configurations
                 SET endpoint_origin = ?3, credential_reference = ?4,
                     trust_bundle_digest = ?5, public_key_digest = ?6,
                     configuration_digest = ?7, status = ?8, updated_unix_ms = ?9,
                     version = ?10 WHERE tenant_id = ?1 AND id = ?2 AND version = ?11",
                params![
                    record.tenant_id,
                    record.id,
                    record.endpoint_origin,
                    record.credential_reference,
                    record.trust_bundle_digest.as_str(),
                    record.public_key_digest.as_ref().map(ContentDigest::as_str),
                    record.configuration_digest.as_str(),
                    record.status,
                    to_i64(record.updated_unix_ms)?,
                    to_i64(record.version)?,
                    to_i64(existing.version)?
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            insert_provider_configuration_version_tx(&transaction, record)?;
            transaction.commit()?;
            return Ok(true);
        }
        if expected_version.is_some() || record.version != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO tenant_provider_configurations
             (id, tenant_id, capability, provider_kind, endpoint_origin,
              credential_reference, trust_bundle_digest, public_key_digest,
              configuration_digest, status, created_unix_ms, updated_unix_ms, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)",
            params![
                record.id,
                record.tenant_id,
                record.capability,
                record.provider_kind,
                record.endpoint_origin,
                record.credential_reference,
                record.trust_bundle_digest.as_str(),
                record.public_key_digest.as_ref().map(ContentDigest::as_str),
                record.configuration_digest.as_str(),
                record.status,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?
            ],
        )?;
        insert_provider_configuration_version_tx(&transaction, record)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn tenant_provider_configuration(
        &self,
        tenant_id: &str,
        provider_id: &str,
    ) -> Result<TenantProviderConfiguration, ControlPlaneError> {
        validate_r10_identifier(provider_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = provider_configuration_tx(&transaction, tenant_id, provider_id)?
            .ok_or_else(|| not_found("provider configuration", provider_id))?;
        validate_provider_configuration(&record)?;
        require_provider_configuration_version_tx(&transaction, &record)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn put_signer_policy(
        &self,
        record: &SignerPolicyRecord,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        validate_signer_policy(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        let provider = provider_configuration_tx(
            &transaction,
            &record.tenant_id,
            &record.provider_configuration_id,
        )?
        .ok_or_else(|| not_found("provider configuration", &record.provider_configuration_id))?;
        require_provider_configuration_version_tx(&transaction, &provider)?;
        if provider.capability != "signing"
            || provider.status != "active"
            || provider.configuration_digest != record.provider_configuration_digest
            || provider.version != record.provider_configuration_version
            || provider.public_key_digest.as_ref() != Some(&record.public_key_digest)
        {
            return Err(ControlPlaneError::EnvironmentGateNotReady);
        }
        if let Some(existing) = signer_policy_tx(&transaction, &record.tenant_id, &record.id)? {
            if existing == *record {
                require_signer_policy_version_tx(&transaction, &existing)?;
                transaction.commit()?;
                return Ok(false);
            }
            if expected_version != Some(existing.version)
                || record.version
                    != existing
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "signer policy version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
                || record.tenant_id != existing.tenant_id
                || record.provider_configuration_id != existing.provider_configuration_id
                || record.provider_configuration_digest != existing.provider_configuration_digest
                || record.provider_configuration_version != existing.provider_configuration_version
                || record.backend_key_reference != existing.backend_key_reference
                || record.purpose != existing.purpose
                || record.operation != existing.operation
                || record.public_key_digest != existing.public_key_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = transaction.execute(
                "UPDATE signer_policies SET policy_digest = ?3, status = ?4,
                        updated_unix_ms = ?5, version = ?6
                 WHERE tenant_id = ?1 AND id = ?2 AND version = ?7",
                params![
                    record.tenant_id,
                    record.id,
                    record.policy_digest.as_str(),
                    record.status,
                    to_i64(record.updated_unix_ms)?,
                    to_i64(record.version)?,
                    to_i64(existing.version)?
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            insert_signer_policy_version_tx(&transaction, record)?;
            transaction.commit()?;
            return Ok(true);
        }
        if expected_version.is_some() || record.version != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO signer_policies
             (id, tenant_id, provider_configuration_id,
              provider_configuration_digest, provider_configuration_version,
              backend_key_reference, purpose, operation, public_key_digest,
              policy_digest, status, created_unix_ms, updated_unix_ms, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1)",
            params![
                record.id,
                record.tenant_id,
                record.provider_configuration_id,
                record.provider_configuration_digest.as_str(),
                to_i64(record.provider_configuration_version)?,
                record.backend_key_reference,
                record.purpose,
                record.operation,
                record.public_key_digest.as_str(),
                record.policy_digest.as_str(),
                record.status,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?
            ],
        )?;
        insert_signer_policy_version_tx(&transaction, record)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn signer_policy(
        &self,
        tenant_id: &str,
        policy_id: &str,
    ) -> Result<SignerPolicyRecord, ControlPlaneError> {
        validate_r10_identifier(policy_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = signer_policy_tx(&transaction, tenant_id, policy_id)?
            .ok_or_else(|| not_found("signer policy", policy_id))?;
        validate_signer_policy(&record)?;
        require_signer_policy_version_tx(&transaction, &record)?;
        transaction.commit()?;
        Ok(record)
    }
}
