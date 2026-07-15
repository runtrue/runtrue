use super::*;

pub(in crate::store) fn environment_row(row: &Row<'_>) -> rusqlite::Result<EnvironmentRecord> {
    Ok(EnvironmentRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        name: row.get(3)?,
        deployment_target_reference: row.get(4)?,
        deployment_target_digest: digest_column(row, 5)?,
        status: row.get(6)?,
        protection_rules: bounded_json_blob_column(
            row,
            7,
            MAX_R10_RECORD_BYTES,
            "environment protection rules",
        )?,
        protection_rules_digest: digest_column(row, 8)?,
        wait_timer_ms: u64_column(row, 9, "environment wait timer")?,
        concurrency_limit: u32::try_from(u64_column(row, 10, "environment concurrency")?)
            .map_err(|error| conversion(10, error))?,
        secret_provider_configuration_id: row.get(11)?,
        signing_provider_configuration_id: row.get(12)?,
        required_policy_epoch: u64_column(row, 13, "environment policy epoch")?,
        last_concurrency_fence: u64_column(row, 14, "environment concurrency fence")?,
        created_unix_ms: u64_column(row, 15, "environment creation")?,
        updated_unix_ms: u64_column(row, 16, "environment update")?,
        version: u64_column(row, 17, "environment version")?,
    })
}

pub(in crate::store) fn environment_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    environment_id: &str,
) -> Result<Option<EnvironmentRecord>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            "SELECT id, tenant_id, repository_id, name, deployment_target_reference,
                    deployment_target_digest, status, protection_rules_json,
                    protection_rules_digest, wait_timer_ms, concurrency_limit,
                    secret_provider_configuration_id, signing_provider_configuration_id,
                    required_policy_epoch, last_concurrency_fence, created_unix_ms,
                    updated_unix_ms, version FROM environments
             WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, environment_id],
            environment_row,
        )
        .optional()?)
}

pub(in crate::store) fn require_active_policy_epoch_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    expected_epoch: u64,
) -> Result<(), ControlPlaneError> {
    let active: Option<i64> = transaction
        .query_row(
            "SELECT policy_epoch FROM tenant_policy_states
             WHERE tenant_id = ?1 AND active_draft_id IS NOT NULL
               AND active_policy_digest IS NOT NULL",
            [tenant_id],
            |row| row.get(0),
        )
        .optional()?;
    if active
        .map(|value| from_i64("active policy epoch", value))
        .transpose()?
        != Some(expected_epoch)
    {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    Ok(())
}

pub(in crate::store) fn validate_environment(
    record: &EnvironmentRecord,
) -> Result<Vec<u8>, ControlPlaneError> {
    for value in [
        &record.id,
        &record.tenant_id,
        &record.repository_id,
        &record.name,
    ] {
        validate_r10_identifier(value)?;
    }
    validate_sorted_r10_identifiers(&record.protection_rules.allowed_deployment_actors)?;
    validate_sorted_r10_identifiers(&record.protection_rules.allowed_signing_purposes)?;
    validate_sorted_r10_identifiers(&record.protection_rules.allowed_signer_policy_ids)?;
    validate_r10_identifier(&record.protection_rules.required_artifact_classification)?;
    let target_id = record
        .deployment_target_reference
        .strip_prefix("deployment-target://")
        .unwrap_or_default();
    let rules = r10_json_bytes(&record.protection_rules, MAX_R10_RECORD_BYTES)?;
    if !matches!(record.status.as_str(), "active" | "disabled")
        || record.version == 0
        || record.updated_unix_ms < record.created_unix_ms
        || record.required_policy_epoch == 0
        || record.wait_timer_ms > 7 * 24 * 60 * 60 * 1_000
        || !(1..=128).contains(&record.concurrency_limit)
        || record.protection_rules.minimum_approvals > 16
        || record.protection_rules.require_approval
            != (record.protection_rules.minimum_approvals > 0)
        || (record.protection_rules.require_approval
            && !(1..=24 * 60 * 60 * 1_000).contains(&record.protection_rules.approval_ttl_ms))
        || (!record.protection_rules.require_approval
            && record.protection_rules.approval_ttl_ms != 0)
        || record.protection_rules.require_approval
            != record.protection_rules.approval_rule_digest.is_some()
        || (record.protection_rules.require_promotion_evidence
            && !record.protection_rules.require_passed_scan)
        || record.expected_protection_rules_digest()? != record.protection_rules_digest
        || target_id.is_empty()
        || target_id.len() > 512
        || !target_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || record.expected_deployment_target_digest() != record.deployment_target_digest
        || (record.protection_rules.require_signed_artifact
            && (record.signing_provider_configuration_id.is_none()
                || record.protection_rules.allowed_signer_policy_ids.is_empty()
                || record.protection_rules.allowed_signing_purposes.is_empty()))
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid environment configuration",
        ));
    }
    Ok(rules)
}

pub(in crate::store) fn environment_snapshot(
    record: &EnvironmentRecord,
) -> Result<(Vec<u8>, ContentDigest), ControlPlaneError> {
    #[derive(Serialize)]
    struct Snapshot<'a> {
        id: &'a str,
        tenant_id: &'a str,
        repository_id: &'a str,
        name: &'a str,
        deployment_target_reference: &'a str,
        deployment_target_digest: &'a ContentDigest,
        status: &'a str,
        protection_rules: &'a crate::types::EnvironmentProtectionRules,
        protection_rules_digest: &'a ContentDigest,
        wait_timer_ms: u64,
        concurrency_limit: u32,
        secret_provider_configuration_id: &'a Option<String>,
        signing_provider_configuration_id: &'a Option<String>,
        required_policy_epoch: u64,
        created_unix_ms: u64,
        version: u64,
    }
    let snapshot = Snapshot {
        id: &record.id,
        tenant_id: &record.tenant_id,
        repository_id: &record.repository_id,
        name: &record.name,
        deployment_target_reference: &record.deployment_target_reference,
        deployment_target_digest: &record.deployment_target_digest,
        status: &record.status,
        protection_rules: &record.protection_rules,
        protection_rules_digest: &record.protection_rules_digest,
        wait_timer_ms: record.wait_timer_ms,
        concurrency_limit: record.concurrency_limit,
        secret_provider_configuration_id: &record.secret_provider_configuration_id,
        signing_provider_configuration_id: &record.signing_provider_configuration_id,
        required_policy_epoch: record.required_policy_epoch,
        created_unix_ms: record.created_unix_ms,
        version: record.version,
    };
    let bytes = r10_json_bytes(&snapshot, MAX_R10_RECORD_BYTES)?;
    let mut material = b"runtrue.environment-version.v1\0".to_vec();
    material.extend_from_slice(&bytes);
    Ok((bytes, ContentDigest::sha256(material)))
}

pub(in crate::store) fn require_environment_version_tx(
    transaction: &Transaction<'_>,
    record: &EnvironmentRecord,
) -> Result<(), ControlPlaneError> {
    let (expected_bytes, expected_digest) = environment_snapshot(record)?;
    let durable: Option<(String, Vec<u8>)> = transaction
        .query_row(
            "SELECT snapshot_digest, snapshot_json FROM environment_versions
             WHERE tenant_id = ?1 AND environment_id = ?2 AND version = ?3",
            params![record.tenant_id, record.id, to_i64(record.version)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if durable != Some((expected_digest.to_string(), expected_bytes)) {
        return Err(ControlPlaneError::CorruptState(
            "environment version snapshot is missing or changed".to_owned(),
        ));
    }
    Ok(())
}

pub(in crate::store) fn insert_environment_version_tx(
    transaction: &Transaction<'_>,
    record: &EnvironmentRecord,
) -> Result<(), ControlPlaneError> {
    let (bytes, digest) = environment_snapshot(record)?;
    transaction.execute(
        "INSERT INTO environment_versions
         (tenant_id, environment_id, version, snapshot_digest, snapshot_json,
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

pub(in crate::store) fn require_provider_capability_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    provider_id: Option<&str>,
    capability: &str,
) -> Result<(), ControlPlaneError> {
    let Some(provider_id) = provider_id else {
        return Ok(());
    };
    let provider = provider_configuration_tx(transaction, tenant_id, provider_id)?
        .ok_or_else(|| not_found("provider configuration", provider_id))?;
    if provider.capability != capability || provider.status != "active" {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    Ok(())
}

impl ControlPlane {
    pub fn put_environment(
        &self,
        record: &EnvironmentRecord,
        expected_version: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        let protection_rules = validate_environment(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        require_active_policy_epoch_tx(
            &transaction,
            &record.tenant_id,
            record.required_policy_epoch,
        )?;
        let repository_tenant: Option<String> = transaction
            .query_row(
                "SELECT tenant_id FROM repositories WHERE id = ?1",
                [&record.repository_id],
                |row| row.get(0),
            )
            .optional()?;
        if repository_tenant.as_deref() != Some(record.tenant_id.as_str()) {
            return Err(not_found("repository", &record.repository_id));
        }
        require_provider_capability_tx(
            &transaction,
            &record.tenant_id,
            record.secret_provider_configuration_id.as_deref(),
            "external-secret",
        )?;
        require_provider_capability_tx(
            &transaction,
            &record.tenant_id,
            record.signing_provider_configuration_id.as_deref(),
            "signing",
        )?;
        for policy_id in &record.protection_rules.allowed_signer_policy_ids {
            let policy = signer_policy_tx(&transaction, &record.tenant_id, policy_id)?
                .ok_or_else(|| not_found("signer policy", policy_id))?;
            if policy.status != "active"
                || Some(policy.provider_configuration_id.as_str())
                    != record.signing_provider_configuration_id.as_deref()
                || record
                    .protection_rules
                    .allowed_signing_purposes
                    .binary_search(&policy.purpose)
                    .is_err()
            {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
            require_signer_policy_version_tx(&transaction, &policy)?;
        }
        if let Some(existing) = environment_tx(&transaction, &record.tenant_id, &record.id)? {
            if existing == *record {
                require_environment_version_tx(&transaction, &existing)?;
                transaction.commit()?;
                return Ok(false);
            }
            if expected_version != Some(existing.version)
                || record.version
                    != existing
                        .version
                        .checked_add(1)
                        .ok_or(ControlPlaneError::IntegerRange {
                            field: "environment version",
                        })?
                || record.created_unix_ms != existing.created_unix_ms
                || record.tenant_id != existing.tenant_id
                || record.repository_id != existing.repository_id
                || record.last_concurrency_fence != existing.last_concurrency_fence
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = transaction.execute(
                "UPDATE environments SET name = ?3, deployment_target_reference = ?4,
                     deployment_target_digest = ?5, status = ?6,
                     protection_rules_json = ?7, protection_rules_digest = ?8,
                     wait_timer_ms = ?9, concurrency_limit = ?10,
                     secret_provider_configuration_id = ?11,
                     signing_provider_configuration_id = ?12,
                     required_policy_epoch = ?13, updated_unix_ms = ?14, version = ?15
                 WHERE tenant_id = ?1 AND id = ?2 AND version = ?16",
                params![
                    record.tenant_id,
                    record.id,
                    record.name,
                    record.deployment_target_reference,
                    record.deployment_target_digest.as_str(),
                    record.status,
                    protection_rules,
                    record.protection_rules_digest.as_str(),
                    to_i64(record.wait_timer_ms)?,
                    i64::from(record.concurrency_limit),
                    record.secret_provider_configuration_id,
                    record.signing_provider_configuration_id,
                    to_i64(record.required_policy_epoch)?,
                    to_i64(record.updated_unix_ms)?,
                    to_i64(record.version)?,
                    to_i64(existing.version)?
                ],
            )?;
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            insert_environment_version_tx(&transaction, record)?;
            transaction.commit()?;
            return Ok(true);
        }
        if expected_version.is_some() || record.version != 1 || record.last_concurrency_fence != 0 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO environments
             (id, tenant_id, repository_id, name, deployment_target_reference,
              deployment_target_digest, status, protection_rules_json,
              protection_rules_digest, wait_timer_ms, concurrency_limit,
              secret_provider_configuration_id, signing_provider_configuration_id,
              required_policy_epoch, last_concurrency_fence, created_unix_ms,
              updated_unix_ms, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 0, ?15, ?16, 1)",
            params![
                record.id,
                record.tenant_id,
                record.repository_id,
                record.name,
                record.deployment_target_reference,
                record.deployment_target_digest.as_str(),
                record.status,
                protection_rules,
                record.protection_rules_digest.as_str(),
                to_i64(record.wait_timer_ms)?,
                i64::from(record.concurrency_limit),
                record.secret_provider_configuration_id,
                record.signing_provider_configuration_id,
                to_i64(record.required_policy_epoch)?,
                to_i64(record.created_unix_ms)?,
                to_i64(record.updated_unix_ms)?
            ],
        )?;
        insert_environment_version_tx(&transaction, record)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn environment(
        &self,
        tenant_id: &str,
        environment_id: &str,
    ) -> Result<EnvironmentRecord, ControlPlaneError> {
        validate_r10_identifier(environment_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let record = environment_tx(&transaction, tenant_id, environment_id)?
            .ok_or_else(|| not_found("environment", environment_id))?;
        validate_environment(&record)?;
        require_environment_version_tx(&transaction, &record)?;
        transaction.commit()?;
        Ok(record)
    }
}
