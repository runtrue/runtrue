// Durable deployment result and metrics dependencies are explicit.
use super::super::{
    append_deployment_event_tx, bounded_json_blob_column, deployment_request_tx, digest_column,
    environment_tx, from_i64, not_found, optional_digest_column, optional_u64_column, params,
    r10_json_bytes, require_r9_tenant_tx, signing_result_tx, to_i64, u64_column,
    validate_deployment_inputs_tx, validate_r10_identifier, ContentDigest, ControlPlane,
    ControlPlaneError, DeploymentMetrics, DeploymentRecord, DeploymentRequestStatus,
    IdempotentResult, R9AuditMetadata, Row, SigningResultState, Transaction, TransactionBehavior,
    MAX_R10_RECORD_BYTES,
};
use rusqlite::OptionalExtension as _;

pub(in crate::store) fn deployment_row(row: &Row<'_>) -> rusqlite::Result<DeploymentRecord> {
    Ok(DeploymentRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        environment_id: row.get(2)?,
        deployment_request_id: row.get(3)?,
        rollback_of_deployment_id: row.get(4)?,
        artifact_id: row.get(5)?,
        promoted_artifact_id: row.get(6)?,
        artifact_digest: digest_column(row, 7)?,
        manifest_digest: digest_column(row, 8)?,
        provenance_digest: digest_column(row, 9)?,
        target_digest: digest_column(row, 10)?,
        deployment_capsule_digest: digest_column(row, 11)?,
        signing_request_id: row.get(12)?,
        signing_result_digest: optional_digest_column(row, 13)?,
        signer_key_id: row.get(14)?,
        signing_algorithm: row.get(15)?,
        signature_digest: optional_digest_column(row, 16)?,
        certificate_digest: optional_digest_column(row, 17)?,
        attestation_digest: optional_digest_column(row, 18)?,
        external_reference: row.get(19)?,
        status: row.get(20)?,
        result_digest: digest_column(row, 21)?,
        metadata: bounded_json_blob_column(row, 22, MAX_R10_RECORD_BYTES, "deployment metadata")?,
        metadata_digest: digest_column(row, 23)?,
        started_unix_ms: u64_column(row, 24, "deployment start")?,
        completed_unix_ms: optional_u64_column(row, 25, "deployment completion")?,
    })
}

pub(in crate::store) fn deployment_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    deployment_id: &str,
) -> Result<Option<DeploymentRecord>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            "SELECT id, tenant_id, environment_id, deployment_request_id,
                    rollback_of_deployment_id, artifact_id, promoted_artifact_id,
                    artifact_digest, manifest_digest, provenance_digest, target_digest,
                    deployment_capsule_digest, signing_request_id, signing_result_digest,
                    signer_key_id, signing_algorithm, signature_digest,
                    certificate_digest, attestation_digest, external_reference, status,
                    result_digest, metadata_json, metadata_digest, started_unix_ms,
                    completed_unix_ms FROM deployments WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, deployment_id],
            deployment_row,
        )
        .optional()?)
}

impl ControlPlane {
    pub fn record_deployment_result(
        &self,
        record: &DeploymentRecord,
        audit: &R9AuditMetadata,
    ) -> Result<IdempotentResult<DeploymentRecord>, ControlPlaneError> {
        for value in [
            &record.id,
            &record.tenant_id,
            &record.environment_id,
            &record.deployment_request_id,
            &audit.actor_id,
            &audit.correlation_id,
        ] {
            validate_r10_identifier(value)?;
        }
        let metadata = r10_json_bytes(&record.metadata, MAX_R10_RECORD_BYTES)?;
        if !matches!(record.status.as_str(), "succeeded" | "failed")
            || record.completed_unix_ms != Some(audit.occurred_unix_ms)
            || record.started_unix_ms > audit.occurred_unix_ms
            || record.expected_metadata_digest()? != record.metadata_digest
            || record.expected_result_digest()? != record.result_digest
            || record
                .external_reference
                .as_ref()
                .is_some_and(|value| validate_r10_identifier(value).is_err())
        {
            return Err(ControlPlaneError::InvalidInput("invalid deployment result"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &record.tenant_id)?;
        if let Some(existing) = deployment_tx(&transaction, &record.tenant_id, &record.id)? {
            if existing == *record {
                transaction.commit()?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let mut request = deployment_request_tx(
            &transaction,
            &record.tenant_id,
            &record.deployment_request_id,
        )?
        .ok_or_else(|| not_found("deployment request", &record.deployment_request_id))?;
        let environment = environment_tx(&transaction, &record.tenant_id, &record.environment_id)?
            .ok_or_else(|| not_found("environment", &record.environment_id))?;
        validate_deployment_inputs_tx(&transaction, &request, &environment)?;
        if request.status != DeploymentRequestStatus::InProgress
            || request.environment_id != record.environment_id
            || request.rollback_of_deployment_id != record.rollback_of_deployment_id
            || request.artifact_id != record.artifact_id
            || request.promoted_artifact_id != record.promoted_artifact_id
            || request.artifact_digest != record.artifact_digest
            || request.manifest_digest != record.manifest_digest
            || request.provenance_digest != record.provenance_digest
            || request.target_digest != record.target_digest
            || request.deployment_capsule_digest != record.deployment_capsule_digest
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if environment.protection_rules.require_signed_artifact {
            let signing_request_id = record
                .signing_request_id
                .as_deref()
                .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
            let signing = signing_result_tx(&transaction, &record.tenant_id, signing_request_id)?
                .ok_or_else(|| not_found("signing result", signing_request_id))?;
            let SigningResultState::Complete(result) = signing.state else {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            };
            if record.signing_result_digest.as_ref() != Some(&result.result_digest)
                || record.signer_key_id.as_deref() != Some(result.signer_key_id.as_str())
                || record.signing_algorithm.as_deref() != Some(result.algorithm.as_str())
                || record.signature_digest.as_ref()
                    != Some(&ContentDigest::sha256(&result.signature))
                || record.certificate_digest
                    != result.certificate.as_ref().map(ContentDigest::sha256)
                || record.attestation_digest
                    != result.attestation.as_ref().map(ContentDigest::sha256)
                || signing.reservation.deployment_request_id != record.deployment_request_id
                || signing.reservation.artifact_digest != record.artifact_digest
                || signing.reservation.provenance_digest != record.provenance_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
        } else if record.signing_request_id.is_some()
            || record.signing_result_digest.is_some()
            || record.signer_key_id.is_some()
            || record.signing_algorithm.is_some()
            || record.signature_digest.is_some()
            || record.certificate_digest.is_some()
            || record.attestation_digest.is_some()
        {
            return Err(ControlPlaneError::InvalidInput(
                "unexpected signing result on unsigned environment",
            ));
        }
        transaction.execute(
            "INSERT INTO deployments
             (id, tenant_id, environment_id, deployment_request_id,
              rollback_of_deployment_id, artifact_id, promoted_artifact_id,
              artifact_digest, manifest_digest, provenance_digest, target_digest,
              deployment_capsule_digest, signing_request_id, signing_result_digest,
              signer_key_id, signing_algorithm, signature_digest, certificate_digest,
              attestation_digest, external_reference, status, result_digest,
              metadata_json, metadata_digest, started_unix_ms, completed_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                     ?23, ?24, ?25, ?26)",
            params![
                record.id,
                record.tenant_id,
                record.environment_id,
                record.deployment_request_id,
                record.rollback_of_deployment_id,
                record.artifact_id,
                record.promoted_artifact_id,
                record.artifact_digest.as_str(),
                record.manifest_digest.as_str(),
                record.provenance_digest.as_str(),
                record.target_digest.as_str(),
                record.deployment_capsule_digest.as_str(),
                record.signing_request_id,
                record
                    .signing_result_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
                record.signer_key_id,
                record.signing_algorithm,
                record.signature_digest.as_ref().map(ContentDigest::as_str),
                record
                    .certificate_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
                record
                    .attestation_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
                record.external_reference,
                record.status,
                record.result_digest.as_str(),
                metadata,
                record.metadata_digest.as_str(),
                to_i64(record.started_unix_ms)?,
                record.completed_unix_ms.map(to_i64).transpose()?
            ],
        )?;
        let terminal_status = if record.status == "succeeded" {
            DeploymentRequestStatus::Succeeded
        } else {
            DeploymentRequestStatus::Failed
        };
        request.status = terminal_status;
        request.actor_id.clone_from(&audit.actor_id);
        request
            .audit_correlation_id
            .clone_from(&audit.correlation_id);
        request.updated_unix_ms = audit.occurred_unix_ms;
        request.completed_unix_ms = Some(audit.occurred_unix_ms);
        request.version =
            request
                .version
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "deployment request version",
                })?;
        let changed = transaction.execute(
            "UPDATE deployment_requests SET status = ?3, actor_id = ?4,
                    audit_correlation_id = ?5, updated_unix_ms = ?6,
                    completed_unix_ms = ?6, version = ?7
             WHERE tenant_id = ?1 AND id = ?2 AND status = 'in-progress'",
            params![
                record.tenant_id,
                record.deployment_request_id,
                terminal_status.as_str(),
                audit.actor_id,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?,
                to_i64(request.version)?
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE environment_concurrency_leases SET state = 'released',
                    released_unix_ms = ?3
             WHERE tenant_id = ?1 AND deployment_request_id = ?2 AND state = 'active'",
            params![
                record.tenant_id,
                record.deployment_request_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        if record.status == "succeeded" {
            if let Some(parent_id) = &record.rollback_of_deployment_id {
                transaction.execute(
                    "UPDATE deployments SET status = 'rolled-back'
                     WHERE tenant_id = ?1 AND id = ?2 AND status = 'succeeded'",
                    params![record.tenant_id, parent_id],
                )?;
            }
        }
        append_deployment_event_tx(&transaction, &request)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record.clone(),
            replayed: false,
        })
    }

    pub fn deployment_metrics(
        &self,
        tenant_id: &str,
    ) -> Result<DeploymentMetrics, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let counts = |sql: &str| -> Result<u64, ControlPlaneError> {
            let value: i64 = transaction.query_row(sql, [tenant_id], |row| row.get(0))?;
            from_i64("deployment metric", value)
        };
        let metrics = DeploymentMetrics {
            requests: counts("SELECT COUNT(*) FROM deployment_requests WHERE tenant_id = ?1")?,
            requests_ready: counts("SELECT COUNT(*) FROM deployment_requests WHERE tenant_id = ?1 AND status = 'ready'")?,
            active_concurrency_leases: counts("SELECT COUNT(*) FROM environment_concurrency_leases WHERE tenant_id = ?1 AND state = 'active'")?,
            deployments_succeeded: counts("SELECT COUNT(*) FROM deployments WHERE tenant_id = ?1 AND status = 'succeeded'")?,
            deployments_failed: counts("SELECT COUNT(*) FROM deployments WHERE tenant_id = ?1 AND status = 'failed'")?,
            secret_releases_pending_revoke: counts("SELECT COUNT(*) FROM external_secret_release_journal WHERE tenant_id = ?1 AND state IN ('delivered','revoking','indeterminate')")?,
            signing_results_replayed: counts("SELECT COUNT(*) FROM signing_result_journal WHERE tenant_id = ?1 AND state IN ('signed','complete')")?,
        };
        transaction.commit()?;
        Ok(metrics)
    }
}
