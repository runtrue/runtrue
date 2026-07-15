use super::super::*;

impl ControlPlane {
    /// Insert one provider-neutral trigger envelope. Authorization is checked
    /// before looking for an existing identity to avoid cross-tenant leaks.
    pub fn record_normalized_trigger(
        &self,
        record: &NormalizedTriggerEventRecord,
    ) -> Result<bool, ControlPlaneError> {
        validate_text("trigger id", &record.id)?;
        validate_text("trigger tenant", &record.tenant_id)?;
        validate_text("trigger repository", &record.repository_id)?;
        validate_text("trigger kind", &record.trigger_kind)?;
        validate_text("trigger idempotency identity", &record.idempotency_identity)?;
        validate_text("trigger actor", &record.actor_identity)?;
        if !matches!(
            record.trigger_kind.as_str(),
            "tag" | "schedule" | "manual" | "api" | "repository-dispatch" | "dependent-workflow"
        ) {
            return Err(ControlPlaneError::InvalidInput("unsupported trigger kind"));
        }
        let canonical = serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(
            record.normalized_envelope.clone(),
        ))?;
        if canonical.len() > 256 * 1024
            || ContentDigest::sha256(&canonical) != record.normalized_digest
        {
            return Err(ControlPlaneError::InvalidInput(
                "normalized trigger envelope is oversized or has the wrong digest",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM repositories
                           WHERE id = ?1 AND tenant_id = ?2)",
            params![record.repository_id, record.tenant_id],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(not_found("repository", &record.repository_id));
        }
        let envelope = String::from_utf8(canonical).map_err(|_| {
            ControlPlaneError::InvalidInput("normalized trigger envelope is not UTF-8")
        })?;
        let inserted = transaction.execute(
            "INSERT INTO normalized_trigger_events
             (id, tenant_id, repository_id, trigger_kind, idempotency_identity,
              normalized_digest, normalized_envelope_json, actor_identity, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(tenant_id, repository_id, trigger_kind, idempotency_identity)
             DO NOTHING",
            params![
                record.id,
                record.tenant_id,
                record.repository_id,
                record.trigger_kind,
                record.idempotency_identity,
                record.normalized_digest.as_str(),
                envelope,
                record.actor_identity,
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        if inserted == 1 {
            append_audit_event_tx(
                &transaction,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: record.created_unix_ms,
                    tenant_id: record.tenant_id.clone(),
                    actor: AuditPrincipal {
                        kind: "trigger".to_owned(),
                        id: record.actor_identity.clone(),
                    },
                    action: "workflow.trigger.normalize".to_owned(),
                    resource: AuditResource {
                        kind: "normalized-trigger".to_owned(),
                        id: record.id.clone(),
                    },
                    result: "persisted".to_owned(),
                    request_id: record.idempotency_identity.clone(),
                    decision_id: None,
                    metadata: BTreeMap::from([(
                        "normalized_digest".to_owned(),
                        AuditValue::Digest(record.normalized_digest.clone()),
                    )]),
                },
            )?;
            transaction.commit()?;
            return Ok(false);
        }
        let exact: bool = transaction.query_row(
            "SELECT id = ?5 AND normalized_digest = ?6
                    AND normalized_envelope_json = ?7
                    AND actor_identity = ?8 AND created_unix_ms = ?9
             FROM normalized_trigger_events
             WHERE tenant_id = ?1 AND repository_id = ?2
               AND trigger_kind = ?3 AND idempotency_identity = ?4",
            params![
                record.tenant_id,
                record.repository_id,
                record.trigger_kind,
                record.idempotency_identity,
                record.id,
                record.normalized_digest.as_str(),
                envelope,
                record.actor_identity,
                to_i64(record.created_unix_ms)?,
            ],
            |row| row.get(0),
        )?;
        if exact {
            transaction.commit()?;
            Ok(true)
        } else {
            Err(ControlPlaneError::IdempotencyConflict)
        }
    }
}

pub(super) fn persist_normalized_trigger_tx(
    transaction: &Transaction<'_>,
    record: &NormalizedTriggerEventRecord,
) -> Result<bool, ControlPlaneError> {
    let canonical = serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(
        record.normalized_envelope.clone(),
    ))?;
    if canonical.len() > 256 * 1024 || ContentDigest::sha256(&canonical) != record.normalized_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "normalized trigger envelope is oversized or has the wrong digest",
        ));
    }
    let envelope = String::from_utf8(canonical)
        .map_err(|_| ControlPlaneError::InvalidInput("normalized trigger envelope is not UTF-8"))?;
    let inserted = transaction.execute(
        "INSERT INTO normalized_trigger_events
         (id, tenant_id, repository_id, trigger_kind, idempotency_identity,
          normalized_digest, normalized_envelope_json, actor_identity, created_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(tenant_id, repository_id, trigger_kind, idempotency_identity)
         DO NOTHING",
        params![
            record.id,
            record.tenant_id,
            record.repository_id,
            record.trigger_kind,
            record.idempotency_identity,
            record.normalized_digest.as_str(),
            envelope,
            record.actor_identity,
            to_i64(record.created_unix_ms)?,
        ],
    )?;
    if inserted == 1 {
        return Ok(false);
    }
    let exact: bool = transaction.query_row(
        "SELECT id = ?5 AND normalized_digest = ?6
                AND normalized_envelope_json = ?7
                AND actor_identity = ?8 AND created_unix_ms = ?9
         FROM normalized_trigger_events
         WHERE tenant_id = ?1 AND repository_id = ?2
           AND trigger_kind = ?3 AND idempotency_identity = ?4",
        params![
            record.tenant_id,
            record.repository_id,
            record.trigger_kind,
            record.idempotency_identity,
            record.id,
            record.normalized_digest.as_str(),
            envelope,
            record.actor_identity,
            to_i64(record.created_unix_ms)?,
        ],
        |row| row.get(0),
    )?;
    if exact {
        Ok(true)
    } else {
        Err(ControlPlaneError::IdempotencyConflict)
    }
}

pub(super) fn append_normalized_trigger_audit_tx(
    transaction: &Transaction<'_>,
    installation_id: &str,
    record: &NormalizedTriggerEventRecord,
) -> Result<(), ControlPlaneError> {
    append_audit_event_tx(
        transaction,
        installation_id,
        AuditEventData {
            observed_unix_ms: record.created_unix_ms,
            tenant_id: record.tenant_id.clone(),
            actor: AuditPrincipal {
                kind: "trigger".to_owned(),
                id: record.actor_identity.clone(),
            },
            action: "workflow.trigger.normalize".to_owned(),
            resource: AuditResource {
                kind: "normalized-trigger".to_owned(),
                id: record.id.clone(),
            },
            result: "persisted".to_owned(),
            request_id: record.idempotency_identity.clone(),
            decision_id: None,
            metadata: BTreeMap::from([(
                "normalized_digest".to_owned(),
                AuditValue::Digest(record.normalized_digest.clone()),
            )]),
        },
    )?;
    Ok(())
}
