use super::super::*;

impl ControlPlane {
    pub fn issue_artifact_download_ticket(
        &self,
        ticket: &ArtifactDownloadTicketRecord,
    ) -> Result<IdempotentResult<ArtifactDownloadTicketRecord>, ControlPlaneError> {
        if ticket.expires_unix_ms <= ticket.issued_unix_ms
            || ticket.used_unix_ms.is_some()
            || ticket.expires_unix_ms.saturating_sub(ticket.issued_unix_ms) > 15 * 60 * 1_000
        {
            return Err(ControlPlaneError::InvalidInput(
                "artifact download ticket lifetime is invalid",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let artifact =
            optional_artifact_catalog_tx(&transaction, &ticket.tenant_id, &ticket.artifact_id)?
                .ok_or_else(|| ControlPlaneError::NotFound {
                    kind: "artifact",
                    id: ticket.artifact_id.clone(),
                })?;
        if artifact.classification != ticket.classification
            || artifact.manifest_digest != ticket.manifest_digest
            || artifact.state == "retired"
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let existing = optional_artifact_download_ticket_tx(&transaction, &ticket.token_hash)?;
        if let Some(existing) = existing {
            if existing != *ticket {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        transaction.execute(
            "INSERT INTO artifact_download_tickets
             (token_hash, artifact_id, tenant_id, principal_id, classification,
              manifest_digest, issued_unix_ms, expires_unix_ms, used_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
            params![
                ticket.token_hash.as_str(),
                ticket.artifact_id,
                ticket.tenant_id,
                ticket.principal_id,
                ticket.classification,
                ticket.manifest_digest.as_str(),
                to_i64(ticket.issued_unix_ms)?,
                to_i64(ticket.expires_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: ticket.clone(),
            replayed: false,
        })
    }

    pub fn consume_artifact_download_ticket(
        &self,
        token_hash: &ContentDigest,
        tenant_id: Option<&str>,
        principal_id: &str,
        now_unix_ms: u64,
    ) -> Result<ArtifactDownloadTicketRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ticket =
            optional_artifact_download_ticket_tx(&transaction, token_hash)?.ok_or_else(|| {
                ControlPlaneError::NotFound {
                    kind: "artifact download",
                    id: "redacted".to_owned(),
                }
            })?;
        if tenant_id.is_some_and(|tenant_id| ticket.tenant_id != tenant_id)
            || ticket.principal_id != principal_id
            || ticket.used_unix_ms.is_some()
            || now_unix_ms >= ticket.expires_unix_ms
        {
            return Err(ControlPlaneError::NotFound {
                kind: "artifact download",
                id: "redacted".to_owned(),
            });
        }
        let changed = transaction.execute(
            "UPDATE artifact_download_tickets SET used_unix_ms = ?2
             WHERE token_hash = ?1 AND used_unix_ms IS NULL AND expires_unix_ms > ?2",
            params![token_hash.as_str(), to_i64(now_unix_ms)?],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let consumed = ArtifactDownloadTicketRecord {
            used_unix_ms: Some(now_unix_ms),
            ..ticket
        };
        transaction.commit()?;
        Ok(consumed)
    }

    pub fn artifact_metrics(&self, tenant_id: &str) -> Result<ArtifactMetrics, ControlPlaneError> {
        validate_text("artifact metrics tenant", tenant_id)?;
        let connection = self.connection()?;
        let count = |sql: &str| -> Result<u64, ControlPlaneError> {
            let value: i64 = connection.query_row(sql, [tenant_id], |row| row.get(0))?;
            from_i64("artifact metric", value)
        };
        Ok(ArtifactMetrics {
            cataloged: count("SELECT COUNT(*) FROM artifacts_catalog WHERE tenant_id = ?1")?,
            quarantined: count(
                "SELECT COUNT(*) FROM artifacts_catalog WHERE tenant_id = ?1 AND state = 'quarantined'",
            )?,
            download_tickets_issued: count(
                "SELECT COUNT(*) FROM artifact_download_tickets WHERE tenant_id = ?1",
            )?,
            download_tickets_consumed: count(
                "SELECT COUNT(*) FROM artifact_download_tickets WHERE tenant_id = ?1 AND used_unix_ms IS NOT NULL",
            )?,
        })
    }
}

fn optional_artifact_download_ticket_tx(
    transaction: &Transaction<'_>,
    token_hash: &ContentDigest,
) -> Result<Option<ArtifactDownloadTicketRecord>, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT token_hash, artifact_id, tenant_id, principal_id, classification,
                    manifest_digest, issued_unix_ms, expires_unix_ms, used_unix_ms
             FROM artifact_download_tickets WHERE token_hash = ?1",
            [token_hash.as_str()],
            |row| {
                Ok(ArtifactDownloadTicketRecord {
                    token_hash: digest_column(row, 0)?,
                    artifact_id: row.get(1)?,
                    tenant_id: row.get(2)?,
                    principal_id: row.get(3)?,
                    classification: row.get(4)?,
                    manifest_digest: digest_column(row, 5)?,
                    issued_unix_ms: u64_column(row, 6, "issued_unix_ms")?,
                    expires_unix_ms: u64_column(row, 7, "expires_unix_ms")?,
                    used_unix_ms: optional_u64_column(row, 8, "used_unix_ms")?,
                })
            },
        )
        .optional()
        .map_err(ControlPlaneError::from)
}

pub(in crate::store) fn map_not_found(
    error: rusqlite::Error,
    kind: &'static str,
    id: &str,
) -> ControlPlaneError {
    if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
        ControlPlaneError::NotFound {
            kind,
            id: id.to_owned(),
        }
    } else {
        ControlPlaneError::Sqlite(error)
    }
}
