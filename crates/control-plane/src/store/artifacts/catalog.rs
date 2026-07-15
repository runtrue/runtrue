use super::super::*;

impl ControlPlane {
    /// Derive an immutable runner grant from durable lease/run/capsule state.
    /// The runner supplies only its desired audience and exact execution
    /// coordinates; it cannot submit trust, repository, environment, approval,
    /// or source claims.
    pub fn catalog_artifact(
        &self,
        record: &ArtifactCatalogRecord,
    ) -> Result<IdempotentResult<ArtifactCatalogRecord>, ControlPlaneError> {
        for (field, value) in [
            ("artifact id", record.artifact_id.as_str()),
            ("tenant id", record.tenant_id.as_str()),
            ("repository id", record.repository_id.as_str()),
            ("run id", record.run_id.as_str()),
            ("job id", record.job_id.as_str()),
            ("step id", record.step_id.as_str()),
            ("output name", record.output_name.as_str()),
            ("media type", record.media_type.as_str()),
            ("classification", record.classification.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if record.job_attempt == 0
            || !matches!(
                record.scan_state.as_str(),
                "pending" | "passed" | "failed" | "waived"
            )
            || !matches!(
                record.state.as_str(),
                "available" | "quarantined" | "retired"
            )
        {
            return Err(ControlPlaneError::InvalidInput(
                "artifact catalog metadata is invalid",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM job_result_objects o
                JOIN jobs j ON j.id = o.job_id
                JOIN runs r ON r.id = j.run_id
                JOIN repositories repo ON repo.id = r.repository_id
                WHERE o.job_id = ?1 AND o.job_attempt = ?2 AND o.kind = 'artifact'
                  AND o.object_id = ?3 AND j.run_id = ?4 AND r.repository_id = ?5
                  AND repo.tenant_id = ?6
             )",
            params![
                record.job_id,
                i64::from(record.job_attempt),
                record.artifact_id,
                record.run_id,
                record.repository_id,
                record.tenant_id
            ],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(ControlPlaneError::NotFound {
                kind: "artifact",
                id: record.artifact_id.clone(),
            });
        }
        let existing =
            optional_artifact_catalog_tx(&transaction, &record.tenant_id, &record.artifact_id)?;
        if let Some(existing) = existing {
            if existing != *record {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            account_artifact_storage_ticket_if_present_tx(
                &transaction,
                record,
                record.created_unix_ms,
            )?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        transaction.execute(
            "INSERT INTO artifacts_catalog
             (artifact_id, tenant_id, repository_id, run_id, job_id, job_attempt,
              result_kind, step_id, output_name, content_digest, manifest_digest,
              provenance_digest, size_bytes, media_type, classification, scan_state,
              retention_until_unix_seconds, legal_hold, state, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'artifact', ?7, ?8, ?9, ?10,
                     ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                record.artifact_id,
                record.tenant_id,
                record.repository_id,
                record.run_id,
                record.job_id,
                i64::from(record.job_attempt),
                record.step_id,
                record.output_name,
                record.content_digest.as_str(),
                record.manifest_digest.as_str(),
                record.provenance_digest.as_str(),
                to_i64(record.size_bytes)?,
                record.media_type,
                record.classification,
                record.scan_state,
                to_i64(record.retention_until_unix_seconds)?,
                record.legal_hold,
                record.state,
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        account_artifact_storage_ticket_if_present_tx(
            &transaction,
            record,
            record.created_unix_ms,
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record.clone(),
            replayed: false,
        })
    }

    pub fn artifact_for_tenant(
        &self,
        tenant_id: &str,
        artifact_id: &str,
    ) -> Result<ArtifactCatalogRecord, ControlPlaneError> {
        validate_text("tenant id", tenant_id)?;
        validate_text("artifact id", artifact_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        optional_artifact_catalog_tx(&transaction, tenant_id, artifact_id)?.ok_or_else(|| {
            ControlPlaneError::NotFound {
                kind: "artifact",
                id: artifact_id.to_owned(),
            }
        })
    }

    pub fn artifact(&self, artifact_id: &str) -> Result<ArtifactCatalogRecord, ControlPlaneError> {
        validate_text("artifact id", artifact_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction
            .query_row(
                "SELECT artifact_id, tenant_id, repository_id, run_id, job_id, job_attempt,
                        step_id, output_name, content_digest, manifest_digest, provenance_digest,
                        size_bytes, media_type, classification, scan_state,
                        retention_until_unix_seconds, legal_hold, state, created_unix_ms
                 FROM artifacts_catalog WHERE artifact_id = ?1",
                [artifact_id],
                artifact_catalog_row,
            )
            .optional()?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "artifact",
                id: artifact_id.to_owned(),
            })
    }
}

pub(in crate::store) fn optional_artifact_catalog_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    artifact_id: &str,
) -> Result<Option<ArtifactCatalogRecord>, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT artifact_id, tenant_id, repository_id, run_id, job_id, job_attempt,
                    step_id, output_name, content_digest, manifest_digest, provenance_digest,
                    size_bytes, media_type, classification, scan_state,
                    retention_until_unix_seconds, legal_hold, state, created_unix_ms
             FROM artifacts_catalog WHERE tenant_id = ?1 AND artifact_id = ?2",
            params![tenant_id, artifact_id],
            artifact_catalog_row,
        )
        .optional()
        .map_err(ControlPlaneError::from)
}

fn artifact_catalog_row(row: &Row<'_>) -> rusqlite::Result<ArtifactCatalogRecord> {
    Ok(ArtifactCatalogRecord {
        artifact_id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        run_id: row.get(3)?,
        job_id: row.get(4)?,
        job_attempt: u32::try_from(row.get::<_, i64>(5)?).map_err(|error| conversion(5, error))?,
        step_id: row.get(6)?,
        output_name: row.get(7)?,
        content_digest: digest_column(row, 8)?,
        manifest_digest: digest_column(row, 9)?,
        provenance_digest: digest_column(row, 10)?,
        size_bytes: u64_column(row, 11, "size_bytes")?,
        media_type: row.get(12)?,
        classification: row.get(13)?,
        scan_state: row.get(14)?,
        retention_until_unix_seconds: u64_column(row, 15, "retention_until_unix_seconds")?,
        legal_hold: row.get(16)?,
        state: row.get(17)?,
        created_unix_ms: u64_column(row, 18, "created_unix_ms")?,
    })
}
