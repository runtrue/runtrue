use super::super::*;

impl ControlPlane {
    pub fn enqueue_artifact_scan(
        &self,
        record: &ArtifactScanJournalRecord,
    ) -> Result<bool, ControlPlaneError> {
        validate_artifact_scan(record)?;
        if record.state != ArtifactScanState::Pending
            || record.attempts != 0
            || record.result_digest.is_some()
            || record.lease_owner.is_some()
            || record.lease_expires_unix_ms.is_some()
            || record.completed_unix_ms.is_some()
            || record.last_error_code.is_some()
        {
            return Err(ControlPlaneError::InvalidInput(
                "new artifact scan must be pending",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let artifact =
            optional_artifact_catalog_tx(&transaction, &record.tenant_id, &record.artifact_id)?
                .ok_or_else(|| not_found("artifact", &record.artifact_id))?;
        let expected = artifact_scan_subject_digest(&artifact, &record.scanner)?;
        if expected != record.subject_digest {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let existing = transaction
            .query_row(
                "SELECT id, tenant_id, artifact_id, scanner, subject_digest, state,
                        result_digest, lease_owner, lease_expires_unix_ms, attempts,
                        created_unix_ms, completed_unix_ms, last_error_code
                 FROM artifact_scan_journal WHERE id = ?1",
                [&record.id],
                artifact_scan_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *record {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO artifact_scan_journal
             (id, tenant_id, artifact_id, scanner, subject_digest, state, attempts,
              created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6)",
            params![
                record.id,
                record.tenant_id,
                record.artifact_id,
                record.scanner,
                record.subject_digest.as_str(),
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "UPDATE artifacts_catalog SET scan_state = 'pending', state = 'quarantined'
             WHERE artifact_id = ?1 AND tenant_id = ?2",
            params![record.artifact_id, record.tenant_id],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    pub fn claim_artifact_scan(
        &self,
        worker_id: &str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Option<ArtifactScanJournalRecord>, ControlPlaneError> {
        validate_text("scanner worker id", worker_id)?;
        if lease_duration_ms == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "scanner lease duration must be positive",
            ));
        }
        let expires =
            now_unix_ms
                .checked_add(lease_duration_ms)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "scanner lease expiry",
                })?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE artifact_scan_journal
             SET state = 'pending', lease_owner = NULL, lease_expires_unix_ms = NULL,
                 last_error_code = 'lease-expired'
             WHERE state = 'claimed' AND lease_expires_unix_ms <= ?1",
            [to_i64(now_unix_ms)?],
        )?;
        let id = transaction
            .query_row(
                "SELECT id FROM artifact_scan_journal
                 WHERE state = 'pending' ORDER BY created_unix_ms, id LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(id) = id else {
            transaction.commit()?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE artifact_scan_journal
             SET state = 'claimed', lease_owner = ?2, lease_expires_unix_ms = ?3,
                 attempts = attempts + 1
             WHERE id = ?1 AND state = 'pending'",
            params![id, worker_id, to_i64(expires)?],
        )?;
        let claimed = transaction.query_row(
            "SELECT id, tenant_id, artifact_id, scanner, subject_digest, state,
                    result_digest, lease_owner, lease_expires_unix_ms, attempts,
                    created_unix_ms, completed_unix_ms, last_error_code
             FROM artifact_scan_journal WHERE id = ?1",
            [&id],
            artifact_scan_row,
        )?;
        transaction.commit()?;
        Ok(Some(claimed))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "scanner completion keeps every lease, tenant, evidence, and time fence explicit"
    )]
    pub fn finish_artifact_scan(
        &self,
        tenant_id: &str,
        scan_id: &str,
        worker_id: &str,
        state: ArtifactScanState,
        result_digest: Option<&ContentDigest>,
        error_code: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        if !matches!(
            state,
            ArtifactScanState::Passed | ArtifactScanState::Failed | ArtifactScanState::Error
        ) || matches!(state, ArtifactScanState::Passed | ArtifactScanState::Failed)
            != result_digest.is_some()
        {
            return Err(ControlPlaneError::InvalidInput(
                "artifact scan result is invalid",
            ));
        }
        if let Some(value) = error_code {
            validate_text("scanner error code", value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scan = transaction
            .query_row(
                "SELECT id, tenant_id, artifact_id, scanner, subject_digest, state,
                        result_digest, lease_owner, lease_expires_unix_ms, attempts,
                        created_unix_ms, completed_unix_ms, last_error_code
                 FROM artifact_scan_journal WHERE id = ?1 AND tenant_id = ?2",
                params![scan_id, tenant_id],
                artifact_scan_row,
            )
            .optional()?
            .ok_or_else(|| not_found("artifact scan", scan_id))?;
        if scan.state == state && scan.result_digest.as_ref() == result_digest {
            transaction.commit()?;
            return Ok(true);
        }
        if scan.state != ArtifactScanState::Claimed
            || scan.lease_owner.as_deref() != Some(worker_id)
            || scan
                .lease_expires_unix_ms
                .is_none_or(|expiry| expiry <= now_unix_ms)
        {
            return Err(ControlPlaneError::TaskNotOwned);
        }
        if let Some(digest) = result_digest {
            transaction.execute(
                "INSERT OR IGNORE INTO artifact_scan_results
                 (artifact_id, scanner, result_digest, status, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    scan.artifact_id,
                    scan.scanner,
                    digest.as_str(),
                    artifact_scan_state_str(&state),
                    to_i64(now_unix_ms)?,
                ],
            )?;
        }
        transaction.execute(
            "UPDATE artifact_scan_journal
             SET state = ?3, result_digest = ?4, lease_owner = NULL,
                 lease_expires_unix_ms = NULL, completed_unix_ms = ?5,
                 last_error_code = ?6
             WHERE id = ?1 AND tenant_id = ?2 AND state = 'claimed'",
            params![
                scan_id,
                tenant_id,
                artifact_scan_state_str(&state),
                result_digest.map(ContentDigest::as_str),
                to_i64(now_unix_ms)?,
                error_code,
            ],
        )?;
        let passed = state == ArtifactScanState::Passed;
        transaction.execute(
            "UPDATE artifacts_catalog
             SET scan_state = ?3, state = CASE WHEN ?4 THEN 'available' ELSE 'quarantined' END
             WHERE artifact_id = ?1 AND tenant_id = ?2",
            params![
                scan.artifact_id,
                tenant_id,
                if passed { "passed" } else { "failed" },
                passed,
            ],
        )?;
        let mut metadata = BTreeMap::new();
        metadata.insert("scanner".to_owned(), AuditValue::String(scan.scanner));
        metadata.insert(
            "artifact_id".to_owned(),
            AuditValue::String(scan.artifact_id),
        );
        if let Some(digest) = result_digest {
            metadata.insert(
                "result_digest".to_owned(),
                AuditValue::Digest(digest.clone()),
            );
        }
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: now_unix_ms,
                tenant_id: tenant_id.to_owned(),
                actor: AuditPrincipal {
                    kind: "worker".to_owned(),
                    id: worker_id.to_owned(),
                },
                action: "artifact.scan".to_owned(),
                resource: AuditResource {
                    kind: "artifact-scan".to_owned(),
                    id: scan_id.to_owned(),
                },
                result: artifact_scan_state_str(&state).to_owned(),
                request_id: scan_id.to_owned(),
                decision_id: Some(scan.subject_digest.to_string()),
                metadata,
            },
        )?;
        transaction.commit()?;
        Ok(false)
    }
}

pub fn artifact_scan_subject_digest(
    artifact: &ArtifactCatalogRecord,
    scanner: &str,
) -> Result<ContentDigest, ControlPlaneError> {
    validate_text("scanner", scanner)?;
    #[derive(Serialize)]
    struct Subject<'a> {
        domain: &'static str,
        artifact_id: &'a str,
        tenant_id: &'a str,
        manifest_digest: &'a ContentDigest,
        provenance_digest: &'a ContentDigest,
        classification: &'a str,
        scanner: &'a str,
    }
    Ok(ContentDigest::sha256(serde_json::to_vec(&Subject {
        domain: "runtrue.artifact-scan-subject.v1",
        artifact_id: &artifact.artifact_id,
        tenant_id: &artifact.tenant_id,
        manifest_digest: &artifact.manifest_digest,
        provenance_digest: &artifact.provenance_digest,
        classification: &artifact.classification,
        scanner,
    })?))
}

fn artifact_scan_state_str(state: &ArtifactScanState) -> &'static str {
    match state {
        ArtifactScanState::Pending => "pending",
        ArtifactScanState::Claimed => "claimed",
        ArtifactScanState::Passed => "passed",
        ArtifactScanState::Failed => "failed",
        ArtifactScanState::Error => "error",
    }
}

fn validate_artifact_scan(scan: &ArtifactScanJournalRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("artifact scan id", scan.id.as_str()),
        ("artifact scan tenant", scan.tenant_id.as_str()),
        ("artifact scan artifact", scan.artifact_id.as_str()),
        ("artifact scan scanner", scan.scanner.as_str()),
    ] {
        validate_text(field, value)?;
    }
    Ok(())
}

fn artifact_scan_row(row: &Row<'_>) -> rusqlite::Result<ArtifactScanJournalRecord> {
    let raw: String = row.get(5)?;
    let state = match raw.as_str() {
        "pending" => ArtifactScanState::Pending,
        "claimed" => ArtifactScanState::Claimed,
        "passed" => ArtifactScanState::Passed,
        "failed" => ArtifactScanState::Failed,
        "error" => ArtifactScanState::Error,
        _ => {
            return Err(conversion(
                5,
                DecodeError("invalid artifact scan state".to_owned()),
            ));
        }
    };
    Ok(ArtifactScanJournalRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        artifact_id: row.get(2)?,
        scanner: row.get(3)?,
        subject_digest: digest_column(row, 4)?,
        state,
        result_digest: optional_digest_column(row, 6)?,
        lease_owner: row.get(7)?,
        lease_expires_unix_ms: optional_u64_column(row, 8, "scan lease expiry")?,
        attempts: u32::try_from(row.get::<_, i64>(9)?)
            .map_err(|error| conversion(9, DecodeError(error.to_string())))?,
        created_unix_ms: u64_column(row, 10, "scan creation")?,
        completed_unix_ms: optional_u64_column(row, 11, "scan completion")?,
        last_error_code: row.get(12)?,
    })
}
