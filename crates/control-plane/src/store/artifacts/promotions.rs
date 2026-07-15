use super::super::*;

impl ControlPlane {
    pub fn create_artifact_promotion(
        &self,
        intent: &ArtifactPromotionIntent,
    ) -> Result<bool, ControlPlaneError> {
        validate_artifact_promotion(intent)?;
        if intent.status != "pending"
            || intent.promoted_artifact_id.is_some()
            || intent.promoted_manifest_digest.is_some()
            || intent.completed_unix_ms.is_some()
            || intent.last_error_code.is_some()
        {
            return Err(ControlPlaneError::InvalidInput(
                "new artifact promotion must be pending",
            ));
        }
        let expected_subject = artifact_promotion_subject_digest(intent)?;
        if expected_subject != intent.subject_digest {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source = optional_artifact_catalog_tx(
            &transaction,
            &intent.tenant_id,
            &intent.source_artifact_id,
        )?
        .ok_or_else(|| not_found("artifact promotion source", &intent.source_artifact_id))?;
        if source.manifest_digest != intent.source_manifest_digest
            || source.provenance_digest != intent.source_provenance_digest
            || source.classification != intent.source_classification
            || source.state == "retired"
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if intent.target_classification != "quarantined" {
            let scan_ok = intent.scan_evidence_digest.as_ref().is_some_and(|digest| {
                transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM artifact_scan_results
                         WHERE artifact_id = ?1 AND result_digest = ?2 AND status = 'passed')",
                        params![intent.source_artifact_id, digest.as_str()],
                        |row| row.get::<_, bool>(0),
                    )
                    .unwrap_or(false)
            });
            let waived = source.scan_state == "waived" && intent.approval_evidence_digest.is_some();
            if !scan_ok && !waived {
                return Err(ControlPlaneError::ArtifactPromotionEvidenceRequired);
            }
        }
        let existing = transaction
            .query_row(
                ARTIFACT_PROMOTION_SELECT,
                [&intent.id],
                artifact_promotion_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *intent {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO artifact_promotions
             (id, source_artifact_id, tenant_id, target_classification,
              evidence_digest, status, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
            params![
                intent.id,
                intent.source_artifact_id,
                intent.tenant_id,
                intent.target_classification,
                intent.evidence_digest.as_str(),
                to_i64(intent.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO artifact_promotion_bindings
             (promotion_id, subject_digest, source_manifest_digest,
              source_provenance_digest, source_classification, evidence_json,
              scan_evidence_digest, approval_evidence_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                intent.id,
                intent.subject_digest.as_str(),
                intent.source_manifest_digest.as_str(),
                intent.source_provenance_digest.as_str(),
                intent.source_classification,
                serde_json::to_string(&canonicalize_json(intent.evidence.clone()))?,
                intent
                    .scan_evidence_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
                intent
                    .approval_evidence_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    pub fn artifact_promotion(
        &self,
        tenant_id: &str,
        promotion_id: &str,
    ) -> Result<ArtifactPromotionIntent, ControlPlaneError> {
        validate_text("artifact promotion tenant", tenant_id)?;
        validate_text("artifact promotion id", promotion_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                &format!("{ARTIFACT_PROMOTION_SELECT} AND p.tenant_id = ?2"),
                params![promotion_id, tenant_id],
                artifact_promotion_row,
            )
            .optional()?
            .ok_or_else(|| not_found("artifact promotion", promotion_id))
    }

    pub fn complete_artifact_promotion(
        &self,
        tenant_id: &str,
        promotion_id: &str,
        promoted_artifact_id: &str,
        promoted_manifest_digest: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        validate_text("promoted artifact id", promoted_artifact_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                &format!("{ARTIFACT_PROMOTION_SELECT} AND p.tenant_id = ?2"),
                params![promotion_id, tenant_id],
                artifact_promotion_row,
            )
            .optional()?
            .ok_or_else(|| not_found("artifact promotion", promotion_id))?;
        if current.status == "succeeded" {
            if current.promoted_artifact_id.as_deref() == Some(promoted_artifact_id)
                && current.promoted_manifest_digest.as_ref() == Some(promoted_manifest_digest)
            {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if current.status != "pending" {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE artifact_promotions SET status = 'succeeded', promoted_artifact_id = ?2,
                    completed_unix_ms = ?3 WHERE id = ?1 AND status = 'pending'",
            params![promotion_id, promoted_artifact_id, to_i64(now_unix_ms)?],
        )?;
        transaction.execute(
            "UPDATE artifact_promotion_bindings SET promoted_manifest_digest = ?2
             WHERE promotion_id = ?1 AND promoted_manifest_digest IS NULL",
            params![promotion_id, promoted_manifest_digest.as_str()],
        )?;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "source_artifact_id".to_owned(),
            AuditValue::String(current.source_artifact_id),
        );
        metadata.insert(
            "promoted_artifact_id".to_owned(),
            AuditValue::String(promoted_artifact_id.to_owned()),
        );
        metadata.insert(
            "evidence_digest".to_owned(),
            AuditValue::Digest(current.evidence_digest),
        );
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: now_unix_ms,
                tenant_id: tenant_id.to_owned(),
                actor: AuditPrincipal {
                    kind: "worker".to_owned(),
                    id: "artifact-promotion".to_owned(),
                },
                action: "artifact.promote".to_owned(),
                resource: AuditResource {
                    kind: "artifact-promotion".to_owned(),
                    id: promotion_id.to_owned(),
                },
                result: "completed".to_owned(),
                request_id: promotion_id.to_owned(),
                decision_id: Some(current.subject_digest.to_string()),
                metadata,
            },
        )?;
        transaction.commit()?;
        Ok(false)
    }
}

pub fn artifact_promotion_subject_digest(
    intent: &ArtifactPromotionIntent,
) -> Result<ContentDigest, ControlPlaneError> {
    #[derive(Serialize)]
    struct Subject<'a> {
        domain: &'static str,
        tenant_id: &'a str,
        source_artifact_id: &'a str,
        source_manifest_digest: &'a ContentDigest,
        source_provenance_digest: &'a ContentDigest,
        source_classification: &'a str,
        target_classification: &'a str,
        evidence_digest: &'a ContentDigest,
        scan_evidence_digest: &'a Option<ContentDigest>,
        approval_evidence_digest: &'a Option<ContentDigest>,
    }
    Ok(ContentDigest::sha256(serde_json::to_vec(&Subject {
        domain: "runtrue.artifact-promotion-subject.v1",
        tenant_id: &intent.tenant_id,
        source_artifact_id: &intent.source_artifact_id,
        source_manifest_digest: &intent.source_manifest_digest,
        source_provenance_digest: &intent.source_provenance_digest,
        source_classification: &intent.source_classification,
        target_classification: &intent.target_classification,
        evidence_digest: &intent.evidence_digest,
        scan_evidence_digest: &intent.scan_evidence_digest,
        approval_evidence_digest: &intent.approval_evidence_digest,
    })?))
}

const ARTIFACT_PROMOTION_SELECT: &str =
    "SELECT p.id, b.subject_digest, p.tenant_id, p.source_artifact_id,
            b.source_manifest_digest, b.source_provenance_digest,
            b.source_classification, p.target_classification, p.evidence_digest,
            b.evidence_json, b.scan_evidence_digest, b.approval_evidence_digest,
            p.status, p.promoted_artifact_id, b.promoted_manifest_digest,
            p.created_unix_ms, p.completed_unix_ms, b.last_error_code
       FROM artifact_promotions p
       JOIN artifact_promotion_bindings b ON b.promotion_id = p.id
      WHERE p.id = ?1";

fn validate_artifact_promotion(intent: &ArtifactPromotionIntent) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("artifact promotion id", intent.id.as_str()),
        ("artifact promotion tenant", intent.tenant_id.as_str()),
        (
            "artifact promotion source",
            intent.source_artifact_id.as_str(),
        ),
    ] {
        validate_text(field, value)?;
    }
    let edge = (
        intent.source_classification.as_str(),
        intent.target_classification.as_str(),
    );
    if !matches!(
        edge,
        ("untrusted-build", "quarantined")
            | ("quarantined", "verified-test-output")
            | ("verified-test-output", "release-candidate")
            | ("release-candidate", "promoted-release")
            | ("promoted-release", "public")
    ) || !intent.evidence.is_object()
        || ContentDigest::sha256(serde_json::to_vec(&canonicalize_json(
            intent.evidence.clone(),
        ))?) != intent.evidence_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "artifact promotion metadata is invalid",
        ));
    }
    Ok(())
}

fn artifact_promotion_row(row: &Row<'_>) -> rusqlite::Result<ArtifactPromotionIntent> {
    Ok(ArtifactPromotionIntent {
        id: row.get(0)?,
        subject_digest: digest_column(row, 1)?,
        tenant_id: row.get(2)?,
        source_artifact_id: row.get(3)?,
        source_manifest_digest: digest_column(row, 4)?,
        source_provenance_digest: digest_column(row, 5)?,
        source_classification: row.get(6)?,
        target_classification: row.get(7)?,
        evidence_digest: digest_column(row, 8)?,
        evidence: json_column(row, 9)?,
        scan_evidence_digest: optional_digest_column(row, 10)?,
        approval_evidence_digest: optional_digest_column(row, 11)?,
        status: row.get(12)?,
        promoted_artifact_id: row.get(13)?,
        promoted_manifest_digest: optional_digest_column(row, 14)?,
        created_unix_ms: u64_column(row, 15, "artifact promotion creation")?,
        completed_unix_ms: optional_u64_column(row, 16, "artifact promotion completion")?,
        last_error_code: row.get(17)?,
    })
}
