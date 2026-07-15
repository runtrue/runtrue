use crate::LifecycleError;
use runtrue_artifacts::{ArtifactClassification, ArtifactPromotionEvidence, ArtifactStore};
use runtrue_control_plane::ControlPlane;
use runtrue_model::ContentDigest;

/// Execute an exact durable artifact promotion against the real immutable
/// artifact store. The source record is never changed; replay recovers the
/// same promoted record digest.
pub fn execute_artifact_promotion(
    control: &ControlPlane,
    artifacts: &ArtifactStore,
    tenant_id: &str,
    promotion_id: &str,
    now_unix_ms: u64,
) -> Result<ContentDigest, LifecycleError> {
    let intent = control.artifact_promotion(tenant_id, promotion_id)?;
    if intent.status == "succeeded" {
        let promoted_id = ContentDigest::parse(
            intent
                .promoted_artifact_id
                .ok_or(LifecycleError::PromotionResultMissing)?,
        )
        .map_err(|_| LifecycleError::PromotionResultMissing)?;
        let promoted = artifacts.load(&promoted_id)?;
        let promotion = promoted
            .record
            .promotion
            .as_ref()
            .ok_or(LifecycleError::PromotionResultMissing)?;
        let expected_evidence: ArtifactPromotionEvidence =
            serde_json::from_value(intent.evidence.clone())?;
        if promotion.source_record_digest.as_str() != intent.source_artifact_id
            || promotion.evidence != expected_evidence
            || serde_json::to_value(promoted.record.classification)?
                != serde_json::Value::String(intent.target_classification)
        {
            return Err(LifecycleError::PromotionSourceMismatch);
        }
        return Ok(promoted_id);
    }
    if intent.status != "pending" {
        return Err(LifecycleError::PromotionNotPending);
    }
    let source_id = ContentDigest::parse(&intent.source_artifact_id)
        .map_err(|_| LifecycleError::PromotionSourceMismatch)?;
    let source = artifacts.load(&source_id)?;
    if source.artifact_id != source_id
        || source.record.content_digest != intent.source_manifest_digest
        || source.record.tenant_id != intent.tenant_id
        || source.record.provenance.statement_digest != intent.source_provenance_digest
        || serde_json::to_value(source.record.classification)?
            != serde_json::Value::String(intent.source_classification.clone())
    {
        return Err(LifecycleError::PromotionSourceMismatch);
    }
    let target: ArtifactClassification = serde_json::from_value(serde_json::Value::String(
        intent.target_classification.clone(),
    ))?;
    let evidence: ArtifactPromotionEvidence = serde_json::from_value(intent.evidence.clone())?;
    if intent
        .approval_evidence_digest
        .as_ref()
        .is_some_and(|digest| digest != &evidence.evidence_digest)
    {
        return Err(LifecycleError::PromotionEvidenceMismatch);
    }
    let evidence_bytes = serde_json::to_vec(&intent.evidence)?;
    if ContentDigest::sha256(&evidence_bytes) != intent.evidence_digest {
        return Err(LifecycleError::PromotionEvidenceMismatch);
    }
    let evidence_object = artifacts.cas().put_bytes(&evidence_bytes)?;
    if evidence_object.digest != intent.evidence_digest {
        return Err(LifecycleError::PromotionEvidenceMismatch);
    }
    if let Some(digest) = &intent.scan_evidence_digest {
        artifacts.cas().verify_blob(digest)?;
    }
    if let Some(digest) = &intent.approval_evidence_digest {
        artifacts.cas().verify_blob(digest)?;
    }
    let promoted =
        artifacts.promote(&source_id, target, evidence, intent.created_unix_ms / 1_000)?;
    control.complete_artifact_promotion(
        tenant_id,
        promotion_id,
        promoted.artifact_id.as_str(),
        &promoted.artifact_id,
        now_unix_ms,
    )?;
    Ok(promoted.artifact_id)
}
