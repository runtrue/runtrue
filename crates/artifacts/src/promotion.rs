use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPromotionKind {
    QuarantineReview,
    TrustedRebuild,
    VerifiedAttestation,
    ReleaseApproval,
    PublicationApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPromotionEvidence {
    pub kind: ArtifactPromotionKind,
    pub evidence_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub policy_version_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPromotion {
    pub source_record_digest: ContentDigest,
    pub from: ArtifactClassification,
    pub to: ArtifactClassification,
    pub promoted_at_unix_seconds: u64,
    pub evidence: ArtifactPromotionEvidence,
}

impl ArtifactStore {
    pub fn promote(
        &self,
        source_artifact_id: &ContentDigest,
        target: ArtifactClassification,
        evidence: ArtifactPromotionEvidence,
        now_unix_seconds: u64,
    ) -> Result<ArtifactHandle, ArtifactError> {
        let source = self.load(source_artifact_id)?;
        let from = source.record.classification;
        if !from.can_promote_to(target) {
            return Err(ArtifactError::InvalidPromotion(
                "classification transition is not allowed".to_owned(),
            ));
        }
        validate_promotion_evidence(from, target, &evidence, self.limits)?;
        if matches!(
            target,
            ArtifactClassification::VerifiedTestOutput
                | ArtifactClassification::ReleaseCandidate
                | ArtifactClassification::PromotedRelease
                | ArtifactClassification::Public
        ) && !source.record.scan_state.permits_trusted_promotion()
        {
            return Err(ArtifactError::InvalidPromotion(
                "trusted promotion requires a passed or explicitly waived scan".to_owned(),
            ));
        }
        let mut record = source.record;
        record.classification = target;
        record.promotion = Some(ArtifactPromotion {
            source_record_digest: source_artifact_id.clone(),
            from,
            to: target,
            promoted_at_unix_seconds: now_unix_seconds,
            evidence,
        });
        let artifact_id = self.store_record(&record)?;
        Ok(ArtifactHandle {
            artifact_id,
            record,
        })
    }
}

pub(crate) fn validate_promotion_evidence(
    from: ArtifactClassification,
    to: ArtifactClassification,
    evidence: &ArtifactPromotionEvidence,
    limits: ArtifactLimits,
) -> Result<(), ArtifactError> {
    if evidence
        .policy_version_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || evidence.policy_version_ids.iter().any(String::is_empty)
    {
        return Err(ArtifactError::InvalidPromotion(
            "promotion policy versions must be sorted, unique, and non-empty".to_owned(),
        ));
    }
    let kind_allowed = matches!(
        (from, to, evidence.kind),
        (
            ArtifactClassification::UntrustedBuild,
            ArtifactClassification::Quarantined,
            ArtifactPromotionKind::QuarantineReview
        ) | (
            ArtifactClassification::Quarantined,
            ArtifactClassification::VerifiedTestOutput,
            ArtifactPromotionKind::TrustedRebuild | ArtifactPromotionKind::VerifiedAttestation
        ) | (
            ArtifactClassification::VerifiedTestOutput,
            ArtifactClassification::ReleaseCandidate,
            ArtifactPromotionKind::VerifiedAttestation | ArtifactPromotionKind::ReleaseApproval
        ) | (
            ArtifactClassification::ReleaseCandidate,
            ArtifactClassification::PromotedRelease,
            ArtifactPromotionKind::ReleaseApproval
        ) | (
            ArtifactClassification::PromotedRelease,
            ArtifactClassification::Public,
            ArtifactPromotionKind::PublicationApproval
        )
    );
    if !kind_allowed {
        return Err(ArtifactError::InvalidPromotion(
            "promotion evidence kind does not authorize this transition".to_owned(),
        ));
    }
    let approval_required = matches!(
        evidence.kind,
        ArtifactPromotionKind::QuarantineReview
            | ArtifactPromotionKind::ReleaseApproval
            | ArtifactPromotionKind::PublicationApproval
    );
    if approval_required && evidence.approval_id.is_none() {
        return Err(ArtifactError::InvalidPromotion(
            "promotion evidence requires an approval id".to_owned(),
        ));
    }
    if let Some(approval_id) = &evidence.approval_id {
        validate_identifier("promotion.approval_id", approval_id, limits)?;
    }
    Ok(())
}
use crate::{
    validate_identifier, ArtifactClassification, ArtifactError, ArtifactHandle, ArtifactLimits,
    ArtifactStore,
};
