use crate::{validate_identifier, CacheError, CacheLimits};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionKind {
    TrustedRebuild,
    VerifiedAttestation,
    ManualSecurityApproval,
}

/// Evidence required for an explicit upward trust transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionEvidence {
    pub kind: PromotionKind,
    pub evidence_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionRecord {
    pub source_manifest_digest: ContentDigest,
    pub evidence: PromotionEvidence,
}
pub(crate) fn validate_promotion_evidence(
    evidence: &PromotionEvidence,
    limits: CacheLimits,
) -> Result<(), CacheError> {
    if evidence.kind == PromotionKind::ManualSecurityApproval && evidence.approval_id.is_none() {
        return Err(CacheError::InvalidPromotion(
            "manual security promotion requires an approval id".to_owned(),
        ));
    }
    if let Some(approval_id) = &evidence.approval_id {
        validate_identifier("promotion.approval_id", approval_id, limits)?;
    }
    Ok(())
}
