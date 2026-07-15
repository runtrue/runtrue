use crate::{ArtifactProducer, ArtifactPromotion, ArtifactProvenance};
use runtrue_model::ContentDigest;
use runtrue_storage::PathSnapshot;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactClassification {
    UntrustedBuild,
    Quarantined,
    VerifiedTestOutput,
    ReleaseCandidate,
    PromotedRelease,
    Sensitive,
    Public,
}

impl ArtifactClassification {
    #[must_use]
    pub const fn can_upload_directly(self) -> bool {
        matches!(
            self,
            Self::UntrustedBuild | Self::Quarantined | Self::VerifiedTestOutput | Self::Sensitive
        )
    }

    #[must_use]
    pub const fn can_promote_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::UntrustedBuild, Self::Quarantined)
                | (Self::Quarantined, Self::VerifiedTestOutput)
                | (Self::VerifiedTestOutput, Self::ReleaseCandidate)
                | (Self::ReleaseCandidate, Self::PromotedRelease)
                | (Self::PromotedRelease, Self::Public)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactScanState {
    Pending,
    Passed {
        scanner: String,
        report_digest: ContentDigest,
    },
    Failed {
        scanner: String,
        report_digest: ContentDigest,
    },
    Waived {
        approval_id: String,
        evidence_digest: ContentDigest,
    },
}

impl ArtifactScanState {
    pub(crate) const fn permits_trusted_promotion(&self) -> bool {
        matches!(self, Self::Passed { .. } | Self::Waived { .. })
    }
}

/// Immutable artifact metadata. Its external artifact ID is the digest of the
/// canonical JSON bytes for this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub record_version: u32,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub name: String,
    pub classification: ArtifactClassification,
    pub content: PathSnapshot,
    pub content_digest: ContentDigest,
    pub size_bytes: u64,
    pub media_type: String,
    pub producer: ArtifactProducer,
    pub provenance: ArtifactProvenance,
    pub scan_state: ArtifactScanState,
    pub committed_at_unix_seconds: u64,
    pub retention_until_unix_seconds: u64,
    pub legal_hold: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<ArtifactPromotion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactHandle {
    pub artifact_id: ContentDigest,
    pub record: ArtifactRecord,
}
