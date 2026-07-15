use crate::{
    canonical::{
        canonical_digest, validate_collection_size, validate_identifier, validate_profile_name,
    },
    EvidenceCheckpoint, EvidenceEnvelope, ObjectTombstone, ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const EVIDENCE_EXPORT_DOMAIN: &[u8] = b"runtrue.provider.evidence-export-manifest.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    VerificationMetadata,
    OrdinaryPayload,
    SpeciallyGovernedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionRule {
    pub class: RetentionClass,
    pub policy_digest: ContentDigest,
    pub tenant_id: String,
    pub administrative_trust_domain: String,
    pub location_constraint: String,
    pub expires_unix_ms: u64,
    pub deletion_method: String,
    pub legal_hold_reference_digest: Option<ContentDigest>,
}

impl RetentionRule {
    pub fn validate(
        &self,
        sealed_minimum_expires_unix_ms: u64,
    ) -> Result<(), ProviderContractError> {
        validate_identifier("retention tenant", &self.tenant_id)?;
        validate_identifier("retention trust domain", &self.administrative_trust_domain)?;
        validate_profile_name(&self.location_constraint)?;
        validate_profile_name(&self.deletion_method)?;
        if self.expires_unix_ms < sealed_minimum_expires_unix_ms {
            return Err(ProviderContractError::InvalidRetention(
                "retention expiry is shorter than the sealed minimum",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadAvailability {
    Available { object_digest: ContentDigest },
    Omitted { reason: String },
    Redacted { reason: String },
    Expired { tombstone_digest: ContentDigest },
}

impl PayloadAvailability {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        match self {
            Self::Omitted { reason } | Self::Redacted { reason } => validate_profile_name(reason),
            Self::Available { .. } | Self::Expired { .. } => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExportManifest {
    pub export_version: u32,
    pub events: Vec<EvidenceEnvelope>,
    pub checkpoint: EvidenceCheckpoint,
    pub tombstones: Vec<ObjectTombstone>,
    pub manifest_digests: BTreeSet<ContentDigest>,
    pub payloads: BTreeMap<ContentDigest, PayloadAvailability>,
}

impl EvidenceExportManifest {
    pub fn validate_structure(&self) -> Result<(), ProviderContractError> {
        if self.export_version != 1 || self.events.is_empty() {
            return Err(ProviderContractError::InvalidRetention(
                "unsupported or empty Evidence export",
            ));
        }
        for length in [
            self.events.len(),
            self.tombstones.len(),
            self.manifest_digests.len(),
            self.payloads.len(),
        ] {
            validate_collection_size(length)?;
        }
        self.checkpoint.verify_structure(&self.events)?;
        for tombstone in &self.tombstones {
            tombstone.validate()?;
        }
        let tombstone_digests = self
            .tombstones
            .iter()
            .map(ObjectTombstone::digest)
            .collect::<Result<BTreeSet<_>, _>>()?;
        for availability in self.payloads.values() {
            availability.validate()?;
            if let PayloadAvailability::Expired { tombstone_digest } = availability {
                if !tombstone_digests.contains(tombstone_digest) {
                    return Err(ProviderContractError::InvalidRetention(
                        "expired payload does not reference an exported tombstone",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate_structure()?;
        canonical_digest(EVIDENCE_EXPORT_DOMAIN, self)
    }
}
