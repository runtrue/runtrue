use crate::{
    canonical::{
        canonical_bytes, canonical_digest, validate_collection_size, validate_identifier,
        validate_profile_name,
    },
    EvidenceCheckpoint, EvidenceEnvelope, EvidenceIdentities, EvidenceScopeKind, FailureResolution,
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const ATTESTATION_DOMAIN: &[u8] = b"runtrue.provider.attestation-statement.v1\0";
const ATTESTATION_SIGNATURE_DOMAIN: &[u8] = b"runtrue.provider.attestation-signature.v1\0";

pub trait AttestationSignatureVerifier {
    fn verify_attestation_signature(
        &self,
        issuer_id: &str,
        signing_key_id: &str,
        signing_key_generation: u64,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationStatement {
    pub statement_version: u32,
    pub evidence_schema_generation: u32,
    pub evidence_scope_kind: EvidenceScopeKind,
    pub subject_id: String,
    pub identities: EvidenceIdentities,
    pub evidence_chain_root_digest: ContentDigest,
    pub evidence_from_sequence: u64,
    pub evidence_through_sequence: u64,
    pub terminal_cleanup_event_digest: ContentDigest,
    pub admission_summary_digest: ContentDigest,
    pub lease_fence_summary_digest: ContentDigest,
    pub capability_summary_digest: ContentDigest,
    pub external_effect_summary_digest: ContentDigest,
    pub failure_resolution: Option<FailureResolution>,
    pub output_manifest_digests: BTreeSet<ContentDigest>,
    pub artifact_manifest_digests: BTreeSet<ContentDigest>,
    pub checkpoint_manifest_digests: BTreeSet<ContentDigest>,
    pub replay_bundle_manifest_digests: BTreeSet<ContentDigest>,
    pub cleanup_result_digest: ContentDigest,
    pub issuer_id: String,
    pub evidence_grade: String,
    pub isolation_grade: String,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub revocation_reference_digest: ContentDigest,
    pub extension_claim_digests: BTreeMap<String, ContentDigest>,
}

impl AttestationStatement {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.statement_version != 1
            || self.evidence_schema_generation == 0
            || self.evidence_from_sequence == 0
            || self.evidence_through_sequence < self.evidence_from_sequence
            || self.issued_unix_ms == 0
            || self.expires_unix_ms <= self.issued_unix_ms
        {
            return Err(ProviderContractError::InvalidAttestation(
                "invalid version, Evidence range, or lifetime",
            ));
        }
        validate_identifier("attestation subject", &self.subject_id)?;
        validate_identifier("attestation issuer", &self.issuer_id)?;
        validate_profile_name(&self.evidence_grade)?;
        validate_profile_name(&self.isolation_grade)?;
        self.identities.validate()?;
        if let Some(failure) = &self.failure_resolution {
            failure.validate()?;
        }
        for length in [
            self.output_manifest_digests.len(),
            self.artifact_manifest_digests.len(),
            self.checkpoint_manifest_digests.len(),
            self.replay_bundle_manifest_digests.len(),
            self.extension_claim_digests.len(),
        ] {
            validate_collection_size(length)?;
        }
        for name in self.extension_claim_digests.keys() {
            validate_profile_name(name)?;
        }
        Ok(())
    }

    pub fn validate_finalized_prefix(
        &self,
        checkpoint: &EvidenceCheckpoint,
        events: &[EvidenceEnvelope],
    ) -> Result<(), ProviderContractError> {
        self.validate()?;
        checkpoint.verify_structure(events)?;
        let terminal_cleanup = events
            .last()
            .ok_or(ProviderContractError::InvalidAttestation(
                "attestation Evidence prefix is empty",
            ))?;
        let cleanup_type = terminal_cleanup.event.event_type.as_str();
        let first = &events[0].event;
        if checkpoint.scope_kind != self.evidence_scope_kind
            || checkpoint.subject_id != self.subject_id
            || first.subject_sequence != self.evidence_from_sequence
            || checkpoint.through_sequence != self.evidence_through_sequence
            || checkpoint.chain_root_digest != self.evidence_chain_root_digest
            || terminal_cleanup.event.subject_sequence != self.evidence_through_sequence
            || terminal_cleanup.event_digest != self.terminal_cleanup_event_digest
            || terminal_cleanup.event.schema_generation != self.evidence_schema_generation
            || terminal_cleanup.event.identities != self.identities
            || !matches!(cleanup_type, "execution.cleanup" | "session.cleanup")
        {
            return Err(ProviderContractError::InvalidAttestation(
                "attestation is not bound to a finalized cleanup prefix",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(ATTESTATION_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAttestation {
    pub statement: AttestationStatement,
    pub statement_digest: ContentDigest,
    pub signature_algorithm: String,
    pub signing_key_id: String,
    pub signing_key_generation: u64,
    pub signature: Vec<u8>,
}

impl SignedAttestation {
    pub fn validate_structure(&self, now_unix_ms: u64) -> Result<(), ProviderContractError> {
        self.statement.validate()?;
        validate_profile_name(&self.signature_algorithm)?;
        validate_identifier("attestation signing key", &self.signing_key_id)?;
        if now_unix_ms < self.statement.issued_unix_ms
            || now_unix_ms >= self.statement.expires_unix_ms
            || self.signing_key_generation == 0
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
            || self.statement.digest()? != self.statement_digest
        {
            return Err(ProviderContractError::InvalidAttestation(
                "attestation is expired, malformed, or has a digest mismatch",
            ));
        }
        Ok(())
    }

    pub fn signature_message(&self, now_unix_ms: u64) -> Result<Vec<u8>, ProviderContractError> {
        self.validate_structure(now_unix_ms)?;
        #[derive(Serialize)]
        struct Subject<'a> {
            statement_digest: &'a ContentDigest,
            signature_algorithm: &'a str,
            signing_key_id: &'a str,
            signing_key_generation: u64,
        }
        let canonical = canonical_bytes(&Subject {
            statement_digest: &self.statement_digest,
            signature_algorithm: &self.signature_algorithm,
            signing_key_id: &self.signing_key_id,
            signing_key_generation: self.signing_key_generation,
        })?;
        let mut message = Vec::with_capacity(ATTESTATION_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(ATTESTATION_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        now_unix_ms: u64,
        verifier: &impl AttestationSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        let message = self.signature_message(now_unix_ms)?;
        if !verifier.verify_attestation_signature(
            &self.statement.issuer_id,
            &self.signing_key_id,
            self.signing_key_generation,
            &self.signature_algorithm,
            &message,
            &self.signature,
        ) {
            return Err(ProviderContractError::InvalidAttestation(
                "attestation signature verification failed",
            ));
        }
        Ok(())
    }
}
