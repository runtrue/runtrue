use crate::{validation::canonical_bytes, BisimError, BisimResultBinding};
use runtrue_model::ContentDigest;
use runtrue_provider_contract::{
    BisimPortableObservation, DeployedProviderGeneration, EvidenceCheckpoint, EvidenceEnvelope,
    EvidenceProducerIdentity, EvidenceProducerKind, EvidenceSignatureVerifier,
};
use serde::{Deserialize, Serialize};

const PORTABLE_PAYLOAD_DOMAIN: &[u8] = b"runtrue.bisim.portable-evidence-payload.v1\0";
const EVIDENCE_PRODUCER_DOMAIN: &[u8] = b"runtrue.bisim.evidence-producer-identity.v1\0";
const PORTABLE_EVENT_TYPE: &str = "bisim.portable-observation";

/// Self-contained provider proof for one active Bisim portable observation.
///
/// Structural verification binds the complete portable payload and exact
/// normalized engine-result identity to the terminal Evidence event and its
/// checkpoint. `verify_with` additionally authenticates every event and the
/// checkpoint against the caller's configured trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimPortableEvidence {
    pub deployed_provider: DeployedProviderGeneration,
    pub events: Vec<EvidenceEnvelope>,
    pub checkpoint: EvidenceCheckpoint,
}

impl BisimPortableEvidence {
    pub fn verify_structure(
        &self,
        portable: &BisimPortableObservation,
        result_binding: &BisimResultBinding,
    ) -> Result<(), BisimError> {
        portable.validate()?;
        self.deployed_provider.validate()?;
        self.checkpoint.verify_structure(&self.events)?;

        let terminal = self
            .events
            .last()
            .ok_or(BisimError::InvalidEvidenceBinding(
                "portable observation has no Evidence event",
            ))?;
        let event = &terminal.event;
        let provider = &self.deployed_provider.provider;
        let provider_digest = provider.digest()?;
        let deployed_digest = self.deployed_provider.digest()?;

        if event.event_type != PORTABLE_EVENT_TYPE
            || event.producer.kind != EvidenceProducerKind::ProviderControlPlane
            || event.producer != self.checkpoint.producer
            || event.producer.producer_id != provider.provider_id
            || event.producer.authentication_identity_digest != provider.authentication_key_digest
            || event.producer.signing_key_generation
                != self.deployed_provider.signing_key_generation
            || event.administrative_trust_domain.as_deref()
                != Some(provider.administrative_trust_domain.as_str())
        {
            return Err(BisimError::InvalidEvidenceBinding(
                "Evidence producer or checkpoint is not the deployed Provider",
            ));
        }

        let payload = portable_payload_bytes(portable, result_binding)?;
        let payload_size = u64::try_from(payload.len()).map_err(|_| {
            BisimError::InvalidEvidenceBinding("portable Evidence payload is oversized")
        })?;
        if event.payload_digest != ContentDigest::sha256(&payload)
            || event.payload_size_bytes != payload_size
        {
            return Err(BisimError::InvalidEvidenceBinding(
                "portable observation differs from its signed Evidence payload",
            ));
        }

        let identities = &event.identities;
        if portable.provider_identity_digest != provider_digest
            || identities.provider_identity_digest.as_ref() != Some(&provider_digest)
            || identities.deployed_provider_generation_digest.as_ref() != Some(&deployed_digest)
            || identities.program_digest.as_ref() != Some(&portable.program_digest)
            || identities.capsule_digest.as_ref() != Some(&portable.capsule_digest)
            || identities.runtime_compatibility_digest.as_ref()
                != Some(&portable.runtime_compatibility_digest)
            || portable.evidence_producer_identity_digest
                != evidence_producer_identity_digest(&event.producer)?
        {
            return Err(BisimError::InvalidEvidenceBinding(
                "portable identities differ from signed Provider Evidence",
            ));
        }
        Ok(())
    }

    pub fn verify_with(
        &self,
        portable: &BisimPortableObservation,
        result_binding: &BisimResultBinding,
        verifier: &impl EvidenceSignatureVerifier,
    ) -> Result<(), BisimError> {
        self.verify_structure(portable, result_binding)?;
        self.checkpoint.verify_with(&self.events, verifier)?;
        Ok(())
    }
}

/// Digest the portable observation and exact engine-result binding as a
/// Provider must record them in the terminal Bisim Evidence event.
pub fn portable_evidence_payload_digest(
    portable: &BisimPortableObservation,
    result_binding: &BisimResultBinding,
) -> Result<ContentDigest, BisimError> {
    portable.validate()?;
    Ok(ContentDigest::sha256(portable_payload_bytes(
        portable,
        result_binding,
    )?))
}

/// Canonical byte length paired with `portable_evidence_payload_digest` in an
/// Evidence event. Providers must not report a caller-selected payload size.
pub fn portable_evidence_payload_size(
    portable: &BisimPortableObservation,
    result_binding: &BisimResultBinding,
) -> Result<u64, BisimError> {
    portable.validate()?;
    u64::try_from(portable_payload_bytes(portable, result_binding)?.len())
        .map_err(|_| BisimError::InvalidEvidenceBinding("portable Evidence payload is oversized"))
}

/// Canonical identity used by the portable observation's Evidence-producer
/// admission set. This binds the complete producer identity, including its key
/// generation, rather than trusting a caller-selected label.
pub fn evidence_producer_identity_digest(
    producer: &EvidenceProducerIdentity,
) -> Result<ContentDigest, BisimError> {
    producer.validate()?;
    let canonical = canonical_bytes(producer)?;
    let mut material = Vec::with_capacity(EVIDENCE_PRODUCER_DOMAIN.len() + canonical.len());
    material.extend_from_slice(EVIDENCE_PRODUCER_DOMAIN);
    material.extend_from_slice(&canonical);
    Ok(ContentDigest::sha256(material))
}

fn portable_payload_bytes(
    portable: &BisimPortableObservation,
    result_binding: &BisimResultBinding,
) -> Result<Vec<u8>, BisimError> {
    #[derive(Serialize)]
    struct SignedPayload<'a> {
        portable: &'a BisimPortableObservation,
        result_binding: &'a BisimResultBinding,
    }
    let canonical = canonical_bytes(&SignedPayload {
        portable,
        result_binding,
    })?;
    let mut payload = Vec::with_capacity(PORTABLE_PAYLOAD_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(PORTABLE_PAYLOAD_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}
