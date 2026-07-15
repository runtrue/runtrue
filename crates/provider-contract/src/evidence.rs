use crate::{
    canonical::{
        canonical_digest, validate_collection_size, validate_identifier, validate_profile_name,
        validate_text, MAX_SHORT_TEXT_BYTES,
    },
    DeployedProviderGeneration, ProviderContractError, ProviderIdentity,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const EVIDENCE_EVENT_DOMAIN: &[u8] = b"runtrue.provider.evidence-event.v1\0";
const EVIDENCE_CHECKPOINT_DOMAIN: &[u8] = b"runtrue.provider.evidence-checkpoint.v1\0";
const EVIDENCE_EVENT_SIGNATURE_DOMAIN: &[u8] = b"runtrue.provider.evidence-event-signature.v1\0";
const EVIDENCE_CHECKPOINT_SIGNATURE_DOMAIN: &[u8] =
    b"runtrue.provider.evidence-checkpoint-signature.v1\0";

/// Cryptographic adapter supplied by a trust-boundary implementation. The
/// contract crate defines the exact signing bytes but does not choose a crypto
/// library or key resolver.
pub trait EvidenceSignatureVerifier {
    fn verify_signature(
        &self,
        producer: &EvidenceProducerIdentity,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScopeKind {
    Execution,
    Session,
    SterileTemplate,
    PoolMember,
    RuntimeInventory,
    ProviderDeployment,
    BisimConformance,
    BackendSecurityConformance,
    ClientClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProducerKind {
    ExecutionPlane,
    Runner,
    CapabilityBroker,
    StoragePlane,
    ProviderControlPlane,
    ConformanceHarness,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProducerIdentity {
    pub kind: EvidenceProducerKind,
    pub producer_id: String,
    pub authentication_identity_digest: ContentDigest,
    pub signing_key_id: ContentDigest,
    pub signing_key_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSignature {
    pub algorithm: String,
    pub signing_key_id: ContentDigest,
    pub signing_key_generation: u64,
    pub signature: Vec<u8>,
}

impl EvidenceSignature {
    pub fn validate_for(
        &self,
        producer: &EvidenceProducerIdentity,
    ) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.algorithm)?;
        if self.signing_key_id != producer.signing_key_id
            || self.signing_key_generation != producer.signing_key_generation
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
        {
            return Err(ProviderContractError::InvalidEvidence(
                "Evidence signature is empty, oversized, or belongs to another producer key",
            ));
        }
        Ok(())
    }
}

impl EvidenceProducerIdentity {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Evidence producer id", &self.producer_id)?;
        if self.signing_key_generation == 0 {
            return Err(ProviderContractError::InvalidEvidence(
                "producer signing-key generation must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentities {
    pub provider_identity_digest: Option<ContentDigest>,
    pub deployed_provider_generation_digest: Option<ContentDigest>,
    pub program_digest: Option<ContentDigest>,
    pub capsule_digest: Option<ContentDigest>,
    pub seal_digest: Option<ContentDigest>,
    pub policy_digest: Option<ContentDigest>,
    pub execution_id: Option<String>,
    pub session_id: Option<String>,
    pub sterile_template_digest: Option<ContentDigest>,
    pub pool_id: Option<String>,
    pub runtime_compatibility_digest: Option<ContentDigest>,
    pub conformance_profile_digest: Option<ContentDigest>,
}

impl EvidenceIdentities {
    pub fn for_provider(
        provider: &ProviderIdentity,
        deployed: &DeployedProviderGeneration,
    ) -> Result<Self, ProviderContractError> {
        if provider != &deployed.provider {
            return Err(ProviderContractError::InvalidEvidence(
                "Provider and deployed generation identities differ",
            ));
        }
        Ok(Self {
            provider_identity_digest: Some(provider.digest()?),
            deployed_provider_generation_digest: Some(deployed.digest()?),
            ..Self::default()
        })
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if let Some(id) = &self.execution_id {
            validate_identifier("Evidence Execution id", id)?;
        }
        if let Some(id) = &self.session_id {
            validate_identifier("Evidence Session id", id)?;
        }
        if let Some(id) = &self.pool_id {
            validate_identifier("Evidence pool id", id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLink {
    pub relation: String,
    pub scope_kind: EvidenceScopeKind,
    pub subject_id: String,
    pub event_digest: Option<ContentDigest>,
}

impl EvidenceLink {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.relation)?;
        validate_identifier("related Evidence subject id", &self.subject_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceObservedTime {
    pub wall_unix_nanoseconds: u64,
    pub wall_precision_nanoseconds: u64,
    pub monotonic_nanoseconds: u64,
    pub monotonic_precision_nanoseconds: u64,
}

impl EvidenceObservedTime {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.wall_precision_nanoseconds == 0 || self.monotonic_precision_nanoseconds == 0 {
            return Err(ProviderContractError::InvalidEvidence(
                "declared clock precision must be positive",
            ));
        }
        Ok(())
    }
}

/// Canonical event material before its digest is attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEvent {
    pub envelope_version: u32,
    pub scope_kind: EvidenceScopeKind,
    pub subject_id: String,
    pub tenant_id: Option<String>,
    pub administrative_trust_domain: Option<String>,
    pub identities: EvidenceIdentities,
    pub subject_sequence: u64,
    pub previous_event_digest: Option<ContentDigest>,
    pub event_type: String,
    pub schema_generation: u32,
    pub payload_digest: ContentDigest,
    pub payload_size_bytes: u64,
    pub producer: EvidenceProducerIdentity,
    pub observed_time: EvidenceObservedTime,
    pub links: Vec<EvidenceLink>,
    pub provider_diagnostics: BTreeMap<String, String>,
}

impl EvidenceEvent {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.envelope_version != 1 || self.schema_generation == 0 || self.subject_sequence == 0 {
            return Err(ProviderContractError::InvalidEvidence(
                "unsupported version or zero sequence/generation",
            ));
        }
        validate_identifier("Evidence subject id", &self.subject_id)?;
        if let Some(tenant) = &self.tenant_id {
            validate_identifier("Evidence tenant id", tenant)?;
        }
        if let Some(domain) = &self.administrative_trust_domain {
            validate_identifier("Evidence administrative trust domain", domain)?;
        }
        if self.tenant_id.is_none() && self.administrative_trust_domain.is_none() {
            return Err(ProviderContractError::InvalidEvidence(
                "tenant or administrative trust domain is required",
            ));
        }
        self.identities.validate()?;
        self.producer.validate()?;
        self.observed_time.validate()?;
        validate_profile_name(&self.event_type)?;
        if (self.subject_sequence == 1) != self.previous_event_digest.is_none() {
            return Err(ProviderContractError::InvalidEvidence(
                "genesis and previous-event linkage disagree",
            ));
        }
        validate_collection_size(self.links.len())?;
        for link in &self.links {
            link.validate()?;
        }
        if self.links.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ProviderContractError::InvalidEvidence(
                "Evidence links must be strictly sorted and unique",
            ));
        }
        validate_collection_size(self.provider_diagnostics.len())?;
        for (key, value) in &self.provider_diagnostics {
            if !key.starts_with("provider.") {
                return Err(ProviderContractError::InvalidEvidence(
                    "Provider diagnostics keys must use the provider namespace",
                ));
            }
            validate_profile_name(key)?;
            validate_text("Provider diagnostic value", value, MAX_SHORT_TEXT_BYTES)?;
        }
        if self.scope_kind == EvidenceScopeKind::ClientClaim
            && self.producer.kind != EvidenceProducerKind::Client
        {
            return Err(ProviderContractError::InvalidEvidence(
                "client claims require a client producer",
            ));
        }
        if self.scope_kind != EvidenceScopeKind::ClientClaim
            && self.producer.kind == EvidenceProducerKind::Client
        {
            return Err(ProviderContractError::InvalidEvidence(
                "clients cannot produce portable Provider Evidence",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(EVIDENCE_EVENT_DOMAIN, self)
    }

    pub fn seal(
        self,
        signature: EvidenceSignature,
    ) -> Result<EvidenceEnvelope, ProviderContractError> {
        let event_digest = self.digest()?;
        signature.validate_for(&self.producer)?;
        Ok(EvidenceEnvelope {
            event: self,
            event_digest,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    #[serde(flatten)]
    pub event: EvidenceEvent,
    pub event_digest: ContentDigest,
    pub signature: EvidenceSignature,
}

impl EvidenceEnvelope {
    /// Checks canonical digest linkage and signature metadata only. Portable
    /// authenticity requires `verify_with`.
    pub fn verify_structure(&self) -> Result<(), ProviderContractError> {
        self.signature.validate_for(&self.event.producer)?;
        let actual = self.event.digest()?;
        if actual != self.event_digest {
            return Err(ProviderContractError::EvidenceDigestMismatch {
                expected: self.event_digest.clone(),
                actual,
            });
        }
        Ok(())
    }

    pub fn signature_message(&self) -> Result<Vec<u8>, ProviderContractError> {
        self.verify_structure()?;
        #[derive(Serialize)]
        struct Subject<'a> {
            event_digest: &'a ContentDigest,
            algorithm: &'a str,
            signing_key_id: &'a ContentDigest,
            signing_key_generation: u64,
        }
        let canonical = crate::canonical::canonical_bytes(&Subject {
            event_digest: &self.event_digest,
            algorithm: &self.signature.algorithm,
            signing_key_id: &self.signature.signing_key_id,
            signing_key_generation: self.signature.signing_key_generation,
        })?;
        let mut message =
            Vec::with_capacity(EVIDENCE_EVENT_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(EVIDENCE_EVENT_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        verifier: &impl EvidenceSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        let message = self.signature_message()?;
        if !verifier.verify_signature(
            &self.event.producer,
            &self.signature.algorithm,
            &message,
            &self.signature.signature,
        ) {
            return Err(ProviderContractError::InvalidEvidence(
                "Evidence signature cryptographic verification failed",
            ));
        }
        Ok(())
    }
}

pub fn verify_evidence_chain_structure(
    events: &[EvidenceEnvelope],
) -> Result<(), ProviderContractError> {
    if events.is_empty() {
        return Ok(());
    }
    validate_collection_size(events.len())?;
    let first = &events[0].event;
    let anchor = (
        first.scope_kind,
        first.subject_id.as_str(),
        first.tenant_id.as_deref(),
        first.administrative_trust_domain.as_deref(),
    );
    let mut previous = None;
    for (index, envelope) in events.iter().enumerate() {
        envelope.verify_structure()?;
        let event = &envelope.event;
        if (
            event.scope_kind,
            event.subject_id.as_str(),
            event.tenant_id.as_deref(),
            event.administrative_trust_domain.as_deref(),
        ) != anchor
        {
            return Err(ProviderContractError::EvidenceSubjectChanged);
        }
        let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if event.subject_sequence != expected {
            return Err(ProviderContractError::EvidenceSequence {
                expected,
                actual: event.subject_sequence,
            });
        }
        if event.previous_event_digest.as_ref() != previous {
            return Err(ProviderContractError::EvidencePreviousDigest(
                event.subject_sequence,
            ));
        }
        previous = Some(&envelope.event_digest);
    }
    Ok(())
}

pub fn verify_evidence_chain_with(
    events: &[EvidenceEnvelope],
    verifier: &impl EvidenceSignatureVerifier,
) -> Result<(), ProviderContractError> {
    verify_evidence_chain_structure(events)?;
    for event in events {
        event.verify_with(verifier)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCheckpoint {
    pub checkpoint_version: u32,
    pub scope_kind: EvidenceScopeKind,
    pub subject_id: String,
    pub through_sequence: u64,
    pub event_digest: ContentDigest,
    pub chain_root_digest: ContentDigest,
    pub producer: EvidenceProducerIdentity,
    pub issued_unix_ms: u64,
    pub signature: EvidenceSignature,
}

impl EvidenceCheckpoint {
    pub fn for_chain(
        events: &[EvidenceEnvelope],
        producer: EvidenceProducerIdentity,
        issued_unix_ms: u64,
        signature: EvidenceSignature,
    ) -> Result<Self, ProviderContractError> {
        verify_evidence_chain_structure(events)?;
        producer.validate()?;
        signature.validate_for(&producer)?;
        let last = events.last().ok_or(ProviderContractError::InvalidEvidence(
            "cannot checkpoint an empty chain",
        ))?;
        #[derive(Serialize)]
        struct Root<'a> {
            scope_kind: EvidenceScopeKind,
            subject_id: &'a str,
            through_sequence: u64,
            event_digest: &'a ContentDigest,
        }
        let root = Root {
            scope_kind: last.event.scope_kind,
            subject_id: &last.event.subject_id,
            through_sequence: last.event.subject_sequence,
            event_digest: &last.event_digest,
        };
        Ok(Self {
            checkpoint_version: 1,
            scope_kind: root.scope_kind,
            subject_id: root.subject_id.to_owned(),
            through_sequence: root.through_sequence,
            event_digest: root.event_digest.clone(),
            chain_root_digest: canonical_digest(EVIDENCE_CHECKPOINT_DOMAIN, &root)?,
            producer,
            issued_unix_ms,
            signature,
        })
    }

    /// Checks chain/digest linkage and signature metadata only. Portable
    /// authenticity requires `verify_with`.
    pub fn verify_structure(
        &self,
        events: &[EvidenceEnvelope],
    ) -> Result<(), ProviderContractError> {
        let actual = Self::for_chain(
            events,
            self.producer.clone(),
            self.issued_unix_ms,
            self.signature.clone(),
        )?;
        if &actual != self {
            return Err(ProviderContractError::InvalidEvidence(
                "Evidence checkpoint does not match the chain",
            ));
        }
        Ok(())
    }

    pub fn signature_message(&self) -> Result<Vec<u8>, ProviderContractError> {
        self.producer.validate()?;
        self.signature.validate_for(&self.producer)?;
        #[derive(Serialize)]
        struct Subject<'a> {
            checkpoint_version: u32,
            scope_kind: EvidenceScopeKind,
            subject_id: &'a str,
            through_sequence: u64,
            event_digest: &'a ContentDigest,
            chain_root_digest: &'a ContentDigest,
            issued_unix_ms: u64,
            algorithm: &'a str,
            signing_key_id: &'a ContentDigest,
            signing_key_generation: u64,
        }
        let canonical = crate::canonical::canonical_bytes(&Subject {
            checkpoint_version: self.checkpoint_version,
            scope_kind: self.scope_kind,
            subject_id: &self.subject_id,
            through_sequence: self.through_sequence,
            event_digest: &self.event_digest,
            chain_root_digest: &self.chain_root_digest,
            issued_unix_ms: self.issued_unix_ms,
            algorithm: &self.signature.algorithm,
            signing_key_id: &self.signature.signing_key_id,
            signing_key_generation: self.signature.signing_key_generation,
        })?;
        let mut message =
            Vec::with_capacity(EVIDENCE_CHECKPOINT_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(EVIDENCE_CHECKPOINT_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        events: &[EvidenceEnvelope],
        verifier: &impl EvidenceSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        verify_evidence_chain_with(events, verifier)?;
        self.verify_structure(events)?;
        let message = self.signature_message()?;
        if !verifier.verify_signature(
            &self.producer,
            &self.signature.algorithm,
            &message,
            &self.signature.signature,
        ) {
            return Err(ProviderContractError::InvalidEvidence(
                "Evidence checkpoint signature cryptographic verification failed",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendEvidenceOutcome {
    Appended(EvidenceEnvelope),
    ExactReplay(EvidenceEnvelope),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRangeRequest {
    pub scope_kind: EvidenceScopeKind,
    pub subject_id: String,
    pub after_sequence: Option<u64>,
    pub maximum_events: usize,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePage {
    pub events: Vec<EvidenceEnvelope>,
    pub next_sequence: Option<u64>,
    pub finalized_through_sequence: Option<u64>,
}

/// Append-only subject-scoped Evidence storage. Implementations must use the
/// expected previous digest as a compare-and-swap condition.
pub trait EvidenceStore {
    type Error;

    fn append(
        &self,
        expected_previous: Option<&ContentDigest>,
        event: EvidenceEvent,
    ) -> Result<AppendEvidenceOutcome, Self::Error>;

    fn range(&self, request: &EvidenceRangeRequest) -> Result<EvidencePage, Self::Error>;

    fn checkpoint(
        &self,
        scope_kind: EvidenceScopeKind,
        subject_id: &str,
    ) -> Result<Option<EvidenceCheckpoint>, Self::Error>;

    fn finalize(
        &self,
        scope_kind: EvidenceScopeKind,
        subject_id: &str,
        through_sequence: u64,
        expected_event_digest: &ContentDigest,
    ) -> Result<EvidenceCheckpoint, Self::Error>;
}
