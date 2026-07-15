use crate::{
    canonical::{
        canonical_bytes, canonical_digest, validate_collection_size, validate_profile_name,
        validate_text,
    },
    ProviderContractError, RetryAuthorization,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const FAILURE_CAUSE_DOMAIN: &[u8] = b"runtrue.provider.failure-cause.v1\0";
const FAILURE_RESOLUTION_DOMAIN: &[u8] = b"runtrue.provider.failure-resolution.v1\0";
const RETRY_DECISION_DOMAIN: &[u8] = b"runtrue.provider.retry-decision.v1\0";
const RETRY_PROOF_DOMAIN: &[u8] = b"runtrue.provider.authenticated-retry-proof.v1\0";
const RETRY_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"runtrue.provider.authenticated-retry-proof-signature.v1\0";

pub trait RetryProofSignatureVerifier {
    fn verify_retry_proof_signature(
        &self,
        issuer_identity_digest: &ContentDigest,
        signing_key_id: &ContentDigest,
        signing_key_generation: u64,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

/// Compatibility name for the single authoritative portable failure class.
pub use runtrue_execution::FailureClass as PortableFailureClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureSubjectKind {
    Execution,
    Session,
    SessionOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePhase {
    Admission,
    Queued,
    Running,
    Finalizing,
    SessionRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCause {
    pub sequence: u64,
    pub subject_id: String,
    pub class: PortableFailureClass,
    pub subject_kind: FailureSubjectKind,
    pub phase: FailurePhase,
    pub evidence_event_digest: ContentDigest,
    pub diagnostic_code: Option<String>,
    pub retry_hint: Option<String>,
}

impl ObservedCause {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.sequence == 0 {
            return Err(ProviderContractError::InvalidFailureCause(
                "cause sequence must be positive",
            ));
        }
        crate::canonical::validate_identifier("failure subject", &self.subject_id)?;
        if let Some(code) = &self.diagnostic_code {
            validate_text("failure diagnostic code", code, 1024)?;
        }
        if let Some(hint) = &self.retry_hint {
            validate_text("failure retry hint", hint, 4096)?;
        }
        let initial_subject_failure =
            matches!(self.phase, FailurePhase::Admission | FailurePhase::Queued)
                || (self.subject_kind == FailureSubjectKind::SessionOperation
                    && self.phase == FailurePhase::SessionRecovery);
        match self.class {
            PortableFailureClass::AdmissionRejected
            | PortableFailureClass::PolicyDenied
            | PortableFailureClass::CapacityUnavailable
                if !initial_subject_failure =>
            {
                Err(ProviderContractError::InvalidFailureCause(
                    "pre-execution class appeared after guest execution",
                ))
            }
            PortableFailureClass::ProgramFailure
                if self.subject_kind != FailureSubjectKind::Execution
                    || !matches!(self.phase, FailurePhase::Running | FailurePhase::Finalizing) =>
            {
                Err(ProviderContractError::InvalidFailureCause(
                    "Program failure applies only to a running Execution",
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(FAILURE_CAUSE_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureResolution {
    pub primary_class: PortableFailureClass,
    pub primary_cause_sequence: u64,
    pub observed_causes: Vec<ObservedCause>,
}

impl FailureResolution {
    pub fn resolve(mut causes: Vec<ObservedCause>) -> Result<Self, ProviderContractError> {
        if causes.is_empty() {
            return Err(ProviderContractError::InvalidFailureCause(
                "failure resolution requires an observed cause",
            ));
        }
        validate_collection_size(causes.len())?;
        causes.sort_by_key(|cause| cause.sequence);
        for cause in &causes {
            cause.validate()?;
        }
        if causes
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
            || causes
                .iter()
                .map(|cause| cause.subject_kind)
                .collect::<BTreeSet<_>>()
                .len()
                != 1
            || causes
                .iter()
                .map(|cause| cause.subject_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != 1
        {
            return Err(ProviderContractError::InvalidFailureCause(
                "causes must have unique sequences and one exact subject",
            ));
        }
        let initial_classes = causes
            .iter()
            .filter(|cause| {
                matches!(
                    cause.class,
                    PortableFailureClass::AdmissionRejected
                        | PortableFailureClass::PolicyDenied
                        | PortableFailureClass::CapacityUnavailable
                )
            })
            .count();
        if initial_classes > 0 && causes.len() != 1 {
            return Err(ProviderContractError::InvalidFailureCause(
                "initial admission, policy, and capacity outcomes are mutually exclusive with other causes",
            ));
        }
        let primary = causes
            .iter()
            .find(|cause| cause.class == PortableFailureClass::RunnerIntegrityFailure)
            .or_else(|| {
                causes
                    .iter()
                    .find(|cause| cause.class == PortableFailureClass::ExternalEffectIndeterminate)
            })
            .unwrap_or(&causes[0]);
        Ok(Self {
            primary_class: primary.class,
            primary_cause_sequence: primary.sequence,
            observed_causes: causes,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        let actual = Self::resolve(self.observed_causes.clone())?;
        if actual.primary_class != self.primary_class
            || actual.primary_cause_sequence != self.primary_cause_sequence
        {
            return Err(ProviderContractError::InvalidFailureCause(
                "primary failure does not follow safety-override precedence",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(FAILURE_RESOLUTION_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDenial {
    PolicyNotAuthorized,
    EffectSafetyUnproven,
    RunnerNotRemediated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryProofKind {
    PolicyAuthorization,
    EffectSafety,
    RunnerRemediation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRetryProof {
    pub proof_version: u32,
    pub kind: RetryProofKind,
    pub subject_digest: ContentDigest,
    pub evidence_event_digest: ContentDigest,
    pub issuer_identity_digest: ContentDigest,
    pub signing_key_id: ContentDigest,
    pub signing_key_generation: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub algorithm: String,
    pub signature: Vec<u8>,
}

impl AuthenticatedRetryProof {
    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        if self.proof_version != 1
            || self.signing_key_generation == 0
            || self.issued_unix_ms == 0
            || self.expires_unix_ms <= self.issued_unix_ms
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
        {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        validate_profile_name(&self.algorithm)?;
        canonical_digest(RETRY_PROOF_DOMAIN, self)
    }

    pub fn verify_for(
        &self,
        kind: RetryProofKind,
        subject_digest: &ContentDigest,
        now_unix_ms: u64,
        verifier: &impl RetryProofSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        self.digest()?;
        if self.kind != kind
            || &self.subject_digest != subject_digest
            || now_unix_ms < self.issued_unix_ms
            || now_unix_ms >= self.expires_unix_ms
        {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        #[derive(Serialize)]
        struct SignedSubject<'a> {
            proof_version: u32,
            kind: RetryProofKind,
            subject_digest: &'a ContentDigest,
            evidence_event_digest: &'a ContentDigest,
            issuer_identity_digest: &'a ContentDigest,
            signing_key_id: &'a ContentDigest,
            signing_key_generation: u64,
            issued_unix_ms: u64,
            expires_unix_ms: u64,
            algorithm: &'a str,
        }
        let canonical = canonical_bytes(&SignedSubject {
            proof_version: self.proof_version,
            kind: self.kind,
            subject_digest: &self.subject_digest,
            evidence_event_digest: &self.evidence_event_digest,
            issuer_identity_digest: &self.issuer_identity_digest,
            signing_key_id: &self.signing_key_id,
            signing_key_generation: self.signing_key_generation,
            issued_unix_ms: self.issued_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
            algorithm: &self.algorithm,
        })?;
        let mut message = Vec::with_capacity(RETRY_PROOF_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(RETRY_PROOF_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        if !verifier.verify_retry_proof_signature(
            &self.issuer_identity_digest,
            &self.signing_key_id,
            self.signing_key_generation,
            &self.algorithm,
            &message,
            &self.signature,
        ) {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrySafetyProof {
    pub policy_authorization: Option<AuthenticatedRetryProof>,
    pub effect_authorization: Option<RetryAuthorization>,
    pub effect_safety: Option<AuthenticatedRetryProof>,
    pub runner_remediation: Option<AuthenticatedRetryProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryDecision {
    pub allowed: bool,
    pub resolution: FailureResolution,
    pub resolution_digest: ContentDigest,
    pub cause_digests: Vec<ContentDigest>,
    pub proof: RetrySafetyProof,
    pub denials: BTreeSet<RetryDenial>,
}

impl RetryDecision {
    fn denials_for(
        resolution: &FailureResolution,
        proof: &RetrySafetyProof,
    ) -> BTreeSet<RetryDenial> {
        let mut denials = BTreeSet::new();
        if proof.policy_authorization.is_none() {
            denials.insert(RetryDenial::PolicyNotAuthorized);
        }
        let has_integrity_failure = resolution
            .observed_causes
            .iter()
            .any(|cause| cause.class == PortableFailureClass::RunnerIntegrityFailure);
        // Every automatic retry must consume a verified effect-journal
        // frontier. The digest may prove an empty/read-only frontier, but its
        // absence can never prove that a failed attempt performed no mutation.
        if proof.effect_authorization.is_none() || proof.effect_safety.is_none() {
            denials.insert(RetryDenial::EffectSafetyUnproven);
        }
        if has_integrity_failure && proof.runner_remediation.is_none() {
            denials.insert(RetryDenial::RunnerNotRemediated);
        }
        denials
    }

    pub fn evaluate(
        resolution: &FailureResolution,
        proof: RetrySafetyProof,
        now_unix_ms: u64,
        verifier: &impl RetryProofSignatureVerifier,
    ) -> Result<Self, ProviderContractError> {
        resolution.validate()?;
        let resolution_digest = resolution.digest()?;
        if let Some(policy) = &proof.policy_authorization {
            policy.verify_for(
                RetryProofKind::PolicyAuthorization,
                &resolution_digest,
                now_unix_ms,
                verifier,
            )?;
        }
        match (&proof.effect_authorization, &proof.effect_safety) {
            (Some(authorization), Some(effect_proof)) => {
                let prior_execution_id = &resolution.observed_causes[0].subject_id;
                if &authorization.retry_of_execution_id != prior_execution_id {
                    return Err(ProviderContractError::InvalidRetryDecision);
                }
                effect_proof.verify_for(
                    RetryProofKind::EffectSafety,
                    &authorization.digest()?,
                    now_unix_ms,
                    verifier,
                )?;
            }
            (None, None) => {}
            _ => return Err(ProviderContractError::InvalidRetryDecision),
        }
        if let Some(remediation) = &proof.runner_remediation {
            remediation.verify_for(
                RetryProofKind::RunnerRemediation,
                &resolution_digest,
                now_unix_ms,
                verifier,
            )?;
        }
        let denials = Self::denials_for(resolution, &proof);
        let cause_digests = resolution
            .observed_causes
            .iter()
            .map(ObservedCause::digest)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            allowed: denials.is_empty(),
            resolution: resolution.clone(),
            resolution_digest,
            cause_digests,
            proof,
            denials,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.resolution.validate()?;
        validate_collection_size(self.cause_digests.len())?;
        let unique = self.cause_digests.iter().collect::<BTreeSet<_>>();
        let expected_cause_digests = self
            .resolution
            .observed_causes
            .iter()
            .map(ObservedCause::digest)
            .collect::<Result<Vec<_>, _>>()?;
        let expected_denials = Self::denials_for(&self.resolution, &self.proof);
        if self.cause_digests.is_empty()
            || unique.len() != self.cause_digests.len()
            || self.resolution_digest != self.resolution.digest()?
            || self.cause_digests != expected_cause_digests
            || self.denials != expected_denials
            || self.allowed != expected_denials.is_empty()
        {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        Ok(())
    }

    pub fn validate_with(
        &self,
        now_unix_ms: u64,
        verifier: &impl RetryProofSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        self.validate()?;
        let rebuilt = Self::evaluate(&self.resolution, self.proof.clone(), now_unix_ms, verifier)?;
        if &rebuilt != self {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(RETRY_DECISION_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryLineage {
    pub prior_execution_id: String,
    pub failure_resolution_digest: ContentDigest,
    pub retry_decision_digest: ContentDigest,
    pub effect_journal_frontier_digest: ContentDigest,
}

impl RetryLineage {
    pub fn from_decision(
        decision: &RetryDecision,
        now_unix_ms: u64,
        verifier: &impl RetryProofSignatureVerifier,
    ) -> Result<Self, ProviderContractError> {
        decision.validate_with(now_unix_ms, verifier)?;
        if !decision.allowed
            || decision.resolution.observed_causes[0].subject_kind != FailureSubjectKind::Execution
        {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        let authorization = decision
            .proof
            .effect_authorization
            .as_ref()
            .ok_or(ProviderContractError::InvalidRetryDecision)?;
        Ok(Self {
            prior_execution_id: decision.resolution.observed_causes[0].subject_id.clone(),
            failure_resolution_digest: decision.resolution_digest.clone(),
            retry_decision_digest: decision.digest()?,
            effect_journal_frontier_digest: authorization.retry_of_effect_frontier_digest.clone(),
        })
    }

    pub fn validate_against(&self, decision: &RetryDecision) -> Result<(), ProviderContractError> {
        crate::canonical::validate_identifier("retry prior Execution", &self.prior_execution_id)?;
        decision.validate()?;
        if !decision.allowed
            || self.failure_resolution_digest != decision.resolution_digest
            || self.retry_decision_digest != decision.digest()?
            || decision
                .resolution
                .observed_causes
                .iter()
                .any(|cause| cause.subject_id != self.prior_execution_id)
            || decision
                .proof
                .effect_authorization
                .as_ref()
                .is_none_or(|authorization| {
                    authorization.retry_of_execution_id != self.prior_execution_id
                        || authorization.retry_of_effect_frontier_digest
                            != self.effect_journal_frontier_digest
                })
        {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        Ok(())
    }
}
