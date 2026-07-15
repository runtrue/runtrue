use crate::{
    canonical::{canonical_digest, validate_collection_size, validate_text},
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const FAILURE_CAUSE_DOMAIN: &[u8] = b"runtrue.provider.failure-cause.v1\0";
const RETRY_DECISION_DOMAIN: &[u8] = b"runtrue.provider.retry-decision.v1\0";

/// Closed portable terminal classes. Provider diagnostics may refine these
/// classes but cannot add another portable class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableFailureClass {
    AdmissionRejected,
    PolicyDenied,
    CapacityUnavailable,
    RuntimeFailure,
    ProgramFailure,
    TimedOut,
    Canceled,
    ResourceExhausted,
    ExternalEffectIndeterminate,
    RunnerIntegrityFailure,
}

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
        if let Some(code) = &self.diagnostic_code {
            validate_text("failure diagnostic code", code, 1024)?;
        }
        if let Some(hint) = &self.retry_hint {
            validate_text("failure retry hint", hint, 4096)?;
        }
        let before_running = matches!(self.phase, FailurePhase::Admission | FailurePhase::Queued);
        match self.class {
            PortableFailureClass::AdmissionRejected
            | PortableFailureClass::PolicyDenied
            | PortableFailureClass::CapacityUnavailable
                if !before_running =>
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
            PortableFailureClass::AdmissionRejected
            | PortableFailureClass::PolicyDenied
            | PortableFailureClass::CapacityUnavailable
                if self.subject_kind == FailureSubjectKind::Session
                    && self.phase != FailurePhase::Admission =>
            {
                Err(ProviderContractError::InvalidFailureCause(
                    "active Session operation outcomes cannot reclassify the Session",
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
        {
            return Err(ProviderContractError::InvalidFailureCause(
                "causes must have unique sequences and one subject kind",
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDenial {
    PolicyNotAuthorized,
    EffectSafetyUnproven,
    RunnerNotRemediated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrySafetyProof {
    pub policy_authorization_digest: Option<ContentDigest>,
    pub effect_safety_digest: Option<ContentDigest>,
    pub runner_remediation_digest: Option<ContentDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryDecision {
    pub allowed: bool,
    pub cause_digests: Vec<ContentDigest>,
    pub proof: RetrySafetyProof,
    pub denials: BTreeSet<RetryDenial>,
}

impl RetryDecision {
    pub fn evaluate(
        resolution: &FailureResolution,
        proof: RetrySafetyProof,
    ) -> Result<Self, ProviderContractError> {
        resolution.validate()?;
        let mut denials = BTreeSet::new();
        if proof.policy_authorization_digest.is_none() {
            denials.insert(RetryDenial::PolicyNotAuthorized);
        }
        let has_indeterminate_effect = resolution
            .observed_causes
            .iter()
            .any(|cause| cause.class == PortableFailureClass::ExternalEffectIndeterminate);
        let has_integrity_failure = resolution
            .observed_causes
            .iter()
            .any(|cause| cause.class == PortableFailureClass::RunnerIntegrityFailure);
        if (has_indeterminate_effect || has_integrity_failure)
            && proof.effect_safety_digest.is_none()
        {
            denials.insert(RetryDenial::EffectSafetyUnproven);
        }
        if has_integrity_failure && proof.runner_remediation_digest.is_none() {
            denials.insert(RetryDenial::RunnerNotRemediated);
        }
        let cause_digests = resolution
            .observed_causes
            .iter()
            .map(ObservedCause::digest)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            allowed: denials.is_empty(),
            cause_digests,
            proof,
            denials,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_collection_size(self.cause_digests.len())?;
        let unique = self.cause_digests.iter().collect::<BTreeSet<_>>();
        if self.cause_digests.is_empty()
            || unique.len() != self.cause_digests.len()
            || self.allowed != self.denials.is_empty()
            || (self.allowed && self.proof.policy_authorization_digest.is_none())
        {
            return Err(ProviderContractError::InvalidRetryDecision);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(RETRY_DECISION_DOMAIN, self)
    }
}
