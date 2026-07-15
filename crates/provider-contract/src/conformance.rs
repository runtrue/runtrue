use crate::{
    canonical::{
        canonical_bytes, canonical_digest, validate_collection_size, validate_identifier,
        validate_profile_name,
    },
    CheckpointCompatibilityGrade, ContractGeneration, DeployedProviderGeneration, ExecutionState,
    FailureResolution, FeatureProfileId, ProviderContractError, SessionState, TerminalCause,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const CONFORMANCE_STATEMENT_DOMAIN: &[u8] = b"runtrue.provider.conformance-statement.v1\0";
const CONFORMANCE_SIGNATURE_DOMAIN: &[u8] = b"runtrue.provider.conformance-signature.v1\0";

pub trait ConformanceSignatureVerifier {
    fn verify_conformance_signature(
        &self,
        deployed_provider: &DeployedProviderGeneration,
        signing_key_id: &str,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedConformanceSuite {
    pub suite: ConformanceSuiteIdentity,
    pub positive_vectors_digest: ContentDigest,
    pub negative_vectors_digest: ContentDigest,
    pub required_cases_by_profile: BTreeMap<FeatureProfileId, BTreeSet<String>>,
}

impl PinnedConformanceSuite {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.suite.validate()?;
        validate_collection_size(self.required_cases_by_profile.len())?;
        if self.required_cases_by_profile.is_empty() {
            return Err(ProviderContractError::InvalidConformance(
                "pinned suite has no profile case manifest",
            ));
        }
        for (profile, cases) in &self.required_cases_by_profile {
            profile.validate()?;
            if cases.is_empty() {
                return Err(ProviderContractError::InvalidConformance(
                    "pinned profile has no required cases",
                ));
            }
            validate_collection_size(cases.len())?;
            for case in cases {
                validate_profile_name(case)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceSuiteIdentity {
    pub name: String,
    pub generation: u32,
    pub fixture_digest: ContentDigest,
    pub harness_digest: ContentDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BisimComparisonRole {
    Baseline,
    Candidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimOperationalContext {
    pub comparison_role: BisimComparisonRole,
    pub observed_unix_ms: u64,
    pub worker_id: String,
    pub pool_id: Option<String>,
    pub warm_acquisition: bool,
}

impl BisimOperationalContext {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Bisim worker id", &self.worker_id)?;
        if let Some(pool_id) = &self.pool_id {
            validate_identifier("Bisim pool id", pool_id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimLifecycleObservation {
    pub execution_state: Option<ExecutionState>,
    pub session_state: Option<SessionState>,
    pub terminal_cause: Option<TerminalCause>,
    pub failure: Option<FailureResolution>,
}

impl BisimLifecycleObservation {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.execution_state.is_some() == self.session_state.is_some() {
            return Err(ProviderContractError::InvalidConformance(
                "Bisim lifecycle must describe exactly one subject kind",
            ));
        }
        let terminal = self
            .execution_state
            .is_some_and(ExecutionState::is_terminal)
            || self.session_state.is_some_and(SessionState::is_terminal);
        if terminal != self.terminal_cause.is_some()
            || matches!(self.terminal_cause, Some(TerminalCause::Failed(_)))
                != self.failure.is_some()
        {
            return Err(ProviderContractError::InvalidConformance(
                "Bisim lifecycle terminal outcome or failure disagrees",
            ));
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimPortableObservation {
    pub observation_version: u32,
    pub capsule_digest: ContentDigest,
    pub program_digest: ContentDigest,
    pub allowed_provider_identity_digests: BTreeSet<ContentDigest>,
    pub provider_identity_digest: ContentDigest,
    pub allowed_pool_trust_profile_digests: BTreeSet<ContentDigest>,
    pub pool_trust_profile_digest: ContentDigest,
    pub allowed_runtime_inventory_digests: BTreeSet<ContentDigest>,
    pub runtime_inventory_digest: ContentDigest,
    pub allowed_evidence_producer_identity_digests: BTreeSet<ContentDigest>,
    pub evidence_producer_identity_digest: ContentDigest,
    pub runtime_compatibility_digest: ContentDigest,
    pub lifecycle: BisimLifecycleObservation,
    pub normalized_outputs: BTreeMap<String, ContentDigest>,
    pub normalized_artifacts: BTreeMap<String, ContentDigest>,
    pub capability_state_digest: ContentDigest,
    pub external_effect_state_digest: ContentDigest,
    pub checkpoint_grade: CheckpointCompatibilityGrade,
    pub replay_bundle_digest: ContentDigest,
    pub cleanup_result_digest: ContentDigest,
    pub backend_security_result_digest: ContentDigest,
    /// Declared operational context is validated but deliberately excluded from
    /// portable comparison. No other field may be normalized away.
    pub operational: BisimOperationalContext,
}

impl BisimPortableObservation {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.observation_version != 1 {
            return Err(ProviderContractError::InvalidConformance(
                "unsupported Bisim observation version",
            ));
        }
        for length in [
            self.allowed_provider_identity_digests.len(),
            self.allowed_pool_trust_profile_digests.len(),
            self.allowed_runtime_inventory_digests.len(),
            self.allowed_evidence_producer_identity_digests.len(),
        ] {
            validate_collection_size(length)?;
        }
        if !self
            .allowed_provider_identity_digests
            .contains(&self.provider_identity_digest)
            || !self
                .allowed_pool_trust_profile_digests
                .contains(&self.pool_trust_profile_digest)
            || !self
                .allowed_runtime_inventory_digests
                .contains(&self.runtime_inventory_digest)
            || !self
                .allowed_evidence_producer_identity_digests
                .contains(&self.evidence_producer_identity_digest)
        {
            return Err(ProviderContractError::InvalidConformance(
                "actual Provider, pool, runtime, or Evidence producer is outside the admitted set",
            ));
        }
        self.lifecycle.validate()?;
        self.operational.validate()?;
        validate_collection_size(self.normalized_outputs.len())?;
        validate_collection_size(self.normalized_artifacts.len())?;
        for name in self
            .normalized_outputs
            .keys()
            .chain(self.normalized_artifacts.keys())
        {
            validate_profile_name(name)?;
        }
        Ok(())
    }

    pub fn portable_digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Portable<'a> {
            observation_version: u32,
            capsule_digest: &'a ContentDigest,
            program_digest: &'a ContentDigest,
            allowed_provider_identity_digests: &'a BTreeSet<ContentDigest>,
            allowed_pool_trust_profile_digests: &'a BTreeSet<ContentDigest>,
            allowed_runtime_inventory_digests: &'a BTreeSet<ContentDigest>,
            allowed_evidence_producer_identity_digests: &'a BTreeSet<ContentDigest>,
            runtime_compatibility_digest: &'a ContentDigest,
            lifecycle: &'a BisimLifecycleObservation,
            normalized_outputs: &'a BTreeMap<String, ContentDigest>,
            normalized_artifacts: &'a BTreeMap<String, ContentDigest>,
            capability_state_digest: &'a ContentDigest,
            external_effect_state_digest: &'a ContentDigest,
            checkpoint_grade: CheckpointCompatibilityGrade,
            replay_bundle_digest: &'a ContentDigest,
            cleanup_result_digest: &'a ContentDigest,
        }
        canonical_digest(
            b"runtrue.provider.bisim-portable-observation.v1\0",
            &Portable {
                observation_version: self.observation_version,
                capsule_digest: &self.capsule_digest,
                program_digest: &self.program_digest,
                allowed_provider_identity_digests: &self.allowed_provider_identity_digests,
                allowed_pool_trust_profile_digests: &self.allowed_pool_trust_profile_digests,
                allowed_runtime_inventory_digests: &self.allowed_runtime_inventory_digests,
                allowed_evidence_producer_identity_digests: &self
                    .allowed_evidence_producer_identity_digests,
                runtime_compatibility_digest: &self.runtime_compatibility_digest,
                lifecycle: &self.lifecycle,
                normalized_outputs: &self.normalized_outputs,
                normalized_artifacts: &self.normalized_artifacts,
                capability_state_digest: &self.capability_state_digest,
                external_effect_state_digest: &self.external_effect_state_digest,
                checkpoint_grade: self.checkpoint_grade,
                replay_bundle_digest: &self.replay_bundle_digest,
                cleanup_result_digest: &self.cleanup_result_digest,
            },
        )
    }

    pub fn require_equivalent(&self, other: &Self) -> Result<(), ProviderContractError> {
        if self.portable_digest()? != other.portable_digest()? {
            return Err(ProviderContractError::InvalidConformance(
                "Bisim portable observations differ",
            ));
        }
        Ok(())
    }
}

impl ConformanceSuiteIdentity {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.name)?;
        if self.name != "bisim" || self.generation == 0 {
            return Err(ProviderContractError::InvalidConformance(
                "suite must identify a positive Bisim generation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceCaseOutcome {
    Passed,
    Failed,
    Skipped,
    Unsupported,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceCaseResult {
    pub case_id: String,
    pub outcome: ConformanceCaseOutcome,
    pub result_digest: ContentDigest,
    pub evidence_event_digest: ContentDigest,
}

impl ConformanceCaseResult {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.case_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConformance {
    pub profile: FeatureProfileId,
    pub compatibility_digest: ContentDigest,
    pub required_case_ids: BTreeSet<String>,
}

impl ProfileConformance {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.profile.validate()?;
        if self.required_case_ids.is_empty() {
            return Err(ProviderContractError::InvalidConformance(
                "advertised profile has no required conformance cases",
            ));
        }
        validate_collection_size(self.required_case_ids.len())?;
        for case_id in &self.required_case_ids {
            validate_profile_name(case_id)?;
        }
        Ok(())
    }
}

/// Exact metadata a Provider may publish after its advertised profiles pass
/// Bisim. A skipped, unsupported, or indeterminate required case is not a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceStatement {
    pub statement_version: u32,
    pub contract_generation: ContractGeneration,
    pub deployed_provider: DeployedProviderGeneration,
    pub provider_image_digest: ContentDigest,
    pub suite: ConformanceSuiteIdentity,
    pub advertised_profiles: BTreeMap<String, ProfileConformance>,
    pub cases: BTreeMap<String, ConformanceCaseResult>,
    pub backend_security_result_digest: ContentDigest,
    pub runtime_inventory_digests: BTreeSet<ContentDigest>,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl ConformanceStatement {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ProviderContractError> {
        if self.statement_version != 1 || self.contract_generation.get() == 0 {
            return Err(ProviderContractError::InvalidConformance(
                "unsupported statement or contract generation",
            ));
        }
        self.deployed_provider.validate()?;
        self.suite.validate()?;
        if self.issued_unix_ms > now_unix_ms || now_unix_ms >= self.expires_unix_ms {
            return Err(ProviderContractError::InvalidConformance(
                "conformance statement is not currently valid",
            ));
        }
        validate_collection_size(self.advertised_profiles.len())?;
        validate_collection_size(self.cases.len())?;
        validate_collection_size(self.runtime_inventory_digests.len())?;
        if self.advertised_profiles.is_empty()
            || self.cases.is_empty()
            || self.runtime_inventory_digests.is_empty()
        {
            return Err(ProviderContractError::InvalidConformance(
                "conformance coverage and runtime identity cannot be empty",
            ));
        }
        for (case_id, result) in &self.cases {
            result.validate()?;
            if case_id != &result.case_id {
                return Err(ProviderContractError::InvalidConformance(
                    "case map key differs from case identity",
                ));
            }
        }
        for (profile_name, coverage) in &self.advertised_profiles {
            coverage.validate()?;
            if profile_name != &coverage.profile.name {
                return Err(ProviderContractError::InvalidConformance(
                    "profile map key differs from profile identity",
                ));
            }
            for case_id in &coverage.required_case_ids {
                if self.cases.get(case_id).map(|case| case.outcome)
                    != Some(ConformanceCaseOutcome::Passed)
                {
                    return Err(ProviderContractError::InvalidConformance(
                        "required case did not pass",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self, now_unix_ms: u64) -> Result<ContentDigest, ProviderContractError> {
        self.validate(now_unix_ms)?;
        canonical_digest(CONFORMANCE_STATEMENT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConformanceMetadata {
    pub media_type: String,
    pub signature_algorithm: String,
    pub signing_key_id: String,
    pub signing_key_generation: u64,
    pub statement: ConformanceStatement,
    pub statement_digest: ContentDigest,
    pub signature: Vec<u8>,
}

impl SignedConformanceMetadata {
    pub fn validate_structure(&self, now_unix_ms: u64) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.media_type)?;
        validate_profile_name(&self.signature_algorithm)?;
        validate_identifier("conformance signing key id", &self.signing_key_id)?;
        if self.signature.is_empty() || self.signature.len() > 16 * 1024 {
            return Err(ProviderContractError::InvalidConformance(
                "signature is empty or oversized",
            ));
        }
        if self.signing_key_generation != self.statement.deployed_provider.signing_key_generation {
            return Err(ProviderContractError::InvalidConformance(
                "signature key generation differs from deployed Provider generation",
            ));
        }
        let actual = self.statement.digest(now_unix_ms)?;
        if actual != self.statement_digest {
            return Err(ProviderContractError::InvalidConformance(
                "statement digest mismatch",
            ));
        }
        Ok(())
    }

    /// Domain-separated bytes an implementation signs or verifies with its
    /// configured cryptographic implementation.
    pub fn signature_message(&self, now_unix_ms: u64) -> Result<Vec<u8>, ProviderContractError> {
        self.validate_structure(now_unix_ms)?;
        #[derive(Serialize)]
        struct SignatureSubject<'a> {
            media_type: &'a str,
            signature_algorithm: &'a str,
            signing_key_id: &'a str,
            signing_key_generation: u64,
            statement_digest: &'a ContentDigest,
        }
        let subject = SignatureSubject {
            media_type: &self.media_type,
            signature_algorithm: &self.signature_algorithm,
            signing_key_id: &self.signing_key_id,
            signing_key_generation: self.signing_key_generation,
            statement_digest: &self.statement_digest,
        };
        let canonical = canonical_bytes(&subject)?;
        let mut message = Vec::with_capacity(CONFORMANCE_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(CONFORMANCE_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        now_unix_ms: u64,
        pinned: &PinnedConformanceSuite,
        descriptor: &crate::ProviderDescriptor,
        verifier: &impl ConformanceSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        self.validate_structure(now_unix_ms)?;
        pinned.validate()?;
        descriptor.validate()?;
        if self.statement.suite != pinned.suite
            || self.statement.contract_generation != descriptor.contract_generation
            || self.statement.deployed_provider.digest()?
                != descriptor.deployed_generation.digest()?
        {
            return Err(ProviderContractError::InvalidConformance(
                "statement differs from the pinned suite or deployed Provider",
            ));
        }
        for (name, coverage) in &self.statement.advertised_profiles {
            let advertised = descriptor.feature_profiles.get(name).ok_or(
                ProviderContractError::InvalidConformance(
                    "conformance statement claims an unadvertised profile",
                ),
            )?;
            let pinned_cases = pinned
                .required_cases_by_profile
                .get(&coverage.profile)
                .ok_or(ProviderContractError::InvalidConformance(
                    "profile is absent from the pinned suite",
                ))?;
            if advertised.id != coverage.profile
                || advertised.compatibility_digest != coverage.compatibility_digest
                || pinned_cases != &coverage.required_case_ids
            {
                return Err(ProviderContractError::InvalidConformance(
                    "profile compatibility or required cases differ from pinned inputs",
                ));
            }
        }
        let message = self.signature_message(now_unix_ms)?;
        if !verifier.verify_conformance_signature(
            &self.statement.deployed_provider,
            &self.signing_key_id,
            &self.signature_algorithm,
            &message,
            &self.signature,
        ) {
            return Err(ProviderContractError::InvalidConformance(
                "conformance signature verification failed",
            ));
        }
        Ok(())
    }
}
