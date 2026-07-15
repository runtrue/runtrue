use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const MAX_POLICY_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_POLICY_DIAGNOSTICS: usize = 1000;
pub const MAX_POLICY_DIAGNOSTIC_BYTES: usize = 4096;

/// Policy domains. Evaluation is deny-overrides across all domains; this
/// ordering exists for diagnostics and ownership, not precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    Authorization,
    Admission,
    Execution,
    Secret,
    Network,
    CacheArtifact,
    Environment,
    SupplyChain,
    Operational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVersionStatus {
    Draft,
    Test,
    Shadow,
    Enforce,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyValidationReport {
    pub schema_digest: ContentDigest,
    pub validator_version: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub validated_unix_ms: u64,
}

impl PolicyValidationReport {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    fn validate(&self) -> Result<(), PolicyLifecycleError> {
        validate_identifier("validator version", &self.validator_version)?;
        validate_diagnostics(&self.errors)?;
        validate_diagnostics(&self.warnings)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivationEvidence {
    pub simulation_digest: ContentDigest,
    pub approval_id: String,
    pub approved_by: String,
    pub approved_unix_ms: u64,
}

impl PolicyActivationEvidence {
    fn validate(&self, created_unix_ms: u64) -> Result<(), PolicyLifecycleError> {
        validate_identifier("policy approval id", &self.approval_id)?;
        validate_identifier("policy approver", &self.approved_by)?;
        if self.approved_unix_ms < created_unix_ms {
            return Err(PolicyLifecycleError::InvalidTransition(
                "policy approval predates the version",
            ));
        }
        Ok(())
    }
}

/// Immutable source plus monotonic lifecycle metadata. Updating policy text
/// requires a new version; `verify_source` detects accidental/tampered mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyVersion {
    pub id: String,
    pub policy_id: String,
    pub version: u64,
    pub layer: PolicyLayer,
    source: String,
    source_digest: ContentDigest,
    pub author_id: String,
    pub security_critical: bool,
    pub status: PolicyVersionStatus,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<PolicyValidationReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<PolicyActivationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPolicyVersion {
    pub id: String,
    pub policy_id: String,
    pub version: u64,
    pub layer: PolicyLayer,
    pub source: String,
    pub author_id: String,
    pub security_critical: bool,
    pub created_unix_ms: u64,
}

impl PolicyVersion {
    pub fn new(new: NewPolicyVersion) -> Result<Self, PolicyLifecycleError> {
        validate_identifier("policy version id", &new.id)?;
        validate_identifier("policy id", &new.policy_id)?;
        validate_identifier("policy author", &new.author_id)?;
        if new.version == 0
            || new.source.trim().is_empty()
            || new.source.len() > MAX_POLICY_SOURCE_BYTES
        {
            return Err(PolicyLifecycleError::InvalidVersion);
        }
        let source_digest = ContentDigest::sha256(new.source.as_bytes());
        Ok(Self {
            id: new.id,
            policy_id: new.policy_id,
            version: new.version,
            layer: new.layer,
            source: new.source,
            source_digest,
            author_id: new.author_id,
            security_critical: new.security_critical,
            status: PolicyVersionStatus::Draft,
            created_unix_ms: new.created_unix_ms,
            validation: None,
            activation: None,
        })
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub const fn source_digest(&self) -> &ContentDigest {
        &self.source_digest
    }

    pub fn record_validation(
        &mut self,
        report: PolicyValidationReport,
    ) -> Result<(), PolicyLifecycleError> {
        if self.status != PolicyVersionStatus::Draft {
            return Err(PolicyLifecycleError::InvalidTransition(
                "validation can be recorded only on a draft",
            ));
        }
        report.validate()?;
        if report.validated_unix_ms < self.created_unix_ms {
            return Err(PolicyLifecycleError::InvalidTransition(
                "validation predates the policy version",
            ));
        }
        self.validation = Some(report);
        Ok(())
    }

    pub fn transition(
        &mut self,
        target: PolicyVersionStatus,
        evidence: Option<PolicyActivationEvidence>,
    ) -> Result<(), PolicyLifecycleError> {
        let allowed = matches!(
            (self.status, target),
            (PolicyVersionStatus::Draft, PolicyVersionStatus::Test)
                | (PolicyVersionStatus::Test, PolicyVersionStatus::Shadow)
                | (PolicyVersionStatus::Shadow, PolicyVersionStatus::Enforce)
                | (PolicyVersionStatus::Draft, PolicyVersionStatus::Retired)
                | (PolicyVersionStatus::Test, PolicyVersionStatus::Retired)
                | (PolicyVersionStatus::Shadow, PolicyVersionStatus::Retired)
                | (PolicyVersionStatus::Enforce, PolicyVersionStatus::Retired)
        );
        if !allowed {
            return Err(PolicyLifecycleError::InvalidTransition(
                "policy lifecycle transition is not allowed",
            ));
        }
        let validation = self
            .validation
            .as_ref()
            .ok_or(PolicyLifecycleError::NotValidated)?;
        if !validation.is_valid() {
            return Err(PolicyLifecycleError::ValidationFailed);
        }
        match target {
            PolicyVersionStatus::Enforce => {
                let evidence = evidence.ok_or(PolicyLifecycleError::ActivationEvidenceRequired)?;
                evidence.validate(self.created_unix_ms)?;
                if evidence.approved_by == self.author_id {
                    return Err(PolicyLifecycleError::SeparationOfDuties);
                }
                self.activation = Some(evidence);
            }
            _ if evidence.is_some() => {
                return Err(PolicyLifecycleError::InvalidTransition(
                    "activation evidence is accepted only when enforcing",
                ));
            }
            _ => {}
        }
        self.status = target;
        Ok(())
    }

    pub fn verify_source(&self) -> Result<(), PolicyLifecycleError> {
        if ContentDigest::sha256(self.source.as_bytes()) != self.source_digest {
            return Err(PolicyLifecycleError::SourceDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationEffect {
    Permit,
    Deny,
    NotApplicable,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerEvaluation {
    pub policy_version_id: String,
    pub layer: PolicyLayer,
    pub mode: PolicyVersionStatus,
    pub effect: EvaluationEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergedPolicyDecision {
    pub allowed: bool,
    pub permitting_versions: Vec<String>,
    pub denying_versions: Vec<String>,
    pub error_versions: Vec<String>,
    pub shadow_denials: Vec<String>,
}

/// Merge independently evaluated policy layers. Enforced errors fail closed;
/// shadow results are observable but never grant or deny. At least one
/// enforced permit is required and every enforced deny wins.
pub fn merge_policy_evaluations(
    evaluations: &[LayerEvaluation],
) -> Result<MergedPolicyDecision, PolicyLifecycleError> {
    let mut seen = BTreeSet::new();
    let mut permits = Vec::new();
    let mut denies = Vec::new();
    let mut errors = Vec::new();
    let mut shadow_denials = Vec::new();
    for evaluation in evaluations {
        validate_identifier("evaluated policy version", &evaluation.policy_version_id)?;
        if !seen.insert(evaluation.policy_version_id.clone()) {
            return Err(PolicyLifecycleError::DuplicateEvaluation(
                evaluation.policy_version_id.clone(),
            ));
        }
        if let Some(code) = &evaluation.diagnostic_code {
            validate_identifier("policy diagnostic code", code)?;
        }
        match (evaluation.mode, evaluation.effect) {
            (PolicyVersionStatus::Enforce, EvaluationEffect::Permit) => {
                permits.push(evaluation.policy_version_id.clone());
            }
            (PolicyVersionStatus::Enforce, EvaluationEffect::Deny) => {
                denies.push(evaluation.policy_version_id.clone());
            }
            (PolicyVersionStatus::Enforce, EvaluationEffect::Error) => {
                errors.push(evaluation.policy_version_id.clone());
            }
            (PolicyVersionStatus::Shadow, EvaluationEffect::Deny | EvaluationEffect::Error) => {
                shadow_denials.push(evaluation.policy_version_id.clone());
            }
            (PolicyVersionStatus::Draft | PolicyVersionStatus::Retired, _) => {
                return Err(PolicyLifecycleError::InactiveEvaluation(
                    evaluation.policy_version_id.clone(),
                ));
            }
            _ => {}
        }
    }
    let allowed = !permits.is_empty() && denies.is_empty() && errors.is_empty();
    Ok(MergedPolicyDecision {
        allowed,
        permitting_versions: permits,
        denying_versions: denies,
        error_versions: errors,
        shadow_denials,
    })
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), PolicyLifecycleError> {
    if value.is_empty()
        || value.len() > MAX_POLICY_DIAGNOSTIC_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PolicyLifecycleError::InvalidIdentifier(kind));
    }
    Ok(())
}

fn validate_diagnostics(values: &[String]) -> Result<(), PolicyLifecycleError> {
    if values.len() > MAX_POLICY_DIAGNOSTICS
        || values.iter().any(|value| {
            value.is_empty() || value.len() > MAX_POLICY_DIAGNOSTIC_BYTES || value.contains('\0')
        })
    {
        return Err(PolicyLifecycleError::InvalidDiagnostics);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyLifecycleError {
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("policy version source or version is invalid")]
    InvalidVersion,
    #[error("policy validation diagnostics are invalid or exceed limits")]
    InvalidDiagnostics,
    #[error("invalid policy lifecycle transition: {0}")]
    InvalidTransition(&'static str),
    #[error("policy version has not been validated")]
    NotValidated,
    #[error("policy validation contains errors")]
    ValidationFailed,
    #[error("policy activation requires simulation and approval evidence")]
    ActivationEvidenceRequired,
    #[error("policy author cannot independently approve activation")]
    SeparationOfDuties,
    #[error("policy source digest mismatch")]
    SourceDigestMismatch,
    #[error("duplicate evaluation for policy version `{0}`")]
    DuplicateEvaluation(String),
    #[error("inactive policy version `{0}` was evaluated")]
    InactiveEvaluation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version() -> PolicyVersion {
        PolicyVersion::new(NewPolicyVersion {
            id: "policy-version-1".to_owned(),
            policy_id: "repository-authorization".to_owned(),
            version: 1,
            layer: PolicyLayer::Authorization,
            source: "permit(principal, action, resource);".to_owned(),
            author_id: "author".to_owned(),
            security_critical: true,
            created_unix_ms: 100,
        })
        .expect("version")
    }

    fn valid_report() -> PolicyValidationReport {
        PolicyValidationReport {
            schema_digest: ContentDigest::sha256(b"schema"),
            validator_version: "validator-v1".to_owned(),
            errors: Vec::new(),
            warnings: Vec::new(),
            validated_unix_ms: 101,
        }
    }

    #[test]
    fn activation_is_monotonic_validated_and_separation_bound() {
        let mut version = version();
        assert!(matches!(
            version.transition(PolicyVersionStatus::Test, None),
            Err(PolicyLifecycleError::NotValidated)
        ));
        version
            .record_validation(valid_report())
            .expect("validation");
        version
            .transition(PolicyVersionStatus::Test, None)
            .expect("test");
        version
            .transition(PolicyVersionStatus::Shadow, None)
            .expect("shadow");
        let self_approval = PolicyActivationEvidence {
            simulation_digest: ContentDigest::sha256(b"simulation"),
            approval_id: "approval-1".to_owned(),
            approved_by: "author".to_owned(),
            approved_unix_ms: 102,
        };
        assert!(matches!(
            version.transition(PolicyVersionStatus::Enforce, Some(self_approval)),
            Err(PolicyLifecycleError::SeparationOfDuties)
        ));
        version
            .transition(
                PolicyVersionStatus::Enforce,
                Some(PolicyActivationEvidence {
                    simulation_digest: ContentDigest::sha256(b"simulation"),
                    approval_id: "approval-1".to_owned(),
                    approved_by: "security-reviewer".to_owned(),
                    approved_unix_ms: 102,
                }),
            )
            .expect("enforce");
        version
            .transition(PolicyVersionStatus::Retired, None)
            .expect("retire");
        assert!(matches!(
            version.transition(PolicyVersionStatus::Enforce, None),
            Err(PolicyLifecycleError::InvalidTransition(_))
        ));
    }

    #[test]
    fn failed_validation_cannot_advance() {
        let mut version = version();
        let mut report = valid_report();
        report.errors.push("unknown entity type".to_owned());
        version.record_validation(report).expect("record report");
        assert!(matches!(
            version.transition(PolicyVersionStatus::Test, None),
            Err(PolicyLifecycleError::ValidationFailed)
        ));
    }

    #[test]
    fn source_mutation_is_detected() {
        let mut version = version();
        version.verify_source().expect("source");
        version
            .source
            .push_str(" forbid(principal, action, resource);");
        assert!(matches!(
            version.verify_source(),
            Err(PolicyLifecycleError::SourceDigestMismatch)
        ));
    }

    #[test]
    fn deny_and_errors_override_permits_while_shadow_is_observational() {
        let permit = LayerEvaluation {
            policy_version_id: "permit-v1".to_owned(),
            layer: PolicyLayer::Authorization,
            mode: PolicyVersionStatus::Enforce,
            effect: EvaluationEffect::Permit,
            diagnostic_code: None,
        };
        let shadow = LayerEvaluation {
            policy_version_id: "shadow-v1".to_owned(),
            layer: PolicyLayer::Operational,
            mode: PolicyVersionStatus::Shadow,
            effect: EvaluationEffect::Deny,
            diagnostic_code: Some("would_deny".to_owned()),
        };
        let allowed = merge_policy_evaluations(&[permit.clone(), shadow]).expect("merge");
        assert!(allowed.allowed);
        assert_eq!(allowed.shadow_denials, vec!["shadow-v1"]);

        let deny = LayerEvaluation {
            policy_version_id: "deny-v1".to_owned(),
            layer: PolicyLayer::Secret,
            mode: PolicyVersionStatus::Enforce,
            effect: EvaluationEffect::Deny,
            diagnostic_code: None,
        };
        let denied = merge_policy_evaluations(&[permit.clone(), deny]).expect("merge");
        assert!(!denied.allowed);
        assert_eq!(denied.denying_versions, vec!["deny-v1"]);

        let error = LayerEvaluation {
            policy_version_id: "error-v1".to_owned(),
            layer: PolicyLayer::Network,
            mode: PolicyVersionStatus::Enforce,
            effect: EvaluationEffect::Error,
            diagnostic_code: Some("evaluation_error".to_owned()),
        };
        assert!(
            !merge_policy_evaluations(&[permit, error])
                .expect("merge")
                .allowed
        );
        assert!(!merge_policy_evaluations(&[]).expect("empty").allowed);
    }

    #[test]
    fn duplicate_or_inactive_evaluations_fail_closed() {
        let evaluation = LayerEvaluation {
            policy_version_id: "version-1".to_owned(),
            layer: PolicyLayer::Admission,
            mode: PolicyVersionStatus::Enforce,
            effect: EvaluationEffect::Permit,
            diagnostic_code: None,
        };
        assert!(matches!(
            merge_policy_evaluations(&[evaluation.clone(), evaluation]),
            Err(PolicyLifecycleError::DuplicateEvaluation(_))
        ));
        assert!(matches!(
            merge_policy_evaluations(&[LayerEvaluation {
                policy_version_id: "draft-1".to_owned(),
                layer: PolicyLayer::Admission,
                mode: PolicyVersionStatus::Draft,
                effect: EvaluationEffect::Permit,
                diagnostic_code: None,
            }]),
            Err(PolicyLifecycleError::InactiveEvaluation(_))
        ));
    }
}
