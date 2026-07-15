use crate::{
    canonical, validation, CapabilityContract, ContentDigest, EvidenceContract,
    ExecutionModelError, OutputContract, PlacementConstraints, ProgramIdentity, ProgramKind,
    ResourceLimits, RuntimeCompatibilityProfile, Seal,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const EXECUTION_CAPSULE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapsuleKind {
    Execution,
    Session,
}

/// Canonical approval subject. Its identity is deliberately distinct from the
/// Capsule identity because policy and authority context are approval inputs,
/// not execution specification fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSubject {
    pub schema_version: u32,
    pub capsule_kind: CapsuleKind,
    pub capsule_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub authority_context_digest: ContentDigest,
}

impl ApprovalSubject {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "approval subject schema version",
            self.schema_version,
            EXECUTION_CAPSULE_SCHEMA_VERSION,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentBinding {
    pub session_capsule_digest: ContentDigest,
    pub session_seal_digest: ContentDigest,
    pub delegation_id: String,
    pub delegation_grant_digest: ContentDigest,
    pub workspace_generation_digest: ContentDigest,
    pub containment_proof_digest: ContentDigest,
}

impl ParentBinding {
    fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::identifier("delegation identity", &self.delegation_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationPolicy {
    pub planner_principal: String,
    pub planner_implementation_digest: ContentDigest,
    pub allowed_program_kinds: BTreeSet<ProgramKind>,
    pub allowed_program_resolvers: BTreeSet<ContentDigest>,
    pub allowed_runtime_profiles: BTreeSet<ContentDigest>,
    pub maximum_resources: ResourceLimits,
    pub placement: PlacementConstraints,
    pub capabilities: CapabilityContract,
    pub output: OutputContract,
    pub maximum_child_count: u32,
    pub maximum_concurrency: u32,
    pub maximum_child_duration_ms: u64,
    pub subdelegation_allowed: bool,
    pub policy_version_id: String,
    pub policy_version_digest: ContentDigest,
}

impl DelegationPolicy {
    fn validate(
        &self,
        session: &SessionCapsule,
        runtime_digest: &ContentDigest,
    ) -> Result<(), ExecutionModelError> {
        validation::identifier("delegated planner principal", &self.planner_principal)?;
        validation::bounded(
            "allowed Program kinds",
            self.allowed_program_kinds.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        if self.allowed_program_kinds.is_empty()
            || self.allowed_program_resolvers.is_empty()
            || self.allowed_runtime_profiles.is_empty()
        {
            return Err(ExecutionModelError::InvalidField {
                field: "delegation allowed sets",
                reason: "must be finite and non-empty",
            });
        }
        if self.allowed_runtime_profiles.len() != 1
            || !self.allowed_runtime_profiles.contains(runtime_digest)
            || !session.maximum_resources.contains(&self.maximum_resources)
            || !session.placement.contains(&self.placement)
            || !session.capabilities.contains(&self.capabilities)
            || !session.output.contains(&self.output)
            || self.maximum_child_count == 0
            || self.maximum_child_count > session.maximum_child_count
            || self.maximum_concurrency == 0
            || self.maximum_concurrency > session.maximum_concurrency
            || self.maximum_concurrency > self.maximum_child_count
            || self.maximum_child_duration_ms == 0
            || self.maximum_child_duration_ms > session.maximum_resources.maximum_duration_ms
        {
            return Err(ExecutionModelError::InvalidField {
                field: "delegation envelope",
                reason: "must be a positive finite subset of the Session envelope",
            });
        }
        validation::identifier("delegation policy version", &self.policy_version_id)?;
        self.maximum_resources.validate()?;
        self.placement.validate()?;
        self.capabilities.validate()?;
        self.output.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        canonical::canonical_digest(self)
    }
}

/// A time-bounded grant issued from a sealed Session delegation policy.
///
/// The grant is deliberately not embedded in the Session Capsule: doing so
/// would create an identity cycle when it binds that Capsule and its Seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationGrant {
    pub schema_version: u32,
    pub delegation_id: String,
    pub parent_session_capsule_digest: ContentDigest,
    pub parent_session_seal_digest: ContentDigest,
    pub policy_id: String,
    pub policy_digest: ContentDigest,
    pub planner_principal: String,
    pub planner_implementation_digest: ContentDigest,
    pub allowed_program_kinds: BTreeSet<ProgramKind>,
    pub allowed_program_resolvers: BTreeSet<ContentDigest>,
    pub allowed_runtime_profiles: BTreeSet<ContentDigest>,
    pub maximum_resources: ResourceLimits,
    pub placement: PlacementConstraints,
    pub capabilities: CapabilityContract,
    pub output: OutputContract,
    pub maximum_child_count: u32,
    pub maximum_concurrency: u32,
    pub maximum_child_duration_ms: u64,
    pub subdelegation_allowed: bool,
    pub policy_version_id: String,
    pub policy_version_digest: ContentDigest,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub revocation_generation: u64,
}

impl DelegationGrant {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "Delegation Grant schema version",
            self.schema_version,
            EXECUTION_CAPSULE_SCHEMA_VERSION,
        )?;
        validation::identifier("delegation identity", &self.delegation_id)?;
        validation::identifier("delegation policy identity", &self.policy_id)?;
        validation::identifier("delegated planner principal", &self.planner_principal)?;
        validation::identifier("delegation policy version", &self.policy_version_id)?;
        if self.allowed_program_kinds.is_empty()
            || self.allowed_program_resolvers.is_empty()
            || self.allowed_runtime_profiles.is_empty()
            || self.maximum_child_count == 0
            || self.maximum_concurrency == 0
            || self.maximum_concurrency > self.maximum_child_count
            || self.maximum_child_duration_ms == 0
            || self.issued_unix_ms >= self.expires_unix_ms
            || self.revocation_generation == 0
        {
            return Err(ExecutionModelError::InvalidField {
                field: "delegation grant",
                reason: "must have finite non-empty bounds and a valid lifetime",
            });
        }
        self.maximum_resources.validate()?;
        self.placement.validate()?;
        self.capabilities.validate()?;
        self.output.validate()
    }

    pub fn validate_against_parent(
        &self,
        session: &SessionCapsule,
        subject: &ApprovalSubject,
        seal: &Seal,
        now_unix_ms: u64,
        current_seal_revocation_generation: u64,
        current_grant_revocation_generation: u64,
    ) -> Result<(), ExecutionModelError> {
        self.validate()?;
        session.validate()?;
        seal.validate_for_subject(subject, now_unix_ms, current_seal_revocation_generation)?;
        if subject.capsule_kind != CapsuleKind::Session
            || subject.capsule_digest != session.digest()?
            || self.parent_session_capsule_digest != subject.capsule_digest
            || self.parent_session_seal_digest != seal.digest()?
        {
            return Err(ExecutionModelError::ContainmentViolation {
                field: "sealed parent identity",
            });
        }
        if now_unix_ms < self.issued_unix_ms || now_unix_ms >= self.expires_unix_ms {
            return Err(ExecutionModelError::ContainmentViolation {
                field: "delegation lifetime",
            });
        }
        if self.revocation_generation != current_grant_revocation_generation {
            return Err(ExecutionModelError::ContainmentViolation {
                field: "delegation revocation generation",
            });
        }
        let policy = session.delegation_policies.get(&self.policy_id).ok_or(
            ExecutionModelError::ContainmentViolation {
                field: "delegation policy",
            },
        )?;
        if self.policy_digest != policy.digest()?
            || self.planner_principal != policy.planner_principal
            || self.planner_implementation_digest != policy.planner_implementation_digest
            || !self
                .allowed_program_kinds
                .is_subset(&policy.allowed_program_kinds)
            || !self
                .allowed_program_resolvers
                .is_subset(&policy.allowed_program_resolvers)
            || !self
                .allowed_runtime_profiles
                .is_subset(&policy.allowed_runtime_profiles)
            || !policy.maximum_resources.contains(&self.maximum_resources)
            || !policy.placement.contains(&self.placement)
            || !policy.capabilities.contains(&self.capabilities)
            || !policy.output.contains(&self.output)
            || self.maximum_child_count > policy.maximum_child_count
            || self.maximum_concurrency > policy.maximum_concurrency
            || self.maximum_child_duration_ms > policy.maximum_child_duration_ms
            || (self.subdelegation_allowed && !policy.subdelegation_allowed)
            || self.policy_version_id != policy.policy_version_id
            || self.policy_version_digest != policy.policy_version_digest
        {
            return Err(ExecutionModelError::ContainmentViolation {
                field: "delegation policy envelope",
            });
        }
        Ok(())
    }

    pub fn contains_child(&self, child: &ExecutionCapsule) -> Result<(), ExecutionModelError> {
        self.validate()?;
        child.validate()?;
        let parent = child
            .parent
            .as_ref()
            .ok_or(ExecutionModelError::ContainmentViolation {
                field: "parent binding",
            })?;
        if parent.session_capsule_digest != self.parent_session_capsule_digest
            || parent.session_seal_digest != self.parent_session_seal_digest
            || parent.delegation_id != self.delegation_id
            || parent.delegation_grant_digest != self.digest()?
        {
            return Err(ExecutionModelError::ContainmentViolation {
                field: "parent binding",
            });
        }
        let runtime_digest = child.runtime.digest()?;
        let checks = [
            (
                self.allowed_program_kinds.contains(&child.program.kind),
                "Program kind",
            ),
            (
                self.allowed_program_resolvers
                    .contains(&child.program.resolver_digest),
                "Program resolver",
            ),
            (
                self.allowed_runtime_profiles.contains(&runtime_digest),
                "runtime profile",
            ),
            (
                self.maximum_resources.contains(&child.resources)
                    && child.resources.maximum_duration_ms <= self.maximum_child_duration_ms,
                "resource limits",
            ),
            (self.placement.contains(&child.placement), "placement"),
            (
                self.capabilities.contains(&child.capabilities),
                "capabilities",
            ),
            (self.output.contains(&child.output), "output classes"),
        ];
        if let Some((_, field)) = checks.into_iter().find(|(allowed, _)| !allowed) {
            return Err(ExecutionModelError::ContainmentViolation { field });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCapsule {
    pub schema_version: u32,
    pub kind: CapsuleKind,
    pub tenant_id: String,
    pub principal_id: String,
    pub program: ProgramIdentity,
    pub arguments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    pub input_artifacts: BTreeSet<ContentDigest>,
    pub runtime: RuntimeCompatibilityProfile,
    pub placement: PlacementConstraints,
    pub resources: ResourceLimits,
    pub capabilities: CapabilityContract,
    pub output: OutputContract,
    pub evidence: EvidenceContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentBinding>,
}

impl ExecutionCapsule {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "Execution Capsule schema version",
            self.schema_version,
            EXECUTION_CAPSULE_SCHEMA_VERSION,
        )?;
        if self.kind != CapsuleKind::Execution {
            return Err(ExecutionModelError::CapsuleKindMismatch);
        }
        validation::identifier("tenant identity", &self.tenant_id)?;
        validation::identifier("principal identity", &self.principal_id)?;
        self.program.validate()?;
        validation::bounded(
            "Execution arguments",
            self.arguments.len(),
            validation::MAX_ARGUMENTS,
        )?;
        for argument in &self.arguments {
            validation::argument("Execution argument", argument)?;
        }
        if let Some(path) = &self.working_directory {
            validation::relative_path("working directory", path)?;
        }
        validation::bounded(
            "input Artifacts",
            self.input_artifacts.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        self.runtime.validate()?;
        self.placement.validate()?;
        self.resources.validate()?;
        self.capabilities.validate()?;
        self.output.validate()?;
        self.evidence.validate()?;
        if let Some(parent) = &self.parent {
            parent.validate()?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }

    pub fn approval_subject(
        &self,
        policy_digest: ContentDigest,
        authority_context_digest: ContentDigest,
    ) -> Result<ApprovalSubject, ExecutionModelError> {
        Ok(ApprovalSubject {
            schema_version: EXECUTION_CAPSULE_SCHEMA_VERSION,
            capsule_kind: CapsuleKind::Execution,
            capsule_digest: self.digest()?,
            policy_digest,
            authority_context_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCapsule {
    pub schema_version: u32,
    pub kind: CapsuleKind,
    pub tenant_id: String,
    pub principal_id: String,
    pub initial_workspace_digest: ContentDigest,
    pub mutable_workspace_roots: BTreeSet<String>,
    pub runtime: RuntimeCompatibilityProfile,
    pub placement: PlacementConstraints,
    pub maximum_resources: ResourceLimits,
    pub capabilities: CapabilityContract,
    pub output: OutputContract,
    pub evidence: EvidenceContract,
    pub idle_timeout_ms: u64,
    pub hard_lifetime_ms: u64,
    pub maximum_child_count: u32,
    pub maximum_concurrency: u32,
    pub delegation_policies: BTreeMap<String, DelegationPolicy>,
}

impl SessionCapsule {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "Session Capsule schema version",
            self.schema_version,
            EXECUTION_CAPSULE_SCHEMA_VERSION,
        )?;
        if self.kind != CapsuleKind::Session {
            return Err(ExecutionModelError::CapsuleKindMismatch);
        }
        validation::identifier("tenant identity", &self.tenant_id)?;
        validation::identifier("principal identity", &self.principal_id)?;
        validation::bounded(
            "mutable workspace roots",
            self.mutable_workspace_roots.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        for root in &self.mutable_workspace_roots {
            validation::relative_path("mutable workspace root", root)?;
        }
        self.runtime.validate()?;
        self.placement.validate()?;
        self.maximum_resources.validate()?;
        self.capabilities.validate()?;
        self.output.validate()?;
        self.evidence.validate()?;
        if self.idle_timeout_ms == 0
            || self.hard_lifetime_ms == 0
            || self.idle_timeout_ms > self.hard_lifetime_ms
            || self.hard_lifetime_ms > self.maximum_resources.maximum_duration_ms
            || self.maximum_child_count == 0
            || self.maximum_concurrency == 0
            || self.maximum_concurrency > self.maximum_child_count
        {
            return Err(ExecutionModelError::InvalidField {
                field: "Session lifetime or concurrency",
                reason: "must be positive and within the Session resource envelope",
            });
        }
        validation::bounded(
            "delegation policies",
            self.delegation_policies.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        let runtime_digest = self.runtime.digest()?;
        for (identity, policy) in &self.delegation_policies {
            validation::identifier("delegation policy identity", identity)?;
            policy.validate(self, &runtime_digest)?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }

    pub fn approval_subject(
        &self,
        policy_digest: ContentDigest,
        authority_context_digest: ContentDigest,
    ) -> Result<ApprovalSubject, ExecutionModelError> {
        Ok(ApprovalSubject {
            schema_version: EXECUTION_CAPSULE_SCHEMA_VERSION,
            capsule_kind: CapsuleKind::Session,
            capsule_digest: self.digest()?,
            policy_digest,
            authority_context_digest,
        })
    }
}
