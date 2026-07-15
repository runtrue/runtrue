use crate::{
    canonical::{canonical_bytes, canonical_digest, validate_identifier, validate_profile_name},
    InventoryAuthoritySignatureVerifier, ProviderContractError, ProviderContractSignatureVerifier,
    ProviderIdentity, SignedInventoryAuthoritySnapshot, SignedRuntimeInventoryEntry,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

const POOL_TRANSITION_DOMAIN: &[u8] = b"runtrue.provider.pool-member-transition.v1\0";
const STERILE_TEMPLATE_DOMAIN: &[u8] = b"runtrue.provider.sterile-template-publication.v1\0";
const STERILE_TEMPLATE_SIGNATURE_DOMAIN: &[u8] =
    b"runtrue.provider.sterile-template-signature.v1\0";

pub trait SterileTemplateSignatureVerifier {
    fn verify_sterile_template_signature(
        &self,
        authority_identity_digest: &ContentDigest,
        signing_key_id: &ContentDigest,
        signing_key_generation: u64,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

/// Durable, one-shot lifecycle. A member that may have seen tenant state can
/// only proceed toward destruction; it can never become sterile again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolMemberState {
    Creating,
    Sterile,
    Assigning,
    TenantUsed,
    Quarantined,
    Destroying,
    Destroyed,
}

impl PoolMemberState {
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        use PoolMemberState::{
            Assigning, Creating, Destroyed, Destroying, Quarantined, Sterile, TenantUsed,
        };
        match self {
            Creating => matches!(next, Sterile | Quarantined),
            Sterile => matches!(next, Assigning | Quarantined),
            Assigning => matches!(next, TenantUsed | Quarantined),
            TenantUsed => matches!(next, Destroying | Quarantined),
            Quarantined => matches!(next, Destroying),
            Destroying => matches!(next, Destroyed),
            Destroyed => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolAssignmentSubjectKind {
    Execution,
    SessionOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolAssignmentBinding {
    pub tenant_id: String,
    pub capsule_digest: ContentDigest,
    pub subject_kind: PoolAssignmentSubjectKind,
    pub subject_id: String,
    pub lease_id: String,
    pub fence_generation: u64,
    pub sterile_template_digest: ContentDigest,
    pub member_generation: u64,
}

impl PoolAssignmentBinding {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("pool assignment tenant", &self.tenant_id)?;
        validate_identifier("pool assignment subject", &self.subject_id)?;
        validate_identifier("pool assignment lease", &self.lease_id)?;
        if self.fence_generation == 0 || self.member_generation == 0 {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolMemberRecord {
    pub member_id: String,
    pub member_generation: u64,
    pub pool_id: String,
    pub pool_trust_domain: String,
    pub provider: ProviderIdentity,
    pub state: PoolMemberState,
    pub transition_sequence: u64,
    pub fence_generation: u64,
    pub runtime_inventory_digest: ContentDigest,
    pub sterile_template_digest: ContentDigest,
    pub assignment: Option<PoolAssignmentBinding>,
    pub last_transition_digest: Option<ContentDigest>,
}

impl PoolMemberRecord {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("pool member id", &self.member_id)?;
        validate_identifier("pool id", &self.pool_id)?;
        validate_identifier("pool trust domain", &self.pool_trust_domain)?;
        self.provider.validate()?;
        if self.member_generation == 0 || self.fence_generation == 0 {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        if self.transition_sequence == 0 {
            if self.state != PoolMemberState::Creating || self.last_transition_digest.is_some() {
                return Err(ProviderContractError::InvalidPoolTransition);
            }
        } else if self.last_transition_digest.is_none() {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        if matches!(
            self.state,
            PoolMemberState::Assigning | PoolMemberState::TenantUsed
        ) && self.assignment.is_none()
        {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        if let Some(assignment) = &self.assignment {
            assignment.validate()?;
            if assignment.member_generation != self.member_generation
                || assignment.sterile_template_digest != self.sterile_template_digest
                || assignment.fence_generation != self.fence_generation
            {
                return Err(ProviderContractError::InvalidPoolTransition);
            }
        }
        Ok(())
    }

    pub fn apply(&self, transition: &PoolMemberTransition) -> Result<Self, ProviderContractError> {
        self.validate()?;
        transition.validate()?;
        if transition.member_id != self.member_id
            || transition.member_generation != self.member_generation
            || transition.pool_id != self.pool_id
            || transition.from != self.state
            || transition.sequence != self.transition_sequence.saturating_add(1)
            || transition.previous_transition_digest.as_ref()
                != self.last_transition_digest.as_ref()
        {
            return Err(ProviderContractError::InvalidPoolTransition);
        }

        let assignment = if transition.to == PoolMemberState::Assigning {
            let binding = transition
                .assignment
                .clone()
                .ok_or(ProviderContractError::InvalidPoolTransition)?;
            if self.assignment.is_some()
                || binding.member_generation != self.member_generation
                || binding.sterile_template_digest != self.sterile_template_digest
                || binding.fence_generation != self.fence_generation.saturating_add(1)
            {
                return Err(ProviderContractError::InvalidPoolTransition);
            }
            Some(binding)
        } else {
            if transition.assignment.is_some() {
                return Err(ProviderContractError::InvalidPoolTransition);
            }
            self.assignment.clone()
        };
        if transition.to == PoolMemberState::Destroyed
            && transition.destruction_proof_digest.is_none()
        {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        let fence_generation = assignment
            .as_ref()
            .map_or(self.fence_generation, |binding| binding.fence_generation);
        let next = Self {
            member_id: self.member_id.clone(),
            member_generation: self.member_generation,
            pool_id: self.pool_id.clone(),
            pool_trust_domain: self.pool_trust_domain.clone(),
            provider: self.provider.clone(),
            state: transition.to,
            transition_sequence: transition.sequence,
            fence_generation,
            runtime_inventory_digest: self.runtime_inventory_digest.clone(),
            sterile_template_digest: self.sterile_template_digest.clone(),
            assignment,
            last_transition_digest: Some(transition.digest()?),
        };
        next.validate()?;
        Ok(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolMemberTransition {
    pub member_id: String,
    pub member_generation: u64,
    pub pool_id: String,
    pub sequence: u64,
    pub previous_transition_digest: Option<ContentDigest>,
    pub from: PoolMemberState,
    pub to: PoolMemberState,
    pub assignment: Option<PoolAssignmentBinding>,
    pub destruction_proof_digest: Option<ContentDigest>,
    pub reason_digest: ContentDigest,
    pub observed_unix_ms: u64,
}

impl PoolMemberTransition {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("pool member transition member", &self.member_id)?;
        validate_identifier("pool member transition pool", &self.pool_id)?;
        if self.member_generation == 0
            || self.sequence == 0
            || !self.from.can_transition_to(self.to)
            || (self.sequence == 1) != self.previous_transition_digest.is_none()
            || (self.to == PoolMemberState::Assigning) != self.assignment.is_some()
            || (self.to != PoolMemberState::Destroyed && self.destruction_proof_digest.is_some())
        {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        if let Some(assignment) = &self.assignment {
            assignment.validate()?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(POOL_TRANSITION_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SterileTemplatePublication {
    pub publication_version: u32,
    pub template_digest: ContentDigest,
    pub builder_definition_digest: ContentDigest,
    pub builder_identity_digest: ContentDigest,
    pub runtime_inventory_digest: ContentDigest,
    pub runtime_compatibility_digest: ContentDigest,
    pub snapshot_compatibility_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub sbom_digest: ContentDigest,
    pub vulnerability_evidence_digest: ContentDigest,
    pub policy_evidence_digest: ContentDigest,
    pub sterility_scan_digest: ContentDigest,
    pub cold_boot_probe_digest: ContentDigest,
    pub restore_probe_digest: ContentDigest,
    pub inventory_generation: u64,
    pub revocation_generation: u64,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl SterileTemplatePublication {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.publication_version != 1
            || self.inventory_generation == 0
            || self.revocation_generation == 0
            || self.created_unix_ms == 0
            || self.expires_unix_ms <= self.created_unix_ms
        {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(STERILE_TEMPLATE_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSterileTemplatePublication {
    pub publication: SterileTemplatePublication,
    pub publication_digest: ContentDigest,
    pub authority_identity_digest: ContentDigest,
    pub signing_key_id: ContentDigest,
    pub signing_key_generation: u64,
    pub signature_algorithm: String,
    pub signature: Vec<u8>,
}

impl SignedSterileTemplatePublication {
    pub fn signature_message(&self) -> Result<Vec<u8>, ProviderContractError> {
        self.publication.validate()?;
        validate_profile_name(&self.signature_algorithm)?;
        if self.publication.digest()? != self.publication_digest
            || self.signing_key_generation == 0
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
        {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        let canonical = canonical_bytes(&(
            &self.publication_digest,
            &self.authority_identity_digest,
            &self.signing_key_id,
            self.signing_key_generation,
            &self.signature_algorithm,
        ))?;
        let mut message =
            Vec::with_capacity(STERILE_TEMPLATE_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(STERILE_TEMPLATE_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        verifier: &impl SterileTemplateSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        let message = self.signature_message()?;
        if !verifier.verify_sterile_template_signature(
            &self.authority_identity_digest,
            &self.signing_key_id,
            self.signing_key_generation,
            &self.signature_algorithm,
            &message,
            &self.signature,
        ) {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        Ok(())
    }

    pub fn authorize_member(
        &self,
        member: &PoolMemberRecord,
        inventory: &SignedRuntimeInventoryEntry,
        authority: &SignedInventoryAuthoritySnapshot,
        now_unix_ms: u64,
        verifier: &(impl SterileTemplateSignatureVerifier
              + ProviderContractSignatureVerifier
              + InventoryAuthoritySignatureVerifier),
    ) -> Result<(), ProviderContractError> {
        self.verify_with(verifier)?;
        inventory.verify_with(authority, now_unix_ms, verifier)?;
        member.validate()?;
        if !matches!(
            member.state,
            PoolMemberState::Creating | PoolMemberState::Sterile
        ) || member.sterile_template_digest != self.publication.template_digest
            || member.runtime_inventory_digest != self.publication.runtime_inventory_digest
            || inventory.inventory_digest != self.publication.runtime_inventory_digest
            || inventory.inventory.inventory_generation != self.publication.inventory_generation
            || inventory.inventory.revocation_generation != self.publication.revocation_generation
            || now_unix_ms < self.publication.created_unix_ms
            || now_unix_ms >= self.publication.expires_unix_ms
        {
            return Err(ProviderContractError::InvalidPoolTransition);
        }
        Ok(())
    }
}

pub trait SterileTemplatePublicationStore {
    type Error;

    /// Create-once or exact replay. A digest collision with different canonical
    /// publication bytes must fail closed.
    fn publish(
        &self,
        expected_absent: bool,
        publication: &SignedSterileTemplatePublication,
    ) -> Result<SignedSterileTemplatePublication, Self::Error>;

    fn current(
        &self,
        template_digest: &ContentDigest,
    ) -> Result<Option<SignedSterileTemplatePublication>, Self::Error>;

    fn revoke(
        &self,
        template_digest: &ContentDigest,
        expected_revocation_generation: u64,
        next_revocation_generation: u64,
    ) -> Result<SignedSterileTemplatePublication, Self::Error>;
}

pub trait DurablePoolManager {
    type Error;

    fn member(&self, member_id: &str) -> Result<Option<PoolMemberRecord>, Self::Error>;

    /// Atomically compare the complete prior record and apply one transition.
    fn compare_and_swap(
        &self,
        expected: &PoolMemberRecord,
        transition: &PoolMemberTransition,
    ) -> Result<PoolMemberRecord, Self::Error>;

    /// Reconciliation may only follow the transition graph; it can never move
    /// assigning, tenant-used, or quarantined state back to sterile.
    fn reconcile(
        &self,
        expected: &PoolMemberRecord,
        transition: &PoolMemberTransition,
    ) -> Result<PoolMemberRecord, Self::Error>;
}
