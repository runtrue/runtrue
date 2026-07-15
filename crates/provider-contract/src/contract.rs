use crate::{
    canonical::{
        canonical_bytes, canonical_digest, validate_collection_size, validate_identifier,
        validate_profile_name, validate_text, MAX_SHORT_TEXT_BYTES,
    },
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const PROVIDER_IDENTITY_DOMAIN: &[u8] = b"runtrue.provider.identity.v1\0";
const DEPLOYED_GENERATION_DOMAIN: &[u8] = b"runtrue.provider.deployed-generation.v1\0";
const INVENTORY_DOMAIN: &[u8] = b"runtrue.provider.runtime-inventory.v1\0";
const CAPACITY_DOMAIN: &[u8] = b"runtrue.provider.capacity-observation.v1\0";
const INVENTORY_SIGNATURE_DOMAIN: &[u8] = b"runtrue.provider.runtime-inventory-signature.v1\0";
const CAPACITY_SIGNATURE_DOMAIN: &[u8] = b"runtrue.provider.capacity-signature.v1\0";
const INVENTORY_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"runtrue.provider.inventory-authority-signature.v1\0";

pub trait ProviderContractSignatureVerifier {
    fn verify_provider_signature(
        &self,
        provider: &ProviderIdentity,
        signing_key_generation: u64,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

pub trait InventoryAuthoritySignatureVerifier {
    fn verify_inventory_authority_signature(
        &self,
        authority_identity_digest: &ContentDigest,
        signing_key_id: &ContentDigest,
        signing_key_generation: u64,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderContractSignature {
    pub algorithm: String,
    pub signing_key_generation: u64,
    pub signature: Vec<u8>,
}

impl ProviderContractSignature {
    fn validate_for(
        &self,
        deployed: &DeployedProviderGeneration,
    ) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.algorithm)?;
        if self.signing_key_generation != deployed.signing_key_generation
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
        {
            return Err(ProviderContractError::InvalidInventory(
                "Provider signature is malformed or uses another key generation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractGeneration(u32);

impl ContractGeneration {
    pub fn new(value: u32) -> Result<Self, ProviderContractError> {
        if value == 0 {
            return Err(ProviderContractError::InvalidNumber("contract generation"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractGenerationRange {
    pub minimum: ContractGeneration,
    pub maximum: ContractGeneration,
}

impl ContractGenerationRange {
    pub fn new(
        minimum: ContractGeneration,
        maximum: ContractGeneration,
    ) -> Result<Self, ProviderContractError> {
        let range = Self { minimum, maximum };
        range.validate()?;
        Ok(range)
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.minimum.get() == 0 || self.maximum.get() == 0 || self.minimum > self.maximum {
            return Err(ProviderContractError::InvalidGenerationRange);
        }
        Ok(())
    }

    #[must_use]
    pub const fn contains(self, generation: ContractGeneration) -> bool {
        generation.0 >= self.minimum.0 && generation.0 <= self.maximum.0
    }
}

/// Select the newest exact mutual generation and reject an authenticated
/// downgrade. There is no best-effort or oldest-generation fallback.
pub fn negotiate_contract_generation(
    local: ContractGenerationRange,
    remote: ContractGenerationRange,
    previously_authenticated: Option<ContractGeneration>,
) -> Result<ContractGeneration, ProviderContractError> {
    local.validate()?;
    remote.validate()?;
    let minimum = local.minimum.max(remote.minimum);
    let maximum = local.maximum.min(remote.maximum);
    if minimum > maximum {
        return Err(ProviderContractError::NoCompatibleGeneration);
    }
    if let Some(authenticated) = previously_authenticated {
        if maximum < authenticated {
            return Err(ProviderContractError::DowngradeRejected {
                authenticated: authenticated.get(),
                selected: maximum.get(),
            });
        }
    }
    Ok(maximum)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub administrative_trust_domain: String,
    pub authentication_key_digest: ContentDigest,
}

impl ProviderIdentity {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Provider id", &self.provider_id)?;
        validate_identifier(
            "Provider administrative trust domain",
            &self.administrative_trust_domain,
        )
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(PROVIDER_IDENTITY_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployedProviderGeneration {
    pub provider: ProviderIdentity,
    pub generation: u64,
    pub binary_digest: ContentDigest,
    pub configuration_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub key_set_digest: ContentDigest,
    pub signing_key_generation: u64,
}

impl DeployedProviderGeneration {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.provider.validate()?;
        if self.generation == 0 || self.signing_key_generation == 0 {
            return Err(ProviderContractError::InvalidNumber(
                "deployed Provider or signing-key generation",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(DEPLOYED_GENERATION_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureProfileId {
    pub name: String,
    pub generation: u32,
}

impl FeatureProfileId {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.name)?;
        if self.generation == 0 {
            return Err(ProviderContractError::InvalidNumber(
                "feature profile generation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureProfile {
    pub id: FeatureProfileId,
    pub compatibility_digest: ContentDigest,
    pub limits: BTreeMap<String, u64>,
    pub compatibility_metadata: BTreeMap<String, String>,
}

impl FeatureProfile {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.id.validate()?;
        validate_collection_size(self.limits.len())?;
        validate_collection_size(self.compatibility_metadata.len())?;
        for (name, value) in &self.limits {
            validate_profile_name(name)?;
            if *value == 0 {
                return Err(ProviderContractError::InvalidNumber(
                    "feature profile limit",
                ));
            }
        }
        for (name, value) in &self.compatibility_metadata {
            validate_profile_name(name)?;
            validate_text(
                "feature compatibility metadata",
                value,
                MAX_SHORT_TEXT_BYTES,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureRequirement {
    pub id: FeatureProfileId,
    pub compatibility_digest: Option<ContentDigest>,
    pub minimum_limits: BTreeMap<String, u64>,
}

impl FeatureRequirement {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.id.validate()?;
        validate_collection_size(self.minimum_limits.len())?;
        for (name, minimum) in &self.minimum_limits {
            validate_profile_name(name)?;
            if *minimum == 0 {
                return Err(ProviderContractError::InvalidNumber(
                    "required feature limit",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDescriptor {
    pub contract_generation: ContractGeneration,
    pub deployed_generation: DeployedProviderGeneration,
    pub feature_profiles: BTreeMap<String, FeatureProfile>,
    pub replay_grades: BTreeSet<String>,
    pub evidence_grades: BTreeSet<String>,
    pub attestation_grades: BTreeSet<String>,
}

impl ProviderDescriptor {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.contract_generation.get() == 0 {
            return Err(ProviderContractError::InvalidDescriptor(
                "contract generation must be positive",
            ));
        }
        self.deployed_generation.validate()?;
        validate_collection_size(self.feature_profiles.len())?;
        validate_collection_size(self.replay_grades.len())?;
        validate_collection_size(self.evidence_grades.len())?;
        validate_collection_size(self.attestation_grades.len())?;
        for (key, profile) in &self.feature_profiles {
            profile.validate()?;
            if key != &profile.id.name {
                return Err(ProviderContractError::InvalidDescriptor(
                    "feature profile map key differs from its profile id",
                ));
            }
        }
        for grade in self
            .replay_grades
            .iter()
            .chain(&self.evidence_grades)
            .chain(&self.attestation_grades)
        {
            validate_profile_name(grade)?;
        }
        Ok(())
    }

    pub fn require_profiles(
        &self,
        requirements: &[FeatureRequirement],
    ) -> Result<(), ProviderContractError> {
        self.validate()?;
        validate_collection_size(requirements.len())?;
        for requirement in requirements {
            requirement.validate()?;
            let Some(profile) = self.feature_profiles.get(&requirement.id.name) else {
                return Err(ProviderContractError::UnsupportedProfile(
                    requirement.id.name.clone(),
                ));
            };
            let compatible = profile.id == requirement.id
                && requirement
                    .compatibility_digest
                    .as_ref()
                    .is_none_or(|digest| digest == &profile.compatibility_digest)
                && requirement.minimum_limits.iter().all(|(name, minimum)| {
                    profile
                        .limits
                        .get(name)
                        .is_some_and(|actual| actual >= minimum)
                });
            if !compatible {
                return Err(ProviderContractError::UnsupportedProfile(
                    requirement.id.name.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Immutable, authenticated runtime identity. Capacity is deliberately not a
/// field of this object and cannot change its identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryEntry {
    pub inventory_generation: u64,
    pub runtime_id: String,
    pub deployed_provider: DeployedProviderGeneration,
    pub pool_id: String,
    pub pool_trust_domain: String,
    pub pool_trust_profile_digest: ContentDigest,
    pub runtime_compatibility_digest: ContentDigest,
    pub security_generation: u64,
    pub revocation_generation: u64,
    pub placement_attributes: BTreeMap<String, String>,
    pub devices: BTreeSet<String>,
    pub limits: BTreeMap<String, u64>,
    pub feature_profiles: BTreeSet<FeatureProfileId>,
}

/// Caller-pinned view of the Provider posture that is current for admission.
/// Signed inventory remains immutable, but it is usable only while this
/// independently authenticated authority snapshot admits its generations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryAuthoritySnapshot {
    pub snapshot_version: u32,
    pub expected_deployed_provider: DeployedProviderGeneration,
    pub minimum_inventory_generation: u64,
    pub minimum_security_generation: u64,
    pub current_revocation_generation: u64,
    pub valid_from_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub authority_evidence_digest: ContentDigest,
}

impl InventoryAuthoritySnapshot {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ProviderContractError> {
        self.expected_deployed_provider.validate()?;
        if self.snapshot_version != 1
            || self.minimum_inventory_generation == 0
            || self.minimum_security_generation == 0
            || self.current_revocation_generation == 0
            || self.valid_from_unix_ms == 0
            || self.expires_unix_ms <= self.valid_from_unix_ms
            || now_unix_ms < self.valid_from_unix_ms
            || now_unix_ms >= self.expires_unix_ms
        {
            return Err(ProviderContractError::InvalidInventory(
                "inventory authority snapshot is malformed, stale, or not yet valid",
            ));
        }
        Ok(())
    }

    fn authorize(
        &self,
        inventory: &RuntimeInventoryEntry,
        now_unix_ms: u64,
    ) -> Result<(), ProviderContractError> {
        self.validate(now_unix_ms)?;
        inventory.validate()?;
        if inventory.deployed_provider.digest()? != self.expected_deployed_provider.digest()?
            || inventory.inventory_generation < self.minimum_inventory_generation
            || inventory.security_generation < self.minimum_security_generation
            || inventory.revocation_generation != self.current_revocation_generation
        {
            return Err(ProviderContractError::InvalidInventory(
                "inventory is outside the current Provider security or revocation posture",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedInventoryAuthoritySnapshot {
    pub snapshot: InventoryAuthoritySnapshot,
    pub snapshot_digest: ContentDigest,
    pub authority_identity_digest: ContentDigest,
    pub signing_key_id: ContentDigest,
    pub signing_key_generation: u64,
    pub signature_algorithm: String,
    pub signature: Vec<u8>,
}

impl SignedInventoryAuthoritySnapshot {
    pub fn signature_message(&self, now_unix_ms: u64) -> Result<Vec<u8>, ProviderContractError> {
        self.snapshot.validate(now_unix_ms)?;
        validate_profile_name(&self.signature_algorithm)?;
        let actual = canonical_digest(
            b"runtrue.provider.inventory-authority-snapshot.v1\0",
            &self.snapshot,
        )?;
        if actual != self.snapshot_digest
            || self.signing_key_generation == 0
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
        {
            return Err(ProviderContractError::InvalidInventory(
                "inventory authority signature metadata or digest is invalid",
            ));
        }
        let canonical = canonical_bytes(&(
            &self.snapshot_digest,
            &self.authority_identity_digest,
            &self.signing_key_id,
            self.signing_key_generation,
            &self.signature_algorithm,
        ))?;
        let mut message =
            Vec::with_capacity(INVENTORY_AUTHORITY_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(INVENTORY_AUTHORITY_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        now_unix_ms: u64,
        verifier: &impl InventoryAuthoritySignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        let message = self.signature_message(now_unix_ms)?;
        if !verifier.verify_inventory_authority_signature(
            &self.authority_identity_digest,
            &self.signing_key_id,
            self.signing_key_generation,
            &self.signature_algorithm,
            &message,
            &self.signature,
        ) {
            return Err(ProviderContractError::InvalidInventory(
                "inventory authority signature verification failed",
            ));
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        inventory: &RuntimeInventoryEntry,
        now_unix_ms: u64,
        verifier: &impl InventoryAuthoritySignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        self.verify_with(now_unix_ms, verifier)?;
        self.snapshot.authorize(inventory, now_unix_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSelectionRequirement {
    pub runtime_compatibility_digest: ContentDigest,
    pub allowed_provider_identity_digests: BTreeSet<ContentDigest>,
    pub allowed_administrative_trust_domains: BTreeSet<String>,
    pub allowed_pool_trust_profile_digests: BTreeSet<ContentDigest>,
    pub exact_placement_attributes: BTreeMap<String, String>,
    pub required_devices: BTreeSet<String>,
    pub minimum_limits: BTreeMap<String, u64>,
    pub required_feature_profiles: BTreeSet<FeatureProfileId>,
}

impl RuntimeSelectionRequirement {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.allowed_provider_identity_digests.is_empty()
            || self.allowed_administrative_trust_domains.is_empty()
            || self.allowed_pool_trust_profile_digests.is_empty()
        {
            return Err(ProviderContractError::InvalidInventory(
                "selection allowlists cannot be empty",
            ));
        }
        for length in [
            self.allowed_provider_identity_digests.len(),
            self.allowed_administrative_trust_domains.len(),
            self.allowed_pool_trust_profile_digests.len(),
            self.exact_placement_attributes.len(),
            self.required_devices.len(),
            self.minimum_limits.len(),
            self.required_feature_profiles.len(),
        ] {
            validate_collection_size(length)?;
        }
        for domain in &self.allowed_administrative_trust_domains {
            validate_identifier("allowed Provider trust domain", domain)?;
        }
        for (name, value) in &self.exact_placement_attributes {
            validate_profile_name(name)?;
            validate_text("required placement attribute", value, MAX_SHORT_TEXT_BYTES)?;
        }
        for device in &self.required_devices {
            validate_identifier("required runtime device", device)?;
        }
        for (name, minimum) in &self.minimum_limits {
            validate_profile_name(name)?;
            if *minimum == 0 {
                return Err(ProviderContractError::InvalidInventory(
                    "required runtime limits must be positive",
                ));
            }
        }
        for profile in &self.required_feature_profiles {
            profile.validate()?;
        }
        Ok(())
    }

    /// Requires one immutable inventory entry to satisfy every field. Callers
    /// may inspect capacity only after this succeeds; there is no near match.
    pub fn require_exact_match(
        &self,
        inventory: &RuntimeInventoryEntry,
        authority: &SignedInventoryAuthoritySnapshot,
        now_unix_ms: u64,
        verifier: &impl InventoryAuthoritySignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        self.validate()?;
        authority.authorize(inventory, now_unix_ms, verifier)?;
        let provider_identity = inventory.deployed_provider.provider.digest()?;
        let matches = inventory.runtime_compatibility_digest == self.runtime_compatibility_digest
            && self
                .allowed_provider_identity_digests
                .contains(&provider_identity)
            && self.allowed_administrative_trust_domains.contains(
                &inventory
                    .deployed_provider
                    .provider
                    .administrative_trust_domain,
            )
            && self
                .allowed_pool_trust_profile_digests
                .contains(&inventory.pool_trust_profile_digest)
            && self
                .exact_placement_attributes
                .iter()
                .all(|(name, value)| inventory.placement_attributes.get(name) == Some(value))
            && self.required_devices.is_subset(&inventory.devices)
            && self.minimum_limits.iter().all(|(name, minimum)| {
                inventory
                    .limits
                    .get(name)
                    .is_some_and(|actual| actual >= minimum)
            })
            && self
                .required_feature_profiles
                .is_subset(&inventory.feature_profiles);
        if !matches {
            return Err(ProviderContractError::InvalidInventory(
                "runtime did not exactly satisfy the complete selection requirement",
            ));
        }
        Ok(())
    }
}

impl RuntimeInventoryEntry {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.deployed_provider.validate()?;
        for value in [&self.runtime_id, &self.pool_id, &self.pool_trust_domain] {
            validate_identifier("runtime inventory identity", value)?;
        }
        if self.inventory_generation == 0
            || self.security_generation == 0
            || self.revocation_generation == 0
        {
            return Err(ProviderContractError::InvalidInventory(
                "inventory, security, and revocation generations must be positive",
            ));
        }
        validate_collection_size(self.placement_attributes.len())?;
        validate_collection_size(self.devices.len())?;
        validate_collection_size(self.limits.len())?;
        validate_collection_size(self.feature_profiles.len())?;
        for (name, value) in &self.placement_attributes {
            validate_profile_name(name)?;
            validate_text("placement attribute", value, MAX_SHORT_TEXT_BYTES)?;
        }
        for device in &self.devices {
            validate_identifier("runtime device", device)?;
        }
        for (name, value) in &self.limits {
            validate_profile_name(name)?;
            if *value == 0 {
                return Err(ProviderContractError::InvalidInventory(
                    "runtime limits must be positive",
                ));
            }
        }
        for profile in &self.feature_profiles {
            profile.validate()?;
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        descriptor: &ProviderDescriptor,
    ) -> Result<(), ProviderContractError> {
        self.validate()?;
        descriptor.validate()?;
        if self.deployed_provider.digest()? != descriptor.deployed_generation.digest()? {
            return Err(ProviderContractError::InvalidInventory(
                "inventory belongs to another deployed Provider generation",
            ));
        }
        for profile in &self.feature_profiles {
            if descriptor
                .feature_profiles
                .get(&profile.name)
                .is_none_or(|advertised| advertised.id != *profile)
            {
                return Err(ProviderContractError::InvalidInventory(
                    "inventory advertises an unpassed feature profile",
                ));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(INVENTORY_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRuntimeInventoryEntry {
    pub inventory: RuntimeInventoryEntry,
    pub inventory_digest: ContentDigest,
    pub signature: ProviderContractSignature,
}

impl SignedRuntimeInventoryEntry {
    pub fn validate_structure(&self) -> Result<(), ProviderContractError> {
        self.inventory.validate()?;
        self.signature
            .validate_for(&self.inventory.deployed_provider)?;
        if self.inventory.digest()? != self.inventory_digest {
            return Err(ProviderContractError::InvalidInventory(
                "signed inventory digest mismatch",
            ));
        }
        Ok(())
    }

    pub fn signature_message(&self) -> Result<Vec<u8>, ProviderContractError> {
        self.validate_structure()?;
        let canonical = canonical_bytes(&(
            &self.inventory_digest,
            &self.signature.algorithm,
            self.signature.signing_key_generation,
        ))?;
        let mut message = Vec::with_capacity(INVENTORY_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(INVENTORY_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        authority: &SignedInventoryAuthoritySnapshot,
        now_unix_ms: u64,
        verifier: &(impl ProviderContractSignatureVerifier + InventoryAuthoritySignatureVerifier),
    ) -> Result<(), ProviderContractError> {
        authority.authorize(&self.inventory, now_unix_ms, verifier)?;
        let message = self.signature_message()?;
        if !verifier.verify_provider_signature(
            &self.inventory.deployed_provider.provider,
            self.signature.signing_key_generation,
            &self.signature.algorithm,
            &message,
            &self.signature.signature,
        ) {
            return Err(ProviderContractError::InvalidInventory(
                "inventory signature verification failed",
            ));
        }
        Ok(())
    }
}

/// Mutable, expiring scheduling hint bound to one exact immutable inventory
/// entry. It is never proof of runtime identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityObservation {
    pub inventory_digest: ContentDigest,
    pub observation_sequence: u64,
    pub available_slots: u32,
    pub available_cpu: u64,
    pub available_memory_bytes: u64,
    pub available_storage_bytes: u64,
    pub observed_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub producer: ProviderIdentity,
}

impl CapacityObservation {
    pub fn validate_against(
        &self,
        inventory: &RuntimeInventoryEntry,
        now_unix_ms: u64,
    ) -> Result<(), ProviderContractError> {
        self.producer.validate()?;
        let provider_matches = self.producer == inventory.deployed_provider.provider;
        let valid = self.observation_sequence > 0
            && self.expires_unix_ms > self.observed_unix_ms
            && now_unix_ms >= self.observed_unix_ms
            && now_unix_ms < self.expires_unix_ms
            && self.inventory_digest == inventory.digest()?
            && provider_matches;
        if !valid {
            return Err(ProviderContractError::InvalidCapacityObservation);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.producer.validate()?;
        if self.observation_sequence == 0 || self.expires_unix_ms <= self.observed_unix_ms {
            return Err(ProviderContractError::InvalidCapacityObservation);
        }
        canonical_digest(CAPACITY_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCapacityObservation {
    pub observation: CapacityObservation,
    pub observation_digest: ContentDigest,
    pub deployed_provider: DeployedProviderGeneration,
    pub signature: ProviderContractSignature,
}

impl SignedCapacityObservation {
    pub fn validate_against(
        &self,
        inventory: &SignedRuntimeInventoryEntry,
        now_unix_ms: u64,
    ) -> Result<(), ProviderContractError> {
        inventory.validate_structure()?;
        self.deployed_provider.validate()?;
        self.signature.validate_for(&self.deployed_provider)?;
        self.observation
            .validate_against(&inventory.inventory, now_unix_ms)?;
        if self.observation.digest()? != self.observation_digest
            || self.deployed_provider.digest()? != inventory.inventory.deployed_provider.digest()?
        {
            return Err(ProviderContractError::InvalidCapacityObservation);
        }
        Ok(())
    }

    pub fn signature_message(
        &self,
        inventory: &SignedRuntimeInventoryEntry,
        now_unix_ms: u64,
    ) -> Result<Vec<u8>, ProviderContractError> {
        self.validate_against(inventory, now_unix_ms)?;
        let canonical = canonical_bytes(&(
            &self.observation_digest,
            &self.signature.algorithm,
            self.signature.signing_key_generation,
        ))?;
        let mut message = Vec::with_capacity(CAPACITY_SIGNATURE_DOMAIN.len() + canonical.len());
        message.extend_from_slice(CAPACITY_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_with(
        &self,
        inventory: &SignedRuntimeInventoryEntry,
        authority: &SignedInventoryAuthoritySnapshot,
        now_unix_ms: u64,
        verifier: &(impl ProviderContractSignatureVerifier + InventoryAuthoritySignatureVerifier),
    ) -> Result<(), ProviderContractError> {
        inventory.verify_with(authority, now_unix_ms, verifier)?;
        let message = self.signature_message(inventory, now_unix_ms)?;
        if !verifier.verify_provider_signature(
            &self.deployed_provider.provider,
            self.signature.signing_key_generation,
            &self.signature.algorithm,
            &message,
            &self.signature.signature,
        ) {
            return Err(ProviderContractError::InvalidCapacityObservation);
        }
        Ok(())
    }
}
