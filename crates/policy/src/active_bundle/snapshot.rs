use super::{
    canonical::cedar_source_from_canonical_json,
    model::{ActivePolicyBundleState, PolicyBundleDraft},
    validation::validate_identifier,
    ActivePolicyError,
};
use crate::{
    CedarAuthorizationDecision, CedarAuthorizationEngine, CedarAuthorizationRequest,
    DenyFirstPolicy,
};
use runtrue_model::ContentDigest;
use std::fmt;
impl ActivePolicyBundleState {
    pub fn new(tenant_id: impl Into<String>) -> Result<Self, ActivePolicyError> {
        let tenant_id = tenant_id.into();
        validate_identifier("policy tenant id", &tenant_id)?;
        Ok(Self {
            tenant_id,
            policy_epoch: 0,
            decision_cache_generation: 0,
            active: None,
            emergency_denies: DenyFirstPolicy::default(),
        })
    }
    pub fn replace_emergency_denies(
        &mut self,
        emergency_denies: DenyFirstPolicy,
        expected_cache_generation: u64,
    ) -> Result<bool, ActivePolicyError> {
        if emergency_denies == self.emergency_denies {
            return Ok(false);
        }
        if expected_cache_generation != self.decision_cache_generation {
            return Err(ActivePolicyError::StaleCacheGeneration {
                expected: self.decision_cache_generation,
                actual: expected_cache_generation,
            });
        }
        let source = self
            .active
            .as_ref()
            .map(|active| cedar_source_from_canonical_json(&active.canonical_policy_json))
            .transpose()?
            .unwrap_or_default();
        CedarAuthorizationEngine::new(&source, emergency_denies.clone())?;
        self.decision_cache_generation = self
            .decision_cache_generation
            .checked_add(1)
            .ok_or(ActivePolicyError::EpochExhausted)?;
        self.emergency_denies = emergency_denies;
        Ok(true)
    }

    pub fn snapshot(&self) -> Result<ActivePolicySnapshot, ActivePolicyError> {
        self.verify()?;
        let engine = engine_from_json_optional(
            self.active
                .as_ref()
                .map(|active| active.canonical_policy_json.as_str()),
            self.emergency_denies.clone(),
        )?;
        Ok(ActivePolicySnapshot {
            tenant_id: self.tenant_id.clone(),
            policy_epoch: self.policy_epoch,
            decision_cache_generation: self.decision_cache_generation,
            policy_digest: self.active.as_ref().map(|active| active.digest.clone()),
            engine,
        })
    }

    pub fn verify(&self) -> Result<(), ActivePolicyError> {
        validate_identifier("policy tenant id", &self.tenant_id)?;
        if self.decision_cache_generation < self.policy_epoch {
            return Err(ActivePolicyError::CorruptActivePolicyState);
        }
        match &self.active {
            Some(active) => {
                active.verify()?;
                if active.tenant_id != self.tenant_id || active.policy_epoch != self.policy_epoch {
                    return Err(ActivePolicyError::CorruptActivePolicyState);
                }
            }
            None if self.policy_epoch != 0 => {
                return Err(ActivePolicyError::CorruptActivePolicyState);
            }
            None => {}
        }
        let source = self
            .active
            .as_ref()
            .map(|active| cedar_source_from_canonical_json(&active.canonical_policy_json))
            .transpose()?
            .unwrap_or_default();
        CedarAuthorizationEngine::new(&source, self.emergency_denies.clone())?;
        Ok(())
    }

    pub(super) fn ensure_draft_tenant(
        &self,
        draft: &PolicyBundleDraft,
    ) -> Result<(), ActivePolicyError> {
        draft.verify()?;
        if draft.tenant_id != self.tenant_id {
            return Err(ActivePolicyError::CrossTenantDraft);
        }
        Ok(())
    }
}
pub struct ActivePolicySnapshot {
    pub tenant_id: String,
    pub policy_epoch: u64,
    pub decision_cache_generation: u64,
    pub policy_digest: Option<ContentDigest>,
    engine: CedarAuthorizationEngine,
}

impl fmt::Debug for ActivePolicySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivePolicySnapshot")
            .field("tenant_id", &self.tenant_id)
            .field("policy_epoch", &self.policy_epoch)
            .field("decision_cache_generation", &self.decision_cache_generation)
            .field("policy_digest", &self.policy_digest)
            .finish_non_exhaustive()
    }
}

impl ActivePolicySnapshot {
    pub fn authorize(
        &self,
        request: &CedarAuthorizationRequest,
    ) -> Result<CedarAuthorizationDecision, ActivePolicyError> {
        Ok(self.engine.authorize(request)?)
    }
}
pub(super) fn engine_from_json(
    canonical_policy_json: &str,
    emergency: DenyFirstPolicy,
) -> Result<CedarAuthorizationEngine, ActivePolicyError> {
    let source = cedar_source_from_canonical_json(canonical_policy_json)?;
    Ok(CedarAuthorizationEngine::new(&source, emergency)?)
}

pub(super) fn engine_from_json_optional(
    canonical_policy_json: Option<&str>,
    emergency: DenyFirstPolicy,
) -> Result<CedarAuthorizationEngine, ActivePolicyError> {
    match canonical_policy_json {
        Some(json) => engine_from_json(json, emergency),
        None => Ok(CedarAuthorizationEngine::new("", emergency)?),
    }
}
