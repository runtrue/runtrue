use super::{
    canonical::{
        canonical_bytes, canonical_policy_json, cedar_source_from_canonical_json, domain_digest,
    },
    model::{
        ActivatePolicyBundle, ActivatedPolicyBundle, ActivePolicyBundleState, PolicyBundleDraft,
        PolicyBundleDraftStatus, BUNDLE_DIGEST_DOMAIN, MAX_CANONICAL_POLICY_BYTES,
    },
    validation::validate_identifier,
    ActivePolicyError,
};
use crate::{CedarAuthorizationEngine, DenyFirstPolicy};
use runtrue_model::ContentDigest;
use serde_json::Value;
impl PolicyBundleDraft {
    pub fn new(
        id: impl Into<String>,
        tenant_id: impl Into<String>,
        author_id: impl Into<String>,
        cedar_source: &str,
        created_unix_ms: u64,
    ) -> Result<Self, ActivePolicyError> {
        let id = id.into();
        let tenant_id = tenant_id.into();
        let author_id = author_id.into();
        validate_identifier("policy bundle draft id", &id)?;
        validate_identifier("policy tenant id", &tenant_id)?;
        validate_identifier("policy author id", &author_id)?;
        if cedar_source.trim().is_empty() || cedar_source.len() > MAX_CANONICAL_POLICY_BYTES {
            return Err(ActivePolicyError::InvalidPolicySource);
        }
        CedarAuthorizationEngine::new(cedar_source, DenyFirstPolicy::default())?;
        let canonical_policy_json = canonical_policy_json(cedar_source)?;
        let digest = domain_digest(BUNDLE_DIGEST_DOMAIN, canonical_policy_json.as_bytes());
        let draft = Self {
            id,
            tenant_id,
            author_id,
            canonical_policy_json,
            digest,
            created_unix_ms,
            status: PolicyBundleDraftStatus::Draft,
            simulation_digest: None,
            simulation_passed: false,
            activated_policy_epoch: None,
        };
        draft.verify()?;
        Ok(draft)
    }

    #[must_use]
    pub fn canonical_policy_json(&self) -> &str {
        &self.canonical_policy_json
    }

    pub fn verify(&self) -> Result<(), ActivePolicyError> {
        validate_identifier("policy bundle draft id", &self.id)?;
        validate_identifier("policy tenant id", &self.tenant_id)?;
        validate_identifier("policy author id", &self.author_id)?;
        if self.canonical_policy_json.is_empty()
            || self.canonical_policy_json.len() > MAX_CANONICAL_POLICY_BYTES
            || domain_digest(BUNDLE_DIGEST_DOMAIN, self.canonical_policy_json.as_bytes())
                != self.digest
        {
            return Err(ActivePolicyError::CorruptPolicyDraft);
        }
        let value: Value = serde_json::from_str(&self.canonical_policy_json)
            .map_err(|_| ActivePolicyError::CorruptPolicyDraft)?;
        if canonical_bytes(&value)? != self.canonical_policy_json.as_bytes() {
            return Err(ActivePolicyError::NonCanonicalPolicyDraft);
        }
        let source = cedar_source_from_canonical_json(&self.canonical_policy_json)?;
        CedarAuthorizationEngine::new(&source, DenyFirstPolicy::default())?;
        match self.status {
            PolicyBundleDraftStatus::Draft
                if self.simulation_digest.is_none()
                    && !self.simulation_passed
                    && self.activated_policy_epoch.is_none() => {}
            PolicyBundleDraftStatus::Simulated | PolicyBundleDraftStatus::Shadow
                if self.simulation_digest.is_some() && self.activated_policy_epoch.is_none() => {}
            PolicyBundleDraftStatus::Activated
                if self.simulation_digest.is_some()
                    && self.simulation_passed
                    && self.activated_policy_epoch.is_some() => {}
            PolicyBundleDraftStatus::Retired => {}
            _ => return Err(ActivePolicyError::CorruptPolicyDraft),
        }
        Ok(())
    }

    pub fn enter_shadow(
        &mut self,
        simulation_digest: &ContentDigest,
    ) -> Result<(), ActivePolicyError> {
        self.verify()?;
        if self.status != PolicyBundleDraftStatus::Simulated {
            return Err(ActivePolicyError::InvalidLifecycleTransition);
        }
        if self.simulation_digest.as_ref() != Some(simulation_digest) {
            return Err(ActivePolicyError::SimulationDigestMismatch);
        }
        self.status = PolicyBundleDraftStatus::Shadow;
        Ok(())
    }
}

impl ActivatedPolicyBundle {
    pub fn verify(&self) -> Result<(), ActivePolicyError> {
        for (name, value) in [
            ("active policy draft id", self.draft_id.as_str()),
            ("active policy tenant id", self.tenant_id.as_str()),
            ("active policy author id", self.author_id.as_str()),
            ("active policy approval id", self.approval_id.as_str()),
            ("active policy approver", self.approved_by.as_str()),
        ] {
            validate_identifier(name, value)?;
        }
        if self.policy_epoch == 0
            || self.author_id == self.approved_by
            || self.canonical_policy_json.is_empty()
            || self.canonical_policy_json.len() > MAX_CANONICAL_POLICY_BYTES
            || domain_digest(BUNDLE_DIGEST_DOMAIN, self.canonical_policy_json.as_bytes())
                != self.digest
        {
            return Err(ActivePolicyError::CorruptActivePolicyState);
        }
        let value: Value = serde_json::from_str(&self.canonical_policy_json)
            .map_err(|_| ActivePolicyError::CorruptActivePolicyState)?;
        if canonical_bytes(&value)? != self.canonical_policy_json.as_bytes() {
            return Err(ActivePolicyError::CorruptActivePolicyState);
        }
        let source = cedar_source_from_canonical_json(&self.canonical_policy_json)?;
        CedarAuthorizationEngine::new(&source, DenyFirstPolicy::default())?;
        Ok(())
    }
}

impl ActivePolicyBundleState {
    pub fn activate(
        &mut self,
        draft: &mut PolicyBundleDraft,
        activation: &ActivatePolicyBundle,
    ) -> Result<ActivatedPolicyBundle, ActivePolicyError> {
        self.ensure_draft_tenant(draft)?;
        if draft.status == PolicyBundleDraftStatus::Activated {
            return self.replay_activation(draft, activation);
        }
        if draft.status != PolicyBundleDraftStatus::Shadow || !draft.simulation_passed {
            return Err(ActivePolicyError::InvalidLifecycleTransition);
        }
        if activation.draft_digest != draft.digest
            || draft.simulation_digest.as_ref() != Some(&activation.simulation_digest)
        {
            return Err(ActivePolicyError::ActivationEvidenceMismatch);
        }
        validate_identifier("policy activation approval id", &activation.approval_id)?;
        validate_identifier("policy activation approver", &activation.approved_by)?;
        if activation.approved_by == draft.author_id {
            return Err(ActivePolicyError::SeparationOfDuties);
        }
        if activation.approved_unix_ms < draft.created_unix_ms {
            return Err(ActivePolicyError::InvalidActivationTime);
        }
        if activation.expected_policy_epoch != self.policy_epoch {
            return Err(ActivePolicyError::StalePolicyEpoch {
                expected: self.policy_epoch,
                actual: activation.expected_policy_epoch,
            });
        }
        let policy_epoch = self
            .policy_epoch
            .checked_add(1)
            .ok_or(ActivePolicyError::EpochExhausted)?;
        self.decision_cache_generation = self
            .decision_cache_generation
            .checked_add(1)
            .ok_or(ActivePolicyError::EpochExhausted)?;
        let active = ActivatedPolicyBundle {
            draft_id: draft.id.clone(),
            tenant_id: draft.tenant_id.clone(),
            author_id: draft.author_id.clone(),
            digest: draft.digest.clone(),
            canonical_policy_json: draft.canonical_policy_json.clone(),
            simulation_digest: activation.simulation_digest.clone(),
            approval_id: activation.approval_id.clone(),
            approved_by: activation.approved_by.clone(),
            policy_epoch,
            activated_unix_ms: activation.approved_unix_ms,
        };
        self.policy_epoch = policy_epoch;
        self.active = Some(active.clone());
        draft.status = PolicyBundleDraftStatus::Activated;
        draft.activated_policy_epoch = Some(policy_epoch);
        Ok(active)
    }

    /// Replace emergency denies and immediately advance the decision-cache
    fn replay_activation(
        &self,
        draft: &PolicyBundleDraft,
        activation: &ActivatePolicyBundle,
    ) -> Result<ActivatedPolicyBundle, ActivePolicyError> {
        let Some(active) = &self.active else {
            return Err(ActivePolicyError::ActivationEvidenceMismatch);
        };
        let expected_activated_epoch = activation
            .expected_policy_epoch
            .checked_add(1)
            .ok_or(ActivePolicyError::EpochExhausted)?;
        if active.draft_id == draft.id
            && active.digest == activation.draft_digest
            && active.simulation_digest == activation.simulation_digest
            && active.approval_id == activation.approval_id
            && active.approved_by == activation.approved_by
            && active.activated_unix_ms == activation.approved_unix_ms
            && active.policy_epoch == expected_activated_epoch
            && draft.activated_policy_epoch == Some(active.policy_epoch)
        {
            return Ok(active.clone());
        }
        Err(ActivePolicyError::ActivationEvidenceMismatch)
    }
}
