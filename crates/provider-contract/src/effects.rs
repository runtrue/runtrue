use crate::{
    canonical::{
        canonical_digest, validate_collection_size, validate_identifier, validate_profile_name,
    },
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

const EFFECT_TRANSITION_DOMAIN: &[u8] = b"runtrue.provider.external-effect-transition.v1\0";
const EFFECT_RECONCILIATION_DOMAIN: &[u8] = b"runtrue.provider.external-effect-reconciliation.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalEffectState {
    Requested,
    Rejected,
    Accepted,
    Indeterminate,
}

impl ExternalEffectState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Requested)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectIdentity {
    pub operation_id: String,
    pub idempotency_key: String,
    pub tenant_id: String,
    pub execution_id: String,
    pub capsule_digest: ContentDigest,
    pub capability_grant_digest: ContentDigest,
    pub lease_id: String,
    pub fence_generation: u64,
    pub destination_digest: ContentDigest,
    pub bounded_request_digest: ContentDigest,
}

impl ExternalEffectIdentity {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        for (kind, value) in [
            ("external effect operation", self.operation_id.as_str()),
            (
                "external effect idempotency key",
                self.idempotency_key.as_str(),
            ),
            ("external effect tenant", self.tenant_id.as_str()),
            ("external effect Execution", self.execution_id.as_str()),
            ("external effect lease", self.lease_id.as_str()),
        ] {
            validate_identifier(kind, value)?;
        }
        if self.fence_generation == 0 {
            return Err(ProviderContractError::InvalidEffectTransition(
                "fence generation must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectTransition {
    pub transition_version: u32,
    pub identity: ExternalEffectIdentity,
    pub sequence: u32,
    pub previous_transition_digest: Option<ContentDigest>,
    pub state: ExternalEffectState,
    pub terminal_proof_digest: Option<ContentDigest>,
    pub producer_identity_digest: ContentDigest,
    pub observed_unix_ms: u64,
}

impl ExternalEffectTransition {
    pub fn requested(
        identity: ExternalEffectIdentity,
        producer_identity_digest: ContentDigest,
        observed_unix_ms: u64,
    ) -> Result<Self, ProviderContractError> {
        let transition = Self {
            transition_version: 1,
            identity,
            sequence: 1,
            previous_transition_digest: None,
            state: ExternalEffectState::Requested,
            terminal_proof_digest: None,
            producer_identity_digest,
            observed_unix_ms,
        };
        transition.validate()?;
        Ok(transition)
    }

    pub fn terminal(
        requested: &Self,
        state: ExternalEffectState,
        terminal_proof_digest: ContentDigest,
        producer_identity_digest: ContentDigest,
        observed_unix_ms: u64,
    ) -> Result<Self, ProviderContractError> {
        requested.validate()?;
        if requested.state != ExternalEffectState::Requested || !state.is_terminal() {
            return Err(ProviderContractError::InvalidEffectTransition(
                "terminal transition requires a requested predecessor",
            ));
        }
        let transition = Self {
            transition_version: 1,
            identity: requested.identity.clone(),
            sequence: 2,
            previous_transition_digest: Some(requested.digest()?),
            state,
            terminal_proof_digest: Some(terminal_proof_digest),
            producer_identity_digest,
            observed_unix_ms,
        };
        transition.validate()?;
        Ok(transition)
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.identity.validate()?;
        if self.transition_version != 1
            || !matches!(self.sequence, 1 | 2)
            || (self.sequence == 1) != self.previous_transition_digest.is_none()
            || (self.state == ExternalEffectState::Requested) != (self.sequence == 1)
            || self.state.is_terminal() != self.terminal_proof_digest.is_some()
        {
            return Err(ProviderContractError::InvalidEffectTransition(
                "invalid write-ahead or terminal transition shape",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(EFFECT_TRANSITION_DOMAIN, self)
    }
}

pub fn verify_external_effect_chain(
    transitions: &[ExternalEffectTransition],
) -> Result<(), ProviderContractError> {
    if transitions.is_empty() || transitions.len() > 2 {
        return Err(ProviderContractError::InvalidEffectTransition(
            "effect chain requires requested and at most one terminal transition",
        ));
    }
    validate_collection_size(transitions.len())?;
    let requested = &transitions[0];
    requested.validate()?;
    if requested.state != ExternalEffectState::Requested {
        return Err(ProviderContractError::InvalidEffectTransition(
            "first effect transition was not requested",
        ));
    }
    if let Some(terminal) = transitions.get(1) {
        terminal.validate()?;
        if terminal.identity != requested.identity
            || terminal.sequence != 2
            || terminal.previous_transition_digest.as_ref() != Some(&requested.digest()?)
        {
            return Err(ProviderContractError::InvalidEffectTransition(
                "terminal effect transition changed identity or linkage",
            ));
        }
    }
    Ok(())
}

/// Reconciliation does not rewrite an indeterminate terminal transition. It
/// appends a separate linked statement describing the authoritative result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectReconciliation {
    pub reconciliation_version: u32,
    pub indeterminate_transition_digest: ContentDigest,
    pub authoritative_state: ExternalEffectState,
    pub method: String,
    pub result_digest: ContentDigest,
    pub producer_identity_digest: ContentDigest,
    pub observed_unix_ms: u64,
}

impl ExternalEffectReconciliation {
    pub fn for_indeterminate(
        indeterminate: &ExternalEffectTransition,
        authoritative_state: ExternalEffectState,
        method: String,
        result_digest: ContentDigest,
        producer_identity_digest: ContentDigest,
        observed_unix_ms: u64,
    ) -> Result<Self, ProviderContractError> {
        indeterminate.validate()?;
        if indeterminate.state != ExternalEffectState::Indeterminate {
            return Err(ProviderContractError::InvalidEffectTransition(
                "reconciliation predecessor was not indeterminate",
            ));
        }
        let reconciliation = Self {
            reconciliation_version: 1,
            indeterminate_transition_digest: indeterminate.digest()?,
            authoritative_state,
            method,
            result_digest,
            producer_identity_digest,
            observed_unix_ms,
        };
        reconciliation.validate()?;
        Ok(reconciliation)
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.reconciliation_version != 1
            || !matches!(
                self.authoritative_state,
                ExternalEffectState::Accepted | ExternalEffectState::Rejected
            )
        {
            return Err(ProviderContractError::InvalidEffectTransition(
                "reconciliation must resolve to authoritative accepted or rejected",
            ));
        }
        validate_profile_name(&self.method)
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(EFFECT_RECONCILIATION_DOMAIN, self)
    }
}

pub trait ExternalEffectJournal {
    type Error;

    /// This append must commit before any request byte is transmitted.
    fn append_requested(
        &self,
        transition: &ExternalEffectTransition,
    ) -> Result<ExternalEffectTransition, Self::Error>;

    fn append_terminal(
        &self,
        expected_requested_digest: &ContentDigest,
        transition: &ExternalEffectTransition,
    ) -> Result<ExternalEffectTransition, Self::Error>;

    fn append_reconciliation(
        &self,
        reconciliation: &ExternalEffectReconciliation,
    ) -> Result<ExternalEffectReconciliation, Self::Error>;

    fn transitions(
        &self,
        operation_id: &str,
        maximum_transitions: usize,
    ) -> Result<Vec<ExternalEffectTransition>, Self::Error>;
}
