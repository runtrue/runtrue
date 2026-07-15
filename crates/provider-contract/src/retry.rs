use crate::{
    canonical::{canonical_digest, validate_collection_size, validate_identifier},
    verify_external_effect_chain, ExternalEffectReconciliation, ExternalEffectState,
    ExternalEffectTransition, ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

const RETRY_DOMAIN: &[u8] = b"runtrue.provider.retry-authorization.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RetryEffectSafety {
    Mutation {
        destination_idempotency_contract_digest: Option<ContentDigest>,
        contract_verification_evidence_digest: Option<ContentDigest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryEffectProof {
    pub transitions: Vec<ExternalEffectTransition>,
    pub reconciliation: Option<ExternalEffectReconciliation>,
    pub admitted_effect_declaration_digest: ContentDigest,
    pub capability_grant_digest: ContentDigest,
    pub safety: RetryEffectSafety,
}

impl RetryEffectProof {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        verify_external_effect_chain(&self.transitions)?;
        let terminal =
            self.transitions
                .last()
                .ok_or(ProviderContractError::InvalidEffectTransition(
                    "retry proof has no effect history",
                ))?;
        if let Some(reconciliation) = &self.reconciliation {
            reconciliation.validate()?;
            if terminal.state != ExternalEffectState::Indeterminate
                || reconciliation.indeterminate_transition_digest != terminal.digest()?
            {
                return Err(ProviderContractError::InvalidEffectTransition(
                    "retry reconciliation does not resolve the indeterminate effect",
                ));
            }
        }
        if terminal.identity.capability_grant_digest != self.capability_grant_digest {
            return Err(ProviderContractError::InvalidEffectTransition(
                "retry proof belongs to another capability grant",
            ));
        }
        let RetryEffectSafety::Mutation {
            destination_idempotency_contract_digest,
            contract_verification_evidence_digest,
        } = &self.safety;
        if destination_idempotency_contract_digest.is_some()
            != contract_verification_evidence_digest.is_some()
        {
            return Err(ProviderContractError::InvalidEffectTransition(
                "idempotency assertion lacks authenticated verification Evidence",
            ));
        }
        Ok(())
    }

    fn permits_retry(&self) -> Result<bool, ProviderContractError> {
        self.validate()?;
        let terminal = self.transitions.last().expect("validated non-empty chain");
        if terminal.state == ExternalEffectState::Rejected {
            return Ok(true);
        }
        if terminal.state == ExternalEffectState::Requested {
            return Ok(false);
        }
        if terminal.state == ExternalEffectState::Accepted {
            return Ok(self.has_idempotency_proof());
        }
        let Some(reconciliation) = &self.reconciliation else {
            return Ok(false);
        };
        Ok(
            reconciliation.authoritative_state == ExternalEffectState::Rejected
                || self.has_idempotency_proof(),
        )
    }

    fn has_idempotency_proof(&self) -> bool {
        matches!(
            &self.safety,
            RetryEffectSafety::Mutation {
                destination_idempotency_contract_digest: Some(_),
                contract_verification_evidence_digest: Some(_),
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryAuthorization {
    pub authorization_version: u32,
    pub execution_id: String,
    pub retry_of_execution_id: String,
    pub retry_of_effect_frontier_digest: ContentDigest,
    pub effect_proof_digests: Vec<ContentDigest>,
    pub signed_evidence_event_digest: ContentDigest,
}

impl RetryAuthorization {
    pub fn decide(
        execution_id: String,
        retry_of_execution_id: String,
        effects: &[RetryEffectProof],
        signed_evidence_event_digest: ContentDigest,
    ) -> Result<Self, ProviderContractError> {
        validate_identifier("retry Execution", &execution_id)?;
        validate_identifier("retry predecessor Execution", &retry_of_execution_id)?;
        if execution_id == retry_of_execution_id {
            return Err(ProviderContractError::InvalidEffectTransition(
                "retry lineage must name a distinct Execution",
            ));
        }
        validate_collection_size(effects.len())?;
        let mut digests = Vec::with_capacity(effects.len());
        for proof in effects {
            if !proof.permits_retry()? {
                return Err(ProviderContractError::InvalidEffectTransition(
                    "effect journal does not prove retry safety",
                ));
            }
            digests.push(canonical_digest(
                b"runtrue.provider.retry-effect-proof.v1\0",
                proof,
            )?);
        }
        let retry_of_effect_frontier_digest =
            canonical_digest(b"runtrue.provider.retry-effect-frontier.v1\0", &digests)?;
        Ok(Self {
            authorization_version: 1,
            execution_id,
            retry_of_execution_id,
            retry_of_effect_frontier_digest,
            effect_proof_digests: digests,
            signed_evidence_event_digest,
        })
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        if self.authorization_version != 1 || self.execution_id == self.retry_of_execution_id {
            return Err(ProviderContractError::InvalidEffectTransition(
                "invalid retry authorization lineage",
            ));
        }
        canonical_digest(RETRY_DOMAIN, self)
    }
}
