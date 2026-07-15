use crate::{
    canonical::{canonical_digest, validate_identifier},
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc};

const RESERVATION_DOMAIN: &[u8] = b"runtrue.provider.capability-budget-reservation.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationSubject {
    pub tenant_id: String,
    pub program_digest: ContentDigest,
    pub capsule_digest: ContentDigest,
    pub execution_id: String,
    pub session_id: Option<String>,
    pub session_operation_id: Option<String>,
}

impl InvocationSubject {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Invocation tenant", &self.tenant_id)?;
        validate_identifier("Invocation Execution", &self.execution_id)?;
        if self.session_id.is_some() != self.session_operation_id.is_some() {
            return Err(ProviderContractError::InvalidInvocation(
                "Session and Session-operation identities must appear together",
            ));
        }
        if let Some(session_id) = &self.session_id {
            validate_identifier("Invocation Session", session_id)?;
        }
        if let Some(operation_id) = &self.session_operation_id {
            validate_identifier("Invocation Session operation", operation_id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationBudget {
    pub maximum_uses: u64,
    pub maximum_effect_bytes: u64,
}

impl InvocationBudget {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.maximum_uses == 0 {
            return Err(ProviderContractError::InvalidInvocation(
                "Invocation must permit at least one use",
            ));
        }
        Ok(())
    }
}

/// Process-local capability. It intentionally implements neither Clone nor
/// Serialize, and its marker makes it neither Send nor Sync. Only its explicit
/// reservation records are durable.
#[derive(Debug)]
pub struct InvocationHandle {
    invocation_id: String,
    subject: InvocationSubject,
    resource_identity_digest: ContentDigest,
    capability_grant_digest: ContentDigest,
    lease_id: String,
    fence_generation: u64,
    expires_unix_ms: u64,
    budget: InvocationBudget,
    _non_transferable: PhantomData<Rc<()>>,
}

impl InvocationHandle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invocation_id: String,
        subject: InvocationSubject,
        resource_identity_digest: ContentDigest,
        capability_grant_digest: ContentDigest,
        lease_id: String,
        fence_generation: u64,
        expires_unix_ms: u64,
        budget: InvocationBudget,
    ) -> Result<Self, ProviderContractError> {
        let handle = Self {
            invocation_id,
            subject,
            resource_identity_digest,
            capability_grant_digest,
            lease_id,
            fence_generation,
            expires_unix_ms,
            budget,
            _non_transferable: PhantomData,
        };
        handle.validate()?;
        Ok(handle)
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Invocation id", &self.invocation_id)?;
        self.subject.validate()?;
        validate_identifier("Invocation lease", &self.lease_id)?;
        self.budget.validate()?;
        if self.fence_generation == 0 || self.expires_unix_ms == 0 {
            return Err(ProviderContractError::InvalidInvocation(
                "fence generation and expiry must be positive",
            ));
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        expected_subject: &InvocationSubject,
        expected_resource_identity_digest: &ContentDigest,
        current_lease_id: &str,
        current_fence_generation: u64,
        now_unix_ms: u64,
    ) -> Result<(), ProviderContractError> {
        self.validate()?;
        expected_subject.validate()?;
        if &self.subject != expected_subject
            || &self.resource_identity_digest != expected_resource_identity_digest
            || self.lease_id != current_lease_id
            || self.fence_generation != current_fence_generation
            || now_unix_ms >= self.expires_unix_ms
        {
            return Err(ProviderContractError::InvalidInvocation(
                "Invocation is expired, stale, or bound to another subject/resource",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    #[must_use]
    pub const fn budget(&self) -> InvocationBudget {
        self.budget
    }

    #[must_use]
    pub fn capability_grant_digest(&self) -> &ContentDigest {
        &self.capability_grant_digest
    }

    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub const fn fence_generation(&self) -> u64 {
        self.fence_generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBudgetReservation {
    pub reservation_version: u32,
    pub invocation_id: String,
    pub capability_grant_digest: ContentDigest,
    pub lease_id: String,
    pub fence_generation: u64,
    pub sequence: u64,
    pub previous_reservation_digest: Option<ContentDigest>,
    pub effect_request_digest: ContentDigest,
    pub reserved_uses: u64,
    pub reserved_effect_bytes: u64,
    pub cumulative_uses: u64,
    pub cumulative_effect_bytes: u64,
}

impl CapabilityBudgetReservation {
    pub fn reserve(
        handle: &InvocationHandle,
        previous: Option<&Self>,
        effect_request_digest: ContentDigest,
        uses: u64,
        effect_bytes: u64,
    ) -> Result<Self, ProviderContractError> {
        handle.validate()?;
        if uses == 0 {
            return Err(ProviderContractError::InvalidInvocation(
                "budget reservation must consume a use",
            ));
        }
        if let Some(previous) = previous {
            previous.validate_against(handle)?;
        }
        let prior_uses = previous.map_or(0, |record| record.cumulative_uses);
        let prior_bytes = previous.map_or(0, |record| record.cumulative_effect_bytes);
        let cumulative_uses =
            prior_uses
                .checked_add(uses)
                .ok_or(ProviderContractError::InvalidInvocation(
                    "use budget overflow",
                ))?;
        let cumulative_effect_bytes = prior_bytes.checked_add(effect_bytes).ok_or(
            ProviderContractError::InvalidInvocation("effect-byte budget overflow"),
        )?;
        if cumulative_uses > handle.budget.maximum_uses
            || cumulative_effect_bytes > handle.budget.maximum_effect_bytes
        {
            return Err(ProviderContractError::InvalidInvocation(
                "Invocation capability budget exceeded",
            ));
        }
        let record = Self {
            reservation_version: 1,
            invocation_id: handle.invocation_id.clone(),
            capability_grant_digest: handle.capability_grant_digest.clone(),
            lease_id: handle.lease_id.clone(),
            fence_generation: handle.fence_generation,
            sequence: previous.map_or(1, |record| record.sequence.saturating_add(1)),
            previous_reservation_digest: previous.map(Self::digest).transpose()?,
            effect_request_digest,
            reserved_uses: uses,
            reserved_effect_bytes: effect_bytes,
            cumulative_uses,
            cumulative_effect_bytes,
        };
        record.validate_against(handle)?;
        Ok(record)
    }

    pub fn validate_against(&self, handle: &InvocationHandle) -> Result<(), ProviderContractError> {
        if self.reservation_version != 1
            || self.invocation_id != handle.invocation_id
            || self.capability_grant_digest != handle.capability_grant_digest
            || self.lease_id != handle.lease_id
            || self.fence_generation != handle.fence_generation
            || self.sequence == 0
            || (self.sequence == 1) != self.previous_reservation_digest.is_none()
            || self.reserved_uses == 0
            || self.cumulative_uses > handle.budget.maximum_uses
            || self.cumulative_effect_bytes > handle.budget.maximum_effect_bytes
        {
            return Err(ProviderContractError::InvalidInvocation(
                "budget reservation is malformed or belongs to another Invocation",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        if self.reservation_version != 1 || self.sequence == 0 {
            return Err(ProviderContractError::InvalidInvocation(
                "cannot digest malformed budget reservation",
            ));
        }
        canonical_digest(RESERVATION_DOMAIN, self)
    }
}

pub trait CapabilityBudgetLedger {
    type Error;

    /// Atomically compares the previous digest and appends the reservation.
    fn reserve(
        &self,
        expected_previous: Option<&ContentDigest>,
        reservation: &CapabilityBudgetReservation,
    ) -> Result<CapabilityBudgetReservation, Self::Error>;
}
