use crate::{
    canonical::{canonical_digest, validate_identifier},
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, marker::PhantomData, rc::Rc};

const RESERVATION_DOMAIN: &[u8] = b"runtrue.provider.capability-budget-reservation.v1\0";
const GRANT_DOMAIN: &[u8] = b"runtrue.provider.capability-grant.v1\0";
const COMPLETION_DOMAIN: &[u8] = b"runtrue.provider.capability-budget-completion.v1\0";

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
    pub maximum_external_effects: u64,
    pub maximum_effect_bytes: u64,
}

impl InvocationBudget {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.maximum_uses == 0 || self.maximum_external_effects > self.maximum_uses {
            return Err(ProviderContractError::InvalidInvocation(
                "Invocation must permit at least one use",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationCapabilityGrant {
    pub grant_version: u32,
    pub grant_id: String,
    pub sealed_capability_grant_digest: ContentDigest,
    pub subject: InvocationSubject,
    pub resource_identity_digest: ContentDigest,
    pub capability_type: String,
    pub external_effect_class: Option<String>,
    pub permitted_operations: BTreeSet<String>,
    pub permitted_destination_digests: BTreeSet<ContentDigest>,
    pub request_contract_digest: ContentDigest,
    pub response_contract_digest: ContentDigest,
    pub lease_id: String,
    pub fence_generation: u64,
    pub revocation_generation: u64,
    pub not_before_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub maximum_concurrency: u32,
    pub maximum_request_bytes: u64,
    pub maximum_response_bytes: u64,
    pub rate_window_milliseconds: u64,
    pub maximum_uses_per_window: u64,
    pub budget: InvocationBudget,
}

impl InvocationCapabilityGrant {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        use crate::canonical::validate_profile_name;

        if self.grant_version != 1 {
            return Err(ProviderContractError::InvalidInvocation(
                "unsupported capability grant version",
            ));
        }
        validate_identifier("Capability grant id", &self.grant_id)?;
        validate_profile_name(&self.capability_type)?;
        if let Some(effect_class) = &self.external_effect_class {
            validate_profile_name(effect_class)?;
        }
        self.subject.validate()?;
        validate_identifier("Capability grant lease", &self.lease_id)?;
        self.budget.validate()?;
        if self.permitted_operations.is_empty()
            || self.permitted_destination_digests.is_empty()
            || self.fence_generation == 0
            || self.revocation_generation == 0
            || self.not_before_unix_ms >= self.expires_unix_ms
            || self.maximum_concurrency == 0
            || self.maximum_request_bytes == 0
            || self.maximum_response_bytes == 0
            || self.rate_window_milliseconds == 0
            || self.maximum_uses_per_window == 0
            || self.budget.maximum_external_effects > self.budget.maximum_uses
        {
            return Err(ProviderContractError::InvalidInvocation(
                "capability grant has an empty authority set or invalid bound",
            ));
        }
        for operation in &self.permitted_operations {
            validate_profile_name(operation)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(GRANT_DOMAIN, self)
    }

    /// Proves that this invocation-local grant only narrows the exact grant
    /// sealed into the Capsule. Destination strings have one Provider-neutral
    /// identity: SHA-256 over their UTF-8 canonical spelling.
    pub fn validate_against_sealed(
        &self,
        sealed: &runtrue_execution::CapabilityGrant,
    ) -> Result<(), ProviderContractError> {
        self.validate()?;
        sealed.validate().map_err(|_| {
            ProviderContractError::InvalidInvocation("sealed capability grant is invalid")
        })?;
        let sealed_digest = sealed.digest().map_err(|_| {
            ProviderContractError::InvalidInvocation("sealed capability grant digest failed")
        })?;
        let sealed_destinations = sealed
            .destinations
            .iter()
            .map(|destination| ContentDigest::sha256(destination.as_bytes()))
            .collect::<BTreeSet<_>>();
        let maximum_effect_bytes = sealed
            .budget
            .maximum_request_bytes
            .saturating_add(sealed.budget.maximum_response_bytes);
        if self.sealed_capability_grant_digest != sealed_digest
            || self.capability_type != sealed.class
            || self.external_effect_class != sealed.external_effect_class
            || self.resource_identity_digest != ContentDigest::sha256(sealed.resource.as_bytes())
            || !self.permitted_operations.is_subset(&sealed.operations)
            || !self
                .permitted_destination_digests
                .is_subset(&sealed_destinations)
            || self.maximum_request_bytes > sealed.budget.maximum_request_bytes
            || self.maximum_response_bytes > sealed.budget.maximum_response_bytes
            || self.request_contract_digest != sealed.constraints_digest
            || self.response_contract_digest != sealed.constraints_digest
            || self.budget.maximum_uses > sealed.budget.maximum_calls
            || self.budget.maximum_external_effects > sealed.budget.maximum_external_effects
            || self.budget.maximum_effect_bytes > maximum_effect_bytes
        {
            return Err(ProviderContractError::InvalidInvocation(
                "invocation capability expands or substitutes sealed Capsule authority",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCallAuthorization<'a> {
    pub subject: &'a InvocationSubject,
    pub resource_identity_digest: &'a ContentDigest,
    pub capability_grant_digest: &'a ContentDigest,
    pub lease_id: &'a str,
    pub fence_generation: u64,
    pub current_revocation_generation: u64,
    pub operation: &'a str,
    pub destination_digest: &'a ContentDigest,
    pub request_bytes: u64,
    pub maximum_response_bytes: u64,
    pub current_concurrency: u32,
    pub rate_window_started_unix_ms: u64,
    pub uses_in_current_rate_window: u64,
    pub now_unix_ms: u64,
    pub call_deadline_unix_ms: u64,
    pub canceled: bool,
    pub external_effecting: bool,
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
    grant: InvocationCapabilityGrant,
    _non_transferable: PhantomData<Rc<()>>,
}

impl InvocationHandle {
    pub fn new(
        invocation_id: String,
        grant: InvocationCapabilityGrant,
        sealed_grant: &runtrue_execution::CapabilityGrant,
        issued_unix_ms: u64,
    ) -> Result<Self, ProviderContractError> {
        grant.validate_against_sealed(sealed_grant)?;
        if issued_unix_ms < grant.not_before_unix_ms || issued_unix_ms >= grant.expires_unix_ms {
            return Err(ProviderContractError::InvalidInvocation(
                "Invocation was issued outside the capability grant lifetime",
            ));
        }
        let handle = Self {
            invocation_id,
            subject: grant.subject.clone(),
            resource_identity_digest: grant.resource_identity_digest.clone(),
            capability_grant_digest: grant.digest()?,
            lease_id: grant.lease_id.clone(),
            fence_generation: grant.fence_generation,
            expires_unix_ms: grant.expires_unix_ms,
            budget: grant.budget,
            grant,
            _non_transferable: PhantomData,
        };
        handle.validate()?;
        Ok(handle)
    }

    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Invocation id", &self.invocation_id)?;
        self.subject.validate()?;
        validate_identifier("Invocation lease", &self.lease_id)?;
        self.grant.validate()?;
        self.budget.validate()?;
        if self.fence_generation == 0 || self.expires_unix_ms == 0 {
            return Err(ProviderContractError::InvalidInvocation(
                "fence generation and expiry must be positive",
            ));
        }
        Ok(())
    }

    pub fn authorize_call(
        &self,
        call: &CapabilityCallAuthorization<'_>,
    ) -> Result<(), ProviderContractError> {
        self.authorize(
            call.subject,
            call.resource_identity_digest,
            call.lease_id,
            call.fence_generation,
            call.now_unix_ms,
        )?;
        let valid = call.capability_grant_digest == &self.capability_grant_digest
            && call.current_revocation_generation == self.grant.revocation_generation
            && self.grant.permitted_operations.contains(call.operation)
            && self
                .grant
                .permitted_destination_digests
                .contains(call.destination_digest)
            && call.request_bytes <= self.grant.maximum_request_bytes
            && call.maximum_response_bytes <= self.grant.maximum_response_bytes
            && call.current_concurrency < self.grant.maximum_concurrency
            && call.rate_window_started_unix_ms <= call.now_unix_ms
            && call.now_unix_ms >= self.grant.not_before_unix_ms
            && call
                .now_unix_ms
                .saturating_sub(call.rate_window_started_unix_ms)
                < self.grant.rate_window_milliseconds
            && call.uses_in_current_rate_window < self.grant.maximum_uses_per_window
            && !call.canceled
            && call.now_unix_ms < call.call_deadline_unix_ms
            && call.call_deadline_unix_ms <= self.expires_unix_ms;
        let valid = valid && call.external_effecting == self.grant.external_effect_class.is_some();
        if !valid {
            return Err(ProviderContractError::InvalidInvocation(
                "Invocation call violates operation, destination, budget, cancellation, deadline, revocation, or fence authority",
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
pub struct CapabilityBudgetCompletion {
    pub completion_version: u32,
    pub reservation_digest: ContentDigest,
    pub actual_effect_bytes: u64,
    pub unused_effect_bytes_released: u64,
    pub response_digest: ContentDigest,
    pub completed: bool,
}

impl CapabilityBudgetCompletion {
    pub fn reconcile(
        reservation: &CapabilityBudgetReservation,
        actual_effect_bytes: u64,
        response_digest: ContentDigest,
        completed: bool,
    ) -> Result<Self, ProviderContractError> {
        if actual_effect_bytes > reservation.reserved_effect_bytes {
            return Err(ProviderContractError::InvalidInvocation(
                "actual capability use exceeded its reservation",
            ));
        }
        let unused_effect_bytes_released = if completed {
            reservation.reserved_effect_bytes - actual_effect_bytes
        } else {
            0
        };
        Ok(Self {
            completion_version: 1,
            reservation_digest: reservation.digest()?,
            actual_effect_bytes,
            unused_effect_bytes_released,
            response_digest,
            completed,
        })
    }

    pub fn validate_against(
        &self,
        reservation: &CapabilityBudgetReservation,
    ) -> Result<(), ProviderContractError> {
        let expected_release = if self.completed {
            reservation
                .reserved_effect_bytes
                .checked_sub(self.actual_effect_bytes)
                .ok_or(ProviderContractError::InvalidInvocation(
                    "actual capability use exceeded its reservation",
                ))?
        } else {
            0
        };
        if self.completion_version != 1
            || self.reservation_digest != reservation.digest()?
            || self.actual_effect_bytes > reservation.reserved_effect_bytes
            || self.unused_effect_bytes_released != expected_release
        {
            return Err(ProviderContractError::InvalidInvocation(
                "capability completion does not exactly reconcile its reservation",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        if self.completion_version != 1
            || (!self.completed && self.unused_effect_bytes_released != 0)
        {
            return Err(ProviderContractError::InvalidInvocation(
                "invalid capability completion reconciliation",
            ));
        }
        canonical_digest(COMPLETION_DOMAIN, self)
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
    pub operation: String,
    pub destination_digest: ContentDigest,
    pub reserved_concurrency: u32,
    pub reserved_request_bytes: u64,
    pub reserved_response_bytes: u64,
    pub rate_window_started_unix_ms: u64,
    pub reserved_rate_uses: u64,
    pub call_deadline_unix_ms: u64,
    pub reserved_uses: u64,
    pub reserved_external_effects: u64,
    pub reserved_effect_bytes: u64,
    pub cumulative_uses: u64,
    pub cumulative_external_effects: u64,
    pub cumulative_effect_bytes: u64,
}

impl CapabilityBudgetReservation {
    pub fn reserve_call(
        handle: &InvocationHandle,
        previous: Option<&Self>,
        call: &CapabilityCallAuthorization<'_>,
        effect_request_digest: ContentDigest,
    ) -> Result<Self, ProviderContractError> {
        handle.authorize_call(call)?;
        if let Some(previous) = previous {
            previous.validate_against(handle)?;
        }
        let uses = 1;
        let external_effects = u64::from(handle.grant.external_effect_class.is_some());
        let effect_bytes = call
            .request_bytes
            .checked_add(call.maximum_response_bytes)
            .ok_or(ProviderContractError::InvalidInvocation(
                "capability request/response byte reservation overflow",
            ))?;
        let prior_uses = previous.map_or(0, |record| record.cumulative_uses);
        let prior_bytes = previous.map_or(0, |record| record.cumulative_effect_bytes);
        let prior_external_effects =
            previous.map_or(0, |record| record.cumulative_external_effects);
        let cumulative_uses =
            prior_uses
                .checked_add(uses)
                .ok_or(ProviderContractError::InvalidInvocation(
                    "use budget overflow",
                ))?;
        let cumulative_effect_bytes = prior_bytes.checked_add(effect_bytes).ok_or(
            ProviderContractError::InvalidInvocation("effect-byte budget overflow"),
        )?;
        let cumulative_external_effects =
            prior_external_effects.checked_add(external_effects).ok_or(
                ProviderContractError::InvalidInvocation("external-effect use budget overflow"),
            )?;
        if cumulative_uses > handle.budget.maximum_uses
            || cumulative_external_effects > handle.budget.maximum_external_effects
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
            operation: call.operation.to_owned(),
            destination_digest: call.destination_digest.clone(),
            reserved_concurrency: 1,
            reserved_request_bytes: call.request_bytes,
            reserved_response_bytes: call.maximum_response_bytes,
            rate_window_started_unix_ms: call.rate_window_started_unix_ms,
            reserved_rate_uses: 1,
            call_deadline_unix_ms: call.call_deadline_unix_ms,
            reserved_uses: uses,
            reserved_external_effects: external_effects,
            reserved_effect_bytes: effect_bytes,
            cumulative_uses,
            cumulative_external_effects,
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
            || self.reserved_external_effects
                != u64::from(handle.grant.external_effect_class.is_some())
            || !handle.grant.permitted_operations.contains(&self.operation)
            || !handle
                .grant
                .permitted_destination_digests
                .contains(&self.destination_digest)
            || self.reserved_concurrency == 0
            || self.reserved_concurrency > handle.grant.maximum_concurrency
            || self.reserved_request_bytes > handle.grant.maximum_request_bytes
            || self.reserved_response_bytes > handle.grant.maximum_response_bytes
            || self.reserved_rate_uses == 0
            || self.reserved_rate_uses > handle.grant.maximum_uses_per_window
            || self.call_deadline_unix_ms <= self.rate_window_started_unix_ms
            || self.call_deadline_unix_ms > handle.expires_unix_ms
            || self.reserved_effect_bytes
                != self
                    .reserved_request_bytes
                    .saturating_add(self.reserved_response_bytes)
            || self.cumulative_uses > handle.budget.maximum_uses
            || self.cumulative_external_effects < self.reserved_external_effects
            || self.cumulative_external_effects > handle.budget.maximum_external_effects
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
