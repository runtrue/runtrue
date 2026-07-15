use crate::{canonical, validation, ContentDigest, ExecutionModelError, SessionCapsule};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SESSION_RESERVATION_SCHEMA_VERSION: u32 = 1;

/// Aggregate resources reserved for one child. Capability and external-effect
/// accounting is explicit so recursive planners cannot bypass a sealed budget
/// by splitting work into many small children.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildResourceReservation {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    pub task_count: u64,
    pub capability_calls: u64,
    pub capability_request_bytes: u64,
    pub capability_response_bytes: u64,
    pub external_effect_count: u64,
}

impl ChildResourceReservation {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        if self.cpu_millis == 0
            || self.memory_bytes == 0
            || self.storage_bytes == 0
            || self.task_count == 0
        {
            return Err(ExecutionModelError::InvalidField {
                field: "child resource reservation",
                reason: "compute reservations must be greater than zero",
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn contains(&self, child: &Self) -> bool {
        child.cpu_millis <= self.cpu_millis
            && child.memory_bytes <= self.memory_bytes
            && child.storage_bytes <= self.storage_bytes
            && child.task_count <= self.task_count
            && child.capability_calls <= self.capability_calls
            && child.capability_request_bytes <= self.capability_request_bytes
            && child.capability_response_bytes <= self.capability_response_bytes
            && child.external_effect_count <= self.external_effect_count
    }

    fn checked_add(self, other: Self) -> Result<Self, ExecutionModelError> {
        Ok(Self {
            cpu_millis: self
                .cpu_millis
                .checked_add(other.cpu_millis)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            memory_bytes: self
                .memory_bytes
                .checked_add(other.memory_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            storage_bytes: self
                .storage_bytes
                .checked_add(other.storage_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            task_count: self
                .task_count
                .checked_add(other.task_count)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            capability_calls: self
                .capability_calls
                .checked_add(other.capability_calls)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            capability_request_bytes: self
                .capability_request_bytes
                .checked_add(other.capability_request_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            capability_response_bytes: self
                .capability_response_bytes
                .checked_add(other.capability_response_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            external_effect_count: self
                .external_effect_count
                .checked_add(other.external_effect_count)
                .ok_or(ExecutionModelError::AccountingFailure)?,
        })
    }

    fn checked_sub(self, other: Self) -> Result<Self, ExecutionModelError> {
        Ok(Self {
            cpu_millis: self
                .cpu_millis
                .checked_sub(other.cpu_millis)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            memory_bytes: self
                .memory_bytes
                .checked_sub(other.memory_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            storage_bytes: self
                .storage_bytes
                .checked_sub(other.storage_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            task_count: self
                .task_count
                .checked_sub(other.task_count)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            capability_calls: self
                .capability_calls
                .checked_sub(other.capability_calls)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            capability_request_bytes: self
                .capability_request_bytes
                .checked_sub(other.capability_request_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            capability_response_bytes: self
                .capability_response_bytes
                .checked_sub(other.capability_response_bytes)
                .ok_or(ExecutionModelError::AccountingFailure)?,
            external_effect_count: self
                .external_effect_count
                .checked_sub(other.external_effect_count)
                .ok_or(ExecutionModelError::AccountingFailure)?,
        })
    }

    pub fn from_session(session: &SessionCapsule) -> Self {
        let budget = &session.capabilities.aggregate_budget;
        Self {
            cpu_millis: u64::from(session.maximum_resources.cpu_millis),
            memory_bytes: session.maximum_resources.memory_bytes,
            storage_bytes: session.maximum_resources.storage_bytes,
            task_count: u64::from(session.maximum_resources.task_count),
            capability_calls: budget.maximum_calls,
            capability_request_bytes: budget.maximum_request_bytes,
            capability_response_bytes: budget.maximum_response_bytes,
            external_effect_count: budget.maximum_external_effects,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildReservationRequest {
    pub schema_version: u32,
    pub reservation_id: String,
    pub session_id: String,
    pub session_capsule_digest: ContentDigest,
    pub child_execution_id: String,
    pub child_capsule_digest: ContentDigest,
    pub idempotency_key: String,
    pub session_fence: u64,
    pub resources: ChildResourceReservation,
    pub created_unix_ms: u64,
}

impl ChildReservationRequest {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "child reservation schema version",
            self.schema_version,
            SESSION_RESERVATION_SCHEMA_VERSION,
        )?;
        validation::identifier("reservation identity", &self.reservation_id)?;
        validation::identifier("Session identity", &self.session_id)?;
        validation::identifier("child Execution identity", &self.child_execution_id)?;
        validation::identifier("reservation idempotency key", &self.idempotency_key)?;
        if self.session_fence == 0 || self.created_unix_ms == 0 {
            return Err(ExecutionModelError::InvalidField {
                field: "reservation fence or creation time",
                reason: "must be greater than zero",
            });
        }
        self.resources.validate()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservationState {
    Reserved,
    Released,
    Finalized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservationTerminalOutcome {
    Released { reason_digest: ContentDigest },
    Finalized { result_digest: ContentDigest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationTransitionRequest {
    pub schema_version: u32,
    pub reservation_id: String,
    pub child_execution_id: String,
    pub idempotency_key: String,
    pub session_fence: u64,
    pub outcome: ReservationTerminalOutcome,
    pub observed_unix_ms: u64,
}

impl ReservationTransitionRequest {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "reservation transition schema version",
            self.schema_version,
            SESSION_RESERVATION_SCHEMA_VERSION,
        )?;
        validation::identifier("reservation identity", &self.reservation_id)?;
        validation::identifier("child Execution identity", &self.child_execution_id)?;
        validation::identifier("transition idempotency key", &self.idempotency_key)?;
        if self.session_fence == 0 || self.observed_unix_ms == 0 {
            return Err(ExecutionModelError::InvalidField {
                field: "transition fence or observation time",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildReservationRecord {
    pub request: ChildReservationRequest,
    pub request_digest: ContentDigest,
    pub generation: u64,
    pub state: ReservationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_request_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_request: Option<ReservationTransitionRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_outcome: Option<ReservationTerminalOutcome>,
}

impl ChildReservationRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        canonical::canonical_bytes(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationResult {
    pub record: ChildReservationRecord,
    pub replayed: bool,
}

/// Serializable state machine suitable for placement behind a transactional
/// store. Each method either commits all accounting changes or none of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionReservationLedger {
    pub session_id: String,
    pub session_capsule_digest: ContentDigest,
    pub session_fence: u64,
    pub limits: ChildResourceReservation,
    pub allocated: ChildResourceReservation,
    pub maximum_concurrency: u32,
    pub maximum_child_count: u32,
    pub active_concurrency: u32,
    pub admitted_child_count: u32,
    pub next_generation: u64,
    reservations: BTreeMap<String, ChildReservationRecord>,
    child_reservations: BTreeMap<String, String>,
    reserve_idempotency: BTreeMap<String, String>,
    transition_idempotency: BTreeMap<String, (String, ContentDigest)>,
}

impl SessionReservationLedger {
    pub fn new(
        session_id: String,
        session: &SessionCapsule,
        session_fence: u64,
    ) -> Result<Self, ExecutionModelError> {
        validation::identifier("Session identity", &session_id)?;
        session.validate()?;
        if session_fence == 0 {
            return Err(ExecutionModelError::StaleSessionFence);
        }
        Ok(Self {
            session_id,
            session_capsule_digest: session.digest()?,
            session_fence,
            limits: ChildResourceReservation::from_session(session),
            allocated: ChildResourceReservation::default(),
            maximum_concurrency: session.maximum_concurrency,
            maximum_child_count: session.maximum_child_count,
            active_concurrency: 0,
            admitted_child_count: 0,
            next_generation: 1,
            reservations: BTreeMap::new(),
            child_reservations: BTreeMap::new(),
            reserve_idempotency: BTreeMap::new(),
            transition_idempotency: BTreeMap::new(),
        })
    }

    pub fn reserve(
        &mut self,
        request: ChildReservationRequest,
    ) -> Result<ReservationResult, ExecutionModelError> {
        self.validate()?;
        let mut staged = self.clone();
        let result = staged.reserve_staged(request)?;
        staged.validate()?;
        *self = staged;
        Ok(result)
    }

    fn reserve_staged(
        &mut self,
        request: ChildReservationRequest,
    ) -> Result<ReservationResult, ExecutionModelError> {
        request.validate()?;
        let request_digest = request.digest()?;
        if let Some(reservation_id) = self.reserve_idempotency.get(&request.idempotency_key) {
            let record = self
                .reservations
                .get(reservation_id)
                .ok_or(ExecutionModelError::AccountingFailure)?;
            if record.request_digest == request_digest {
                return Ok(ReservationResult {
                    record: record.clone(),
                    replayed: true,
                });
            }
            return Err(ExecutionModelError::IdempotencyConflict);
        }
        if request.session_fence != self.session_fence {
            return Err(ExecutionModelError::StaleSessionFence);
        }
        if request.session_id != self.session_id
            || request.session_capsule_digest != self.session_capsule_digest
            || self.reservations.contains_key(&request.reservation_id)
            || self
                .child_reservations
                .contains_key(&request.child_execution_id)
        {
            return Err(ExecutionModelError::ReservationIdentityConflict);
        }
        let allocated = self.allocated.checked_add(request.resources)?;
        if !self.limits.contains(&allocated)
            || self.active_concurrency >= self.maximum_concurrency
            || self.admitted_child_count >= self.maximum_child_count
        {
            return Err(ExecutionModelError::ReservationCapacityUnavailable);
        }
        let generation = self.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(ExecutionModelError::AccountingFailure)?;
        let next_active = self
            .active_concurrency
            .checked_add(1)
            .ok_or(ExecutionModelError::AccountingFailure)?;
        let next_admitted = self
            .admitted_child_count
            .checked_add(1)
            .ok_or(ExecutionModelError::AccountingFailure)?;
        let record = ChildReservationRecord {
            request: request.clone(),
            request_digest,
            generation,
            state: ReservationState::Reserved,
            terminal_request_digest: None,
            terminal_request: None,
            terminal_outcome: None,
        };
        self.allocated = allocated;
        self.active_concurrency = next_active;
        self.admitted_child_count = next_admitted;
        self.next_generation = next_generation;
        self.child_reservations.insert(
            request.child_execution_id.clone(),
            request.reservation_id.clone(),
        );
        self.reserve_idempotency.insert(
            request.idempotency_key.clone(),
            request.reservation_id.clone(),
        );
        self.reservations
            .insert(request.reservation_id, record.clone());
        Ok(ReservationResult {
            record,
            replayed: false,
        })
    }

    pub fn transition(
        &mut self,
        request: ReservationTransitionRequest,
    ) -> Result<ReservationResult, ExecutionModelError> {
        self.validate()?;
        let mut staged = self.clone();
        let result = staged.transition_staged(request)?;
        staged.validate()?;
        *self = staged;
        Ok(result)
    }

    fn transition_staged(
        &mut self,
        request: ReservationTransitionRequest,
    ) -> Result<ReservationResult, ExecutionModelError> {
        request.validate()?;
        let request_digest = request.digest()?;
        if let Some((reservation_id, prior_digest)) =
            self.transition_idempotency.get(&request.idempotency_key)
        {
            if prior_digest != &request_digest {
                return Err(ExecutionModelError::IdempotencyConflict);
            }
            let record = self
                .reservations
                .get(reservation_id)
                .ok_or(ExecutionModelError::AccountingFailure)?;
            return Ok(ReservationResult {
                record: record.clone(),
                replayed: true,
            });
        }
        if request.session_fence != self.session_fence {
            return Err(ExecutionModelError::StaleSessionFence);
        }
        let record = self
            .reservations
            .get(&request.reservation_id)
            .ok_or(ExecutionModelError::ReservationNotFound)?;
        if record.request.child_execution_id != request.child_execution_id {
            return Err(ExecutionModelError::ReservationIdentityConflict);
        }
        if record.state != ReservationState::Reserved {
            return Err(ExecutionModelError::InvalidReservationTransition);
        }
        let allocated = self.allocated.checked_sub(record.request.resources)?;
        let active = self
            .active_concurrency
            .checked_sub(1)
            .ok_or(ExecutionModelError::AccountingFailure)?;
        let state = match request.outcome {
            ReservationTerminalOutcome::Released { .. } => ReservationState::Released,
            ReservationTerminalOutcome::Finalized { .. } => ReservationState::Finalized,
        };
        let record = self
            .reservations
            .get_mut(&request.reservation_id)
            .ok_or(ExecutionModelError::AccountingFailure)?;
        record.state = state;
        record.terminal_request_digest = Some(request_digest.clone());
        record.terminal_request = Some(request.clone());
        record.terminal_outcome = Some(request.outcome.clone());
        let result = record.clone();
        self.allocated = allocated;
        self.active_concurrency = active;
        self.transition_idempotency.insert(
            request.idempotency_key,
            (request.reservation_id, request_digest),
        );
        Ok(ReservationResult {
            record: result,
            replayed: false,
        })
    }

    #[must_use]
    pub fn reservation(&self, reservation_id: &str) -> Option<&ChildReservationRecord> {
        self.reservations.get(reservation_id)
    }

    /// Reconstruct every derived counter and index from canonical records.
    /// Callers must invoke this after deserializing durable state and before
    /// accepting it as an accounting authority.
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::identifier("Session identity", &self.session_id)?;
        self.limits.validate()?;
        if self.session_fence == 0
            || self.maximum_concurrency == 0
            || self.maximum_child_count == 0
            || self.maximum_concurrency > self.maximum_child_count
        {
            return Err(ExecutionModelError::AccountingFailure);
        }
        let mut reconstructed = ChildResourceReservation::default();
        let mut active = 0_u32;
        let mut max_generation = 0_u64;
        let mut terminal_count = 0_usize;
        let mut generations = std::collections::BTreeSet::new();
        for (reservation_id, record) in &self.reservations {
            record.request.validate()?;
            if reservation_id != &record.request.reservation_id
                || record.request_digest != record.request.digest()?
                || record.request.session_id != self.session_id
                || record.request.session_capsule_digest != self.session_capsule_digest
                || record.request.session_fence != self.session_fence
                || record.generation == 0
                || !generations.insert(record.generation)
                || self
                    .child_reservations
                    .get(&record.request.child_execution_id)
                    != Some(reservation_id)
                || self
                    .reserve_idempotency
                    .get(&record.request.idempotency_key)
                    != Some(reservation_id)
            {
                return Err(ExecutionModelError::AccountingFailure);
            }
            max_generation = max_generation.max(record.generation);
            match record.state {
                ReservationState::Reserved => {
                    if record.terminal_request_digest.is_some()
                        || record.terminal_request.is_some()
                        || record.terminal_outcome.is_some()
                    {
                        return Err(ExecutionModelError::AccountingFailure);
                    }
                    reconstructed = reconstructed.checked_add(record.request.resources)?;
                    active = active
                        .checked_add(1)
                        .ok_or(ExecutionModelError::AccountingFailure)?;
                }
                ReservationState::Released | ReservationState::Finalized => {
                    terminal_count += 1;
                    let terminal = record
                        .terminal_request
                        .as_ref()
                        .ok_or(ExecutionModelError::AccountingFailure)?;
                    let terminal_digest = terminal.digest()?;
                    let expected_state = match terminal.outcome {
                        ReservationTerminalOutcome::Released { .. } => ReservationState::Released,
                        ReservationTerminalOutcome::Finalized { .. } => ReservationState::Finalized,
                    };
                    if terminal.reservation_id != *reservation_id
                        || terminal.child_execution_id != record.request.child_execution_id
                        || terminal.session_fence != self.session_fence
                        || record.terminal_request_digest.as_ref() != Some(&terminal_digest)
                        || record.terminal_outcome.as_ref() != Some(&terminal.outcome)
                        || record.state != expected_state
                        || self.transition_idempotency.get(&terminal.idempotency_key)
                            != Some(&(reservation_id.clone(), terminal_digest))
                    {
                        return Err(ExecutionModelError::AccountingFailure);
                    }
                }
            }
        }
        let admitted = u32::try_from(self.reservations.len())
            .map_err(|_| ExecutionModelError::AccountingFailure)?;
        let expected_next = max_generation
            .checked_add(1)
            .ok_or(ExecutionModelError::AccountingFailure)?;
        if self.child_reservations.len() != self.reservations.len()
            || self.reserve_idempotency.len() != self.reservations.len()
            || self.transition_idempotency.len() != terminal_count
            || self.allocated != reconstructed
            || !self.limits.contains(&self.allocated)
            || self.active_concurrency != active
            || self.active_concurrency > self.maximum_concurrency
            || self.admitted_child_count != admitted
            || self.admitted_child_count > self.maximum_child_count
            || self.next_generation != expected_next
        {
            return Err(ExecutionModelError::AccountingFailure);
        }
        Ok(())
    }
}
