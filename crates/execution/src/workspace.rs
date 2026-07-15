use crate::ReservationState;
use crate::{canonical, validation, ContentDigest, ExecutionModelError, SessionReservationLedger};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const WORKSPACE_PUBLICATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceGeneration {
    pub generation: u64,
    pub state_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePublicationRequest {
    pub schema_version: u32,
    pub session_id: String,
    pub session_capsule_digest: ContentDigest,
    pub reservation_id: String,
    pub child_execution_id: String,
    pub input_generation: u64,
    pub input_workspace_digest: ContentDigest,
    pub output_workspace_digest: ContentDigest,
    pub output_manifest_digest: ContentDigest,
    pub idempotency_key: String,
    pub session_fence: u64,
    pub committed_unix_ms: u64,
}

impl WorkspacePublicationRequest {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "workspace publication schema version",
            self.schema_version,
            WORKSPACE_PUBLICATION_SCHEMA_VERSION,
        )?;
        validation::identifier("Session identity", &self.session_id)?;
        validation::identifier("reservation identity", &self.reservation_id)?;
        validation::identifier("child Execution identity", &self.child_execution_id)?;
        validation::identifier("publication idempotency key", &self.idempotency_key)?;
        if self.session_fence == 0 || self.committed_unix_ms == 0 {
            return Err(ExecutionModelError::InvalidField {
                field: "publication fence or commit time",
                reason: "must be greater than zero",
            });
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
pub struct WorkspacePublicationRecord {
    pub request: WorkspacePublicationRequest,
    pub request_digest: ContentDigest,
    pub reservation_id: String,
    pub child_execution_id: String,
    pub previous: WorkspaceGeneration,
    pub current: WorkspaceGeneration,
    pub output_manifest_digest: ContentDigest,
    pub committed_unix_ms: u64,
}

impl WorkspacePublicationRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        canonical::canonical_bytes(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePublicationResult {
    pub record: WorkspacePublicationRecord,
    pub replayed: bool,
}

/// Generation-fenced publication ledger. Durable callers should transact the
/// whole value (or enforce the same generation CAS) to preserve first-writer
/// wins across recursive workers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePublicationLedger {
    pub session_id: String,
    pub session_capsule_digest: ContentDigest,
    pub session_fence: u64,
    pub initial_workspace_digest: ContentDigest,
    pub current: WorkspaceGeneration,
    publications: BTreeMap<u64, WorkspacePublicationRecord>,
    idempotency: BTreeMap<String, (u64, ContentDigest)>,
    published_by_child: BTreeMap<String, u64>,
}

impl WorkspacePublicationLedger {
    pub fn new(
        session_id: String,
        session_capsule_digest: ContentDigest,
        session_fence: u64,
        initial_workspace_digest: ContentDigest,
    ) -> Result<Self, ExecutionModelError> {
        validation::identifier("Session identity", &session_id)?;
        if session_fence == 0 {
            return Err(ExecutionModelError::StaleSessionFence);
        }
        Ok(Self {
            session_id,
            session_capsule_digest,
            session_fence,
            initial_workspace_digest: initial_workspace_digest.clone(),
            current: WorkspaceGeneration {
                generation: 0,
                state_digest: initial_workspace_digest,
            },
            publications: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            published_by_child: BTreeMap::new(),
        })
    }

    pub fn publish(
        &mut self,
        request: WorkspacePublicationRequest,
        reservations: &SessionReservationLedger,
    ) -> Result<WorkspacePublicationResult, ExecutionModelError> {
        self.validate()?;
        reservations.validate()?;
        let mut staged = self.clone();
        let result = staged.publish_staged(request, reservations)?;
        staged.validate()?;
        *self = staged;
        Ok(result)
    }

    fn publish_staged(
        &mut self,
        request: WorkspacePublicationRequest,
        reservations: &SessionReservationLedger,
    ) -> Result<WorkspacePublicationResult, ExecutionModelError> {
        request.validate()?;
        let request_digest = request.digest()?;
        if let Some((generation, prior_digest)) = self.idempotency.get(&request.idempotency_key) {
            if prior_digest != &request_digest {
                return Err(ExecutionModelError::IdempotencyConflict);
            }
            let record = self
                .publications
                .get(generation)
                .ok_or(ExecutionModelError::AccountingFailure)?;
            return Ok(WorkspacePublicationResult {
                record: record.clone(),
                replayed: true,
            });
        }
        if request.session_fence != self.session_fence {
            return Err(ExecutionModelError::StaleSessionFence);
        }
        if request.session_id != self.session_id
            || request.session_capsule_digest != self.session_capsule_digest
        {
            return Err(ExecutionModelError::ReservationIdentityConflict);
        }
        let reservation = reservations
            .reservation(&request.reservation_id)
            .ok_or(ExecutionModelError::WorkspaceReservationInactive)?;
        if reservation.state != ReservationState::Reserved
            || reservation.request.reservation_id != request.reservation_id
            || reservation.request.child_execution_id != request.child_execution_id
            || reservation.request.session_id != request.session_id
            || reservation.request.session_capsule_digest != request.session_capsule_digest
        {
            return Err(ExecutionModelError::WorkspaceReservationInactive);
        }
        if self
            .published_by_child
            .contains_key(&request.child_execution_id)
            || request.input_generation != self.current.generation
            || request.input_workspace_digest != self.current.state_digest
        {
            return Err(ExecutionModelError::WorkspaceGenerationConflict);
        }
        let generation = self
            .current
            .generation
            .checked_add(1)
            .ok_or(ExecutionModelError::AccountingFailure)?;
        let previous = self.current.clone();
        let current = WorkspaceGeneration {
            generation,
            state_digest: request.output_workspace_digest.clone(),
        };
        let record = WorkspacePublicationRecord {
            request: request.clone(),
            request_digest: request_digest.clone(),
            reservation_id: request.reservation_id,
            child_execution_id: request.child_execution_id.clone(),
            previous,
            current: current.clone(),
            output_manifest_digest: request.output_manifest_digest,
            committed_unix_ms: request.committed_unix_ms,
        };
        self.current = current;
        self.idempotency
            .insert(request.idempotency_key, (generation, request_digest));
        self.published_by_child
            .insert(request.child_execution_id, generation);
        self.publications.insert(generation, record.clone());
        Ok(WorkspacePublicationResult {
            record,
            replayed: false,
        })
    }

    /// Reconstruct the generation chain and all indexes from publication
    /// records before trusting deserialized durable state.
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::identifier("Session identity", &self.session_id)?;
        if self.session_fence == 0
            || self.idempotency.len() != self.publications.len()
            || self.published_by_child.len() != self.publications.len()
        {
            return Err(ExecutionModelError::AccountingFailure);
        }
        let mut expected = WorkspaceGeneration {
            generation: 0,
            state_digest: self.initial_workspace_digest.clone(),
        };
        for (generation, record) in &self.publications {
            record.request.validate()?;
            let next_generation = expected
                .generation
                .checked_add(1)
                .ok_or(ExecutionModelError::AccountingFailure)?;
            if *generation != next_generation
                || record.request_digest != record.request.digest()?
                || record.request.session_id != self.session_id
                || record.request.session_capsule_digest != self.session_capsule_digest
                || record.request.session_fence != self.session_fence
                || record.request.reservation_id != record.reservation_id
                || record.request.child_execution_id != record.child_execution_id
                || record.request.input_generation != expected.generation
                || record.request.input_workspace_digest != expected.state_digest
                || record.request.output_workspace_digest != record.current.state_digest
                || record.request.output_manifest_digest != record.output_manifest_digest
                || record.request.committed_unix_ms != record.committed_unix_ms
                || record.previous != expected
                || record.current.generation != *generation
                || self.idempotency.get(&record.request.idempotency_key)
                    != Some(&(*generation, record.request_digest.clone()))
                || self.published_by_child.get(&record.child_execution_id) != Some(generation)
            {
                return Err(ExecutionModelError::AccountingFailure);
            }
            expected = record.current.clone();
        }
        if self.current != expected {
            return Err(ExecutionModelError::AccountingFailure);
        }
        Ok(())
    }
}
