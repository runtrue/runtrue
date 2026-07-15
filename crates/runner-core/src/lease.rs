use crate::{validation::validate_identifier, LeaseCompletion, RunnerAdmissionError};
use runtrue_attest::CapsuleSignature;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::ExecutionCapsule;

#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedLease {
    pub lease_id: String,
    pub job_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub issued_unix_ms: u64,
    pub accept_by_unix_ms: u64,
    /// Initial rolling soft lease expiry used by the server's heartbeat fence.
    pub expires_unix_ms: u64,
    /// Immutable local execution and guest-session deadline. For an old v1
    /// server that omits field 14, this conservatively equals `expires_at`.
    pub hard_deadline_unix_ms: u64,
    pub capsule_digest: ContentDigest,
    pub signing_key_id: ContentDigest,
    /// The exact signature envelope already verified during admission. The
    /// microVM host forwards this unchanged so the guest independently admits
    /// the same canonical capsule; it must never be reconstructed from labels.
    pub capsule_signature: CapsuleSignature,
    pub capsule: ExecutionCapsule,
}

impl AdmittedLease {
    #[must_use]
    pub fn into_guard(self) -> LeaseExecutionGuard {
        LeaseExecutionGuard {
            lease_id: self.lease_id,
            fencing_generation: self.fencing_generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            hard_deadline_unix_ms: self.hard_deadline_unix_ms,
            state: LeaseExecutionState::Accepted,
            completion: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseExecutionState {
    Accepted,
    Running,
    Completed,
    Canceled,
}

/// Stateful fence checked by secret/cache/artifact/completion adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseExecutionGuard {
    lease_id: String,
    fencing_generation: u64,
    installation_fencing_epoch: u64,
    hard_deadline_unix_ms: u64,
    state: LeaseExecutionState,
    completion: Option<LeaseCompletion>,
}

impl LeaseExecutionGuard {
    #[must_use]
    pub const fn state(&self) -> LeaseExecutionState {
        self.state
    }

    pub fn start(
        &mut self,
        lease_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
    ) -> Result<(), RunnerAdmissionError> {
        self.authorize_identity(
            lease_id,
            fencing_generation,
            installation_fencing_epoch,
            now_unix_ms,
        )?;
        if self.state != LeaseExecutionState::Accepted {
            return Err(RunnerAdmissionError::InvalidLeaseState);
        }
        self.state = LeaseExecutionState::Running;
        Ok(())
    }

    /// Authorize a step-scoped broker or publication operation.
    pub fn authorize_active(
        &self,
        lease_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
    ) -> Result<(), RunnerAdmissionError> {
        self.authorize_identity(
            lease_id,
            fencing_generation,
            installation_fencing_epoch,
            now_unix_ms,
        )?;
        if self.state != LeaseExecutionState::Running {
            return Err(RunnerAdmissionError::InvalidLeaseState);
        }
        Ok(())
    }

    pub fn complete(
        &mut self,
        lease_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
        completion: LeaseCompletion,
    ) -> Result<bool, RunnerAdmissionError> {
        self.authorize_identity(
            lease_id,
            fencing_generation,
            installation_fencing_epoch,
            now_unix_ms,
        )?;
        validate_identifier("final lease state", &completion.final_state)?;
        if self.state == LeaseExecutionState::Completed {
            return if self.completion.as_ref() == Some(&completion) {
                Ok(false)
            } else {
                Err(RunnerAdmissionError::ConflictingCompletion)
            };
        }
        if self.state != LeaseExecutionState::Running {
            return Err(RunnerAdmissionError::InvalidLeaseState);
        }
        self.completion = Some(completion);
        self.state = LeaseExecutionState::Completed;
        Ok(true)
    }

    pub fn cancel(
        &mut self,
        lease_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
    ) -> Result<bool, RunnerAdmissionError> {
        self.authorize_identity(
            lease_id,
            fencing_generation,
            installation_fencing_epoch,
            now_unix_ms,
        )?;
        match self.state {
            LeaseExecutionState::Accepted | LeaseExecutionState::Running => {
                self.state = LeaseExecutionState::Canceled;
                Ok(true)
            }
            LeaseExecutionState::Canceled => Ok(false),
            LeaseExecutionState::Completed => Err(RunnerAdmissionError::InvalidLeaseState),
        }
    }

    fn authorize_identity(
        &self,
        lease_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        now_unix_ms: u64,
    ) -> Result<(), RunnerAdmissionError> {
        if lease_id != self.lease_id
            || fencing_generation != self.fencing_generation
            || installation_fencing_epoch != self.installation_fencing_epoch
        {
            return Err(RunnerAdmissionError::StaleLeaseFence);
        }
        if now_unix_ms >= self.hard_deadline_unix_ms {
            return Err(RunnerAdmissionError::LeaseExpired);
        }
        Ok(())
    }
}
