use crate::LeaseState;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("invalid runner inventory")]
    InvalidRunner,
    #[error("invalid queued job")]
    InvalidJob,
    #[error("invalid tenant quota")]
    InvalidQuota,
    #[error("runner `{0}` is unknown")]
    UnknownRunner(String),
    #[error("runner `{0}` is already registered")]
    DuplicateRunner(String),
    #[error("runner `{0}` is revoked")]
    RunnerRevoked(String),
    #[error("job `{0}` is unknown")]
    UnknownJob(String),
    #[error("job `{0}` is already queued or leased")]
    DuplicateJob(String),
    #[error("lease `{0}` is unknown")]
    UnknownLease(String),
    #[error("lease state mismatch: expected {expected:?}, found {actual:?}")]
    InvalidLeaseState {
        expected: LeaseState,
        actual: LeaseState,
    },
    #[error("lease is not active; current state is {0:?}")]
    LeaseNotActive(LeaseState),
    #[error("lease offer expired before it was accepted")]
    OfferExpired,
    #[error("lease belongs to a different runner")]
    WrongRunner,
    #[error("stale lease generation: expected {expected}, found {actual}")]
    StaleGeneration { expected: u64, actual: u64 },
    #[error("stale installation fencing epoch: expected {expected}, found {actual}")]
    StaleInstallationEpoch { expected: u64, actual: u64 },
    #[error("completion conflicts with the previously accepted terminal result")]
    ConflictingCompletion,
    #[error("installation fencing epoch must increase after restore")]
    EpochMustIncrease,
    #[error("lease fencing generation overflow")]
    GenerationOverflow,
    #[error("lease identifier overflow")]
    LeaseIdOverflow,
}
