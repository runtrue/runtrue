//! Pull-based scheduling with security-first filters and fenced leases.
//!
//! Locality is considered only after platform, isolation, pool policy,
//! verified capabilities, resources, drain state, and tenant quotas pass.
//! Every state-changing runner operation validates both the lease generation
//! and installation fencing epoch.

mod error;
mod matching;
mod model;
mod quota;
mod resources;
mod scheduler;
mod validation;

pub use error::SchedulerError;
pub use model::{Lease, LeaseState, QueuedJob, RunnerRecord, RunnerStatus, SchedulingRequirements};
pub use quota::TenantQuota;
pub use scheduler::{
    Scheduler, DEFAULT_ACCEPT_WINDOW_MS, DEFAULT_LEASE_DURATION_MS, PRIORITY_AGING_INTERVAL_MS,
};

#[cfg(test)]
mod tests;
