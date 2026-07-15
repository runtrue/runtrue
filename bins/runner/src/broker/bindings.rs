use crate::transport::TransportError;
use runtrue_executor_wasm::{CapabilityAdapterError, CapabilityCallContext};
use runtrue_runner_core::AdmittedLease;
use std::{thread, time::Duration};

const MAX_BROKER_ATTEMPTS: usize = 5;
const MAX_BROKER_RPC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerExecutionBinding {
    pub(super) execution_lease_id: String,
    pub(super) fencing_generation: u64,
    pub(super) installation_fencing_epoch: u64,
    pub(super) execution_hard_deadline_unix_ms: u64,
    pub(super) job_id: String,
}

impl BrokerExecutionBinding {
    #[must_use]
    pub fn from_lease(lease: &AdmittedLease) -> Self {
        Self {
            execution_lease_id: lease.lease_id.clone(),
            fencing_generation: lease.fencing_generation,
            installation_fencing_epoch: lease.installation_fencing_epoch,
            execution_hard_deadline_unix_ms: lease.hard_deadline_unix_ms,
            job_id: lease.job_id.clone(),
        }
    }
}

pub(super) fn exact_step_binding<'a>(
    context: &'a CapabilityCallContext,
    binding: &BrokerExecutionBinding,
) -> Result<(&'a str, u32, &'a str), CapabilityAdapterError> {
    let job_id = context.job_id().ok_or_else(|| {
        CapabilityAdapterError::Denied("capability call has no job binding".to_owned())
    })?;
    let step_id = context.step_id().ok_or_else(|| {
        CapabilityAdapterError::Denied("capability call has no step binding".to_owned())
    })?;
    let job_attempt = context
        .job_attempt()
        .filter(|attempt| *attempt > 0)
        .ok_or_else(|| {
            CapabilityAdapterError::Denied(
                "capability call has no valid job attempt binding".to_owned(),
            )
        })?;
    if job_id != binding.job_id {
        return Err(CapabilityAdapterError::Denied(
            "capability call job binding does not match the lease".to_owned(),
        ));
    }
    Ok((job_id, job_attempt, step_id))
}

pub(super) fn call_after_running<T>(
    context: &CapabilityCallContext,
    mut operation: impl FnMut() -> Result<T, TransportError>,
) -> Result<T, CapabilityAdapterError> {
    for attempt in 0..MAX_BROKER_ATTEMPTS {
        context.check()?;
        match operation() {
            Ok(value) => return Ok(value),
            Err(error)
                if error.is_running_step_not_observed()
                    && attempt.saturating_add(1) < MAX_BROKER_ATTEMPTS =>
            {
                let shift = u32::try_from(attempt).unwrap_or(u32::MAX).min(4);
                let delay = Duration::from_millis(10_u64.saturating_mul(1_u64 << shift));
                if context.remaining() <= delay {
                    return Err(CapabilityAdapterError::DeadlineExceeded);
                }
                thread::sleep(delay);
            }
            Err(error) => return Err(capability_transport_error(error)),
        }
    }
    Err(CapabilityAdapterError::Failed(
        "broker retry bound exhausted".to_owned(),
    ))
}

pub(super) fn rpc_timeout(remaining: Duration) -> Duration {
    remaining
        .min(MAX_BROKER_RPC_TIMEOUT)
        .max(Duration::from_millis(1))
}

pub(super) fn capability_transport_error(error: TransportError) -> CapabilityAdapterError {
    CapabilityAdapterError::Failed(error.to_string())
}
