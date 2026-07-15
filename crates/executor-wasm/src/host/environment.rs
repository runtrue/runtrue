use super::CapabilityAdapterError;
use runtrue_engine::CancellationToken;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Debug, Clone)]
pub struct CapabilityCallContext {
    deadline: Instant,
    cancellation: CancellationToken,
    max_request_bytes: usize,
    max_response_bytes: usize,
    job_id: Option<Arc<str>>,
    step_id: Option<Arc<str>>,
    job_attempt: Option<u32>,
}

impl CapabilityCallContext {
    #[must_use]
    pub const fn new(
        deadline: Instant,
        cancellation: CancellationToken,
        max_request_bytes: usize,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            deadline,
            cancellation,
            max_request_bytes,
            max_response_bytes,
            job_id: None,
            step_id: None,
            job_attempt: None,
        }
    }

    #[must_use]
    pub fn with_step_binding(mut self, job_id: &str, job_attempt: u32, step_id: &str) -> Self {
        self.job_id = Some(Arc::from(job_id));
        self.step_id = Some(Arc::from(step_id));
        self.job_attempt = Some(job_attempt);
        self
    }

    #[must_use]
    pub fn job_id(&self) -> Option<&str> {
        self.job_id.as_deref()
    }

    #[must_use]
    pub fn step_id(&self) -> Option<&str> {
        self.step_id.as_deref()
    }

    #[must_use]
    pub const fn job_attempt(&self) -> Option<u32> {
        self.job_attempt
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    #[must_use]
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    #[must_use]
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub fn check(&self) -> Result<(), CapabilityAdapterError> {
        if self.is_cancelled() {
            Err(CapabilityAdapterError::Canceled)
        } else if self.remaining().is_zero() {
            Err(CapabilityAdapterError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}
