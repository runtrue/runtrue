use super::RunnerServiceError;
use crate::runner_certificates::{
    DEFAULT_RUNNER_CERTIFICATE_OVERLAP, DEFAULT_RUNNER_ROTATION_NOTICE,
};
use runtrue_protocol::{supports_protocol_version, PROTOCOL_MIN};
use std::time::Duration;
#[derive(Debug, Clone)]
pub struct RunnerControlConfig {
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub lease_extension: Duration,
    pub drain_grace_period: Duration,
    pub stream_send_timeout: Duration,
    pub certificate_overlap: Duration,
    pub certificate_rotation_notice: Duration,
    /// Oldest runner protocol generation admitted for enrollment and Open.
    pub protocol_minimum: u32,
}

impl Default for RunnerControlConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(5),
            heartbeat_timeout: Duration::from_secs(20),
            lease_extension: Duration::from_secs(60),
            drain_grace_period: Duration::from_secs(30),
            stream_send_timeout: Duration::from_secs(2),
            certificate_overlap: DEFAULT_RUNNER_CERTIFICATE_OVERLAP,
            certificate_rotation_notice: DEFAULT_RUNNER_ROTATION_NOTICE,
            protocol_minimum: PROTOCOL_MIN,
        }
    }
}

impl RunnerControlConfig {
    pub(super) fn validate(&self) -> Result<(), RunnerServiceError> {
        if self.heartbeat_interval < Duration::from_millis(100)
            || self.heartbeat_interval > Duration::from_secs(5 * 60)
            || self.heartbeat_timeout <= self.heartbeat_interval
            || self.lease_extension <= self.heartbeat_timeout
            || self.drain_grace_period.is_zero()
            || self.stream_send_timeout.is_zero()
            || self.certificate_overlap.is_zero()
            || self.certificate_rotation_notice <= self.certificate_overlap
            || !supports_protocol_version(self.protocol_minimum)
        {
            return Err(RunnerServiceError::InvalidConfiguration);
        }
        Ok(())
    }
}
