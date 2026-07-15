#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OciLimits {
    pub max_mounts: usize,
    pub max_mount_entries: usize,
    pub max_environment_variables: usize,
    pub max_environment_name_bytes: usize,
    pub max_environment_value_bytes: usize,
    pub max_environment_bytes: usize,
    pub max_arguments: usize,
    pub max_argument_bytes: usize,
    pub max_output_bytes: usize,
    pub max_timeout: Duration,
    pub max_pids: u32,
    pub tmpfs_bytes: u64,
    pub max_services: usize,
    pub max_service_health_retries: u32,
    pub max_service_startup_timeout: Duration,
}

impl Default for OciLimits {
    fn default() -> Self {
        Self {
            max_mounts: 32,
            max_mount_entries: 100_000,
            max_environment_variables: 1024,
            max_environment_name_bytes: 256,
            max_environment_value_bytes: 64 * 1024,
            max_environment_bytes: 1024 * 1024,
            max_arguments: 4096,
            max_argument_bytes: 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
            max_timeout: Duration::from_secs(24 * 60 * 60),
            max_pids: 1024,
            tmpfs_bytes: 256 * 1024 * 1024,
            max_services: 16,
            max_service_health_retries: 100,
            max_service_startup_timeout: DEFAULT_SERVICE_STARTUP_TIMEOUT,
        }
    }
}

impl OciLimits {
    pub(crate) fn validate(self) -> Result<Self, OciError> {
        if self.max_mounts == 0
            || self.max_mount_entries == 0
            || self.max_environment_variables == 0
            || self.max_environment_name_bytes == 0
            || self.max_environment_value_bytes == 0
            || self.max_environment_bytes == 0
            || self.max_arguments == 0
            || self.max_argument_bytes == 0
            || self.max_output_bytes == 0
            || self.max_timeout.is_zero()
            || self.max_pids == 0
            || self.tmpfs_bytes == 0
            || self.max_services == 0
            || self.max_service_health_retries == 0
            || self.max_service_startup_timeout.is_zero()
            || self.max_service_startup_timeout > self.max_timeout
        {
            return Err(OciError::InvalidConfiguration(
                "OCI limits must all be non-zero".to_owned(),
            ));
        }
        Ok(self)
    }
}
use crate::{Duration, OciError, DEFAULT_SERVICE_STARTUP_TIMEOUT};
