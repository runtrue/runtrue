use crate::{validation::validate_identifier, NetworkError};
use runtrue_workflow_ir::NetworkProtocol;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkLimits {
    pub max_resolved_addresses: usize,
    pub maximum_dns_ttl_seconds: u64,
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self {
            max_resolved_addresses: 32,
            maximum_dns_ttl_seconds: 300,
        }
    }
}

impl NetworkLimits {
    pub(crate) fn validate(self) -> Result<Self, NetworkError> {
        if self.max_resolved_addresses == 0 || self.maximum_dns_ttl_seconds == 0 {
            return Err(NetworkError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseNetworkBinding {
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub step_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
}

impl LeaseNetworkBinding {
    pub(crate) fn validate(&self) -> Result<(), NetworkError> {
        for (kind, value) in [
            ("run id", self.run_id.as_str()),
            ("job id", self.job_id.as_str()),
            ("step id", self.step_id.as_str()),
            ("execution lease id", self.execution_lease_id.as_str()),
        ] {
            validate_identifier(kind, value)?;
        }
        if self.fencing_generation == 0 {
            return Err(NetworkError::InvalidFencingGeneration);
        }
        if self.job_attempt == 0 {
            return Err(NetworkError::InvalidJobAttempt);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub protocol: NetworkProtocol,
    /// Complete address set returned by the trusted host resolver.
    pub resolved_addresses: Vec<IpAddr>,
    pub dns_ttl_seconds: u64,
}
