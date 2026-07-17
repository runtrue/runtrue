use crate::{host::HostLimits, WasmError};
use std::time::Duration;

const FUEL_BUDGET_QUANTUM: Duration = Duration::from_secs(60);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmLimits {
    pub max_component_bytes: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_log_bytes: usize,
    pub max_log_entry_bytes: usize,
    pub max_adapter_request_bytes: usize,
    pub max_adapter_response_bytes: usize,
    pub max_secret_bytes: usize,
    pub max_oidc_token_bytes: usize,
    pub max_memory_bytes: usize,
    pub max_table_elements: u32,
    pub max_instances: usize,
    pub max_tables: usize,
    pub max_memories: usize,
    pub max_wasm_stack_bytes: usize,
    /// Fuel granted for each started minute of the bounded step deadline.
    /// Short steps retain one quantum; longer steps receive a proportional
    /// budget while the wall-clock timeout remains authoritative.
    pub fuel: u64,
    pub max_timeout: Duration,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            max_component_bytes: 64 * 1024 * 1024,
            max_input_bytes: 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
            max_log_bytes: 4 * 1024 * 1024,
            max_log_entry_bytes: 64 * 1024,
            max_adapter_request_bytes: 4 * 1024 * 1024,
            max_adapter_response_bytes: 16 * 1024 * 1024,
            max_secret_bytes: 1024 * 1024,
            max_oidc_token_bytes: 64 * 1024,
            max_memory_bytes: 256 * 1024 * 1024,
            max_table_elements: 100_000,
            max_instances: 128,
            max_tables: 128,
            max_memories: 128,
            max_wasm_stack_bytes: 2 * 1024 * 1024,
            fuel: 100_000_000,
            max_timeout: Duration::from_secs(60 * 60),
        }
    }
}

impl WasmLimits {
    pub(crate) fn validate(self) -> Result<Self, WasmError> {
        if self.max_component_bytes == 0
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_log_bytes == 0
            || self.max_log_entry_bytes == 0
            || self.max_adapter_request_bytes == 0
            || self.max_adapter_response_bytes == 0
            || self.max_secret_bytes == 0
            || self.max_oidc_token_bytes == 0
            || self.max_memory_bytes == 0
            || self.max_table_elements == 0
            || self.max_instances == 0
            || self.max_tables == 0
            || self.max_memories == 0
            || self.max_wasm_stack_bytes == 0
            || self.fuel == 0
            || self.max_timeout.is_zero()
            || self.max_log_entry_bytes > self.max_log_bytes
        {
            return Err(WasmError::InvalidConfiguration(
                "all Wasm limits must be positive and internally consistent".to_owned(),
            ));
        }
        Ok(self)
    }

    pub(crate) fn host_limits(self) -> HostLimits {
        HostLimits {
            max_output_bytes: self.max_output_bytes,
            max_log_bytes: self.max_log_bytes,
            max_log_entry_bytes: self.max_log_entry_bytes,
            max_adapter_request_bytes: self.max_adapter_request_bytes,
            max_adapter_response_bytes: self.max_adapter_response_bytes,
            max_secret_bytes: self.max_secret_bytes,
            max_oidc_token_bytes: self.max_oidc_token_bytes,
        }
    }

    pub(crate) fn fuel_for_timeout(self, timeout: Duration) -> u64 {
        let quantum_millis = FUEL_BUDGET_QUANTUM.as_millis();
        let timeout_millis = timeout.as_millis();
        let quanta =
            timeout_millis.saturating_add(quantum_millis.saturating_sub(1)) / quantum_millis;
        let quanta = u64::try_from(quanta.max(1)).unwrap_or(u64::MAX);
        self.fuel.saturating_mul(quanta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuel_budget_scales_with_the_bounded_step_deadline() {
        let limits = WasmLimits::default();
        assert_eq!(limits.fuel_for_timeout(Duration::from_secs(1)), limits.fuel);
        assert_eq!(
            limits.fuel_for_timeout(Duration::from_secs(15 * 60)),
            15 * limits.fuel
        );
    }

    #[test]
    fn fuel_budget_saturates_instead_of_wrapping() {
        let limits = WasmLimits {
            fuel: u64::MAX,
            ..WasmLimits::default()
        };
        assert_eq!(
            limits.fuel_for_timeout(Duration::from_secs(2 * 60)),
            u64::MAX
        );
    }
}
