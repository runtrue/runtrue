use crate::AotCacheStatus;
use runtrue_engine::ExecutorOutput;
use runtrue_runtime_metrics::RuntimeMeasurement;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExecutionOutput {
    pub executor: ExecutorOutput,
    pub component_output: Option<String>,
    /// Host-generated runtime failure classification. This never contains
    /// guest output and remains safe to surface when credential-tainted guest
    /// streams are suppressed.
    pub runtime_diagnostic: Option<String>,
    pub aot_cache_status: AotCacheStatus,
    pub measurement: RuntimeMeasurement,
}
