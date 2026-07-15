use crate::AotCacheStatus;
use runtrue_engine::ExecutorOutput;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExecutionOutput {
    pub executor: ExecutorOutput,
    pub component_output: Option<String>,
    pub aot_cache_status: AotCacheStatus,
}
