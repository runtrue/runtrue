/// Every path is explicit. No registry, package manager, or network fallback
/// is consulted when a lease references a component.
#[derive(Debug, Clone)]
pub struct WasmRuntimePaths {
    pub component_directory: PathBuf,
    pub manifest_directory: PathBuf,
    pub keyring_directory: PathBuf,
    pub aot_cache: PathBuf,
    /// A mode-0600 file containing 64 raw bytes (or 128 hex characters): the
    /// first half authenticates AOT entries and the second authenticates
    /// invocation-local capability handles.
    pub runtime_key: PathBuf,
}
use super::PathBuf;
