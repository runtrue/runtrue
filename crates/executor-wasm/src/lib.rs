//! Embedded Wasmtime Component executor for the `runtrue:action/run@1.0.0`
//! contract.

mod authentication;
mod cache;
mod capabilities;
mod component;
mod config;
mod error;
mod executor;
mod host;
mod invocation;
mod limits;
#[cfg(target_os = "linux")]
mod rooted_fs;
mod target;
mod validation;
mod watchdog;

pub use authentication::HandleAuthenticationKey;
pub use component::WasmComponentArtifact;
pub use config::WasmExecutorConfig;
pub use error::WasmError;
pub(crate) use executor::expected_compatibility;
pub use executor::WasmExecutor;
pub use invocation::WasmExecutionOutput;
pub use limits::WasmLimits;
pub use target::WasmTarget;
pub(crate) use validation::{exact_reference_digest, validate_bounded_text};
wasmtime::component::bindgen!({
    path: "wit",
    world: "run",
});

pub use cache::{
    AotAuthenticationKey, AotCacheConfig, AotCacheError, AotCacheEvent, AotCacheEventKind,
    AotCacheKey, AotCacheStatus,
};
pub use host::{
    CapabilityAdapterError, CapabilityAdapters, CapabilityCallContext, DirectoryGrant,
    FilesystemAccess, FilesystemAdapter, NetworkAdapter, OidcAdapter, OidcToken, SecretAdapter,
    SecretValue,
};
#[cfg(target_os = "linux")]
pub use rooted_fs::RootedFilesystemAdapter;

/// Exact component world supported by this runtime generation.
pub const WIT_WORLD: &str = "runtrue:action/run@1.0.0";

/// Pinned Wasmtime runtime used to compile and execute components.
pub const WASMTIME_VERSION: &str = "36.0.12";

/// Source of the versioned host contract, embedded for admission and cache
/// key derivation.
pub const WIT_SOURCE: &str = include_str!("../wit/action.wit");

pub const COMPONENT_MEDIA_TYPE: &str = "application/wasm";
pub const COMPILER_SETTINGS: &str =
    "cranelift-speed-and-size;nan-canonicalization;memory-reservation=0;growth-reservation=0;no-threads;no-simd;fuel;epoch";
pub const SECURITY_MITIGATION_PROFILE: &str = "runtrue-wasm-deny-ambient-v1";
const MAX_RETAINED_AOT_CACHE_EVENTS: usize = 1_024;
const MAX_CAPABILITY_GRANTS: usize = 256;

#[cfg(test)]
mod tests;
