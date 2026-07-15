//! Fail-closed runner daemon orchestration and live gRPC transport.

mod broker;
mod credentials;
mod daemon;
mod data_plane;
mod enrollment;
mod firecracker;
mod inventory;
mod oci;
mod state;
mod transport;
mod wasm;

pub use broker::{BrokerExecutionBinding, RunnerBrokerClient};
pub use credentials::{
    CredentialError, LoadedRunnerCredentials, NewRunnerCredentials, RunnerCredentialStore,
};
pub use daemon::{
    NativeJobExecutor, RemoteJobExecutor, RunMode, RunnerDaemon, RunnerDaemonConfig, RunnerError,
};
pub use enrollment::{enroll_runner, enroll_runner_from_token_file, EnrollmentError};
pub use firecracker::{FirecrackerJobExecutor, FirecrackerRuntimePaths};
pub use inventory::{
    apply_authoritative_posture, load_capsule_trust_store, probe_inventory,
    probe_inventory_with_backends, probe_inventory_with_backends_for_protocol, InventoryError,
    TrustedCapsuleKeys, VerifiedInventory,
};
pub use oci::{OciJobExecutor, OciRuntimePaths};
pub use state::{PersistentRunnerState, RunnerStateStore, StateError, WorkspaceManager};
pub use transport::{
    EndpointSecurity, EnrollmentEndpointSecurity, RunnerTransport, TonicRunnerTransport,
    TransportError,
};
pub use wasm::{WasmJobExecutor, WasmRuntimePaths};
