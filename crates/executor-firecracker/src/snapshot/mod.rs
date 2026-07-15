mod api;
mod capsule;
mod request;
mod validation;
#[cfg(test)]
use api::MAX_API_RESPONSE_HEADER_BYTES;
pub use api::{SnapshotApi, UnixSnapshotApiClient};
pub use capsule::FirecrackerLaunchPlan;
pub use request::SnapshotLoadRequest;
#[cfg(test)]
use request::{IN_JAIL_SNAPSHOT_MEMORY, IN_JAIL_SNAPSHOT_STATE, IN_JAIL_VSOCK_SOCKET};
pub const IN_JAIL_API_SOCKET: &str = "/run/firecracker-api.sock";
#[cfg(test)]
mod tests;
