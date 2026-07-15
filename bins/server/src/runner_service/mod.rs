#![allow(clippy::result_large_err)]
//! Enrolled-runner gRPC control service.
//!
//! TLS authenticates the leaf certificate, while this module resolves its DER
//! fingerprint through durable certificate, runner, pool, overlap, revocation,
//! and expiry state. Application messages then bind that identity to one live
//! connection and to durable lease, generation, installation-epoch, and capsule
//! records. A separate server-auth-only façade exposes only one-time enrollment.

use std::time::Duration;

const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_CONNECTIONS: usize = 4096;
const MAX_CONTROL_QUEUE: usize = 32;
const MAX_STREAM_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_CONTROL_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_INVENTORY_CAPABILITIES: usize = 256;
const MAX_INVENTORY_LABELS: usize = 256;
const MAX_ACTIVE_LEASES_PER_RUNNER: usize = 1;
const MAX_LOG_FRAMES_PER_BATCH: usize = 256;
const MAX_LOG_FRAME_BYTES: usize = 64 * 1024;
const MAX_BLOB_CHUNK_BYTES: usize = 256 * 1024;
const MAX_CONCURRENT_OBJECT_TRANSFERS: usize = 8;
const OBJECT_TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const OBJECT_TRANSFER_TOTAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SOURCE_TICKET_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_SOURCE_TICKET_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_LIST_ITEMS: usize = 256;
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const MAX_SECRET_LEASE_TTL_MS: u64 = 5 * 60 * 1000;

mod completion;
mod config;
mod control;
pub mod data_plane;
mod enrollment;
mod identity;
mod leases;
mod metrics;
mod session;
mod status;
mod validation;

pub use config::RunnerControlConfig;
pub use control::RunnerControlService;
pub use data_plane::RunnerDataPlane;
pub use enrollment::RunnerEnrollmentService;
pub use metrics::RunnerProtocolMetricsSnapshot;
pub use status::RunnerServiceError;

use completion::job_state_name;
use data_plane::artifacts::{artifact_classification_name, artifact_scan_state_name};
use data_plane::authorization::authorize_source_object;
use data_plane::storage::{
    cache_generation_id, data_status, issue_or_recover_artifact_ticket,
    issue_or_recover_cache_ticket, reserve_or_recover_storage,
};
use data_plane::uploads::RunnerUploadBinding;
use data_plane::wire::{parse_v2_digest, wire_v2_digest};
use enrollment::source_ticket_id;
use identity::{enrolled_runner_record, AuthenticatedIdentity, RunnerDataSubject};
use metrics::RunnerProtocolMetrics;
use session::{RunnerControlInner, RunnerSession, SessionState};
use status::{certificate_status, control_plane_status, enrollment_status};
use validation::{
    architecture_name, cache_read_policy, cache_source_trust, cache_write_policy, canonical_json,
    duration_millis, fetch_capsule_response, isolation_name, lease_offer, now_unix_ms,
    operating_system_name, optional_string, parse_guest_session_key, parse_isolation,
    proto_duration, proto_timestamp, require_session_lease, require_session_protocol,
    rotation_response, runner_upload_wait_until, timestamp_millis, validate_active_state,
    validate_bounded_identifiers, validate_bounded_text, validate_capsule_binding, validate_health,
    validate_identifier_status, validate_inventory, validate_locality, validate_observed_timestamp,
    validate_runner_message_identity,
};
#[cfg(test)]
#[derive(Debug, Clone)]
struct TestRunnerIdentity(String);

#[cfg(test)]
mod tests;
