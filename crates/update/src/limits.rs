pub const UPDATE_SCHEMA_VERSION: u32 = 1;
pub const UPDATE_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TARGET_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_TARGETS: usize = 4_096;
pub const MAX_ROOT_KEYS: usize = 64;
pub const MAX_SIGNATURES: usize = 64;
pub const MAX_CUSTOM_FIELDS: usize = 64;
pub const MAX_ROOT_ROTATIONS: usize = 32;
pub const MAX_STRING_BYTES: usize = 1_024;
pub const MAX_TRUST_STATE_BYTES: usize = 8 * 1024 * 1024;

pub(crate) const SIGNATURE_DOMAIN: &[u8] = b"runtrue.update.metadata.signature.v1\0";
const DAY_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const ROOT_MAX_LIFETIME: u64 = 10 * 365 * DAY_SECONDS;
pub(crate) const TARGETS_MAX_LIFETIME: u64 = 366 * DAY_SECONDS;
pub(crate) const SNAPSHOT_MAX_LIFETIME: u64 = 90 * DAY_SECONDS;
pub(crate) const TIMESTAMP_MAX_LIFETIME: u64 = 14 * DAY_SECONDS;
