//! Trust-scoped immutable cache generations over [`runtrue_storage::FsCas`].
//!
//! The public surface remains at the crate root; implementation details are
//! grouped by their security and persistence responsibility.

mod access;
mod error;
mod identity;
mod key;
mod limits;
mod manifest;
mod promotion;
mod secure_io;
mod store;
mod ticket;

#[cfg(test)]
mod tests;

pub use access::*;
pub use error::CacheError;
pub use identity::*;
pub use key::*;
pub use limits::*;
pub use manifest::*;
pub use promotion::*;
pub use store::*;
pub use ticket::*;

pub(crate) const CACHE_MANIFEST_VERSION: u32 = 1;
pub(crate) const CACHE_HEAD_VERSION: u32 = 1;
pub(crate) const CACHE_TICKET_VERSION: u32 = 1;
pub(crate) const HEAD_GENERATION_WIDTH: usize = 20;

const fn default_job_attempt() -> u32 {
    1
}

pub(crate) use identity::validate_identifier;
pub(crate) use promotion::validate_promotion_evidence;
pub(crate) use secure_io::{
    append_metadata, digest_hex, ensure_directory, io_failure, read_small_regular_file,
    require_directory, reserve_temporary_file, storage_is_stored_corruption, sync_directory,
    write_temporary_metadata,
};
pub(crate) use ticket::{cache_ticket_subject_digest, validate_producer};
