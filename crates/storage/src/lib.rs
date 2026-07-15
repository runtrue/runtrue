//! Filesystem-backed immutable content storage and safe tree snapshots.
//!
//! Objects are addressed by their SHA-256 digest. New objects are written to a
//! private temporary file, synced, made read-only, and linked into their final
//! path without replacement. Reads always recompute the digest. Tree snapshots
//! contain only normalized relative paths, directories, and regular files;
//! symlinks and special files are deliberately outside the format.

mod blob;
mod cas;
mod error;
mod limits;
mod manifest;
mod secure_io;
mod snapshot;

pub use blob::{BlobRecord, CasObjectRecord, VerifiedBlobReader};
pub use cas::FsCas;
pub use error::StorageError;
pub use limits::CasLimits;
pub use manifest::{TreeEntry, TreeEntryKind, TreeManifest};
pub use snapshot::{PathSnapshot, TreeSnapshot};

pub(crate) use manifest::TREE_MANIFEST_VERSION;
pub(crate) const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests;
