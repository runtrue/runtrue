//! Metadata directory layout and path validation for [`CacheStore`].

impl CacheStore {
    pub(super) fn ensure_layout(&self) -> Result<(), CacheError> {
        let heads = self.root.join("heads");
        ensure_directory(&heads)?;
        ensure_directory(&heads.join("sha256"))?;
        let tickets = self.root.join("tickets");
        ensure_directory(&tickets)?;
        ensure_directory(&tickets.join("sha256"))
    }

    pub(super) fn ticket_directory_path(
        &self,
        ticket_id: &ContentDigest,
    ) -> Result<PathBuf, CacheError> {
        let encoded = digest_hex(ticket_id)?;
        let algorithm = self.root.join("tickets/sha256");
        ensure_directory(&algorithm)?;
        let prefix = algorithm.join(&encoded[..2]);
        ensure_directory(&prefix)?;
        Ok(prefix.join(&encoded[2..]))
    }

    pub(super) fn ticket_directory(
        &self,
        ticket_id: &ContentDigest,
    ) -> Result<PathBuf, CacheError> {
        let directory = self.ticket_directory_path(ticket_id)?;
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|source| io_failure("inspect cache ticket directory", &directory, source))?;
        require_directory(&directory, &metadata)?;
        Ok(directory)
    }

    pub(super) fn head_directory(&self, digest: &ContentDigest) -> Result<PathBuf, CacheError> {
        let encoded = digest_hex(digest)?;
        let algorithm = self.root.join("heads").join("sha256");
        ensure_directory(&algorithm)?;
        let prefix = algorithm.join(&encoded[..2]);
        ensure_directory(&prefix)?;
        let identity = prefix.join(&encoded[2..]);
        ensure_directory(&identity)?;
        Ok(identity)
    }
}
use crate::{digest_hex, ensure_directory, io_failure, require_directory, CacheError, CacheStore};
use runtrue_model::ContentDigest;
use std::{fs, path::PathBuf};
