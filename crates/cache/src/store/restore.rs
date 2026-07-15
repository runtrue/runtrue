use std::path::Path;

impl CacheStore {
    pub fn inspect(&self, identity: &CacheIdentity) -> Result<Option<CacheEntry>, CacheError> {
        let identity_digest = identity.digest(self.limits)?;
        let Some(head) = self.read_head(&identity_digest)? else {
            return Ok(None);
        };
        self.load_entry(identity, head).map(Some)
    }

    /// Restore a readable cache generation. Missing or integrity-failed stored
    /// content is a miss. Authorization and destination errors remain errors.
    pub fn restore(
        &self,
        reader: &TrustDomain,
        identity: &CacheIdentity,
        destination: impl AsRef<Path>,
    ) -> Result<RestoreOutcome, CacheError> {
        identity.validate(self.limits)?;
        if !reader.can_read_from(&identity.trust_domain) {
            return Err(CacheError::UnauthorizedRead);
        }
        let identity_digest = identity.digest(self.limits)?;
        let head = match self.read_head(&identity_digest) {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(RestoreOutcome::Miss(CacheMiss::NotFound)),
            Err(error) if error.is_stored_corruption() => {
                return Ok(RestoreOutcome::Miss(CacheMiss::Corrupt));
            }
            Err(error) => return Err(error),
        };
        let entry = match self.load_entry(identity, head) {
            Ok(entry) => entry,
            Err(error) if error.is_stored_corruption() => {
                return Ok(RestoreOutcome::Miss(CacheMiss::Corrupt));
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = self.verify_tree_content(&entry.manifest.tree) {
            if error.is_stored_corruption() {
                return Ok(RestoreOutcome::Miss(CacheMiss::Corrupt));
            }
            return Err(error);
        }
        match self
            .cas
            .materialize_tree(&entry.manifest.tree.manifest_digest, destination)
        {
            Ok(_) => Ok(RestoreOutcome::Hit(Box::new(entry))),
            Err(error) if storage_is_stored_corruption(&error) => {
                Ok(RestoreOutcome::Miss(CacheMiss::Corrupt))
            }
            Err(error) => Err(CacheError::Storage(error)),
        }
    }
}
use crate::{
    storage_is_stored_corruption, CacheEntry, CacheError, CacheIdentity, CacheMiss, CacheStore,
    RestoreOutcome, TrustDomain,
};
