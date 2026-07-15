use super::{CapabilityAdapterError, CapabilityCallContext};
use runtrue_model::normalize_relative_path;
pub(super) const MAX_CAPABILITY_PATH_BYTES: usize = 4096;
pub(super) const MAX_CAPABILITY_PATH_SEGMENTS: usize = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemAccess {
    Read,
    Write,
    ReadWrite,
}

impl FilesystemAccess {
    pub(super) const fn permits_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    pub(super) const fn permits_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryGrant {
    pub(super) scope: String,
    pub(super) access: FilesystemAccess,
}

impl DirectoryGrant {
    pub(crate) fn new(scope: String, access: FilesystemAccess) -> Self {
        Self { scope, access }
    }

    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    #[must_use]
    pub const fn access(&self) -> FilesystemAccess {
        self.access
    }

    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        normalize_guest_path(path).is_ok_and(|normalized| {
            normalized == self.scope
                || normalized
                    .strip_prefix(&self.scope)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }
}

pub trait FilesystemAdapter: Send + Sync {
    fn read_file(
        &self,
        context: &CapabilityCallContext,
        grant: &DirectoryGrant,
        relative_path: &str,
    ) -> Result<Vec<u8>, CapabilityAdapterError>;

    fn write_file(
        &self,
        context: &CapabilityCallContext,
        grant: &DirectoryGrant,
        relative_path: &str,
        value: &[u8],
    ) -> Result<(), CapabilityAdapterError>;
}
pub(super) fn normalize_guest_path(path: &str) -> Result<String, ()> {
    if path.len() > MAX_CAPABILITY_PATH_BYTES
        || path.split('/').count() > MAX_CAPABILITY_PATH_SEGMENTS
    {
        return Err(());
    }
    normalize_relative_path(path).map_err(|_| ())
}
