mod capture;
mod materialize;
mod read;
mod write;

pub(crate) use write::*;

use crate::{secure_io::*, CasLimits, StorageError};
use runtrue_model::ContentDigest;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Filesystem SHA-256 content-addressed storage.
#[derive(Debug, Clone)]
pub struct FsCas {
    pub(crate) root: PathBuf,
    pub(crate) limits: CasLimits,
}

impl FsCas {
    /// Open or initialize a CAS. The CAS root itself must be a real directory,
    /// never a symlink or special file.
    pub fn open(root: impl AsRef<Path>, limits: CasLimits) -> Result<Self, StorageError> {
        let limits = limits.validate()?;
        let requested = root.as_ref();
        match fs::symlink_metadata(requested) {
            Ok(metadata) => require_real_directory(requested, &metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(requested)
                    .map_err(|source| io_failure("create CAS root", requested, source))?;
                let metadata = fs::symlink_metadata(requested)
                    .map_err(|source| io_failure("inspect CAS root", requested, source))?;
                require_real_directory(requested, &metadata)?;
            }
            Err(source) => return Err(io_failure("inspect CAS root", requested, source)),
        }

        let root = requested
            .canonicalize()
            .map_err(|source| io_failure("canonicalize CAS root", requested, source))?;
        let cas = Self { root, limits };
        cas.ensure_layout()?;
        Ok(cas)
    }

    /// Open an existing CAS for verification without creating staging or
    /// layout entries. Backup verification uses this to remain read-only.
    pub fn open_read_only(root: impl AsRef<Path>, limits: CasLimits) -> Result<Self, StorageError> {
        let limits = limits.validate()?;
        let requested = root.as_ref();
        let metadata = fs::symlink_metadata(requested)
            .map_err(|source| io_failure("inspect read-only CAS root", requested, source))?;
        require_real_directory(requested, &metadata)?;
        let objects = requested.join("objects");
        let objects_metadata = fs::symlink_metadata(&objects)
            .map_err(|source| io_failure("inspect CAS objects root", &objects, source))?;
        require_real_directory(&objects, &objects_metadata)?;
        let sha256 = objects.join("sha256");
        let sha256_metadata = fs::symlink_metadata(&sha256)
            .map_err(|source| io_failure("inspect SHA-256 CAS root", &sha256, source))?;
        require_real_directory(&sha256, &sha256_metadata)?;
        let root = requested
            .canonicalize()
            .map_err(|source| io_failure("canonicalize read-only CAS root", requested, source))?;
        Ok(Self { root, limits })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn limits(&self) -> CasLimits {
        self.limits
    }
}

impl FsCas {
    pub(crate) fn ensure_layout(&self) -> Result<(), StorageError> {
        let objects = self.root.join("objects");
        ensure_owned_directory(&objects)?;
        ensure_owned_directory(&objects.join("sha256"))?;
        ensure_owned_directory(&self.root.join("tmp"))
    }
}

impl FsCas {
    pub(crate) fn object_path(&self, digest: &ContentDigest) -> Result<PathBuf, StorageError> {
        let encoded = digest
            .as_str()
            .strip_prefix("sha256:")
            .ok_or_else(|| StorageError::UnsupportedDigest(digest.to_string()))?;
        if encoded.len() != 64 {
            return Err(StorageError::UnsupportedDigest(digest.to_string()));
        }
        let prefix = &encoded[..2];
        Ok(self
            .root
            .join("objects")
            .join("sha256")
            .join(prefix)
            .join(&encoded[2..]))
    }
}
