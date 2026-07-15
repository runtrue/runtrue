use runtrue_storage::FsCas;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

mod commit;
mod read;

pub use read::verify_immutable_artifact_record;

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    pub(crate) root: PathBuf,
    pub(crate) cas: FsCas,
    pub(crate) limits: ArtifactLimits,
}

impl ArtifactStore {
    pub fn open(
        root: impl AsRef<Path>,
        cas: FsCas,
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        let limits = limits.validate()?;
        let requested = root.as_ref();
        match fs::symlink_metadata(requested) {
            Ok(metadata) => require_directory(requested, &metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(requested)
                    .map_err(|source| io_failure("create artifact root", requested, source))?;
                let metadata = fs::symlink_metadata(requested)
                    .map_err(|source| io_failure("inspect artifact root", requested, source))?;
                require_directory(requested, &metadata)?;
            }
            Err(source) => return Err(io_failure("inspect artifact root", requested, source)),
        }
        let root = requested
            .canonicalize()
            .map_err(|source| io_failure("canonicalize artifact root", requested, source))?;
        let store = Self { root, cas, limits };
        store.ensure_layout()?;
        Ok(store)
    }

    #[must_use]
    pub fn cas(&self) -> &FsCas {
        &self.cas
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ensure_layout(&self) -> Result<(), ArtifactError> {
        let tickets = self.root.join("tickets");
        ensure_directory(&tickets)?;
        ensure_directory(&tickets.join("sha256"))
    }
}
use crate::{ensure_directory, io_failure, require_directory, ArtifactError, ArtifactLimits};
