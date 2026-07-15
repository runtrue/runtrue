#[cfg(unix)]
use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentityMetadata {
    pub(super) metadata_version: u32,
    pub(super) identity: RepositoryIdentity,
    pub(super) origin: NormalizedOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HydrationMetadata {
    pub(super) metadata_version: u32,
    pub(super) commit: String,
    pub(super) mirror_identity_digest: ContentDigest,
}

pub(super) fn hydration_destination(destination: &Path) -> Result<(PathBuf, &OsStr), GitError> {
    if !destination.is_absolute()
        || destination
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(GitError::UnsafeHydrationDestination(destination.to_owned()));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| GitError::UnsafeHydrationDestination(destination.to_owned()))?;
    let name = destination
        .file_name()
        .ok_or_else(|| GitError::UnsafeHydrationDestination(destination.to_owned()))?;
    validate_single_component(name)
        .map_err(|_| GitError::UnsafeHydrationDestination(destination.to_owned()))?;
    if name.as_bytes().len() > 240 {
        return Err(GitError::UnsafeHydrationDestination(destination.to_owned()));
    }
    Ok((parent.to_owned(), name))
}

pub(super) fn validate_hydration_parent(path: &Path, parent: &File) -> Result<(), GitError> {
    let metadata = parent
        .metadata()
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if !metadata.is_dir() || metadata.uid() != effective_uid() || metadata.mode() & 0o777 != 0o700 {
        return Err(GitError::UnsafeHydrationDestination(path.to_owned()));
    }
    Ok(())
}

pub(super) fn write_hydration_metadata(
    path: &Path,
    metadata: &HydrationMetadata,
) -> Result<(), GitError> {
    let mut bytes =
        serde_json::to_vec(metadata).map_err(|error| GitError::MirrorCorrupt(error.to_string()))?;
    bytes.push(b'\n');
    write_atomic_private_file(path, &bytes)
}

pub(super) fn read_hydration_metadata(path: &Path) -> Result<HydrationMetadata, GitError> {
    let bytes = read_bounded_private_file(path, MAX_METADATA_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|error| GitError::MirrorCorrupt(error.to_string()))
}

pub(super) fn hydration_failure_is_miss(error: &GitError) -> bool {
    fetch_failure_is_miss(error)
        || matches!(
            error,
            GitError::MirrorCorrupt(_)
                | GitError::MirrorLimit { .. }
                | GitError::SharedHydrationObject(_)
                | GitError::RepositoryRootMismatch { .. }
                | GitError::InvalidGitOutput(_)
        )
}
pub(super) fn write_identity_metadata(
    path: &Path,
    metadata: &IdentityMetadata,
) -> Result<(), GitError> {
    let mut bytes =
        serde_json::to_vec(metadata).map_err(|error| GitError::MirrorCorrupt(error.to_string()))?;
    bytes.push(b'\n');
    write_atomic_private_file(path, &bytes)
}

pub(super) fn verify_identity_metadata(
    path: &Path,
    expected: &IdentityMetadata,
) -> Result<(), GitError> {
    let bytes = read_bounded_private_file(path, MAX_METADATA_BYTES)?;
    let actual: IdentityMetadata = serde_json::from_slice(&bytes)
        .map_err(|error| GitError::MirrorCorrupt(error.to_string()))?;
    if actual.identity != expected.identity {
        return Err(GitError::MirrorIdentityChanged);
    }
    if actual.origin != expected.origin {
        return Err(GitError::MirrorOriginChanged);
    }
    if actual.metadata_version != expected.metadata_version {
        return Err(GitError::MirrorCorrupt(
            "unsupported identity metadata version".to_owned(),
        ));
    }
    Ok(())
}
use super::{
    effective_uid, fetch_failure_is_miss, read_bounded_private_file, validate_single_component,
    write_atomic_private_file, Component, ContentDigest, File, GitError, NormalizedOrigin, OsStr,
    Path, PathBuf, RepositoryIdentity, MAX_METADATA_BYTES,
};
use serde::{Deserialize, Serialize};
