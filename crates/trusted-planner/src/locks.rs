use crate::TrustedPlannerError;
use runtrue_git::GitBlob;
use runtrue_lock::LockFile;
use runtrue_model::ContentDigest;

pub(crate) fn parse_required_lock(
    blob: Option<&GitBlob>,
    kind: &'static str,
) -> Result<Option<LockFile>, TrustedPlannerError> {
    blob.map(|blob| {
        LockFile::parse(&blob.bytes)
            .map_err(|source| TrustedPlannerError::InvalidLockfile { kind, source })
    })
    .transpose()
}

pub(crate) fn parse_analysis_lock(blob: Option<&GitBlob>) -> Result<Option<LockFile>, ()> {
    blob.map(|blob| LockFile::parse(&blob.bytes).map_err(|_| ()))
        .transpose()
}

pub(crate) fn lock_identity(blob: Option<&GitBlob>) -> Option<ContentDigest> {
    blob.map(|blob| {
        LockFile::parse(&blob.bytes)
            .and_then(|lock| lock.digest())
            .unwrap_or_else(|_| blob.digest.clone())
    })
}
