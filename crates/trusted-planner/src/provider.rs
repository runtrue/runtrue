use crate::TrustedPlannerError;
use runtrue_compiler::{ReusableWorkflowSource, ReusableWorkflowSources};
use runtrue_git::GitError;
use runtrue_lock::LockFile;
use runtrue_model::ContentDigest;
use std::collections::BTreeMap;
use thiserror::Error;

pub trait ReusableWorkflowSourceProvider {
    /// Load exact bytes for an already validated lock entry. Implementations
    /// must never fetch or fall back to a checkout/worktree.
    fn load_exact(
        &self,
        reference: &str,
        commit: &str,
        digest: &ContentDigest,
    ) -> Result<Vec<u8>, ReusableWorkflowProviderError>;
}

#[derive(Debug, Error)]
pub enum ReusableWorkflowProviderError {
    #[error("reusable workflow reference is unsupported")]
    UnsupportedReference,
    #[error("reusable workflow origin or repository identity is not authenticated")]
    ForeignOrigin,
    #[error("reusable workflow path is unsafe")]
    UnsafePath,
    #[error("exact reusable workflow mirror or object is unavailable")]
    Unavailable,
    #[error("reusable workflow Git object read failed: {0}")]
    Git(#[from] GitError),
    #[error("reusable workflow source bytes do not match the locked digest")]
    DigestMismatch,
}

pub(crate) fn hydrate_reusable_sources(
    provider: Option<&dyn ReusableWorkflowSourceProvider>,
    lockfile: Option<&LockFile>,
) -> Result<ReusableWorkflowSources, TrustedPlannerError> {
    let Some(lockfile) = lockfile else {
        return Ok(ReusableWorkflowSources::default());
    };
    if lockfile.workflows().is_empty() {
        return Ok(ReusableWorkflowSources::default());
    }
    let provider = provider.ok_or(TrustedPlannerError::ReusableSourceProviderRequired)?;
    let mut entries = BTreeMap::new();
    for entry in lockfile.workflows() {
        let bytes = provider.load_exact(entry.source(), entry.commit(), entry.digest())?;
        if ContentDigest::sha256(&bytes) != *entry.digest() {
            return Err(ReusableWorkflowProviderError::DigestMismatch.into());
        }
        entries.insert(
            entry.source().to_owned(),
            ReusableWorkflowSource::new(entry.commit(), bytes)?,
        );
    }
    Ok(ReusableWorkflowSources::new(entries)?)
}
