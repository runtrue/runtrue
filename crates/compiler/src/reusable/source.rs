#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableWorkflowSource {
    pub(crate) commit: String,
    pub(crate) source: Box<[u8]>,
}

impl ReusableWorkflowSource {
    pub fn new(
        commit: impl Into<String>,
        source: impl Into<Vec<u8>>,
    ) -> Result<Self, ReusableSourceBundleError> {
        let commit = commit.into();
        let source = source.into();
        if commit.is_empty() || commit.len() > 128 || commit.contains(['\0', '\n', '\r']) {
            return Err(ReusableSourceBundleError::InvalidCommit);
        }
        if source.len() > MAX_REUSABLE_SOURCE_BYTES {
            return Err(ReusableSourceBundleError::SourceTooLarge {
                limit: MAX_REUSABLE_SOURCE_BYTES,
                actual: source.len(),
            });
        }
        Ok(Self {
            commit,
            source: source.into_boxed_slice(),
        })
    }
}

/// Bounded, deterministic source provider used by the pure compiler. It never
/// performs filesystem or network I/O.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReusableWorkflowSources {
    pub(crate) entries: BTreeMap<String, ReusableWorkflowSource>,
}

impl ReusableWorkflowSources {
    pub fn new(
        entries: BTreeMap<String, ReusableWorkflowSource>,
    ) -> Result<Self, ReusableSourceBundleError> {
        if entries.len() > MAX_REUSABLE_SOURCES {
            return Err(ReusableSourceBundleError::TooManySources {
                limit: MAX_REUSABLE_SOURCES,
                actual: entries.len(),
            });
        }
        let mut total = 0usize;
        for (reference, source) in &entries {
            if reference.is_empty()
                || reference.len() > 4_096
                || reference.contains(['\0', '\n', '\r'])
            {
                return Err(ReusableSourceBundleError::InvalidReference(
                    reference.clone(),
                ));
            }
            total = total.saturating_add(source.source.len());
            if total > MAX_REUSABLE_BUNDLE_BYTES {
                return Err(ReusableSourceBundleError::BundleTooLarge {
                    limit: MAX_REUSABLE_BUNDLE_BYTES,
                    actual: total,
                });
            }
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReusableSourceBundleError {
    #[error("reusable workflow commit identity is empty or malformed")]
    InvalidCommit,
    #[error("invalid reusable workflow reference `{0}`")]
    InvalidReference(String),
    #[error("reusable workflow source exceeds the {limit}-byte limit (found {actual})")]
    SourceTooLarge { limit: usize, actual: usize },
    #[error("reusable source bundle exceeds {limit} entries (found {actual})")]
    TooManySources { limit: usize, actual: usize },
    #[error("reusable source bundle exceeds the {limit}-byte limit (found {actual})")]
    BundleTooLarge { limit: usize, actual: usize },
}
use crate::{BTreeMap, MAX_REUSABLE_BUNDLE_BYTES, MAX_REUSABLE_SOURCES, MAX_REUSABLE_SOURCE_BYTES};
use thiserror::Error;
