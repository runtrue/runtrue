use crate::GitError;
use runtrue_model::ContentDigest;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitLimits {
    pub max_blob_bytes: usize,
    pub max_diff_bytes: usize,
    pub max_changed_paths: usize,
    pub max_path_bytes: usize,
    pub command_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for GitLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 2 * 1024 * 1024,
            max_diff_bytes: 8 * 1024 * 1024,
            max_changed_paths: 50_000,
            max_path_bytes: 4096,
            command_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(5),
        }
    }
}

impl GitLimits {
    pub(crate) fn validate(self) -> Result<Self, GitError> {
        if self.max_blob_bytes == 0
            || self.max_diff_bytes == 0
            || self.max_changed_paths == 0
            || self.max_path_bytes == 0
            || self.command_timeout.is_zero()
            || self.poll_interval.is_zero()
            || self.poll_interval > self.command_timeout
        {
            return Err(GitError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitBlob {
    pub commit: String,
    pub path: String,
    pub executable: bool,
    pub digest: ContentDigest,
    pub bytes: Vec<u8>,
}

/// Target-branch execution bytes plus optional proposed bytes used only for a
/// risk diff. The type deliberately does not offer a fallback from execution
/// to proposed content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedWorkflowSources {
    pub(crate) execution: GitBlob,
    pub(crate) proposed_for_risk: Option<GitBlob>,
}

impl TrustedWorkflowSources {
    #[must_use]
    pub fn execution(&self) -> &GitBlob {
        &self.execution
    }

    #[must_use]
    pub fn proposed_for_risk(&self) -> Option<&GitBlob> {
        self.proposed_for_risk.as_ref()
    }
}
