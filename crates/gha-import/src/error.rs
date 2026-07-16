use crate::MAX_GITHUB_WORKFLOW_BYTES;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("GitHub Actions workflow exceeds the {MAX_GITHUB_WORKFLOW_BYTES}-byte input limit")]
    TooLarge,
    #[error("invalid GitHub Actions YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("generated native workflow is invalid: {0}")]
    GeneratedWorkflow(String),
    #[error("generated lockfile is invalid: {0}")]
    GeneratedLockfile(String),
    #[error("cannot serialize generated output: {0}")]
    Serialize(String),
    #[error("repository action metadata is unsupported: {0}")]
    RepositoryActionMetadata(String),
}
