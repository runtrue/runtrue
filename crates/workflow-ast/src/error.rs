use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("workflow exceeds the 1 MiB parser limit")]
    TooLarge,
    #[error("unsupported workflow version {0}; expected version 1")]
    UnsupportedVersion(u32),
    #[error("invalid workflow YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
}
