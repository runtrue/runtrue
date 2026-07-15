#[derive(Debug, Error)]
pub enum ReportError {
    #[error("all report limits must be greater than zero")]
    InvalidLimits,
    #[error("report exceeds the configured byte limit")]
    InputTooLarge,
    #[error("report exceeds a configured complexity limit")]
    ComplexityLimit,
    #[error("report contains duplicate JSON key `{0}`")]
    DuplicateKey(String),
    #[error("report is malformed: {0}")]
    Malformed(String),
    #[error("unsupported report version `{0}`")]
    UnsupportedVersion(String),
    #[error("report path is unsafe")]
    UnsafePath,
    #[error("failed to serialize normalized report: {0}")]
    Serialize(serde_json::Error),
}
use thiserror::Error;
