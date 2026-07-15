use thiserror::Error;

#[derive(Debug, Error)]
pub enum MatrixExpansionError {
    #[error("dynamic matrix template identity does not match its signed job identity")]
    TemplateIdentityMismatch,
    #[error("dynamic matrix template must not contain pre-expanded matrix values")]
    TemplateMatrixNotEmpty,
    #[error("dynamic matrix template must retain its producer as an explicit dependency")]
    ProducerDependencyMissing,
    #[error("dynamic matrix limit {0} is outside 1..=1024")]
    InvalidLimit(usize),
    #[error("dynamic matrix expands beyond the configured {0} job limit")]
    LimitExceeded(usize),
    #[error("invalid dynamic matrix axis `{0}`")]
    InvalidAxis(String),
    #[error("dynamic matrix axis `{0}` is empty")]
    EmptyAxis(String),
    #[error("dynamic matrix input must be a JSON object")]
    InputMustBeObject,
    #[error("dynamic matrix axis `{0}` must be a JSON array")]
    AxisMustBeArray(String),
    #[error("dynamic matrix values must be finite scalar values")]
    InvalidScalar,
    #[error("could not canonicalize dynamic matrix input: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum CapsuleError {
    #[error("could not serialize canonical execution capsule: {0}")]
    Serialize(#[from] serde_json::Error),
}
