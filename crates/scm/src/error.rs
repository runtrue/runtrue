use thiserror::Error;
#[derive(Debug, Error)]
pub enum ScmError {
    #[error("invalid SCM configuration: {0}")]
    InvalidConfiguration(String),
    #[error("{0} limit exceeded")]
    LimitExceeded(&'static str),
    #[error("invalid webhook header name")]
    InvalidHeaderName,
    #[error("invalid value for webhook header `{0}`")]
    InvalidHeaderValue(String),
    #[error("duplicate webhook header `{0}`")]
    DuplicateHeader(String),
    #[error("missing required webhook header `{0}`")]
    MissingHeader(&'static str),
    #[error("malformed webhook signature")]
    MalformedSignature,
    #[error("webhook signature mismatch")]
    SignatureMismatch,
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("authenticated provider does not match normalizer")]
    ProviderMismatch,
    #[error("unsupported SCM event `{0}`")]
    UnsupportedEvent(String),
    #[error("unsupported pull request action `{0}`")]
    UnsupportedAction(String),
    #[error("invalid webhook JSON: {0}")]
    InvalidJson(String),
    #[error("invalid provider payload: {0}")]
    InvalidPayload(String),
    #[error("invalid repository path: {0}")]
    InvalidPath(String),
    #[error("invalid Git object id")]
    InvalidGitCommit,
    #[error("unsupported normalized event version {0}")]
    UnsupportedNormalizedVersion(u32),
    #[error("normalized event digest mismatch")]
    NormalizedDigestMismatch,
    #[error("cannot serialize normalized event: {0}")]
    Serialize(serde_json::Error),
}
