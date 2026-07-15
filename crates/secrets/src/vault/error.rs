//! Errors returned by encrypted vault operations.
use super::model::SecretIdentity;
use crate::SensitiveError;
use thiserror::Error;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretsError {
    #[error("unsupported secret-vault snapshot version {0}")]
    UnsupportedVaultSnapshotVersion(u32),
    #[error("secret-vault snapshot version identity does not match its record")]
    SnapshotIdentityMismatch,
    #[error("secret-vault snapshot contains duplicate secret identities")]
    DuplicateSnapshotIdentity,
    #[error("secret-vault snapshot versions must be contiguous starting at one")]
    NonContiguousVersions,
    #[error("invalid {field}: {reason}")]
    InvalidComponent {
        field: &'static str,
        reason: &'static str,
    },
    #[error("secret plaintext exceeds {limit} bytes: got {actual}")]
    SecretTooLarge { limit: usize, actual: usize },
    #[error("secret `{0:?}` already exists")]
    SecretAlreadyExists(SecretIdentity),
    #[error("secret `{0:?}` was not found")]
    SecretNotFound(SecretIdentity),
    #[error("secret `{0:?}` is tombstoned")]
    SecretTombstoned(SecretIdentity),
    #[error("secret version {version} was not found for `{identity:?}`")]
    SecretVersionNotFound {
        identity: SecretIdentity,
        version: u64,
    },
    #[error("version numbers must start at one")]
    InvalidVersion,
    #[error("secret version counter overflowed")]
    VersionOverflow,
    #[error("immutable secret version {0} already exists")]
    ImmutableVersionConflict(u64),
    #[error("secret record contains no versions")]
    MissingVersions,
    #[error("unsupported secret encryption algorithm `{0}`")]
    UnsupportedEncryptionAlgorithm(String),
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("secret encryption failed")]
    EncryptionFailed,
    #[error("secret authentication or decryption failed")]
    AuthenticationFailed,
    #[error("unwrapped DEK has invalid length {0}")]
    InvalidWrappedKeyLength(usize),
    #[error("encrypted version expected KEK `{expected}`, got `{actual}`")]
    UnexpectedKekId { expected: String, actual: String },
    #[error("new KEK identifier `{0}` must differ from the active identifier")]
    KekIdNotAdvanced(String),
    #[error("fencing generation must be greater than zero")]
    InvalidFencingGeneration,
    #[error("no active fencing generation is registered for `{0}`")]
    FencingGenerationNotRegistered(String),
    #[error("stale fencing generation {provided}; active generation is {active}")]
    StaleFencingGeneration { active: u64, provided: u64 },
    #[error("cannot move fencing generation backward from {current} to {proposed}")]
    FencingGenerationRegression { current: u64, proposed: u64 },
    #[error("lease expiry must be later than the current time")]
    InvalidLeaseExpiry,
    #[error("could not allocate a unique secret lease identifier")]
    LeaseIdCollision,
    #[error("secret lease `{0}` was not found")]
    LeaseNotFound(String),
    #[error("secret lease `{0}` was already consumed")]
    LeaseAlreadyConsumed(String),
    #[error("secret lease `{0}` was revoked")]
    LeaseRevoked(String),
    #[error("secret lease `{0}` expired")]
    LeaseExpired(String),
    #[error("secret lease {field} does not match the requested binding")]
    LeaseBindingMismatch { field: &'static str },
}

impl From<SensitiveError> for SecretsError {
    fn from(_error: SensitiveError) -> Self {
        Self::RandomnessUnavailable
    }
}
