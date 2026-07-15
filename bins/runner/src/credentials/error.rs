use crate::state::StateError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("runner credentials are not installed at `{0}`")]
    MissingCredentials(PathBuf),
    #[error("runner credential current marker is invalid")]
    InvalidCurrent,
    #[error("runner credential generation `{0}` is unsafe")]
    UnsafeGeneration(PathBuf),
    #[error("runner credential metadata is invalid")]
    InvalidMetadata,
    #[error("runner credential metadata JSON is invalid: {0}")]
    Metadata(serde_json::Error),
    #[error("runner credential protocol generation is absent; configure an explicit version to upgrade it")]
    MissingProtocolVersion,
    #[error("runner credential protocol generation is invalid")]
    InvalidProtocolVersion,
    #[error(
        "configured protocol generation {configured} conflicts with persisted generation {persisted}"
    )]
    ProtocolVersionMismatch { persisted: u32, configured: u32 },
    #[error("runner pending certificate rotation is invalid")]
    InvalidPendingRotation,
    #[error("runner pending certificate request is invalid or does not match its private key")]
    InvalidCertificateRequest,
    #[error("runner pending certificate rotation does not match the active credential generation")]
    RotationStateMismatch,
    #[error("runner certificate rotation has no durably recorded response")]
    RotationResponseMissing,
    #[error("runner certificate rotation replay returned a different public response")]
    ConflictingRotationResponse,
    #[error("runner certificate rotation response changed the enrolled issuing authority")]
    RotationIssuerMismatch,
    #[error("runner client private key is invalid or is not Ed25519")]
    InvalidKey,
    #[error("runner client certificate chain is invalid")]
    InvalidCertificate,
    #[error("runner client certificate does not match its local key or durable identity")]
    IdentityMismatch,
    #[error("runner credential file is empty or exceeds its size bound")]
    CredentialSize,
    #[error(transparent)]
    State(#[from] StateError),
}
