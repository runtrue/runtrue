use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageAttestError {
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("invalid image manifest: {0}")]
    InvalidManifest(&'static str),
    #[error("image manifest exceeds its component or compatibility limit")]
    ManifestLimitExceeded,
    #[error("only a sterile Firecracker snapshot may be published to a warm pool")]
    SnapshotNotSterile,
    #[error("invalid image-signing public key length {0}; expected 32 bytes")]
    InvalidPublicKeyLength(usize),
    #[error("invalid signature length {0}; expected 64 bytes")]
    InvalidSignatureLength(usize),
    #[error("signature metadata does not match the object or verification key")]
    SignatureMetadataMismatch,
    #[error("signed object digest does not match its canonical bytes")]
    ObjectDigestMismatch,
    #[error("invalid update metadata")]
    InvalidUpdateMetadata,
    #[error("invalid update-signature trust threshold")]
    InvalidTrustThreshold,
    #[error("update metadata targets the wrong channel")]
    WrongUpdateChannel,
    #[error("update metadata is not currently valid")]
    UpdateMetadataExpired,
    #[error(
        "update rollback rejected: highest accepted generation is {highest}, offered {offered}"
    )]
    UpdateRollback { highest: u64, offered: u64 },
    #[error("update metadata contains too many signatures")]
    SignatureLimitExceeded,
    #[error("update metadata repeats a trusted signing key")]
    DuplicateUpdateSignature,
    #[error("update signature threshold not met: required {required}, verified {verified}")]
    UpdateSignatureThreshold { required: usize, verified: usize },
    #[error("signature verification failed: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("image attestation JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}
