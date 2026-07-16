use runtrue_attest::ImageAttestError;
use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ImageCliError {
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("image attestation failed: {0}")]
    ImageAttestation(#[from] ImageAttestError),
    #[error("invalid digest: {0}")]
    Digest(#[from] runtrue_model::ModelError),
    #[error("path is unsafe or contains a symbolic link: `{0}`")]
    UnsafePath(PathBuf),
    #[error("path is not a regular file: `{0}`")]
    NotRegularFile(PathBuf),
    #[error("private key `{path}` has insecure mode {mode:o}; expected no group/other access")]
    InsecurePrivateKeyMode { path: PathBuf, mode: u32 },
    #[error("registry credential file `{path}` has insecure mode {mode:o}; expected no group/other access")]
    InsecureRegistryConfigMode { path: PathBuf, mode: u32 },
    #[error("registry credential file `{path}` is owned by uid {actual}; expected uid {expected}")]
    RegistryConfigOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("private image key has {0} bytes; expected exactly 32")]
    InvalidPrivateKeyLength(usize),
    #[error("private and public image key paths must be different")]
    KeyPathsConflict,
    #[error("refusing to replace existing output `{0}`")]
    OutputAlreadyExists(PathBuf),
    #[error("file `{path}` exceeds {limit} bytes (observed {actual})")]
    FileTooLarge {
        path: PathBuf,
        limit: u64,
        actual: u64,
    },
    #[error("file changed while it was being verified: `{0}`")]
    FileChanged(PathBuf),
    #[error("file length overflow")]
    SizeOverflow,
    #[error("metadata must use a nonempty NAME=VALUE pair: `{0}`")]
    InvalidMetadataPair(String),
    #[error("metadata key `{0}` was repeated")]
    DuplicateMetadataKey(String),
    #[error("manifest input is not its exact canonical encoding")]
    NonCanonicalManifest,
    #[error("signed manifest input is not its exact canonical encoding")]
    NonCanonicalSignedManifest,
    #[error("signed manifest is not currently valid")]
    ManifestNotCurrentlyValid,
    #[error("payload digest or byte length does not match the signed manifest")]
    PayloadMismatch,
    #[error("provenance digest does not match the signed manifest")]
    ProvenanceMismatch,
    #[error("SBOM digest does not match the signed manifest")]
    SbomMismatch,
    #[error("OCI component reference must name an exact sha256 manifest: `{0}`")]
    InvalidOciReference(String),
    #[error("OCI component manifest is invalid: {0}")]
    InvalidOciManifest(String),
    #[error("trusted ORAS binary digest does not match --oras-digest")]
    OrasDigestMismatch,
    #[error("ORAS {operation} failed with status {status}")]
    OrasFailed {
        operation: &'static str,
        status: String,
    },
}
