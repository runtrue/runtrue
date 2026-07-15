use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("only sha256 digests are supported by this capsule generation")]
    UnsupportedDigestAlgorithm,
    #[error("digest must contain exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("invalid duration `{0}`; expected a positive integer followed by ms, s, m, or h")]
    InvalidDuration(String),
    #[error("invalid byte size `{0}`; expected an integer followed by B, KB, MB, GB, KiB, MiB, GiB, or TiB")]
    InvalidSize(String),
    #[error("path `{0}` is not a safe repository-relative path")]
    UnsafePath(String),
}
