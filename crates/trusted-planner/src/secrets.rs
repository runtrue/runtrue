use runtrue_compiler::Compilation;
use thiserror::Error;

/// Trusted metadata resolver invoked after pure compilation and before any
/// workflow-definition approval comparison or Capsule selection.
pub trait SecretMetadataResolver {
    fn bind_exact(&self, compilation: &mut Compilation) -> Result<(), SecretResolutionError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SecretResolutionError {
    #[error("a declared secret has no eligible metadata")]
    Missing,
    #[error("secret project resolution is ambiguous")]
    Ambiguous,
    #[error("secret metadata or project membership changed during planning")]
    Stale,
    #[error("secret metadata resolution is unavailable")]
    Unavailable,
}
