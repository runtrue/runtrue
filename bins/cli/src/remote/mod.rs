mod authentication;
mod client;
mod models;
mod submit;

pub(super) use authentication::{valid_api_identifier, AuthenticatedRemote};
pub(super) use submit::execute;

use super::ContextArgs;
use clap::Args;
use std::{io, path::PathBuf, time::Duration};
use thiserror::Error;

const SERVER_POLICY_VERSION_ID: &str = "server-default-deny-v1";
const MAX_TOKEN_BYTES: u64 = 4096;
const MAX_SUBMIT_REQUEST_BYTES: usize = 40 * 1024 * 1024;
const MAX_SUBMIT_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Args)]
pub(super) struct SubmitArgs {
    /// Job id (or matrix base id) to submit, including its dependencies.
    pub(super) job: Option<String>,
    #[command(flatten)]
    pub(super) context: ContextArgs,
    /// Runtrue server origin. Paths, credentials, queries, and fragments are rejected.
    #[arg(long, value_name = "URL")]
    pub(super) server: String,
    /// Durable repository id registered with the Runtrue server.
    #[arg(long, value_name = "ID")]
    pub(super) repository_id: String,
    /// Private mode-0600 file containing the bearer token.
    #[arg(long, value_name = "PATH")]
    pub(super) token_file: PathBuf,
    /// Permit plaintext HTTP only when --server uses an IP-literal loopback origin.
    #[arg(long)]
    pub(super) allow_loopback_http: bool,
    /// Remote scheduling priority.
    #[arg(long, default_value_t = 0)]
    pub(super) priority: i32,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub(super) json: bool,
}

#[derive(Debug, Error)]
pub(super) enum SubmitError {
    #[error("server must be an HTTPS origin without credentials, path, query, or fragment")]
    InvalidServerOrigin,
    #[error("plaintext server URLs require --allow-loopback-http")]
    PlaintextHttpDenied,
    #[error("plaintext evaluation is limited to IP-literal loopback origins")]
    LoopbackHttpRequired,
    #[error("repository id is empty, oversized, or unsafe in an API path")]
    InvalidRepositoryId,
    #[error("approval id is empty, oversized, or unsafe in an API path")]
    InvalidApprovalId,
    #[error("approval subject must be an exact qualified SHA-256 digest")]
    InvalidApprovalSubject,
    #[error("approval reason must be non-empty, control-free, and at most 2000 bytes")]
    InvalidApprovalReason,
    #[error("approval rule id must be non-empty, control-free, and at most 8192 bytes")]
    InvalidApprovalRule,
    #[error("cannot read bearer token file {}: {source}", path.display())]
    TokenIo { path: PathBuf, source: io::Error },
    #[error("refusing bearer token file {}: {reason}", path.display())]
    UnsafeTokenFile { path: PathBuf, reason: &'static str },
    #[error("submit request cannot be encoded")]
    RequestEncoding,
    #[error("submit request exceeds the bounded transport size")]
    RequestTooLarge,
    #[error("{operation} transport failed")]
    Transport { operation: &'static str },
    #[error("{operation} returned unexpected HTTP status {status}")]
    RemoteStatus {
        operation: &'static str,
        status: u16,
    },
    #[error("remote response exceeds the bounded transport size")]
    ResponseTooLarge,
    #[error("remote response body could not be read within its bound")]
    ResponseRead,
    #[error("remote response is malformed or violates the API contract")]
    MalformedResponse,
    #[error("remote capsule digest does not authenticate its canonical capsule bytes")]
    RemoteDigestMismatch,
    #[error(
        "remote canonical capsule does not exactly match the local capsule; run was not created"
    )]
    CapsuleParityMismatch,
}

impl SubmitError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::InvalidServerOrigin => "invalid_server_origin",
            Self::PlaintextHttpDenied => "plaintext_http_denied",
            Self::LoopbackHttpRequired => "loopback_http_required",
            Self::InvalidRepositoryId => "invalid_repository_id",
            Self::InvalidApprovalId => "invalid_approval_id",
            Self::InvalidApprovalSubject => "invalid_approval_subject",
            Self::InvalidApprovalReason => "invalid_approval_reason",
            Self::InvalidApprovalRule => "invalid_approval_rule",
            Self::TokenIo { .. } => "token_read_failed",
            Self::UnsafeTokenFile { .. } => "unsafe_token_file",
            Self::RequestEncoding | Self::RequestTooLarge => "submit_request_invalid",
            Self::Transport { .. } => "submit_transport_failed",
            Self::RemoteStatus { .. } => "submit_remote_rejected",
            Self::ResponseTooLarge => "submit_response_too_large",
            Self::ResponseRead | Self::MalformedResponse => "submit_response_invalid",
            Self::RemoteDigestMismatch => "remote_capsule_digest_mismatch",
            Self::CapsuleParityMismatch => "capsule_parity_mismatch",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client::{RemoteClient, ServerOrigin};
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn transport_origin_requires_tls_or_explicit_ip_loopback() {
        assert!(matches!(
            ServerOrigin::parse("http://127.0.0.1:8080", false),
            Err(SubmitError::PlaintextHttpDenied)
        ));
        assert!(ServerOrigin::parse("http://127.0.0.1:8080", true).is_ok());
        assert!(ServerOrigin::parse("http://[::1]:8080", true).is_ok());
        assert!(matches!(
            ServerOrigin::parse("http://localhost:8080", true),
            Err(SubmitError::LoopbackHttpRequired)
        ));
        assert!(matches!(
            ServerOrigin::parse("http://192.0.2.10:8080", true),
            Err(SubmitError::LoopbackHttpRequired)
        ));
        assert!(ServerOrigin::parse("https://runtrue.example", false).is_ok());
        for invalid in [
            "https://user@runtrue.example",
            "https://runtrue.example/prefix",
            "https://runtrue.example/?query=1",
            "file:///tmp/runtrue",
        ] {
            assert!(ServerOrigin::parse(invalid, false).is_err(), "{invalid}");
        }
    }

    #[test]
    fn remote_client_debug_redacts_token() {
        let client = RemoteClient::new(
            ServerOrigin::parse("https://runtrue.example", false).unwrap(),
            Zeroizing::new("do-not-print-this".to_owned()),
        );
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("do-not-print-this"));
    }
}
