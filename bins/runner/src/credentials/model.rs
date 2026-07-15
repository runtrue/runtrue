#[derive(Debug, Clone)]
pub struct RunnerCredentialStore {
    pub(super) root: PathBuf,
    pub(super) generations: PathBuf,
    pub(super) current: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedRunnerCredentials {
    pub runner_id: String,
    pub pool_id: String,
    pub certificate_expires_unix_ms: u64,
    pub certificate_fingerprint: runtrue_model::ContentDigest,
    pub issuer_fingerprint: runtrue_model::ContentDigest,
    pub authoritative_posture_digest: Option<runtrue_model::ContentDigest>,
    pub selected_protocol_version: Option<u32>,
    pub client_certificate: PathBuf,
    pub client_private_key: PathBuf,
}

pub struct NewRunnerCredentials {
    pub runner_id: String,
    pub pool_id: String,
    pub certificate_expires_unix_ms: u64,
    pub private_key_pem: Zeroizing<String>,
    pub certificate_chain_pem: Vec<u8>,
    pub authoritative_posture_digest: Option<runtrue_model::ContentDigest>,
    pub selected_protocol_version: u32,
}

/// A crash-recoverable certificate rotation. The private key and exact CSR
/// are published before the RPC is attempted, and an issued response is
/// persisted before the active credential generation is switched.
pub struct PendingRunnerRotation {
    pub runner_id: String,
    pub pool_id: String,
    pub previous_certificate_fingerprint: runtrue_model::ContentDigest,
    pub issuer_fingerprint: runtrue_model::ContentDigest,
    pub private_key_pem: Zeroizing<String>,
    pub csr_der: Vec<u8>,
    pub response: Option<PendingRotationResponse>,
}

impl fmt::Debug for PendingRunnerRotation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRunnerRotation")
            .field("runner_id", &self.runner_id)
            .field("pool_id", &self.pool_id)
            .field(
                "previous_certificate_fingerprint",
                &self.previous_certificate_fingerprint,
            )
            .field("issuer_fingerprint", &self.issuer_fingerprint)
            .field("private_key_pem", &"<redacted>")
            .field("csr_bytes", &self.csr_der.len())
            .field("response", &self.response)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRotationResponse {
    pub certificate_expires_unix_ms: u64,
    pub certificate_chain_pem: Vec<u8>,
}

impl PendingRotationResponse {
    pub(crate) fn certificate_fingerprint(
        &self,
    ) -> Result<runtrue_model::ContentDigest, CredentialError> {
        certificate_fingerprint(&self.certificate_chain_pem)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingRotationMetadata {
    pub(super) version: u32,
    pub(super) runner_id: String,
    pub(super) pool_id: String,
    pub(super) previous_certificate_fingerprint: runtrue_model::ContentDigest,
    pub(super) issuer_fingerprint: runtrue_model::ContentDigest,
    pub(super) csr_digest: runtrue_model::ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialMetadata {
    pub(super) version: u32,
    pub(super) runner_id: String,
    pub(super) pool_id: String,
    pub(super) certificate_expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) authoritative_posture_digest: Option<runtrue_model::ContentDigest>,
}
use super::{certificate_fingerprint, CredentialError};
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};
use zeroize::Zeroizing;
