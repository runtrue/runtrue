use runtrue_model::ContentDigest;
use runtrue_scheduler::RunnerRecord;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerPoolStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerPoolRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub status: RunnerPoolStatus,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedRunner {
    pub runner: RunnerRecord,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerCertificateStatus {
    Active,
    Overlap,
    Revoked,
}

/// Durable authorization state for one issued runner client certificate.
/// The private key is generated and retained by the runner and is never
/// represented in control-plane state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerCertificateRecord {
    pub fingerprint: ContentDigest,
    pub runner_id: String,
    pub pool_id: String,
    pub serial_hex: String,
    pub not_before_unix_ms: u64,
    pub not_after_unix_ms: u64,
    pub status: RunnerCertificateStatus,
    pub issued_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlap_until_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix_ms: Option<u64>,
}

/// Immutable response journal for one certificate-rotation CSR. The old
/// certificate fingerprint is the idempotency boundary: it may authorize one
/// exact CSR and thereafter only replay that exact public response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerCertificateRotationRecord {
    pub old_fingerprint: ContentDigest,
    pub runner_id: String,
    pub pool_id: String,
    pub csr_digest: ContentDigest,
    pub new_certificate: RunnerCertificateRecord,
    pub certificate_chain_pem: Vec<u8>,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRunnerCertificate {
    pub runner: PersistedRunner,
    pub certificate: RunnerCertificateRecord,
}

/// One-time enrollment bearer returned only by token creation.
pub struct EnrollmentToken(Zeroizing<String>);

impl EnrollmentToken {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnrollmentToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentToken([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentTokenRecord {
    pub id: String,
    pub pool_id: String,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_unix_ms: Option<u64>,
}

#[derive(Debug)]
pub struct IssuedEnrollmentToken {
    pub metadata: EnrollmentTokenRecord,
    pub token: EnrollmentToken,
}

/// Idempotent enrollment creation never persists or replays bearer plaintext.
#[derive(Debug)]
pub enum EnrollmentTokenIssueResult {
    Issued(IssuedEnrollmentToken),
    Replayed(EnrollmentTokenRecord),
}
