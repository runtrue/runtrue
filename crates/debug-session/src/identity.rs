use crate::DebugSessionError;
use runtrue_model::ContentDigest;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentityRequest {
    pub session_id: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub approval_id: String,
    pub subject_digest: ContentDigest,
    pub expires_unix_ms: u64,
}

pub struct EphemeralClientIdentity {
    pub certificate_serial: String,
    pub certificate_pem: Zeroizing<String>,
    pub private_key_pem: Zeroizing<String>,
}

impl fmt::Debug for EphemeralClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralClientIdentity")
            .field("certificate_serial", &self.certificate_serial)
            .field("certificate_pem", &"[REDACTED]")
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

pub trait EphemeralIdentityIssuer {
    fn issue(
        &mut self,
        request: &ClientIdentityRequest,
    ) -> Result<EphemeralClientIdentity, DebugSessionError>;
}
