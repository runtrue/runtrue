use crate::GuestError;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const GUEST_PROTOCOL_VERSION: u32 = 1;
pub const MAX_GUEST_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_GUEST_CAPSULE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_GUEST_MOUNTS: usize = 256;
pub const MAX_SECRET_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const MAX_OIDC_TOKEN_BYTES: usize = 64 * 1024;
pub const MAX_LOG_FRAME_BYTES: usize = 64 * 1024;
pub const GUEST_BOOT_CONFIG_VERSION: u32 = 1;
pub const MAX_GUEST_BOOT_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedEnvelope {
    pub protocol_version: u32,
    pub session_id: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub authentication_tag: Vec<u8>,
}

impl fmt::Debug for AuthenticatedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedEnvelope")
            .field("protocol_version", &self.protocol_version)
            .field("session_id", &self.session_id)
            .field("sequence", &self.sequence)
            .field("payload_bytes", &self.payload.len())
            .field("authentication_tag", &"<redacted>")
            .finish()
    }
}

pub(crate) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), GuestError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(GuestError::InvalidIdentifier(kind));
    }
    Ok(())
}
