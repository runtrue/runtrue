use crate::{DebugSessionError, TunnelTokenDigest};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelDirection {
    ReverseOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRegistration {
    pub session_id: String,
    pub tenant_id: String,
    pub run_id: String,
    pub job_id: String,
    pub direction: TunnelDirection,
    pub public_runner_listener: bool,
    pub tunnel_token_digest: TunnelTokenDigest,
    pub certificate_serial: String,
    pub expires_unix_ms: u64,
}

pub trait DebugRelay {
    fn register_reverse_tunnel(
        &mut self,
        registration: &RelayRegistration,
    ) -> Result<ContentDigest, DebugSessionError>;

    fn revoke(&mut self, session_id: &str) -> Result<(), DebugSessionError>;
}
