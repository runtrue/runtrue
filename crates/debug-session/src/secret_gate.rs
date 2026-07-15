use crate::DebugSessionError;
use runtrue_model::ContentDigest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBlockRequest {
    pub session_id: String,
    pub tenant_id: String,
    pub run_id: String,
    pub job_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub expires_unix_ms: u64,
}

pub trait DebugSecretGate {
    /// Atomically prevent every future secret/OIDC release for the exact job
    /// and fence until at least the supplied expiration.
    fn block_future_release(
        &mut self,
        request: &SecretBlockRequest,
    ) -> Result<ContentDigest, DebugSessionError>;

    /// Revoke all live secret/OIDC leases for the exact job and fence.
    fn revoke_existing(
        &mut self,
        request: &SecretBlockRequest,
    ) -> Result<ContentDigest, DebugSessionError>;
}
