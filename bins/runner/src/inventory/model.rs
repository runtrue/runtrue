#[derive(Debug, Clone)]
pub struct VerifiedInventory {
    pub profile: VerifiedRunnerProfile,
    pub wire: v1::RunnerInventory,
    pub binary_digest: ContentDigest,
}

#[derive(Debug, Clone)]
pub struct TrustedCapsuleKeys {
    pub store: CapsuleTrustStore,
    pub key_ids: Vec<ContentDigest>,
}

use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_runner_core::{CapsuleTrustStore, VerifiedRunnerProfile};
