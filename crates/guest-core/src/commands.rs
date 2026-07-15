use runtrue_attest::CapsuleSignature;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostCommand {
    StartJob {
        canonical_capsule: Vec<u8>,
        signature: CapsuleSignature,
    },
    Mount(MountDescriptor),
    StartStep {
        step_id: String,
        attempt: u32,
        capability_digest: ContentDigest,
    },
    SignalStep {
        step_id: String,
        signal: StepSignal,
    },
    Secret(SecretEnvelope),
    Oidc(OidcEnvelope),
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepSignal {
    Cancel,
    Terminate,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountPurpose {
    Workspace,
    Input,
    Cache,
    Artifact,
    Toolchain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountDescriptor {
    pub mount_id: String,
    pub guest_path: String,
    pub content_digest: ContentDigest,
    pub read_only: bool,
    pub purpose: MountPurpose,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEnvelope {
    pub step_id: String,
    pub metadata_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub expires_unix_ms: u64,
    /// Ciphertext is opaque to protocol framing; the guest's delivery adapter
    /// decrypts it into a memory-backed file, sealed fd, or explicit handle.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SecretEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvelope")
            .field("step_id", &self.step_id)
            .field("metadata_id", &self.metadata_id)
            .field("name", &self.name)
            .field("purpose", &self.purpose)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcEnvelope {
    pub step_id: String,
    pub audience: String,
    pub expires_unix_ms: u64,
    pub token: String,
}

impl fmt::Debug for OidcEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcEnvelope")
            .field("step_id", &self.step_id)
            .field("audience", &self.audience)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("token", &"<redacted>")
            .finish()
    }
}
