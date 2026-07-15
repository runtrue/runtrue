use crate::{
    protocol::{validate_identifier, GUEST_BOOT_CONFIG_VERSION, GUEST_PROTOCOL_VERSION},
    GuestError,
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fmt, path::PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub(crate) type HmacSha256 = Hmac<Sha256>;

/// One-time boot secret. It is never serializable, cloneable, or printable.
pub struct GuestSessionKey([u8; 32]);

impl GuestSessionKey {
    pub fn generate() -> Result<Self, GuestError> {
        let mut key = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .map_err(|_| GuestError::RandomnessUnavailable)?;
        Ok(Self(key))
    }

    #[must_use]
    pub const fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub(crate) fn authenticator(&self) -> Result<HmacSha256, GuestError> {
        HmacSha256::new_from_slice(&self.0).map_err(|_| GuestError::AuthenticationUnavailable)
    }
}

impl Drop for GuestSessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for GuestSessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuestSessionKey(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestBootstrap {
    pub protocol_version: u32,
    pub session_id: String,
    pub lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub job_id: String,
    pub capsule_digest: ContentDigest,
    pub guest_image_digest: ContentDigest,
    pub expires_unix_ms: u64,
}

impl GuestBootstrap {
    pub(crate) fn validate(&self, now_unix_ms: u64) -> Result<(), GuestError> {
        if self.protocol_version != GUEST_PROTOCOL_VERSION {
            return Err(GuestError::UnsupportedProtocol(self.protocol_version));
        }
        validate_identifier("session id", &self.session_id)?;
        validate_identifier("lease id", &self.lease_id)?;
        validate_identifier("job id", &self.job_id)?;
        if self.fencing_generation == 0
            || self.installation_fencing_epoch == 0
            || now_unix_ms >= self.expires_unix_ms
        {
            return Err(GuestError::InvalidBootstrap);
        }
        Ok(())
    }
}

/// Protected boot-drive document shared by the host image builder and guest.
/// The session key is deliberately redacted from Debug and zeroized on drop.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestBootConfig {
    pub config_version: u32,
    pub bootstrap: GuestBootstrap,
    session_key_hex: String,
    pub capsule_trust_directory: PathBuf,
    pub vsock_port: u32,
}

impl GuestBootConfig {
    pub fn new(
        bootstrap: GuestBootstrap,
        session_key: &[u8; 32],
        capsule_trust_directory: impl Into<PathBuf>,
        vsock_port: u32,
    ) -> Result<Self, GuestError> {
        let config = Self {
            config_version: GUEST_BOOT_CONFIG_VERSION,
            bootstrap,
            session_key_hex: hex::encode(session_key),
            capsule_trust_directory: capsule_trust_directory.into(),
            vsock_port,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), GuestError> {
        if self.config_version != GUEST_BOOT_CONFIG_VERSION
            || self.vsock_port < 1024
            || self.session_key_hex.len() != 64
            || !self
                .session_key_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !self.capsule_trust_directory.is_absolute()
        {
            return Err(GuestError::InvalidBootConfiguration);
        }
        Ok(())
    }

    /// Decode the one-time key and immediately erase its textual form.
    pub fn take_session_key(&mut self) -> Result<GuestSessionKey, GuestError> {
        self.validate()?;
        let decoded = Zeroizing::new(
            hex::decode(&self.session_key_hex).map_err(|_| GuestError::InvalidBootConfiguration)?,
        );
        self.session_key_hex.zeroize();
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| GuestError::InvalidBootConfiguration)?;
        Ok(GuestSessionKey::from_bytes(bytes))
    }
}

impl Drop for GuestBootConfig {
    fn drop(&mut self) {
        self.session_key_hex.zeroize();
    }
}

impl fmt::Debug for GuestBootConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestBootConfig")
            .field("config_version", &self.config_version)
            .field("bootstrap", &self.bootstrap)
            .field("session_key_hex", &"<redacted>")
            .field("capsule_trust_directory", &self.capsule_trust_directory)
            .field("vsock_port", &self.vsock_port)
            .finish()
    }
}
