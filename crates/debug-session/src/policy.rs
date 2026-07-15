use crate::{DebugSessionError, TranscriptMode};

pub(crate) const MAX_DURATION_MS: u64 = 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugSessionPolicy {
    pub production_enabled: bool,
    pub public_untrusted_enabled: bool,
    pub secret_retention_enabled: bool,
    pub maximum_duration_ms: u64,
    pub recent_mfa_maximum_age_ms: u64,
    pub recent_reauthentication_maximum_age_ms: u64,
    pub transcript_mode: TranscriptMode,
}

impl Default for DebugSessionPolicy {
    fn default() -> Self {
        Self {
            production_enabled: false,
            public_untrusted_enabled: false,
            secret_retention_enabled: false,
            maximum_duration_ms: 30 * 60 * 1000,
            recent_mfa_maximum_age_ms: 5 * 60 * 1000,
            recent_reauthentication_maximum_age_ms: 5 * 60 * 1000,
            transcript_mode: TranscriptMode::MetadataOnly,
        }
    }
}

impl DebugSessionPolicy {
    pub(crate) fn validate(self) -> Result<Self, DebugSessionError> {
        if self.maximum_duration_ms == 0
            || self.maximum_duration_ms > MAX_DURATION_MS
            || self.recent_mfa_maximum_age_ms == 0
            || self.recent_reauthentication_maximum_age_ms == 0
        {
            return Err(DebugSessionError::InvalidConfiguration);
        }
        Ok(self)
    }
}
