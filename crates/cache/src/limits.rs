use crate::CacheError;

/// Bounds for cache-controlled metadata. Content bounds remain enforced by
/// the underlying CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLimits {
    pub max_manifest_bytes: u64,
    pub max_head_bytes: u64,
    pub max_head_records: usize,
    pub max_identifier_bytes: usize,
    pub max_ticket_bytes: u64,
    pub max_ticket_lifetime_seconds: u64,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 1024 * 1024,
            max_head_bytes: 64 * 1024,
            max_head_records: 100_000,
            max_identifier_bytes: 512,
            max_ticket_bytes: 64 * 1024,
            max_ticket_lifetime_seconds: 60 * 60,
        }
    }
}

impl CacheLimits {
    pub(crate) fn validate(self) -> Result<Self, CacheError> {
        if self.max_manifest_bytes == 0
            || self.max_head_bytes == 0
            || self.max_head_records == 0
            || self.max_identifier_bytes == 0
            || self.max_ticket_bytes == 0
            || self.max_ticket_lifetime_seconds == 0
        {
            return Err(CacheError::InvalidConfiguration(
                "all cache limits must be greater than zero".to_owned(),
            ));
        }
        Ok(self)
    }
}
