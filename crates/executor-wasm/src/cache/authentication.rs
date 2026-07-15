use std::fmt;
use zeroize::Zeroize;
pub struct AotAuthenticationKey(pub(super) [u8; 32]);

impl AotAuthenticationKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Drop for AotAuthenticationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for AotAuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AotAuthenticationKey(<redacted>)")
    }
}
