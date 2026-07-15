use crate::WasmError;
use hmac::{Hmac, Mac as _};
use runtrue_engine::StepExecutionRequest;
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;
pub struct HandleAuthenticationKey([u8; 32]);

impl HandleAuthenticationKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn derive(
        &self,
        domain: &[u8],
        request: &StepExecutionRequest,
        grant: &[u8],
        nonce: u64,
    ) -> Result<u64, WasmError> {
        let mut mac = HmacSha256::new_from_slice(&self.0)
            .map_err(|_| WasmError::InvalidConfiguration("invalid handle key".to_owned()))?;
        mac.update(b"runtrue.wasm-handle.v1\0");
        mac.update(domain);
        mac.update(request.job_id.as_bytes());
        mac.update(&[0]);
        mac.update(request.step_id.as_bytes());
        mac.update(&request.job_attempt.to_be_bytes());
        mac.update(grant);
        mac.update(&nonce.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&tag[..8]);
        let value = u64::from_be_bytes(bytes);
        Ok(if value == 0 { 1 } else { value })
    }
}

impl Drop for HandleAuthenticationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for HandleAuthenticationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandleAuthenticationKey(<redacted>)")
    }
}
