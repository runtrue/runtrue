use crate::{
    validation::canonical_bytes, BisimError, MAX_BISIM_CANARY_BYTES, MIN_BISIM_CANARY_BYTES,
};
use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use runtrue_engine::ExecutionResult;
use std::fmt;
use zeroize::{Zeroize as _, Zeroizing};

/// A high-entropy value deliberately inserted into broker tests. It is never
/// serializable or printable and is zeroized on drop.
pub struct SecretCanary(Zeroizing<Vec<u8>>);

impl SecretCanary {
    pub fn new(mut value: Vec<u8>) -> Result<Self, BisimError> {
        if !(MIN_BISIM_CANARY_BYTES..=MAX_BISIM_CANARY_BYTES).contains(&value.len()) {
            let length = value.len();
            value.zeroize();
            return Err(BisimError::InvalidCanarySize(length));
        }
        Ok(Self(Zeroizing::new(value)))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretCanary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCanary(<redacted>)")
    }
}

pub(crate) fn scan_result_secrets(
    result: &ExecutionResult,
    canaries: &[SecretCanary],
) -> Result<(), BisimError> {
    let encoded = canonical_bytes(result)?;
    scan_secret_bytes("serialized execution result", &encoded, canaries)?;
    for job in result.jobs.values() {
        for attempt in &job.attempts {
            for step in attempt.steps.iter().chain(&attempt.finalizers) {
                if let Some(output) = &step.output {
                    scan_secret_text("step stdout", &output.stdout, canaries)?;
                    scan_secret_text("step stderr", &output.stderr, canaries)?;
                }
                if let Some(error) = &step.error {
                    scan_secret_text("step error", error, canaries)?;
                }
            }
        }
    }
    Ok(())
}

fn scan_secret_text(
    surface: &'static str,
    text: &str,
    canaries: &[SecretCanary],
) -> Result<(), BisimError> {
    scan_secret_bytes(surface, text.as_bytes(), canaries)?;
    for canary in canaries {
        let variants = [
            hex::encode(canary.as_bytes()),
            Base64::encode_string(canary.as_bytes()),
            Base64UrlUnpadded::encode_string(canary.as_bytes()),
        ];
        if variants.iter().any(|encoded| text.contains(encoded)) {
            return Err(BisimError::SecretCanaryLeak { surface });
        }
    }
    Ok(())
}

pub(crate) fn scan_secret_bytes(
    surface: &'static str,
    bytes: &[u8],
    canaries: &[SecretCanary],
) -> Result<(), BisimError> {
    for canary in canaries {
        if bytes
            .windows(canary.as_bytes().len())
            .any(|window| window == canary.as_bytes())
        {
            return Err(BisimError::SecretCanaryLeak { surface });
        }
    }
    Ok(())
}
