pub(crate) struct StreamingRedactor {
    secrets: SecretSet,
    pending: Vec<u8>,
}

impl StreamingRedactor {
    pub(crate) fn new(secrets: SecretSet) -> Self {
        Self {
            secrets,
            pending: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> (Vec<u8>, bool) {
        if self.secrets.is_empty() {
            return (bytes.to_vec(), false);
        }
        let mut combined = Zeroizing::new(std::mem::take(&mut self.pending));
        combined.extend_from_slice(bytes);
        let retained = longest_secret_prefix_suffix(&combined, self.secrets.patterns());
        let safe_length = combined.len().saturating_sub(retained);
        let (output, redacted) = redact_complete(&combined[..safe_length], self.secrets.patterns());
        self.pending.extend_from_slice(&combined[safe_length..]);
        (output, redacted)
    }

    pub(crate) fn finish(&mut self) -> (Vec<u8>, bool) {
        let pending = Zeroizing::new(std::mem::take(&mut self.pending));
        redact_complete(&pending, self.secrets.patterns())
    }
}

impl Drop for StreamingRedactor {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

fn longest_secret_prefix_suffix(bytes: &[u8], secrets: &[SecretPattern]) -> usize {
    let maximum = secrets
        .iter()
        .map(SecretPattern::len)
        .max()
        .unwrap_or(0)
        .saturating_sub(1)
        .min(bytes.len());
    (1..=maximum)
        .rev()
        .find(|length| {
            let suffix = &bytes[bytes.len() - *length..];
            secrets
                .iter()
                .any(|secret| *length < secret.len() && secret.as_slice().starts_with(suffix))
        })
        .unwrap_or(0)
}

fn redact_complete(bytes: &[u8], secrets: &[SecretPattern]) -> (Vec<u8>, bool) {
    if secrets.is_empty() {
        return (bytes.to_vec(), false);
    }
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    let mut redacted = false;
    while index < bytes.len() {
        let matched = secrets
            .iter()
            .find(|secret| bytes[index..].starts_with(secret.as_slice()));
        if let Some(secret) = matched {
            output.extend_from_slice(REDACTION_MARKER);
            index += secret.len();
            redacted = true;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    (output, redacted)
}
use crate::{pipeline::REDACTION_MARKER, secrets::SecretPattern, SecretSet};
use zeroize::{Zeroize as _, Zeroizing};
