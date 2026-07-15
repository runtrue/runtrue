use crate::{
    canonical_bytes, SignatureEnvelope, SigningError, ENVELOPE_VERSION, MAX_SIGNATURE_BYTES,
};
use runtrue_model::ContentDigest;

pub(super) const MAX_LEDGER_ENVELOPE_BYTES: usize = 1024 * 1024;
pub(super) fn validate_envelope_for_ledger(
    request_id: &str,
    request_digest: &ContentDigest,
    envelope: &SignatureEnvelope,
) -> Result<(), SigningError> {
    if envelope.version != ENVELOPE_VERSION
        || envelope.request_id != request_id
        || envelope.request_digest != *request_digest
        || envelope.signature.is_empty()
        || envelope.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(SigningError::Ledger);
    }
    Ok(())
}
pub(super) fn canonical_envelope_bytes(
    envelope: &SignatureEnvelope,
) -> Result<Vec<u8>, SigningError> {
    let bytes = canonical_bytes(envelope)?;
    if bytes.len() > MAX_LEDGER_ENVELOPE_BYTES {
        return Err(SigningError::Ledger);
    }
    Ok(bytes)
}
