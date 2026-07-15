use crate::{
    signature_message, MetadataHeader, RoleMetadata, RoleType, RootMetadata, SignedEnvelope,
    UpdateError, MAX_SIGNATURES, MAX_STRING_BYTES,
};
use ed25519_dalek::Verifier as _;
use runtrue_model::ContentDigest;

pub(crate) fn verify_role_threshold<T: RoleMetadata>(
    envelope: &SignedEnvelope<T>,
    root: &RootMetadata,
    role: RoleType,
    allow_unassigned: bool,
) -> Result<(), UpdateError> {
    envelope.signed.validate_structure()?;
    if envelope.signed.role() != role
        || envelope.signatures.is_empty()
        || envelope.signatures.len() > MAX_SIGNATURES
        || envelope
            .signatures
            .windows(2)
            .any(|pair| pair[0].key_id >= pair[1].key_id)
    {
        return Err(UpdateError::InvalidSignatureSet);
    }
    root.validate_structure()?;
    let assignment = root
        .roles
        .get(&role)
        .ok_or(UpdateError::MissingRoleAssignment(role))?;
    let message = signature_message(role, &envelope.signed)?;
    let mut valid = 0_usize;
    for signature in &envelope.signatures {
        let parsed = signature.signature()?;
        if !assignment.key_ids.contains(&signature.key_id) {
            if allow_unassigned {
                continue;
            }
            return Err(UpdateError::SignatureKeyNotAuthorized);
        }
        let key = root
            .keys
            .get(&signature.key_id)
            .ok_or(UpdateError::SignatureKeyNotAuthorized)?
            .verifying_key()?;
        key.verify(&message, &parsed)
            .map_err(|_| UpdateError::InvalidSignature)?;
        valid += 1;
    }
    if valid < usize::from(assignment.threshold) {
        return Err(UpdateError::SignatureThresholdNotMet {
            role,
            required: assignment.threshold,
            valid,
        });
    }
    Ok(())
}

pub(crate) fn validate_chain_times(
    root: &MetadataHeader,
    targets: &MetadataHeader,
    snapshot: &MetadataHeader,
    timestamp: &MetadataHeader,
) -> Result<(), UpdateError> {
    if !(targets.issued_unix_seconds <= snapshot.issued_unix_seconds
        && snapshot.issued_unix_seconds <= timestamp.issued_unix_seconds
        && timestamp.expires_unix_seconds <= snapshot.expires_unix_seconds
        && snapshot.expires_unix_seconds <= targets.expires_unix_seconds
        && targets.expires_unix_seconds <= root.expires_unix_seconds)
    {
        return Err(UpdateError::IncoherentMetadataTimes);
    }
    Ok(())
}

pub(crate) fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_STRING_BYTES && !value.contains('\0')
}

pub(crate) fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn digest_hex(digest: &ContentDigest) -> &str {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("ContentDigest is always algorithm-qualified")
}
