use chacha20poly1305::{
    aead::{Aead as _, Payload},
    KeyInit as _, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use runtrue_executor_wasm::CapabilityAdapterError;
use runtrue_protocol::v1;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(super) const ENVELOPE_DELIVERY_KIND: &str = "x25519-hkdf-sha256-xchacha20poly1305-v1";
pub(super) const ENVELOPE_MAGIC: &[u8; 8] = b"ANVSEC01";
pub(super) const ENVELOPE_DOMAIN: &[u8] = b"runtrue.runner.secret-envelope.v1\0";
const X25519_KEY_BYTES: usize = 32;
pub(super) const XCHACHA_NONCE_BYTES: usize = 24;
const POLY1305_TAG_BYTES: usize = 16;

pub(crate) struct SecretEnvelopeBinding<'a> {
    pub(crate) execution_lease_id: &'a str,
    pub(crate) fencing_generation: u64,
    pub(crate) installation_fencing_epoch: u64,
    pub(crate) job_id: &'a str,
    pub(crate) job_attempt: u32,
    pub(crate) step_id: &'a str,
    pub(crate) secret_lease_id: &'a str,
    pub(crate) secret_metadata_id: &'a str,
    pub(crate) purpose: &'a str,
    pub(crate) expires_unix_ms: u64,
}

impl SecretEnvelopeBinding<'_> {
    pub(super) fn aad(&self) -> Result<Vec<u8>, CapabilityAdapterError> {
        let mut aad = Vec::with_capacity(512);
        aad.extend_from_slice(ENVELOPE_DOMAIN);
        append_field(&mut aad, self.execution_lease_id.as_bytes())?;
        append_field(&mut aad, &self.fencing_generation.to_be_bytes())?;
        append_field(&mut aad, &self.installation_fencing_epoch.to_be_bytes())?;
        append_field(&mut aad, self.job_id.as_bytes())?;
        append_field(&mut aad, &self.job_attempt.to_be_bytes())?;
        append_field(&mut aad, self.step_id.as_bytes())?;
        append_field(&mut aad, self.secret_lease_id.as_bytes())?;
        append_field(&mut aad, self.secret_metadata_id.as_bytes())?;
        append_field(&mut aad, self.purpose.as_bytes())?;
        append_field(&mut aad, &self.expires_unix_ms.to_be_bytes())?;
        Ok(aad)
    }
}

pub(crate) fn decrypt_envelope(
    response: &v1::SecretLeaseResponse,
    guest_secret: &StaticSecret,
    binding: &SecretEnvelopeBinding<'_>,
    maximum_plaintext_bytes: usize,
) -> Result<Vec<u8>, CapabilityAdapterError> {
    if response.delivery_kind != ENVELOPE_DELIVERY_KIND {
        return Err(CapabilityAdapterError::Failed(
            "secret broker selected an unsupported delivery kind".to_owned(),
        ));
    }
    let minimum =
        ENVELOPE_MAGIC.len() + X25519_KEY_BYTES + XCHACHA_NONCE_BYTES + POLY1305_TAG_BYTES;
    let maximum = minimum
        .checked_add(maximum_plaintext_bytes)
        .ok_or_else(|| CapabilityAdapterError::Failed("secret size bound overflow".to_owned()))?;
    let envelope = &response.encrypted_envelope;
    if envelope.len() < minimum
        || envelope.len() > maximum
        || &envelope[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC
    {
        return Err(CapabilityAdapterError::Failed(
            "secret broker returned an invalid envelope".to_owned(),
        ));
    }
    let key_start = ENVELOPE_MAGIC.len();
    let nonce_start = key_start + X25519_KEY_BYTES;
    let ciphertext_start = nonce_start + XCHACHA_NONCE_BYTES;
    let ephemeral: [u8; X25519_KEY_BYTES] = envelope[key_start..nonce_start]
        .try_into()
        .map_err(|_| CapabilityAdapterError::Failed("invalid secret envelope key".to_owned()))?;
    let shared = Zeroizing::new(
        guest_secret
            .diffie_hellman(&PublicKey::from(ephemeral))
            .to_bytes(),
    );
    if shared.iter().all(|byte| *byte == 0) {
        return Err(CapabilityAdapterError::Failed(
            "secret envelope uses an invalid X25519 key".to_owned(),
        ));
    }
    let aad = binding.aad()?;
    let hkdf = Hkdf::<Sha256>::new(Some(ENVELOPE_DOMAIN), shared.as_slice());
    let mut info = Vec::with_capacity(ENVELOPE_DOMAIN.len() + aad.len());
    info.extend_from_slice(ENVELOPE_DOMAIN);
    info.extend_from_slice(&aad);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut()).map_err(|_| {
        CapabilityAdapterError::Failed("secret envelope key derivation failed".to_owned())
    })?;
    XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(
            XNonce::from_slice(&envelope[nonce_start..ciphertext_start]),
            Payload {
                msg: &envelope[ciphertext_start..],
                aad: &aad,
            },
        )
        .map_err(|_| {
            CapabilityAdapterError::Failed("secret envelope authentication failed".to_owned())
        })
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CapabilityAdapterError> {
    let length = u32::try_from(value.len()).map_err(|_| {
        CapabilityAdapterError::Failed("secret envelope binding is too large".to_owned())
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub(super) fn timestamp_millis(
    value: Option<&prost_types::Timestamp>,
    field: &str,
) -> Result<u64, CapabilityAdapterError> {
    let value = value.ok_or_else(|| {
        CapabilityAdapterError::Failed(format!("broker response omitted {field}"))
    })?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(CapabilityAdapterError::Failed(format!(
            "broker response contains invalid {field}"
        )));
    }
    u64::try_from(value.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|millis| millis.checked_add(u64::from(value.nanos as u32) / 1_000_000))
        .ok_or_else(|| {
            CapabilityAdapterError::Failed(format!("broker response contains out-of-range {field}"))
        })
}

pub(super) fn validate_identifier(field: &str, value: &str) -> Result<(), CapabilityAdapterError> {
    if value.is_empty() || value.len() > 1024 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(CapabilityAdapterError::Failed(format!(
            "broker response contains invalid {field}"
        )));
    }
    Ok(())
}
