//! Cryptographic boundary for one-shot runner secret delivery.
//!
//! Wire version 1 uses ephemeral X25519, HKDF-SHA-256, and
//! XChaCha20-Poly1305. The complete execution binding is length-prefixed into
//! authenticated data and HKDF info. No digest is interpreted as a key.

use chacha20poly1305::{
    aead::{Aead as _, Payload},
    KeyInit as _, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore as _};
use runtrue_secrets::SecretPlaintext;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(crate) const ENVELOPE_DELIVERY_KIND: &str = "x25519-hkdf-sha256-xchacha20poly1305-v1";
const ENVELOPE_MAGIC: &[u8; 8] = b"ANVSEC01";
const ENVELOPE_DOMAIN: &[u8] = b"runtrue.runner.secret-envelope.v1\0";
const X25519_KEY_BYTES: usize = 32;
const XCHACHA_NONCE_BYTES: usize = 24;

pub(crate) struct SecretEnvelopeBinding<'a> {
    pub execution_lease_id: &'a str,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub job_id: &'a str,
    pub job_attempt: u32,
    pub step_id: &'a str,
    pub secret_lease_id: &'a str,
    pub secret_metadata_id: &'a str,
    pub purpose: &'a str,
    pub expires_unix_ms: u64,
}

impl SecretEnvelopeBinding<'_> {
    fn aad(&self) -> Result<Vec<u8>, SecretEnvelopeError> {
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

pub(crate) struct SecretEnvelopeSealer {
    ephemeral_public_key: [u8; X25519_KEY_BYTES],
    shared_secret: Zeroizing<[u8; X25519_KEY_BYTES]>,
    nonce: [u8; XCHACHA_NONCE_BYTES],
}

impl SecretEnvelopeSealer {
    pub(crate) fn new(
        guest_session_public_key: [u8; X25519_KEY_BYTES],
    ) -> Result<Self, SecretEnvelopeError> {
        let mut scalar = Zeroizing::new([0_u8; X25519_KEY_BYTES]);
        OsRng
            .try_fill_bytes(scalar.as_mut())
            .map_err(|_| SecretEnvelopeError::RandomnessUnavailable)?;
        let ephemeral_secret = StaticSecret::from(*scalar);
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret).to_bytes();
        let peer = PublicKey::from(guest_session_public_key);
        let shared_secret = Zeroizing::new(ephemeral_secret.diffie_hellman(&peer).to_bytes());
        if shared_secret.iter().all(|byte| *byte == 0) {
            return Err(SecretEnvelopeError::InvalidGuestKey);
        }
        let mut nonce = [0_u8; XCHACHA_NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| SecretEnvelopeError::RandomnessUnavailable)?;
        Ok(Self {
            ephemeral_public_key,
            shared_secret,
            nonce,
        })
    }

    pub(crate) fn seal(
        self,
        binding: &SecretEnvelopeBinding<'_>,
        plaintext: &SecretPlaintext,
    ) -> Result<Vec<u8>, SecretEnvelopeError> {
        let aad = binding.aad()?;
        let hkdf = Hkdf::<Sha256>::new(Some(ENVELOPE_DOMAIN), self.shared_secret.as_slice());
        let mut info = Vec::with_capacity(ENVELOPE_DOMAIN.len() + aad.len());
        info.extend_from_slice(ENVELOPE_DOMAIN);
        info.extend_from_slice(&aad);
        let mut key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, key.as_mut())
            .map_err(|_| SecretEnvelopeError::KeyDerivation)?;
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretEnvelopeError::Encryption)?;
        let capacity = ENVELOPE_MAGIC
            .len()
            .checked_add(X25519_KEY_BYTES)
            .and_then(|size| size.checked_add(XCHACHA_NONCE_BYTES))
            .and_then(|size| size.checked_add(ciphertext.len()))
            .ok_or(SecretEnvelopeError::EnvelopeTooLarge)?;
        let mut envelope = Vec::with_capacity(capacity);
        envelope.extend_from_slice(ENVELOPE_MAGIC);
        envelope.extend_from_slice(&self.ephemeral_public_key);
        envelope.extend_from_slice(&self.nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SecretEnvelopeError> {
    let length = u32::try_from(value.len()).map_err(|_| SecretEnvelopeError::BindingTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum SecretEnvelopeError {
    #[error("guest session X25519 public key is invalid or low order")]
    InvalidGuestKey,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("secret envelope binding exceeds its encoded bound")]
    BindingTooLarge,
    #[error("secret envelope key derivation failed")]
    KeyDerivation,
    #[error("secret envelope encryption failed")]
    Encryption,
    #[error("secret envelope is too large")]
    EnvelopeTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    const TAG_BYTES: usize = 16;

    fn binding<'a>() -> SecretEnvelopeBinding<'a> {
        SecretEnvelopeBinding {
            execution_lease_id: "lease-1",
            fencing_generation: 7,
            installation_fencing_epoch: 3,
            job_id: "job-1",
            job_attempt: 1,
            step_id: "publish",
            secret_lease_id: "secret-lease-1",
            secret_metadata_id: "secret-1",
            purpose: "publish",
            expires_unix_ms: 99_000,
        }
    }

    fn decrypt(
        envelope: &[u8],
        guest_secret: &StaticSecret,
        binding: &SecretEnvelopeBinding<'_>,
    ) -> Result<Vec<u8>, ()> {
        if envelope.len()
            < ENVELOPE_MAGIC.len() + X25519_KEY_BYTES + XCHACHA_NONCE_BYTES + TAG_BYTES
            || &envelope[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC
        {
            return Err(());
        }
        let key_start = ENVELOPE_MAGIC.len();
        let nonce_start = key_start + X25519_KEY_BYTES;
        let ciphertext_start = nonce_start + XCHACHA_NONCE_BYTES;
        let ephemeral: [u8; X25519_KEY_BYTES] = envelope[key_start..nonce_start]
            .try_into()
            .map_err(|_| ())?;
        let shared = Zeroizing::new(
            guest_secret
                .diffie_hellman(&PublicKey::from(ephemeral))
                .to_bytes(),
        );
        let aad = binding.aad().map_err(|_| ())?;
        let hkdf = Hkdf::<Sha256>::new(Some(ENVELOPE_DOMAIN), shared.as_slice());
        let mut info = Vec::new();
        info.extend_from_slice(ENVELOPE_DOMAIN);
        info.extend_from_slice(&aad);
        let mut key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, key.as_mut()).map_err(|_| ())?;
        XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(
                XNonce::from_slice(&envelope[nonce_start..ciphertext_start]),
                Payload {
                    msg: &envelope[ciphertext_start..],
                    aad: &aad,
                },
            )
            .map_err(|_| ())
    }

    #[test]
    fn envelope_requires_exact_key_aad_and_ciphertext() {
        let guest_secret = StaticSecret::random_from_rng(OsRng);
        let guest_public = PublicKey::from(&guest_secret).to_bytes();
        let plaintext = SecretPlaintext::new(b"not-in-diagnostics".to_vec());
        let envelope = SecretEnvelopeSealer::new(guest_public)
            .unwrap()
            .seal(&binding(), &plaintext)
            .unwrap();
        assert_eq!(
            decrypt(&envelope, &guest_secret, &binding()).unwrap(),
            b"not-in-diagnostics"
        );

        let wrong_secret = StaticSecret::random_from_rng(OsRng);
        assert!(decrypt(&envelope, &wrong_secret, &binding()).is_err());
        let mut wrong_binding = binding();
        wrong_binding.step_id = "other";
        assert!(decrypt(&envelope, &guest_secret, &wrong_binding).is_err());
        let mut tampered = envelope;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt(&tampered, &guest_secret, &binding()).is_err());
    }

    #[test]
    fn low_order_guest_key_is_rejected() {
        assert_eq!(
            SecretEnvelopeSealer::new([0_u8; X25519_KEY_BYTES]).err(),
            Some(SecretEnvelopeError::InvalidGuestKey)
        );
    }
}
