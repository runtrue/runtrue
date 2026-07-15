//! Envelope encryption, authenticated wrapping, and randomness.
use super::model::{SecretIdentity, WrappedDek, DEK_AAD_DOMAIN, NONCE_BYTES};
use super::SecretsError;
use crate::{sensitive::KEY_BYTES, MasterKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use std::fmt;
use zeroize::Zeroizing;
pub(super) struct DataEncryptionKey(Zeroizing<[u8; KEY_BYTES]>);

impl DataEncryptionKey {
    pub(super) fn generate() -> Result<Self, SecretsError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        OsRng
            .try_fill_bytes(&mut *bytes)
            .map_err(|_| SecretsError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    pub(super) fn from_plaintext(bytes: Vec<u8>) -> Result<Self, SecretsError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != KEY_BYTES {
            return Err(SecretsError::InvalidWrappedKeyLength(bytes.len()));
        }
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    pub(super) fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DataEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataEncryptionKey([REDACTED])")
    }
}
pub(super) fn wrap_dek(
    dek: &DataEncryptionKey,
    identity: &SecretIdentity,
    version: u64,
    kek_id: &str,
    master_key: &MasterKey,
) -> Result<WrappedDek, SecretsError> {
    let nonce = random_array()?;
    let aad = associated_data(DEK_AAD_DOMAIN, identity, version, Some(kek_id));
    let ciphertext = encrypt_aead(master_key.as_bytes(), &nonce, dek.as_bytes(), &aad)?;
    Ok(WrappedDek {
        kek_id: kek_id.to_owned(),
        nonce,
        ciphertext,
    })
}

pub(super) fn unwrap_dek(
    wrapped: &WrappedDek,
    identity: &SecretIdentity,
    version: u64,
    master_key: &MasterKey,
) -> Result<DataEncryptionKey, SecretsError> {
    let aad = associated_data(DEK_AAD_DOMAIN, identity, version, Some(&wrapped.kek_id));
    let plaintext = decrypt_aead(
        master_key.as_bytes(),
        &wrapped.nonce,
        &wrapped.ciphertext,
        &aad,
    )?;
    DataEncryptionKey::from_plaintext(plaintext)
}

pub(super) fn encrypt_aead(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SecretsError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| SecretsError::EncryptionFailed)?;
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SecretsError::EncryptionFailed)
}

pub(super) fn decrypt_aead(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SecretsError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| SecretsError::AuthenticationFailed)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SecretsError::AuthenticationFailed)
}

pub(super) fn associated_data(
    domain: &[u8],
    identity: &SecretIdentity,
    version: u64,
    kek_id: Option<&str>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        domain.len()
            + identity.tenant_id().len()
            + identity.scope().len()
            + identity.name().len()
            + kek_id.map_or(0, str::len)
            + 48,
    );
    aad.extend_from_slice(domain);
    append_aad_field(&mut aad, identity.tenant_id().as_bytes());
    append_aad_field(&mut aad, identity.scope().as_bytes());
    append_aad_field(&mut aad, identity.name().as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    if let Some(kek_id) = kek_id {
        append_aad_field(&mut aad, kek_id.as_bytes());
    }
    aad
}

pub(super) fn append_aad_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

pub(super) fn random_array<const N: usize>() -> Result<[u8; N], SecretsError> {
    let mut bytes = [0_u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SecretsError::RandomnessUnavailable)?;
    Ok(bytes)
}
