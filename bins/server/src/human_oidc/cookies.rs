use crate::human_oidc::{HumanOidcError, MAX_SEALED_COOKIE_BYTES};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chacha20poly1305::{
    aead::{Aead as _, Payload},
    KeyInit as _, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore as _};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt;
use zeroize::Zeroizing;

const SEALED_COOKIE_VERSION: u8 = 1;
const SEALED_COOKIE_NONCE_BYTES: usize = 24;

/// AEAD envelope for OIDC transaction and session cookies. Associated data is
/// the exact cookie name, preventing cross-cookie substitution.
pub struct CookieSealer {
    cipher: XChaCha20Poly1305,
}

impl fmt::Debug for CookieSealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CookieSealer([REDACTED])")
    }
}

impl CookieSealer {
    pub fn new(key: &[u8; 32]) -> Result<Self, HumanOidcError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| HumanOidcError::InvalidConfiguration)?;
        Ok(Self { cipher })
    }

    pub fn seal<T: Serialize>(
        &self,
        cookie_name: &str,
        value: &T,
    ) -> Result<String, HumanOidcError> {
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext.push(SEALED_COOKIE_VERSION);
        serde_json::to_writer(&mut *plaintext, value).map_err(|_| HumanOidcError::InvalidCookie)?;
        let mut nonce = [0_u8; SEALED_COOKIE_NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| HumanOidcError::RandomnessUnavailable)?;
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: cookie_name.as_bytes(),
                },
            )
            .map_err(|_| HumanOidcError::InvalidCookie)?;
        let mut envelope = Vec::with_capacity(nonce.len() + ciphertext.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        let encoded = Base64UrlUnpadded::encode_string(&envelope);
        if encoded.len() > MAX_SEALED_COOKIE_BYTES {
            return Err(HumanOidcError::CookieTooLarge);
        }
        Ok(encoded)
    }

    pub fn open<T: DeserializeOwned>(
        &self,
        cookie_name: &str,
        value: &str,
    ) -> Result<T, HumanOidcError> {
        if value.is_empty() || value.len() > MAX_SEALED_COOKIE_BYTES {
            return Err(HumanOidcError::InvalidCookie);
        }
        let envelope =
            Base64UrlUnpadded::decode_vec(value).map_err(|_| HumanOidcError::InvalidCookie)?;
        if envelope.len() <= SEALED_COOKIE_NONCE_BYTES {
            return Err(HumanOidcError::InvalidCookie);
        }
        let plaintext = Zeroizing::new(
            self.cipher
                .decrypt(
                    XNonce::from_slice(&envelope[..SEALED_COOKIE_NONCE_BYTES]),
                    Payload {
                        msg: &envelope[SEALED_COOKIE_NONCE_BYTES..],
                        aad: cookie_name.as_bytes(),
                    },
                )
                .map_err(|_| HumanOidcError::InvalidCookie)?,
        );
        if plaintext.first().copied() != Some(SEALED_COOKIE_VERSION) {
            return Err(HumanOidcError::InvalidCookie);
        }
        serde_json::from_slice(&plaintext[1..]).map_err(|_| HumanOidcError::InvalidCookie)
    }
}
