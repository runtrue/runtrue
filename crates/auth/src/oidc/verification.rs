use super::claims::{BeginOidcExchange, OidcAuthorizationTransaction, OidcTransactionStatus};
use crate::{token::TokenKind, AuthError, TokenHasher};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sha2::{Digest as _, Sha256};

pub(crate) fn pkce_challenge(verifier: &str) -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()))
}

impl OidcAuthorizationTransaction {
    /// Verify the callback and reserve its one token exchange opportunity.
    /// Exact replay observes `Exchanging` or a terminal status and is denied.
    pub fn begin_exchange(
        &mut self,
        hasher: &TokenHasher,
        request: BeginOidcExchange<'_>,
    ) -> Result<(), AuthError> {
        self.validate()?;
        if self.status != OidcTransactionStatus::Pending {
            return Err(AuthError::OidcTransactionAlreadyUsed);
        }
        if request.now_unix_ms < self.created_unix_ms {
            return Err(AuthError::InvalidOidcTransactionTime);
        }
        if request.now_unix_ms >= self.expires_unix_ms {
            self.status = OidcTransactionStatus::Expired;
            self.finished_unix_ms = Some(request.now_unix_ms);
            return Err(AuthError::Expired);
        }
        if request.tenant_id != self.tenant_id
            || request.provider_configuration_id != self.provider_configuration_id
            || request.issuer != self.issuer
            || request.client_id != self.client_id
            || request.redirect_uri != self.redirect_uri
        {
            return Err(AuthError::OidcBindingMismatch);
        }
        if !hasher.verify(TokenKind::OidcState, request.state, &self.state_digest) {
            return Err(AuthError::InvalidCredential);
        }
        if !hasher.verify(
            TokenKind::OidcPkceVerifier,
            request.pkce_verifier,
            &self.pkce_verifier_digest,
        ) || pkce_challenge(request.pkce_verifier) != self.pkce_challenge
        {
            return Err(AuthError::OidcPkceMismatch);
        }
        self.status = OidcTransactionStatus::Exchanging;
        self.exchange_started_unix_ms = Some(request.now_unix_ms);
        Ok(())
    }

    /// Terminally reject a callback that failed its state, PKCE, or exact
    /// provider binding before any token exchange was attempted. Recording the
    /// bounded callback attempt timestamps makes this distinct from an
    /// exchange reservation while preserving one-use recovery semantics.
    pub fn reject_callback(&mut self, now_unix_ms: u64) -> Result<(), AuthError> {
        self.validate()?;
        if self.status != OidcTransactionStatus::Pending {
            return Err(AuthError::OidcTransactionAlreadyUsed);
        }
        if now_unix_ms < self.created_unix_ms {
            return Err(AuthError::InvalidOidcTransactionTime);
        }
        if now_unix_ms >= self.expires_unix_ms {
            return Err(AuthError::Expired);
        }
        self.status = OidcTransactionStatus::Rejected;
        self.exchange_started_unix_ms = Some(now_unix_ms);
        self.finished_unix_ms = Some(now_unix_ms);
        Ok(())
    }

    /// Finish only after the adapter has verified the ID-token signature,
    /// issuer, audience, and time claims. A nonce mismatch is terminal.
    pub fn finish_identity(
        &mut self,
        hasher: &TokenHasher,
        id_token_nonce: &str,
        now_unix_ms: u64,
    ) -> Result<(), AuthError> {
        self.validate()?;
        if self.status != OidcTransactionStatus::Exchanging {
            return Err(AuthError::OidcTransactionNotExchanging);
        }
        if now_unix_ms >= self.expires_unix_ms {
            self.status = OidcTransactionStatus::Expired;
            self.finished_unix_ms = Some(now_unix_ms);
            return Err(AuthError::Expired);
        }
        if now_unix_ms
            < self
                .exchange_started_unix_ms
                .unwrap_or(self.created_unix_ms)
        {
            return Err(AuthError::InvalidOidcTransactionTime);
        }
        if !hasher.verify(TokenKind::OidcNonce, id_token_nonce, &self.nonce_digest) {
            self.status = OidcTransactionStatus::Rejected;
            self.finished_unix_ms = Some(now_unix_ms);
            return Err(AuthError::OidcNonceMismatch);
        }
        self.status = OidcTransactionStatus::Consumed;
        self.finished_unix_ms = Some(now_unix_ms);
        Ok(())
    }
}
