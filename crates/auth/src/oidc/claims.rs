//! One-use human OIDC Authorization Code + PKCE transaction primitives.

use super::{
    config::{validate_oidc_bindings, MAX_OIDC_TRANSACTION_TTL_MS},
    verification::pkce_challenge,
};
use crate::{
    authorization::validate_identifier,
    token::{generate_token, TokenKind},
    AuthError, SecretToken, TokenDigest, TokenHasher,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcTransactionStatus {
    Pending,
    Exchanging,
    Consumed,
    Rejected,
    Expired,
}

/// Persistable login transaction. State, nonce, and PKCE verifier plaintext
/// are represented only by installation-keyed, domain-separated digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcAuthorizationTransaction {
    pub id: String,
    pub tenant_id: String,
    pub provider_configuration_id: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state_digest: TokenDigest,
    pub nonce_digest: TokenDigest,
    pub pkce_verifier_digest: TokenDigest,
    pub pkce_challenge: String,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub status: OidcTransactionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange_started_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueOidcAuthorization {
    pub id: String,
    pub tenant_id: String,
    pub provider_configuration_id: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
}

pub struct IssuedOidcAuthorization {
    pub record: OidcAuthorizationTransaction,
    pub state: SecretToken,
    pub nonce: SecretToken,
    pub pkce_verifier: SecretToken,
    pub pkce_challenge: String,
}

impl fmt::Debug for IssuedOidcAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedOidcAuthorization")
            .field("record", &self.record)
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .field("pkce_challenge", &self.pkce_challenge)
            .finish()
    }
}

pub struct BeginOidcExchange<'a> {
    pub tenant_id: &'a str,
    pub provider_configuration_id: &'a str,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub pkce_verifier: &'a str,
    pub now_unix_ms: u64,
}

impl OidcAuthorizationTransaction {
    pub fn issue(
        hasher: &TokenHasher,
        request: IssueOidcAuthorization,
    ) -> Result<IssuedOidcAuthorization, AuthError> {
        validate_identifier("OIDC transaction id", &request.id)?;
        validate_identifier("OIDC tenant id", &request.tenant_id)?;
        validate_identifier(
            "OIDC provider configuration id",
            &request.provider_configuration_id,
        )?;
        validate_oidc_bindings(&request.issuer, &request.client_id, &request.redirect_uri)?;
        if request.expires_unix_ms <= request.created_unix_ms
            || request.expires_unix_ms - request.created_unix_ms > MAX_OIDC_TRANSACTION_TTL_MS
        {
            return Err(AuthError::InvalidOidcTransactionLifetime);
        }
        let state = generate_token()?;
        let nonce = generate_token()?;
        let pkce_verifier = generate_token()?;
        let pkce_challenge = pkce_challenge(pkce_verifier.expose());
        Ok(IssuedOidcAuthorization {
            record: Self {
                id: request.id,
                tenant_id: request.tenant_id,
                provider_configuration_id: request.provider_configuration_id,
                issuer: request.issuer,
                client_id: request.client_id,
                redirect_uri: request.redirect_uri,
                state_digest: hasher.digest(TokenKind::OidcState, state.expose()),
                nonce_digest: hasher.digest(TokenKind::OidcNonce, nonce.expose()),
                pkce_verifier_digest: hasher
                    .digest(TokenKind::OidcPkceVerifier, pkce_verifier.expose()),
                pkce_challenge: pkce_challenge.clone(),
                created_unix_ms: request.created_unix_ms,
                expires_unix_ms: request.expires_unix_ms,
                status: OidcTransactionStatus::Pending,
                exchange_started_unix_ms: None,
                finished_unix_ms: None,
            },
            state,
            nonce,
            pkce_verifier,
            pkce_challenge,
        })
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        validate_identifier("OIDC transaction id", &self.id)?;
        validate_identifier("OIDC tenant id", &self.tenant_id)?;
        validate_identifier(
            "OIDC provider configuration id",
            &self.provider_configuration_id,
        )?;
        validate_oidc_bindings(&self.issuer, &self.client_id, &self.redirect_uri)?;
        if self.expires_unix_ms <= self.created_unix_ms
            || self.expires_unix_ms - self.created_unix_ms > MAX_OIDC_TRANSACTION_TTL_MS
            || self.pkce_challenge.is_empty()
            || self.pkce_challenge.len() > 128
        {
            return Err(AuthError::InvalidOidcTransactionRecord);
        }
        let timestamps_valid = match self.status {
            OidcTransactionStatus::Pending => {
                self.exchange_started_unix_ms.is_none() && self.finished_unix_ms.is_none()
            }
            OidcTransactionStatus::Exchanging => {
                self.exchange_started_unix_ms.is_some_and(|started| {
                    started >= self.created_unix_ms && started < self.expires_unix_ms
                }) && self.finished_unix_ms.is_none()
            }
            OidcTransactionStatus::Consumed | OidcTransactionStatus::Rejected => self
                .exchange_started_unix_ms
                .zip(self.finished_unix_ms)
                .is_some_and(|(started, finished)| {
                    started >= self.created_unix_ms
                        && started < self.expires_unix_ms
                        && finished >= started
                        && finished < self.expires_unix_ms
                }),
            OidcTransactionStatus::Expired => self.finished_unix_ms.is_some_and(|finished| {
                finished >= self.expires_unix_ms
                    && self
                        .exchange_started_unix_ms
                        .is_none_or(|started| started >= self.created_unix_ms)
            }),
        };
        if !timestamps_valid {
            return Err(AuthError::InvalidOidcTransactionRecord);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(hasher: &TokenHasher) -> IssuedOidcAuthorization {
        OidcAuthorizationTransaction::issue(
            hasher,
            IssueOidcAuthorization {
                id: "login-1".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                provider_configuration_id: "provider-1".to_owned(),
                issuer: "https://identity.example/tenant".to_owned(),
                client_id: "runtrue".to_owned(),
                redirect_uri: "https://runtrue.example/auth/callback".to_owned(),
                created_unix_ms: 100,
                expires_unix_ms: 500,
            },
        )
        .expect("issue")
    }

    #[test]
    fn plaintext_transaction_secrets_are_never_persisted_or_debugged() {
        let hasher = TokenHasher::from_key([4; 32]);
        let issued = issue(&hasher);
        let persisted = serde_json::to_string(&issued.record).expect("serialize");
        for secret in [
            issued.state.expose(),
            issued.nonce.expose(),
            issued.pkce_verifier.expose(),
        ] {
            assert!(!persisted.contains(secret));
            assert!(!format!("{issued:?}").contains(secret));
        }
        assert_eq!(
            issued.pkce_challenge,
            pkce_challenge(issued.pkce_verifier.expose())
        );
    }

    #[test]
    fn exact_binding_pkce_nonce_and_one_use_are_enforced() {
        let hasher = TokenHasher::from_key([4; 32]);
        let issued = issue(&hasher);
        let state = issued.state.expose().to_owned();
        let nonce = issued.nonce.expose().to_owned();
        let verifier = issued.pkce_verifier.expose().to_owned();
        let mut record = issued.record;
        record
            .begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 200,
                },
            )
            .expect("begin");
        assert!(matches!(
            record.begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 201,
                }
            ),
            Err(AuthError::OidcTransactionAlreadyUsed)
        ));
        record
            .finish_identity(&hasher, &nonce, 202)
            .expect("finish");
        assert_eq!(record.status, OidcTransactionStatus::Consumed);
        assert!(matches!(
            record.finish_identity(&hasher, &nonce, 203),
            Err(AuthError::OidcTransactionNotExchanging)
        ));
    }

    #[test]
    fn substitution_does_not_consume_but_nonce_mismatch_is_terminal() {
        let hasher = TokenHasher::from_key([4; 32]);
        let issued = issue(&hasher);
        let state = issued.state.expose().to_owned();
        let verifier = issued.pkce_verifier.expose().to_owned();
        let mut record = issued.record;
        assert!(matches!(
            record.begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: "wrong",
                    pkce_verifier: &verifier,
                    now_unix_ms: 200,
                }
            ),
            Err(AuthError::InvalidCredential)
        ));
        assert_eq!(record.status, OidcTransactionStatus::Pending);
        assert!(matches!(
            record.begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: "wrong",
                    now_unix_ms: 200,
                }
            ),
            Err(AuthError::OidcPkceMismatch)
        ));
        assert_eq!(record.status, OidcTransactionStatus::Pending);
        assert!(matches!(
            record.begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-2",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 200,
                }
            ),
            Err(AuthError::OidcBindingMismatch)
        ));
        assert_eq!(record.status, OidcTransactionStatus::Pending);
        assert!(matches!(
            record.begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-2",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 200,
                }
            ),
            Err(AuthError::OidcBindingMismatch)
        ));
        assert_eq!(record.status, OidcTransactionStatus::Pending);
        record
            .begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 201,
                },
            )
            .expect("begin");
        assert!(matches!(
            record.finish_identity(&hasher, "wrong", 202),
            Err(AuthError::OidcNonceMismatch)
        ));
        assert_eq!(record.status, OidcTransactionStatus::Rejected);
    }

    #[test]
    fn rejected_callback_is_terminal_bounded_and_not_exchangeable() {
        let hasher = TokenHasher::from_key([4; 32]);
        let issued = issue(&hasher);
        let state = issued.state.expose().to_owned();
        let verifier = issued.pkce_verifier.expose().to_owned();
        let mut record = issued.record;
        assert_eq!(
            record.reject_callback(99),
            Err(AuthError::InvalidOidcTransactionTime)
        );
        record.reject_callback(200).expect("terminal rejection");
        assert_eq!(record.status, OidcTransactionStatus::Rejected);
        assert_eq!(record.exchange_started_unix_ms, Some(200));
        assert_eq!(record.finished_unix_ms, Some(200));
        record.validate().expect("rejected record remains valid");
        assert_eq!(
            record.reject_callback(201),
            Err(AuthError::OidcTransactionAlreadyUsed)
        );
        assert_eq!(
            record.begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 201,
                }
            ),
            Err(AuthError::OidcTransactionAlreadyUsed)
        );

        let mut expired = issue(&hasher).record;
        assert_eq!(expired.reject_callback(500), Err(AuthError::Expired));
        assert_eq!(expired.status, OidcTransactionStatus::Pending);
    }

    #[test]
    fn expiry_is_bounded_and_terminal() {
        let hasher = TokenHasher::from_key([4; 32]);
        let issued = issue(&hasher);
        let state = issued.state.expose().to_owned();
        let verifier = issued.pkce_verifier.expose().to_owned();
        let mut record = issued.record;
        assert!(matches!(
            record.begin_exchange(
                &hasher,
                BeginOidcExchange {
                    tenant_id: "tenant-1",
                    provider_configuration_id: "provider-1",
                    issuer: "https://identity.example/tenant",
                    client_id: "runtrue",
                    redirect_uri: "https://runtrue.example/auth/callback",
                    state: &state,
                    pkce_verifier: &verifier,
                    now_unix_ms: 500,
                }
            ),
            Err(AuthError::Expired)
        ));
        assert_eq!(record.status, OidcTransactionStatus::Expired);
    }

    #[test]
    fn malformed_or_ambiguous_https_bindings_are_rejected() {
        let hasher = TokenHasher::from_key([4; 32]);
        for issuer in [
            "http://identity.example",
            "https://",
            "https://user@identity.example",
            "https://identity.example\\redirect",
            "https://identity.example?tenant=one",
            "https://identity.example#fragment",
            "https://identity.example:",
            "https://identity .example",
        ] {
            assert!(matches!(
                OidcAuthorizationTransaction::issue(
                    &hasher,
                    IssueOidcAuthorization {
                        id: "login-1".to_owned(),
                        tenant_id: "tenant-1".to_owned(),
                        provider_configuration_id: "provider-1".to_owned(),
                        issuer: issuer.to_owned(),
                        client_id: "runtrue".to_owned(),
                        redirect_uri: "https://runtrue.example/auth/callback".to_owned(),
                        created_unix_ms: 100,
                        expires_unix_ms: 500,
                    }
                ),
                Err(AuthError::InsecureOidcBinding | AuthError::InvalidIdentifier(_))
            ));
        }
    }
}
