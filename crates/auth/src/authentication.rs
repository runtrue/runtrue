use crate::{
    authorization::{require_recent, validate_identifier, validate_scopes},
    principal::{AuthContext, AuthenticationKind},
    token::{generate_token, TokenKind},
    AuthError, SecretToken, TokenDigest, TokenHasher, MAX_USED_REFRESH_DIGESTS,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

fn bounded_expiry(now: u64, ttl: u64, absolute: u64) -> Result<u64, AuthError> {
    now.checked_add(ttl)
        .map(|expiry| expiry.min(absolute))
        .filter(|expiry| *expiry > now)
        .ok_or(AuthError::InvalidLifetime)
}

fn validate_assertion_time(observed: Option<u64>, now: u64) -> Result<(), AuthError> {
    if observed.is_some_and(|observed| observed > now) {
        return Err(AuthError::FutureAuthenticationAssertion);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenRecord {
    pub id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub name: String,
    pub digest: TokenDigest,
    pub scopes: BTreeSet<String>,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix_ms: Option<u64>,
}

#[derive(Debug)]
pub struct IssuedApiToken {
    pub record: ApiTokenRecord,
    pub token: SecretToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueApiToken {
    pub id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub name: String,
    pub scopes: BTreeSet<String>,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl ApiTokenRecord {
    pub fn validate(&self) -> Result<(), AuthError> {
        validate_identifier("API token id", &self.id)?;
        validate_identifier("principal id", &self.principal_id)?;
        validate_identifier("tenant id", &self.tenant_id)?;
        validate_identifier("API token name", &self.name)?;
        validate_scopes(&self.scopes)?;
        if self.expires_unix_ms <= self.created_unix_ms
            || self
                .last_used_unix_ms
                .is_some_and(|value| value < self.created_unix_ms || value >= self.expires_unix_ms)
            || self
                .revoked_unix_ms
                .is_some_and(|value| value < self.created_unix_ms)
        {
            return Err(AuthError::InvalidLifetime);
        }
        Ok(())
    }

    pub fn issue(
        hasher: &TokenHasher,
        request: IssueApiToken,
    ) -> Result<IssuedApiToken, AuthError> {
        validate_identifier("API token id", &request.id)?;
        validate_identifier("principal id", &request.principal_id)?;
        validate_identifier("tenant id", &request.tenant_id)?;
        validate_identifier("API token name", &request.name)?;
        validate_scopes(&request.scopes)?;
        if request.expires_unix_ms <= request.created_unix_ms {
            return Err(AuthError::InvalidLifetime);
        }
        let token = generate_token()?;
        let digest = hasher.digest(TokenKind::Api, token.expose());
        Ok(IssuedApiToken {
            record: Self {
                id: request.id,
                principal_id: request.principal_id,
                tenant_id: request.tenant_id,
                name: request.name,
                digest,
                scopes: request.scopes,
                created_unix_ms: request.created_unix_ms,
                expires_unix_ms: request.expires_unix_ms,
                last_used_unix_ms: None,
                revoked_unix_ms: None,
            },
            token,
        })
    }

    pub fn authenticate(
        &mut self,
        hasher: &TokenHasher,
        token: &str,
        required_scope: &str,
        now_unix_ms: u64,
    ) -> Result<AuthContext, AuthError> {
        validate_identifier("required scope", required_scope)?;
        if self.revoked_unix_ms.is_some() {
            return Err(AuthError::Revoked);
        }
        if now_unix_ms < self.created_unix_ms || now_unix_ms >= self.expires_unix_ms {
            return Err(AuthError::Expired);
        }
        if !hasher.verify(TokenKind::Api, token, &self.digest) {
            return Err(AuthError::InvalidCredential);
        }
        if !self.scopes.contains(required_scope) {
            return Err(AuthError::InsufficientScope(required_scope.to_owned()));
        }
        self.last_used_unix_ms = Some(now_unix_ms);
        Ok(AuthContext {
            principal_id: self.principal_id.clone(),
            tenant_id: self.tenant_id.clone(),
            authentication: AuthenticationKind::ApiToken,
            scopes: self.scopes.clone(),
            credential_id: Some(self.id.clone()),
            credential_expires_unix_ms: Some(self.expires_unix_ms),
            mfa_authenticated_unix_ms: None,
            reauthenticated_unix_ms: None,
        })
    }

    pub fn revoke(&mut self, now_unix_ms: u64) -> bool {
        if self.revoked_unix_ms.is_some() {
            false
        } else {
            self.revoked_unix_ms = Some(now_unix_ms);
            true
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPolicy {
    pub access_ttl_ms: u64,
    pub refresh_ttl_ms: u64,
    pub absolute_ttl_ms: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            access_ttl_ms: 15 * 60 * 1000,
            refresh_ttl_ms: 24 * 60 * 60 * 1000,
            absolute_ttl_ms: 7 * 24 * 60 * 60 * 1000,
        }
    }
}

impl SessionPolicy {
    fn validate(self) -> Result<Self, AuthError> {
        if self.access_ttl_ms == 0
            || self.refresh_ttl_ms == 0
            || self.absolute_ttl_ms == 0
            || self.access_ttl_ms > self.refresh_ttl_ms
            || self.refresh_ttl_ms > self.absolute_ttl_ms
        {
            return Err(AuthError::InvalidSessionPolicy);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub device_id: String,
    pub scopes: BTreeSet<String>,
    pub access_generation: u64,
    pub access_digest: TokenDigest,
    pub access_expires_unix_ms: u64,
    pub refresh_digest: TokenDigest,
    pub refresh_expires_unix_ms: u64,
    pub csrf_digest: TokenDigest,
    pub created_unix_ms: u64,
    pub absolute_expires_unix_ms: u64,
    pub used_refresh_digests: Vec<TokenDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_authenticated_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauthenticated_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix_ms: Option<u64>,
}

pub struct IssuedSession {
    pub record: SessionRecord,
    pub access_token: SecretToken,
    pub refresh_token: SecretToken,
    pub csrf_token: SecretToken,
}

impl fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSession")
            .field("record", &self.record)
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .finish()
    }
}

pub struct RotatedSessionTokens {
    pub access_token: SecretToken,
    pub refresh_token: SecretToken,
    pub csrf_token: SecretToken,
}

/// Credentials and security context presented for one refresh-family
/// rotation. The plaintext fields must come from bound browser cookies/header
/// state and are never persistable.
pub struct RotateSessionRequest<'a> {
    pub refresh_token: &'a str,
    pub csrf_token: &'a str,
    pub require_mfa_within_ms: Option<u64>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueSession {
    pub id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub device_id: String,
    pub scopes: BTreeSet<String>,
    pub now_unix_ms: u64,
    pub mfa_authenticated_unix_ms: Option<u64>,
}

impl fmt::Debug for RotatedSessionTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotatedSessionTokens")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .finish()
    }
}

impl SessionRecord {
    /// Validate the bounded refresh-family history and lifetime relationships
    /// after loading a session from durable storage.
    pub fn validate(&self) -> Result<(), AuthError> {
        validate_identifier("session id", &self.id)?;
        validate_identifier("principal id", &self.principal_id)?;
        validate_identifier("tenant id", &self.tenant_id)?;
        validate_identifier("device id", &self.device_id)?;
        validate_scopes(&self.scopes)?;
        let expected_generation = u64::try_from(self.used_refresh_digests.len())
            .ok()
            .and_then(|used| used.checked_add(1))
            .ok_or(AuthError::InvalidSessionRecord)?;
        let unique_used = self
            .used_refresh_digests
            .iter()
            .collect::<BTreeSet<_>>()
            .len();
        if self.used_refresh_digests.len() > MAX_USED_REFRESH_DIGESTS
            || unique_used != self.used_refresh_digests.len()
            || self.used_refresh_digests.contains(&self.refresh_digest)
            || self.access_generation != expected_generation
            || self.created_unix_ms >= self.absolute_expires_unix_ms
            || self.access_expires_unix_ms <= self.created_unix_ms
            || self.access_expires_unix_ms > self.absolute_expires_unix_ms
            || self.refresh_expires_unix_ms < self.access_expires_unix_ms
            || self.refresh_expires_unix_ms > self.absolute_expires_unix_ms
            || self
                .mfa_authenticated_unix_ms
                .is_some_and(|observed| observed > self.absolute_expires_unix_ms)
            || self.reauthenticated_unix_ms.is_some_and(|observed| {
                observed < self.created_unix_ms || observed > self.absolute_expires_unix_ms
            })
            || self
                .revoked_unix_ms
                .is_some_and(|observed| observed < self.created_unix_ms)
        {
            return Err(AuthError::InvalidSessionRecord);
        }
        Ok(())
    }

    pub fn issue(
        hasher: &TokenHasher,
        policy: SessionPolicy,
        request: IssueSession,
    ) -> Result<IssuedSession, AuthError> {
        let policy = policy.validate()?;
        validate_identifier("session id", &request.id)?;
        validate_identifier("principal id", &request.principal_id)?;
        validate_identifier("tenant id", &request.tenant_id)?;
        validate_identifier("device id", &request.device_id)?;
        validate_scopes(&request.scopes)?;
        validate_assertion_time(request.mfa_authenticated_unix_ms, request.now_unix_ms)?;
        let absolute_expires_unix_ms = request
            .now_unix_ms
            .checked_add(policy.absolute_ttl_ms)
            .ok_or(AuthError::InvalidLifetime)?;
        let access_token = generate_token()?;
        let refresh_token = generate_token()?;
        let csrf_token = generate_token()?;
        Ok(IssuedSession {
            record: Self {
                id: request.id,
                principal_id: request.principal_id,
                tenant_id: request.tenant_id,
                device_id: request.device_id,
                scopes: request.scopes,
                access_generation: 1,
                access_digest: hasher.digest(TokenKind::Access, access_token.expose()),
                access_expires_unix_ms: bounded_expiry(
                    request.now_unix_ms,
                    policy.access_ttl_ms,
                    absolute_expires_unix_ms,
                )?,
                refresh_digest: hasher.digest(TokenKind::Refresh, refresh_token.expose()),
                refresh_expires_unix_ms: bounded_expiry(
                    request.now_unix_ms,
                    policy.refresh_ttl_ms,
                    absolute_expires_unix_ms,
                )?,
                csrf_digest: hasher.digest(TokenKind::Csrf, csrf_token.expose()),
                created_unix_ms: request.now_unix_ms,
                absolute_expires_unix_ms,
                used_refresh_digests: Vec::new(),
                mfa_authenticated_unix_ms: request.mfa_authenticated_unix_ms,
                reauthenticated_unix_ms: Some(request.now_unix_ms),
                revoked_unix_ms: None,
            },
            access_token,
            refresh_token,
            csrf_token,
        })
    }

    pub fn authenticate_browser_request(
        &self,
        hasher: &TokenHasher,
        access_token: &str,
        csrf_token: Option<&str>,
        required_scope: &str,
        state_changing: bool,
        now_unix_ms: u64,
    ) -> Result<AuthContext, AuthError> {
        self.ensure_live(now_unix_ms)?;
        validate_identifier("required scope", required_scope)?;
        if now_unix_ms >= self.access_expires_unix_ms {
            return Err(AuthError::Expired);
        }
        if !hasher.verify(TokenKind::Access, access_token, &self.access_digest) {
            return Err(AuthError::InvalidCredential);
        }
        if state_changing
            && !csrf_token
                .is_some_and(|token| hasher.verify(TokenKind::Csrf, token, &self.csrf_digest))
        {
            return Err(AuthError::CsrfRequired);
        }
        if !self.scopes.contains(required_scope) {
            return Err(AuthError::InsufficientScope(required_scope.to_owned()));
        }
        Ok(AuthContext {
            principal_id: self.principal_id.clone(),
            tenant_id: self.tenant_id.clone(),
            authentication: AuthenticationKind::BrowserSession,
            scopes: self.scopes.clone(),
            credential_id: None,
            credential_expires_unix_ms: None,
            mfa_authenticated_unix_ms: self.mfa_authenticated_unix_ms,
            reauthenticated_unix_ms: self.reauthenticated_unix_ms,
        })
    }

    /// Consume the current refresh token and rotate all browser credentials.
    /// Reuse of any previously consumed refresh token revokes the session.
    pub fn rotate(
        &mut self,
        hasher: &TokenHasher,
        policy: SessionPolicy,
        request: RotateSessionRequest<'_>,
    ) -> Result<RotatedSessionTokens, AuthError> {
        let policy = policy.validate()?;
        self.ensure_live(request.now_unix_ms)?;
        if request.now_unix_ms >= self.refresh_expires_unix_ms {
            self.revoked_unix_ms = Some(request.now_unix_ms);
            return Err(AuthError::Expired);
        }
        let presented = hasher.digest(TokenKind::Refresh, request.refresh_token);
        if self.used_refresh_digests.contains(&presented) {
            self.revoked_unix_ms = Some(request.now_unix_ms);
            return Err(AuthError::RefreshReplay);
        }
        if !hasher.verify(
            TokenKind::Refresh,
            request.refresh_token,
            &self.refresh_digest,
        ) {
            return Err(AuthError::InvalidCredential);
        }
        if !hasher.verify(TokenKind::Csrf, request.csrf_token, &self.csrf_digest) {
            return Err(AuthError::CsrfRequired);
        }
        if let Some(maximum_age_ms) = request.require_mfa_within_ms {
            require_recent(
                self.mfa_authenticated_unix_ms,
                request.now_unix_ms,
                maximum_age_ms,
                AuthError::RecentMfaRequired,
            )?;
        }

        if self.used_refresh_digests.len() >= MAX_USED_REFRESH_DIGESTS {
            self.revoked_unix_ms = Some(request.now_unix_ms);
            return Err(AuthError::RefreshFamilyExhausted);
        }

        self.used_refresh_digests.push(self.refresh_digest.clone());
        self.access_generation = self
            .access_generation
            .checked_add(1)
            .ok_or(AuthError::GenerationExhausted)?;
        let access_token = generate_token()?;
        let refresh_token = generate_token()?;
        let csrf_token = generate_token()?;
        self.access_digest = hasher.digest(TokenKind::Access, access_token.expose());
        self.refresh_digest = hasher.digest(TokenKind::Refresh, refresh_token.expose());
        self.csrf_digest = hasher.digest(TokenKind::Csrf, csrf_token.expose());
        self.access_expires_unix_ms = bounded_expiry(
            request.now_unix_ms,
            policy.access_ttl_ms,
            self.absolute_expires_unix_ms,
        )?;
        self.refresh_expires_unix_ms = bounded_expiry(
            request.now_unix_ms,
            policy.refresh_ttl_ms,
            self.absolute_expires_unix_ms,
        )?;
        Ok(RotatedSessionTokens {
            access_token,
            refresh_token,
            csrf_token,
        })
    }

    pub fn record_reauthentication(
        &mut self,
        now_unix_ms: u64,
        included_mfa: bool,
    ) -> Result<(), AuthError> {
        self.ensure_live(now_unix_ms)?;
        self.reauthenticated_unix_ms = Some(now_unix_ms);
        if included_mfa {
            self.mfa_authenticated_unix_ms = Some(now_unix_ms);
        }
        Ok(())
    }

    pub fn revoke(&mut self, now_unix_ms: u64) -> bool {
        if self.revoked_unix_ms.is_some() {
            false
        } else {
            self.revoked_unix_ms = Some(now_unix_ms);
            true
        }
    }

    fn ensure_live(&self, now_unix_ms: u64) -> Result<(), AuthError> {
        self.validate()?;
        if self.revoked_unix_ms.is_some() {
            return Err(AuthError::Revoked);
        }
        if now_unix_ms < self.created_unix_ms || now_unix_ms >= self.absolute_expires_unix_ms {
            return Err(AuthError::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes() -> BTreeSet<String> {
        BTreeSet::from(["runs:read".to_owned(), "runs:write".to_owned()])
    }

    fn issue_api(hasher: &TokenHasher) -> IssuedApiToken {
        ApiTokenRecord::issue(
            hasher,
            IssueApiToken {
                id: "token-1".to_owned(),
                principal_id: "user-1".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                name: "automation".to_owned(),
                scopes: scopes(),
                created_unix_ms: 100,
                expires_unix_ms: 1000,
            },
        )
        .expect("issue")
    }

    fn issue_session(
        hasher: &TokenHasher,
        policy: SessionPolicy,
        mfa_authenticated_unix_ms: Option<u64>,
    ) -> IssuedSession {
        SessionRecord::issue(
            hasher,
            policy,
            IssueSession {
                id: "session-1".to_owned(),
                principal_id: "user-1".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                device_id: "device-1".to_owned(),
                scopes: scopes(),
                now_unix_ms: 100,
                mfa_authenticated_unix_ms,
            },
        )
        .expect("issue")
    }

    #[test]
    fn api_token_is_returned_once_and_only_keyed_digest_is_persisted() {
        let hasher = TokenHasher::from_key([7; 32]);
        let mut issued = issue_api(&hasher);
        let plaintext = issued.token.expose().to_owned();
        assert_eq!(plaintext.len(), 64);
        let serialized = serde_json::to_string(&issued.record).expect("serialize");
        assert!(!serialized.contains(&plaintext));
        assert!(!format!("{:?}", issued.token).contains(&plaintext));
        assert!(!format!("{:?}", issued.record.digest).contains(&plaintext));

        let context = issued
            .record
            .authenticate(&hasher, &plaintext, "runs:read", 200)
            .expect("authenticate");
        assert_eq!(context.principal_id, "user-1");
        assert_eq!(issued.record.last_used_unix_ms, Some(200));
    }

    #[test]
    fn api_token_scope_expiry_and_revocation_are_enforced() {
        let hasher = TokenHasher::from_key([7; 32]);
        let mut issued = issue_api(&hasher);
        let plaintext = issued.token.expose().to_owned();
        assert!(matches!(
            issued
                .record
                .authenticate(&hasher, &plaintext, "secrets:write", 200),
            Err(AuthError::InsufficientScope(_))
        ));
        assert_eq!(issued.record.last_used_unix_ms, None);
        assert!(matches!(
            issued
                .record
                .authenticate(&hasher, &plaintext, "runs:read", 1000),
            Err(AuthError::Expired)
        ));
        assert!(issued.record.revoke(900));
        assert!(!issued.record.revoke(901));
        assert!(matches!(
            issued
                .record
                .authenticate(&hasher, &plaintext, "runs:read", 901),
            Err(AuthError::Revoked)
        ));
    }

    #[test]
    fn token_hashes_are_installation_keyed_and_domain_separated() {
        let first = TokenHasher::from_key([1; 32]);
        let second = TokenHasher::from_key([2; 32]);
        let value = "a".repeat(64);
        assert_ne!(
            first.digest(TokenKind::Api, &value),
            second.digest(TokenKind::Api, &value)
        );
        assert_ne!(
            first.digest(TokenKind::Api, &value),
            first.digest(TokenKind::Access, &value)
        );
        assert_eq!(format!("{first:?}"), "TokenHasher([REDACTED])");
    }

    #[test]
    fn browser_mutations_require_access_and_bound_csrf_tokens() {
        let hasher = TokenHasher::from_key([7; 32]);
        let issued = issue_session(&hasher, SessionPolicy::default(), Some(90));
        let access = issued.access_token.expose();
        assert!(issued
            .record
            .authenticate_browser_request(&hasher, access, None, "runs:read", false, 200)
            .is_ok());
        assert!(matches!(
            issued.record.authenticate_browser_request(
                &hasher,
                access,
                None,
                "runs:write",
                true,
                200
            ),
            Err(AuthError::CsrfRequired)
        ));
        assert!(issued
            .record
            .authenticate_browser_request(
                &hasher,
                access,
                Some(issued.csrf_token.expose()),
                "runs:write",
                true,
                200
            )
            .is_ok());
    }

    #[test]
    fn rotation_invalidates_old_access_and_refresh_replay_revokes_session() {
        let hasher = TokenHasher::from_key([7; 32]);
        let issued = issue_session(&hasher, SessionPolicy::default(), Some(90));
        let old_access = issued.access_token.expose().to_owned();
        let old_refresh = issued.refresh_token.expose().to_owned();
        let old_csrf = issued.csrf_token.expose().to_owned();
        let mut record = issued.record;
        let rotated = record
            .rotate(
                &hasher,
                SessionPolicy::default(),
                RotateSessionRequest {
                    refresh_token: &old_refresh,
                    csrf_token: &old_csrf,
                    require_mfa_within_ms: None,
                    now_unix_ms: 200,
                },
            )
            .expect("rotate");
        assert_eq!(record.access_generation, 2);
        assert!(matches!(
            record.authenticate_browser_request(
                &hasher,
                &old_access,
                None,
                "runs:read",
                false,
                201
            ),
            Err(AuthError::InvalidCredential)
        ));
        assert!(record
            .authenticate_browser_request(
                &hasher,
                rotated.access_token.expose(),
                None,
                "runs:read",
                false,
                201
            )
            .is_ok());
        assert!(matches!(
            record.rotate(
                &hasher,
                SessionPolicy::default(),
                RotateSessionRequest {
                    refresh_token: &old_refresh,
                    csrf_token: &old_csrf,
                    require_mfa_within_ms: None,
                    now_unix_ms: 202,
                }
            ),
            Err(AuthError::RefreshReplay)
        ));
        assert!(record.revoked_unix_ms.is_some());
        assert!(matches!(
            record.authenticate_browser_request(
                &hasher,
                rotated.access_token.expose(),
                None,
                "runs:read",
                false,
                203
            ),
            Err(AuthError::Revoked)
        ));
    }

    #[test]
    fn random_refresh_failure_does_not_revoke_a_session() {
        let hasher = TokenHasher::from_key([7; 32]);
        let issued = issue_session(&hasher, SessionPolicy::default(), None);
        let csrf = issued.csrf_token.expose().to_owned();
        let mut record = issued.record;
        assert!(matches!(
            record.rotate(
                &hasher,
                SessionPolicy::default(),
                RotateSessionRequest {
                    refresh_token: &"0".repeat(64),
                    csrf_token: &csrf,
                    require_mfa_within_ms: None,
                    now_unix_ms: 200,
                }
            ),
            Err(AuthError::InvalidCredential)
        ));
        assert_eq!(record.revoked_unix_ms, None);
    }

    #[test]
    fn sensitive_actions_require_fresh_mfa_and_reauthentication() {
        let context = AuthContext {
            principal_id: "user".to_owned(),
            tenant_id: "tenant".to_owned(),
            authentication: AuthenticationKind::BrowserSession,
            scopes: scopes(),
            credential_id: None,
            credential_expires_unix_ms: None,
            mfa_authenticated_unix_ms: Some(100),
            reauthenticated_unix_ms: Some(150),
        };
        assert!(context.require_recent_mfa(200, 101).is_ok());
        assert!(context.require_recent_reauthentication(200, 51).is_ok());
        assert!(matches!(
            context.require_recent_mfa(202, 101),
            Err(AuthError::RecentMfaRequired)
        ));
        assert!(matches!(
            context.require_recent_reauthentication(202, 51),
            Err(AuthError::RecentReauthenticationRequired)
        ));
    }

    #[test]
    fn absolute_session_expiry_caps_sliding_rotation() {
        let hasher = TokenHasher::from_key([7; 32]);
        let policy = SessionPolicy {
            access_ttl_ms: 10,
            refresh_ttl_ms: 20,
            absolute_ttl_ms: 25,
        };
        let issued = issue_session(&hasher, policy, None);
        let refresh = issued.refresh_token.expose().to_owned();
        let csrf = issued.csrf_token.expose().to_owned();
        let mut record = issued.record;
        record
            .rotate(
                &hasher,
                policy,
                RotateSessionRequest {
                    refresh_token: &refresh,
                    csrf_token: &csrf,
                    require_mfa_within_ms: None,
                    now_unix_ms: 110,
                },
            )
            .expect("rotate");
        assert_eq!(record.access_expires_unix_ms, 120);
        assert_eq!(record.refresh_expires_unix_ms, 125);
        assert!(matches!(
            record.authenticate_browser_request(
                &hasher,
                "irrelevant",
                None,
                "runs:read",
                false,
                125
            ),
            Err(AuthError::Expired)
        ));
    }

    #[test]
    fn refresh_requires_bound_csrf_and_configured_recent_mfa() {
        let hasher = TokenHasher::from_key([7; 32]);
        let issued = issue_session(&hasher, SessionPolicy::default(), Some(90));
        let refresh = issued.refresh_token.expose().to_owned();
        let csrf = issued.csrf_token.expose().to_owned();
        let mut record = issued.record;

        assert!(matches!(
            record.rotate(
                &hasher,
                SessionPolicy::default(),
                RotateSessionRequest {
                    refresh_token: &refresh,
                    csrf_token: "wrong",
                    require_mfa_within_ms: None,
                    now_unix_ms: 200,
                }
            ),
            Err(AuthError::CsrfRequired)
        ));
        assert_eq!(record.access_generation, 1);
        assert!(matches!(
            record.rotate(
                &hasher,
                SessionPolicy::default(),
                RotateSessionRequest {
                    refresh_token: &refresh,
                    csrf_token: &csrf,
                    require_mfa_within_ms: Some(100),
                    now_unix_ms: 200,
                }
            ),
            Err(AuthError::RecentMfaRequired)
        ));
        assert_eq!(record.access_generation, 1);
        record
            .rotate(
                &hasher,
                SessionPolicy::default(),
                RotateSessionRequest {
                    refresh_token: &refresh,
                    csrf_token: &csrf,
                    require_mfa_within_ms: Some(111),
                    now_unix_ms: 200,
                },
            )
            .expect("fresh MFA and CSRF allow rotation");
    }
}
