use crate::{authorization::require_recent, AuthError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationKind {
    ApiToken,
    BrowserSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthContext {
    pub principal_id: String,
    pub tenant_id: String,
    pub authentication: AuthenticationKind,
    pub scopes: BTreeSet<String>,
    /// Durable bearer/session identity used for bounded delegation ancestry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_expires_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_authenticated_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauthenticated_unix_ms: Option<u64>,
}

impl AuthContext {
    pub fn require_recent_mfa(
        &self,
        now_unix_ms: u64,
        maximum_age_ms: u64,
    ) -> Result<(), AuthError> {
        require_recent(
            self.mfa_authenticated_unix_ms,
            now_unix_ms,
            maximum_age_ms,
            AuthError::RecentMfaRequired,
        )
    }

    pub fn require_recent_reauthentication(
        &self,
        now_unix_ms: u64,
        maximum_age_ms: u64,
    ) -> Result<(), AuthError> {
        require_recent(
            self.reauthenticated_unix_ms,
            now_unix_ms,
            maximum_age_ms,
            AuthError::RecentReauthenticationRequired,
        )
    }
}
