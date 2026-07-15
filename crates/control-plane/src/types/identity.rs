use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

// ---- Migration 23: human identity and active-policy durable projections. ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantIdentityRecord {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub settings: Value,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub version: u64,
}

/// Public tenant-owned OIDC metadata. Client secrets, authorization codes,
/// ID tokens, and refresh tokens have no field in this durable type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantOidcProviderConfiguration {
    pub id: String,
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub mfa_claim: Value,
    pub status: String,
    pub configuration_digest: ContentDigest,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub version: u64,
}

impl TenantOidcProviderConfiguration {
    pub fn expected_configuration_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        let material = serde_json::json!({
            "id": self.id,
            "tenant_id": self.tenant_id,
            "issuer": self.issuer,
            "client_id": self.client_id,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
            "redirect_uri": self.redirect_uri,
            "scopes": self.scopes,
            "mfa_claim": self.mfa_claim,
            "status": self.status,
        });
        let mut bytes = b"runtrue.tenant-oidc-configuration.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&material)?);
        Ok(ContentDigest::sha256(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanUserRecord {
    pub id: String,
    pub display_name: String,
    pub primary_email: String,
    pub status: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub last_seen_unix_ms: Option<u64>,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanIdentityRecord {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub provider_configuration_id: String,
    pub issuer: String,
    pub subject: String,
    pub provider_kind: String,
    pub claims_digest: ContentDigest,
    pub created_unix_ms: u64,
    pub last_authenticated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMembershipRecord {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub role_template: String,
    pub attributes: Value,
    pub attributes_digest: ContentDigest,
    pub status: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub version: u64,
}

impl TenantMembershipRecord {
    pub fn expected_attributes_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        let mut bytes = b"runtrue.tenant-membership-attributes.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&self.attributes)?);
        Ok(ContentDigest::sha256(bytes))
    }
}
