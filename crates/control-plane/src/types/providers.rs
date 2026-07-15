use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

// ---- Migration 24: external providers, environments, and deployments. ----

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantProviderConfiguration {
    pub id: String,
    pub tenant_id: String,
    pub capability: String,
    pub provider_kind: String,
    pub endpoint_origin: String,
    pub credential_reference: String,
    pub trust_bundle_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_digest: Option<ContentDigest>,
    pub configuration_digest: ContentDigest,
    pub status: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub version: u64,
}

impl TenantProviderConfiguration {
    pub fn expected_configuration_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct Material<'a> {
            id: &'a str,
            tenant_id: &'a str,
            capability: &'a str,
            provider_kind: &'a str,
            endpoint_origin: &'a str,
            credential_reference: &'a str,
            trust_bundle_digest: &'a ContentDigest,
            public_key_digest: &'a Option<ContentDigest>,
            status: &'a str,
        }
        let material = Material {
            id: &self.id,
            tenant_id: &self.tenant_id,
            capability: &self.capability,
            provider_kind: &self.provider_kind,
            endpoint_origin: &self.endpoint_origin,
            credential_reference: &self.credential_reference,
            trust_bundle_digest: &self.trust_bundle_digest,
            public_key_digest: &self.public_key_digest,
            status: &self.status,
        };
        let mut bytes = b"runtrue.tenant-provider-configuration.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&material)?);
        Ok(ContentDigest::sha256(bytes))
    }
}

impl fmt::Debug for TenantProviderConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantProviderConfiguration")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("capability", &self.capability)
            .field("provider_kind", &self.provider_kind)
            .field("endpoint_origin", &self.endpoint_origin)
            .field("credential_reference", &"<provider reference>")
            .field("trust_bundle_digest", &self.trust_bundle_digest)
            .field("public_key_digest", &self.public_key_digest)
            .field("configuration_digest", &self.configuration_digest)
            .field("status", &self.status)
            .field("created_unix_ms", &self.created_unix_ms)
            .field("updated_unix_ms", &self.updated_unix_ms)
            .field("version", &self.version)
            .finish()
    }
}
