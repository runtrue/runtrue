use serde::{Deserialize, Serialize};

use crate::{
    validation::validate_issuer, OidcError, JWT_ALGORITHM, MAX_DISCOVERY_DOCUMENT_BYTES,
    WORKLOAD_IDENTITY_GRANT_TYPE,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

impl OidcDiscoveryDocument {
    pub(crate) fn for_issuer(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{issuer}/jwks.json"),
            token_endpoint: format!("{issuer}/token"),
            grant_types_supported: vec![WORKLOAD_IDENTITY_GRANT_TYPE.to_owned()],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec![JWT_ALGORITHM.to_owned()],
        }
    }

    pub fn from_json(bytes: &[u8], expected_issuer: &str) -> Result<Self, OidcError> {
        if bytes.is_empty() || bytes.len() > MAX_DISCOVERY_DOCUMENT_BYTES {
            return Err(OidcError::DiscoveryDocumentTooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate(expected_issuer)?;
        Ok(value)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, OidcError> {
        self.validate(&self.issuer)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_DISCOVERY_DOCUMENT_BYTES {
            return Err(OidcError::DiscoveryDocumentTooLarge);
        }
        Ok(bytes)
    }

    pub fn validate(&self, expected_issuer: &str) -> Result<(), OidcError> {
        validate_issuer(expected_issuer)?;
        if self != &Self::for_issuer(expected_issuer) {
            return Err(OidcError::InvalidDiscoveryDocument);
        }
        Ok(())
    }
}
