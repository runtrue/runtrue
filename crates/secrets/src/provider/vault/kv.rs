//! Vault/OpenBao KV-v2 provider implementation and strict response decoding.
use super::{
    reference::{normalize_vault_address, VaultSecretReference, VaultValueEncoding},
    token::VaultTokenSource,
    transport::{
        VaultEndpointPolicy, VaultHttpMethod, VaultHttpRequest, VaultHttpResponse, VaultTransport,
    },
};
use crate::provider::validation::{
    strict_json, validate_identifier, validate_lease_metadata, validate_namespace,
    validate_provider_id,
};
use crate::provider::{
    ExternalSecretLease, ExternalSecretLeaseMetadata, ExternalSecretLeaseRequest,
    ExternalSecretProvider, ProviderError, MAX_PROVIDER_RESPONSE_BYTES,
};
use crate::{SecretPlaintext, MAX_SECRET_BYTES};
use base64ct::{Base64, Encoding as _};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;
pub struct VaultKvV2Provider<T, S> {
    provider_id: String,
    address: String,
    namespace: Option<String>,
    pub(crate) transport: T,
    token_source: S,
    max_lease_ms: u64,
}

impl<T, S> VaultKvV2Provider<T, S>
where
    T: VaultTransport,
    S: VaultTokenSource,
{
    pub fn new(
        address: impl Into<String>,
        namespace: Option<String>,
        transport: T,
        token_source: S,
        max_lease_ms: u64,
    ) -> Result<Self, ProviderError> {
        Self::new_named(
            "vault-kv-v2",
            address,
            namespace,
            transport,
            token_source,
            max_lease_ms,
        )
    }

    pub fn new_named(
        provider_id: impl Into<String>,
        address: impl Into<String>,
        namespace: Option<String>,
        transport: T,
        token_source: S,
        max_lease_ms: u64,
    ) -> Result<Self, ProviderError> {
        Self::new_with_policy(
            provider_id,
            address,
            namespace,
            transport,
            token_source,
            max_lease_ms,
            VaultEndpointPolicy::PublicHttps,
        )
    }

    /// Construct a provider for an exact loopback HTTP integration-test
    /// endpoint. Production callers must use [`Self::new`] or
    /// [`Self::new_named`].
    pub fn new_loopback_test_only(
        address: impl Into<String>,
        namespace: Option<String>,
        transport: T,
        token_source: S,
        max_lease_ms: u64,
    ) -> Result<Self, ProviderError> {
        Self::new_with_policy(
            "vault-kv-v2",
            address,
            namespace,
            transport,
            token_source,
            max_lease_ms,
            VaultEndpointPolicy::LoopbackTestOnly,
        )
    }

    fn new_with_policy(
        provider_id: impl Into<String>,
        address: impl Into<String>,
        namespace: Option<String>,
        transport: T,
        token_source: S,
        max_lease_ms: u64,
        endpoint_policy: VaultEndpointPolicy,
    ) -> Result<Self, ProviderError> {
        let provider_id = provider_id.into();
        validate_provider_id(&provider_id)?;
        let address = normalize_vault_address(address.into(), endpoint_policy)?;
        if max_lease_ms == 0 {
            return Err(ProviderError::InvalidProviderConfiguration);
        }
        if let Some(namespace) = &namespace {
            validate_namespace(namespace)?;
        }
        Ok(Self {
            provider_id,
            address,
            namespace,
            transport,
            token_source,
            max_lease_ms,
        })
    }

    fn request(
        &self,
        method: VaultHttpMethod,
        path: &str,
        body: Vec<u8>,
        now_unix_ms: u64,
    ) -> Result<VaultHttpResponse, ProviderError> {
        let response = self.transport.execute(VaultHttpRequest {
            method,
            url: format!("{}/v1/{path}", self.address),
            namespace: self.namespace.clone(),
            token: self.token_source.token(now_unix_ms)?,
            body: Zeroizing::new(body),
        })?;
        if response.body().len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(ProviderError::ProviderResponseTooLarge);
        }
        Ok(response)
    }
}

impl<T, S> ExternalSecretProvider for VaultKvV2Provider<T, S>
where
    T: VaultTransport + Send + Sync,
    S: VaultTokenSource + Send + Sync,
{
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn lease(
        &self,
        request: &ExternalSecretLeaseRequest,
        now_unix_ms: u64,
    ) -> Result<ExternalSecretLease, ProviderError> {
        request.validate(now_unix_ms)?;
        if request.provider_id != self.provider_id {
            return Err(ProviderError::ProviderIdentityMismatch);
        }
        let reference = VaultSecretReference::parse(&request.provider_reference)?;
        let response = self.request(
            VaultHttpMethod::Get,
            &reference.read_path(),
            Vec::new(),
            now_unix_ms,
        )?;
        if response.status() != 200 {
            return Err(ProviderError::ProviderStatus(response.status()));
        }
        let parsed: VaultReadResponse = strict_json(response.body())?;
        if parsed.data.metadata.version == 0 {
            return Err(ProviderError::InvalidProviderResponse);
        }
        let encoded = parsed
            .data
            .data
            .0
            .get(&reference.field)
            .ok_or(ProviderError::SecretFieldMissing)?;
        let plaintext = match reference.encoding {
            VaultValueEncoding::Utf8 => encoded.as_bytes().to_vec(),
            VaultValueEncoding::Base64 => {
                Base64::decode_vec(encoded).map_err(|_| ProviderError::InvalidSecretEncoding)?
            }
        };
        if plaintext.len() > MAX_SECRET_BYTES {
            return Err(ProviderError::SecretTooLarge {
                limit: MAX_SECRET_BYTES,
                actual: plaintext.len(),
            });
        }
        let duration_ms = parsed
            .lease_duration
            .checked_mul(1_000)
            .ok_or(ProviderError::ProviderLeaseOverflow)?;
        let provider_expiry = now_unix_ms
            .checked_add(if duration_ms == 0 {
                self.max_lease_ms
            } else {
                duration_ms.min(self.max_lease_ms)
            })
            .ok_or(ProviderError::ProviderLeaseOverflow)?;
        let expires_unix_ms = provider_expiry.min(request.expires_unix_ms);
        if expires_unix_ms <= now_unix_ms {
            return Err(ProviderError::ProviderLeaseExpired);
        }
        let provider_lease_id = if parsed.lease_id.is_empty() {
            None
        } else {
            validate_identifier("Vault lease id", &parsed.lease_id)?;
            Some(parsed.lease_id)
        };
        ExternalSecretLease::from_parts(
            ExternalSecretLeaseMetadata {
                release_id: request.release_id.clone(),
                release_subject_digest: request.release_subject_digest.clone(),
                provider: self.provider_id.clone(),
                tenant_id: request.tenant_id.clone(),
                repository_id: request.repository_id.clone(),
                run_id: request.run_id.clone(),
                runner_id: request.runner_id.clone(),
                secret_metadata_id: request.secret_metadata_id.clone(),
                execution_lease_id: request.execution_lease_id.clone(),
                fencing_generation: request.fencing_generation,
                installation_fencing_epoch: request.installation_fencing_epoch,
                job_id: request.job_id.clone(),
                job_attempt: request.job_attempt,
                step_id: request.step_id.clone(),
                purpose: request.purpose.clone(),
                provider_lease_id,
                provider_version: Some(parsed.data.metadata.version),
                renewable: parsed.renewable,
                expires_unix_ms,
            },
            SecretPlaintext::new(plaintext),
        )
    }

    fn revoke(
        &self,
        metadata: &ExternalSecretLeaseMetadata,
        now_unix_ms: u64,
    ) -> Result<(), ProviderError> {
        validate_lease_metadata(metadata, &self.provider_id)?;
        let Some(provider_lease_id) = &metadata.provider_lease_id else {
            return Ok(());
        };
        let body = serde_json::to_vec(&VaultRevokeRequest {
            lease_id: provider_lease_id,
        })?;
        let response = self.request(
            VaultHttpMethod::Post,
            "sys/leases/revoke",
            body,
            now_unix_ms,
        )?;
        if !matches!(response.status(), 200 | 204) {
            return Err(ProviderError::ProviderStatus(response.status()));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct VaultReadResponse {
    #[serde(default)]
    lease_id: String,
    #[serde(default)]
    renewable: bool,
    #[serde(default)]
    lease_duration: u64,
    data: VaultKvEnvelope,
}

#[derive(Deserialize)]
struct VaultKvEnvelope {
    data: StrictStringMap,
    metadata: VaultKvMetadata,
}

#[derive(Deserialize)]
struct VaultKvMetadata {
    version: u64,
}

// Vault values are sensitive even when a different requested field is used or
// validation fails after deserialization. Wrapping every parsed value closes
// those error/rejection paths without treating field names as secret.
struct StrictStringMap(BTreeMap<String, Zeroizing<String>>);

impl<'de> Deserialize<'de> for StrictStringMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictStringMapVisitor;

        impl<'de> Visitor<'de> for StrictStringMapVisitor {
            type Value = StrictStringMap;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object containing unique string-valued secret fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if values.insert(key, Zeroizing::new(value)).is_some() {
                        return Err(serde::de::Error::custom("duplicate Vault secret field"));
                    }
                    if values.len() > 10_000 {
                        return Err(serde::de::Error::custom("too many Vault secret fields"));
                    }
                }
                Ok(StrictStringMap(values))
            }
        }

        deserializer.deserialize_map(StrictStringMapVisitor)
    }
}

#[derive(Serialize)]
struct VaultRevokeRequest<'a> {
    lease_id: &'a str,
}
