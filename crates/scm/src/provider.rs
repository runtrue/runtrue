use crate::{ProviderKind, ScmError};
use runtrue_model::ContentDigest;
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;

/// Resource limits applied before an authenticated delivery is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookLimits {
    pub max_body_bytes: usize,
    pub max_headers: usize,
    pub max_header_name_bytes: usize,
    pub max_header_value_bytes: usize,
    pub max_identifier_bytes: usize,
    pub max_changed_paths: usize,
    pub max_changed_path_bytes: usize,
}

impl Default for WebhookLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 2 * 1024 * 1024,
            max_headers: 64,
            max_header_name_bytes: 128,
            max_header_value_bytes: 1024,
            max_identifier_bytes: 512,
            max_changed_paths: 20_000,
            max_changed_path_bytes: 4096,
        }
    }
}

impl WebhookLimits {
    pub(crate) fn validate(self) -> Result<Self, ScmError> {
        if self.max_body_bytes == 0
            || self.max_headers == 0
            || self.max_header_name_bytes == 0
            || self.max_header_value_bytes == 0
            || self.max_identifier_bytes == 0
            || self.max_changed_paths == 0
            || self.max_changed_path_bytes == 0
        {
            return Err(ScmError::InvalidConfiguration(
                "all webhook limits must be greater than zero".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// A case-insensitive header set which rejects duplicate names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebhookHeaders(BTreeMap<String, String>);

impl WebhookHeaders {
    pub fn from_pairs<I, K, V>(pairs: I, limits: WebhookLimits) -> Result<Self, ScmError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let limits = limits.validate()?;
        let mut headers = BTreeMap::new();
        for (index, (name, value)) in pairs.into_iter().enumerate() {
            if index >= limits.max_headers {
                return Err(ScmError::LimitExceeded("webhook header count"));
            }
            let name = name.into();
            let value = value.into();
            if name.is_empty()
                || name.len() > limits.max_header_name_bytes
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(ScmError::InvalidHeaderName);
            }
            if value.len() > limits.max_header_value_bytes
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(ScmError::InvalidHeaderValue(name));
            }
            let canonical_name = name.to_ascii_lowercase();
            if headers.insert(canonical_name.clone(), value).is_some() {
                return Err(ScmError::DuplicateHeader(canonical_name));
            }
        }
        Ok(Self(headers))
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(&name.to_ascii_lowercase()).map(String::as_str)
    }
}

/// An authenticated provider delivery. Its raw body has not yet been parsed.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedDelivery {
    pub provider: ProviderKind,
    pub delivery_id: String,
    pub event_name: String,
    pub raw_payload_digest: ContentDigest,
    raw_payload: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for VerifiedDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDelivery")
            .field("provider", &self.provider)
            .field("delivery_id", &self.delivery_id)
            .field("event_name", &self.event_name)
            .field("raw_payload_digest", &self.raw_payload_digest)
            .field("raw_payload", &"[REDACTED]")
            .finish()
    }
}

impl VerifiedDelivery {
    #[must_use]
    pub fn raw_payload(&self) -> &[u8] {
        &self.raw_payload
    }
}

impl VerifiedDelivery {
    pub(crate) fn authenticated(
        provider: ProviderKind,
        delivery_id: String,
        event_name: String,
        raw_payload: Vec<u8>,
    ) -> Self {
        Self {
            provider,
            delivery_id,
            event_name,
            raw_payload_digest: ContentDigest::sha256(&raw_payload),
            raw_payload: Zeroizing::new(raw_payload),
        }
    }
}
