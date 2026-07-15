use super::validation::{required_header, validate_identifier};
use crate::{ProviderKind, ScmError, VerifiedDelivery, WebhookHeaders, WebhookLimits};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

const GITHUB_SIGNATURE_HEADER: &str = "x-hub-signature-256";
const GITHUB_DELIVERY_HEADER: &str = "x-github-delivery";
const GITHUB_EVENT_HEADER: &str = "x-github-event";
type HmacSha256 = Hmac<Sha256>;

pub struct GitHubWebhookVerifier {
    secret: Zeroizing<Vec<u8>>,
    limits: WebhookLimits,
}

impl fmt::Debug for GitHubWebhookVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubWebhookVerifier")
            .field("secret", &"[REDACTED]")
            .field("limits", &self.limits)
            .finish()
    }
}

impl GitHubWebhookVerifier {
    pub fn new(secret: impl AsRef<[u8]>, limits: WebhookLimits) -> Result<Self, ScmError> {
        let limits = limits.validate()?;
        let secret = secret.as_ref();
        if secret.is_empty() || secret.len() > 4096 {
            return Err(ScmError::InvalidConfiguration(
                "GitHub webhook secret must contain 1 to 4096 bytes".to_owned(),
            ));
        }
        Ok(Self {
            secret: Zeroizing::new(secret.to_vec()),
            limits,
        })
    }

    /// Authenticate exact raw bytes before returning a delivery to a parser.
    pub fn verify(
        &self,
        headers: &WebhookHeaders,
        body: Vec<u8>,
    ) -> Result<VerifiedDelivery, ScmError> {
        if body.len() > self.limits.max_body_bytes {
            return Err(ScmError::LimitExceeded("webhook body bytes"));
        }
        let signature = required_header(headers, GITHUB_SIGNATURE_HEADER)?;
        let signature = signature
            .strip_prefix("sha256=")
            .ok_or(ScmError::MalformedSignature)?;
        if signature.len() != 64 {
            return Err(ScmError::MalformedSignature);
        }
        let signature = hex::decode(signature).map_err(|_| ScmError::MalformedSignature)?;
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| ScmError::InvalidConfiguration("invalid HMAC key".to_owned()))?;
        mac.update(&body);
        mac.verify_slice(&signature)
            .map_err(|_| ScmError::SignatureMismatch)?;

        let delivery_id = validate_identifier(
            "GitHub delivery id",
            required_header(headers, GITHUB_DELIVERY_HEADER)?,
            self.limits,
        )?;
        let event_name = validate_identifier(
            "GitHub event name",
            required_header(headers, GITHUB_EVENT_HEADER)?,
            self.limits,
        )?;
        Ok(VerifiedDelivery::authenticated(
            ProviderKind::GitHub,
            delivery_id,
            event_name,
            body,
        ))
    }
}
