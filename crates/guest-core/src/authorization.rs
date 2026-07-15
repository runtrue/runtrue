use crate::{
    protocol::validate_identifier, AuthenticatedEnvelope, GuestError, OidcEnvelope, SecretEnvelope,
    StepSignal, MAX_OIDC_TOKEN_BYTES, MAX_SECRET_ENVELOPE_BYTES,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{PlannedJob, PlannedStep};
use std::fmt;
use zeroize::Zeroizing;

/// Decrypted material is intentionally neither serializable nor cloneable.
pub struct SecretMaterial {
    pub metadata_id: String,
    pub name: String,
    pub purpose: Option<String>,
    pub expires_unix_ms: u64,
    pub(crate) ciphertext: Zeroizing<Vec<u8>>,
}

impl SecretMaterial {
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("metadata_id", &self.metadata_id)
            .field("name", &self.name)
            .field("purpose", &self.purpose)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

pub struct OidcToken {
    pub audience: String,
    pub expires_unix_ms: u64,
    pub(crate) token: Zeroizing<String>,
}

impl OidcToken {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for OidcToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcToken")
            .field("audience", &self.audience)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("token", &"<redacted>")
            .finish()
    }
}

pub enum GuestAction {
    Send(AuthenticatedEnvelope),
    StartStep(Box<AuthorizedStep>),
    SignalStep { step_id: String, signal: StepSignal },
    DeliverSecret(SecretMaterial),
    DeliverOidc(OidcToken),
    Shutdown,
}

impl fmt::Debug for GuestAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(envelope) => formatter.debug_tuple("Send").field(envelope).finish(),
            Self::StartStep(step) => formatter.debug_tuple("StartStep").field(step).finish(),
            Self::SignalStep { step_id, signal } => formatter
                .debug_struct("SignalStep")
                .field("step_id", step_id)
                .field("signal", signal)
                .finish(),
            Self::DeliverSecret(secret) => formatter
                .debug_tuple("DeliverSecret")
                .field(secret)
                .finish(),
            Self::DeliverOidc(token) => formatter.debug_tuple("DeliverOidc").field(token).finish(),
            Self::Shutdown => formatter.write_str("Shutdown"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizedStep {
    pub job_id: String,
    pub attempt: u32,
    pub step: PlannedStep,
}

pub fn step_capability_digest(step: &PlannedStep) -> Result<ContentDigest, GuestError> {
    let bytes = serde_json::to_vec(&step.capabilities).map_err(GuestError::Json)?;
    Ok(ContentDigest::sha256(bytes))
}

pub(crate) fn mount_is_declared(job: &PlannedJob, path: &str, read_only: bool) -> bool {
    job.steps.iter().any(|step| {
        let readable = step
            .capabilities
            .fs_read
            .iter()
            .chain(step.capabilities.fs_write.iter())
            .any(|declared| path_within(path, declared));
        let writable = step
            .capabilities
            .fs_write
            .iter()
            .any(|declared| path_within(path, declared));
        if read_only {
            readable
        } else {
            writable
        }
    })
}

pub(crate) fn authorize_secret(
    step: &PlannedStep,
    secret: SecretEnvelope,
    now_unix_ms: u64,
) -> Result<SecretMaterial, GuestError> {
    if secret.ciphertext.is_empty()
        || secret.ciphertext.len() > MAX_SECRET_ENVELOPE_BYTES
        || now_unix_ms >= secret.expires_unix_ms
    {
        return Err(GuestError::InvalidSecretEnvelope);
    }
    validate_identifier("secret metadata id", &secret.metadata_id)?;
    validate_identifier("secret name", &secret.name)?;
    if let Some(purpose) = &secret.purpose {
        validate_identifier("secret purpose", purpose)?;
    }
    let declared = step.capabilities.secrets.iter().any(|reference| {
        reference.metadata_id == secret.metadata_id
            && reference.name == secret.name
            && reference.purpose == secret.purpose
    });
    if !declared {
        return Err(GuestError::UndeclaredSecret);
    }
    Ok(SecretMaterial {
        metadata_id: secret.metadata_id,
        name: secret.name,
        purpose: secret.purpose,
        expires_unix_ms: secret.expires_unix_ms,
        ciphertext: Zeroizing::new(secret.ciphertext),
    })
}

pub(crate) fn authorize_oidc(
    step: &PlannedStep,
    token: OidcEnvelope,
    now_unix_ms: u64,
) -> Result<OidcToken, GuestError> {
    if token.token.is_empty()
        || token.token.len() > MAX_OIDC_TOKEN_BYTES
        || now_unix_ms >= token.expires_unix_ms
    {
        return Err(GuestError::InvalidOidcEnvelope);
    }
    validate_identifier("OIDC audience", &token.audience)?;
    if !step.capabilities.oidc_audiences.contains(&token.audience) {
        return Err(GuestError::UndeclaredOidcAudience);
    }
    Ok(OidcToken {
        audience: token.audience,
        expires_unix_ms: token.expires_unix_ms,
        token: Zeroizing::new(token.token),
    })
}

fn path_within(path: &str, declared: &str) -> bool {
    path == declared
        || path
            .strip_prefix(declared)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
