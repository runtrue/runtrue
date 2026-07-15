use crate::app::{
    reconcile_claimed_github_lifecycle, wall_clock_unix_ms, HmacSha256, AUTH_DOMAIN,
    GITHUB_LIFECYCLE_LEASE_MS, GITHUB_SETUP_MAX_CONCURRENCY, MAX_BOOTSTRAP_TOKEN_BYTES,
};
use crate::human_oidc::{
    CookieSealer, GitHubOauthAdapter, HumanAuthMetrics, HumanOidcAdapter, HumanOidcError,
};
use crate::runner_certificates::RunnerCertificateAuthority;
use crate::runner_service::{
    RunnerControlConfig, RunnerControlService, RunnerDataPlane, RunnerServiceError,
};
use crate::scm_worker::GitHubInstallationTokenProvider;
use rand_core::OsRng;
use runtrue_attest::CapsuleSigningKey;
use runtrue_auth::{SessionPolicy, TokenHasher};
use runtrue_control_plane::{ControlPlane, ControlPlaneError};
use runtrue_oidc::OidcIssuer;
use runtrue_policy::CedarAuthorizationEngine;
use runtrue_scm::{
    GitHubAppPublicConfig, GitHubError, GitHubInstallationProvider, GitHubWebhookVerifier,
    ScmError, WebhookLimits,
};
use runtrue_secrets::MasterKey;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;
/// Constant-time verifier which never retains the configured bearer token.
#[derive(Clone)]
pub struct BootstrapAuth {
    pub(in crate::app) hmac_key: Zeroizing<[u8; 32]>,
    pub(in crate::app) expected_tag: [u8; 32],
}

impl BootstrapAuth {
    pub(in crate::app) fn new(token: &str) -> Result<Self, ServerBuildError> {
        if token.is_empty() || token.len() > MAX_BOOTSTRAP_TOKEN_BYTES || token.contains('\0') {
            return Err(ServerBuildError::InvalidBootstrapToken);
        }
        let mut hmac_key = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(hmac_key.as_mut())
            .map_err(|_| ServerBuildError::RandomnessUnavailable)?;
        let expected_tag = authentication_tag(hmac_key.as_ref(), token.as_bytes());
        Ok(Self {
            hmac_key,
            expected_tag,
        })
    }

    pub(in crate::app) fn verify(&self, candidate: &str) -> bool {
        let mut mac = HmacSha256::new_from_slice(self.hmac_key.as_ref())
            .expect("HMAC-SHA-256 accepts a 32-byte key");
        mac.update(AUTH_DOMAIN);
        mac.update(candidate.as_bytes());
        mac.verify_slice(&self.expected_tag).is_ok()
    }
}

impl fmt::Debug for BootstrapAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapAuth([REDACTED])")
    }
}

pub(in crate::app) fn authentication_tag(key: &[u8], token: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(AUTH_DOMAIN);
    mac.update(token);
    mac.finalize().into_bytes().into()
}

pub(in crate::app) struct HumanOidcState {
    pub(in crate::app) public_origin: String,
    pub(in crate::app) cookie_sealer: CookieSealer,
    pub(in crate::app) adapter: Arc<dyn HumanOidcAdapter>,
    pub(in crate::app) exchange_admission: Arc<tokio::sync::Semaphore>,
    pub(in crate::app) session_policy: SessionPolicy,
    pub(in crate::app) metrics: Arc<HumanAuthMetrics>,
    pub(in crate::app) github_oauth: Option<GitHubOauthState>,
}

#[derive(Clone)]
pub(in crate::app) struct GitHubOauthState {
    pub(in crate::app) tenant_id: String,
    pub(in crate::app) provider_id: String,
    pub(in crate::app) issuer: String,
    pub(in crate::app) client_id: String,
    pub(in crate::app) authorization_endpoint: String,
    pub(in crate::app) adapter: Arc<dyn GitHubOauthAdapter>,
    pub(in crate::app) allowed_roles: BTreeMap<u64, String>,
}

pub struct GitHubOauthQuickstartConfig {
    pub tenant_id: String,
    pub tenant_name: String,
    pub web_origin: String,
    pub client_id: String,
    pub adapter: Arc<dyn GitHubOauthAdapter>,
    pub allowed_roles: BTreeMap<u64, String>,
    pub now_unix_ms: u64,
}

pub(in crate::app) struct GitHubInstallationState {
    pub(in crate::app) public_config: GitHubAppPublicConfig,
    pub(in crate::app) credential_reference: String,
    pub(in crate::app) provider: Arc<dyn GitHubInstallationProvider>,
    pub(in crate::app) setup_key: Zeroizing<[u8; 32]>,
    pub(in crate::app) admission: Arc<tokio::sync::Semaphore>,
    pub(in crate::app) metrics: Arc<GitHubInstallationMetrics>,
}

#[derive(Debug, Default)]
pub(in crate::app) struct GitHubInstallationMetrics {
    pub(in crate::app) setup_started: AtomicU64,
    pub(in crate::app) callbacks_completed: AtomicU64,
    pub(in crate::app) callbacks_rejected: AtomicU64,
    pub(in crate::app) provider_failures: AtomicU64,
    pub(in crate::app) reconciliations: AtomicU64,
    pub(in crate::app) installations_revoked: AtomicU64,
    pub(in crate::app) lifecycle_deliveries_reserved: AtomicU64,
    pub(in crate::app) lifecycle_delivery_replays: AtomicU64,
    pub(in crate::app) lifecycle_retries: AtomicU64,
    pub(in crate::app) lifecycle_terminal_failures: AtomicU64,
}

/// Redaction-safe counters for GitHub App installation administration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct GitHubInstallationMetricsSnapshot {
    pub setup_started: u64,
    pub callbacks_completed: u64,
    pub callbacks_rejected: u64,
    pub provider_failures: u64,
    pub reconciliations: u64,
    pub installations_revoked: u64,
    pub lifecycle_deliveries_reserved: u64,
    pub lifecycle_delivery_replays: u64,
    pub lifecycle_retries: u64,
    pub lifecycle_terminal_failures: u64,
}

impl GitHubInstallationMetrics {
    pub(in crate::app) fn snapshot(&self) -> GitHubInstallationMetricsSnapshot {
        GitHubInstallationMetricsSnapshot {
            setup_started: self.setup_started.load(Ordering::Relaxed),
            callbacks_completed: self.callbacks_completed.load(Ordering::Relaxed),
            callbacks_rejected: self.callbacks_rejected.load(Ordering::Relaxed),
            provider_failures: self.provider_failures.load(Ordering::Relaxed),
            reconciliations: self.reconciliations.load(Ordering::Relaxed),
            installations_revoked: self.installations_revoked.load(Ordering::Relaxed),
            lifecycle_deliveries_reserved: self
                .lifecycle_deliveries_reserved
                .load(Ordering::Relaxed),
            lifecycle_delivery_replays: self.lifecycle_delivery_replays.load(Ordering::Relaxed),
            lifecycle_retries: self.lifecycle_retries.load(Ordering::Relaxed),
            lifecycle_terminal_failures: self.lifecycle_terminal_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub control_plane: Arc<ControlPlane>,
    pub(in crate::app) auth: BootstrapAuth,
    pub(in crate::app) webhook: Option<Arc<GitHubWebhookVerifier>>,
    pub(in crate::app) webhook_limits: WebhookLimits,
    pub(in crate::app) request_timeout: Duration,
    pub(crate) capsule_signing_key: Arc<CapsuleSigningKey>,
    pub(in crate::app) token_hasher: Arc<TokenHasher>,
    pub(in crate::app) secret_master_key: Arc<MasterKey>,
    pub(in crate::app) oidc: Arc<OidcIssuer>,
    pub(in crate::app) authorization: Arc<CedarAuthorizationEngine>,
    pub(in crate::app) runner_data_plane: Option<Arc<RunnerDataPlane>>,
    pub(in crate::app) scm_credential_provider: Option<Arc<dyn GitHubInstallationTokenProvider>>,
    pub(in crate::app) human_oidc: Option<Arc<HumanOidcState>>,
    pub(in crate::app) github_installation: Option<Arc<GitHubInstallationState>>,
    pub(in crate::app) github_setup_key: Zeroizing<[u8; 32]>,
}

impl AppState {
    pub fn new(
        control_plane: Arc<ControlPlane>,
        bootstrap_token: &str,
        webhook_secret: Option<&[u8]>,
    ) -> Result<Self, ServerBuildError> {
        let mut seed = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| ServerBuildError::RandomnessUnavailable)?;
        Self::new_with_security_seed(
            control_plane,
            bootstrap_token,
            webhook_secret,
            seed,
            "https://runtrue.invalid/oidc".to_owned(),
        )
    }

    pub fn new_with_security_seed(
        control_plane: Arc<ControlPlane>,
        bootstrap_token: &str,
        webhook_secret: Option<&[u8]>,
        mut security_seed: [u8; 32],
        oidc_issuer: String,
    ) -> Result<Self, ServerBuildError> {
        let webhook_limits = WebhookLimits::default();
        let webhook = webhook_secret
            .map(|secret| GitHubWebhookVerifier::new(secret, webhook_limits).map(Arc::new))
            .transpose()?;
        let mut capsule_seed = derive_security_seed(&security_seed, b"capsule-signing");
        let mut secret_seed = derive_security_seed(&security_seed, b"secret-vault");
        let mut oidc_seed = derive_security_seed(&security_seed, b"oidc-signing");
        let mut auth_seed = derive_security_seed(&security_seed, b"api-token-hashing");
        let mut github_setup_seed = derive_security_seed(&security_seed, b"github-app-setup");
        use zeroize::Zeroize as _;
        security_seed.zeroize();
        let capsule_signing_key = Arc::new(CapsuleSigningKey::from_seed(capsule_seed));
        let secret_master_key = Arc::new(MasterKey::from_bytes(secret_seed));
        let oidc_signing_key = OidcSigningKey::from_seed(oidc_seed);
        let token_hasher = Arc::new(TokenHasher::from_key(auth_seed));
        let github_setup_key = Zeroizing::new(github_setup_seed);
        capsule_seed.zeroize();
        secret_seed.zeroize();
        oidc_seed.zeroize();
        auth_seed.zeroize();
        github_setup_seed.zeroize();
        let oidc = OidcIssuer::new(oidc_issuer, oidc_signing_key)?;
        let authorization = CedarAuthorizationEngine::new(
            BUILTIN_SERVER_AUTHORIZATION_POLICY,
            DenyFirstPolicy::default(),
        )?;
        Ok(Self {
            control_plane,
            auth: BootstrapAuth::new(bootstrap_token)?,
            webhook,
            webhook_limits,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            capsule_signing_key,
            token_hasher,
            secret_master_key,
            oidc: Arc::new(oidc),
            authorization: Arc::new(authorization),
            runner_data_plane: None,
            scm_credential_provider: None,
            human_oidc: None,
            github_installation: None,
            github_setup_key,
        })
    }

    #[must_use]
    pub fn with_scm_credential_provider(
        mut self,
        provider: Arc<dyn GitHubInstallationTokenProvider>,
    ) -> Self {
        self.scm_credential_provider = Some(provider);
        self
    }

    #[must_use]
    pub fn with_authorization_engine(mut self, engine: CedarAuthorizationEngine) -> Self {
        self.authorization = Arc::new(engine);
        self
    }

    pub fn with_human_oidc(
        mut self,
        public_origin: String,
        cookie_sealing_key: &[u8; 32],
        adapter: Arc<dyn HumanOidcAdapter>,
        limits: HumanOidcLimits,
    ) -> Result<Self, ServerBuildError> {
        validate_human_oidc_public_origin(&public_origin)?;
        let limits = limits.validate()?;
        let callback = format!("{public_origin}/auth/oidc/callback");
        if callback.len() > 4096 {
            return Err(ServerBuildError::HumanOidc(
                HumanOidcError::InvalidConfiguration,
            ));
        }
        self.human_oidc = Some(Arc::new(HumanOidcState {
            public_origin,
            cookie_sealer: CookieSealer::new(cookie_sealing_key)?,
            adapter,
            exchange_admission: Arc::new(tokio::sync::Semaphore::new(
                limits.maximum_concurrent_exchanges,
            )),
            session_policy: SessionPolicy::default(),
            metrics: Arc::new(HumanAuthMetrics::default()),
            github_oauth: None,
        }));
        Ok(self)
    }

    pub fn with_github_oauth_quickstart(
        mut self,
        config: GitHubOauthQuickstartConfig,
    ) -> Result<Self, ServerBuildError> {
        let human = self.human_oidc.as_mut().ok_or(ServerBuildError::HumanOidc(
            HumanOidcError::InvalidConfiguration,
        ))?;
        validate_human_oidc_public_origin(&config.web_origin)?;
        if config.allowed_roles.is_empty()
            || config.tenant_id.is_empty()
            || config.client_id.is_empty()
        {
            return Err(ServerBuildError::HumanOidc(
                HumanOidcError::InvalidConfiguration,
            ));
        }
        let provider_id = "github-oauth".to_owned();
        let redirect_uri = format!("{}/auth/callback", human.public_origin);
        let authorization_endpoint = format!("{}/login/oauth/authorize", config.web_origin);
        let token_endpoint = format!("{}/login/oauth/access_token", config.web_origin);
        let mut provider = TenantOidcProviderConfiguration {
            id: provider_id.clone(),
            tenant_id: config.tenant_id.clone(),
            issuer: config.web_origin.clone(),
            client_id: config.client_id.clone(),
            authorization_endpoint: authorization_endpoint.clone(),
            token_endpoint,
            jwks_uri: format!("{}/api/v3/meta", config.web_origin),
            redirect_uri,
            scopes: vec![
                "read:user".to_owned(),
                "read:org".to_owned(),
                "repo".to_owned(),
            ],
            mfa_claim: serde_json::json!({}),
            status: "active".to_owned(),
            configuration_digest: ContentDigest::sha256([]),
            created_unix_ms: config.now_unix_ms,
            updated_unix_ms: config.now_unix_ms,
            version: 1,
        };
        provider.configuration_digest = provider
            .expected_configuration_digest()
            .map_err(|_| ServerBuildError::HumanOidc(HumanOidcError::InvalidConfiguration))?;
        let tenant = TenantIdentityRecord {
            id: config.tenant_id.clone(),
            slug: config.tenant_id.clone(),
            name: config.tenant_name,
            status: "active".to_owned(),
            settings: serde_json::json!({"quickstart_auth":"github-oauth"}),
            created_unix_ms: config.now_unix_ms,
            updated_unix_ms: config.now_unix_ms,
            version: 1,
        };
        match self.control_plane.tenant_identity(&tenant.id) {
            Ok(existing) if existing.slug == tenant.slug && existing.status == "active" => {}
            Ok(_) => {
                return Err(ServerBuildError::HumanOidc(
                    HumanOidcError::InvalidConfiguration,
                ))
            }
            Err(ControlPlaneError::NotFound { .. }) => {
                self.control_plane.put_tenant_identity(&tenant, None)?;
            }
            Err(error) => return Err(error.into()),
        }
        match self
            .control_plane
            .tenant_oidc_provider_configuration(&provider.tenant_id, &provider.id)
        {
            Ok(existing)
                if existing.issuer == provider.issuer
                    && existing.client_id == provider.client_id
                    && existing.redirect_uri == provider.redirect_uri
                    && existing.status == "active" => {}
            Ok(_) => {
                return Err(ServerBuildError::HumanOidc(
                    HumanOidcError::InvalidConfiguration,
                ))
            }
            Err(ControlPlaneError::NotFound { .. }) => {
                self.control_plane
                    .put_tenant_oidc_provider_configuration(&provider, None)?;
            }
            Err(error) => return Err(error.into()),
        }
        Arc::get_mut(human)
            .ok_or(ServerBuildError::HumanOidc(
                HumanOidcError::InvalidConfiguration,
            ))?
            .github_oauth = Some(GitHubOauthState {
            tenant_id: config.tenant_id,
            provider_id,
            issuer: config.web_origin,
            client_id: config.client_id,
            authorization_endpoint,
            adapter: config.adapter,
            allowed_roles: config.allowed_roles,
        });
        Ok(self)
    }

    #[must_use]
    pub fn human_auth_metrics(&self) -> Option<crate::HumanAuthMetricsSnapshot> {
        self.human_oidc
            .as_ref()
            .map(|human| human.metrics.snapshot())
    }

    /// Enable tenant-owned GitHub App installation administration. The
    /// provider exposes verified public metadata only; App JWTs, installation
    /// tokens, and private-key material never cross this boundary.
    pub fn with_github_installation_provider(
        mut self,
        public_config: GitHubAppPublicConfig,
        credential_reference: String,
        provider: Arc<dyn GitHubInstallationProvider>,
    ) -> Result<Self, ServerBuildError> {
        if !credential_reference.starts_with("provider://github-app/")
            || credential_reference.len() > 255
            || credential_reference
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(ServerBuildError::GitHubInstallation(
                GitHubError::InvalidConfiguration,
            ));
        }
        self.github_installation = Some(Arc::new(GitHubInstallationState {
            public_config,
            credential_reference,
            provider,
            setup_key: self.github_setup_key.clone(),
            admission: Arc::new(tokio::sync::Semaphore::new(GITHUB_SETUP_MAX_CONCURRENCY)),
            metrics: Arc::new(GitHubInstallationMetrics::default()),
        }));
        Ok(self)
    }

    #[must_use]
    pub fn github_installation_metrics(&self) -> Option<GitHubInstallationMetricsSnapshot> {
        self.github_installation
            .as_ref()
            .map(|github| github.metrics.snapshot())
    }

    /// Reconcile at most one durable, signature-verified GitHub installation
    /// lifecycle delivery. Provider credentials remain behind the configured
    /// adapter and are never written into the delivery journal.
    pub async fn process_github_lifecycle_once(
        &self,
        worker_id: &str,
    ) -> Result<bool, GitHubLifecycleWorkerError> {
        self.process_github_lifecycle_once_at(worker_id, wall_clock_unix_ms()?)
            .await
    }

    /// Deterministic clock entry point for recovery and adversarial tests.
    #[doc(hidden)]
    pub async fn process_github_lifecycle_once_at(
        &self,
        worker_id: &str,
        now_unix_ms: u64,
    ) -> Result<bool, GitHubLifecycleWorkerError> {
        if self.github_installation.is_none() || self.control_plane.recovery_state()?.safe_mode {
            return Ok(false);
        }
        let Some(delivery) = self.control_plane.claim_next_github_lifecycle_delivery(
            worker_id,
            now_unix_ms,
            GITHUB_LIFECYCLE_LEASE_MS,
        )?
        else {
            return Ok(false);
        };
        reconcile_claimed_github_lifecycle(self, worker_id, delivery).await?;
        Ok(true)
    }

    pub fn with_runner_data_plane(
        mut self,
        root: impl AsRef<std::path::Path>,
    ) -> Result<Self, RunnerServiceError> {
        self.runner_data_plane = Some(Arc::new(RunnerDataPlane::open(
            root,
            Arc::clone(&self.capsule_signing_key),
        )?));
        Ok(self)
    }

    pub(crate) fn runner_source_cas(&self) -> Option<runtrue_storage::FsCas> {
        self.runner_data_plane.as_ref().map(|plane| plane.cas())
    }

    /// Construct the mTLS runner service without exposing installation key
    /// material across the library boundary.
    #[doc(hidden)]
    pub fn runner_control_service(
        &self,
        authority: Arc<RunnerCertificateAuthority>,
    ) -> Result<RunnerControlService, RunnerServiceError> {
        self.runner_control_service_with_config(authority, RunnerControlConfig::default())
    }

    /// Construct the mTLS runner service with an explicit protocol security
    /// minimum and bounded transport configuration.
    #[doc(hidden)]
    pub fn runner_control_service_with_config(
        &self,
        authority: Arc<RunnerCertificateAuthority>,
        config: RunnerControlConfig,
    ) -> Result<RunnerControlService, RunnerServiceError> {
        let service = if let Some(data_plane) = &self.runner_data_plane {
            RunnerControlService::new_with_data_plane_and_config(
                Arc::clone(&self.control_plane),
                authority,
                Arc::clone(&self.secret_master_key),
                Arc::clone(&self.oidc),
                Arc::clone(data_plane),
                config,
            )?
        } else {
            RunnerControlService::new_with_brokers_and_config(
                Arc::clone(&self.control_plane),
                authority,
                Arc::clone(&self.secret_master_key),
                Arc::clone(&self.oidc),
                config,
            )?
        };
        match &self.scm_credential_provider {
            Some(provider) => service.with_scm_credential_provider(Arc::clone(provider)),
            None => Ok(service),
        }
    }

    #[cfg(test)]
    pub(in crate::app) fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }
}

#[derive(Debug, Error)]
pub enum ServerBuildError {
    #[error("bootstrap token must contain 1 to 4096 safe bytes")]
    InvalidBootstrapToken,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid SCM webhook configuration: {0}")]
    Scm(#[from] ScmError),
    #[error("invalid OIDC issuer configuration: {0}")]
    Oidc(#[from] runtrue_oidc::OidcError),
    #[error("invalid server authorization policy: {0}")]
    Cedar(#[from] runtrue_policy::CedarAuthorizationError),
    #[error("invalid human OIDC configuration: {0}")]
    HumanOidc(#[from] HumanOidcError),
    #[error("quickstart identity persistence failed: {0}")]
    ControlPlane(#[from] ControlPlaneError),
    #[error("invalid GitHub App installation configuration: {0}")]
    GitHubInstallation(#[from] GitHubError),
}

/// Redaction-safe failure of the durable GitHub installation reconciler.
#[derive(Debug, Error)]
pub enum GitHubLifecycleWorkerError {
    #[error("system clock is outside the supported Unix millisecond range")]
    Clock,
    #[error("GitHub lifecycle persistence failed: {0}")]
    ControlPlane(#[from] ControlPlaneError),
}

pub(in crate::app) fn derive_security_seed(seed: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hash = sha2::Sha256::new();
    hash.update(b"runtrue.server.security-key.v1\0");
    hash.update(domain);
    hash.update(seed);
    hash.finalize().into()
}
use super::{BUILTIN_SERVER_AUTHORIZATION_POLICY, DEFAULT_REQUEST_TIMEOUT};
use crate::human_oidc::{validate_human_oidc_public_origin, HumanOidcLimits};
use hmac::Mac as _;
use rand_core::RngCore as _;
use runtrue_control_plane::{TenantIdentityRecord, TenantOidcProviderConfiguration};
use runtrue_model::ContentDigest;
use runtrue_oidc::OidcSigningKey;
use runtrue_policy::DenyFirstPolicy;
