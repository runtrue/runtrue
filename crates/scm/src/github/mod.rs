//! Outbound GitHub App operations through an injectable HTTPS transport.
//!
//! Source and check access tokens are always exact-repository and
//! permission-scoped. Installation catalog reconciliation uses a distinct,
//! internal metadata-read-only token. All tokens remain inside this broker and
//! are redacted/zeroized. Check annotations are emitted in API-sized batches
//! and all public text is escaped as plain text.

use thiserror::Error;

// GHES 3.19 rejects the newer 2026-03-10 contract with HTTP 400. Keep the
// provider on the API version shared by GitHub.com and supported GHES releases.
pub const GITHUB_API_VERSION: &str = "2022-11-28";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 8192;
const MAX_REPOSITORIES: usize = 500;
const MAX_ANNOTATIONS_PER_REQUEST: usize = 50;
const MAX_ANNOTATIONS_TOTAL: usize = 10_000;
const MAX_CHECK_ACTIONS: usize = 3;
const MAX_CHECK_ACTION_LABEL_BYTES: usize = 20;
const MAX_CHECK_ACTION_DESCRIPTION_BYTES: usize = 40;
const MAX_CHECK_ACTION_IDENTIFIER_BYTES: usize = 20;
const MAX_CHECK_TEXT_BYTES: usize = 64 * 1024;
const MAX_CHECK_TITLE_BYTES: usize = 255;
const MAX_CHECK_NAME_BYTES: usize = 100;
const MAX_EXTERNAL_ID_BYTES: usize = 255;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_SELECTED_REPOSITORIES: usize = 1_000;
const MAX_REPOSITORIES_PER_PAGE: usize = 100;
const MAX_APP_SLUG_BYTES: usize = 100;
const MIN_INSTALL_STATE_BYTES: usize = 43;
const MAX_INSTALL_STATE_BYTES: usize = 256;
const MAX_ACCOUNT_LOGIN_BYTES: usize = 100;
const MAX_DEFAULT_BRANCH_BYTES: usize = 255;

/// Exact, non-secret endpoints for one GitHub provider.
///
/// GitHub.com is admitted only as the fixed `github.com` / `api.github.com`
/// pair. A GitHub Enterprise Server API must be the exact web authority plus
/// `/api/v3`. This prevents an operator typo or substitution from sending an
/// App JWT or installation token to a different host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubProviderEndpoints {
    web_origin: String,
    api_origin: String,
    provider_host: String,
    provider_port: u16,
}

impl GitHubProviderEndpoints {
    #[must_use]
    pub fn github_dot_com() -> Self {
        Self {
            web_origin: "https://github.com".to_owned(),
            api_origin: "https://api.github.com".to_owned(),
            provider_host: "github.com".to_owned(),
            provider_port: 443,
        }
    }

    pub fn new(
        web_origin: impl Into<String>,
        api_origin: impl Into<String>,
    ) -> Result<Self, GitHubError> {
        let web_origin = web_origin.into();
        let api_origin = api_origin.into();
        let (provider_host, provider_port) = validate_web_origin(&web_origin)?;
        validate_api_origin(&api_origin)?;
        let valid_pair = if web_origin == "https://github.com" {
            api_origin == "https://api.github.com"
        } else {
            api_origin == format!("{web_origin}/api/v3")
        };
        if !valid_pair {
            return Err(GitHubError::InvalidConfiguration);
        }
        Ok(Self {
            web_origin,
            api_origin,
            provider_host,
            provider_port,
        })
    }

    #[must_use]
    pub fn web_origin(&self) -> &str {
        &self.web_origin
    }

    #[must_use]
    pub fn api_origin(&self) -> &str {
        &self.api_origin
    }

    #[must_use]
    pub fn provider_host(&self) -> &str {
        &self.provider_host
    }

    #[must_use]
    pub const fn provider_port(&self) -> u16 {
        self.provider_port
    }

    /// Build the only repository HTTPS URL authorized for this provider and
    /// exact owner/name pair. Provider payloads cannot supply an alternate
    /// origin, path, port, or credential channel.
    pub fn repository_clone_url(&self, owner: &str, name: &str) -> Result<String, GitHubError> {
        if !valid_account_login(owner) || !valid_repository_segment(name) {
            return Err(GitHubError::InvalidConfiguration);
        }
        Ok(format!("{}/{owner}/{name}.git", self.web_origin))
    }
}

/// Public, non-secret GitHub App identity used to build the provider-owned
/// installation action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubAppPublicConfig {
    app_id: u64,
    app_slug: String,
    endpoints: GitHubProviderEndpoints,
}

impl GitHubAppPublicConfig {
    pub fn new(app_id: u64, app_slug: impl Into<String>) -> Result<Self, GitHubError> {
        Self::new_with_endpoints(app_id, app_slug, GitHubProviderEndpoints::github_dot_com())
    }

    pub fn new_with_origins(
        app_id: u64,
        app_slug: impl Into<String>,
        web_origin: impl Into<String>,
        api_origin: impl Into<String>,
    ) -> Result<Self, GitHubError> {
        Self::new_with_endpoints(
            app_id,
            app_slug,
            GitHubProviderEndpoints::new(web_origin, api_origin)?,
        )
    }

    pub fn new_with_endpoints(
        app_id: u64,
        app_slug: impl Into<String>,
        endpoints: GitHubProviderEndpoints,
    ) -> Result<Self, GitHubError> {
        let app_slug = app_slug.into();
        if app_id == 0 || !valid_app_slug(&app_slug) {
            return Err(GitHubError::InvalidConfiguration);
        }
        Ok(Self {
            app_id,
            app_slug,
            endpoints,
        })
    }

    #[must_use]
    pub const fn app_id(&self) -> u64 {
        self.app_id
    }

    #[must_use]
    pub fn app_slug(&self) -> &str {
        &self.app_slug
    }

    #[must_use]
    pub fn web_origin(&self) -> &str {
        self.endpoints.web_origin()
    }

    #[must_use]
    pub fn api_origin(&self) -> &str {
        self.endpoints.api_origin()
    }

    #[must_use]
    pub fn provider_host(&self) -> &str {
        self.endpoints.provider_host()
    }

    #[must_use]
    pub const fn provider_port(&self) -> u16 {
        self.endpoints.provider_port()
    }

    #[must_use]
    pub const fn endpoints(&self) -> &GitHubProviderEndpoints {
        &self.endpoints
    }

    pub fn repository_clone_url(&self, owner: &str, name: &str) -> Result<String, GitHubError> {
        self.endpoints.repository_clone_url(owner, name)
    }

    /// Build a GitHub-owned installation URL carrying an opaque, caller-owned
    /// one-use state. Requiring at least 43 base64url characters makes a
    /// 256-bit random state representable without accepting short identifiers.
    pub fn installation_url(&self, state: &str) -> Result<String, GitHubError> {
        if !valid_install_state(state) {
            return Err(GitHubError::InvalidInstallState);
        }
        let app_path = if self.endpoints.web_origin == "https://github.com" {
            "apps"
        } else {
            "github-apps"
        };
        Ok(format!(
            "{}/{app_path}/{}/installations/new?state={state}",
            self.endpoints.web_origin, self.app_slug
        ))
    }

    /// Build GitHub's repository preselection URL for one user or organization.
    /// GitHub accepts at most 100 repository identifiers for this flow.
    pub fn installation_url_for_repositories(
        &self,
        state: &str,
        suggested_target_id: u64,
        repository_ids: &[u64],
    ) -> Result<String, GitHubError> {
        if !valid_install_state(state)
            || suggested_target_id == 0
            || repository_ids.is_empty()
            || repository_ids.len() > 100
            || repository_ids.contains(&0)
            || repository_ids
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != repository_ids.len()
        {
            return Err(GitHubError::InvalidInstallState);
        }
        let app_path = if self.endpoints.web_origin == "https://github.com" {
            "apps"
        } else {
            "github-apps"
        };
        let repositories = repository_ids
            .iter()
            .map(|repository_id| format!("&repository_ids%5B%5D={repository_id}"))
            .collect::<String>();
        Ok(format!(
            "{}/{app_path}/{}/installations/new/permissions?state={state}&suggested_target_id={suggested_target_id}{repositories}",
            self.endpoints.web_origin, self.app_slug
        ))
    }
}

mod validation;
use validation::{valid_app_slug, valid_install_state, validate_api_origin, validate_web_origin};
mod client;
pub use client::*;
mod installation;
pub use installation::*;
mod webhook;
pub use webhook::*;
mod checks;
pub use checks::*;
mod pagination;
use checks::valid_repository_segment;
use pagination::valid_account_login;
pub struct GitHubAppBroker<T, J> {
    pub(super) transport: T,
    pub(super) jwt_provider: J,
    pub(super) api_origin: String,
}

impl<T, J> GitHubAppBroker<T, J>
where
    T: GitHubTransport,
    J: GitHubAppJwtProvider,
{
    pub fn new(
        transport: T,
        jwt_provider: J,
        api_origin: impl Into<String>,
    ) -> Result<Self, GitHubError> {
        let api_origin = api_origin.into();
        validate_api_origin(&api_origin)?;
        Ok(Self {
            transport,
            jwt_provider,
            api_origin,
        })
    }
}

impl<T, J> GitHubAppBroker<T, J> {
    pub fn into_parts(self) -> (T, J) {
        (self.transport, self.jwt_provider)
    }
}
#[derive(Debug, Error)]
pub enum GitHubError {
    #[error("invalid GitHub App broker configuration")]
    InvalidConfiguration,
    #[error("invalid GitHub App installation state")]
    InvalidInstallState,
    #[error("invalid GitHub App installation identity")]
    InvalidInstallation,
    #[error("GitHub App installation metadata did not match the exact request")]
    InstallationSubstitution,
    #[error("GitHub App installation is missing required permissions")]
    InsufficientInstallationPermissions,
    #[error("GitHub App installation repository catalog exceeded the configured limit")]
    RepositoryCatalogTooLarge,
    #[error("invalid or over-broad GitHub installation token scope")]
    InvalidTokenScope,
    #[error("invalid GitHub check run request")]
    InvalidCheckRequest,
    #[error("GitHub response exceeded the configured byte limit")]
    ResponseTooLarge,
    #[error("GitHub request exceeded the configured byte limit")]
    RequestTooLarge,
    #[error("GitHub returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    #[error("GitHub returned a malformed response")]
    MalformedResponse,
    #[error("GitHub transport failed")]
    Transport,
    #[error("GitHub App JWT provider failed")]
    JwtProvider,
    #[error("GitHub rate limit requires a bounded retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },
    #[error("GitHub check reconciliation returned multiple or inconsistent exact matches")]
    AmbiguousCheckReconciliation,
    #[error(
        "GitHub check run {check_run_id} was created but only {confirmed_annotations} annotations are confirmed; reconcile before retrying"
    )]
    PartialPublish {
        check_run_id: u64,
        confirmed_annotations: usize,
    },
}

fn response_error(response: &GitHubResponse) -> GitHubError {
    if response.status == 429 {
        GitHubError::RateLimited {
            retry_after_seconds: response.retry_after_seconds.unwrap_or(1).min(60 * 60),
        }
    } else {
        GitHubError::UnexpectedStatus(response.status)
    }
}

#[cfg(test)]
mod tests;
