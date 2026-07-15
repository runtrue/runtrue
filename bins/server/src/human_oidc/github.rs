use crate::human_oidc::{
    network::{
        encode_query_component, read_bounded, read_bounded_zeroizing, validate_external_endpoint,
        validate_secret_text, PublicOnlyOidcResolver,
    },
    validate_human_oidc_public_origin, GitHubAccessToken, GitHubUserCatalog, GitHubUserRepository,
    HumanOidcError, HumanOidcLimits, VerifiedGitHubIdentity, MAX_AUTHORIZATION_CODE_BYTES,
    MAX_OIDC_RESPONSE_HEADER_BYTES, MAX_TOKEN_RESPONSE_BYTES,
};
use runtrue_model::ContentDigest;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
use ureq::{unversioned::transport::DefaultConnector, Agent};
use zeroize::{Zeroize as _, Zeroizing};

pub trait GitHubOauthAdapter: Send + Sync {
    fn exchange_authorization_code(
        &self,
        authorization_code: &str,
        redirect_uri: &str,
    ) -> Result<VerifiedGitHubIdentity, HumanOidcError>;

    fn authorized_catalog(&self, _access_token: &str) -> Result<GitHubUserCatalog, HumanOidcError> {
        Err(HumanOidcError::InvalidConfiguration)
    }

    fn authorized_organizations(&self, access_token: &str) -> Result<Vec<String>, HumanOidcError> {
        self.authorized_catalog(access_token)
            .map(|catalog| catalog.organizations)
    }

    fn authorized_repositories(
        &self,
        access_token: &str,
        owner: &str,
        _viewer_login: &str,
    ) -> Result<Vec<GitHubUserRepository>, HumanOidcError> {
        self.authorized_catalog(access_token).map(|catalog| {
            catalog
                .repositories
                .into_iter()
                .filter(|repository| repository.owner.eq_ignore_ascii_case(owner))
                .collect()
        })
    }
}

#[derive(Clone)]
pub struct HardenedGitHubOauthClient {
    agent: Agent,
    token_endpoint: String,
    user_endpoint: String,
    api_origin: String,
    client_id: String,
    client_secret: Zeroizing<String>,
}

impl fmt::Debug for HardenedGitHubOauthClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardenedGitHubOauthClient")
            .finish_non_exhaustive()
    }
}

impl HardenedGitHubOauthClient {
    pub fn new(
        web_origin: &str,
        api_origin: &str,
        client_id: String,
        client_secret: Zeroizing<String>,
        limits: HumanOidcLimits,
    ) -> Result<Self, HumanOidcError> {
        validate_human_oidc_public_origin(web_origin)?;
        validate_human_oidc_public_origin(api_origin.trim_end_matches("/api/v3"))?;
        validate_secret_text(&client_id, 512, HumanOidcError::InvalidConfiguration)?;
        validate_secret_text(&client_secret, 4096, HumanOidcError::InvalidConfiguration)?;
        let limits = limits.validate()?;
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_OIDC_RESPONSE_HEADER_BYTES)
            .timeout_global(Some(limits.request_timeout))
            .timeout_resolve(Some(limits.connect_timeout))
            .timeout_connect(Some(limits.connect_timeout))
            .timeout_send_request(Some(limits.connect_timeout))
            .timeout_send_body(Some(limits.request_timeout))
            .timeout_recv_response(Some(limits.request_timeout))
            .timeout_recv_body(Some(limits.request_timeout))
            .build();
        Ok(Self {
            agent: Agent::with_parts(
                config,
                DefaultConnector::default(),
                PublicOnlyOidcResolver::default(),
            ),
            token_endpoint: format!("{web_origin}/login/oauth/access_token"),
            user_endpoint: format!("{}/user", api_origin.trim_end_matches('/')),
            api_origin: api_origin.trim_end_matches('/').to_owned(),
            client_id,
            client_secret,
        })
    }
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
}

#[derive(Deserialize, Serialize)]
struct GitHubUserResponse {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GitHubRepositoryOwnerResponse {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct GitHubOrganizationResponse {
    login: String,
}

#[derive(Deserialize)]
struct GitHubRepositoryResponse {
    id: u64,
    name: String,
    private: bool,
    visibility: Option<String>,
    default_branch: String,
    owner: GitHubRepositoryOwnerResponse,
}

const GITHUB_CATALOG_PAGE_SIZE: usize = 100;
const GITHUB_CATALOG_MAX_PAGES: usize = 10;
const GITHUB_CATALOG_PAGE_BYTES: usize = 2 * 1024 * 1024;

impl HardenedGitHubOauthClient {
    fn catalog_page<T: DeserializeOwned>(
        &self,
        path_and_query: &str,
        access_token: &str,
    ) -> Result<Vec<T>, HumanOidcError> {
        validate_secret_text(access_token, 2048, HumanOidcError::InvalidTokenResponse)?;
        let authorization = Zeroizing::new(format!("Bearer {access_token}"));
        let mut response = self
            .agent
            .get(format!("{}{}", self.api_origin, path_and_query))
            .header("accept", "application/vnd.github+json")
            .header("authorization", authorization.as_str())
            .header("user-agent", "runtrue-server")
            .call()
            .map_err(|_| HumanOidcError::Transport)?;
        if response.status().as_u16() != 200 {
            return Err(HumanOidcError::ProviderApiRejected);
        }
        let bytes = read_bounded(&mut response, GITHUB_CATALOG_PAGE_BYTES)?;
        serde_json::from_slice(&bytes).map_err(|_| HumanOidcError::InvalidTokenResponse)
    }

    fn repository_catalog(
        &self,
        access_token: &str,
        path_for_page: impl Fn(usize) -> String,
        owner_filter: Option<&str>,
    ) -> Result<Vec<GitHubUserRepository>, HumanOidcError> {
        let mut repositories = BTreeMap::<u64, GitHubUserRepository>::new();
        for page in 1..=GITHUB_CATALOG_MAX_PAGES {
            let values =
                self.catalog_page::<GitHubRepositoryResponse>(&path_for_page(page), access_token)?;
            let full_page = values.len() == GITHUB_CATALOG_PAGE_SIZE;
            for repository in values {
                if owner_filter
                    .is_some_and(|owner| !repository.owner.login.eq_ignore_ascii_case(owner))
                {
                    continue;
                }
                if repository.id == 0
                    || repository.owner.id == 0
                    || repository.name.is_empty()
                    || repository.name.len() > 255
                    || repository.owner.login.is_empty()
                    || repository.owner.login.len() > 255
                    || repository.default_branch.is_empty()
                    || repository.default_branch.len() > 255
                {
                    return Err(HumanOidcError::InvalidTokenResponse);
                }
                let visibility = repository.visibility.unwrap_or_else(|| {
                    if repository.private {
                        "private".to_owned()
                    } else {
                        "public".to_owned()
                    }
                });
                if !matches!(visibility.as_str(), "public" | "private" | "internal") {
                    return Err(HumanOidcError::InvalidTokenResponse);
                }
                repositories.insert(
                    repository.id,
                    GitHubUserRepository {
                        repository_id: repository.id,
                        owner_id: repository.owner.id,
                        owner: repository.owner.login,
                        name: repository.name,
                        visibility,
                        default_branch: repository.default_branch,
                    },
                );
            }
            if !full_page {
                break;
            }
        }
        Ok(repositories.into_values().collect())
    }
}

impl GitHubOauthAdapter for HardenedGitHubOauthClient {
    fn exchange_authorization_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<VerifiedGitHubIdentity, HumanOidcError> {
        validate_secret_text(
            code,
            MAX_AUTHORIZATION_CODE_BYTES,
            HumanOidcError::InvalidAuthorizationCode,
        )?;
        validate_external_endpoint(redirect_uri)?;
        let body = Zeroizing::new(format!(
            "client_id={}&client_secret={}&code={}&redirect_uri={}",
            encode_query_component(&self.client_id),
            encode_query_component(&self.client_secret),
            encode_query_component(code),
            encode_query_component(redirect_uri)
        ));
        let mut response = self
            .agent
            .post(&self.token_endpoint)
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .send(body.as_bytes())
            .map_err(|_| HumanOidcError::Transport)?;
        if response.status().as_u16() != 200 {
            return Err(HumanOidcError::TokenEndpointRejected);
        }
        let token_bytes = read_bounded_zeroizing(&mut response, MAX_TOKEN_RESPONSE_BYTES)?;
        let mut token: GitHubTokenResponse = serde_json::from_slice(&token_bytes)
            .map_err(|_| HumanOidcError::InvalidTokenResponse)?;
        if !token.token_type.eq_ignore_ascii_case("bearer") {
            token.access_token.zeroize();
            return Err(HumanOidcError::InvalidTokenResponse);
        }
        validate_secret_text(
            &token.access_token,
            8192,
            HumanOidcError::InvalidTokenResponse,
        )?;
        let access_token = GitHubAccessToken::new(std::mem::take(&mut token.access_token));
        let authorization = Zeroizing::new(format!("Bearer {}", access_token.expose()));
        let mut response = self
            .agent
            .get(&self.user_endpoint)
            .header("accept", "application/vnd.github+json")
            .header("authorization", authorization.as_str())
            .call()
            .map_err(|_| HumanOidcError::Transport)?;
        if response.status().as_u16() != 200 {
            return Err(HumanOidcError::TokenEndpointRejected);
        }
        let user_bytes = read_bounded(&mut response, 64 * 1024)?;
        let user: GitHubUserResponse = serde_json::from_slice(&user_bytes)
            .map_err(|_| HumanOidcError::InvalidTokenResponse)?;
        if user.id == 0 || user.login.is_empty() || user.login.len() > 255 {
            return Err(HumanOidcError::InvalidTokenResponse);
        }
        let claims_digest = ContentDigest::sha256(
            serde_json::to_vec(&user).map_err(|_| HumanOidcError::InvalidTokenResponse)?,
        );
        Ok(VerifiedGitHubIdentity {
            user_id: user.id,
            display_name: user
                .name
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| user.login.clone()),
            login: user.login,
            email: user.email,
            claims_digest,
            access_token,
        })
    }

    fn authorized_catalog(&self, access_token: &str) -> Result<GitHubUserCatalog, HumanOidcError> {
        let repositories = self.repository_catalog(
            access_token,
            |page| format!(
                "/user/repos?affiliation=owner%2Ccollaborator%2Corganization_member&sort=full_name&direction=asc&per_page={GITHUB_CATALOG_PAGE_SIZE}&page={page}"
            ),
            None,
        )?;
        let organizations = repositories
            .iter()
            .map(|repository| repository.owner.clone())
            .collect::<std::collections::BTreeSet<_>>();
        Ok(GitHubUserCatalog {
            organizations: organizations.into_iter().collect(),
            repositories,
        })
    }

    fn authorized_organizations(&self, access_token: &str) -> Result<Vec<String>, HumanOidcError> {
        let mut organizations = BTreeMap::<String, ()>::new();
        for page in 1..=GITHUB_CATALOG_MAX_PAGES {
            let values = self.catalog_page::<GitHubOrganizationResponse>(
                &format!("/user/orgs?per_page={GITHUB_CATALOG_PAGE_SIZE}&page={page}"),
                access_token,
            )?;
            let full_page = values.len() == GITHUB_CATALOG_PAGE_SIZE;
            for organization in values {
                if organization.login.is_empty() || organization.login.len() > 255 {
                    return Err(HumanOidcError::InvalidTokenResponse);
                }
                organizations.insert(organization.login, ());
            }
            if !full_page {
                break;
            }
        }
        Ok(organizations.into_keys().collect())
    }

    fn authorized_repositories(
        &self,
        access_token: &str,
        owner: &str,
        viewer_login: &str,
    ) -> Result<Vec<GitHubUserRepository>, HumanOidcError> {
        let owner = owner.to_owned();
        if owner.eq_ignore_ascii_case(viewer_login) {
            self.repository_catalog(
                access_token,
                |page| format!(
                    "/user/repos?affiliation=owner&sort=full_name&direction=asc&per_page={GITHUB_CATALOG_PAGE_SIZE}&page={page}"
                ),
                Some(&owner),
            )
        } else {
            let encoded_owner = encode_query_component(&owner);
            self.repository_catalog(
                access_token,
                |page| format!(
                    "/orgs/{encoded_owner}/repos?type=all&sort=full_name&direction=asc&per_page={GITHUB_CATALOG_PAGE_SIZE}&page={page}"
                ),
                Some(&owner),
            )
        }
    }
}
