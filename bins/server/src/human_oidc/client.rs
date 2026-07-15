use crate::human_oidc::{
    jwt::verify_id_token,
    network::{
        encode_query_component, read_bounded, read_bounded_zeroizing, validate_external_endpoint,
        validate_secret_text, PublicOnlyOidcResolver,
    },
    HumanOidcError, HumanOidcLimits, VerifiedHumanIdentity, MAX_AUTHORIZATION_CODE_BYTES,
    MAX_HUMAN_JWKS_BYTES, MAX_ID_TOKEN_BYTES, MAX_OIDC_RESPONSE_HEADER_BYTES,
    MAX_TOKEN_RESPONSE_BYTES,
};
use runtrue_control_plane::TenantOidcProviderConfiguration;
use serde::Deserialize;
use std::fmt;
use ureq::{unversioned::transport::DefaultConnector, Agent};
use zeroize::Zeroizing;

/// Injectable boundary used by HTTP application services. Production uses
/// [`HardenedHumanOidcClient`]; tests can substitute a deterministic adapter
/// without opening a loopback exception in the production resolver.
pub trait HumanOidcAdapter: Send + Sync {
    fn exchange_authorization_code(
        &self,
        provider: &TenantOidcProviderConfiguration,
        authorization_code: &str,
        pkce_verifier: &str,
        now_unix_seconds: u64,
    ) -> Result<VerifiedHumanIdentity, HumanOidcError>;
}

/// HTTPS-only OIDC client. Environment proxies, redirects, private/special
/// DNS answers, unbounded headers/bodies, and caller-chosen endpoints are all
/// rejected.
#[derive(Clone)]
pub struct HardenedHumanOidcClient {
    agent: Agent,
    limits: HumanOidcLimits,
}

impl fmt::Debug for HardenedHumanOidcClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardenedHumanOidcClient")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl HardenedHumanOidcClient {
    pub fn new(limits: HumanOidcLimits) -> Result<Self, HumanOidcError> {
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
        let agent = Agent::with_parts(
            config,
            DefaultConnector::default(),
            PublicOnlyOidcResolver::default(),
        );
        Ok(Self { agent, limits })
    }

    fn token_response(
        &self,
        provider: &TenantOidcProviderConfiguration,
        authorization_code: &str,
        pkce_verifier: &str,
    ) -> Result<Zeroizing<Vec<u8>>, HumanOidcError> {
        validate_external_endpoint(&provider.token_endpoint)?;
        validate_secret_text(
            authorization_code,
            MAX_AUTHORIZATION_CODE_BYTES,
            HumanOidcError::InvalidAuthorizationCode,
        )?;
        validate_secret_text(
            pkce_verifier,
            1024,
            HumanOidcError::InvalidAuthorizationCode,
        )?;
        let mut body = Zeroizing::new(String::with_capacity(
            authorization_code.len() + pkce_verifier.len() + provider.redirect_uri.len() + 128,
        ));
        for (index, (name, value)) in [
            ("grant_type", "authorization_code"),
            ("code", authorization_code),
            ("redirect_uri", provider.redirect_uri.as_str()),
            ("client_id", provider.client_id.as_str()),
            ("code_verifier", pkce_verifier),
        ]
        .into_iter()
        .enumerate()
        {
            if index != 0 {
                body.push('&');
            }
            body.push_str(name);
            body.push('=');
            body.push_str(&encode_query_component(value));
        }
        let mut response = self
            .agent
            .post(&provider.token_endpoint)
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .send(body.as_bytes())
            .map_err(|_| HumanOidcError::Transport)?;
        if response.status().as_u16() != 200 {
            return Err(HumanOidcError::TokenEndpointRejected);
        }
        read_bounded_zeroizing(&mut response, MAX_TOKEN_RESPONSE_BYTES)
    }

    fn jwks(&self, provider: &TenantOidcProviderConfiguration) -> Result<Vec<u8>, HumanOidcError> {
        validate_external_endpoint(&provider.jwks_uri)?;
        let mut response = self
            .agent
            .get(&provider.jwks_uri)
            .header("accept", "application/json")
            .call()
            .map_err(|_| HumanOidcError::Transport)?;
        if response.status().as_u16() != 200 {
            return Err(HumanOidcError::JwksEndpointRejected);
        }
        read_bounded(&mut response, MAX_HUMAN_JWKS_BYTES)
    }
}

impl HumanOidcAdapter for HardenedHumanOidcClient {
    fn exchange_authorization_code(
        &self,
        provider: &TenantOidcProviderConfiguration,
        authorization_code: &str,
        pkce_verifier: &str,
        now_unix_seconds: u64,
    ) -> Result<VerifiedHumanIdentity, HumanOidcError> {
        if provider.status != "active" {
            return Err(HumanOidcError::ProviderDisabled);
        }
        let token_response = self.token_response(provider, authorization_code, pkce_verifier)?;
        let response: TokenResponse<'_> = serde_json::from_slice(&token_response)
            .map_err(|_| HumanOidcError::InvalidTokenResponse)?;
        validate_secret_text(
            response.id_token,
            MAX_ID_TOKEN_BYTES,
            HumanOidcError::InvalidIdToken,
        )?;
        let jwks = self.jwks(provider)?;
        verify_id_token(response.id_token, &jwks, provider, now_unix_seconds)
    }
}

#[derive(Deserialize)]
struct TokenResponse<'a> {
    #[serde(borrow)]
    id_token: &'a str,
}
