use super::{
    validation::{is_public_ip, parse_strict_json, validate_api_origin, validate_secret_token},
    GitHubError, MAX_RESPONSE_BYTES, MAX_RESPONSE_HEADER_BYTES,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, io::Read as _, time::Duration};
use ureq::{
    http::Uri,
    unversioned::{
        resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver},
        transport::{DefaultConnector, NextTimeout},
    },
    Agent,
};
use zeroize::Zeroizing;
/// Fixed resource bounds for outbound GitHub API calls. These limits are
/// deliberately not caller-controlled per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitHubTransportLimits {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for GitHubTransportLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// HTTPS-only GitHub transport with environment proxies and redirects
/// disabled. DNS answers containing a private or special address are rejected
/// as a unit so a public answer cannot mask a rebinding answer.
#[derive(Clone)]
pub struct HardenedGitHubTransport {
    agent: Agent,
    api_origin: String,
}

impl fmt::Debug for HardenedGitHubTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardenedGitHubTransport")
            .field("api_origin", &self.api_origin)
            .finish_non_exhaustive()
    }
}

impl HardenedGitHubTransport {
    pub fn new(
        api_origin: impl Into<String>,
        limits: GitHubTransportLimits,
    ) -> Result<Self, GitHubError> {
        let api_origin = api_origin.into();
        validate_api_origin(&api_origin)?;
        if limits.connect_timeout.is_zero()
            || limits.request_timeout.is_zero()
            || limits.connect_timeout > limits.request_timeout
            || limits.request_timeout > Duration::from_secs(120)
        {
            return Err(GitHubError::InvalidConfiguration);
        }
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .timeout_global(Some(limits.request_timeout))
            .timeout_connect(Some(limits.connect_timeout))
            .timeout_send_request(Some(limits.connect_timeout))
            .timeout_send_body(Some(limits.request_timeout))
            .timeout_recv_response(Some(limits.request_timeout))
            .timeout_recv_body(Some(limits.request_timeout))
            .build();
        let agent = Agent::with_parts(
            config,
            DefaultConnector::default(),
            PublicOnlyResolver::default(),
        );
        Ok(Self { agent, api_origin })
    }
}

#[derive(Debug, Default)]
struct PublicOnlyResolver(DefaultResolver);

impl Resolver for PublicOnlyResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addresses = self.0.resolve(uri, config, timeout)?;
        if addresses.iter().any(|address| !is_public_ip(address.ip())) {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(addresses)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveToken(Zeroizing<String>);

impl SensitiveToken {
    pub fn new(value: String) -> Result<Self, GitHubError> {
        validate_secret_token(&value)?;
        Ok(Self(Zeroizing::new(value)))
    }

    pub(super) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

/// Validate the public claims returned by a non-exportable App-JWT signer.
/// Signature verification remains GitHub's responsibility; this boundary
/// prevents a confused signer/provider from returning a token for another App
/// or an unbounded lifetime.
pub fn validate_github_app_jwt(
    value: String,
    expected_app_id: u64,
    now_unix_seconds: u64,
) -> Result<SensitiveToken, GitHubError> {
    if expected_app_id == 0 {
        return Err(GitHubError::JwtProvider);
    }
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(GitHubError::JwtProvider);
    }
    let header = Base64UrlUnpadded::decode_vec(parts[0]).map_err(|_| GitHubError::JwtProvider)?;
    let claims = Base64UrlUnpadded::decode_vec(parts[1]).map_err(|_| GitHubError::JwtProvider)?;
    let signature =
        Base64UrlUnpadded::decode_vec(parts[2]).map_err(|_| GitHubError::JwtProvider)?;
    if header.len() > 1024 || claims.len() > 2048 || signature.is_empty() || signature.len() > 1024
    {
        return Err(GitHubError::JwtProvider);
    }
    let header = parse_strict_json(&header).map_err(|_| GitHubError::JwtProvider)?;
    let header = header.as_object().ok_or(GitHubError::JwtProvider)?;
    if header.len() > 2
        || header.get("alg").and_then(Value::as_str) != Some("RS256")
        || header
            .get("typ")
            .is_some_and(|value| value.as_str() != Some("JWT"))
    {
        return Err(GitHubError::JwtProvider);
    }
    let claims = parse_strict_json(&claims).map_err(|_| GitHubError::JwtProvider)?;
    let claims = claims.as_object().ok_or(GitHubError::JwtProvider)?;
    if claims.len() != 3 {
        return Err(GitHubError::JwtProvider);
    }
    let issuer_matches = claims
        .get("iss")
        .and_then(Value::as_u64)
        .is_some_and(|issuer| issuer == expected_app_id)
        || claims
            .get("iss")
            .and_then(Value::as_str)
            .and_then(|issuer| issuer.parse::<u64>().ok())
            .is_some_and(|issuer| issuer == expected_app_id);
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(GitHubError::JwtProvider)?;
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(GitHubError::JwtProvider)?;
    if !issuer_matches
        || issued_at > now_unix_seconds
        || issued_at.saturating_add(60) < now_unix_seconds
        || expires_at <= now_unix_seconds.saturating_add(30)
        || expires_at > issued_at.saturating_add(10 * 60)
    {
        return Err(GitHubError::JwtProvider);
    }
    SensitiveToken::new(value).map_err(|_| GitHubError::JwtProvider)
}

impl fmt::Debug for SensitiveToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveToken([REDACTED])")
    }
}

pub trait GitHubAppJwtProvider {
    /// Mint a short-lived GitHub App JWT for this exact request time. The
    /// provider owns private-key loading and JWT claim validation.
    fn mint(&mut self, now_unix_seconds: u64) -> Result<SensitiveToken, GitHubError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHubMethod {
    Get,
    Post,
    Patch,
}

pub struct GitHubRequest {
    pub method: GitHubMethod,
    pub url: String,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) bearer_token: SensitiveToken,
    pub(super) body: Zeroizing<Vec<u8>>,
}

impl GitHubRequest {
    #[must_use]
    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Sensitive credential accessor for the HTTPS transport only. Transport
    /// implementations must not persist or log the returned value.
    #[must_use]
    pub fn bearer_token(&self) -> &str {
        self.bearer_token.expose()
    }
}

impl fmt::Debug for GitHubRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub struct GitHubResponse {
    pub status: u16,
    pub(super) retry_after_seconds: Option<u64>,
    body: Zeroizing<Vec<u8>>,
}

impl GitHubResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Result<Self, GitHubError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GitHubError::ResponseTooLarge);
        }
        Ok(Self {
            status,
            retry_after_seconds: None,
            body: Zeroizing::new(body),
        })
    }

    pub fn with_retry_after_seconds(
        mut self,
        retry_after_seconds: u64,
    ) -> Result<Self, GitHubError> {
        if retry_after_seconds == 0 || retry_after_seconds > 60 * 60 {
            return Err(GitHubError::MalformedResponse);
        }
        self.retry_after_seconds = Some(retry_after_seconds);
        Ok(self)
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for GitHubResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubResponse")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub trait GitHubTransport {
    fn send(&mut self, request: GitHubRequest) -> Result<GitHubResponse, GitHubError>;
}

impl GitHubTransport for HardenedGitHubTransport {
    fn send(&mut self, request: GitHubRequest) -> Result<GitHubResponse, GitHubError> {
        if !request.url.starts_with(&format!("{}/", self.api_origin))
            || request.url.len() > 8 * 1024
            || request.url.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(GitHubError::InvalidConfiguration);
        }
        let authorization = Zeroizing::new(format!("Bearer {}", request.bearer_token()));
        let mut response = match request.method {
            GitHubMethod::Get => {
                let mut outbound = self.agent.get(&request.url);
                for (name, value) in request.headers() {
                    outbound = outbound.header(name, value);
                }
                outbound
                    .header("authorization", authorization.as_str())
                    .call()
                    .map_err(|_| GitHubError::Transport)?
            }
            GitHubMethod::Post => {
                let mut outbound = self.agent.post(&request.url);
                for (name, value) in request.headers() {
                    outbound = outbound.header(name, value);
                }
                outbound
                    .header("authorization", authorization.as_str())
                    .send(request.body())
                    .map_err(|_| GitHubError::Transport)?
            }
            GitHubMethod::Patch => {
                let mut outbound = self.agent.patch(&request.url);
                for (name, value) in request.headers() {
                    outbound = outbound.header(name, value);
                }
                outbound
                    .header("authorization", authorization.as_str())
                    .send(request.body())
                    .map_err(|_| GitHubError::Transport)?
            }
        };
        let status = response.status().as_u16();
        let retry_after_seconds = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0 && *seconds <= 60 * 60);
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(u64::try_from(MAX_RESPONSE_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut body)
            .map_err(|_| GitHubError::Transport)?;
        let mut response = GitHubResponse::new(status, body)?;
        response.retry_after_seconds = retry_after_seconds;
        Ok(response)
    }
}
