//! Hardened Vault/OpenBao HTTP transport and endpoint policy.
use super::super::model::{
    ProviderError, MAX_PROVIDER_RESPONSE_BYTES, MAX_VAULT_CA_BUNDLE_BYTES,
    MAX_VAULT_CA_CERTIFICATES, MAX_VAULT_REQUEST_BYTES, MAX_VAULT_RESPONSE_HEADER_BYTES,
};
use super::super::validation::validate_namespace;
use super::{reference::normalize_vault_address, token::VaultToken};
use std::{
    fmt,
    io::Read as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use ureq::{
    http::Uri,
    tls::{parse_pem, PemItem, RootCerts, TlsConfig, TlsProvider},
    unversioned::{
        resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver},
        transport::{DefaultConnector, NextTimeout},
    },
    Agent,
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultHttpMethod {
    Get,
    Post,
}

pub struct VaultHttpRequest {
    pub(crate) method: VaultHttpMethod,
    pub(crate) url: String,
    pub(crate) namespace: Option<String>,
    pub(crate) token: VaultToken,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl VaultHttpRequest {
    #[must_use]
    pub const fn method(&self) -> VaultHttpMethod {
        self.method
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    #[must_use]
    pub fn token(&self) -> &str {
        self.token.expose()
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for VaultHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("namespace", &self.namespace)
            .field("token", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

pub struct VaultHttpResponse {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}

impl VaultHttpResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body: Zeroizing::new(body),
        }
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for VaultHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultHttpResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

pub trait VaultTransport {
    fn execute(&self, request: VaultHttpRequest) -> Result<VaultHttpResponse, ProviderError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultEndpointPolicy {
    /// Production policy: reviewed CA roots, HTTPS, and public DNS answers only.
    PublicHttps,
    /// Test-only policy: exact IP-literal loopback endpoints over HTTP.
    LoopbackTestOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultTransportLimits {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for VaultTransportLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            max_response_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Vault/OpenBao transport with an origin pin, reviewed rustls roots, no
/// environment proxy, no redirects, all-answer DNS filtering, and fixed
/// resource bounds.
#[derive(Clone)]
pub struct HardenedVaultTransport {
    agent: Agent,
    origin: String,
    endpoint_policy: VaultEndpointPolicy,
    max_response_bytes: usize,
}

impl fmt::Debug for HardenedVaultTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardenedVaultTransport")
            .field("origin", &self.origin)
            .field("endpoint_policy", &self.endpoint_policy)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl HardenedVaultTransport {
    pub fn public_https(
        origin: impl Into<String>,
        reviewed_ca_bundle_pem: &[u8],
        limits: VaultTransportLimits,
    ) -> Result<Self, ProviderError> {
        let origin = normalize_vault_address(origin.into(), VaultEndpointPolicy::PublicHttps)?;
        let certificates = parse_reviewed_ca_bundle(reviewed_ca_bundle_pem)?;
        let tls_config = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::from(certificates))
            .build();
        let config = transport_config(limits, true, tls_config)?;
        let agent = Agent::with_parts(
            config,
            DefaultConnector::default(),
            PublicOnlyVaultResolver::default(),
        );
        Ok(Self {
            agent,
            origin,
            endpoint_policy: VaultEndpointPolicy::PublicHttps,
            max_response_bytes: limits.max_response_bytes,
        })
    }

    /// Construct an HTTP transport only for an exact IP-literal loopback test
    /// endpoint. This mode is intentionally separate from production setup.
    pub fn loopback_test_only(
        origin: impl Into<String>,
        limits: VaultTransportLimits,
    ) -> Result<Self, ProviderError> {
        let origin = normalize_vault_address(origin.into(), VaultEndpointPolicy::LoopbackTestOnly)?;
        let tls_config = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::from(
                Vec::<ureq::tls::Certificate<'static>>::new(),
            ))
            .build();
        let config = transport_config(limits, false, tls_config)?;
        let agent = Agent::with_parts(
            config,
            DefaultConnector::default(),
            LoopbackOnlyVaultResolver::default(),
        );
        Ok(Self {
            agent,
            origin,
            endpoint_policy: VaultEndpointPolicy::LoopbackTestOnly,
            max_response_bytes: limits.max_response_bytes,
        })
    }

    fn validate_request(&self, request: &VaultHttpRequest) -> Result<(), ProviderError> {
        if request.url.len() > 8 * 1024
            || request.url.bytes().any(|byte| byte.is_ascii_control())
            || request.body.len() > MAX_VAULT_REQUEST_BYTES
            || (request.method == VaultHttpMethod::Get && !request.body.is_empty())
        {
            return Err(ProviderError::InvalidTransportRequest);
        }
        if let Some(namespace) = request.namespace() {
            validate_namespace(namespace).map_err(|_| ProviderError::InvalidTransportRequest)?;
        }
        let uri: Uri = request
            .url
            .parse()
            .map_err(|_| ProviderError::InvalidTransportRequest)?;
        let origin: Uri = self
            .origin
            .parse()
            .map_err(|_| ProviderError::InvalidProviderConfiguration)?;
        if uri.scheme() != origin.scheme()
            || uri.authority() != origin.authority()
            || !uri.path().starts_with("/v1/")
        {
            return Err(ProviderError::InvalidTransportRequest);
        }
        match self.endpoint_policy {
            VaultEndpointPolicy::PublicHttps if uri.scheme_str() != Some("https") => {
                Err(ProviderError::InvalidTransportRequest)
            }
            VaultEndpointPolicy::LoopbackTestOnly if uri.scheme_str() != Some("http") => {
                Err(ProviderError::InvalidTransportRequest)
            }
            _ => Ok(()),
        }
    }
}

impl VaultTransport for HardenedVaultTransport {
    fn execute(&self, request: VaultHttpRequest) -> Result<VaultHttpResponse, ProviderError> {
        self.validate_request(&request)?;
        let mut response = match request.method {
            VaultHttpMethod::Get => {
                let mut outbound = self
                    .agent
                    .get(&request.url)
                    .header("x-vault-token", request.token());
                if let Some(namespace) = request.namespace() {
                    outbound = outbound.header("x-vault-namespace", namespace);
                }
                outbound.call().map_err(|_| ProviderError::Transport)?
            }
            VaultHttpMethod::Post => {
                let mut outbound = self
                    .agent
                    .post(&request.url)
                    .header("content-type", "application/json")
                    .header("x-vault-token", request.token());
                if let Some(namespace) = request.namespace() {
                    outbound = outbound.header("x-vault-namespace", namespace);
                }
                outbound
                    .send(request.body())
                    .map_err(|_| ProviderError::Transport)?
            }
        };
        let status = response.status().as_u16();
        let read_limit = self
            .max_response_bytes
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(ProviderError::InvalidProviderConfiguration)?;
        // The response may contain secret values even when it is malformed or
        // one byte over the configured bound. Keep the staging allocation
        // zeroizing so every early-return path scrubs the bytes it already
        // received.
        let mut body = Zeroizing::new(Vec::with_capacity(self.max_response_bytes.min(64 * 1024)));
        response
            .body_mut()
            .as_reader()
            .take(read_limit)
            .read_to_end(&mut body)
            .map_err(|_| ProviderError::Transport)?;
        if body.len() > self.max_response_bytes {
            return Err(ProviderError::ProviderResponseTooLarge);
        }
        Ok(VaultHttpResponse { status, body })
    }
}

fn transport_config(
    limits: VaultTransportLimits,
    https_only: bool,
    tls_config: TlsConfig,
) -> Result<ureq::config::Config, ProviderError> {
    if limits.connect_timeout.is_zero()
        || limits.request_timeout.is_zero()
        || limits.connect_timeout > limits.request_timeout
        || limits.request_timeout > Duration::from_secs(120)
        || limits.max_response_bytes == 0
        || limits.max_response_bytes > MAX_PROVIDER_RESPONSE_BYTES
    {
        return Err(ProviderError::InvalidProviderConfiguration);
    }
    Ok(Agent::config_builder()
        .http_status_as_error(false)
        .https_only(https_only)
        .tls_config(tls_config)
        .proxy(None)
        .max_redirects(0)
        .max_response_header_size(MAX_VAULT_RESPONSE_HEADER_BYTES)
        .timeout_global(Some(limits.request_timeout))
        .timeout_resolve(Some(limits.connect_timeout))
        .timeout_connect(Some(limits.connect_timeout))
        .timeout_send_request(Some(limits.connect_timeout))
        .timeout_send_body(Some(limits.request_timeout))
        .timeout_recv_response(Some(limits.request_timeout))
        .timeout_recv_body(Some(limits.request_timeout))
        .build())
}

fn parse_reviewed_ca_bundle(
    pem: &[u8],
) -> Result<Vec<ureq::tls::Certificate<'static>>, ProviderError> {
    if pem.is_empty() || pem.len() > MAX_VAULT_CA_BUNDLE_BYTES {
        return Err(ProviderError::InvalidCaBundle);
    }
    let mut certificates = Vec::new();
    for item in parse_pem(pem) {
        match item.map_err(|_| ProviderError::InvalidCaBundle)? {
            PemItem::Certificate(certificate) => {
                let (remaining, _) = x509_parser::parse_x509_certificate(certificate.der())
                    .map_err(|_| ProviderError::InvalidCaBundle)?;
                if !remaining.is_empty() {
                    return Err(ProviderError::InvalidCaBundle);
                }
                certificates.push(certificate);
                if certificates.len() > MAX_VAULT_CA_CERTIFICATES {
                    return Err(ProviderError::InvalidCaBundle);
                }
            }
            PemItem::PrivateKey(_) => return Err(ProviderError::InvalidCaBundle),
            _ => return Err(ProviderError::InvalidCaBundle),
        }
    }
    if certificates.is_empty() {
        return Err(ProviderError::InvalidCaBundle);
    }
    Ok(certificates)
}

#[derive(Debug, Default)]
struct PublicOnlyVaultResolver(DefaultResolver);

impl Resolver for PublicOnlyVaultResolver {
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

#[derive(Debug, Default)]
struct LoopbackOnlyVaultResolver(DefaultResolver);

impl Resolver for LoopbackOnlyVaultResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addresses = self.0.resolve(uri, config, timeout)?;
        if addresses.iter().any(|address| !address.ip().is_loopback()) {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(addresses)
    }
}
pub(super) fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }
            is_public_ipv6(address)
        }
    }
}

#[cfg(test)]
pub(crate) fn dns_answers_are_public(addresses: &[IpAddr]) -> bool {
    !addresses.is_empty() && addresses.iter().copied().all(is_public_ip)
}

pub(super) fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

pub(super) fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}
