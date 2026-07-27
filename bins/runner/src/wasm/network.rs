use crate::daemon::RunnerError;
use runtrue_executor_wasm::{CapabilityAdapterError, CapabilityCallContext, NetworkAdapter};
use runtrue_workflow_ir::{DnsPolicy, NetworkPermission, NetworkProtocol};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Read as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use ureq::{
    http::{self, Uri},
    unversioned::{
        resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver},
        transport::{DefaultConnector, NextTimeout},
    },
    Agent,
};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(Debug, Serialize)]
struct HttpResponse {
    status: u16,
    body: String,
}

#[derive(Debug, Clone)]
pub(super) struct HttpsNetworkAdapter {
    public_agent: Agent,
    private_agent: Agent,
}

impl HttpsNetworkAdapter {
    pub(super) fn new() -> Result<Self, RunnerError> {
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .timeout_global(Some(Duration::from_secs(120)))
            .timeout_connect(Some(Duration::from_secs(15)))
            .build();
        let public_agent = Agent::with_parts(
            config.clone(),
            DefaultConnector::default(),
            PublicOnlyResolver::default(),
        );
        let private_agent = Agent::with_parts(
            config,
            DefaultConnector::default(),
            DefaultResolver::default(),
        );
        Ok(Self {
            public_agent,
            private_agent,
        })
    }
}

impl NetworkAdapter for HttpsNetworkAdapter {
    fn http_request(
        &self,
        context: &CapabilityCallContext,
        grant: &NetworkPermission,
        bytes: &[u8],
    ) -> Result<Vec<u8>, CapabilityAdapterError> {
        context.check()?;
        let request: HttpRequest = serde_json::from_slice(bytes).map_err(|_| {
            CapabilityAdapterError::Denied("invalid HTTP request envelope".to_owned())
        })?;
        let uri = request
            .url
            .parse::<http::Uri>()
            .map_err(|_| CapabilityAdapterError::Denied("invalid HTTPS URL".to_owned()))?;
        if uri.scheme_str() != Some("https") || uri.path().is_empty() {
            return Err(CapabilityAdapterError::Denied(
                "only absolute HTTPS URLs are allowed".to_owned(),
            ));
        }
        let authority = uri.authority().ok_or_else(|| {
            CapabilityAdapterError::Denied("HTTPS URL has no authority".to_owned())
        })?;
        let host = authority.host().to_ascii_lowercase();
        let port = authority.port_u16().unwrap_or(443);
        authorize_destination(grant, &host, port)?;
        let method = request
            .method
            .parse::<http::Method>()
            .map_err(|_| CapabilityAdapterError::Denied("invalid HTTP method".to_owned()))?;
        if !matches!(
            method,
            http::Method::GET
                | http::Method::POST
                | http::Method::PUT
                | http::Method::PATCH
                | http::Method::DELETE
        ) {
            return Err(CapabilityAdapterError::Denied(
                "HTTP method is not allowed".to_owned(),
            ));
        }
        let mut outbound = http::Request::builder().method(method).uri(uri);
        for (name, value) in request.headers {
            let normalized = name.to_ascii_lowercase();
            if matches!(
                normalized.as_str(),
                "host" | "connection" | "content-length" | "transfer-encoding" | "upgrade"
            ) {
                return Err(CapabilityAdapterError::Denied(
                    "hop-by-hop or transport header is not allowed".to_owned(),
                ));
            }
            outbound = outbound.header(name, value);
        }
        let outbound = outbound
            .body(request.body)
            .map_err(|_| CapabilityAdapterError::Denied("invalid HTTP request".to_owned()))?;
        let deny_private_ranges = matches!(
            grant,
            NetworkPermission::Allow {
                deny_private_ranges: true,
                ..
            }
        );
        let mut response = if deny_private_ranges {
            &self.public_agent
        } else {
            &self.private_agent
        }
        .run(outbound)
        .map_err(|_| CapabilityAdapterError::Failed("HTTPS request failed".to_owned()))?;
        context.check()?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(u64::try_from(MAX_RESPONSE_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut body)
            .map_err(|_| CapabilityAdapterError::Failed("HTTPS response failed".to_owned()))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(CapabilityAdapterError::Failed(
                "HTTPS response exceeded the byte limit".to_owned(),
            ));
        }
        let body = String::from_utf8(body).map_err(|_| {
            CapabilityAdapterError::Failed("HTTPS response is not UTF-8".to_owned())
        })?;
        serde_json::to_vec(&HttpResponse { status, body })
            .map_err(|_| CapabilityAdapterError::Failed("cannot encode HTTPS response".to_owned()))
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

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or_else(|| is_public_ipv6(address), is_public_ipv4),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
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

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn authorize_destination(
    grant: &NetworkPermission,
    host: &str,
    port: u16,
) -> Result<(), CapabilityAdapterError> {
    let NetworkPermission::Allow {
        dns, destinations, ..
    } = grant
    else {
        return Err(CapabilityAdapterError::Denied(
            "network access is denied".to_owned(),
        ));
    };
    if *dns == DnsPolicy::Deny && host.parse::<IpAddr>().is_err() {
        return Err(CapabilityAdapterError::Denied(
            "DNS resolution is outside the signed grant".to_owned(),
        ));
    }
    if destinations.iter().any(|destination| {
        destination.protocol == NetworkProtocol::Tcp
            && destination.port == port
            && destination.host.eq_ignore_ascii_case(host)
    }) {
        Ok(())
    } else {
        Err(CapabilityAdapterError::Denied(
            "HTTPS destination is outside the signed grant".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_workflow_ir::NetworkDestination;

    fn grant() -> NetworkPermission {
        NetworkPermission::Allow {
            dns: DnsPolicy::Restricted,
            deny_private_ranges: false,
            destinations: vec![NetworkDestination {
                host: "github.example.test".to_owned(),
                port: 443,
                protocol: NetworkProtocol::Tcp,
            }],
            listen: Vec::new(),
        }
    }

    #[test]
    fn destination_authority_is_exact_and_case_insensitive() {
        assert!(authorize_destination(&grant(), "github.example.test", 443).is_ok());
        assert!(authorize_destination(&grant(), "github.example.test", 8443).is_err());
        assert!(authorize_destination(&grant(), "api.github.com", 443).is_err());
        assert!(
            authorize_destination(&NetworkPermission::Deny, "github.example.test", 443).is_err()
        );
    }

    #[test]
    fn dns_denial_only_allows_exact_ip_destinations() {
        let mut denied = grant();
        let NetworkPermission::Allow { dns, .. } = &mut denied else {
            unreachable!();
        };
        *dns = DnsPolicy::Deny;
        assert!(authorize_destination(&denied, "github.example.test", 443).is_err());

        let NetworkPermission::Allow { destinations, .. } = &mut denied else {
            unreachable!();
        };
        destinations[0].host = "192.0.2.10".to_owned();
        assert!(authorize_destination(&denied, "192.0.2.10", 443).is_ok());
    }

    #[test]
    fn public_resolver_policy_rejects_private_and_documentation_ranges() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "203.0.113.8",
            "::1",
            "fd00::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
