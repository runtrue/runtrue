use crate::human_oidc::HumanOidcError;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use std::{
    io::Read as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use ureq::{
    http::Uri,
    unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver},
    unversioned::transport::NextTimeout,
};
use zeroize::Zeroizing;

pub(super) fn read_bounded(
    response: &mut ureq::http::Response<ureq::Body>,
    maximum: usize,
) -> Result<Vec<u8>, HumanOidcError> {
    let mut body = Vec::with_capacity(maximum.min(64 * 1024));
    response
        .body_mut()
        .as_reader()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| HumanOidcError::Transport)?;
    if body.len() > maximum {
        return Err(HumanOidcError::ResponseTooLarge);
    }
    Ok(body)
}

pub(super) fn read_bounded_zeroizing(
    response: &mut ureq::http::Response<ureq::Body>,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, HumanOidcError> {
    let mut body = Zeroizing::new(Vec::with_capacity(maximum.min(64 * 1024)));
    response
        .body_mut()
        .as_reader()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| HumanOidcError::Transport)?;
    if body.len() > maximum {
        return Err(HumanOidcError::ResponseTooLarge);
    }
    Ok(body)
}

pub(super) fn decode_bounded(value: &str, maximum: usize) -> Result<Vec<u8>, HumanOidcError> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| HumanOidcError::InvalidIdToken)?;
    if bytes.len() > maximum {
        return Err(HumanOidcError::InvalidIdToken);
    }
    Ok(bytes)
}

pub(super) fn validate_external_endpoint(value: &str) -> Result<(), HumanOidcError> {
    let uri: Uri = value
        .parse()
        .map_err(|_| HumanOidcError::InvalidConfiguration)?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri.query().is_some()
        || value.len() > 8192
        || value.contains('@')
        || value.contains('#')
        || value.contains('\\')
    {
        return Err(HumanOidcError::InvalidConfiguration);
    }
    Ok(())
}

pub(super) fn validate_secret_text(
    value: &str,
    maximum: usize,
    error: HumanOidcError,
) -> Result<(), HumanOidcError> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(error);
    }
    Ok(())
}

pub(crate) fn encode_query_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

#[derive(Debug, Default)]
pub(super) struct PublicOnlyOidcResolver(DefaultResolver);

impl Resolver for PublicOnlyOidcResolver {
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

pub(super) fn is_public_ip(address: IpAddr) -> bool {
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
