//! Strict KV-v2 secret-reference parsing and canonical path encoding.
use super::super::model::{ProviderError, MAX_PROVIDER_REFERENCE_BYTES, MAX_VAULT_PATH_SEGMENTS};
use super::super::validation::{encode_path_segment, validate_identifier, validate_path_segment};
use super::transport::{is_public_ip, VaultEndpointPolicy};
use std::net::IpAddr;
use ureq::http::Uri;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultValueEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultSecretReference {
    mount: String,
    path: Vec<String>,
    pub(super) field: String,
    version: Option<u64>,
    pub(super) encoding: VaultValueEncoding,
}

impl VaultSecretReference {
    /// `kv-v2://MOUNT/path/to/secret#FIELD[?version=N&encoding=base64]`
    pub(crate) fn parse(value: &str) -> Result<Self, ProviderError> {
        let Some(value) = value.strip_prefix("kv-v2://") else {
            return Err(ProviderError::InvalidProviderReference);
        };
        let (location, query) = value
            .split_once('?')
            .map_or((value, None), |(a, b)| (a, Some(b)));
        let Some((location, field)) = location.rsplit_once('#') else {
            return Err(ProviderError::InvalidProviderReference);
        };
        let mut segments = location.split('/');
        let mount = segments.next().unwrap_or_default().to_owned();
        validate_path_segment(&mount)?;
        validate_identifier("Vault secret field", field)?;
        let path = segments
            .map(|segment| {
                validate_path_segment(segment)?;
                Ok(segment.to_owned())
            })
            .collect::<Result<Vec<_>, ProviderError>>()?;
        if path.is_empty() || path.len() > MAX_VAULT_PATH_SEGMENTS {
            return Err(ProviderError::InvalidProviderReference);
        }
        let mut version = None;
        let mut encoding = VaultValueEncoding::Utf8;
        if let Some(query) = query {
            for pair in query.split('&') {
                let Some((name, value)) = pair.split_once('=') else {
                    return Err(ProviderError::InvalidProviderReference);
                };
                match name {
                    "version" if version.is_none() => {
                        let parsed = value
                            .parse::<u64>()
                            .map_err(|_| ProviderError::InvalidProviderReference)?;
                        if parsed == 0 {
                            return Err(ProviderError::InvalidProviderReference);
                        }
                        version = Some(parsed);
                    }
                    "encoding" if encoding == VaultValueEncoding::Utf8 && value == "base64" => {
                        encoding = VaultValueEncoding::Base64;
                    }
                    _ => return Err(ProviderError::InvalidProviderReference),
                }
            }
        }
        Ok(Self {
            mount,
            path,
            field: field.to_owned(),
            version,
            encoding,
        })
    }

    pub(super) fn read_path(&self) -> String {
        let mut path = format!("{}/data", encode_path_segment(&self.mount));
        for segment in &self.path {
            path.push('/');
            path.push_str(&encode_path_segment(segment));
        }
        if let Some(version) = self.version {
            path.push_str("?version=");
            path.push_str(&version.to_string());
        }
        path
    }
}
pub(super) fn normalize_vault_address(
    mut value: String,
    endpoint_policy: VaultEndpointPolicy,
) -> Result<String, ProviderError> {
    if value.ends_with('/') {
        value.pop();
    }
    if value.is_empty()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('@')
        || value.contains('#')
        || value.contains('?')
    {
        return Err(ProviderError::InvalidProviderAddress);
    }
    let uri: Uri = value
        .parse()
        .map_err(|_| ProviderError::InvalidProviderAddress)?;
    let Some(scheme) = uri.scheme_str() else {
        return Err(ProviderError::InvalidProviderAddress);
    };
    let Some(authority) = uri.authority() else {
        return Err(ProviderError::InvalidProviderAddress);
    };
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err(ProviderError::InvalidProviderAddress);
    }
    if authority.as_str().len() > MAX_PROVIDER_REFERENCE_BYTES
        || authority.as_str().contains('@')
        || authority.port_u16() == Some(0)
    {
        return Err(ProviderError::InvalidProviderAddress);
    }
    let host = uri.host().ok_or(ProviderError::InvalidProviderAddress)?;
    let host_without_brackets = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let normalized_host = host_without_brackets.to_ascii_lowercase();
    match endpoint_policy {
        VaultEndpointPolicy::PublicHttps => {
            if scheme != "https"
                || normalized_host == "localhost"
                || normalized_host.ends_with(".localhost")
                || host_without_brackets
                    .parse::<IpAddr>()
                    .is_ok_and(|address| !is_public_ip(address))
            {
                return Err(ProviderError::InvalidProviderAddress);
            }
        }
        VaultEndpointPolicy::LoopbackTestOnly => {
            if scheme != "http"
                || !host_without_brackets
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
            {
                return Err(ProviderError::InvalidProviderAddress);
            }
        }
    }
    Ok(value)
}
