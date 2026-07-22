use super::pull::PackageKind;
use crate::{canonical::MAX_SHORT_TEXT_BYTES, ProviderContractError};
use runtrue_model::ContentDigest;
use std::net::{IpAddr, Ipv6Addr};

pub(super) fn parse_exact_reference(
    kind: &PackageKind,
    reference: &str,
) -> Result<(String, ContentDigest), ProviderContractError> {
    if reference.is_empty()
        || reference.len() > MAX_SHORT_TEXT_BYTES
        || reference.chars().any(char::is_whitespace)
        || reference.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_reference());
    }
    let (scheme, locator) = reference
        .split_once("://")
        .map_or((None, reference), |(scheme, locator)| {
            (Some(scheme), locator)
        });
    validate_scheme(kind, scheme)?;
    let (repository, digest) = locator.rsplit_once('@').ok_or_else(invalid_reference)?;
    if repository.contains('@') {
        return Err(invalid_reference());
    }
    let (registry, path) = repository.split_once('/').ok_or_else(invalid_reference)?;
    validate_registry(registry)?;
    validate_repository_path(kind, path)?;
    let digest = ContentDigest::parse(digest.to_owned()).map_err(|_| invalid_reference())?;
    Ok((registry.to_owned(), digest))
}

fn validate_repository_path(kind: &PackageKind, path: &str) -> Result<(), ProviderContractError> {
    if path.is_empty()
        || path.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.bytes().any(|byte| {
                    byte.is_ascii_control() || matches!(byte, b':' | b'@' | b'?' | b'#' | b'\\')
                })
        })
    {
        return Err(invalid_reference());
    }
    if matches!(
        kind,
        PackageKind::ContainerImage | PackageKind::WasmComponent
    ) && !path.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'/' | b'.' | b'_' | b'-')
    }) {
        return Err(invalid_reference());
    }
    Ok(())
}

fn validate_scheme(kind: &PackageKind, scheme: Option<&str>) -> Result<(), ProviderContractError> {
    let supported = match kind {
        PackageKind::ContainerImage => scheme.is_none() || matches!(scheme, Some("oci" | "docker")),
        PackageKind::WasmComponent => matches!(scheme, Some("wasm" | "oci")),
        PackageKind::Named(_) => scheme.is_none() || scheme.is_some_and(valid_scheme_name),
    };
    if !supported {
        return Err(invalid_reference());
    }
    Ok(())
}

fn valid_scheme_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
        })
}

pub(super) fn validate_registry(registry: &str) -> Result<(), ProviderContractError> {
    if registry.is_empty()
        || registry.len() > 512
        || registry.chars().any(char::is_whitespace)
        || registry.contains(['/', '@'])
    {
        return Err(invalid_registry());
    }
    let (host, port) = split_registry_authority(registry)?;
    if let Some(port) = port {
        if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
            return Err(ProviderContractError::InvalidPackagePull(
                "invalid registry port",
            ));
        }
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if host.is_empty()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return Err(ProviderContractError::InvalidPackagePull(
            "invalid registry host",
        ));
    }
    Ok(())
}

fn split_registry_authority(registry: &str) -> Result<(&str, Option<&str>), ProviderContractError> {
    if let Some(rest) = registry.strip_prefix('[') {
        let (address, suffix) = rest.split_once(']').ok_or_else(invalid_registry)?;
        address
            .parse::<Ipv6Addr>()
            .map_err(|_| invalid_registry())?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid_registry)?)
        };
        return Ok((address, port));
    }
    if registry.matches(':').count() > 1 {
        return Err(invalid_registry());
    }
    Ok(registry
        .split_once(':')
        .map_or((registry, None), |(host, port)| (host, Some(port))))
}

fn invalid_reference() -> ProviderContractError {
    ProviderContractError::InvalidPackagePull("reference must be exact and digest-pinned")
}

fn invalid_registry() -> ProviderContractError {
    ProviderContractError::InvalidPackagePull("invalid registry authority")
}
