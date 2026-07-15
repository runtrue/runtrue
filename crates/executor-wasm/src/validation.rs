use crate::{CapabilityAdapters, WasmError, MAX_CAPABILITY_GRANTS};
use runtrue_model::{normalize_relative_path, ContentDigest};
use runtrue_workflow_ir::{Access, CacheRead, CacheWrite, NetworkPermission, StepCapabilitySet};
use std::time::Duration;
pub(crate) fn validate_capabilities(
    capabilities: &StepCapabilitySet,
    adapters: &CapabilityAdapters,
) -> Result<(), WasmError> {
    let filesystem_grants = capabilities
        .fs_read
        .len()
        .checked_add(capabilities.fs_write.len())
        .ok_or(WasmError::LimitExceeded("filesystem capability grants"))?;
    if filesystem_grants > MAX_CAPABILITY_GRANTS
        || capabilities.secrets.len() > MAX_CAPABILITY_GRANTS
        || capabilities.oidc_audiences.len() > MAX_CAPABILITY_GRANTS
    {
        return Err(WasmError::LimitExceeded("capability grants"));
    }
    if (!capabilities.fs_read.is_empty() || !capabilities.fs_write.is_empty())
        && !adapters.has_filesystem()
    {
        return Err(WasmError::UnsupportedCapability(
            "filesystem adapter is unavailable".to_owned(),
        ));
    }
    if capabilities.network != NetworkPermission::Deny && !adapters.has_network() {
        return Err(WasmError::UnsupportedCapability(
            "network adapter is unavailable".to_owned(),
        ));
    }
    if !capabilities.secrets.is_empty() && !adapters.has_secrets() {
        return Err(WasmError::UnsupportedCapability(
            "secret adapter is unavailable".to_owned(),
        ));
    }
    if !capabilities.oidc_audiences.is_empty() && !adapters.has_oidc() {
        return Err(WasmError::UnsupportedCapability(
            "OIDC adapter is unavailable".to_owned(),
        ));
    }
    if capabilities.checks != Access::Deny
        || capabilities.artifacts != Access::Deny
        || capabilities.cache_read != CacheRead::Deny
        || capabilities.cache_write != CacheWrite::Deny
    {
        return Err(WasmError::UnsupportedCapability(
            "requested capability has no WIT adapter in this runtime generation".to_owned(),
        ));
    }
    for path in capabilities.fs_read.iter().chain(&capabilities.fs_write) {
        normalize_scope(path)?;
    }
    for secret in &capabilities.secrets {
        validate_bounded_text("secret metadata id", &secret.metadata_id, 256)?;
        validate_bounded_text("secret name", &secret.name, 256)?;
        if let Some(purpose) = &secret.purpose {
            validate_bounded_text("secret purpose", purpose, 1024)?;
        }
    }
    for audience in &capabilities.oidc_audiences {
        validate_bounded_text("OIDC audience", audience, 1024)?;
    }
    if let NetworkPermission::Allow {
        destinations,
        listen,
        ..
    } = &capabilities.network
    {
        if destinations.len() > MAX_CAPABILITY_GRANTS {
            return Err(WasmError::LimitExceeded("network capability grants"));
        }
        if !listen.is_empty() {
            return Err(WasmError::UnsupportedCapability(
                "network listeners have no WIT adapter".to_owned(),
            ));
        }
        for destination in destinations {
            if destination.host.is_empty()
                || destination.host.len() > 253
                || destination.host.chars().any(char::is_whitespace)
                || destination.host.bytes().any(|byte| byte.is_ascii_control())
                || destination.port == 0
            {
                return Err(WasmError::InvalidRequest(
                    "invalid network capability destination".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn normalize_scope(path: &str) -> Result<String, WasmError> {
    if path.len() > 4096 || path.split('/').count() > 256 {
        return Err(WasmError::InvalidRequest(
            "filesystem capability scope exceeds its bound".to_owned(),
        ));
    }
    if path == "." {
        return Err(WasmError::InvalidRequest(
            "filesystem capability scope cannot be the whole workspace".to_owned(),
        ));
    }
    normalize_relative_path(path)
        .map_err(|_| WasmError::InvalidRequest("filesystem capability path is not safe".to_owned()))
}

pub(crate) fn validate_timeout(timeout_ms: Option<u64>, max: Duration) -> Result<(), WasmError> {
    if timeout_ms.is_some_and(|timeout| timeout == 0 || Duration::from_millis(timeout) > max) {
        return Err(WasmError::LimitExceeded("wall timeout"));
    }
    Ok(())
}

pub(crate) fn effective_timeout(
    timeout_ms: Option<u64>,
    max: Duration,
) -> Result<Duration, WasmError> {
    validate_timeout(timeout_ms, max)?;
    Ok(timeout_ms.map_or(max, Duration::from_millis))
}

pub(crate) fn exact_reference_digest(reference: &str) -> Result<ContentDigest, WasmError> {
    validate_bounded_text("component reference", reference, 4096)?;
    let (locator, digest) = reference
        .rsplit_once('@')
        .ok_or(WasmError::MutableComponentReference)?;
    if locator.is_empty() || locator.contains('@') || locator.chars().any(char::is_whitespace) {
        return Err(WasmError::MutableComponentReference);
    }
    ContentDigest::parse(digest).map_err(|_| WasmError::MutableComponentReference)
}

pub(crate) fn validate_bounded_text(
    kind: &'static str,
    value: &str,
    max: usize,
) -> Result<(), WasmError> {
    if value.is_empty() || value.len() > max || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(WasmError::InvalidRequest(format!("invalid {kind}")));
    }
    Ok(())
}
