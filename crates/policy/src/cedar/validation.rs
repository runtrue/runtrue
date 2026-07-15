use super::model::{
    CedarAction, CedarAuthorizationRequest, MAX_EMERGENCY_DENIES, MAX_GROUPS, MAX_IDENTIFIER_BYTES,
    MAX_POLICY_SOURCE_BYTES,
};
use crate::DenyFirstPolicy;
use std::fmt;
use thiserror::Error;
pub(super) fn validate_policy_source(source: &str) -> Result<(), CedarAuthorizationError> {
    if source.len() > MAX_POLICY_SOURCE_BYTES || source.contains('\0') {
        return Err(CedarAuthorizationError::PolicySourceLimit);
    }
    Ok(())
}

pub(super) fn validate_emergency_rules(
    policy: &DenyFirstPolicy,
) -> Result<(), CedarAuthorizationError> {
    if policy.emergency_denies.len() > MAX_EMERGENCY_DENIES {
        return Err(CedarAuthorizationError::EmergencyRuleLimit);
    }
    for rule in &policy.emergency_denies {
        validate_identifier("emergency deny id", &rule.id)?;
        if let Some(repository) = &rule.repository_id {
            validate_identifier("emergency deny repository", repository)?;
        }
        if rule.actions.len() > CedarAction::ALL.len()
            || rule.actions.iter().any(|action| {
                !CedarAction::ALL
                    .iter()
                    .any(|candidate| candidate.as_str() == action)
            })
        {
            return Err(CedarAuthorizationError::InvalidEmergencyAction);
        }
    }
    Ok(())
}

pub(super) fn validate_request(
    request: &CedarAuthorizationRequest,
) -> Result<(), CedarAuthorizationError> {
    validate_identifier("principal id", &request.principal.id)?;
    validate_identifier("principal tenant", &request.principal.tenant_id)?;
    if request.principal.groups.len() > MAX_GROUPS {
        return Err(CedarAuthorizationError::GroupLimit);
    }
    for group in &request.principal.groups {
        validate_identifier("principal group", group)?;
    }
    validate_identifier("resource id", &request.resource.id)?;
    validate_identifier("resource tenant", &request.resource.tenant_id)?;
    if request.resource.risk_score > 100 {
        return Err(CedarAuthorizationError::InvalidRiskScore);
    }
    if request.principal.tenant_id != request.resource.tenant_id {
        return Err(CedarAuthorizationError::CrossTenantRequest);
    }
    if let Some(repository) = &request.resource.repository_id {
        validate_identifier("resource repository", repository)?;
    }
    if let Some(author) = &request.resource.author_id {
        validate_identifier("resource author", author)?;
    }
    for value in [
        request.context.mfa_age_seconds,
        request.context.reauthentication_age_seconds,
    ]
    .into_iter()
    .flatten()
    {
        i64::try_from(value).map_err(|_| CedarAuthorizationError::InvalidContextAge)?;
    }
    Ok(())
}

pub(super) fn validate_identifier(
    kind: &'static str,
    value: &str,
) -> Result<(), CedarAuthorizationError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CedarAuthorizationError::InvalidIdentifier(kind));
    }
    Ok(())
}

pub(super) fn bounded(error: impl fmt::Display) -> String {
    error
        .to_string()
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(2048)
        .collect()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CedarAuthorizationError {
    #[error("Cedar policy source exceeds its bound or contains NUL")]
    PolicySourceLimit,
    #[error("Cedar schema is invalid: {0}")]
    Schema(String),
    #[error("Cedar policy syntax is invalid: {0}")]
    PolicyParse(String),
    #[error("Cedar policy count or template usage exceeds the supported bound")]
    PolicyLimit,
    #[error("Cedar policy validation reported {errors} errors and {warnings} warnings")]
    PolicyValidation { errors: usize, warnings: usize },
    #[error("too many emergency deny rules")]
    EmergencyRuleLimit,
    #[error("emergency deny contains an unknown action")]
    InvalidEmergencyAction,
    #[error("too many principal groups")]
    GroupLimit,
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("risk score must be at most 100")]
    InvalidRiskScore,
    #[error("principal and resource tenants do not match")]
    CrossTenantRequest,
    #[error("authentication age is outside Cedar's signed integer range")]
    InvalidContextAge,
    #[error("Cedar entities are invalid: {0}")]
    Entities(String),
    #[error("Cedar request context is invalid: {0}")]
    Context(String),
    #[error("Cedar request is invalid: {0}")]
    Request(String),
}
