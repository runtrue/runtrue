use crate::{
    DebugApproval, DebugSessionError, DebugSessionPolicy, DebugSessionRequest, EnvironmentClass,
    EphemeralClientIdentity, SecretState, WorkloadTrust, MAX_DURATION_MS,
};
use runtrue_auth::AuthContext;
use runtrue_model::ContentDigest;
use serde::Serialize;

const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 4096;
const MAX_APPROVAL_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub(crate) const DEBUG_SCOPE: &str = "runs:debug";

pub(crate) fn validate_open(
    auth: &AuthContext,
    request: &DebugSessionRequest,
    approval: &DebugApproval,
    policy: DebugSessionPolicy,
    now_unix_ms: u64,
) -> Result<(), DebugSessionError> {
    validate_request(request, policy, now_unix_ms)?;
    if auth.principal_id != request.actor_id
        || auth.tenant_id != request.tenant_id
        || !auth.scopes.contains(DEBUG_SCOPE)
        || auth
            .require_recent_mfa(now_unix_ms, policy.recent_mfa_maximum_age_ms)
            .is_err()
        || auth
            .require_recent_reauthentication(
                now_unix_ms,
                policy.recent_reauthentication_maximum_age_ms,
            )
            .is_err()
    {
        return Err(DebugSessionError::Authentication);
    }
    let expected_subject = request.approval_subject()?.digest()?;
    validate_identifier(&approval.approval_id)?;
    validate_identifier(&approval.approver_id)?;
    let approval_lifetime = approval
        .expires_unix_ms
        .checked_sub(approval.approved_unix_ms)
        .ok_or(DebugSessionError::InvalidApproval)?;
    if approval.subject_digest != expected_subject
        || approval.approver_id == request.actor_id
        || approval_lifetime == 0
        || approval_lifetime > MAX_APPROVAL_LIFETIME_MS
        || approval.approved_unix_ms < request.requested_unix_ms
        || approval.approved_unix_ms > now_unix_ms
        || approval.expires_unix_ms <= now_unix_ms
    {
        return Err(DebugSessionError::InvalidApproval);
    }
    if request.environment == EnvironmentClass::Production
        && (!policy.production_enabled || !approval.allow_production)
    {
        return Err(DebugSessionError::PolicyDenied);
    }
    if request.workload_trust == WorkloadTrust::PublicUntrusted
        && (!policy.public_untrusted_enabled || !approval.allow_public_untrusted)
    {
        return Err(DebugSessionError::PolicyDenied);
    }
    if request.retain_existing_secrets
        && (!policy.secret_retention_enabled
            || !approval.allow_secret_retention
            || request.secret_state != SecretState::Released)
    {
        return Err(DebugSessionError::PolicyDenied);
    }
    Ok(())
}

fn validate_request(
    request: &DebugSessionRequest,
    policy: DebugSessionPolicy,
    now_unix_ms: u64,
) -> Result<(), DebugSessionError> {
    for identifier in [
        &request.session_id,
        &request.tenant_id,
        &request.repository_id,
        &request.run_id,
        &request.job_id,
        &request.execution_lease_id,
        &request.actor_id,
    ] {
        validate_identifier(identifier)?;
    }
    if request.fencing_generation == 0
        || request.installation_fencing_epoch == 0
        || request.requested_duration_ms == 0
        || request.requested_duration_ms > policy.maximum_duration_ms
        || request.requested_duration_ms > MAX_DURATION_MS
        || request.requested_unix_ms > now_unix_ms
        || request.reason.is_empty()
        || request.reason.len() > MAX_REASON_BYTES
        || request
            .reason
            .bytes()
            .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\r' | b'\t'))
        || (request.retain_existing_secrets && request.secret_state != SecretState::Released)
    {
        return Err(DebugSessionError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn validate_identifier(value: &str) -> Result<(), DebugSessionError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(DebugSessionError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn validate_client_identity(
    identity: &EphemeralClientIdentity,
) -> Result<(), DebugSessionError> {
    validate_identifier(&identity.certificate_serial)
        .map_err(|_| DebugSessionError::IdentityIssuer)?;
    if identity.certificate_pem.is_empty()
        || identity.private_key_pem.is_empty()
        || identity.certificate_pem.len() > 256 * 1024
        || identity.private_key_pem.len() > 256 * 1024
        || !identity
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
        || !identity.private_key_pem.starts_with("-----BEGIN ")
        || identity.certificate_pem.contains('\0')
        || identity.private_key_pem.contains('\0')
    {
        return Err(DebugSessionError::IdentityIssuer);
    }
    Ok(())
}

pub(crate) fn canonical_digest<T: Serialize>(
    value: &T,
) -> Result<ContentDigest, DebugSessionError> {
    fn canonicalize(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(canonicalize).collect())
            }
            serde_json::Value::Object(values) => {
                let values = values
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect::<std::collections::BTreeMap<_, _>>();
                serde_json::Value::Object(values.into_iter().collect())
            }
            other => other,
        }
    }
    let value = serde_json::to_value(value).map_err(|_| DebugSessionError::Serialize)?;
    let bytes =
        serde_json::to_vec(&canonicalize(value)).map_err(|_| DebugSessionError::Serialize)?;
    Ok(ContentDigest::sha256(bytes))
}
