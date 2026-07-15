use crate::{SigningApproval, SigningError, SigningGrant, SigningRequest};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 512;
pub(crate) const MAX_POLICY_VERSIONS: usize = 128;
pub(crate) const MAX_APPROVERS: usize = 16;
pub(crate) const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_REQUEST_LIFETIME_SECONDS: u64 = 15 * 60;

pub(crate) fn validate_request_shape(request: &SigningRequest) -> Result<(), SigningError> {
    for identifier in [
        &request.request_id,
        &request.tenant_id,
        &request.repository_id,
        &request.run_id,
        &request.job_id,
        &request.step_id,
        &request.execution_lease_id,
        &request.requester_identity,
        &request.purpose,
        &request.approval_id,
    ] {
        validate_identifier(identifier)?;
    }
    if request.fencing_generation == 0
        || request.installation_fencing_epoch == 0
        || request.policy_version_ids.is_empty()
        || request.policy_version_ids.len() > MAX_POLICY_VERSIONS
        || !sorted_unique_identifiers(&request.policy_version_ids)?
    {
        return Err(SigningError::InvalidRequest);
    }
    Ok(())
}
pub(crate) fn validate_request_time(
    request: &SigningRequest,
    now_unix_seconds: u64,
) -> Result<(), SigningError> {
    let lifetime = request
        .expires_at_unix_seconds
        .checked_sub(request.requested_at_unix_seconds)
        .ok_or(SigningError::InvalidRequest)?;
    if lifetime == 0
        || lifetime > MAX_REQUEST_LIFETIME_SECONDS
        || request.requested_at_unix_seconds > now_unix_seconds.saturating_add(30)
        || request.expires_at_unix_seconds <= now_unix_seconds
    {
        return Err(SigningError::InvalidRequest);
    }
    Ok(())
}
pub(crate) fn validate_grant(
    request: &SigningRequest,
    grant: &SigningGrant,
    now_unix_seconds: u64,
) -> Result<(), SigningError> {
    if grant.tenant_id != request.tenant_id
        || grant.repository_id != request.repository_id
        || grant.run_id != request.run_id
        || grant.job_id != request.job_id
        || grant.step_id != request.step_id
        || grant.execution_lease_id != request.execution_lease_id
        || grant.fencing_generation != request.fencing_generation
        || grant.installation_fencing_epoch != request.installation_fencing_epoch
        || grant.requester_identity != request.requester_identity
        || grant.capsule_digest != request.capsule_digest
        || grant.artifact_digest != request.artifact_digest
        || grant.provenance_digest != request.provenance_digest
        || grant.purpose != request.purpose
        || grant.operation != request.operation
        || grant.policy_version_ids != request.policy_version_ids
        || grant.expires_at_unix_seconds <= now_unix_seconds
    {
        return Err(SigningError::Unauthorized);
    }
    Ok(())
}
pub(crate) fn validate_approval(
    request: &SigningRequest,
    approval: &SigningApproval,
    required_approvers: usize,
    now_unix_seconds: u64,
) -> Result<(), SigningError> {
    let expected_subject = request.approval_subject()?.digest()?;
    if approval.approval_id != request.approval_id
        || approval.subject_digest != expected_subject
        || approval.policy_version_ids != request.policy_version_ids
        || approval.approver_identities.len() < required_approvers
        || approval.approver_identities.len() > MAX_APPROVERS
        || !sorted_unique_identifiers(&approval.approver_identities)?
        || approval
            .approver_identities
            .binary_search(&request.requester_identity)
            .is_ok()
        || approval.approved_at_unix_seconds < request.requested_at_unix_seconds
        || approval.approved_at_unix_seconds > now_unix_seconds.saturating_add(30)
        || approval.expires_at_unix_seconds <= now_unix_seconds
    {
        return Err(SigningError::InvalidApproval);
    }
    Ok(())
}
pub(crate) fn sorted_unique_identifiers(values: &[String]) -> Result<bool, SigningError> {
    for value in values {
        validate_identifier(value)?;
    }
    Ok(values.windows(2).all(|pair| pair[0] < pair[1]))
}
pub(crate) fn validate_identifier(value: &str) -> Result<(), SigningError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(SigningError::InvalidRequest);
    }
    Ok(())
}
