//! Trusted authorization binding for runner-originated secret releases.
use super::model::{
    AuthorizedExternalSecretRelease, ExternalSecretBrokerError, ExternalSecretRevocationRequest,
    RunnerExternalSecretRequest, MAX_BROKER_IDENTIFIER_BYTES,
};
use crate::{ExternalSecretLeaseRequest, MAX_PROVIDER_REFERENCE_BYTES};
use runtrue_model::ContentDigest;
impl RunnerExternalSecretRequest {
    pub(super) fn validate(&self, now_unix_ms: u64) -> Result<(), ExternalSecretBrokerError> {
        validate_identifier("runner id", &self.runner_id)?;
        validate_identifier("execution lease id", &self.execution_lease_id)?;
        validate_identifier("job id", &self.job_id)?;
        validate_identifier("step id", &self.step_id)?;
        validate_identifier("secret metadata id", &self.secret_metadata_id)?;
        validate_identifier("secret purpose", &self.purpose)?;
        if self.fencing_generation == 0
            || self.installation_fencing_epoch == 0
            || self.job_attempt == 0
            || self.expires_unix_ms <= now_unix_ms
        {
            return Err(ExternalSecretBrokerError::InvalidRequest);
        }
        Ok(())
    }
}

impl AuthorizedExternalSecretRelease {
    pub(super) fn provider_request(
        &self,
        request: &RunnerExternalSecretRequest,
        now_unix_ms: u64,
    ) -> Result<ExternalSecretLeaseRequest, ExternalSecretBrokerError> {
        request.validate(now_unix_ms)?;
        if self.runner_id != request.runner_id
            || self.execution_lease_id != request.execution_lease_id
            || self.fencing_generation != request.fencing_generation
            || self.installation_fencing_epoch != request.installation_fencing_epoch
            || self.job_id != request.job_id
            || self.job_attempt != request.job_attempt
            || self.step_id != request.step_id
            || self.secret_metadata_id != request.secret_metadata_id
            || self.purpose != request.purpose
            || self.expires_unix_ms > request.expires_unix_ms
            || self.expires_unix_ms <= now_unix_ms
        {
            return Err(ExternalSecretBrokerError::AuthorizationBindingMismatch);
        }
        validate_identifier("external secret release id", &self.release_id)?;
        validate_identifier("tenant id", &self.tenant_id)?;
        validate_identifier("repository id", &self.repository_id)?;
        validate_identifier("run id", &self.run_id)?;
        validate_provider_id(&self.provider_id)?;
        if self.provider_reference.is_empty()
            || self.provider_reference.len() > MAX_PROVIDER_REFERENCE_BYTES
            || self
                .provider_reference
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(ExternalSecretBrokerError::InvalidRequest);
        }

        let mut provider_request = ExternalSecretLeaseRequest {
            release_id: self.release_id.clone(),
            release_subject_digest: ContentDigest::sha256([]),
            provider_id: self.provider_id.clone(),
            tenant_id: self.tenant_id.clone(),
            repository_id: self.repository_id.clone(),
            run_id: self.run_id.clone(),
            runner_id: self.runner_id.clone(),
            secret_metadata_id: self.secret_metadata_id.clone(),
            provider_reference: self.provider_reference.clone(),
            execution_lease_id: self.execution_lease_id.clone(),
            fencing_generation: self.fencing_generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            job_id: self.job_id.clone(),
            job_attempt: self.job_attempt,
            step_id: self.step_id.clone(),
            purpose: self.purpose.clone(),
            expires_unix_ms: self.expires_unix_ms,
        };
        provider_request.release_subject_digest = provider_request
            .expected_release_subject_digest()
            .map_err(ExternalSecretBrokerError::Provider)?;
        provider_request
            .validate(now_unix_ms)
            .map_err(ExternalSecretBrokerError::Provider)?;
        Ok(provider_request)
    }
}

/// Policy/storage boundary. Implementations must authorize before disclosing
/// whether a secret metadata ID or provider configuration exists.
pub trait ExternalSecretReleaseAuthority: Send + Sync {
    fn authorize(
        &self,
        request: &RunnerExternalSecretRequest,
        now_unix_ms: u64,
    ) -> Result<AuthorizedExternalSecretRelease, ExternalSecretBrokerError>;
}

/// Plaintext-free durable reservation. The provider reference is represented
impl ExternalSecretRevocationRequest {
    pub(super) fn validate(&self) -> Result<(), ExternalSecretBrokerError> {
        validate_identifier("external secret release id", &self.release_id)?;
        validate_identifier("runner id", &self.runner_id)?;
        validate_identifier("execution lease id", &self.execution_lease_id)?;
        validate_identifier("job id", &self.job_id)?;
        validate_identifier("step id", &self.step_id)?;
        if self.fencing_generation == 0
            || self.installation_fencing_epoch == 0
            || self.job_attempt == 0
        {
            return Err(ExternalSecretBrokerError::InvalidRequest);
        }
        Ok(())
    }
}
pub(super) fn validate_identifier(
    _kind: &'static str,
    value: &str,
) -> Result<(), ExternalSecretBrokerError> {
    if value.is_empty()
        || value.len() > MAX_BROKER_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ExternalSecretBrokerError::InvalidRequest);
    }
    Ok(())
}

pub(super) fn validate_provider_id(value: &str) -> Result<(), ExternalSecretBrokerError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ExternalSecretBrokerError::InvalidRequest);
    }
    Ok(())
}
