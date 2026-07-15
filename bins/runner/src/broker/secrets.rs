use super::{
    bindings::{
        call_after_running, capability_transport_error, exact_step_binding, rpc_timeout,
        BrokerExecutionBinding,
    },
    client::RunnerBrokerClient,
    envelope::{decrypt_envelope, timestamp_millis, validate_identifier, SecretEnvelopeBinding},
};
use rand_core::{OsRng, RngCore as _};
use runtrue_executor_wasm::{
    CapabilityAdapterError, CapabilityCallContext, SecretAdapter, SecretValue,
};
use runtrue_model::SecretReference;
use runtrue_protocol::v1;
use std::{sync::Arc, time::Duration};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const X25519_KEY_BYTES: usize = 32;
const MAX_SECRET_PLAINTEXT_BYTES: usize = 1024 * 1024;
const REVOKE_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct RunnerSecretAdapter {
    pub(super) binding: BrokerExecutionBinding,
    pub(super) client: Arc<dyn RunnerBrokerClient>,
}

impl SecretAdapter for RunnerSecretAdapter {
    fn read_secret(
        &self,
        context: &CapabilityCallContext,
        grant: &SecretReference,
    ) -> Result<SecretValue, CapabilityAdapterError> {
        context.check()?;
        let (job_id, job_attempt, step_id) = exact_step_binding(context, &self.binding)?;
        let purpose = grant.purpose.clone().unwrap_or_default();

        let mut scalar = Zeroizing::new([0_u8; X25519_KEY_BYTES]);
        OsRng
            .try_fill_bytes(scalar.as_mut())
            .map_err(|_| CapabilityAdapterError::Failed("secure randomness unavailable".into()))?;
        let guest_secret = StaticSecret::from(*scalar);
        let guest_public = PublicKey::from(&guest_secret).to_bytes();
        let request = v1::SecretLeaseRequest {
            execution_lease_id: self.binding.execution_lease_id.clone(),
            fencing_generation: self.binding.fencing_generation,
            job_id: job_id.to_owned(),
            step_id: step_id.to_owned(),
            secret_metadata_id: grant.metadata_id.clone(),
            purpose: purpose.clone(),
            guest_session_key: Some(v1::Digest {
                algorithm: "x25519".to_owned(),
                value: guest_public.to_vec(),
            }),
            job_attempt,
        };
        let response = call_after_running(context, || {
            self.client
                .request_secret_lease(request.clone(), rpc_timeout(context.remaining()))
        })?;
        validate_identifier("secret lease id", &response.secret_lease_id)?;
        let revoke = v1::RevokeSecretLeaseRequest {
            secret_lease_id: response.secret_lease_id.clone(),
            execution_lease_id: self.binding.execution_lease_id.clone(),
            fencing_generation: self.binding.fencing_generation,
            job_attempt,
        };
        let expires_unix_ms = match timestamp_millis(response.expires_at.as_ref(), "secret expiry")
        {
            Ok(expires_unix_ms)
                if expires_unix_ms <= self.binding.execution_hard_deadline_unix_ms =>
            {
                expires_unix_ms
            }
            Ok(_) => {
                let _ = self.client.revoke_secret_lease(revoke, REVOKE_TIMEOUT);
                return Err(CapabilityAdapterError::Failed(
                    "secret lease outlives its execution lease".to_owned(),
                ));
            }
            Err(error) => {
                let _ = self.client.revoke_secret_lease(revoke, REVOKE_TIMEOUT);
                return Err(error);
            }
        };

        if let Err(error) = context.check() {
            let _ = self.client.revoke_secret_lease(revoke, REVOKE_TIMEOUT);
            return Err(error);
        }

        let decrypted = decrypt_envelope(
            &response,
            &guest_secret,
            &SecretEnvelopeBinding {
                execution_lease_id: &self.binding.execution_lease_id,
                fencing_generation: self.binding.fencing_generation,
                installation_fencing_epoch: self.binding.installation_fencing_epoch,
                job_id,
                job_attempt,
                step_id,
                secret_lease_id: &response.secret_lease_id,
                secret_metadata_id: &grant.metadata_id,
                purpose: &purpose,
                expires_unix_ms,
            },
            context.max_response_bytes().min(MAX_SECRET_PLAINTEXT_BYTES),
        );
        let revoke_result = self
            .client
            .revoke_secret_lease(revoke, REVOKE_TIMEOUT)
            .map_err(capability_transport_error);
        let mut plaintext = Zeroizing::new(decrypted?);
        revoke_result?;
        context.check()?;
        Ok(SecretValue::new(std::mem::take(&mut *plaintext)))
    }
}
