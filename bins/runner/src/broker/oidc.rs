use super::{
    bindings::{call_after_running, exact_step_binding, rpc_timeout, BrokerExecutionBinding},
    client::RunnerBrokerClient,
    envelope::{timestamp_millis, validate_identifier},
};
use runtrue_executor_wasm::{
    CapabilityAdapterError, CapabilityCallContext, OidcAdapter, OidcToken,
};
use runtrue_protocol::v1;
use std::sync::Arc;
use zeroize::Zeroizing;

const MAX_OIDC_TOKEN_BYTES: usize = 64 * 1024;

pub(super) struct RunnerOidcAdapter {
    pub(super) binding: BrokerExecutionBinding,
    pub(super) client: Arc<dyn RunnerBrokerClient>,
}

impl OidcAdapter for RunnerOidcAdapter {
    fn mint_token(
        &self,
        context: &CapabilityCallContext,
        audience: &str,
    ) -> Result<OidcToken, CapabilityAdapterError> {
        context.check()?;
        let (job_id, job_attempt, step_id) = exact_step_binding(context, &self.binding)?;
        validate_identifier("OIDC audience", audience)?;
        let request = v1::OidcTokenRequest {
            execution_lease_id: self.binding.execution_lease_id.clone(),
            fencing_generation: self.binding.fencing_generation,
            job_id: job_id.to_owned(),
            step_id: step_id.to_owned(),
            audience: audience.to_owned(),
            job_attempt,
        };
        let mut response = call_after_running(context, || {
            self.client
                .mint_oidc_token(request.clone(), rpc_timeout(context.remaining()))
        })?;
        let token = Zeroizing::new(std::mem::take(&mut response.token).into_bytes());
        context.check()?;
        validate_identifier("OIDC token id", &response.jti)?;
        let expires_unix_ms = timestamp_millis(response.expires_at.as_ref(), "OIDC expiry")?;
        if expires_unix_ms > self.binding.execution_hard_deadline_unix_ms {
            return Err(CapabilityAdapterError::Failed(
                "OIDC token outlives its execution lease".to_owned(),
            ));
        }
        if token.is_empty() || token.len() > context.max_response_bytes().min(MAX_OIDC_TOKEN_BYTES)
        {
            return Err(CapabilityAdapterError::Failed(
                "OIDC broker returned an invalid token".to_owned(),
            ));
        }
        context.check()?;
        Ok(OidcToken::new(token.to_vec()))
    }
}
