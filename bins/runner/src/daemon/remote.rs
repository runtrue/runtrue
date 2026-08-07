use super::{
    error::RunnerError,
    executor::{
        execution_from_engine, JobExecution, JobExecutionServices, JobExecutor, NativeJobExecutor,
        PreparedContent, PreparedContentTier,
    },
};
use crate::{
    broker::{RunnerBrokerClient, ScmCredentialObserver, ScmCredentialTaint, ScmRuntimeFiles},
    firecracker::FirecrackerJobExecutor,
    oci::OciJobExecutor,
    wasm::WasmJobExecutor,
};
use runtrue_engine::CancellationToken;
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::Isolation;
use std::{path::Path, sync::Arc};

#[derive(Debug, Clone)]
pub struct RemoteJobExecutor {
    native: NativeJobExecutor,
    oci: Option<OciJobExecutor>,
    wasm: Option<WasmJobExecutor>,
    firecracker: Option<FirecrackerJobExecutor>,
    publish_credential_tainted_logs: bool,
}

impl RemoteJobExecutor {
    #[must_use]
    pub const fn new(allow_trusted_native: bool, oci: Option<OciJobExecutor>) -> Self {
        Self::with_backends(allow_trusted_native, oci, None)
    }

    #[must_use]
    pub const fn with_backends(
        allow_trusted_native: bool,
        oci: Option<OciJobExecutor>,
        wasm: Option<WasmJobExecutor>,
    ) -> Self {
        Self::with_all_backends(allow_trusted_native, oci, wasm, None)
    }

    #[must_use]
    pub const fn with_all_backends(
        allow_trusted_native: bool,
        oci: Option<OciJobExecutor>,
        wasm: Option<WasmJobExecutor>,
        firecracker: Option<FirecrackerJobExecutor>,
    ) -> Self {
        Self {
            native: NativeJobExecutor::new(allow_trusted_native),
            oci,
            wasm,
            firecracker,
            publish_credential_tainted_logs: false,
        }
    }

    #[must_use]
    pub const fn with_credential_tainted_logs(mut self, enabled: bool) -> Self {
        self.publish_credential_tainted_logs = enabled;
        self
    }
}

impl JobExecutor for RemoteJobExecutor {
    fn prepared_content(&self) -> Result<Vec<PreparedContent>, RunnerError> {
        let mut prepared = Vec::new();
        if let Some(wasm) = &self.wasm {
            let tiers = wasm.component_preparation_tiers()?;
            for (tier, kind) in [
                (PreparedContentTier::Warm, "wasm-component-warm"),
                (PreparedContentTier::Warmish, "wasm-component-warmish"),
            ] {
                let digests = tiers
                    .iter()
                    .filter_map(|(digest, observed)| (*observed == tier).then_some(digest.clone()))
                    .collect::<Vec<_>>();
                if !digests.is_empty() {
                    prepared.push(PreparedContent {
                        kind: kind.to_owned(),
                        digests,
                        tier: Some(tier),
                    });
                }
            }
        }
        Ok(prepared)
    }

    fn preflight(&self, lease: &AdmittedLease) -> Result<(), RunnerError> {
        self.preflight_with_broker(lease, None)
    }

    fn preflight_with_broker(
        &self,
        lease: &AdmittedLease,
        broker: Option<Arc<dyn RunnerBrokerClient>>,
    ) -> Result<(), RunnerError> {
        match offered_isolation(lease)? {
            Isolation::Native => self.native.preflight(lease),
            Isolation::Oci => {
                let job = offered_job(lease)?;
                reject_non_scm_broker_capabilities(job, "OCI")?;
                self.oci
                    .as_ref()
                    .ok_or_else(|| RunnerError::UnsupportedIsolation("Oci".to_owned()))?
                    .preflight_lease(lease)
            }
            Isolation::Wasm => self
                .wasm
                .as_ref()
                .ok_or_else(|| RunnerError::UnsupportedIsolation("Wasm".to_owned()))?
                .preflight_lease_with_broker(lease, broker),
            Isolation::Microvm => self
                .firecracker
                .as_ref()
                .ok_or_else(|| RunnerError::UnsupportedIsolation("Microvm".to_owned()))?
                .preflight_lease(lease),
        }
    }

    fn execute(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
    ) -> Result<JobExecution, RunnerError> {
        self.execute_with_services(
            lease,
            workspace,
            cancellation,
            JobExecutionServices::default(),
        )
    }

    fn execute_with_services(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
        services: JobExecutionServices,
    ) -> Result<JobExecution, RunnerError> {
        match offered_isolation(lease)? {
            Isolation::Native => {
                self.native
                    .execute_with_services(lease, workspace, cancellation, services)
            }
            Isolation::Oci => {
                reject_non_scm_broker_capabilities(offered_job(lease)?, "OCI")?;
                let runtime = ScmRuntimeFiles::prepare(lease, workspace)
                    .map_err(RunnerError::OciConfiguration)?;
                let (observer, credential_taint) =
                    match (services.broker, services.step_state_observer) {
                        (Some(client), Some(lifecycle)) => {
                            let (observer, taint) =
                                ScmCredentialObserver::wrap(lease, workspace, client, lifecycle)
                                    .map_err(RunnerError::OciConfiguration)?;
                            (Some(observer), taint)
                        }
                        (None, observer) => (observer, ScmCredentialTaint::default()),
                        (Some(_), None) => (None, ScmCredentialTaint::default()),
                    };
                let mut result = self
                    .oci
                    .as_ref()
                    .ok_or_else(|| RunnerError::UnsupportedIsolation("Oci".to_owned()))?
                    .execute_with_observer_and_broker(
                        lease,
                        workspace,
                        cancellation,
                        observer,
                        runtime.as_ref().and_then(ScmRuntimeFiles::proxy_socket),
                    )?;
                result.apply_credential_taint_with_publication(
                    credential_taint.credential_taint(),
                    self.publish_credential_tainted_logs,
                );
                super::executor::execution_from_engine_with_log_policy(
                    lease,
                    result,
                    self.publish_credential_tainted_logs,
                )
            }
            Isolation::Wasm => {
                let result = self
                    .wasm
                    .as_ref()
                    .ok_or_else(|| RunnerError::UnsupportedIsolation("Wasm".to_owned()))?
                    .execute_with_services(
                        lease,
                        workspace,
                        cancellation,
                        services.broker,
                        services.step_state_observer,
                    )?;
                execution_from_engine(lease, result)
            }
            Isolation::Microvm => self
                .firecracker
                .as_ref()
                .ok_or_else(|| RunnerError::UnsupportedIsolation("Microvm".to_owned()))?
                .execute(lease, cancellation, services.step_state_observer),
        }
    }

    fn cleanup_stale(&self) -> Result<(), RunnerError> {
        if let Some(oci) = &self.oci {
            oci.cleanup_stale()?;
        }
        if let Some(wasm) = &self.wasm {
            wasm.cleanup_stale()?;
        }
        if let Some(firecracker) = &self.firecracker {
            firecracker.cleanup_stale()?;
        }
        Ok(())
    }
}

fn offered_isolation(lease: &AdmittedLease) -> Result<Isolation, RunnerError> {
    offered_job(lease).map(|job| job.runner.isolation)
}

pub(super) fn offered_job(
    lease: &AdmittedLease,
) -> Result<&runtrue_workflow_ir::PlannedJob, RunnerError> {
    lease
        .capsule
        .jobs
        .iter()
        .find(|job| job.id == lease.job_id)
        .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))
}

pub(super) fn reject_broker_capabilities(
    job: &runtrue_workflow_ir::PlannedJob,
    backend: &str,
) -> Result<(), RunnerError> {
    if job.steps.iter().any(|step| {
        !step.capabilities.secrets.is_empty() || !step.capabilities.oidc_audiences.is_empty()
    }) {
        return Err(RunnerError::BrokerUnsupportedBackend(backend.to_owned()));
    }
    Ok(())
}

fn reject_non_scm_broker_capabilities(
    job: &runtrue_workflow_ir::PlannedJob,
    backend: &str,
) -> Result<(), RunnerError> {
    if job
        .steps
        .iter()
        .any(|step| !step.capabilities.oidc_audiences.is_empty())
    {
        return Err(RunnerError::BrokerUnsupportedBackend(backend.to_owned()));
    }
    Ok(())
}

pub(crate) fn reject_remote_retries(
    job: &runtrue_workflow_ir::PlannedJob,
) -> Result<(), RunnerError> {
    if job.retries != 0 {
        return Err(RunnerError::RemoteRetriesUnsupported);
    }
    Ok(())
}
