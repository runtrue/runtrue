pub(super) fn adapters_for_lease(
    lease: &AdmittedLease,
    broker: Option<Arc<dyn RunnerBrokerClient>>,
) -> Result<CapabilityAdapters, RunnerError> {
    let job = lease
        .capsule
        .jobs
        .iter()
        .find(|job| job.id == lease.job_id)
        .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
    let requires_broker = job.steps.iter().any(|step| {
        !step.capabilities.secrets.is_empty() || !step.capabilities.oidc_audiences.is_empty()
    });
    let mut adapters = match (requires_broker, broker) {
        (false, _) => CapabilityAdapters::new(),
        (true, Some(client)) => {
            wasm_broker_adapters(BrokerExecutionBinding::from_lease(lease), client)
        }
        (true, None) => return Err(RunnerError::BrokerUnavailable),
    };
    if job
        .steps
        .iter()
        .any(|step| step.capabilities.network != runtrue_workflow_ir::NetworkPermission::Deny)
    {
        adapters = adapters.with_network(Arc::new(super::network::HttpsNetworkAdapter::new()?));
    }
    if job.steps.iter().any(step_requires_filesystem) {
        // Lease preflight runs before source hydration creates the workspace.
        // This adapter is never used for execution; it only lets the Wasm
        // executor validate the signed scopes and the rest of the capability
        // matrix. Execution replaces it with an fd-rooted adapter below.
        adapters = adapters.with_filesystem(Arc::new(PreflightFilesystemAdapter));
    }
    Ok(adapters)
}

pub(super) fn adapters_for_workspace(
    lease: &AdmittedLease,
    workspace: &Path,
    broker: Option<Arc<dyn RunnerBrokerClient>>,
) -> Result<CapabilityAdapters, RunnerError> {
    let mut adapters = adapters_for_lease(lease, broker)?;
    let job = lease
        .capsule
        .jobs
        .iter()
        .find(|job| job.id == lease.job_id)
        .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
    if job.steps.iter().any(step_requires_filesystem) {
        let workspace = workspace.canonicalize().map_err(|error| {
            RunnerError::WasmConfiguration(format!(
                "canonicalize hydrated Wasm workspace `{}`: {error}",
                workspace.display()
            ))
        })?;
        let adapter = RootedFilesystemAdapter::new(&workspace, MAX_WORKSPACE_FILE_BYTES)
            .map_err(|error| RunnerError::WasmConfiguration(error.to_string()))?;
        adapters = adapters.with_filesystem(Arc::new(adapter));
    }
    Ok(adapters)
}

fn step_requires_filesystem(step: &runtrue_workflow_ir::PlannedStep) -> bool {
    !step.capabilities.fs_read.is_empty() || !step.capabilities.fs_write.is_empty()
}

/// A preflight-only marker. Any accidental invocation fails closed; actual
/// execution always replaces it with `RootedFilesystemAdapter`.
struct PreflightFilesystemAdapter;

impl FilesystemAdapter for PreflightFilesystemAdapter {
    fn read_file(
        &self,
        _context: &CapabilityCallContext,
        _grant: &DirectoryGrant,
        _relative_path: &str,
    ) -> Result<Vec<u8>, CapabilityAdapterError> {
        Err(CapabilityAdapterError::Denied(
            "preflight filesystem adapter cannot perform I/O".to_owned(),
        ))
    }

    fn write_file(
        &self,
        _context: &CapabilityCallContext,
        _grant: &DirectoryGrant,
        _relative_path: &str,
        _value: &[u8],
    ) -> Result<(), CapabilityAdapterError> {
        Err(CapabilityAdapterError::Denied(
            "preflight filesystem adapter cannot perform I/O".to_owned(),
        ))
    }
}

pub(super) fn reject_aot_events(executor: &WasmExecutor) -> Result<(), RunnerError> {
    let events = executor.aot_cache_events()?;
    if events.is_empty() {
        Ok(())
    } else {
        Err(RunnerError::WasmAotState(format!(
            "Wasm AOT integrity probe reported {} event(s)",
            events.len()
        )))
    }
}
use super::{
    wasm_broker_adapters, AdmittedLease, Arc, BrokerExecutionBinding, CapabilityAdapterError,
    CapabilityAdapters, CapabilityCallContext, DirectoryGrant, FilesystemAdapter, Path,
    RootedFilesystemAdapter, RunnerBrokerClient, RunnerError, WasmExecutor,
    MAX_WORKSPACE_FILE_BYTES,
};
