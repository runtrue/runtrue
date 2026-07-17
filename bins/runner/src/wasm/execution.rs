#[derive(Clone)]
pub struct WasmJobExecutor {
    executor: SharedWasmExecutor,
    references: Arc<BTreeSet<String>>,
    component_count: usize,
    target: WasmTarget,
    aot_cache: PathBuf,
}

impl fmt::Debug for WasmJobExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmJobExecutor")
            .field("component_count", &self.component_count)
            .field("target", &self.target.target_triple())
            .field("aot_cache", &self.aot_cache)
            .finish_non_exhaustive()
    }
}

impl WasmJobExecutor {
    pub fn load(paths: &WasmRuntimePaths) -> Result<Self, RunnerError> {
        let component_directory =
            validate_private_directory(&paths.component_directory, "Wasm component directory")?;
        let manifest_directory =
            validate_private_directory(&paths.manifest_directory, "Wasm manifest directory")?;
        let keyring_directory =
            validate_private_directory(&paths.keyring_directory, "Wasm component keyring")?;
        let keys = load_component_keys(&keyring_directory)?;
        let artifacts = load_components(&component_directory, &manifest_directory, &keys)?;
        let references = Arc::new(artifacts.keys().cloned().collect::<BTreeSet<_>>());
        let component_count = artifacts.len();

        let runtime_key = Zeroizing::new(read_bounded_private_file(
            &paths.runtime_key,
            MAX_RUNTIME_KEY_BYTES,
        )?);
        let (aot_key, handle_key) = decode_runtime_keys(&runtime_key).ok_or_else(|| {
            RunnerError::WasmConfiguration(
                "Wasm runtime key must contain exactly 64 raw bytes or 128 hex characters with distinct nonzero key halves".to_owned(),
            )
        })?;
        if !paths.aot_cache.is_absolute() {
            return Err(RunnerError::WasmConfiguration(
                "Wasm AOT cache path must be absolute".to_owned(),
            ));
        }
        validate_no_symlink_components(&paths.aot_cache)?;
        let target = WasmTarget::host_baseline()?;
        let mut config = runtrue_executor_wasm::WasmExecutorConfig::new(
            target.clone(),
            AotCacheConfig::new(&paths.aot_cache, AotAuthenticationKey::new(aot_key)),
            HandleAuthenticationKey::new(handle_key),
        );
        for artifact in artifacts.into_values() {
            config.register_component(artifact)?;
        }
        let mut executor = WasmExecutor::new(config, CapabilityAdapters::new())?;
        executor.set_external_cache_handling(true);
        executor.preflight_components()?;
        reject_aot_events(&executor)?;
        let aot_cache = paths.aot_cache.canonicalize().map_err(|error| {
            RunnerError::WasmConfiguration(format!("canonicalize Wasm AOT cache: {error}"))
        })?;

        Ok(Self {
            executor: SharedWasmExecutor::new(executor),
            references,
            component_count,
            target,
            aot_cache,
        })
    }

    pub fn preflight_lease(&self, lease: &AdmittedLease) -> Result<(), RunnerError> {
        self.preflight_lease_with_broker(lease, None)
    }

    pub fn preflight_lease_with_broker(
        &self,
        lease: &AdmittedLease,
        broker: Option<Arc<dyn RunnerBrokerClient>>,
    ) -> Result<(), RunnerError> {
        self.validate_assignments(lease)?;
        let adapters = adapters_for_lease(lease, broker)?;
        self.executor
            .with_adapters(adapters)
            .preflight_capsule(&selected_capsule(&lease.capsule, &lease.job_id)?)
    }

    pub fn execute(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
    ) -> Result<ExecutionResult, RunnerError> {
        self.execute_with_services(lease, workspace, cancellation, None, None)
    }

    pub fn execute_with_services(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
        broker: Option<Arc<dyn RunnerBrokerClient>>,
        observer: Option<Arc<dyn StepStateObserver>>,
    ) -> Result<ExecutionResult, RunnerError> {
        self.validate_assignments(lease)?;
        let adapters = adapters_for_workspace(lease, workspace, broker)?;
        let executor = self
            .executor
            .with_adapters(adapters)
            .with_capsule_context(&lease.capsule)?;
        executor.preflight_capsule(&selected_capsule(&lease.capsule, &lease.job_id)?)?;
        let mut dispatcher = ExecutorDispatcher::new();
        dispatcher
            .register(Isolation::Wasm, executor)
            .map_err(|error| RunnerError::WasmConfiguration(error.to_string()))?;
        let mut engine = Engine::with_cancellation_token(dispatcher, cancellation);
        engine.set_step_state_observer(observer);
        engine
            .execute_offered_job(&lease.capsule, &lease.job_id)
            .map_err(RunnerError::Engine)
    }

    pub fn cleanup_stale(&self) -> Result<(), RunnerError> {
        self.executor.preflight_components()?;
        self.executor.reject_aot_events()
    }

    #[must_use]
    pub const fn component_count(&self) -> usize {
        self.component_count
    }

    #[must_use]
    pub fn target_triple(&self) -> &str {
        self.target.target_triple()
    }

    #[must_use]
    pub fn aot_cache(&self) -> &Path {
        &self.aot_cache
    }

    fn validate_assignments(&self, lease: &AdmittedLease) -> Result<(), RunnerError> {
        let offered = lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == lease.job_id)
            .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
        if offered.runner.isolation != Isolation::Wasm {
            return Err(RunnerError::UnsupportedIsolation(format!(
                "{:?}",
                offered.runner.isolation
            )));
        }
        if lease.capsule.context.lockfile_digest.is_none() {
            return Err(RunnerError::WasmManifestMismatch(
                "Wasm execution requires a canonical lockfile digest in the capsule".to_owned(),
            ));
        }
        if offered.runner.image.is_some() {
            return Err(RunnerError::WasmManifestMismatch(format!(
                "Wasm job `{}` unexpectedly declares a runner image",
                offered.id
            )));
        }
        for step in &offered.steps {
            if !matches!(step.action, StepAction::Component { .. }) {
                return Err(RunnerError::WasmManifestMismatch(format!(
                    "Wasm step `{}.{}` is not a component action",
                    offered.id, step.id
                )));
            }
        }
        // The signed canonical capsule may contain unrelated jobs for other
        // backends. Do not reinterpret or reject their command steps, but do
        // prove that every Component reference anywhere in that capsule has an
        // exact preloaded signed assignment.
        for job in &lease.capsule.jobs {
            for step in &job.steps {
                let StepAction::Component { reference } = &step.action else {
                    continue;
                };
                exact_component_digest(reference)?;
                if !self.references.contains(reference) {
                    return Err(RunnerError::MissingWasmComponent(reference.clone()));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct SharedWasmExecutor {
    inner: Arc<Mutex<WasmExecutor>>,
    adapters: CapabilityAdapters,
    contextual_inputs: BTreeMap<String, String>,
    fuel_multiplier: u64,
}

pub(super) const GITHUB_ACTIONS_FRONTEND_ID: &str = "runtrue.github-actions";
pub(super) const GITHUB_ACTIONS_FUEL_MULTIPLIER: u64 = 4;

pub(super) fn fuel_multiplier_for_capsule(capsule: &ExecutionCapsule) -> u64 {
    if capsule
        .context
        .workflow_frontend
        .as_ref()
        .is_some_and(|frontend| frontend.frontend_id == GITHUB_ACTIONS_FRONTEND_ID)
    {
        GITHUB_ACTIONS_FUEL_MULTIPLIER
    } else {
        1
    }
}

impl SharedWasmExecutor {
    fn new(executor: WasmExecutor) -> Self {
        Self {
            inner: Arc::new(Mutex::new(executor)),
            adapters: CapabilityAdapters::new(),
            contextual_inputs: BTreeMap::new(),
            fuel_multiplier: 1,
        }
    }

    fn with_adapters(&self, adapters: CapabilityAdapters) -> Self {
        Self {
            inner: self.inner.clone(),
            adapters,
            contextual_inputs: self.contextual_inputs.clone(),
            fuel_multiplier: self.fuel_multiplier,
        }
    }

    fn with_capsule_context(mut self, capsule: &ExecutionCapsule) -> Result<Self, RunnerError> {
        self.fuel_multiplier = fuel_multiplier_for_capsule(capsule);
        if let Some(event) = &capsule.context.normalized_event_json {
            self.contextual_inputs
                .insert("__runtrue_event".to_owned(), event.clone());
        }
        if let Some(scm) = &capsule.context.scm {
            let value = serde_json::to_string(scm).map_err(|error| {
                RunnerError::WasmConfiguration(format!(
                    "encode signed SCM component context: {error}"
                ))
            })?;
            self.contextual_inputs
                .insert("__runtrue_scm".to_owned(), value);
        }
        Ok(self)
    }

    fn lock(&self) -> Result<MutexGuard<'_, WasmExecutor>, RunnerError> {
        self.inner.lock().map_err(|_| {
            RunnerError::WasmConfiguration("Wasm executor state is poisoned".to_owned())
        })
    }

    fn preflight_capsule(&self, capsule: &ExecutionCapsule) -> Result<(), RunnerError> {
        self.lock()?
            .preflight_capsule_with_adapters(capsule, &self.adapters)
            .map_err(RunnerError::Wasm)
    }

    fn preflight_components(&self) -> Result<(), RunnerError> {
        self.lock()?
            .preflight_components()
            .map_err(RunnerError::Wasm)
    }

    fn reject_aot_events(&self) -> Result<(), RunnerError> {
        let executor = self.lock()?;
        reject_aot_events(&executor)
    }
}

impl Executor for SharedWasmExecutor {
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        self.inner
            .lock()
            .map_err(|_| ExecutorError::Spawn("Wasm executor state is poisoned".to_owned()))?
            .preflight_with_adapters(capsule, &self.adapters)
    }

    fn execute(
        &mut self,
        request: &runtrue_engine::StepExecutionRequest,
    ) -> Result<ExecutorOutput, ExecutorError> {
        let mut request = request.clone();
        if let PreparedAction::Component { inputs, .. } = &mut request.action {
            inputs.extend(self.contextual_inputs.clone());
        }
        let (output, diagnostic) = self
            .inner
            .lock()
            .map_err(|_| ExecutorError::Spawn("Wasm executor state is poisoned".to_owned()))?
            .execute_with_adapters_and_diagnostic(&request, &self.adapters, self.fuel_multiplier)?;
        if let Some(diagnostic) = diagnostic {
            eprintln!(
                "runtrue-runner: WASM runtime failure for job {} step {} attempt {}: {diagnostic}",
                request.job_id, request.step_id, request.job_attempt
            );
        }
        Ok(output)
    }

    fn finish_job_attempt(
        &mut self,
        job: &PlannedJob,
        attempt: u32,
        outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        self.inner
            .lock()
            .map_err(|_| ExecutorError::Spawn("Wasm executor state is poisoned".to_owned()))?
            .finish_job_attempt(job, attempt, outcome)
    }
}
fn selected_capsule(
    capsule: &ExecutionCapsule,
    job_id: &str,
) -> Result<ExecutionCapsule, RunnerError> {
    let mut job = capsule
        .jobs
        .iter()
        .find(|job| job.id == job_id)
        .cloned()
        .ok_or_else(|| RunnerError::OfferedJobMissing(job_id.to_owned()))?;
    job.needs.clear();
    let mut selected = capsule.clone();
    selected.jobs = vec![job];
    Ok(selected)
}
use super::{
    adapters_for_lease, adapters_for_workspace, decode_runtime_keys, exact_component_digest,
    load_component_keys, load_components, read_bounded_private_file, reject_aot_events,
    validate_no_symlink_components, validate_private_directory, AdmittedLease,
    AotAuthenticationKey, AotCacheConfig, Arc, BTreeMap, BTreeSet, CancellationToken,
    CapabilityAdapters, Engine, ExecutionCapsule, ExecutionResult, Executor, ExecutorDispatcher,
    ExecutorError, ExecutorOutput, HandleAuthenticationKey, Isolation, JobAttemptOutcome, Mutex,
    MutexGuard, Path, PathBuf, PlannedJob, PreparedAction, RunnerBrokerClient, RunnerError,
    StepAction, StepStateObserver, WasmExecutor, WasmRuntimePaths, WasmTarget, Zeroizing,
    MAX_RUNTIME_KEY_BYTES,
};
use std::fmt;
