use crate::{
    cache::{engine_compatibility_digest, AotCache},
    host::{AggregateStoreLimits, HostInvocation, HostOutput, HostState},
    package_cache::{AdmittedAot, PackageMemoryCache, WarmComponent},
    AotCacheError, AotCacheEvent, AotCacheKey, AotCacheStatus, CapabilityAdapters,
    CapabilityCallContext, DirectoryGrant, FilesystemAccess, HandleAuthenticationKey,
    PackagePreparationTier, Run, RunPre, WasmComponentArtifact, WasmError, WasmExecutionOutput,
    WasmExecutorConfig, WasmLimits, WasmTarget, COMPILER_SETTINGS, MAX_RETAINED_AOT_CACHE_EVENTS,
    SECURITY_MITIGATION_PROFILE, WASI_VERSION, WASMTIME_VERSION, WIT_SOURCE, WIT_WORLD,
};
use crate::{
    capabilities::InvocationGrants,
    validation::{
        effective_timeout, normalize_scope, validate_bounded_text, validate_capabilities,
        validate_timeout,
    },
    watchdog::{EpochWatchdog, Interruption},
};
use runtrue_engine::{
    Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, PreparedAction,
    StepExecutionRequest,
};
use runtrue_model::{ContentDigest, SecretReference};
use runtrue_runtime_metrics::{PhaseRecorder, PreparationState, RuntimePhase};
use runtrue_workflow_ir::{ExecutionCapsule, Isolation, NetworkPermission, PlannedJob, StepAction};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wasmtime::{
    component::{types::ComponentItem, Component},
    Config, Engine, OptLevel, Store, Trap,
};
pub struct WasmExecutor {
    source_engine: Engine,
    cached_engine: Engine,
    target: WasmTarget,
    limits: WasmLimits,
    cache: AotCache,
    handle_authentication_key: HandleAuthenticationKey,
    components: BTreeMap<String, WasmComponentArtifact>,
    adapters: CapabilityAdapters,
    external_cache_handling: bool,
    package_cache: Mutex<PackageMemoryCache>,
    cache_events: Mutex<VecDeque<AotCacheEvent>>,
}

struct AdmittedComponentResult {
    component: Arc<WarmComponent>,
    cache_status: AotCacheStatus,
    preparation_state: PreparationState,
}

impl WasmExecutor {
    pub fn new(
        config: WasmExecutorConfig,
        adapters: CapabilityAdapters,
    ) -> Result<Self, WasmError> {
        let limits = config.limits.validate()?;
        let host_target = WasmTarget::host_baseline()?;
        if config.target != host_target {
            return Err(WasmError::InvalidConfiguration(format!(
                "execution target `{}` must equal this host's baseline target `{}`",
                config.target.target_triple(),
                host_target.target_triple()
            )));
        }
        if config.components.is_empty() {
            return Err(WasmError::InvalidConfiguration(
                "component registry is empty".to_owned(),
            ));
        }
        let prepared_cache = AotCache::prepare(config.cache)?;
        let package_cache = PackageMemoryCache::new(config.package_cache)?;
        let source_engine = Engine::new(&runtime_config(&config.target, limits, None)?)
            .map_err(|error| WasmError::RuntimeConfiguration(error.to_string()))?;
        let cached_engine = Engine::new(&runtime_config(
            &config.target,
            limits,
            Some(&prepared_cache.wasmtime_config_path),
        )?)
        .map_err(|error| WasmError::RuntimeConfiguration(error.to_string()))?;
        if engine_compatibility_digest(&source_engine)
            != engine_compatibility_digest(&cached_engine)
        {
            return Err(WasmError::RuntimeConfiguration(
                "cached and source-only engines are not AOT compatible".to_owned(),
            ));
        }
        Ok(Self {
            source_engine,
            cached_engine,
            target: config.target,
            limits,
            cache: prepared_cache.cache,
            handle_authentication_key: config.handle_authentication_key,
            components: config.components,
            adapters,
            external_cache_handling: false,
            package_cache: Mutex::new(package_cache),
            cache_events: Mutex::new(VecDeque::new()),
        })
    }

    /// Verify and compile every locally configured component before a runner
    /// advertises this backend. A cache integrity failure is retained in
    /// `aot_cache_events`, allowing the caller to fail closed even when the
    /// executor safely quarantined and rebuilt the entry.
    pub fn preflight_components(&self) -> Result<(), WasmError> {
        for reference in self.components.keys() {
            self.admit_and_compile(reference)?;
        }
        Ok(())
    }

    pub fn set_external_cache_handling(&mut self, enabled: bool) {
        self.external_cache_handling = enabled;
    }

    pub fn package_preparation_tiers(
        &self,
    ) -> Result<BTreeMap<ContentDigest, PackagePreparationTier>, WasmError> {
        self.package_cache
            .lock()
            .map(|cache| cache.tiers())
            .map_err(|_| WasmError::Internal("package cache state is poisoned".to_owned()))
    }

    pub fn preflight_capsule(&self, capsule: &ExecutionCapsule) -> Result<(), WasmError> {
        self.preflight_capsule_with_adapters(capsule, &self.adapters)
    }

    pub fn preflight_capsule_with_adapters(
        &self,
        capsule: &ExecutionCapsule,
        adapters: &CapabilityAdapters,
    ) -> Result<(), WasmError> {
        for job in &capsule.jobs {
            if job.runner.isolation != Isolation::Wasm {
                return Err(WasmError::UnsupportedIsolation(format!(
                    "{:?}",
                    job.runner.isolation
                )));
            }
            if job.runner.os != self.target.operating_system
                || job.runner.arch != self.target.architecture
            {
                return Err(WasmError::PlatformMismatch);
            }
            if !job.runner.capabilities.is_empty() {
                return Err(WasmError::UnsupportedCapability(
                    "ambient runner capabilities".to_owned(),
                ));
            }
            if !job.services.is_empty() {
                return Err(WasmError::UnsupportedCapability(
                    "service processes".to_owned(),
                ));
            }
            if job.runner.memory_bytes == 0
                || u64::try_from(self.limits.max_memory_bytes)
                    .map_or(true, |maximum| job.runner.memory_bytes > maximum)
            {
                return Err(WasmError::LimitExceeded("runner memory"));
            }
            validate_timeout(Some(job.timeout_ms), self.limits.max_timeout)?;
            for step in &job.steps {
                if !step.environment.is_empty() {
                    return Err(WasmError::AmbientEnvironmentDenied);
                }
                if step.working_directory.is_some() {
                    return Err(WasmError::UnsupportedCapability(
                        "ambient working directory".to_owned(),
                    ));
                }
                if step.cache.is_some() && !self.external_cache_handling {
                    return Err(WasmError::UnsupportedCapability(
                        "workflow cache declaration has no WIT adapter".to_owned(),
                    ));
                }
                validate_capabilities(&step.capabilities, adapters)?;
                validate_timeout(step.timeout_ms, self.limits.max_timeout)?;
                let StepAction::Component { reference } = &step.action else {
                    return Err(WasmError::NoFallback);
                };
                self.admit_and_compile(reference)?;
            }
        }
        Ok(())
    }

    pub fn execute_request(
        &self,
        request: &StepExecutionRequest,
    ) -> Result<WasmExecutionOutput, WasmError> {
        let adapters = self.adapters.clone();
        self.execute_request_with_adapters(request, &adapters)
    }

    pub fn execute_request_with_adapters(
        &self,
        request: &StepExecutionRequest,
        adapters: &CapabilityAdapters,
    ) -> Result<WasmExecutionOutput, WasmError> {
        self.execute_request_with_adapters_and_fuel_multiplier(request, adapters, 1)
    }

    pub fn execute_request_with_adapters_and_fuel_multiplier(
        &self,
        request: &StepExecutionRequest,
        adapters: &CapabilityAdapters,
        fuel_multiplier: u64,
    ) -> Result<WasmExecutionOutput, WasmError> {
        if !(1..=4).contains(&fuel_multiplier) {
            return Err(WasmError::InvalidRequest(
                "Wasm fuel multiplier must be between one and four".to_owned(),
            ));
        }
        let total_started = Instant::now();
        let mut recorder = PhaseRecorder::new();
        recorder.measure(
            RuntimePhase::RequestAdmission,
            Some("request_validation"),
            || self.validate_request(request, adapters),
        )?;
        let (reference, inputs) = match &request.action {
            PreparedAction::Component { reference, inputs } => (reference, inputs),
            PreparedAction::Command { .. }
            | PreparedAction::Container { .. }
            | PreparedAction::Script { .. } => {
                return Err(WasmError::NoFallback);
            }
        };
        if request.cancellation.is_cancelled() {
            return Ok(WasmExecutionOutput {
                executor: interrupted_output(false, true, Duration::ZERO),
                component_output: None,
                runtime_diagnostic: None,
                aot_cache_status: AotCacheStatus::Miss,
                measurement: recorder.finish(
                    PreparationState::NotObserved,
                    Some("not_inspected".to_owned()),
                ),
            });
        }
        if request.timeout_ms == Some(0) {
            return Ok(WasmExecutionOutput {
                executor: interrupted_output(true, false, Duration::ZERO),
                component_output: None,
                runtime_diagnostic: Some("component timed out".to_owned()),
                aot_cache_status: AotCacheStatus::Miss,
                measurement: recorder.finish(
                    PreparationState::NotObserved,
                    Some("not_inspected".to_owned()),
                ),
            });
        }
        let timeout = effective_timeout(request.timeout_ms, self.limits.max_timeout)?;
        let deadline = total_started
            .checked_add(timeout)
            .ok_or_else(|| WasmError::InvalidRequest("wall timeout overflows".to_owned()))?;
        let package_started = Instant::now();
        let admitted = self.admit_and_compile_measured(reference, &mut recorder);
        recorder.record_elapsed(RuntimePhase::PackagePrepare, None, package_started);
        let AdmittedComponentResult {
            component,
            cache_status,
            preparation_state,
        } = admitted?;
        if request.cancellation.is_cancelled() {
            return Ok(WasmExecutionOutput {
                executor: interrupted_output(false, true, total_started.elapsed()),
                component_output: None,
                runtime_diagnostic: None,
                aot_cache_status: cache_status,
                measurement: recorder.finish(
                    preparation_state,
                    Some(cache_status_name(cache_status).to_owned()),
                ),
            });
        }
        if total_started.elapsed() >= timeout {
            return Ok(WasmExecutionOutput {
                executor: interrupted_output(true, false, total_started.elapsed()),
                component_output: None,
                runtime_diagnostic: Some("component timed out".to_owned()),
                aot_cache_status: cache_status,
                measurement: recorder.finish(
                    preparation_state,
                    Some(cache_status_name(cache_status).to_owned()),
                ),
            });
        }
        let invocation_started = Instant::now();
        let input = recorder
            .measure(
                RuntimePhase::InvocationPrepare,
                Some("input_serialize"),
                || serde_json::to_vec(inputs),
            )
            .map_err(|error| WasmError::InvalidInput(error.to_string()))?;
        if input.len() > self.limits.max_input_bytes {
            return Err(WasmError::LimitExceeded("component input"));
        }
        let grants = recorder.measure(
            RuntimePhase::InvocationPrepare,
            Some("capability_grants"),
            || self.build_grants(request),
        )?;
        let configured_memory = u64::try_from(self.limits.max_memory_bytes)
            .map_err(|_| WasmError::LimitExceeded("configured memory"))?;
        let memory_limit = usize::try_from(request.runner.memory_bytes.min(configured_memory))
            .map_err(|_| WasmError::LimitExceeded("runner memory"))?;
        let store_limits = AggregateStoreLimits::new(
            memory_limit,
            self.limits.max_table_elements,
            self.limits.max_instances,
            self.limits.max_tables,
            self.limits.max_memories,
        );
        let mut store = recorder.measure(
            RuntimePhase::InvocationPrepare,
            Some("store_create"),
            || {
                let mut store = Store::new(
                    &component.engine,
                    HostState::new(HostInvocation {
                        input,
                        limits: self.limits.host_limits(),
                        call_context: CapabilityCallContext::new(
                            deadline,
                            request.cancellation.clone(),
                            self.limits.max_adapter_request_bytes,
                            self.limits
                                .max_adapter_response_bytes
                                .max(self.limits.max_secret_bytes)
                                .max(self.limits.max_oidc_token_bytes),
                        )
                        .with_step_binding(
                            &request.job_id,
                            request.job_attempt,
                            &request.step_id,
                        ),
                        adapters: adapters.clone(),
                        directories: grants.directories,
                        networks: grants.networks,
                        secrets: grants.secrets,
                        oidc_audiences: grants.oidc_audiences,
                        store_limits,
                    }),
                );
                store.limiter(|state| &mut state.store_limits);
                store
                    .set_fuel(
                        self.limits
                            .fuel_for_timeout(timeout)
                            .saturating_mul(fuel_multiplier),
                    )
                    .map_err(|error| WasmError::RuntimeConfiguration(error.to_string()))?;
                store.set_epoch_deadline(1);
                store.epoch_deadline_trap();
                Ok::<_, WasmError>(store)
            },
        )?;

        let linker = recorder.measure(
            RuntimePhase::InvocationPrepare,
            Some("linker_create"),
            || {
                let mut linker = wasmtime::component::Linker::new(&component.engine);
                Run::add_to_linker::<_, wasmtime::component::HasSelf<HostState>>(
                    &mut linker,
                    |state: &mut HostState| state,
                )
                .map_err(|error| WasmError::Link(error.to_string()))?;
                wasmtime_wasi::p3::add_to_linker(&mut linker)
                    .map_err(|error| WasmError::Link(error.to_string()))?;
                Ok::<_, WasmError>(linker)
            },
        )?;
        recorder.record_elapsed(RuntimePhase::InvocationPrepare, None, invocation_started);
        let remaining = timeout.saturating_sub(total_started.elapsed());
        if remaining.is_zero() {
            return Ok(WasmExecutionOutput {
                executor: interrupted_output(true, false, total_started.elapsed()),
                component_output: None,
                runtime_diagnostic: Some("component timed out".to_owned()),
                aot_cache_status: cache_status,
                measurement: recorder.finish(
                    preparation_state,
                    Some(cache_status_name(cache_status).to_owned()),
                ),
            });
        }
        let watchdog = EpochWatchdog::start(
            component.engine.clone(),
            request.cancellation.clone(),
            remaining,
        );
        let instantiated = recorder.measure(RuntimePhase::Instantiate, None, || {
            Run::instantiate(&mut store, &component.component, &linker)
        });
        let call_result = match instantiated {
            Ok(bindings) => recorder.measure(RuntimePhase::GuestRun, None, || {
                bindings.call_run(&mut store)
            }),
            Err(error) => Err(error),
        };
        let interruption = watchdog.finish()?;
        let elapsed = total_started.elapsed();
        let (executor, component_output, runtime_diagnostic) = recorder.measure(
            RuntimePhase::OutputFinalize,
            Some("classify_and_validate"),
            || {
                let host_output = store.data().output();
                let (executor, runtime_diagnostic) = classify_call(
                    call_result,
                    interruption,
                    host_output.clone(),
                    elapsed,
                    self.limits.max_log_bytes,
                );
                let component_output = host_output
                    .output
                    .map(|value| String::from_utf8_lossy(&value).into_owned());
                (executor, component_output, runtime_diagnostic)
            },
        );
        Ok(WasmExecutionOutput {
            executor,
            component_output,
            runtime_diagnostic,
            aot_cache_status: cache_status,
            measurement: recorder.finish(
                preparation_state,
                Some(cache_status_name(cache_status).to_owned()),
            ),
        })
    }

    fn validate_request(
        &self,
        request: &StepExecutionRequest,
        adapters: &CapabilityAdapters,
    ) -> Result<(), WasmError> {
        validate_bounded_text("job id", &request.job_id, 256)?;
        validate_bounded_text("step id", &request.step_id, 256)?;
        if request.job_attempt == 0 {
            return Err(WasmError::InvalidRequest(
                "job attempt must be positive".to_owned(),
            ));
        }
        if request.runner.isolation != Isolation::Wasm {
            return Err(WasmError::UnsupportedIsolation(format!(
                "{:?}",
                request.runner.isolation
            )));
        }
        if request.runner.os != self.target.operating_system
            || request.runner.arch != self.target.architecture
        {
            return Err(WasmError::PlatformMismatch);
        }
        if !request.runner.capabilities.is_empty() {
            return Err(WasmError::UnsupportedCapability(
                "ambient runner capabilities".to_owned(),
            ));
        }
        if !request.environment.is_empty() {
            return Err(WasmError::AmbientEnvironmentDenied);
        }
        if request.working_directory.is_some() {
            return Err(WasmError::UnsupportedCapability(
                "ambient working directory".to_owned(),
            ));
        }
        if request.runner.memory_bytes == 0
            || u64::try_from(self.limits.max_memory_bytes)
                .map_or(true, |maximum| request.runner.memory_bytes > maximum)
        {
            return Err(WasmError::LimitExceeded("runner memory"));
        }
        validate_capabilities(&request.capabilities, adapters)?;
        if request
            .timeout_ms
            .is_some_and(|timeout| Duration::from_millis(timeout) > self.limits.max_timeout)
        {
            return Err(WasmError::LimitExceeded("wall timeout"));
        }
        Ok(())
    }

    fn admit_and_compile(
        &self,
        reference: &str,
    ) -> Result<(Arc<WarmComponent>, AotCacheStatus), WasmError> {
        let mut recorder = PhaseRecorder::new();
        let result = self.admit_and_compile_measured(reference, &mut recorder)?;
        Ok((result.component, result.cache_status))
    }

    fn admit_and_compile_measured(
        &self,
        reference: &str,
        recorder: &mut PhaseRecorder,
    ) -> Result<AdmittedComponentResult, WasmError> {
        let artifact = self
            .components
            .get(reference)
            .ok_or_else(|| WasmError::UnknownComponent(reference.to_owned()))?;
        recorder.measure(
            RuntimePhase::PackagePrepare,
            Some("manifest_verify"),
            || artifact.verify(&self.target, self.limits, now_unix_ms()?),
        )?;
        let digest = artifact.signed_manifest.manifest.payload_digest.clone();
        let resident = recorder.measure(
            RuntimePhase::PackagePrepare,
            Some("warm_component_lookup"),
            || {
                self.package_cache
                    .lock()
                    .map_err(|_| WasmError::Internal("package cache state is poisoned".to_owned()))
                    .map(|mut cache| cache.warm(&digest))
            },
        )?;
        if let Some(component) = resident {
            return Ok(AdmittedComponentResult {
                component,
                cache_status: AotCacheStatus::Hit,
                preparation_state: PreparationState::ProcessWarmPackageHot,
            });
        }
        let key = self.aot_cache_key(digest.clone());
        let memory_aot = recorder.measure(
            RuntimePhase::PackagePrepare,
            Some("warmish_aot_lookup"),
            || {
                self.package_cache
                    .lock()
                    .map_err(|_| WasmError::Internal("package cache state is poisoned".to_owned()))
                    .map(|mut cache| cache.warmish(&digest))
            },
        )?;
        if let Some(aot) = memory_aot {
            let loaded = recorder.measure(
                RuntimePhase::PackagePrepare,
                Some("aot_memory_deserialize"),
                || self.deserialize_component(&self.cached_engine, &key, &aot, false),
            );
            if let Ok(component) = loaded {
                self.retain_warm(digest, component.clone())?;
                return Ok(AdmittedComponentResult {
                    component,
                    cache_status: AotCacheStatus::Hit,
                    preparation_state: PreparationState::ProcessWarmAotPrepared,
                });
            }
            self.package_cache
                .lock()
                .map_err(|_| WasmError::Internal("package cache state is poisoned".to_owned()))?
                .remove_warmish(&digest);
            let error = AotCacheError::CorruptArtifact;
            self.record_cache_event(&key, &error);
            let _ = self.cache.quarantine(&key);
        }
        let inspection_result =
            recorder.measure(RuntimePhase::PackagePrepare, Some("cache_inspect"), || {
                self.cache.inspect(&self.source_engine, &key)
            });
        let inspection = match inspection_result {
            Ok(inspection) => Some(inspection),
            Err(error) => {
                self.record_cache_event(&key, &error);
                let _ = self.cache.quarantine(&key);
                None
            }
        };
        let (component, status, preparation_state) = match inspection {
            Some(inspection) if inspection.status == AotCacheStatus::Hit => {
                let loaded = recorder.measure(
                    RuntimePhase::PackagePrepare,
                    Some("aot_deserialize"),
                    || {
                        let authenticated = inspection
                            .authenticated_artifact
                            .ok_or(WasmError::AotCache(AotCacheError::CorruptArtifact))?;
                        let aot = Arc::new(AdmittedAot::from_authenticated_cache(
                            &self.cached_engine,
                            &key,
                            authenticated,
                        )?);
                        let component =
                            self.deserialize_component(&self.cached_engine, &key, &aot, true)?;
                        self.retain_warmish(digest.clone(), aot)?;
                        Ok::<_, WasmError>(component)
                    },
                );
                match loaded {
                    Ok(component) => (
                        component,
                        AotCacheStatus::Hit,
                        PreparationState::ProcessColdCacheHit,
                    ),
                    Err(_) => {
                        let error = AotCacheError::CorruptArtifact;
                        self.record_cache_event(&key, &error);
                        let _ = self.cache.quarantine(&key);
                        let (component, aot) = recorder.measure(
                            RuntimePhase::PackagePrepare,
                            Some("source_compile_after_quarantine"),
                            || self.compile_component(&self.source_engine, artifact, &key),
                        )?;
                        self.retain_warmish(digest.clone(), aot)?;
                        (
                            component,
                            AotCacheStatus::QuarantinedMiss,
                            PreparationState::ProcessColdQuarantinedMiss,
                        )
                    }
                }
            }
            Some(_) => {
                let (component, aot) = recorder.measure(
                    RuntimePhase::PackagePrepare,
                    Some("source_compile"),
                    || self.compile_component(&self.source_engine, artifact, &key),
                )?;
                recorder.measure(RuntimePhase::PackagePrepare, Some("cache_publish"), || {
                    self.record_compiled_aot(&key, aot.bytes())
                });
                self.retain_warmish(digest.clone(), aot)?;
                (
                    component,
                    AotCacheStatus::Miss,
                    PreparationState::ProcessColdCacheCold,
                )
            }
            None => {
                let (component, aot) = recorder.measure(
                    RuntimePhase::PackagePrepare,
                    Some("source_compile_after_quarantine"),
                    || self.compile_component(&self.source_engine, artifact, &key),
                )?;
                recorder.measure(
                    RuntimePhase::PackagePrepare,
                    Some("cache_publish_after_quarantine"),
                    || self.record_compiled_aot(&key, aot.bytes()),
                );
                self.retain_warmish(digest.clone(), aot)?;
                (
                    component,
                    AotCacheStatus::QuarantinedMiss,
                    PreparationState::ProcessColdQuarantinedMiss,
                )
            }
        };
        self.retain_warm(digest, component.clone())?;
        Ok(AdmittedComponentResult {
            component,
            cache_status: status,
            preparation_state,
        })
    }

    fn record_compiled_aot(&self, key: &AotCacheKey, serialized: &[u8]) {
        if let Err(error) = self.cache.record(key, serialized) {
            let concurrent_exact = matches!(error, AotCacheError::EntryAlreadyExists)
                && self
                    .cache
                    .inspect(&self.source_engine, key)
                    .ok()
                    .and_then(|inspection| inspection.authenticated_artifact)
                    .is_some_and(|authenticated| authenticated.as_bytes() == serialized);
            if !concurrent_exact {
                self.record_cache_event(key, &error);
                let _ = self.cache.quarantine(key);
            }
        }
    }

    fn aot_cache_key(&self, component_digest: ContentDigest) -> AotCacheKey {
        AotCacheKey {
            component_digest,
            wit_world: WIT_WORLD.to_owned(),
            wit_digest: ContentDigest::sha256(WIT_SOURCE),
            wasi_version: WASI_VERSION.to_owned(),
            wasmtime_version: WASMTIME_VERSION.to_owned(),
            target_triple: self.target.target_triple.clone(),
            cpu_feature_floor: self.target.cpu_feature_floor.clone(),
            compiler_settings: COMPILER_SETTINGS.to_owned(),
            security_mitigation_profile: SECURITY_MITIGATION_PROFILE.to_owned(),
            engine_compatibility_digest: engine_compatibility_digest(&self.source_engine),
        }
    }

    fn compile_component(
        &self,
        engine: &Engine,
        artifact: &WasmComponentArtifact,
        key: &AotCacheKey,
    ) -> Result<(Arc<WarmComponent>, Arc<AdmittedAot>), WasmError> {
        let component = Component::from_binary(engine, artifact.bytes())
            .map_err(|error| WasmError::Compile(error.to_string()))?;
        self.validate_component_interface(engine, &component)?;
        let aot = Arc::new(AdmittedAot::from_component(engine, key, &component)?);
        Ok((
            Arc::new(WarmComponent {
                engine: engine.clone(),
                component,
            }),
            aot,
        ))
    }

    fn deserialize_component(
        &self,
        engine: &Engine,
        expected_key: &AotCacheKey,
        aot: &AdmittedAot,
        validate_interface: bool,
    ) -> Result<Arc<WarmComponent>, WasmError> {
        if aot.key() != expected_key {
            return Err(WasmError::AotCache(AotCacheError::Incompatible));
        }
        let component = aot.deserialize(engine)?;
        if validate_interface {
            self.validate_component_interface(engine, &component)?;
        }
        Ok(Arc::new(WarmComponent {
            engine: engine.clone(),
            component,
        }))
    }

    fn retain_warmish(
        &self,
        digest: ContentDigest,
        aot: Arc<AdmittedAot>,
    ) -> Result<(), WasmError> {
        self.package_cache
            .lock()
            .map_err(|_| WasmError::Internal("package cache state is poisoned".to_owned()))?
            .insert_warmish(digest, aot);
        Ok(())
    }

    fn retain_warm(
        &self,
        digest: ContentDigest,
        component: Arc<WarmComponent>,
    ) -> Result<(), WasmError> {
        self.package_cache
            .lock()
            .map_err(|_| WasmError::Internal("package cache state is poisoned".to_owned()))?
            .insert_warm(digest, component);
        Ok(())
    }

    fn record_cache_event(&self, key: &AotCacheKey, error: &AotCacheError) {
        let Ok(key_digest) = key.digest() else {
            return;
        };
        let Ok(mut events) = self.cache_events.lock() else {
            return;
        };
        if events.len() == MAX_RETAINED_AOT_CACHE_EVENTS {
            events.pop_front();
        }
        events.push_back(AotCacheEvent {
            key_digest,
            kind: error.event_kind(),
        });
    }

    pub fn aot_cache_events(&self) -> Result<Vec<AotCacheEvent>, WasmError> {
        self.cache_events
            .lock()
            .map(|events| events.iter().cloned().collect())
            .map_err(|_| WasmError::Internal("AOT cache event state is poisoned".to_owned()))
    }

    fn validate_component_interface(
        &self,
        engine: &Engine,
        component: &Component,
    ) -> Result<(), WasmError> {
        let Some((ComponentItem::ComponentFunc(run), _)) = component.get_export(None, "run") else {
            return Err(WasmError::Link(
                "component does not implement the exact WIT world".to_owned(),
            ));
        };
        if run.params().len() != 0 || run.results().len() != 0 {
            return Err(WasmError::Link(
                "component does not implement the exact WIT world".to_owned(),
            ));
        }
        let mut linker = wasmtime::component::Linker::new(engine);
        Run::add_to_linker::<_, wasmtime::component::HasSelf<HostState>>(
            &mut linker,
            |state: &mut HostState| state,
        )
        .map_err(|error| WasmError::Link(error.to_string()))?;
        wasmtime_wasi::p3::add_to_linker(&mut linker)
            .map_err(|error| WasmError::Link(error.to_string()))?;
        let pre = linker.instantiate_pre(component).map_err(|_| {
            WasmError::Link("component does not implement the exact WIT world".to_owned())
        })?;
        RunPre::new(pre).map(|_| ()).map_err(|_| {
            WasmError::Link("component does not implement the exact WIT world".to_owned())
        })
    }

    pub(crate) fn build_grants(
        &self,
        request: &StepExecutionRequest,
    ) -> Result<InvocationGrants, WasmError> {
        let mut directory_access = BTreeMap::<String, (bool, bool)>::new();
        for path in &request.capabilities.fs_read {
            let path = normalize_scope(path)?;
            directory_access.entry(path).or_default().0 = true;
        }
        for path in &request.capabilities.fs_write {
            let path = normalize_scope(path)?;
            directory_access.entry(path).or_default().1 = true;
        }
        let mut used = BTreeSet::new();
        let mut directories = BTreeMap::new();
        for (scope, (read, write)) in directory_access {
            let access = match (read, write) {
                (true, true) => FilesystemAccess::ReadWrite,
                (true, false) => FilesystemAccess::Read,
                (false, true) => FilesystemAccess::Write,
                (false, false) => {
                    return Err(WasmError::Internal(
                        "empty filesystem capability grant".to_owned(),
                    ))
                }
            };
            let handle = self.unique_handle(b"fs", request, scope.as_bytes(), &mut used)?;
            directories.insert(handle, DirectoryGrant::new(scope, access));
        }
        let mut networks = BTreeMap::new();
        if request.capabilities.network != NetworkPermission::Deny {
            let canonical = serde_json::to_vec(&request.capabilities.network)
                .map_err(|error| WasmError::InvalidRequest(error.to_string()))?;
            let handle = self.unique_handle(b"network", request, &canonical, &mut used)?;
            networks.insert(handle, request.capabilities.network.clone());
        }
        let mut secrets = BTreeMap::new();
        let mut seen_secrets = BTreeSet::<SecretReference>::new();
        for secret in &request.capabilities.secrets {
            if !seen_secrets.insert(secret.clone()) {
                return Err(WasmError::InvalidRequest(
                    "duplicate secret capability".to_owned(),
                ));
            }
            let canonical = serde_json::to_vec(secret)
                .map_err(|error| WasmError::InvalidRequest(error.to_string()))?;
            let handle = self.unique_handle(b"secret", request, &canonical, &mut used)?;
            secrets.insert(handle, secret.clone());
        }
        let mut oidc_audiences = BTreeMap::new();
        let mut seen_audiences = BTreeSet::new();
        for audience in &request.capabilities.oidc_audiences {
            if !seen_audiences.insert(audience) {
                return Err(WasmError::InvalidRequest(
                    "duplicate OIDC audience capability".to_owned(),
                ));
            }
            let handle = self.unique_handle(b"oidc", request, audience.as_bytes(), &mut used)?;
            oidc_audiences.insert(handle, audience.clone());
        }
        Ok(InvocationGrants {
            directories,
            networks,
            secrets,
            oidc_audiences,
        })
    }

    fn unique_handle(
        &self,
        domain: &[u8],
        request: &StepExecutionRequest,
        grant: &[u8],
        used: &mut BTreeSet<u64>,
    ) -> Result<u64, WasmError> {
        for nonce in 0..=u64::MAX {
            let handle = self
                .handle_authentication_key
                .derive(domain, request, grant, nonce)?;
            if used.insert(handle) {
                return Ok(handle);
            }
        }
        Err(WasmError::Internal(
            "could not derive a unique capability handle".to_owned(),
        ))
    }

    pub fn preflight_with_adapters(
        &self,
        capsule: &ExecutionCapsule,
        adapters: &CapabilityAdapters,
    ) -> Result<(), ExecutorError> {
        self.preflight_capsule_with_adapters(capsule, adapters)
            .map_err(map_preflight_error)
    }

    pub fn execute_with_adapters(
        &self,
        request: &StepExecutionRequest,
        adapters: &CapabilityAdapters,
    ) -> Result<ExecutorOutput, ExecutorError> {
        self.execute_request_with_adapters(request, adapters)
            .map(into_executor_output)
            .map_err(map_execution_error)
    }

    pub fn execute_with_adapters_and_diagnostic(
        &self,
        request: &StepExecutionRequest,
        adapters: &CapabilityAdapters,
        fuel_multiplier: u64,
    ) -> Result<(ExecutorOutput, Option<String>), ExecutorError> {
        self.execute_request_with_adapters_and_fuel_multiplier(request, adapters, fuel_multiplier)
            .map(|output| {
                let diagnostic = output.runtime_diagnostic.clone();
                (into_executor_output(output), diagnostic)
            })
            .map_err(map_execution_error)
    }
}

impl Executor for WasmExecutor {
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        self.preflight_capsule(capsule).map_err(map_preflight_error)
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        self.execute_request(request)
            .map(into_executor_output)
            .map_err(map_execution_error)
    }

    fn finish_job_attempt(
        &mut self,
        _job: &PlannedJob,
        _attempt: u32,
        _outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        Ok(())
    }
}

pub(crate) fn into_executor_output(output: WasmExecutionOutput) -> ExecutorOutput {
    let mut executor = output.executor;
    executor.structured_output = output.component_output;
    executor
}

const fn cache_status_name(status: AotCacheStatus) -> &'static str {
    match status {
        AotCacheStatus::Hit => "hit",
        AotCacheStatus::Miss => "miss",
        AotCacheStatus::QuarantinedMiss => "quarantined_miss",
    }
}

fn classify_call(
    result: wasmtime::Result<()>,
    interruption: Interruption,
    host: HostOutput,
    elapsed: Duration,
    max_log_bytes: usize,
) -> (ExecutorOutput, Option<String>) {
    if interruption == Interruption::Timeout {
        let mut output = interrupted_output(true, false, elapsed);
        merge_host_output(&mut output, host);
        return (output, Some("component timed out".to_owned()));
    }
    if interruption == Interruption::Canceled {
        let mut output = interrupted_output(false, true, elapsed);
        merge_host_output(&mut output, host);
        return (output, None);
    }
    match result {
        Ok(()) => {
            let mut output = ExecutorOutput::success();
            output.duration_ms = duration_ms(elapsed);
            merge_host_output(&mut output, host);
            (output, None)
        }
        Err(error) => {
            let out_of_fuel = error
                .downcast_ref::<Trap>()
                .is_some_and(|trap| *trap == Trap::OutOfFuel);
            let mut output = ExecutorOutput::failure(1);
            output.duration_ms = duration_ms(elapsed);
            merge_host_output(&mut output, host);
            let diagnostic = if out_of_fuel {
                "component fuel exhausted"
            } else {
                "component trapped"
            };
            append_bounded_diagnostic(&mut output, diagnostic, max_log_bytes);
            (output, Some(diagnostic.to_owned()))
        }
    }
}

fn merge_host_output(output: &mut ExecutorOutput, host: HostOutput) {
    output.stdout = host.stdout;
    output.stderr = host.stderr;
    output.credential_taint = host.credential_taint;
    output.stdout_truncated = host.stdout_truncated;
    output.stderr_truncated = host.stderr_truncated;
}

fn append_bounded_diagnostic(output: &mut ExecutorOutput, diagnostic: &str, max_log_bytes: usize) {
    let separator = usize::from(!output.stderr.is_empty());
    if output
        .stderr
        .len()
        .saturating_add(separator)
        .saturating_add(diagnostic.len())
        > max_log_bytes
    {
        output.stderr_truncated = true;
        return;
    }
    if separator != 0 {
        output.stderr.push('\n');
    }
    output.stderr.push_str(diagnostic);
}

fn interrupted_output(timed_out: bool, canceled: bool, elapsed: Duration) -> ExecutorOutput {
    ExecutorOutput {
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        structured_output: None,
        credential_taint: runtrue_engine::CredentialTaint::None,
        stdout_truncated: false,
        stderr_truncated: false,
        timed_out,
        canceled,
        duration_ms: duration_ms(elapsed),
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn runtime_config(
    target: &WasmTarget,
    limits: WasmLimits,
    cache_config: Option<&Path>,
) -> Result<Config, WasmError> {
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .wasm_component_model_async(true)
        .consume_fuel(true)
        .epoch_interruption(true)
        .max_wasm_stack(limits.max_wasm_stack_bytes)
        .wasm_relaxed_simd(false)
        .wasm_simd(false)
        .memory_reservation(0)
        .memory_reservation_for_growth(0)
        .cranelift_opt_level(OptLevel::SpeedAndSize)
        .cranelift_nan_canonicalization(true);
    config
        .target(target.target_triple())
        .map_err(|error| WasmError::RuntimeConfiguration(error.to_string()))?;
    if let Some(cache_config) = cache_config {
        let cache = wasmtime::Cache::from_file(Some(cache_config))
            .map_err(|error| WasmError::RuntimeConfiguration(error.to_string()))?;
        config.cache(Some(cache));
    }
    Ok(config)
}

pub(crate) fn expected_compatibility(target: &WasmTarget) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "cpu_feature_floor".to_owned(),
            target.cpu_feature_floor.clone(),
        ),
        ("target_triple".to_owned(), target.target_triple.clone()),
        ("wasi_version".to_owned(), WASI_VERSION.to_owned()),
        ("wasmtime_version".to_owned(), WASMTIME_VERSION.to_owned()),
        ("wit_world".to_owned(), WIT_WORLD.to_owned()),
    ])
}

fn now_unix_ms() -> Result<u64, WasmError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WasmError::Internal("system clock is before the Unix epoch".to_owned()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| WasmError::Internal("system clock overflow".to_owned()))
}

fn map_preflight_error(error: WasmError) -> ExecutorError {
    match error {
        WasmError::UnsupportedIsolation(mode) => ExecutorError::UnsupportedIsolation(mode),
        WasmError::PlatformMismatch => ExecutorError::PlatformMismatch {
            requested: "capsule Wasm target".to_owned(),
            host: "embedded Wasmtime target".to_owned(),
        },
        error => ExecutorError::UnsupportedCapsuleFeature(format!("Wasm executor: {error}")),
    }
}

fn map_execution_error(error: WasmError) -> ExecutorError {
    match error {
        WasmError::UnsupportedIsolation(mode) => ExecutorError::UnsupportedIsolation(mode),
        WasmError::PlatformMismatch => ExecutorError::PlatformMismatch {
            requested: "step Wasm target".to_owned(),
            host: "embedded Wasmtime target".to_owned(),
        },
        WasmError::UnknownComponent(reference) => ExecutorError::UnsupportedComponent(reference),
        error => ExecutorError::Spawn(format!("Wasm executor: {error}")),
    }
}
