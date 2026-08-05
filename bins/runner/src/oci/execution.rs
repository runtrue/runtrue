use super::{
    fmt, fs, io, load_assignments, load_image_keys, load_runtime_environment,
    prepare_private_directory, recover_abandoned_job_state, sorted_directory_files,
    validate_podman, validate_private_directory, validate_private_regular_file,
    validate_runtime_environment, validate_seccomp_profile_file, verify_preloaded_images,
    AdmittedLease, Arc, BTreeSet, CancellationToken, Engine, ExecutionResult, ExecutorDispatcher,
    Isolation, LoadedOciConfiguration, OciExecutor, OciExecutorConfig, OciRecoveryConfig,
    OciRuntimeFactory, OciRuntimePaths, Path, ProcessRuntimeFactory, RunnerError,
    SelectedAssignments, SelectedManifestAdmission, StepStateObserver,
};

#[derive(Clone)]
pub struct OciJobExecutor {
    configuration: Arc<LoadedOciConfiguration>,
    runtime_factory: Arc<dyn OciRuntimeFactory>,
}

impl fmt::Debug for OciJobExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OciJobExecutor")
            .field("state_root", &self.configuration.state_root)
            .field("podman", &self.configuration.podman)
            .field("image_store", &self.configuration.image_store)
            .field("manifest_count", &self.configuration.assignments.len())
            .finish_non_exhaustive()
    }
}

impl OciJobExecutor {
    pub fn load(paths: &OciRuntimePaths) -> Result<Self, RunnerError> {
        // Construction proves this host is rootless before OCI is advertised.
        let factory: Arc<dyn OciRuntimeFactory> = Arc::new(ProcessRuntimeFactory);
        let probe = factory.create()?;
        drop(probe);
        Self::load_with_factory(paths, factory)
    }

    pub(super) fn load_with_factory(
        paths: &OciRuntimePaths,
        runtime_factory: Arc<dyn OciRuntimeFactory>,
    ) -> Result<Self, RunnerError> {
        let state_root = prepare_private_directory(&paths.state_root)?;
        let image_store = validate_private_directory(&paths.image_store, "OCI image store")?;
        let manifest_directory =
            validate_private_directory(&paths.manifest_directory, "OCI manifest directory")?;
        let keyring_directory =
            validate_private_directory(&paths.keyring_directory, "OCI image keyring")?;
        let podman = validate_podman(&paths.podman)?;
        let seccomp_profile = validate_private_regular_file(&paths.seccomp_profile)?;
        let seccomp_profile = validate_seccomp_profile_file(&seccomp_profile)?;
        let runtime_environment = load_runtime_environment(&paths.runtime_environment)?;
        validate_runtime_environment(&runtime_environment)?;
        let keys = load_image_keys(&keyring_directory)?;
        let assignments = load_assignments(&manifest_directory, &keys)?;
        let references = assignments
            .records()
            .map(|record| record.locked.reference().to_owned())
            .collect::<BTreeSet<_>>();
        let mut recovery = OciRecoveryConfig::new(&podman);
        recovery.runtime_environment = runtime_environment.clone();
        recovery.image_store = Some(image_store.clone());
        let mut runtime = runtime_factory.create()?;
        let probe_state = state_root.join(".image-probe");
        match fs::symlink_metadata(&probe_state) {
            Ok(_) => {
                validate_private_directory(&probe_state, "stale OCI image probe")?;
                recover_abandoned_job_state(&probe_state, &recovery, &mut runtime)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RunnerError::OciConfiguration(format!(
                    "inspect stale OCI image probe: {error}"
                )))
            }
        }
        verify_preloaded_images(&probe_state, &recovery, references, &mut runtime)?;
        Ok(Self {
            configuration: Arc::new(LoadedOciConfiguration {
                state_root,
                podman,
                seccomp_profile,
                image_store,
                runtime_environment,
                manifest_directory,
                keys,
                assignments,
            }),
            runtime_factory,
        })
    }

    pub fn preflight_lease(&self, lease: &AdmittedLease) -> Result<(), RunnerError> {
        self.select_current(lease).map(|_| ())
    }

    pub fn execute(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
    ) -> Result<ExecutionResult, RunnerError> {
        self.execute_with_observer(lease, workspace, cancellation, None)
    }

    pub fn execute_with_observer(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
        observer: Option<Arc<dyn StepStateObserver>>,
    ) -> Result<ExecutionResult, RunnerError> {
        self.execute_with_observer_and_broker(lease, workspace, cancellation, observer, None)
    }

    pub fn execute_with_observer_and_broker(
        &self,
        lease: &AdmittedLease,
        workspace: &Path,
        cancellation: CancellationToken,
        observer: Option<Arc<dyn StepStateObserver>>,
        broker_socket: Option<&Path>,
    ) -> Result<ExecutionResult, RunnerError> {
        let selected = self.select_current(lease)?;
        let lease_state = self.configuration.lease_state_path(lease);
        if fs::symlink_metadata(&lease_state).is_ok() {
            return Err(RunnerError::OciConfiguration(format!(
                "stale OCI state exists for lease `{}`",
                lease.lease_id
            )));
        }
        let mut config = OciExecutorConfig::new(
            &self.configuration.podman,
            &self.configuration.seccomp_profile,
        );
        config.image_store = Some(self.configuration.image_store.clone());
        config.runtime_environment = self.configuration.runtime_environment.clone();
        if let Some(socket) = broker_socket {
            config.broker_socket = Some(runtrue_executor_oci::OciMount::read_write(
                socket,
                "/workspace/.runtrue-runtime/scm-proxy.sock",
            ));
        }
        config.insert_job_image(&lease.job_id, selected.job.locked.clone())?;
        for (service_id, record) in &selected.services {
            config.insert_service_image(&lease.job_id, service_id, record.locked.clone())?;
        }
        let provider = SelectedManifestAdmission {
            keys: Arc::clone(&self.configuration.keys),
            records: selected
                .all_records()
                .map(|record| (record.locked.reference().to_owned(), record.clone()))
                .collect(),
        };
        let runtime = self.runtime_factory.create()?;
        let executor = OciExecutor::new(workspace, &lease_state, config, provider, runtime)?;
        let mut dispatcher = ExecutorDispatcher::new();
        dispatcher
            .register(Isolation::Oci, executor)
            .map_err(|error| RunnerError::OciConfiguration(error.to_string()))?;
        let mut engine = Engine::with_cancellation_token(dispatcher, cancellation);
        engine.set_step_state_observer(observer);
        let result = engine.execute_offered_job(&lease.capsule, &lease.job_id)?;
        remove_empty_lease_state(&self.configuration.state_root, &lease_state)?;
        Ok(result)
    }

    /// Sweep abandoned private graph roots before opening the control stream.
    /// State is deleted only after Podman proves containers, volumes, and Runtrue
    /// networks absent.
    pub fn cleanup_stale(&self) -> Result<(), RunnerError> {
        let mut recovery = OciRecoveryConfig::new(&self.configuration.podman);
        recovery.runtime_environment = self.configuration.runtime_environment.clone();
        recovery.image_store = Some(self.configuration.image_store.clone());
        let mut runtime = self.runtime_factory.create()?;
        for lease_state in sorted_directory_files(&self.configuration.state_root)? {
            validate_private_directory(&lease_state, "OCI lease state")?;
            for job_state in sorted_directory_files(&lease_state)? {
                validate_private_directory(&job_state, "OCI job state")?;
                recover_abandoned_job_state(&job_state, &recovery, &mut runtime)?;
            }
            fs::remove_dir(&lease_state).map_err(|error| {
                RunnerError::OciConfiguration(format!(
                    "remove recovered OCI lease state `{}`: {error}",
                    lease_state.display()
                ))
            })?;
        }
        Ok(())
    }

    #[must_use]
    pub fn manifest_count(&self) -> usize {
        self.configuration.assignments.len()
    }

    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.configuration.state_root
    }

    fn select_current(&self, lease: &AdmittedLease) -> Result<SelectedAssignments, RunnerError> {
        // Repository actions can be built and admitted while this runner is
        // serving other leases. Admission publishes manifests atomically, so
        // reloading here makes new immutable assignments available without
        // restarting (and interrupting) the runner.
        let assignments = load_assignments(
            &self.configuration.manifest_directory,
            &self.configuration.keys,
        )?;
        self.configuration.select(lease, &assignments)
    }
}

fn remove_empty_lease_state(root: &Path, lease_state: &Path) -> Result<(), RunnerError> {
    if lease_state.parent() != Some(root) {
        return Err(RunnerError::OciConfiguration(
            "OCI lease state escaped its configured root".to_owned(),
        ));
    }
    match fs::remove_dir(lease_state) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RunnerError::OciConfiguration(format!(
            "OCI lease state is not empty after finalization: {error}"
        ))),
    }
}
