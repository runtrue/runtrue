#[derive(Debug)]
pub(crate) struct JobRuntimeState {
    pub(crate) path: PathBuf,
    pub(crate) containers: BTreeSet<String>,
    pub(crate) network: Option<String>,
    pub(crate) services_started: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedService {
    pub(crate) id: String,
    pub(crate) image: AdmittedImage,
    pub(crate) ports: Vec<u16>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) healthcheck: Option<Healthcheck>,
}

struct PreparedContainerInvocation {
    entrypoint: Option<String>,
    arguments: Option<Vec<String>>,
    script_file: Option<EphemeralFile>,
}

pub struct OciExecutor<P: ImageAdmissionProvider, R: RuntimeCommandRunner> {
    pub(crate) workspace: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) seccomp_profile: PathBuf,
    pub(crate) config: OciExecutorConfig,
    pub(crate) admission_provider: P,
    pub(crate) runtime: R,
    pub(crate) admitted: Mutex<BTreeMap<String, AdmittedImage>>,
    pub(crate) planned_services: Mutex<BTreeMap<String, Vec<PreparedService>>>,
    pub(crate) job_states: BTreeMap<(String, u32), JobRuntimeState>,
}

impl<P, R> OciExecutor<P, R>
where
    P: ImageAdmissionProvider,
    R: RuntimeCommandRunner,
{
    pub fn new(
        workspace: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
        mut config: OciExecutorConfig,
        admission_provider: P,
        runtime: R,
    ) -> Result<Self, OciError> {
        config.limits = config.limits.validate()?;
        if config.cleanup_timeout.is_zero() || config.cleanup_timeout > config.limits.max_timeout {
            return Err(OciError::InvalidConfiguration(
                "cleanup timeout must be non-zero and within the timeout limit".to_owned(),
            ));
        }
        if !config.runtime_program.is_absolute() {
            return Err(OciError::InvalidConfiguration(
                "runtime program must be an absolute path".to_owned(),
            ));
        }
        if config
            .runtime_program
            .file_name()
            .and_then(|name| name.to_str())
            != Some("podman")
        {
            return Err(OciError::InvalidConfiguration(
                "the external runtime command must be a local `podman` binary".to_owned(),
            ));
        }
        let workspace = canonical_real_directory(workspace.as_ref(), "workspace")?;
        let state_root = prepare_private_state_root(state_root.as_ref())?;
        if paths_overlap(&workspace, &state_root) {
            return Err(OciError::InvalidConfiguration(
                "runtime state and workspace must not overlap".to_owned(),
            ));
        }
        let seccomp_profile = canonical_regular_file(
            &config.seccomp_profile,
            "seccomp profile",
            MAX_SECCOMP_PROFILE_BYTES,
        )?;
        validate_seccomp_profile(&seccomp_profile)?;
        if let Some(image_store) = &mut config.image_store {
            *image_store = canonical_real_directory(image_store, "OCI image store")?;
            if paths_overlap(&workspace, image_store) || paths_overlap(&state_root, image_store) {
                return Err(OciError::InvalidConfiguration(
                    "OCI image store must not overlap workspace or runtime state".to_owned(),
                ));
            }
        }
        ensure_mount_tree_is_safe(&workspace, config.limits.max_mount_entries)?;
        if config
            .additional_mounts
            .len()
            .saturating_add(2)
            .saturating_add(usize::from(config.broker_socket.is_some()))
            > config.limits.max_mounts
        {
            return Err(OciError::LimitExceeded {
                kind: "mount count",
                limit: config.limits.max_mounts,
                actual: config
                    .additional_mounts
                    .len()
                    .saturating_add(2)
                    .saturating_add(usize::from(config.broker_socket.is_some())),
            });
        }
        for mount in &mut config.additional_mounts {
            mount.source = validate_mount(mount, &state_root)?;
            ensure_mount_tree_is_safe(&mount.source, config.limits.max_mount_entries)?;
        }
        if let Some(mount) = &mut config.broker_socket {
            mount.source = validate_broker_socket_mount(mount, &workspace, &state_root)?;
        }
        validate_environment(
            &config.runtime_environment,
            config.limits,
            EnvironmentScope::Runtime,
        )?;
        for (job_id, image) in &config.job_images {
            validate_identifier("job image key", job_id)?;
            validate_locked_image(image)?;
        }
        for ((job_id, service_id), image) in &config.service_images {
            validate_identifier("service image job key", job_id)?;
            validate_identifier("service image service key", service_id)?;
            validate_locked_image(image)?;
        }
        Ok(Self {
            workspace,
            state_root,
            seccomp_profile,
            config,
            admission_provider,
            runtime,
            admitted: Mutex::new(BTreeMap::new()),
            planned_services: Mutex::new(BTreeMap::new()),
            job_states: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    #[must_use]
    pub const fn runtime(&self) -> &R {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut R {
        &mut self.runtime
    }

    pub fn preflight_capsule(&self, capsule: &ExecutionCapsule) -> Result<(), OciError> {
        self.admitted
            .lock()
            .map_err(|_| OciError::Internal("image admission state is poisoned".to_owned()))?
            .clear();
        self.planned_services
            .lock()
            .map_err(|_| OciError::Internal("planned service state is poisoned".to_owned()))?
            .clear();
        if !capsule.jobs.is_empty() && capsule.context.lockfile_digest.is_none() {
            return Err(OciError::UnsupportedFeature(
                "OCI execution requires a canonical lockfile digest in the capsule".to_owned(),
            ));
        }
        let mut admitted = BTreeMap::new();
        let mut prepared_services = BTreeMap::new();
        let capsule_jobs = capsule
            .jobs
            .iter()
            .map(|job| job.id.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(unused) = self
            .config
            .job_images
            .keys()
            .find(|job| !capsule_jobs.contains(job.as_str()))
        {
            return Err(OciError::UnusedImageAssignment(unused.clone()));
        }
        let capsule_service_keys = capsule
            .jobs
            .iter()
            .flat_map(|job| {
                job.services
                    .iter()
                    .map(move |service| (job.id.clone(), service.id.clone()))
            })
            .collect::<BTreeSet<_>>();
        if let Some((job_id, service_id)) = self
            .config
            .service_images
            .keys()
            .find(|key| !capsule_service_keys.contains(*key))
        {
            return Err(OciError::UnusedServiceImageAssignment {
                job_id: job_id.clone(),
                service_id: service_id.clone(),
            });
        }
        for job in &capsule.jobs {
            if job.runner.isolation != Isolation::Oci {
                return Err(OciError::UnsupportedIsolation(format!(
                    "{:?}",
                    job.runner.isolation
                )));
            }
            if job.runner.os != OperatingSystem::Linux {
                return Err(OciError::UnsupportedPlatform(format!(
                    "{:?}/{:?}",
                    job.runner.os, job.runner.arch
                )));
            }
            if job.services.len() > self.config.limits.max_services {
                return Err(OciError::LimitExceeded {
                    kind: "service count",
                    limit: self.config.limits.max_services,
                    actual: job.services.len(),
                });
            }
            if !job.runner.capabilities.is_empty() {
                return Err(OciError::UnsupportedFeature(format!(
                    "job `{}` requests ambient runner capabilities",
                    job.id
                )));
            }
            if !network_permission_supported(
                &job.permissions.network,
                self.config.broker_socket.is_some(),
            ) {
                return Err(OciError::UnsupportedFeature(format!(
                    "job `{}` requests network access the runner CONNECT broker cannot enforce",
                    job.id
                )));
            }
            for step in &job.steps {
                if matches!(step.action, StepAction::Component { .. }) {
                    return Err(OciError::UnsupportedFeature(format!(
                        "step `{}.{}` is a Wasm component action",
                        job.id, step.id
                    )));
                }
                if !network_permission_supported(
                    &step.capabilities.network,
                    self.config.broker_socket.is_some(),
                ) {
                    return Err(OciError::UnsupportedFeature(format!(
                        "step `{}.{}` requests network access the runner CONNECT broker cannot enforce",
                        job.id, step.id
                    )));
                }
            }
            let locked = self
                .config
                .job_images
                .get(&job.id)
                .ok_or_else(|| OciError::MissingImageAssignment(job.id.clone()))?;
            let planned_image = job.runner.image.as_deref().ok_or_else(|| {
                OciError::UnsupportedFeature(format!(
                    "OCI job `{}` has no approval-bound runner image",
                    job.id
                ))
            })?;
            if locked.reference() != planned_image {
                return Err(OciError::JobImageReferenceMismatch(job.id.clone()));
            }
            let expected_platform = OciPlatform::new(job.runner.os, job.runner.arch);
            if locked.platform != expected_platform {
                return Err(OciError::ImagePlatformMismatch {
                    expected: expected_platform.as_oci().to_owned(),
                    actual: locked.platform.as_oci().to_owned(),
                });
            }
            admitted.insert(job.id.clone(), self.admit_exact(locked)?);
            let mut service_ids = BTreeSet::new();
            let services = job
                .services
                .iter()
                .map(|service| {
                    if !service_ids.insert(service.id.clone()) {
                        return Err(OciError::InvalidConfiguration(format!(
                            "duplicate service id `{}.{}`",
                            job.id, service.id
                        )));
                    }
                    self.prepare_service(&job.id, service, expected_platform)
                })
                .collect::<Result<Vec<_>, _>>()?;
            prepared_services.insert(job.id.clone(), services);
        }
        *self
            .admitted
            .lock()
            .map_err(|_| OciError::Internal("image admission state is poisoned".to_owned()))? =
            admitted;
        *self
            .planned_services
            .lock()
            .map_err(|_| OciError::Internal("planned service state is poisoned".to_owned()))? =
            prepared_services;
        Ok(())
    }

    fn prepare_service(
        &self,
        job_id: &str,
        service: &PlannedService,
        expected_platform: OciPlatform,
    ) -> Result<PreparedService, OciError> {
        validate_identifier("service id", &service.id)?;
        validate_service_dns_name(&service.id)?;
        let locked = self
            .config
            .service_images
            .get(&(job_id.to_owned(), service.id.clone()))
            .ok_or_else(|| OciError::MissingServiceImageAssignment {
                job_id: job_id.to_owned(),
                service_id: service.id.clone(),
            })?;
        if locked.reference != service.image {
            return Err(OciError::ServiceImageReferenceMismatch {
                job_id: job_id.to_owned(),
                service_id: service.id.clone(),
            });
        }
        if locked.platform != expected_platform {
            return Err(OciError::ImagePlatformMismatch {
                expected: expected_platform.as_oci().to_owned(),
                actual: locked.platform.as_oci().to_owned(),
            });
        }
        let environment = service
            .environment
            .iter()
            .map(|(name, binding)| {
                let ValueBinding::Literal(value) = binding else {
                    return Err(OciError::UnsupportedFeature(format!(
                        "service `{}.{}` environment `{name}` is dynamic; resolved service bindings are not present in step execution requests",
                        job_id, service.id
                    )));
                };
                Ok((name.clone(), scalar_text(value)))
            })
            .collect::<Result<BTreeMap<_, _>, OciError>>()?;
        validate_environment(
            &environment,
            self.config.limits,
            EnvironmentScope::Container,
        )?;
        if service.ports.contains(&0) {
            return Err(OciError::InvalidConfiguration(format!(
                "service `{}.{}` declares port zero",
                job_id, service.id
            )));
        }
        let mut ports = service.ports.clone();
        ports.sort_unstable();
        ports.dedup();
        if let Some(healthcheck) = &service.healthcheck {
            validate_healthcheck(job_id, &service.id, healthcheck, self.config.limits)?;
        }
        Ok(PreparedService {
            id: service.id.clone(),
            image: self.admit_exact(locked)?,
            ports,
            environment,
            healthcheck: service.healthcheck.clone(),
        })
    }

    pub fn execute_request(
        &mut self,
        request: &StepExecutionRequest,
    ) -> Result<ExecutorOutput, OciError> {
        self.validate_request(request)?;
        if request.cancellation.is_cancelled() {
            self.finish_job(&request.job_id, request.job_attempt)?;
            return Ok(ExecutorOutput {
                exit_code: None,
                canceled: true,
                ..ExecutorOutput::success()
            });
        }
        let requested_timeout = request
            .timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(self.config.limits.max_timeout)
            .min(self.config.limits.max_timeout);
        if requested_timeout.is_zero() {
            return Ok(ExecutorOutput {
                exit_code: None,
                timed_out: true,
                ..ExecutorOutput::success()
            });
        }

        let image = self.admitted_image_for_request(request)?;
        let state_path = self.ensure_job_state(request)?;
        let container_name = container_name(request);
        let step_key = short_identity(&format!(
            "{}\0{}\0{}\0{}",
            request.job_id, request.job_attempt, request.step_id, container_name
        ));
        let environment_path = state_path.join(format!("env-{step_key}"));
        let environment_file = match EphemeralFile::write_environment(
            &environment_path,
            &request.environment,
            self.config.limits,
        ) {
            Ok(file) => file,
            Err(error) => {
                return Err(self.cleanup_after_failure(
                    &request.job_id,
                    request.job_attempt,
                    error,
                ));
            }
        };
        let action = match self.prepare_action(request, &state_path, &step_key) {
            Ok(action) => action,
            Err(error) => {
                return Err(self.cleanup_after_failure(
                    &request.job_id,
                    request.job_attempt,
                    error,
                ));
            }
        };
        match self.start_job_services(request, &state_path) {
            Ok(false) => {}
            Ok(true) => {
                return Ok(ExecutorOutput {
                    exit_code: None,
                    canceled: true,
                    ..ExecutorOutput::success()
                });
            }
            Err(error) => {
                return Err(self.cleanup_after_failure(
                    &request.job_id,
                    request.job_attempt,
                    error,
                ));
            }
        }
        let network = self
            .job_states
            .get(&(request.job_id.clone(), request.job_attempt))
            .and_then(|state| state.network.clone());
        let invocation = match self.run_invocation(
            request,
            &state_path,
            &container_name,
            &environment_path,
            &image,
            action.entrypoint.as_deref(),
            action.arguments.as_deref(),
            action.script_file.as_ref().map(EphemeralFile::path),
            network.as_deref(),
        ) {
            Ok(invocation) => invocation,
            Err(error) => {
                return Err(self.cleanup_after_failure(
                    &request.job_id,
                    request.job_attempt,
                    error,
                ));
            }
        };
        {
            let state = self
                .job_states
                .get_mut(&(request.job_id.clone(), request.job_attempt))
                .expect("state was inserted");
            if !state.containers.insert(container_name.clone()) {
                let error = OciError::InvalidState(format!(
                    "container `{container_name}` is already active"
                ));
                return Err(self.cleanup_after_failure(
                    &request.job_id,
                    request.job_attempt,
                    error,
                ));
            }
        }
        let control = RuntimeControl {
            timeout: requested_timeout,
            cancellation: request.cancellation.clone(),
            max_output_bytes: self.config.limits.max_output_bytes,
        };
        let run_result = self.runtime.invoke(&invocation, &control);
        let cleanup_result = self.cleanup_container(&state_path, &container_name);
        drop(action);
        drop(environment_file);
        if cleanup_result.is_ok() {
            if let Some(state) = self
                .job_states
                .get_mut(&(request.job_id.clone(), request.job_attempt))
            {
                state.containers.remove(&container_name);
            }
        }
        if let Err(error) = cleanup_result {
            return Err(self.cleanup_after_failure(&request.job_id, request.job_attempt, error));
        }
        let result = match run_result {
            Ok(result) => result,
            Err(error) => {
                return Err(self.cleanup_after_failure(
                    &request.job_id,
                    request.job_attempt,
                    error,
                ));
            }
        };
        if let Err(error) = validate_runtime_result(&result, self.config.limits.max_output_bytes) {
            return Err(self.cleanup_after_failure(&request.job_id, request.job_attempt, error));
        }
        if !result.process_group_clean {
            return Err(self.cleanup_after_failure(
                &request.job_id,
                request.job_attempt,
                OciError::ProcessGroupLeak,
            ));
        }
        if result.canceled || request.cancellation.is_cancelled() {
            self.finish_job(&request.job_id, request.job_attempt)?;
        }
        Ok(ExecutorOutput {
            exit_code: result.exit_code,
            stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
            structured_output: None,
            credential_taint: runtrue_engine::CredentialTaint::None,
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
            timed_out: result.timed_out,
            canceled: result.canceled,
            duration_ms: u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
        })
    }

    pub fn finish_job(&mut self, job_id: &str, attempt: u32) -> Result<(), OciError> {
        let key = (job_id.to_owned(), attempt);
        let Some(state) = self.job_states.get(&key) else {
            return Ok(());
        };
        let path = state.path.clone();
        let containers = state.containers.iter().cloned().collect::<Vec<_>>();
        let network = state.network.clone();
        let mut first_error = None;
        for container in &containers {
            match self.cleanup_container(&path, container) {
                Ok(()) => {
                    if let Some(state) = self.job_states.get_mut(&key) {
                        state.containers.remove(container);
                    }
                }
                Err(error) => record_first_error(&mut first_error, error),
            }
        }
        if let Some(network) = network {
            match self.cleanup_network(&path, &network) {
                Ok(()) => {
                    if let Some(state) = self.job_states.get_mut(&key) {
                        state.network = None;
                    }
                }
                Err(error) => record_first_error(&mut first_error, error),
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        ensure_descendant(&self.state_root, &path)?;
        fs::remove_dir_all(&path)
            .map_err(|source| io_error("remove job runtime state", &path, source))?;
        self.job_states.remove(&key);
        Ok(())
    }

    fn cleanup_after_failure(&mut self, job_id: &str, attempt: u32, error: OciError) -> OciError {
        match self.finish_job(job_id, attempt) {
            Ok(()) => error,
            Err(cleanup) => OciError::LifecycleCleanup {
                cause: error.to_string(),
                cleanup: cleanup.to_string(),
            },
        }
    }

    #[must_use]
    pub fn job_state_path(&self, job_id: &str, attempt: u32) -> Option<&Path> {
        self.job_states
            .get(&(job_id.to_owned(), attempt))
            .map(|state| state.path.as_path())
    }

    fn admit_exact(&self, locked: &LockedImage) -> Result<AdmittedImage, OciError> {
        let admitted = self.admission_provider.admit(locked)?;
        if !admitted.signature_verified
            || admitted.reference != locked.reference
            || admitted.digest != locked.digest
            || admitted.signature_identity != locked.signature_identity
            || admitted.platform != locked.platform
        {
            return Err(OciError::ImageAdmissionMismatch);
        }
        Ok(admitted)
    }

    fn admitted_image_for_request(
        &self,
        request: &StepExecutionRequest,
    ) -> Result<AdmittedImage, OciError> {
        if let Some(admitted) = self
            .admitted
            .lock()
            .map_err(|_| OciError::Internal("image admission state is poisoned".to_owned()))?
            .get(&request.job_id)
            .cloned()
        {
            return Ok(admitted);
        }
        let locked = self
            .config
            .job_images
            .get(&request.job_id)
            .ok_or_else(|| OciError::MissingImageAssignment(request.job_id.clone()))?;
        let admitted = self.admit_exact(locked)?;
        self.admitted
            .lock()
            .map_err(|_| OciError::Internal("image admission state is poisoned".to_owned()))?
            .insert(request.job_id.clone(), admitted.clone());
        Ok(admitted)
    }

    fn validate_request(&self, request: &StepExecutionRequest) -> Result<(), OciError> {
        validate_identifier("job_id", &request.job_id)?;
        validate_identifier("step_id", &request.step_id)?;
        if request.job_attempt == 0 {
            return Err(OciError::InvalidRequest(
                "job attempt must be positive".to_owned(),
            ));
        }
        if request.runner.isolation != Isolation::Oci {
            return Err(OciError::UnsupportedIsolation(format!(
                "{:?}",
                request.runner.isolation
            )));
        }
        if request.runner.os != OperatingSystem::Linux {
            return Err(OciError::UnsupportedPlatform(format!(
                "{:?}/{:?}",
                request.runner.os, request.runner.arch
            )));
        }
        if !request.runner.capabilities.is_empty() {
            return Err(OciError::UnsupportedFeature(
                "ambient runner capabilities are denied".to_owned(),
            ));
        }
        if !network_permission_supported(
            &request.capabilities.network,
            self.config.broker_socket.is_some(),
        ) {
            return Err(OciError::UnsupportedFeature(
                "OCI network access requires the runner CONNECT broker and TCP-only destinations"
                    .to_owned(),
            ));
        }
        validate_environment(
            &request.environment,
            self.config.limits,
            EnvironmentScope::Container,
        )?;
        ensure_mount_tree_is_safe(&self.workspace, self.config.limits.max_mount_entries)?;
        for mount in &self.config.additional_mounts {
            ensure_mount_tree_is_safe(&mount.source, self.config.limits.max_mount_entries)?;
        }
        validate_working_directory(request.working_directory.as_deref())?;
        let image = self
            .config
            .job_images
            .get(&request.job_id)
            .ok_or_else(|| OciError::MissingImageAssignment(request.job_id.clone()))?;
        if request.runner.image.as_deref() != Some(image.reference()) {
            return Err(OciError::JobImageReferenceMismatch(request.job_id.clone()));
        }
        let expected = OciPlatform::new(request.runner.os, request.runner.arch);
        if image.platform != expected {
            return Err(OciError::ImagePlatformMismatch {
                expected: expected.as_oci().to_owned(),
                actual: image.platform.as_oci().to_owned(),
            });
        }
        Ok(())
    }

    fn ensure_job_state(&mut self, request: &StepExecutionRequest) -> Result<PathBuf, OciError> {
        let key = (request.job_id.clone(), request.job_attempt);
        if let Some(state) = self.job_states.get(&key) {
            return Ok(state.path.clone());
        }
        let path = self.state_root.join(format!(
            "job-{}-{}",
            short_identity(&request.job_id),
            request.job_attempt
        ));
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(OciError::InvalidState(format!(
                    "stale runtime state already exists for job `{}` attempt {}",
                    request.job_id, request.job_attempt
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect job runtime state", &path, source)),
        }
        create_private_directory(&path)?;
        for child in ["storage", "run", "tmp"] {
            create_private_directory(&path.join(child))?;
        }
        self.job_states.insert(
            key,
            JobRuntimeState {
                path: path.clone(),
                containers: BTreeSet::new(),
                network: None,
                services_started: false,
            },
        );
        Ok(path)
    }

    fn prepare_action(
        &self,
        request: &StepExecutionRequest,
        state_path: &Path,
        step_key: &str,
    ) -> Result<PreparedContainerInvocation, OciError> {
        match &request.action {
            PreparedAction::Command { program, args } => {
                validate_command(program, args, self.config.limits)?;
                Ok(PreparedContainerInvocation {
                    entrypoint: Some(program.clone()),
                    arguments: Some(args.clone()),
                    script_file: None,
                })
            }
            PreparedAction::Container { entrypoint, args } => {
                validate_container_invocation(
                    entrypoint.as_deref(),
                    args.as_deref(),
                    self.config.limits,
                )?;
                Ok(PreparedContainerInvocation {
                    entrypoint: entrypoint.clone(),
                    arguments: args.clone(),
                    script_file: None,
                })
            }
            PreparedAction::Script {
                shell,
                script,
                script_digest,
            } => {
                if ContentDigest::sha256(script.as_bytes()) != *script_digest {
                    return Err(OciError::ScriptDigestMismatch);
                }
                if script.len() > self.config.limits.max_argument_bytes {
                    return Err(OciError::LimitExceeded {
                        kind: "script bytes",
                        limit: self.config.limits.max_argument_bytes,
                        actual: script.len(),
                    });
                }
                let path = state_path.join(format!("script-{step_key}"));
                let file = EphemeralFile::write_sensitive(&path, script.as_bytes())?;
                let shell = match shell {
                    Shell::Bash => "/bin/bash",
                    Shell::Sh => "/bin/sh",
                    Shell::Pwsh | Shell::Cmd => {
                        return Err(OciError::UnsupportedFeature(format!(
                            "shell `{shell:?}` is unsupported in Linux OCI jobs"
                        )));
                    }
                };
                Ok(PreparedContainerInvocation {
                    entrypoint: Some(shell.to_owned()),
                    arguments: Some(vec![CONTAINER_SCRIPT.to_owned()]),
                    script_file: Some(file),
                })
            }
            PreparedAction::Component { reference, .. } => Err(OciError::UnsupportedFeature(
                format!("component action `{reference}` requires the Wasm executor"),
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_invocation(
        &self,
        request: &StepExecutionRequest,
        state_path: &Path,
        container_name: &str,
        environment_path: &Path,
        image: &AdmittedImage,
        entrypoint: Option<&str>,
        command_arguments: Option<&[String]>,
        script_path: Option<&Path>,
        network: Option<&str>,
    ) -> Result<RuntimeInvocation, OciError> {
        let mut arguments = self.runtime_prefix(state_path)?;
        arguments.push("run".to_owned());
        arguments.extend([
            "--name".to_owned(),
            container_name.to_owned(),
            "--rm".to_owned(),
            "--pull=never".to_owned(),
            "--userns=keep-id".to_owned(),
            format!(
                "--user={}:{}",
                nix::unistd::geteuid(),
                nix::unistd::getegid()
            ),
            "--read-only".to_owned(),
            "--security-opt=no-new-privileges".to_owned(),
            format!(
                "--security-opt=seccomp={}",
                utf8_path(&self.seccomp_profile, "seccomp profile")?
            ),
            "--cap-drop=ALL".to_owned(),
            "--pid=private".to_owned(),
            "--ipc=private".to_owned(),
            "--ulimit=core=0:0".to_owned(),
            format!("--pids-limit={}", self.config.limits.max_pids),
            format!("--memory={}", request.runner.memory_bytes),
            format!("--cpus={}", request.runner.cpu),
            format!("--platform={}", image.platform.as_oci()),
            format!(
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={}",
                self.config.limits.tmpfs_bytes
            ),
            format!(
                "--env-file={}",
                utf8_path(environment_path, "environment file")?
            ),
            mount_argument(&self.workspace, CONTAINER_WORKSPACE, false)?,
        ]);
        arguments.push(match network {
            Some(network) => format!("--network={network}"),
            None => "--network=none".to_owned(),
        });
        for mount in &self.config.additional_mounts {
            arguments.push(mount_argument(
                &mount.source,
                &mount.destination,
                mount.read_only,
            )?);
        }
        if let Some(mount) = &self.config.broker_socket {
            arguments.push(mount_argument(
                &mount.source,
                &mount.destination,
                mount.read_only,
            )?);
        }
        if let Some(script_path) = script_path {
            arguments.push(mount_argument(script_path, CONTAINER_SCRIPT, true)?);
        }
        let workdir = request.working_directory.as_deref().map_or_else(
            || CONTAINER_WORKSPACE.to_owned(),
            |relative| format!("{CONTAINER_WORKSPACE}/{relative}"),
        );
        arguments.push(format!("--workdir={workdir}"));
        if let Some(entrypoint) = entrypoint {
            arguments.push(format!("--entrypoint={entrypoint}"));
        }
        arguments.push(image.reference.clone());
        if let Some(command_arguments) = command_arguments {
            arguments.extend(command_arguments.iter().cloned());
        }
        validate_argument_bounds(&arguments, self.config.limits)?;
        ensure_secure_runtime_arguments(&arguments, &image.reference, network, entrypoint)?;
        Ok(RuntimeInvocation {
            kind: RuntimeInvocationKind::Run,
            program: self.config.runtime_program.clone(),
            arguments,
            environment: self.config.runtime_environment.clone(),
        })
    }
}

impl<P, R> Executor for OciExecutor<P, R>
where
    P: ImageAdmissionProvider,
    R: RuntimeCommandRunner,
{
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        self.preflight_capsule(capsule).map_err(map_preflight_error)
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        self.execute_request(request).map_err(map_execution_error)
    }

    fn finish_job_attempt(
        &mut self,
        job: &PlannedJob,
        attempt: u32,
        _outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        if job.runner.isolation != Isolation::Oci {
            return Err(ExecutorError::UnsupportedIsolation(format!(
                "{:?}",
                job.runner.isolation
            )));
        }
        self.finish_job(&job.id, attempt)
            .map_err(map_execution_error)
    }
}

impl<P, R> Drop for OciExecutor<P, R>
where
    P: ImageAdmissionProvider,
    R: RuntimeCommandRunner,
{
    fn drop(&mut self) {
        let active = self.job_states.keys().cloned().collect::<Vec<_>>();
        for (job_id, attempt) in active {
            let _ = self.finish_job(&job_id, attempt);
        }
    }
}

fn network_permission_supported(permission: &NetworkPermission, has_broker: bool) -> bool {
    match permission {
        NetworkPermission::Deny => true,
        NetworkPermission::Allow {
            destinations,
            listen,
            ..
        } => {
            has_broker
                && listen.is_empty()
                && destinations
                    .iter()
                    .all(|destination| destination.protocol == NetworkProtocol::Tcp)
        }
    }
}

fn map_preflight_error(error: OciError) -> ExecutorError {
    match error {
        OciError::UnsupportedIsolation(mode) => ExecutorError::UnsupportedIsolation(mode),
        OciError::UnsupportedPlatform(requested) => ExecutorError::PlatformMismatch {
            requested,
            host: "rootless-linux-oci".to_owned(),
        },
        error => ExecutorError::UnsupportedCapsuleFeature(format!("OCI executor: {error}")),
    }
}

fn map_execution_error(error: OciError) -> ExecutorError {
    match error {
        OciError::UnsupportedIsolation(mode) => ExecutorError::UnsupportedIsolation(mode),
        OciError::UnsafeWorkingDirectory(path) => ExecutorError::UnsafeWorkingDirectory(path),
        OciError::InvalidEnvironmentName(name) => ExecutorError::InvalidEnvironmentName(name),
        OciError::InvalidEnvironmentValue(name) => ExecutorError::InvalidEnvironmentValue(name),
        OciError::InvalidCommand(message) => ExecutorError::InvalidCommand(message),
        error => ExecutorError::Spawn(format!("OCI executor: {error}")),
    }
}
use crate::{
    canonical_real_directory, canonical_regular_file, container_name, create_private_directory,
    ensure_descendant, ensure_mount_tree_is_safe, ensure_secure_runtime_arguments, fs, io,
    io_error, mount_argument, paths_overlap, prepare_private_state_root, record_first_error,
    scalar_text, short_identity, utf8_path, validate_argument_bounds, validate_broker_socket_mount,
    validate_command, validate_container_invocation, validate_environment, validate_healthcheck,
    validate_identifier, validate_locked_image, validate_mount, validate_runtime_result,
    validate_seccomp_profile, validate_service_dns_name, validate_working_directory, AdmittedImage,
    BTreeMap, BTreeSet, ContentDigest, Duration, EnvironmentScope, EphemeralFile, ExecutionCapsule,
    Executor, ExecutorError, ExecutorOutput, Healthcheck, ImageAdmissionProvider, Isolation,
    JobAttemptOutcome, LockedImage, Mutex, NetworkPermission, NetworkProtocol, OciError,
    OciExecutorConfig, OciPlatform, OperatingSystem, Path, PathBuf, PlannedJob, PlannedService,
    PreparedAction, RuntimeCommandRunner, RuntimeControl, RuntimeInvocation, RuntimeInvocationKind,
    Shell, StepAction, StepExecutionRequest, ValueBinding, CONTAINER_SCRIPT, CONTAINER_WORKSPACE,
    MAX_SECCOMP_PROFILE_BYTES,
};
