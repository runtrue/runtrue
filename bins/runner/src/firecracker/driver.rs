pub(super) trait MicrovmDriver: Send + Sync {
    fn preflight(&self) -> Result<(), RunnerError>;

    fn execute(
        &self,
        lease: &AdmittedLease,
        cancellation: &CancellationToken,
        observer: Option<&dyn StepStateObserver>,
    ) -> Result<OneJobReport, RunnerError>;

    fn cleanup_stale(&self) -> Result<(), RunnerError>;
}

#[derive(Clone)]
pub struct FirecrackerJobExecutor {
    pub(super) profile: Arc<RuntimeProfile>,
    pub(super) driver: Arc<dyn MicrovmDriver>,
    pub(super) image_set_digest: ContentDigest,
    pub(super) guest_image_digest: ContentDigest,
    pub(super) snapshot_enabled: bool,
    pub(super) image_expiry_unix_ms: Option<u64>,
    pub(super) state_root: PathBuf,
}

impl fmt::Debug for FirecrackerJobExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirecrackerJobExecutor")
            .field("architecture", &self.profile.architecture)
            .field("vcpu_count", &self.profile.vcpu_count)
            .field("memory_bytes", &self.profile.memory_bytes)
            .field("guest_cid", &self.profile.guest_cid)
            .field("image_set_digest", &self.image_set_digest)
            .field("snapshot_enabled", &self.snapshot_enabled)
            .field("state_root", &self.state_root)
            .finish_non_exhaustive()
    }
}

impl FirecrackerJobExecutor {
    pub fn load(paths: &FirecrackerRuntimePaths) -> Result<Self, RunnerError> {
        require_absolute(&paths.state_root, "Firecracker state root")?;
        require_absolute(&paths.runtime_profile, "Firecracker runtime profile")?;
        let state_root = prepare_private_directory(&paths.state_root)?;
        let quarantine_root = prepare_private_directory(&state_root.join("quarantine"))?;
        let jail_root = validate_private_directory(&paths.jail_root, "Firecracker jail root")?;
        let cid_lock_directory =
            validate_private_directory(&paths.cid_lock_directory, "Firecracker CID lock root")?;
        let payload_directory = validate_private_directory(
            &paths.image_payload_directory,
            "Firecracker image payload directory",
        )?;
        let manifest_directory = validate_private_directory(
            &paths.image_manifest_directory,
            "Firecracker image manifest directory",
        )?;
        let keyring_directory = validate_private_directory(
            &paths.image_keyring_directory,
            "Firecracker image keyring",
        )?;
        let profile_bytes = read_bounded_private_file(&paths.runtime_profile, MAX_PROFILE_BYTES)?;
        let profile: RuntimeProfile = strict_json(&profile_bytes).map_err(|error| {
            RunnerError::FirecrackerConfiguration(format!(
                "invalid Firecracker runtime profile: {error}"
            ))
        })?;
        profile.validate()?;
        validate_host_architecture(profile.architecture)?;

        let firecracker_paths = FirecrackerPaths {
            jailer: validate_runtime_binary(
                &paths.jailer,
                "jailer",
                profile.jailer_binary_size_bytes,
                &profile.jailer_binary_digest,
            )?,
            firecracker: validate_runtime_binary(
                &paths.firecracker,
                "firecracker",
                profile.firecracker_binary_size_bytes,
                &profile.firecracker_binary_digest,
            )?,
            reflink_copy: validate_executable(&paths.reflink_copy, "reflink copy")?,
            jail_root,
            cgroup_parent: paths.cgroup_parent.clone(),
        };
        let requirements = HostRequirements {
            paths: firecracker_paths,
            tap_device: None,
        };
        let image_set = load_image_set(&manifest_directory, &payload_directory)?;
        let image_expiry_unix_ms = image_expiry(&image_set);
        let trust = load_image_trust(&keyring_directory)?;
        let snapshot_runtime = image_set
            .snapshot
            .as_ref()
            .map(|_| profile.snapshot_runtime())
            .transpose()?;
        let verified_images = image_set.verify(
            &trust,
            profile.architecture,
            now_unix_ms()?,
            snapshot_runtime.as_ref(),
        )?;
        let snapshot_enabled = verified_images.snapshot().is_some();
        let guest_image_digest = verified_images.guest().digest().clone();
        let image_set_digest = image_set_digest(&verified_images)?;
        let state_manager = JobStateManager::for_jailer(&requirements.paths, &quarantine_root)?;
        let cid_lock = acquire_cid_lock(&cid_lock_directory, profile.guest_cid)?;
        let driver: Arc<dyn MicrovmDriver> = Arc::new(ProcessMicrovmDriver {
            requirements,
            profile: profile.clone(),
            verified_images,
            state_manager,
            quarantine_root,
            provisioner: ProcessReflinkProvisioner::new(&paths.reflink_copy),
            _cid_lock: cid_lock,
        });
        driver.cleanup_stale()?;
        driver.preflight()?;
        Ok(Self {
            profile: Arc::new(profile),
            driver,
            image_set_digest,
            guest_image_digest,
            snapshot_enabled,
            image_expiry_unix_ms,
            state_root,
        })
    }

    pub fn preflight_lease(&self, lease: &AdmittedLease) -> Result<(), RunnerError> {
        self.validate_assignment(lease)?;
        self.driver.preflight()
    }

    pub fn execute(
        &self,
        lease: &AdmittedLease,
        cancellation: CancellationToken,
        observer: Option<Arc<dyn StepStateObserver>>,
    ) -> Result<JobExecution, RunnerError> {
        self.validate_assignment(lease)?;
        self.driver.preflight()?;
        let report = match self
            .driver
            .execute(lease, &cancellation, observer.as_deref())
        {
            Ok(report) => report,
            Err(_) if cancellation.is_cancelled() => return canceled_job_execution(lease),
            Err(error) => return Err(error),
        };
        job_execution_from_report(lease, &self.image_set_digest, report)
    }

    pub fn cleanup_stale(&self) -> Result<(), RunnerError> {
        self.driver.cleanup_stale()
    }

    #[must_use]
    pub fn image_set_digest(&self) -> &ContentDigest {
        &self.image_set_digest
    }

    #[must_use]
    pub fn guest_image_digest(&self) -> &ContentDigest {
        &self.guest_image_digest
    }

    #[must_use]
    pub const fn snapshot_enabled(&self) -> bool {
        self.snapshot_enabled
    }

    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    #[must_use]
    pub fn firecracker_version(&self) -> &str {
        &self.profile.firecracker_version
    }

    #[must_use]
    pub fn vm_vcpu_count(&self) -> u16 {
        self.profile.vcpu_count
    }

    #[must_use]
    pub fn vm_memory_bytes(&self) -> u64 {
        self.profile.memory_bytes
    }

    #[must_use]
    pub fn guest_cid(&self) -> u32 {
        self.profile.guest_cid
    }

    fn validate_assignment(&self, lease: &AdmittedLease) -> Result<(), RunnerError> {
        let job = lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == lease.job_id)
            .ok_or_else(|| RunnerError::OfferedJobMissing(lease.job_id.clone()))?;
        crate::daemon::reject_remote_retries(job)?;
        if job.runner.isolation != Isolation::Microvm {
            return Err(RunnerError::UnsupportedIsolation(format!(
                "{:?}",
                job.runner.isolation
            )));
        }
        if job.runner.os != OperatingSystem::Linux
            || job.runner.arch != self.profile.architecture
            || job.runner.cpu != self.profile.vcpu_count
            || job.runner.memory_bytes != self.profile.memory_bytes
        {
            return Err(RunnerError::FirecrackerAssignment(
                "job platform or exact VM CPU/memory topology differs from the verified runtime"
                    .to_owned(),
            ));
        }
        if lease.capsule_signature.capsule_digest != lease.capsule_digest
            || lease.capsule_signature.key_id != lease.signing_key_id
        {
            return Err(RunnerError::FirecrackerAssignment(
                "admitted capsule signature envelope is inconsistent".to_owned(),
            ));
        }
        let now = now_unix_ms()?;
        if self
            .image_expiry_unix_ms
            .is_some_and(|expiry| now >= expiry)
        {
            return Err(RunnerError::FirecrackerImageExpired);
        }
        validate_guest_job(job)
    }
}

struct ProcessMicrovmDriver {
    requirements: HostRequirements,
    profile: RuntimeProfile,
    verified_images: runtrue_executor_firecracker::VerifiedImageSet,
    state_manager: JobStateManager,
    quarantine_root: PathBuf,
    provisioner: ProcessReflinkProvisioner,
    // Holding this descriptor keeps the host-wide CID reservation for the
    // entire advertised lifetime of the executor.
    _cid_lock: File,
}

impl MicrovmDriver for ProcessMicrovmDriver {
    fn preflight(&self) -> Result<(), RunnerError> {
        LinuxHostCapabilityProbe.preflight(&self.requirements)?;
        probe_cgroup_lifecycle(&self.requirements.paths, self.profile.guest_cid)?;
        validate_runtime_binary(
            &self.requirements.paths.firecracker,
            "firecracker",
            self.profile.firecracker_binary_size_bytes,
            &self.profile.firecracker_binary_digest,
        )?;
        validate_runtime_binary(
            &self.requirements.paths.jailer,
            "jailer",
            self.profile.jailer_binary_size_bytes,
            &self.profile.jailer_binary_digest,
        )?;
        let logical_cpus = u16::try_from(
            std::thread::available_parallelism()
                .map_err(|error| RunnerError::FirecrackerConfiguration(error.to_string()))?
                .get(),
        )
        .map_err(|_| {
            RunnerError::FirecrackerConfiguration("host CPU count overflows".to_owned())
        })?;
        if logical_cpus < self.profile.vcpu_count
            || host_memory_bytes()? < self.profile.memory_bytes
        {
            return Err(RunnerError::FirecrackerConfiguration(
                "host capacity is below the fixed VM topology".to_owned(),
            ));
        }
        let cpu_features = cpu_feature_digest()?;
        if cpu_features != self.profile.cpu_feature_digest {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "host CPU feature digest differs from the runtime profile (actual {cpu_features})"
            )));
        }
        let mitigations = mitigation_profile_digest()?;
        if mitigations != self.profile.mitigation_profile_digest {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "host mitigation digest differs from the runtime profile (actual {mitigations})"
            )));
        }
        probe_reflink(
            &self.provisioner,
            self.verified_images.rootfs().payload_path(),
            &self.requirements.paths,
        )
    }

    fn execute(
        &self,
        lease: &AdmittedLease,
        cancellation: &CancellationToken,
        observer: Option<&dyn StepStateObserver>,
    ) -> Result<OneJobReport, RunnerError> {
        let session_id = session_id(lease);
        let bootstrap = GuestBootstrap {
            protocol_version: GUEST_PROTOCOL_VERSION,
            session_id: session_id.clone(),
            lease_id: lease.lease_id.clone(),
            fencing_generation: lease.fencing_generation,
            installation_fencing_epoch: lease.installation_fencing_epoch,
            job_id: lease.job_id.clone(),
            capsule_digest: lease.capsule_digest.clone(),
            guest_image_digest: self.verified_images.guest().digest().clone(),
            expires_unix_ms: lease.hard_deadline_unix_ms,
        };
        let session = OneJobSession::new(
            bootstrap,
            &lease.capsule,
            lease.capsule_signature.clone(),
            &self.profile.guest_capsule_trust_directory,
            self.profile.guest_vsock_port,
        )?;
        let state = self.state_manager.stage(
            &lease.job_id,
            &session_id,
            &self.verified_images,
            session.boot_config(),
            &self.provisioner,
        )?;
        match self.run_staged(
            state.paths(),
            state.vm_id(),
            session,
            cancellation,
            observer,
        ) {
            Ok(report) => {
                state.cleanup_success()?;
                Ok(report)
            }
            Err(error) => {
                let quarantine = state.quarantine("guest-session-or-vm-boundary-failure");
                match quarantine {
                    Ok(_) => Err(error),
                    Err(cleanup) => Err(RunnerError::FirecrackerConfiguration(format!(
                        "{error}; quarantine also failed: {cleanup}"
                    ))),
                }
            }
        }
    }

    fn cleanup_stale(&self) -> Result<(), RunnerError> {
        recover_abandoned_jails(&self.requirements.paths, &self.quarantine_root)
    }
}

impl ProcessMicrovmDriver {
    fn run_staged(
        &self,
        paths: &runtrue_executor_firecracker::JobStatePaths,
        vm_id: &str,
        session: OneJobSession,
        cancellation: &CancellationToken,
        observer: Option<&dyn StepStateObserver>,
    ) -> Result<OneJobReport, RunnerError> {
        let launch = FirecrackerLaunchPlan::build(
            paths,
            self.profile.vcpu_count,
            self.profile.memory_bytes,
            self.profile.guest_cid,
            None,
        )?;
        if let Some(config) = launch.cold_config() {
            config.write_private(&paths.firecracker_config)?;
        }
        let invocation = VmInvocation::from(JailerInvocation::build_for_launch(
            &self.requirements,
            vm_id,
            self.profile.jailed_uid,
            self.profile.jailed_gid,
            &launch,
        )?);
        let mut vm = ProcessVmLauncher.launch(&invocation)?;
        let result = (|| {
            if launch.snapshot_request().is_some() {
                let api = UnixSnapshotApiClient::new(
                    &paths.api_socket,
                    SNAPSHOT_API_TIMEOUT,
                    SNAPSHOT_API_TIMEOUT,
                )?;
                launch.load_snapshot(&api)?;
            }
            let connector = FirecrackerVsockConnector::new(
                &paths.vsock_socket,
                self.profile.guest_vsock_port,
                VSOCK_CONNECT_TIMEOUT,
                VSOCK_IO_TIMEOUT,
            )?;
            let mut transport = connector.connect()?;
            session.run_with_observer(&mut *transport, cancellation, observer)
        })();
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                let process_cleanup = vm.terminate();
                let cgroup_cleanup = verify_cgroup_clean(&self.requirements.paths, vm_id);
                match (process_cleanup, cgroup_cleanup) {
                    (Ok(()), Ok(())) => {}
                    (Err(cleanup), Ok(())) => {
                        return Err(RunnerError::FirecrackerConfiguration(format!(
                            "{error}; VM termination also failed: {cleanup}"
                        )))
                    }
                    (Ok(()), Err(cleanup)) => {
                        return Err(RunnerError::FirecrackerConfiguration(format!(
                            "{error}; cgroup cleanup also failed: {cleanup}"
                        )))
                    }
                    (Err(process), Err(cgroup)) => {
                        return Err(RunnerError::FirecrackerConfiguration(format!(
                            "{error}; VM termination failed: {process}; cgroup cleanup failed: {cgroup}"
                        )))
                    }
                }
                return Err(error.into());
            }
        };
        let exit = vm.wait(&VmControl {
            timeout: VM_SHUTDOWN_TIMEOUT,
            cancellation: cancellation.clone(),
        });
        let cgroup_cleanup = verify_cgroup_clean(&self.requirements.paths, vm_id);
        let exit = match (exit, cgroup_cleanup) {
            (Ok(exit), Ok(())) => exit,
            (Err(error), Ok(())) => return Err(error.into()),
            (Ok(_), Err(error)) => return Err(error),
            (Err(error), Err(cleanup)) => {
                return Err(RunnerError::FirecrackerConfiguration(format!(
                    "{error}; cgroup cleanup also failed: {cleanup}"
                )))
            }
        };
        if exit.exit_code != Some(0) || exit.timed_out || exit.canceled || !exit.process_group_clean
        {
            return Err(RunnerError::FirecrackerConfiguration(format!(
                "Firecracker jailer exit was not clean: {exit:?}"
            )));
        }
        Ok(report)
    }
}
use super::{
    acquire_cid_lock, canceled_job_execution, cpu_feature_digest, fmt, host_memory_bytes,
    image_expiry, image_set_digest, job_execution_from_report, load_image_set, load_image_trust,
    mitigation_profile_digest, now_unix_ms, prepare_private_directory, probe_cgroup_lifecycle,
    probe_reflink, read_bounded_private_file, recover_abandoned_jails, require_absolute,
    session_id, strict_json, validate_executable, validate_guest_job, validate_host_architecture,
    validate_private_directory, validate_runtime_binary, verify_cgroup_clean, AdmittedLease, Arc,
    CancellationToken, ContentDigest, File, FirecrackerLaunchPlan, FirecrackerPaths,
    FirecrackerRuntimePaths, FirecrackerVsockConnector, GuestBootstrap, GuestConnector,
    HostCapabilityProbe, HostRequirements, Isolation, JailerInvocation, JobExecution,
    JobStateManager, LinuxHostCapabilityProbe, OneJobReport, OneJobSession, OperatingSystem, Path,
    PathBuf, ProcessReflinkProvisioner, ProcessVmLauncher, RunnerError, RuntimeProfile,
    StepStateObserver, UnixSnapshotApiClient, VmControl, VmInvocation, VmLauncher,
    GUEST_PROTOCOL_VERSION, MAX_PROFILE_BYTES, SNAPSHOT_API_TIMEOUT, VM_SHUTDOWN_TIMEOUT,
    VSOCK_CONNECT_TIMEOUT, VSOCK_IO_TIMEOUT,
};
