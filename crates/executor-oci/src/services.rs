impl<P, R> OciExecutor<P, R>
where
    P: ImageAdmissionProvider,
    R: RuntimeCommandRunner,
{
    pub(crate) fn start_job_services(
        &mut self,
        request: &StepExecutionRequest,
        state_path: &Path,
    ) -> Result<bool, OciError> {
        let key = (request.job_id.clone(), request.job_attempt);
        if self
            .job_states
            .get(&key)
            .is_some_and(|state| state.services_started)
        {
            return Ok(false);
        }
        let services = {
            let planned = self
                .planned_services
                .lock()
                .map_err(|_| OciError::Internal("planned service state is poisoned".to_owned()))?;
            match planned.get(&request.job_id) {
                Some(services) => services.clone(),
                None if self
                    .config
                    .service_images
                    .keys()
                    .any(|(job_id, _)| job_id == &request.job_id) =>
                {
                    return Err(OciError::InvalidState(format!(
                        "service lifecycle for job `{}` was not successfully preflighted",
                        request.job_id
                    )));
                }
                None => Vec::new(),
            }
        };
        if services.is_empty() {
            self.job_states
                .get_mut(&key)
                .expect("job state was inserted")
                .services_started = true;
            return Ok(false);
        }
        let deadline = Instant::now()
            .checked_add(self.config.limits.max_service_startup_timeout)
            .ok_or_else(|| {
                OciError::InvalidConfiguration("service startup deadline overflow".to_owned())
            })?;
        let network = network_name(request);
        self.job_states
            .get_mut(&key)
            .expect("job state was inserted")
            .network = Some(network.clone());
        let network_invocation = self.network_create_invocation(state_path, &network)?;
        let network_result = self.runtime.invoke(
            &network_invocation,
            &startup_control(request, deadline, self.config.limits.max_output_bytes)?,
        )?;
        if setup_was_canceled(&network_result, &request.cancellation) {
            self.finish_job(&request.job_id, request.job_attempt)?;
            return Ok(true);
        }
        validate_setup_result(
            &network_result,
            "create private service network",
            self.config.limits.max_output_bytes,
        )?;

        for service in &services {
            if request.cancellation.is_cancelled() {
                self.finish_job(&request.job_id, request.job_attempt)?;
                return Ok(true);
            }
            let container = service_container_name(request, &service.id);
            self.job_states
                .get_mut(&key)
                .expect("job state was inserted")
                .containers
                .insert(container.clone());
            let environment_path = state_path.join(format!(
                "service-env-{}",
                short_identity(&format!("{}\0{}", request.job_id, service.id))
            ));
            let environment_file = EphemeralFile::write_environment(
                &environment_path,
                &service.environment,
                self.config.limits,
            )?;
            let invocation = self.service_start_invocation(
                request,
                state_path,
                &network,
                &container,
                service,
                environment_file.path(),
            )?;
            let result = self.runtime.invoke(
                &invocation,
                &startup_control(request, deadline, self.config.limits.max_output_bytes)?,
            );
            drop(environment_file);
            let result = result?;
            if setup_was_canceled(&result, &request.cancellation) {
                self.finish_job(&request.job_id, request.job_attempt)?;
                return Ok(true);
            }
            validate_setup_result(
                &result,
                &format!("start service `{}`", service.id),
                self.config.limits.max_output_bytes,
            )?;
            if let Some(healthcheck) = &service.healthcheck {
                if self.wait_for_service_health(
                    request,
                    state_path,
                    &container,
                    service,
                    healthcheck,
                    deadline,
                )? {
                    self.finish_job(&request.job_id, request.job_attempt)?;
                    return Ok(true);
                }
            }
        }
        self.job_states
            .get_mut(&key)
            .expect("job state was inserted")
            .services_started = true;
        Ok(false)
    }

    fn network_create_invocation(
        &self,
        state_path: &Path,
        network: &str,
    ) -> Result<RuntimeInvocation, OciError> {
        validate_runtime_identifier("network", network)?;
        let mut arguments = self.runtime_prefix(state_path)?;
        arguments.extend([
            "network".to_owned(),
            "create".to_owned(),
            "--driver=bridge".to_owned(),
            "--internal".to_owned(),
            network.to_owned(),
        ]);
        ensure_secure_network_create_arguments(&arguments, network)?;
        Ok(RuntimeInvocation {
            kind: RuntimeInvocationKind::NetworkCreate,
            program: self.config.runtime_program.clone(),
            arguments,
            environment: self.config.runtime_environment.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn service_start_invocation(
        &self,
        request: &StepExecutionRequest,
        state_path: &Path,
        network: &str,
        container: &str,
        service: &PreparedService,
        environment_path: &Path,
    ) -> Result<RuntimeInvocation, OciError> {
        validate_runtime_identifier("network", network)?;
        validate_runtime_identifier("service container", container)?;
        let mut arguments = self.runtime_prefix(state_path)?;
        arguments.push("run".to_owned());
        arguments.extend([
            "--detach".to_owned(),
            "--name".to_owned(),
            container.to_owned(),
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
            format!("--network={network}"),
            format!("--network-alias={}", service.id),
            "--pid=private".to_owned(),
            "--ipc=private".to_owned(),
            "--ulimit=core=0:0".to_owned(),
            format!("--pids-limit={}", self.config.limits.max_pids),
            format!("--memory={}", request.runner.memory_bytes),
            format!("--cpus={}", request.runner.cpu),
            format!("--platform={}", service.image.platform.as_oci()),
            format!(
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={}",
                self.config.limits.tmpfs_bytes
            ),
            format!(
                "--env-file={}",
                utf8_path(environment_path, "service environment file")?
            ),
        ]);
        arguments.extend(
            service
                .ports
                .iter()
                .map(|port| format!("--expose={port}/tcp")),
        );
        arguments.push(service.image.reference.clone());
        validate_argument_bounds(&arguments, self.config.limits)?;
        ensure_secure_service_arguments(
            &arguments,
            &service.image.reference,
            network,
            &service.id,
        )?;
        Ok(RuntimeInvocation {
            kind: RuntimeInvocationKind::ServiceStart,
            program: self.config.runtime_program.clone(),
            arguments,
            environment: self.config.runtime_environment.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn wait_for_service_health(
        &mut self,
        request: &StepExecutionRequest,
        state_path: &Path,
        container: &str,
        service: &PreparedService,
        healthcheck: &Healthcheck,
        deadline: Instant,
    ) -> Result<bool, OciError> {
        for attempt in 0..healthcheck.retries {
            if request.cancellation.is_cancelled() {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(OciError::ServiceUnhealthy {
                    service_id: service.id.clone(),
                    attempts: attempt,
                });
            }
            let mut arguments = self.runtime_prefix(state_path)?;
            arguments.extend(["exec".to_owned(), "--".to_owned(), container.to_owned()]);
            arguments.extend(healthcheck.command.iter().cloned());
            validate_argument_bounds(&arguments, self.config.limits)?;
            let invocation = RuntimeInvocation {
                kind: RuntimeInvocationKind::HealthCheck,
                program: self.config.runtime_program.clone(),
                arguments,
                environment: self.config.runtime_environment.clone(),
            };
            let result = self.runtime.invoke(
                &invocation,
                &RuntimeControl {
                    timeout: Duration::from_millis(healthcheck.timeout_ms).min(remaining),
                    cancellation: request.cancellation.clone(),
                    max_output_bytes: 64 * 1024,
                },
            )?;
            validate_runtime_result(&result, 64 * 1024)?;
            if !result.process_group_clean {
                return Err(OciError::ProcessGroupLeak);
            }
            if setup_was_canceled(&result, &request.cancellation) {
                return Ok(true);
            }
            if result.exit_code == Some(0) && !result.timed_out {
                return Ok(false);
            }
            if attempt + 1 < healthcheck.retries
                && wait_cancellable(
                    Duration::from_millis(healthcheck.interval_ms),
                    deadline,
                    &request.cancellation,
                )
            {
                return Ok(true);
            }
        }
        Err(OciError::ServiceUnhealthy {
            service_id: service.id.clone(),
            attempts: healthcheck.retries,
        })
    }

    pub(crate) fn cleanup_container(
        &mut self,
        state_path: &Path,
        container_name: &str,
    ) -> Result<(), OciError> {
        let control = RuntimeControl {
            timeout: self.config.cleanup_timeout,
            cancellation: CancellationToken::default(),
            max_output_bytes: 64 * 1024,
        };
        let mut remove_arguments = self.runtime_prefix(state_path)?;
        remove_arguments.extend([
            "rm".to_owned(),
            "--force".to_owned(),
            "--ignore".to_owned(),
            "--volumes".to_owned(),
            container_name.to_owned(),
        ]);
        let remove = self.runtime.invoke(
            &RuntimeInvocation {
                kind: RuntimeInvocationKind::Remove,
                program: self.config.runtime_program.clone(),
                arguments: remove_arguments,
                environment: self.config.runtime_environment.clone(),
            },
            &control,
        )?;
        validate_cleanup_result(&remove, Some(0))?;

        let mut exists_arguments = self.runtime_prefix(state_path)?;
        exists_arguments.extend([
            "container".to_owned(),
            "exists".to_owned(),
            container_name.to_owned(),
        ]);
        let exists = self.runtime.invoke(
            &RuntimeInvocation {
                kind: RuntimeInvocationKind::Exists,
                program: self.config.runtime_program.clone(),
                arguments: exists_arguments,
                environment: self.config.runtime_environment.clone(),
            },
            &control,
        )?;
        validate_cleanup_result(&exists, Some(1))
    }

    pub(crate) fn cleanup_network(
        &mut self,
        state_path: &Path,
        network: &str,
    ) -> Result<(), OciError> {
        validate_runtime_identifier("network", network)?;
        let control = RuntimeControl {
            timeout: self.config.cleanup_timeout,
            cancellation: CancellationToken::default(),
            max_output_bytes: 64 * 1024,
        };
        let mut remove_arguments = self.runtime_prefix(state_path)?;
        remove_arguments.extend([
            "network".to_owned(),
            "rm".to_owned(),
            "--force".to_owned(),
            network.to_owned(),
        ]);
        let remove = self.runtime.invoke(
            &RuntimeInvocation {
                kind: RuntimeInvocationKind::NetworkRemove,
                program: self.config.runtime_program.clone(),
                arguments: remove_arguments,
                environment: self.config.runtime_environment.clone(),
            },
            &control,
        )?;
        validate_cleanup_result(&remove, Some(0))?;

        let mut exists_arguments = self.runtime_prefix(state_path)?;
        exists_arguments.extend([
            "network".to_owned(),
            "exists".to_owned(),
            network.to_owned(),
        ]);
        let exists = self.runtime.invoke(
            &RuntimeInvocation {
                kind: RuntimeInvocationKind::NetworkExists,
                program: self.config.runtime_program.clone(),
                arguments: exists_arguments,
                environment: self.config.runtime_environment.clone(),
            },
            &control,
        )?;
        validate_cleanup_result(&exists, Some(1))
    }

    pub(crate) fn runtime_prefix(&self, state_path: &Path) -> Result<Vec<String>, OciError> {
        let (root, runroot) = self.config.image_store.as_ref().map_or_else(
            || (state_path.join("storage"), state_path.join("run")),
            |store| (store.clone(), store.join(".runtrue-runroot")),
        );
        let prefix = vec![
            format!("--root={}", utf8_path(&root, "runtime storage")?),
            format!("--runroot={}", utf8_path(&runroot, "runtime runroot")?),
            format!(
                "--tmpdir={}",
                utf8_path(&state_path.join("tmp"), "runtime tmpdir")?
            ),
        ];
        Ok(prefix)
    }
}
use crate::{
    ensure_secure_network_create_arguments, ensure_secure_service_arguments, network_name,
    service_container_name, setup_was_canceled, short_identity, startup_control, utf8_path,
    validate_argument_bounds, validate_cleanup_result, validate_runtime_identifier,
    validate_runtime_result, validate_setup_result, wait_cancellable, CancellationToken, Duration,
    EphemeralFile, Healthcheck, ImageAdmissionProvider, Instant, OciError, OciExecutor, Path,
    PreparedService, RuntimeCommandRunner, RuntimeControl, RuntimeInvocation,
    RuntimeInvocationKind, StepExecutionRequest,
};
