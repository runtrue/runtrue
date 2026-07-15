use super::*;

#[test]
fn remote_executor_never_falls_back_to_trusted_native() {
    let executor = RemoteJobExecutor::new(true, None);
    for isolation in [Isolation::Oci, Isolation::Wasm, Isolation::Microvm] {
        let mut execution_capsule = capsule();
        execution_capsule.jobs[0].runner.isolation = isolation;
        let capsule_digest = execution_capsule.digest().unwrap();
        let capsule_signature = CapsuleSigningKey::from_seed([93; 32])
            .sign_capsule(&execution_capsule)
            .unwrap();
        let lease = AdmittedLease {
            lease_id: format!("lease-{isolation:?}"),
            job_id: "build".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            issued_unix_ms: 1,
            accept_by_unix_ms: u64::MAX - 1,
            expires_unix_ms: u64::MAX,
            hard_deadline_unix_ms: u64::MAX,
            capsule_digest,
            signing_key_id: capsule_signature.key_id.clone(),
            capsule_signature,
            capsule: execution_capsule,
        };

        assert!(matches!(
            executor.preflight(&lease),
            Err(RunnerError::UnsupportedIsolation(mode))
                if mode == format!("{isolation:?}")
        ));
    }
}

#[test]
fn attempt_bound_retries_are_enabled_except_for_the_v1_microvm_guest() {
    let executor = RemoteJobExecutor::with_backends(true, None, None);
    for isolation in [
        Isolation::Native,
        Isolation::Oci,
        Isolation::Wasm,
        Isolation::Microvm,
    ] {
        let mut execution_capsule = capsule();
        execution_capsule.jobs[0].runner.isolation = isolation;
        execution_capsule.jobs[0].retries = 1;
        let capsule_signature = CapsuleSigningKey::from_seed([94; 32])
            .sign_capsule(&execution_capsule)
            .unwrap();
        let lease = AdmittedLease {
            lease_id: format!("lease-retry-{isolation:?}"),
            job_id: "build".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            issued_unix_ms: 1,
            accept_by_unix_ms: u64::MAX - 1,
            expires_unix_ms: u64::MAX,
            hard_deadline_unix_ms: u64::MAX,
            capsule_digest: execution_capsule.digest().unwrap(),
            signing_key_id: capsule_signature.key_id.clone(),
            capsule_signature,
            capsule: execution_capsule,
        };
        let result = executor.preflight(&lease);
        match isolation {
            Isolation::Native => assert!(result.is_ok()),
            Isolation::Microvm => assert!(matches!(
                reject_remote_retries(offered_job(&lease).expect("offered job")),
                Err(RunnerError::RemoteRetriesUnsupported)
            )),
            Isolation::Oci | Isolation::Wasm => assert!(!matches!(
                result,
                Err(RunnerError::RemoteRetriesUnsupported)
            )),
        }
    }
}

#[test]
fn native_backend_rejects_secret_and_oidc_grants_without_environment_fallback() {
    let executor = RemoteJobExecutor::new(true, None);
    let mut execution_capsule = capsule();
    execution_capsule.jobs[0].steps.push(PlannedStep {
        id: "publish".to_owned(),
        name: "Publish".to_owned(),
        condition: None,
        action: StepAction::Command {
            program: "/bin/true".to_owned(),
            args: Vec::new(),
        },
        inputs: BTreeMap::new(),
        environment: BTreeMap::new(),
        capabilities: StepCapabilitySet::default(),
        cache: None,
        timeout_ms: None,
        continue_on_error: false,
        outputs: BTreeMap::new(),
        working_directory: None,
    });
    execution_capsule.jobs[0].steps[0]
        .capabilities
        .secrets
        .push(SecretReference {
            metadata_id: "secret-1".to_owned(),
            name: "TOKEN".to_owned(),
            purpose: None,
        });
    execution_capsule.jobs[0].steps[0]
        .capabilities
        .oidc_audiences
        .push("https://registry.example".to_owned());
    let capsule_signature = CapsuleSigningKey::from_seed([95; 32])
        .sign_capsule(&execution_capsule)
        .unwrap();
    let lease = AdmittedLease {
        lease_id: "lease-native-broker".to_owned(),
        job_id: "build".to_owned(),
        fencing_generation: 1,
        installation_fencing_epoch: 1,
        issued_unix_ms: 1,
        accept_by_unix_ms: u64::MAX - 1,
        expires_unix_ms: u64::MAX,
        hard_deadline_unix_ms: u64::MAX,
        capsule_digest: execution_capsule.digest().unwrap(),
        signing_key_id: capsule_signature.key_id.clone(),
        capsule_signature,
        capsule: execution_capsule,
    };
    assert!(matches!(
        executor.preflight(&lease),
        Err(RunnerError::BrokerUnsupportedBackend(backend)) if backend == "native"
    ));
}

#[test]
fn native_backend_rejects_network_allow_before_workspace_creation() {
    let executor = RemoteJobExecutor::new(true, None);
    let mut execution_capsule = capsule();
    execution_capsule.jobs[0].permissions.network = runtrue_workflow_ir::NetworkPermission::Allow {
        dns: runtrue_workflow_ir::DnsPolicy::Restricted,
        deny_private_ranges: true,
        destinations: Vec::new(),
        listen: Vec::new(),
    };
    let capsule_signature = CapsuleSigningKey::from_seed([96; 32])
        .sign_capsule(&execution_capsule)
        .unwrap();
    let lease = AdmittedLease {
        lease_id: "lease-native-network".to_owned(),
        job_id: "build".to_owned(),
        fencing_generation: 1,
        installation_fencing_epoch: 1,
        issued_unix_ms: 1,
        accept_by_unix_ms: u64::MAX - 1,
        expires_unix_ms: u64::MAX,
        hard_deadline_unix_ms: u64::MAX,
        capsule_digest: execution_capsule.digest().unwrap(),
        signing_key_id: capsule_signature.key_id.clone(),
        capsule_signature,
        capsule: execution_capsule,
    };

    assert!(matches!(
        executor.preflight(&lease),
        Err(RunnerError::NetworkEnforcementUnavailable(backend)) if backend == "native"
    ));
}
