use super::driver::MicrovmDriver;
use super::*;
use runtrue_attest::CapsuleSigningKey;
use runtrue_workflow_ir::{
    ApprovalRequirements, CapsuleContext, ExecutionCapsule, ParityGrade, PlannedJob, PlannedStep,
    RunnerRequirements, SourceTrust, Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
    ENGINE_COMPATIBILITY_VERSION,
};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct FakeDriver {
    preflights: AtomicUsize,
    executions: AtomicUsize,
    fail: bool,
}

impl MicrovmDriver for FakeDriver {
    fn preflight(&self) -> Result<(), RunnerError> {
        self.preflights.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn execute(
        &self,
        lease: &AdmittedLease,
        _cancellation: &CancellationToken,
        _observer: Option<&dyn StepStateObserver>,
    ) -> Result<OneJobReport, RunnerError> {
        self.executions.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            return Err(RunnerError::FirecrackerConfiguration(
                "fake VM failure".to_owned(),
            ));
        }
        let mut report = OneJobReport::default();
        report.succeeded = true;
        report.step_results.push(GuestStepResult {
            step_id: lease.capsule.jobs[0].steps[0].id.clone(),
            attempt: 1,
            exit_code: Some(0),
            timed_out: false,
            canceled: false,
            skipped: false,
        });
        Ok(report)
    }

    fn cleanup_stale(&self) -> Result<(), RunnerError> {
        Ok(())
    }
}

fn profile() -> RuntimeProfile {
    RuntimeProfile {
        profile_version: 1,
        architecture: host_architecture(),
        firecracker_version: "1.12.0".to_owned(),
        firecracker_binary_digest: ContentDigest::sha256(b"firecracker"),
        firecracker_binary_size_bytes: 11,
        jailer_version: "1.12.0".to_owned(),
        jailer_binary_digest: ContentDigest::sha256(b"jailer"),
        jailer_binary_size_bytes: 6,
        snapshot_format_version: "1.8.0".to_owned(),
        cpu_template: "T2".to_owned(),
        cpu_feature_digest: ContentDigest::sha256(b"features"),
        mitigation_profile_digest: ContentDigest::sha256(b"mitigations"),
        vcpu_count: 2,
        memory_bytes: 256 * 1024 * 1024,
        guest_cid: 42,
        jailed_uid: 1000,
        jailed_gid: 1000,
        guest_vsock_port: 5000,
        guest_capsule_trust_directory: PathBuf::from("/etc/runtrue/capsule-keys"),
    }
}

fn host_architecture() -> Architecture {
    match std::env::consts::ARCH {
        "aarch64" => Architecture::Arm64,
        _ => Architecture::Amd64,
    }
}

fn capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "microvm".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/microvm.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "abc".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: None,
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: vec![PlannedJob {
            id: "job".to_owned(),
            base_id: "job".to_owned(),
            name: "job".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::TrustedOnly,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: host_architecture(),
                isolation: Isolation::Microvm,
                image: None,
                cpu: 2,
                memory_bytes: 256 * 1024 * 1024,
                storage_bytes: None,
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: vec![PlannedStep {
                id: "step".to_owned(),
                name: "step".to_owned(),
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
            }],
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: true,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::BEnvironmentEquivalent,
    }
}

fn lease(capsule: ExecutionCapsule) -> AdmittedLease {
    let capsule_signature = CapsuleSigningKey::from_seed([77; 32])
        .sign_capsule(&capsule)
        .unwrap();
    AdmittedLease {
        lease_id: "lease".to_owned(),
        job_id: "job".to_owned(),
        fencing_generation: 1,
        installation_fencing_epoch: 1,
        issued_unix_ms: 1,
        accept_by_unix_ms: u64::MAX - 1,
        expires_unix_ms: u64::MAX,
        hard_deadline_unix_ms: u64::MAX,
        capsule_digest: capsule_signature.capsule_digest.clone(),
        signing_key_id: capsule_signature.key_id.clone(),
        capsule_signature,
        capsule,
    }
}

fn executor(driver: Arc<FakeDriver>) -> FirecrackerJobExecutor {
    FirecrackerJobExecutor {
        profile: Arc::new(profile()),
        driver,
        image_set_digest: ContentDigest::sha256(b"images"),
        guest_image_digest: ContentDigest::sha256(b"guest"),
        snapshot_enabled: true,
        image_expiry_unix_ms: None,
        state_root: PathBuf::from("/state"),
    }
}

mod execution;
mod reporting;
mod validation;
