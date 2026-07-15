use super::*;
use runtrue_attest::{CapsuleSigningKey, ImageManifest, ImageSigningKey};
use runtrue_executor_oci::{
    RuntimeControl, RuntimeInvocation, RuntimeInvocationKind, RuntimeResult,
};
use runtrue_workflow_ir::{
    ApprovalRequirements, CapsuleContext, ExecutionCapsule, ParityGrade, PermissionSet, PlannedJob,
    PlannedService, PlannedStep, RunnerRequirements, ScalarValue, SourceTrust, StepAction,
    StepCapabilitySet, Trust, ValueBinding, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
    ENGINE_COMPATIBILITY_VERSION,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;

const JOB_REFERENCE: &str = "registry.example/runtrue/job@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SERVICE_REFERENCE: &str = "registry.example/runtrue/db@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Default)]
struct RecordingFactory {
    invocations: Arc<Mutex<Vec<RuntimeInvocationKind>>>,
    recovery_leak: bool,
    missing_image: bool,
}

impl OciRuntimeFactory for RecordingFactory {
    fn create(&self) -> Result<Box<dyn RuntimeCommandRunner>, RunnerError> {
        Ok(Box::new(RecordingRuntime {
            invocations: Arc::clone(&self.invocations),
            recovery_leak: self.recovery_leak,
            missing_image: self.missing_image,
        }))
    }
}

struct RecordingRuntime {
    invocations: Arc<Mutex<Vec<RuntimeInvocationKind>>>,
    recovery_leak: bool,
    missing_image: bool,
}

impl RuntimeCommandRunner for RecordingRuntime {
    fn invoke(
        &mut self,
        invocation: &RuntimeInvocation,
        control: &RuntimeControl,
    ) -> Result<RuntimeResult, runtrue_executor_oci::OciError> {
        self.invocations.lock().unwrap().push(invocation.kind());
        let mut result = RuntimeResult::success();
        if matches!(
            invocation.kind(),
            RuntimeInvocationKind::Exists | RuntimeInvocationKind::NetworkExists
        ) {
            result.exit_code = Some(1);
        }
        if self.recovery_leak && invocation.kind() == RuntimeInvocationKind::RecoveryListContainers
        {
            result.stdout = b"still-running\n".to_vec();
        }
        if self.missing_image && invocation.kind() == RuntimeInvocationKind::ImageExists {
            result.exit_code = Some(1);
        }
        if control.cancellation.is_cancelled() {
            result.exit_code = None;
            result.canceled = true;
        }
        Ok(result)
    }
}

struct Fixture {
    _directory: TempDir,
    paths: OciRuntimePaths,
    key: ImageSigningKey,
    capsule: ExecutionCapsule,
}

impl Fixture {
    fn new(with_service: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state_root = directory.path().join("state");
        let image_store = directory.path().join("images");
        let manifest_directory = directory.path().join("manifests");
        let keyring_directory = directory.path().join("keys");
        for path in [
            &state_root,
            &image_store,
            &manifest_directory,
            &keyring_directory,
        ] {
            fs::create_dir(path).unwrap();
            private_directory(path);
        }
        let podman = directory.path().join("podman");
        fs::write(&podman, b"#!/bin/sh\nexit 1\n").unwrap();
        executable_file(&podman);
        let seccomp_profile = directory.path().join("seccomp.json");
        private_file(&seccomp_profile, br#"{"defaultAction":"SCMP_ACT_ERRNO"}"#);
        let runtime_environment = directory.path().join("runtime-env.json");
        private_file(&runtime_environment, b"{}");
        let key = ImageSigningKey::from_seed([41; 32]);
        private_file(
            &keyring_directory.join("release.pub"),
            &key.verifying_key().to_bytes(),
        );
        let capsule = execution_capsule(with_service);
        Self {
            _directory: directory,
            paths: OciRuntimePaths {
                state_root,
                podman,
                seccomp_profile,
                image_store,
                runtime_environment,
                manifest_directory,
                keyring_directory,
            },
            key,
            capsule,
        }
    }

    fn write_job_manifest(&self) {
        self.write_manifest("job.json", None, JOB_REFERENCE);
    }

    fn write_service_manifest(&self) {
        self.write_manifest("service.json", Some("db"), SERVICE_REFERENCE);
    }

    fn write_reusable_job_manifest(&self) {
        let digest = LockedImage::new(
            JOB_REFERENCE,
            "release@runtrue.example",
            OciPlatform::linux_amd64(),
        )
        .unwrap()
        .digest()
        .clone();
        let signed = self
            .key
            .sign_manifest(&ImageManifest {
                manifest_version: 1,
                kind: ImageKind::OciImage,
                name: "reusable-job".to_owned(),
                payload_digest: digest,
                payload_size_bytes: 1,
                payload_media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                builder_id: "test-builder".to_owned(),
                build_provenance_digest: ContentDigest::sha256(b"provenance"),
                sbom_digest: ContentDigest::sha256(b"sbom"),
                created_unix_ms: 1,
                expires_unix_ms: None,
                snapshot_phase: None,
                components: BTreeMap::new(),
                compatibility: BTreeMap::from([
                    (
                        COMPAT_ASSIGNMENT_SCOPE.to_owned(),
                        REUSABLE_IMAGE_SCOPE.to_owned(),
                    ),
                    (COMPAT_OCI_REFERENCE.to_owned(), JOB_REFERENCE.to_owned()),
                    (
                        COMPAT_SIGNATURE_IDENTITY.to_owned(),
                        "release@runtrue.example".to_owned(),
                    ),
                ]),
            })
            .unwrap();
        private_file(
            &self.paths.manifest_directory.join("reusable-job.json"),
            &serde_json::to_vec(&signed).unwrap(),
        );
    }

    fn write_manifest(&self, name: &str, service: Option<&str>, reference: &str) {
        let capsule_digest = self.capsule.digest().unwrap();
        let digest = LockedImage::new(
            reference,
            "release@runtrue.example",
            OciPlatform::linux_amd64(),
        )
        .unwrap()
        .digest()
        .clone();
        let signed = self
            .key
            .sign_manifest(&ImageManifest {
                manifest_version: 1,
                kind: ImageKind::OciImage,
                name: name.to_owned(),
                payload_digest: digest,
                payload_size_bytes: 1,
                payload_media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                builder_id: "test-builder".to_owned(),
                build_provenance_digest: ContentDigest::sha256(b"provenance"),
                sbom_digest: ContentDigest::sha256(b"sbom"),
                created_unix_ms: 1,
                expires_unix_ms: None,
                snapshot_phase: None,
                components: BTreeMap::new(),
                compatibility: BTreeMap::from([
                    (COMPAT_CAPSULE_DIGEST.to_owned(), capsule_digest.to_string()),
                    (COMPAT_JOB_ID.to_owned(), "job".to_owned()),
                    (
                        COMPAT_SERVICE_ID.to_owned(),
                        service.unwrap_or(JOB_ROLE).to_owned(),
                    ),
                    (COMPAT_OCI_REFERENCE.to_owned(), reference.to_owned()),
                    (
                        COMPAT_SIGNATURE_IDENTITY.to_owned(),
                        "release@runtrue.example".to_owned(),
                    ),
                ]),
            })
            .unwrap();
        private_file(
            &self.paths.manifest_directory.join(name),
            &serde_json::to_vec(&signed).unwrap(),
        );
    }

    fn lease(&self) -> AdmittedLease {
        let capsule_digest = self.capsule.digest().unwrap();
        let capsule_signature = CapsuleSigningKey::from_seed([92; 32])
            .sign_capsule(&self.capsule)
            .unwrap();
        AdmittedLease {
            lease_id: "lease-1".to_owned(),
            job_id: "job".to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            issued_unix_ms: 1,
            accept_by_unix_ms: u64::MAX - 1,
            expires_unix_ms: u64::MAX,
            hard_deadline_unix_ms: u64::MAX,
            capsule_digest,
            signing_key_id: capsule_signature.key_id.clone(),
            capsule_signature,
            capsule: self.capsule.clone(),
        }
    }

    fn load(&self, factory: RecordingFactory) -> Result<OciJobExecutor, RunnerError> {
        OciJobExecutor::load_with_factory(&self.paths, Arc::new(factory))
    }
}

fn execution_capsule(with_service: bool) -> ExecutionCapsule {
    let services = with_service
        .then(|| PlannedService {
            id: "db".to_owned(),
            image: SERVICE_REFERENCE.to_owned(),
            ports: vec![5432],
            environment: BTreeMap::from([(
                "PASSWORD".to_owned(),
                ValueBinding::Literal(ScalarValue::String("test".to_owned())),
            )]),
            healthcheck: None,
        })
        .into_iter()
        .collect();
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "test".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/test.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "a".repeat(40),
            source_tree_digest: None,
            base_commit: None,
            source_trust: SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: Some(ContentDigest::sha256(b"lock")),
            workflow_frontend: None,
            policy_version_ids: vec!["policy".to_owned()],
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
                arch: Architecture::Amd64,
                isolation: Isolation::Oci,
                image: Some(JOB_REFERENCE.to_owned()),
                cpu: 1,
                memory_bytes: 128 * 1024 * 1024,
                storage_bytes: None,
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services,
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
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::AExact,
    }
}

fn private_directory(path: &Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn executable_file(path: &Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
mod admission;
mod execution;
mod validation;
