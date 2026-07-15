use crate::*;

use runtrue_engine::Engine;
use runtrue_workflow_ir::{
    ApprovalRequirements, CapsuleContext, ParityGrade, PermissionSet, PlannedJob, PlannedStep,
    RunnerRequirements, StepAction, StepCapabilitySet, Trust, WorkflowIdentity,
    CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::{
    collections::VecDeque,
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tempfile::TempDir;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const IMAGE: &str = "registry.example/runtrue/build@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SERVICE_IMAGE: &str = "registry.example/runtrue/postgres@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Copy)]
enum AdmissionMode {
    Exact,
    WrongSigner,
    Unverified,
    Denied,
}

struct FakeAdmission {
    mode: AdmissionMode,
    calls: Arc<AtomicUsize>,
}

impl FakeAdmission {
    fn exact() -> Self {
        Self {
            mode: AdmissionMode::Exact,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ImageAdmissionProvider for FakeAdmission {
    fn admit(&self, image: &LockedImage) -> Result<AdmittedImage, ImageAdmissionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            AdmissionMode::Exact => AdmittedImage::verified(
                image.reference.clone(),
                image.signature_identity.clone(),
                image.platform,
            )
            .map_err(|error| ImageAdmissionError::Denied(error.to_string())),
            AdmissionMode::WrongSigner => AdmittedImage::verified(
                image.reference.clone(),
                "other@runtrue.example",
                image.platform,
            )
            .map_err(|error| ImageAdmissionError::Denied(error.to_string())),
            AdmissionMode::Unverified => Ok(AdmittedImage::unverified(image)),
            AdmissionMode::Denied => Err(ImageAdmissionError::Denied("policy".to_owned())),
        }
    }
}

#[derive(Default)]
struct RecordingRuntime {
    invocations: Vec<RuntimeInvocation>,
    controls: Vec<(Duration, usize, bool)>,
    scripted: VecDeque<Result<RuntimeResult, OciError>>,
    job_results: VecDeque<RuntimeResult>,
    environment_files: Vec<Vec<u8>>,
    service_environment_files: Vec<Vec<u8>>,
    script_files: Vec<Vec<u8>>,
}

impl RecordingRuntime {
    fn push(&mut self, result: RuntimeResult) {
        self.scripted.push_back(Ok(result));
    }

    fn push_job_result(&mut self, result: RuntimeResult) {
        self.job_results.push_back(result);
    }

    fn default_result(kind: RuntimeInvocationKind) -> RuntimeResult {
        let mut result = RuntimeResult::success();
        if matches!(
            kind,
            RuntimeInvocationKind::Exists | RuntimeInvocationKind::NetworkExists
        ) {
            result.exit_code = Some(1);
        }
        result
    }
}

impl RuntimeCommandRunner for RecordingRuntime {
    fn invoke(
        &mut self,
        invocation: &RuntimeInvocation,
        control: &RuntimeControl,
    ) -> Result<RuntimeResult, OciError> {
        self.invocations.push(invocation.clone());
        self.controls.push((
            control.timeout,
            control.max_output_bytes,
            control.cancellation.is_cancelled(),
        ));
        if matches!(
            invocation.kind,
            RuntimeInvocationKind::Run | RuntimeInvocationKind::ServiceStart
        ) {
            if let Some(path) = invocation
                .arguments
                .iter()
                .find_map(|argument| argument.strip_prefix("--env-file="))
            {
                if invocation.kind == RuntimeInvocationKind::ServiceStart {
                    self.service_environment_files.push(fs::read(path).unwrap());
                } else {
                    self.environment_files.push(fs::read(path).unwrap());
                }
            }
            if let Some(source) = invocation.arguments.iter().find_map(|argument| {
                if argument.starts_with("--mount=")
                    && argument.contains(&format!("dst={CONTAINER_SCRIPT}"))
                {
                    argument
                        .split(',')
                        .find_map(|field| field.strip_prefix("src="))
                } else {
                    None
                }
            }) {
                self.script_files.push(fs::read(source).unwrap());
            }
        }
        if invocation.kind == RuntimeInvocationKind::Run {
            if let Some(result) = self.job_results.pop_front() {
                return Ok(result);
            }
        }
        self.scripted
            .pop_front()
            .unwrap_or_else(|| Ok(Self::default_result(invocation.kind)))
    }
}

type TestExecutor = OciExecutor<FakeAdmission, RecordingRuntime>;

struct Fixture {
    _directory: TempDir,
    executor: TestExecutor,
}

fn locked_image() -> LockedImage {
    LockedImage::new(IMAGE, "release@runtrue.example", OciPlatform::linux_amd64()).unwrap()
}

fn locked_service_image() -> LockedImage {
    LockedImage::new(
        SERVICE_IMAGE,
        "release@runtrue.example",
        OciPlatform::linux_amd64(),
    )
    .unwrap()
}

fn fixture_with(mode: AdmissionMode) -> Fixture {
    fixture_with_config(mode, false)
}

fn fixture_with_config(mode: AdmissionMode, services: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let state = directory.path().join("state");
    let seccomp = directory.path().join("seccomp.json");
    fs::create_dir(&workspace).unwrap();
    fs::write(&seccomp, br#"{"defaultAction":"SCMP_ACT_ERRNO"}"#).unwrap();
    let mut config = OciExecutorConfig::new("/usr/bin/podman", &seccomp);
    config.insert_job_image("job", locked_image()).unwrap();
    if services {
        config
            .insert_service_image("job", "postgres", locked_service_image())
            .unwrap();
    }
    let admission = FakeAdmission {
        mode,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let executor = OciExecutor::new(
        &workspace,
        state,
        config,
        admission,
        RecordingRuntime::default(),
    )
    .unwrap();
    Fixture {
        _directory: directory,
        executor,
    }
}

fn request(action: PreparedAction) -> StepExecutionRequest {
    StepExecutionRequest {
        job_id: "job".to_owned(),
        step_id: "step".to_owned(),
        job_attempt: 1,
        runner: RunnerRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation: Isolation::Oci,
            image: Some(IMAGE.to_owned()),
            cpu: 2,
            memory_bytes: 512 * 1024 * 1024,
            storage_bytes: None,
            region: None,
            capabilities: Vec::new(),
        },
        action,
        environment: BTreeMap::new(),
        working_directory: None,
        capabilities: StepCapabilitySet::default(),
        timeout_ms: Some(5_000),
        cancellation: CancellationToken::default(),
    }
}

fn command_request() -> StepExecutionRequest {
    request(PreparedAction::Command {
        program: "/bin/echo".to_owned(),
        args: vec!["hello".to_owned()],
    })
}

fn capsule() -> ExecutionCapsule {
    let step = PlannedStep {
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
    };
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
            source_commit: "source".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: runtrue_workflow_ir::SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: Some(ContentDigest::sha256(b"lock")),
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
            runner: command_request().runner,
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: vec![step],
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
        expected_parity: ParityGrade::BEnvironmentEquivalent,
    }
}

fn capsule_with_service(healthcheck: Option<Healthcheck>) -> ExecutionCapsule {
    let mut capsule = capsule();
    capsule.jobs[0].services.push(PlannedService {
        id: "postgres".to_owned(),
        image: SERVICE_IMAGE.to_owned(),
        ports: vec![5432],
        environment: BTreeMap::from([(
            "POSTGRES_PASSWORD".to_owned(),
            ValueBinding::Literal(ScalarValue::String("test-only".to_owned())),
        )]),
        healthcheck,
    });
    capsule
}

fn short_healthcheck(retries: u32) -> Healthcheck {
    Healthcheck {
        command: vec![
            "pg_isready".to_owned(),
            "-U".to_owned(),
            "postgres".to_owned(),
        ],
        interval_ms: 1,
        timeout_ms: 10,
        retries,
    }
}

mod cleanup;
mod config;
mod execution;
mod image;
mod recovery;
mod security;
mod services;
