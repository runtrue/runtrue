use crate::BackendIdentity;
use runtrue_engine::{
    Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, StepExecutionRequest,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements,
    ScalarValue, StepAction, StepCapabilitySet, Trust, ValueBinding, WorkflowIdentity,
    CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::collections::{BTreeMap, VecDeque};

pub(super) struct ScriptedExecutor {
    pub(super) outputs: VecDeque<ExecutorOutput>,
}

impl Executor for ScriptedExecutor {
    fn preflight(&self, _capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(
        &mut self,
        _request: &StepExecutionRequest,
    ) -> Result<ExecutorOutput, ExecutorError> {
        self.outputs
            .pop_front()
            .ok_or_else(|| ExecutorError::Wait("missing scripted output".to_owned()))
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

pub(super) fn capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "conformance".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/ci.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "0123456789012345678901234567890123456789".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: Default::default(),
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::from([("MODE".to_owned(), ScalarValue::String("test".to_owned()))]),
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
                isolation: Isolation::Native,
                image: None,
                cpu: 1,
                memory_bytes: 1024,
                storage_bytes: None,
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 1_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: vec![PlannedStep {
                id: "step".to_owned(),
                name: "step".to_owned(),
                condition: None,
                action: StepAction::Command {
                    program: "echo".to_owned(),
                    args: vec![ValueBinding::Literal(ScalarValue::String(
                        "hello".to_owned(),
                    ))],
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
        expected_parity: ParityGrade::DNonReplayable,
    }
}

pub(super) fn backend() -> BackendIdentity {
    BackendIdentity {
        name: "scripted".to_owned(),
        version: "1".to_owned(),
        isolation: Isolation::Native,
        parity: ParityGrade::DNonReplayable,
    }
}

pub(super) fn output(stdout: &str, duration_ms: u64) -> ExecutorOutput {
    ExecutorOutput {
        stdout: stdout.to_owned(),
        duration_ms,
        ..ExecutorOutput::success()
    }
}
