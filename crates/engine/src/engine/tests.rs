//! State-machine, output, cancellation, and native integration regression tests.

use super::*;
use runtrue_workflow_ir::{
    ApprovalRequirements, CapsuleContext, ContextBinding, ParityGrade, PermissionSet, PlannedJob,
    PlannedStep, Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
};
use std::collections::VecDeque;
use tempfile::tempdir;

#[derive(Default)]
struct ScriptedExecutor {
    outputs: VecDeque<Result<ExecutorOutput, ExecutorError>>,
    requests: Vec<StepExecutionRequest>,
    finalizations: Vec<(String, u32, JobAttemptOutcome)>,
    timeline: Vec<String>,
    fail_finalization: bool,
}

impl ScriptedExecutor {
    fn with_outputs(outputs: impl IntoIterator<Item = ExecutorOutput>) -> Self {
        Self {
            outputs: outputs.into_iter().map(Ok).collect(),
            requests: Vec::new(),
            finalizations: Vec::new(),
            timeline: Vec::new(),
            fail_finalization: false,
        }
    }
}

impl Executor for ScriptedExecutor {
    fn preflight(&self, _capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        self.timeline.push(format!(
            "execute:{}:{}",
            request.job_id, request.job_attempt
        ));
        self.requests.push(request.clone());
        self.outputs
            .pop_front()
            .unwrap_or_else(|| Ok(ExecutorOutput::success()))
    }

    fn finish_job_attempt(
        &mut self,
        job: &PlannedJob,
        attempt: u32,
        outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        self.timeline.push(format!("finish:{}:{attempt}", job.id));
        self.finalizations.push((job.id.clone(), attempt, outcome));
        if self.fail_finalization {
            Err(ExecutorError::Wait("scripted cleanup failure".to_owned()))
        } else {
            Ok(())
        }
    }
}

fn capsule(jobs: Vec<PlannedJob>) -> ExecutionCapsule {
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
            source_trust: Default::default(),
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            policy_version_ids: vec!["test-policy".to_owned()],
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs,
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::CPlatformSpecific,
    }
}

fn runner(isolation: Isolation) -> RunnerRequirements {
    let (os, arch) = host_platform().expect("tests run on a supported host platform");
    RunnerRequirements {
        os,
        arch,
        isolation,
        image: None,
        cpu: 1,
        memory_bytes: 64 * 1024 * 1024,
        storage_bytes: None,
        region: None,
        capabilities: Vec::new(),
    }
}

fn command_step(id: &str) -> PlannedStep {
    PlannedStep {
        id: id.to_owned(),
        name: id.to_owned(),
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
    }
}

fn job(id: &str, steps: Vec<PlannedStep>) -> PlannedJob {
    PlannedJob {
        id: id.to_owned(),
        base_id: id.to_owned(),
        name: id.to_owned(),
        needs: Vec::new(),
        matrix: BTreeMap::new(),
        condition: None,
        trust: Trust::UntrustedOk,
        environment: None,
        runner: runner(Isolation::Native),
        permissions: PermissionSet::default(),
        timeout_ms: 5_000,
        retries: 0,
        concurrency: None,
        variables: BTreeMap::new(),
        services: Vec::new(),
        steps,
        finalizers: Vec::new(),
        finalizer_timeout_ms: 120_000,
        value_outputs: BTreeMap::new(),
        outputs: BTreeMap::new(),
    }
}

fn native_request(action: PreparedAction) -> StepExecutionRequest {
    StepExecutionRequest {
        job_id: "job".to_owned(),
        step_id: "step".to_owned(),
        job_attempt: 1,
        runner: runner(Isolation::Native),
        action,
        environment: BTreeMap::new(),
        working_directory: None,
        capabilities: StepCapabilitySet::default(),
        timeout_ms: Some(5_000),
        cancellation: CancellationToken::default(),
    }
}

struct TimelineExecutor(Arc<Mutex<Vec<String>>>);

impl Executor for TimelineExecutor {
    fn preflight(&self, _capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(
        &mut self,
        _request: &StepExecutionRequest,
    ) -> Result<ExecutorOutput, ExecutorError> {
        self.0.lock().unwrap().push("execute".to_owned());
        Ok(ExecutorOutput::success())
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

struct TimelineObserver(Arc<Mutex<Vec<String>>>);

impl StepStateObserver for TimelineObserver {
    fn observe(&self, observation: &StepStateObservation) -> Result<(), String> {
        self.0.lock().unwrap().push(format!("{:?}", observation.to));
        Ok(())
    }
}

#[test]
fn synchronous_observer_brackets_backend_execution() {
    let timeline = Arc::new(Mutex::new(Vec::new()));
    let mut engine = Engine::new(TimelineExecutor(timeline.clone()))
        .with_step_state_observer(Arc::new(TimelineObserver(timeline.clone())));
    engine
        .execute(&capsule(vec![job("job", vec![command_step("step")])]))
        .unwrap();
    assert_eq!(
        *timeline.lock().unwrap(),
        ["Created", "Running", "execute", "Succeeded"]
    );
}

#[test]
fn offered_job_execution_never_runs_other_capsule_jobs() {
    let capsule = capsule(vec![
        job("not-offered", vec![command_step("first")]),
        job("offered", vec![command_step("second")]),
    ]);
    let mut engine = Engine::new(ScriptedExecutor::default());
    let result = engine
        .execute_offered_job(&capsule, "offered")
        .expect("offered job");
    assert_eq!(
        result.jobs.keys().cloned().collect::<Vec<_>>(),
        vec!["offered"]
    );
    assert_eq!(engine.executor().requests.len(), 1);
    assert_eq!(engine.executor().requests[0].job_id, "offered");
}

#[test]
fn native_cache_support_requires_an_explicit_outer_orchestrator() {
    let directory = tempdir().unwrap();
    let mut cached = command_step("cached");
    cached.cache = Some(runtrue_workflow_ir::CacheDeclaration {
        inputs: vec!["Cargo.lock".to_owned()],
        outputs: vec!["target/cache".to_owned()],
        mode: runtrue_workflow_ir::CacheMode::WriteOnly,
        max_size_bytes: Some(1024),
    });
    let execution_capsule = capsule(vec![job("job", vec![cached])]);

    let bare = NativeProcessExecutor::new(directory.path(), true);
    assert!(bare
        .preflight(&execution_capsule)
        .unwrap_err()
        .to_string()
        .contains("declares a cache"));

    let mut externally_managed = NativeProcessExecutor::new(directory.path(), true);
    externally_managed.set_external_cache_handling(true);
    assert!(externally_managed.external_cache_handling());
    externally_managed.preflight(&execution_capsule).unwrap();
}

#[test]
fn native_artifacts_require_an_explicit_outer_orchestrator() {
    let directory = tempdir().unwrap();
    let mut artifact_job = job("job", vec![command_step("build")]);
    artifact_job.outputs.insert(
        "result".to_owned(),
        runtrue_workflow_ir::ArtifactOutput {
            path: "build/result".to_owned(),
            retention_ms: 86_400_000,
            classification: runtrue_workflow_ir::ArtifactClassification::UntrustedBuild,
        },
    );
    let execution_capsule = capsule(vec![artifact_job]);

    let bare = NativeProcessExecutor::new(directory.path(), true);
    assert!(bare
        .preflight(&execution_capsule)
        .unwrap_err()
        .to_string()
        .contains("artifact outputs"));

    let mut externally_managed = NativeProcessExecutor::new(directory.path(), true);
    externally_managed.set_external_artifact_handling(true);
    assert!(externally_managed.external_artifact_handling());
    externally_managed.preflight(&execution_capsule).unwrap();
}

#[test]
fn native_network_allow_fails_before_process_side_effects() {
    let directory = tempdir().unwrap();
    let marker = directory.path().join("must-not-run");
    let mut networked = command_step("networked");
    networked.action = StepAction::Command {
        program: "/usr/bin/touch".to_owned(),
        args: vec![ValueBinding::Literal(ScalarValue::String(
            marker.display().to_string(),
        ))],
    };
    networked.capabilities.network = runtrue_workflow_ir::NetworkPermission::Allow {
        dns: runtrue_workflow_ir::DnsPolicy::Restricted,
        deny_private_ranges: true,
        destinations: Vec::new(),
        listen: Vec::new(),
    };
    let execution_capsule = capsule(vec![job("job", vec![networked])]);
    let mut engine = Engine::new(NativeProcessExecutor::new(directory.path(), true));

    let error = engine.execute(&execution_capsule).unwrap_err();

    assert!(matches!(error, EngineError::ExecutorPreflight(_)));
    assert!(!marker.exists());
}

#[test]
fn transition_tables_reject_terminal_state_changes() {
    assert!(JobState::Created.can_transition_to(JobState::Queued));
    assert!(JobState::Running.can_transition_to(JobState::Finalizing));
    assert!(!JobState::Succeeded.can_transition_to(JobState::Running));
    assert!(StepState::Created.can_transition_to(StepState::Skipped));
    assert!(!StepState::Failed.can_transition_to(StepState::Running));
    assert!(JobState::TimedOut.is_terminal());
    assert!(StepState::Canceled.is_terminal());
}

#[test]
fn dependencies_execute_in_topological_order_not_capsule_order() {
    let mut child = job("child", vec![command_step("child-step")]);
    child.needs.push("parent".to_owned());
    let parent = job("parent", vec![command_step("parent-step")]);
    let execution_capsule = capsule(vec![child, parent]);
    let mut engine = Engine::new(ScriptedExecutor::default());

    let result = engine.execute(&execution_capsule).unwrap();

    assert!(result.succeeded());
    let executor = engine.into_executor();
    assert_eq!(executor.requests.len(), 2);
    assert_eq!(executor.requests[0].job_id, "parent");
    assert_eq!(executor.requests[1].job_id, "child");
    for (sequence, event) in result.events.iter().enumerate() {
        assert_eq!(event.sequence, u64::try_from(sequence).unwrap());
    }
}

#[test]
fn failed_dependency_skips_dependent_job() {
    let parent = job("parent", vec![command_step("fail")]);
    let mut child = job("child", vec![command_step("never")]);
    child.needs.push("parent".to_owned());
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([ExecutorOutput::failure(9)]));

    let result = engine.execute(&capsule(vec![child, parent])).unwrap();

    assert_eq!(result.state, RunState::Failed);
    assert_eq!(result.jobs["parent"].state, JobState::Failed);
    assert_eq!(result.jobs["child"].state, JobState::Skipped);
    assert_eq!(
        result.jobs["child"].skip_reason,
        Some(SkipReason::DependencyNotSuccessful)
    );
    assert_eq!(engine.executor().requests.len(), 1);
}

#[test]
fn retries_the_whole_job_until_it_succeeds() {
    let mut retrying = job("retry", vec![command_step("sometimes")]);
    retrying.retries = 1;
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([
        ExecutorOutput::failure(1),
        ExecutorOutput::success(),
    ]));

    let result = engine.execute(&capsule(vec![retrying])).unwrap();
    let result = &result.jobs["retry"];

    assert_eq!(result.state, JobState::Succeeded);
    assert_eq!(result.attempts.len(), 2);
    assert_eq!(result.attempts[0].steps[0].state, StepState::Failed);
    assert_eq!(result.attempts[1].steps[0].state, StepState::Succeeded);
    assert_eq!(
        engine.executor().timeline,
        vec![
            "execute:retry:1",
            "finish:retry:1",
            "execute:retry:2",
            "finish:retry:2",
        ]
    );
    assert_eq!(
        engine.executor().finalizations,
        vec![
            ("retry".to_owned(), 1, JobAttemptOutcome::Failed),
            ("retry".to_owned(), 2, JobAttemptOutcome::Succeeded),
        ]
    );
}

#[test]
fn canceled_and_timed_out_attempts_are_finalized_exactly_once() {
    for (output, expected) in [
        (
            ExecutorOutput {
                exit_code: None,
                canceled: true,
                ..ExecutorOutput::success()
            },
            JobAttemptOutcome::Canceled,
        ),
        (
            ExecutorOutput {
                exit_code: None,
                timed_out: true,
                ..ExecutorOutput::success()
            },
            JobAttemptOutcome::TimedOut,
        ),
    ] {
        let mut engine = Engine::new(ScriptedExecutor::with_outputs([output]));
        let result = engine
            .execute(&capsule(vec![job("job", vec![command_step("step")])]))
            .unwrap();
        assert!(!result.succeeded());
        assert_eq!(
            engine.executor().finalizations,
            vec![("job".to_owned(), 1, expected)]
        );
    }
}

#[test]
fn finalization_failure_is_fatal_and_prevents_retry_or_success() {
    let mut executor =
        ScriptedExecutor::with_outputs([ExecutorOutput::success(), ExecutorOutput::success()]);
    executor.fail_finalization = true;
    let mut retrying = job("job", vec![command_step("step")]);
    retrying.retries = 1;
    let mut engine = Engine::new(executor);

    let error = engine.execute(&capsule(vec![retrying])).unwrap_err();

    assert!(matches!(
        error,
        EngineError::ExecutorFinalization {
            job_id,
            attempt: 1,
            ..
        } if job_id == "job"
    ));
    assert_eq!(
        engine.executor().timeline,
        vec!["execute:job:1", "finish:job:1"]
    );
    assert_eq!(engine.executor().requests.len(), 1);
}

#[test]
fn executor_default_finalization_is_fail_closed() {
    struct MissingFinalizer;

    impl Executor for MissingFinalizer {
        fn preflight(&self, _capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
            Ok(())
        }

        fn execute(
            &mut self,
            _request: &StepExecutionRequest,
        ) -> Result<ExecutorOutput, ExecutorError> {
            Ok(ExecutorOutput::success())
        }
    }

    let mut engine = Engine::new(MissingFinalizer);
    assert!(matches!(
        engine.execute(&capsule(vec![job("job", vec![command_step("step")])])),
        Err(EngineError::ExecutorFinalization {
            job_id,
            attempt: 1,
            ..
        }) if job_id == "job"
    ));
}

#[test]
fn continue_on_error_preserves_failure_but_allows_job_success() {
    let mut tolerated = command_step("tolerated");
    tolerated.continue_on_error = true;
    let next = command_step("next");
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([
        ExecutorOutput::failure(2),
        ExecutorOutput::success(),
    ]));

    let result = engine
        .execute(&capsule(vec![job("job", vec![tolerated, next])]))
        .unwrap();
    let attempt = &result.jobs["job"].attempts[0];

    assert_eq!(result.jobs["job"].state, JobState::Succeeded);
    assert_eq!(attempt.steps[0].state, StepState::Failed);
    assert!(attempt.steps[0].continued_on_error);
    assert_eq!(attempt.steps[1].state, StepState::Succeeded);
}

#[test]
fn evaluates_typed_conditions_and_resolves_inert_bindings() {
    let mut run = command_step("run");
    run.condition = Some("${{ vars.ENABLED == true }}".to_owned());
    run.action = StepAction::Command {
        program: "/bin/echo".to_owned(),
        args: vec![ValueBinding::Context(ContextBinding {
            from: "vars.MESSAGE".to_owned(),
        })],
    };
    run.environment.insert(
        "MESSAGE".to_owned(),
        ValueBinding::Context(ContextBinding {
            from: "vars.MESSAGE".to_owned(),
        }),
    );
    let mut skipped = command_step("skip");
    skipped.condition = Some("false".to_owned());
    let mut execution_capsule = capsule(vec![job("job", vec![run, skipped])]);
    execution_capsule
        .variables
        .insert("ENABLED".to_owned(), ScalarValue::Boolean(true));
    execution_capsule.variables.insert(
        "MESSAGE".to_owned(),
        ScalarValue::String("hello; $(not-a-shell)".to_owned()),
    );
    let mut engine = Engine::new(ScriptedExecutor::default());

    let result = engine.execute(&execution_capsule).unwrap();
    let request = &engine.executor().requests[0];

    assert_eq!(
        result.jobs["job"].attempts[0].steps[1].state,
        StepState::Skipped
    );
    assert_eq!(request.environment["MESSAGE"], "hello; $(not-a-shell)");
    assert!(matches!(
        &request.action,
        PreparedAction::Command { args, .. }
            if args == &["hello; $(not-a-shell)".to_owned()]
    ));
}

#[test]
fn component_variables_are_resolved_only_into_typed_inputs() {
    let mut step = command_step("component");
    step.action = StepAction::Component {
            reference: "wasm://registry.example/action@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
    step.inputs.insert(
        "message".to_owned(),
        ValueBinding::Context(ContextBinding {
            from: "vars.MESSAGE".to_owned(),
        }),
    );
    let mut execution_capsule = capsule(vec![job("job", vec![step])]);
    execution_capsule.variables.insert(
        "MESSAGE".to_owned(),
        ScalarValue::String("typed only".to_owned()),
    );
    let mut engine = Engine::new(ScriptedExecutor::default());

    engine.execute(&execution_capsule).unwrap();
    let request = &engine.executor().requests[0];

    assert!(request.environment.is_empty());
    assert!(matches!(
        &request.action,
        PreparedAction::Component { inputs, .. }
            if inputs == &BTreeMap::from([("message".to_owned(), "typed only".to_owned())])
    ));
}

#[test]
fn reports_missing_runtime_context_without_executing() {
    let mut step = command_step("context");
    let StepAction::Command { args, .. } = &mut step.action else {
        panic!("test helper must construct a command step");
    };
    args.push(ValueBinding::Context(ContextBinding {
        from: "vars.missing".to_owned(),
    }));
    let mut engine = Engine::new(ScriptedExecutor::default());

    let error = engine
        .execute(&capsule(vec![job("job", vec![step])]))
        .unwrap_err();

    assert_eq!(
        error,
        EngineError::MissingContextValue {
            path: "vars.missing".to_owned()
        }
    );
    assert!(engine.executor().requests.is_empty());
}

#[test]
fn rejects_runtime_context_that_is_not_bound_into_the_capsule() {
    let execution_capsule = capsule(vec![job("job", vec![command_step("run")])]);
    let mut runtime = RuntimeContext::new();
    runtime.insert(
        "event.ref".to_owned(),
        ScalarValue::String("refs/heads/other".to_owned()),
    );
    let mut engine = Engine::new(ScriptedExecutor::default());

    assert_eq!(
        engine.execute_with_context(&execution_capsule, &runtime),
        Err(EngineError::RuntimeContextMismatch)
    );
    assert!(engine.executor().requests.is_empty());
}

#[test]
fn runtime_context_comparison_distinguishes_signed_zero() {
    let mut execution_capsule = capsule(vec![job("job", vec![command_step("run")])]);
    execution_capsule
        .context
        .event_context
        .insert("event.value".to_owned(), ScalarValue::Number(0.0));
    let mut runtime = RuntimeContext::new();
    runtime.insert("event.value".to_owned(), ScalarValue::Number(-0.0));
    let mut engine = Engine::new(ScriptedExecutor::default());

    assert_eq!(
        engine.execute_with_context(&execution_capsule, &runtime),
        Err(EngineError::RuntimeContextMismatch)
    );
    assert!(engine.executor().requests.is_empty());
}

#[test]
fn rejects_all_untrusted_dynamic_environment_before_execution() {
    let mut execution_capsule = capsule(vec![job("job", vec![command_step("run")])]);
    execution_capsule.jobs[0].steps[0].environment.insert(
        "MESSAGE".to_owned(),
        ValueBinding::Context(ContextBinding {
            from: "event.library".to_owned(),
        }),
    );
    execution_capsule.context.event_context.insert(
        "event.library".to_owned(),
        ScalarValue::String("./attacker.so".to_owned()),
    );
    let mut engine = Engine::new(ScriptedExecutor::default());

    assert!(matches!(
        engine.execute(&execution_capsule),
        Err(EngineError::UnsafeDynamicEnvironment(path))
            if path.ends_with("env.MESSAGE")
    ));
    assert!(engine.executor().requests.is_empty());
}

#[test]
fn rejects_untrusted_process_arguments_before_execution() {
    let mut step = command_step("shell");
    step.action = StepAction::Command {
        program: "/bin/sh".to_owned(),
        args: vec![
            ValueBinding::Literal(ScalarValue::String("-c".to_owned())),
            ValueBinding::Context(ContextBinding {
                from: "event.payload".to_owned(),
            }),
        ],
    };
    let mut execution_capsule = capsule(vec![job("job", vec![step])]);
    execution_capsule.context.event_context.insert(
        "event.payload".to_owned(),
        ScalarValue::String("touch PWNED".to_owned()),
    );
    let mut engine = Engine::new(ScriptedExecutor::default());

    assert!(matches!(
        engine.execute(&execution_capsule),
        Err(EngineError::UnsafeDynamicArgument(path)) if path.ends_with("steps.shell.args")
    ));
    assert!(engine.executor().requests.is_empty());
}

#[test]
fn validates_graph_retry_and_script_invariants_before_execution() {
    let mut too_many = job("limited", vec![]);
    too_many.retries = MAX_JOB_RETRIES + 1;
    assert!(matches!(
        validate_capsule(&capsule(vec![too_many])),
        Err(EngineError::TooManyRetries { .. })
    ));

    let mut cycle_a = job("a", vec![]);
    cycle_a.needs.push("b".to_owned());
    let mut cycle_b = job("b", vec![]);
    cycle_b.needs.push("a".to_owned());
    assert_eq!(
        validate_capsule(&capsule(vec![cycle_a, cycle_b])),
        Err(EngineError::DependencyCycle)
    );

    let mut script = command_step("script");
    script.action = StepAction::Script {
        shell: Shell::Sh,
        script: "echo safe".to_owned(),
        script_digest: ContentDigest::sha256(b"different bytes"),
    };
    assert!(matches!(
        validate_capsule(&capsule(vec![job("job", vec![script])])),
        Err(EngineError::ScriptDigestMismatch { .. })
    ));
}

#[test]
fn native_executor_requires_both_native_isolation_and_opt_in() {
    let directory = tempdir().unwrap();
    let action = PreparedAction::Command {
        program: "/bin/true".to_owned(),
        args: Vec::new(),
    };
    let mut executor = NativeProcessExecutor::new(directory.path(), false);
    let request = native_request(action.clone());
    assert_eq!(
        executor.execute(&request),
        Err(ExecutorError::NativeExecutionDisabled)
    );

    let mut non_native = native_request(action);
    non_native.runner.isolation = Isolation::Oci;
    executor.set_allow_native(true);
    assert!(matches!(
        executor.execute(&non_native),
        Err(ExecutorError::UnsupportedIsolation(_))
    ));
}

#[cfg(unix)]
#[test]
fn native_engine_preflights_the_entire_capsule_before_any_process() {
    let directory = tempdir().unwrap();
    let marker = directory.path().join("must-not-run");
    let mut first = command_step("first");
    first.action = StepAction::Command {
        program: "/usr/bin/touch".to_owned(),
        args: vec![ValueBinding::Literal(ScalarValue::String(
            marker.to_string_lossy().into_owned(),
        ))],
    };
    let mut unsupported = command_step("unsupported");
    unsupported.action = StepAction::Component {
        reference: format!("wasm://example/action@sha256:{}", "a".repeat(64)),
    };
    let mut native_job = job("job", vec![first]);
    native_job
        .finalizers
        .push(runtrue_workflow_ir::PlannedFinalizer {
            step: unsupported,
            required: true,
            run_on_cancel: true,
        });
    let execution_capsule = capsule(vec![native_job]);
    let mut engine = Engine::new(NativeProcessExecutor::new(directory.path(), true));

    let error = engine.execute(&execution_capsule).unwrap_err();

    assert!(matches!(error, EngineError::ExecutorPreflight(_)));
    assert!(!marker.exists());

    let mut first = command_step("first");
    first.action = StepAction::Command {
        program: "/usr/bin/touch".to_owned(),
        args: vec![ValueBinding::Literal(ScalarValue::String(
            marker.to_string_lossy().into_owned(),
        ))],
    };
    let mut unsupported_output = command_step("typed-output");
    unsupported_output.outputs.insert(
        "value".to_owned(),
        StepOutputSchema {
            kind: StepOutputType::String,
            required: true,
        },
    );
    let execution_capsule = capsule(vec![job("job", vec![first, unsupported_output])]);
    let mut engine = Engine::new(NativeProcessExecutor::new(directory.path(), true));
    let error = engine.execute(&execution_capsule).unwrap_err();
    assert!(matches!(error, EngineError::ExecutorPreflight(_)));
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn native_executor_uses_argv_env_and_captures_output() {
    let directory = tempdir().unwrap();
    let mut executor = NativeProcessExecutor::new(directory.path(), true);
    let mut request = native_request(PreparedAction::Command {
        program: "/bin/sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            "printf '%s' \"$VALUE\"; printf 'problem' >&2".to_owned(),
        ],
    });
    request
        .environment
        .insert("VALUE".to_owned(), "literal; echo this-is-data".to_owned());

    let output = executor.execute(&request).unwrap();

    assert!(output.succeeded());
    assert_eq!(output.stdout, "literal; echo this-is-data");
    assert_eq!(output.stderr, "problem");
    assert!(!output.stdout_truncated);
}

#[cfg(unix)]
#[test]
fn native_timeout_terminates_without_unsafe_code() {
    let directory = tempdir().unwrap();
    let mut executor = NativeProcessExecutor::new(directory.path(), true);
    let mut request = native_request(PreparedAction::Command {
        program: "/bin/sleep".to_owned(),
        args: vec!["2".to_owned()],
    });
    request.timeout_ms = Some(25);
    let started = Instant::now();

    let output = executor.execute(&request).unwrap();

    assert!(output.timed_out);
    assert!(!output.succeeded());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn native_timeout_terminates_the_step_process_group() {
    let directory = tempdir().unwrap();
    let marker = directory.path().join("descendant-survived");
    let mut executor = NativeProcessExecutor::new(directory.path(), true);
    let mut request = native_request(PreparedAction::Command {
        program: "/bin/sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            format!(
                "(sleep 0.15; /usr/bin/touch '{}') & sleep 5",
                marker.display()
            ),
        ],
    });
    request.timeout_ms = Some(25);

    let output = executor.execute(&request).unwrap();
    thread::sleep(Duration::from_millis(250));

    assert!(output.timed_out);
    assert!(!marker.exists(), "background descendant escaped timeout");
}

#[cfg(unix)]
#[test]
fn native_success_requires_process_group_cleanup_proof() {
    let directory = tempdir().unwrap();
    let marker = directory.path().join("descendant-survived-success");
    let mut executor = NativeProcessExecutor::new(directory.path(), true);
    let request = native_request(PreparedAction::Command {
        program: "/bin/sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            format!(
                "(sleep 0.15; /usr/bin/touch '{}') & exit 0",
                marker.display()
            ),
        ],
    });

    let output = executor.execute(&request).unwrap();
    thread::sleep(Duration::from_millis(250));

    assert!(output.succeeded());
    assert!(
        !marker.exists(),
        "background descendant escaped successful step finalization"
    );
}

#[cfg(unix)]
#[test]
fn canonical_working_directory_check_blocks_symlink_escape() {
    use std::os::unix::fs::symlink;

    let workspace = tempdir().unwrap();
    let outside = tempdir().unwrap();
    symlink(outside.path(), workspace.path().join("escape")).unwrap();
    let mut executor = NativeProcessExecutor::new(workspace.path(), true);
    let mut request = native_request(PreparedAction::Command {
        program: "/bin/true".to_owned(),
        args: Vec::new(),
    });
    request.working_directory = Some("escape".to_owned());

    assert_eq!(
        executor.execute(&request),
        Err(ExecutorError::UnsafeWorkingDirectory("escape".to_owned()))
    );
}

#[cfg(unix)]
#[test]
fn capture_limit_drains_but_truncates_large_streams() {
    let directory = tempdir().unwrap();
    let mut executor = NativeProcessExecutor::new(directory.path(), true);
    executor.set_max_capture_bytes(4);
    let request = native_request(PreparedAction::Command {
        program: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), "printf 'abcdefgh'".to_owned()],
    });

    let output = executor.execute(&request).unwrap();

    assert_eq!(output.stdout, "abcd");
    assert!(output.stdout_truncated);
}

#[test]
fn pre_canceled_native_request_does_not_spawn() {
    let directory = tempdir().unwrap();
    let mut executor = NativeProcessExecutor::new(directory.path(), true);
    let request = native_request(PreparedAction::Command {
        program: "/definitely/not/a/program".to_owned(),
        args: Vec::new(),
    });
    request.cancellation.cancel();

    let output = executor.execute(&request).unwrap();

    assert!(output.canceled);
    assert_eq!(output.exit_code, None);
}

#[test]
fn structured_outputs_are_typed_bounded_and_provenance_bound() {
    let mut produce = command_step("produce");
    produce.outputs.insert(
        "count".to_owned(),
        StepOutputSchema {
            kind: StepOutputType::Integer,
            required: true,
        },
    );
    let mut producing_job = job("job", vec![produce]);
    producing_job.value_outputs.insert(
        "count".to_owned(),
        runtrue_workflow_ir::JobValueOutput {
            step_id: "produce".to_owned(),
            output_name: "count".to_owned(),
        },
    );
    let execution_capsule = capsule(vec![producing_job.clone()]);
    let capsule_digest = execution_capsule.digest().unwrap();
    let mut success = ExecutorOutput::success();
    success.stdout = "count=999\n".to_owned();
    success.structured_output = Some(r#"{"count":7}"#.to_owned());
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([success]));
    let result = engine.execute(&execution_capsule).unwrap();
    let output = &result.jobs["job"].outputs["count"];
    assert_eq!(output.value, TypedOutputValue::Integer(7));
    assert_eq!(output.provenance.capsule_digest, capsule_digest);
    assert_eq!(output.provenance.job_attempt, 1);

    let mut mismatch = ExecutorOutput::success();
    mismatch.structured_output = Some(r#"{"count":"7"}"#.to_owned());
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([mismatch]));
    let result = engine
        .execute(&capsule(vec![producing_job.clone()]))
        .unwrap();
    assert_eq!(result.jobs["job"].state, JobState::Failed);
    assert!(result.jobs["job"].attempts[0].steps[0]
        .error
        .as_deref()
        .unwrap()
        .contains("signed 64-bit integer"));

    let mut duplicate = ExecutorOutput::success();
    duplicate.structured_output = Some(r#"{"count":7,"count":8}"#.to_owned());
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([duplicate]));
    let result = engine
        .execute(&capsule(vec![producing_job.clone()]))
        .unwrap();
    assert!(result.jobs["job"].attempts[0].steps[0]
        .error
        .as_deref()
        .unwrap()
        .contains("duplicate-free canonical JSON"));

    let mut undeclared = ExecutorOutput::success();
    undeclared.structured_output = Some(r#"{"rogue":true}"#.to_owned());
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([undeclared]));
    let result = engine
        .execute(&capsule(vec![job("job", vec![command_step("step")])]))
        .unwrap();
    assert!(result.jobs["job"].attempts[0].steps[0]
        .error
        .as_deref()
        .unwrap()
        .contains("undeclared output `rogue`"));

    let mut oversized = ExecutorOutput::success();
    oversized.structured_output = Some(format!(
        r#"{{"count":7,"padding":"{}"}}"#,
        "x".repeat(MAX_STRUCTURED_OUTPUT_BYTES)
    ));
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([oversized]));
    let result = engine.execute(&capsule(vec![producing_job])).unwrap();
    assert!(result.jobs["job"].attempts[0].steps[0]
        .error
        .as_deref()
        .unwrap()
        .contains("record exceeds"));
}

#[test]
fn required_finalizer_can_only_degrade_primary_success() {
    let mut required = job("required", vec![command_step("primary")]);
    required
        .finalizers
        .push(runtrue_workflow_ir::PlannedFinalizer {
            step: command_step("cleanup"),
            required: true,
            run_on_cancel: true,
        });
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([
        ExecutorOutput::success(),
        ExecutorOutput::failure(9),
    ]));
    let result = engine.execute(&capsule(vec![required])).unwrap();
    let attempt = &result.jobs["required"].attempts[0];
    assert_eq!(attempt.primary_state, JobState::Succeeded);
    assert_eq!(attempt.finalizers[0].state, StepState::Failed);
    assert_eq!(result.jobs["required"].state, JobState::Failed);

    let mut preserved = job("preserved", vec![command_step("primary")]);
    preserved
        .finalizers
        .push(runtrue_workflow_ir::PlannedFinalizer {
            step: command_step("cleanup"),
            required: true,
            run_on_cancel: true,
        });
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([
        ExecutorOutput::failure(2),
        ExecutorOutput::success(),
    ]));
    let result = engine.execute(&capsule(vec![preserved])).unwrap();
    let attempt = &result.jobs["preserved"].attempts[0];
    assert_eq!(attempt.primary_state, JobState::Failed);
    assert_eq!(attempt.finalizers[0].state, StepState::Succeeded);
    assert_eq!(result.jobs["preserved"].state, JobState::Failed);
}

#[test]
fn dynamic_jobs_use_the_same_canonical_expansion_as_the_ir() {
    let mut producer_step = command_step("generate");
    producer_step.outputs.insert(
        "axes".to_owned(),
        StepOutputSchema {
            kind: StepOutputType::Json,
            required: true,
        },
    );
    let mut producer = job("generate", vec![producer_step]);
    producer.value_outputs.insert(
        "axes".to_owned(),
        runtrue_workflow_ir::JobValueOutput {
            step_id: "generate".to_owned(),
            output_name: "axes".to_owned(),
        },
    );
    let mut template_job = job("build", vec![command_step("build")]);
    template_job.needs = vec!["generate".to_owned()];
    let template = runtrue_workflow_ir::DynamicJobTemplate {
        id: "build".to_owned(),
        source: runtrue_workflow_ir::DynamicMatrixSource {
            producer_job_id: "generate".to_owned(),
            output_name: "axes".to_owned(),
            maximum_jobs: 2,
        },
        template: template_job,
    };
    let mut execution_capsule = capsule(vec![producer]);
    execution_capsule.dynamic_jobs = vec![template.clone()];
    let mut generated = ExecutorOutput::success();
    generated.structured_output = Some(r#"{"axes":{"mode":["release","debug"]}}"#.to_owned());
    let mut engine = Engine::new(ScriptedExecutor::with_outputs([
        generated,
        ExecutorOutput::success(),
        ExecutorOutput::success(),
    ]));
    let result = engine.execute(&execution_capsule).unwrap();
    let expected = expand_dynamic_job_set(
        execution_capsule.digest().unwrap(),
        &template,
        &serde_json::json!({"mode": ["release", "debug"]}),
        0,
    )
    .unwrap();
    for id in expected.generated_job_ids {
        assert_eq!(result.jobs[&id].state, JobState::Succeeded);
    }
    assert_eq!(engine.executor().requests.len(), 3);

    let reject_without_execution = |mutated: ExecutionCapsule, expected: &str| {
        let mut engine = Engine::new(ScriptedExecutor::default());
        let error = engine.execute(&mutated).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
        assert!(engine.executor().requests.is_empty());
    };

    let mut preexpanded = execution_capsule.clone();
    preexpanded.dynamic_jobs[0]
        .template
        .matrix
        .insert("injected".to_owned(), ScalarValue::Boolean(true));
    reject_without_execution(preexpanded, "pre-expanded matrix values");

    let mut detached = execution_capsule.clone();
    detached.dynamic_jobs[0].template.needs.clear();
    reject_without_execution(detached, "does not retain its producer dependency");

    let mut optional_source = execution_capsule.clone();
    optional_source.jobs[0].steps[0]
        .outputs
        .get_mut("axes")
        .unwrap()
        .required = false;
    reject_without_execution(optional_source, "not a guaranteed required JSON output");

    let mut nonterminal = execution_capsule.clone();
    let mut consumer = job("consume", vec![command_step("consume")]);
    consumer.needs = vec!["build".to_owned()];
    nonterminal.jobs.push(consumer);
    reject_without_execution(nonterminal, "must be terminal");

    let mut excessive = execution_capsule;
    excessive.dynamic_jobs[0].source.maximum_jobs = MAX_EXPANDED_JOBS;
    reject_without_execution(excessive, "signed dynamic maxima exceed");
}

#[test]
fn cancellation_runs_only_explicitly_safe_finalizers() {
    struct CancelAfterPrimary {
        cancellation: CancellationToken,
        requests: Vec<String>,
    }

    impl Executor for CancelAfterPrimary {
        fn preflight(&self, _capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
            Ok(())
        }

        fn execute(
            &mut self,
            request: &StepExecutionRequest,
        ) -> Result<ExecutorOutput, ExecutorError> {
            self.requests.push(request.step_id.clone());
            if request.step_id == "primary" {
                self.cancellation.cancel();
            }
            Ok(ExecutorOutput::success())
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

    let cancellation = CancellationToken::default();
    let mut value = job("job", vec![command_step("primary")]);
    value.finalizers = vec![
        runtrue_workflow_ir::PlannedFinalizer {
            step: command_step("unsafe-cleanup"),
            required: false,
            run_on_cancel: false,
        },
        runtrue_workflow_ir::PlannedFinalizer {
            step: command_step("safe-cleanup"),
            required: true,
            run_on_cancel: true,
        },
    ];
    let executor = CancelAfterPrimary {
        cancellation: cancellation.clone(),
        requests: Vec::new(),
    };
    let mut engine = Engine::with_cancellation_token(executor, cancellation);
    let result = engine.execute(&capsule(vec![value])).unwrap();
    let attempt = &result.jobs["job"].attempts[0];
    assert_eq!(attempt.primary_state, JobState::Canceled);
    assert_eq!(attempt.finalizers[0].state, StepState::Skipped);
    assert_eq!(attempt.finalizers[1].state, StepState::Succeeded);
    assert_eq!(result.jobs["job"].state, JobState::Canceled);
    assert_eq!(
        engine.executor().requests,
        ["primary".to_owned(), "safe-cleanup".to_owned()]
    );
}
