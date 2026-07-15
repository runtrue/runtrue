//! Fail-closed isolation dispatch for the shared execution engine.
//!
//! Concrete backends retain ownership of their security preflight. This layer
//! partitions a mixed capsule by its requested isolation, verifies that every
//! requested backend exists before invoking any backend, and routes each
//! prepared step only to the backend named by the signed capsule.

use runtrue_engine::{
    Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, StepExecutionRequest,
};
use runtrue_workflow_ir::{ExecutionCapsule, Isolation, PlannedJob};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

/// An exact-isolation backend registry. No fallback order exists.
#[derive(Default)]
pub struct ExecutorDispatcher {
    backends: BTreeMap<Isolation, Box<dyn Executor>>,
}

impl ExecutorDispatcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<E>(
        &mut self,
        isolation: Isolation,
        executor: E,
    ) -> Result<(), DispatchConfigurationError>
    where
        E: Executor + 'static,
    {
        if self.backends.contains_key(&isolation) {
            return Err(DispatchConfigurationError::DuplicateBackend(isolation));
        }
        self.backends.insert(isolation, Box::new(executor));
        Ok(())
    }

    #[must_use]
    pub fn supports(&self, isolation: Isolation) -> bool {
        self.backends.contains_key(&isolation)
    }

    #[must_use]
    pub fn configured_isolations(&self) -> Vec<Isolation> {
        self.backends.keys().copied().collect()
    }

    fn missing_backend(isolation: Isolation) -> ExecutorError {
        ExecutorError::UnsupportedIsolation(format!("{isolation:?}"))
    }
}

impl fmt::Debug for ExecutorDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutorDispatcher")
            .field("configured_isolations", &self.configured_isolations())
            .finish()
    }
}

impl Executor for ExecutorDispatcher {
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        let requested = capsule
            .jobs
            .iter()
            .map(|job| job.runner.isolation)
            .collect::<std::collections::BTreeSet<_>>();

        // Check completeness first. Backend preflight may populate admission
        // caches, so never call it for a capsule that cannot be fully admitted.
        for isolation in &requested {
            if !self.backends.contains_key(isolation) {
                return Err(Self::missing_backend(*isolation));
            }
        }

        for isolation in requested {
            let mut projected = capsule.clone();
            projected
                .jobs
                .retain(|job| job.runner.isolation == isolation);
            self.backends
                .get(&isolation)
                .ok_or_else(|| Self::missing_backend(isolation))?
                .preflight(&projected)?;
        }
        Ok(())
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        self.backends
            .get_mut(&request.runner.isolation)
            .ok_or_else(|| Self::missing_backend(request.runner.isolation))?
            .execute(request)
    }

    fn finish_job_attempt(
        &mut self,
        job: &PlannedJob,
        attempt: u32,
        outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        self.backends
            .get_mut(&job.runner.isolation)
            .ok_or_else(|| Self::missing_backend(job.runner.isolation))?
            .finish_job_attempt(job, attempt, outcome)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DispatchConfigurationError {
    #[error("an executor is already registered for isolation `{0:?}`")]
    DuplicateBackend(Isolation),
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_engine::{Engine, PreparedAction};
    use runtrue_model::ContentDigest;
    use runtrue_workflow_ir::{
        ApprovalRequirements, Architecture, CapsuleContext, OperatingSystem, ParityGrade,
        PermissionSet, PlannedJob, PlannedStep, RunnerRequirements, StepAction, StepCapabilitySet,
        Trust, ValueBinding, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
        ENGINE_COMPATIBILITY_VERSION,
    };
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

    #[derive(Debug, Default)]
    struct Observations {
        preflight_jobs: Vec<Vec<String>>,
        executed_jobs: Vec<String>,
        finalized_attempts: Vec<(String, u32, JobAttemptOutcome)>,
    }

    struct RecordingExecutor {
        observations: Rc<RefCell<Observations>>,
        fail_preflight: bool,
    }

    impl Executor for RecordingExecutor {
        fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
            self.observations
                .borrow_mut()
                .preflight_jobs
                .push(capsule.jobs.iter().map(|job| job.id.clone()).collect());
            if self.fail_preflight {
                Err(ExecutorError::UnsupportedCapsuleFeature(
                    "backend preflight rejected the capsule".to_owned(),
                ))
            } else {
                Ok(())
            }
        }

        fn execute(
            &mut self,
            request: &StepExecutionRequest,
        ) -> Result<ExecutorOutput, ExecutorError> {
            self.observations
                .borrow_mut()
                .executed_jobs
                .push(request.job_id.clone());
            Ok(ExecutorOutput::success())
        }

        fn finish_job_attempt(
            &mut self,
            job: &PlannedJob,
            attempt: u32,
            outcome: JobAttemptOutcome,
        ) -> Result<(), ExecutorError> {
            self.observations.borrow_mut().finalized_attempts.push((
                job.id.clone(),
                attempt,
                outcome,
            ));
            Ok(())
        }
    }

    fn runner(isolation: Isolation) -> RunnerRequirements {
        RunnerRequirements {
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation,
            image: None,
            cpu: 1,
            memory_bytes: 64 * 1024 * 1024,
            storage_bytes: None,
            region: None,
            capabilities: Vec::new(),
        }
    }

    fn job(id: &str, isolation: Isolation) -> PlannedJob {
        PlannedJob {
            id: id.to_owned(),
            base_id: id.to_owned(),
            name: id.to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::TrustedOnly,
            environment: None,
            runner: runner(isolation),
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: vec![PlannedStep {
                id: format!("{id}-step"),
                name: format!("{id}-step"),
                condition: None,
                action: StepAction::Command {
                    program: "/bin/true".to_owned(),
                    args: Vec::<ValueBinding>::new(),
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
        }
    }

    fn capsule(jobs: Vec<PlannedJob>) -> ExecutionCapsule {
        ExecutionCapsule {
            schema_version: CAPSULE_SCHEMA_VERSION,
            engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
            compiler_version: "dispatcher-test".to_owned(),
            workflow: WorkflowIdentity {
                name: "mixed".to_owned(),
                digest: ContentDigest::sha256(b"workflow"),
                source_path: ".runtrue/workflows/mixed.yaml".to_owned(),
            },
            context: CapsuleContext {
                source_commit: "a".repeat(40),
                source_tree_digest: None,
                base_commit: None,
                source_trust: runtrue_workflow_ir::SourceTrust::Trusted,
                normalized_event_digest: ContentDigest::sha256(b"event"),
                normalized_event_json: None,
                scm: None,
                event_context: BTreeMap::new(),
                lockfile_digest: None,
                workflow_frontend: None,
                policy_version_ids: vec!["policy-v1".to_owned()],
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
            expected_parity: ParityGrade::AExact,
        }
    }

    fn backend(observations: &Rc<RefCell<Observations>>) -> RecordingExecutor {
        RecordingExecutor {
            observations: Rc::clone(observations),
            fail_preflight: false,
        }
    }

    #[test]
    fn mixed_capsule_is_partitioned_and_each_step_uses_exact_isolation() {
        let native = Rc::new(RefCell::new(Observations::default()));
        let oci = Rc::new(RefCell::new(Observations::default()));
        let mut dispatcher = ExecutorDispatcher::new();
        dispatcher
            .register(Isolation::Native, backend(&native))
            .unwrap();
        dispatcher.register(Isolation::Oci, backend(&oci)).unwrap();

        let mut engine = Engine::new(dispatcher);
        let result = engine
            .execute(&capsule(vec![
                job("native", Isolation::Native),
                job("container", Isolation::Oci),
            ]))
            .unwrap();

        assert!(result.succeeded());
        assert_eq!(
            native.borrow().preflight_jobs,
            vec![vec!["native".to_owned()]]
        );
        assert_eq!(
            oci.borrow().preflight_jobs,
            vec![vec!["container".to_owned()]]
        );
        assert_eq!(native.borrow().executed_jobs, vec!["native"]);
        assert_eq!(oci.borrow().executed_jobs, vec!["container"]);
        assert_eq!(
            native.borrow().finalized_attempts,
            vec![("native".to_owned(), 1, JobAttemptOutcome::Succeeded)]
        );
        assert_eq!(
            oci.borrow().finalized_attempts,
            vec![("container".to_owned(), 1, JobAttemptOutcome::Succeeded)]
        );
    }

    #[test]
    fn missing_backend_rejects_the_complete_capsule_before_any_preflight() {
        let native = Rc::new(RefCell::new(Observations::default()));
        let mut dispatcher = ExecutorDispatcher::new();
        dispatcher
            .register(Isolation::Native, backend(&native))
            .unwrap();
        let error = dispatcher
            .preflight(&capsule(vec![
                job("native", Isolation::Native),
                job("wasm", Isolation::Wasm),
            ]))
            .unwrap_err();
        assert!(matches!(error, ExecutorError::UnsupportedIsolation(_)));
        assert!(native.borrow().preflight_jobs.is_empty());
    }

    #[test]
    fn registration_is_unique_and_unregistered_execution_never_falls_back() {
        let native = Rc::new(RefCell::new(Observations::default()));
        let mut dispatcher = ExecutorDispatcher::new();
        dispatcher
            .register(Isolation::Native, backend(&native))
            .unwrap();
        assert_eq!(
            dispatcher.register(Isolation::Native, backend(&native)),
            Err(DispatchConfigurationError::DuplicateBackend(
                Isolation::Native
            ))
        );

        let request = StepExecutionRequest {
            job_id: "job".to_owned(),
            step_id: "step".to_owned(),
            job_attempt: 1,
            runner: runner(Isolation::Wasm),
            action: PreparedAction::Command {
                program: "/bin/true".to_owned(),
                args: Vec::new(),
            },
            environment: BTreeMap::new(),
            working_directory: None,
            capabilities: StepCapabilitySet::default(),
            timeout_ms: None,
            cancellation: Default::default(),
        };
        assert!(matches!(
            dispatcher.execute(&request),
            Err(ExecutorError::UnsupportedIsolation(_))
        ));
        assert!(native.borrow().executed_jobs.is_empty());
    }
}
