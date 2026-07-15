use super::{
    capture_one_artifact, new_local_lease_id, open_artifact_runtime, prepare_artifacts,
    LocalArtifactCapture, LocalArtifactConfig,
};
use crate::LocalArtifactError;
use runtrue_artifacts::{
    ArtifactClassification as StoredArtifactClassification, ArtifactHandle, ArtifactStore,
};
use runtrue_attest::CapsuleSigningKey;
use runtrue_engine::{
    ExecutionResult, Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, JobState,
    StepExecutionRequest,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{Architecture, ExecutionCapsule, OperatingSystem, PlannedJob};
use std::{cell::RefCell, collections::BTreeMap, path::Path};

/// Executor decorator that validates durable outputs before execution and
/// captures them only after the engine reports their job as successful.
pub struct LocalArtifactExecutor<E> {
    inner: E,
    config: LocalArtifactConfig,
    pub(crate) state: RefCell<LocalArtifactState>,
}

pub(crate) struct LocalArtifactState {
    pub(crate) prepared: Option<PreparedArtifacts>,
    pub(crate) store: Option<ArtifactStore>,
    pub(crate) signing_key: Option<CapsuleSigningKey>,
    pub(crate) lease_id: Option<String>,
    pub(crate) captured: bool,
    pub(crate) captures: Vec<LocalArtifactCapture>,
}

impl<E> LocalArtifactExecutor<E> {
    #[must_use]
    pub fn new(inner: E, config: LocalArtifactConfig) -> Self {
        Self {
            inner,
            config,
            state: RefCell::new(LocalArtifactState {
                prepared: None,
                store: None,
                signing_key: None,
                lease_id: None,
                captured: false,
                captures: Vec::new(),
            }),
        }
    }

    #[must_use]
    pub fn inner(&self) -> &E {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut E {
        &mut self.inner
    }

    pub fn into_inner(self) -> E {
        self.inner
    }

    /// Returns every artifact whose ticket was durably claimed during the
    /// current execution, including captures completed before a later output
    /// failed.
    #[must_use]
    pub fn captured_artifacts(&self) -> Vec<LocalArtifactCapture> {
        self.state.borrow().captures.clone()
    }

    pub fn capture_successful_jobs(
        &mut self,
        capsule: &ExecutionCapsule,
        result: &ExecutionResult,
    ) -> Result<Vec<LocalArtifactCapture>, LocalArtifactError> {
        let state = self.state.get_mut();
        let prepared = state
            .prepared
            .as_ref()
            .ok_or(LocalArtifactError::NotPreflighted)?
            .clone();
        if capsule
            .digest()
            .map_err(|_| LocalArtifactError::CapsuleMismatch)?
            != prepared.capsule_digest
        {
            return Err(LocalArtifactError::CapsuleMismatch);
        }
        if state.captured {
            return Err(LocalArtifactError::AlreadyCaptured);
        }
        state.captured = true;
        if prepared.jobs.is_empty() {
            return Ok(Vec::new());
        }
        // Validate the result envelope before the first durable side effect so
        // a malformed/incomplete engine result cannot cause a partial batch.
        for job_id in prepared.jobs.keys() {
            if !result.jobs.contains_key(job_id) {
                return Err(LocalArtifactError::MissingJob(job_id.clone()));
            }
        }
        let store = state
            .store
            .as_ref()
            .ok_or(LocalArtifactError::NotPreflighted)?;
        let signing_key = state
            .signing_key
            .as_ref()
            .ok_or(LocalArtifactError::NotPreflighted)?;
        let lease_id = state
            .lease_id
            .as_deref()
            .ok_or(LocalArtifactError::NotPreflighted)?;
        let mut captures = Vec::new();
        for (job_id, outputs) in &prepared.jobs {
            let job_result = result
                .jobs
                .get(job_id)
                .ok_or_else(|| LocalArtifactError::MissingJob(job_id.clone()))?;
            if job_result.state != JobState::Succeeded {
                continue;
            }
            for output in outputs {
                let capture = capture_one_artifact(
                    store,
                    signing_key,
                    &self.config,
                    capsule,
                    &prepared.capsule_digest,
                    output,
                    lease_id,
                )
                .map_err(|message| {
                    state.captures = captures.clone();
                    LocalArtifactError::Capture {
                        job_id: output.job_id.clone(),
                        output_name: output.name.clone(),
                        message,
                        committed: captures.clone(),
                    }
                })?;
                captures.push(capture);
            }
        }
        state.captures.clone_from(&captures);
        Ok(captures)
    }

    pub fn materialize_artifact(
        &self,
        artifact_id: &ContentDigest,
        destination: impl AsRef<Path>,
    ) -> Result<ArtifactHandle, LocalArtifactError> {
        let state = self.state.borrow();
        let store = state
            .store
            .as_ref()
            .ok_or(LocalArtifactError::NotPreflighted)?;
        store
            .materialize(artifact_id, destination)
            .map_err(|error| LocalArtifactError::Materialize(error.to_string()))
    }
}

impl<E: Executor> Executor for LocalArtifactExecutor<E> {
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        self.state.replace(LocalArtifactState {
            prepared: None,
            store: None,
            signing_key: None,
            lease_id: None,
            captured: false,
            captures: Vec::new(),
        });

        // Artifact validation is pure and happens before any local state is
        // created. The entire inner executor stack then retains veto power.
        let prepared = prepare_artifacts(capsule, &self.config).map_err(|message| {
            ExecutorError::UnsupportedCapsuleFeature(format!("local artifacts: {message}"))
        })?;
        self.inner.preflight(capsule)?;

        let (store, signing_key, lease_id) = if prepared.jobs.is_empty() {
            (None, None, None)
        } else {
            let (store, signing_key) = open_artifact_runtime(&self.config).map_err(|message| {
                ExecutorError::UnsupportedCapsuleFeature(format!(
                    "local artifact initialization failed: {message}"
                ))
            })?;
            let lease_id = new_local_lease_id().map_err(|message| {
                ExecutorError::UnsupportedCapsuleFeature(format!(
                    "local artifact initialization failed: {message}"
                ))
            })?;
            (Some(store), Some(signing_key), Some(lease_id))
        };
        self.state.replace(LocalArtifactState {
            prepared: Some(prepared),
            store,
            signing_key,
            lease_id,
            captured: false,
            captures: Vec::new(),
        });
        Ok(())
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        self.inner.execute(request)
    }

    fn finish_job_attempt(
        &mut self,
        job: &PlannedJob,
        attempt: u32,
        outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        self.inner.finish_job_attempt(job, attempt, outcome)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedArtifacts {
    pub(crate) capsule_digest: ContentDigest,
    pub(crate) jobs: BTreeMap<String, Vec<PreparedArtifact>>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedArtifact {
    pub(crate) job_id: String,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) classification: StoredArtifactClassification,
    pub(crate) retention_seconds: u64,
    pub(crate) runner_os: OperatingSystem,
    pub(crate) runner_architecture: Architecture,
}
