use crate::{
    broker::RunnerBrokerClient,
    daemon::RunnerError,
    state::{PersistedCommittedObject, PersistedCommittedObjectKind},
};
use runtrue_engine::{CredentialTaint, StepState, StepStateObservation, StepStateObserver};
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::PlannedStep;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone, Default)]
pub(super) struct CredentialTaintState(Arc<AtomicBool>);

impl CredentialTaintState {
    pub(super) fn observe(&self, taint: CredentialTaint) {
        if taint.is_tainted() {
            self.0.store(true, Ordering::Release);
        }
    }

    pub(super) fn permits_publication(&self) -> bool {
        !self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub(crate) struct RemoteDataPlaneSession {
    pub(super) lease: AdmittedLease,
    pub(super) workspace: PathBuf,
    pub(super) broker: Arc<dyn RunnerBrokerClient>,
    pub(super) cache_entry_ids: Arc<Mutex<BTreeMap<String, u32>>>,
    pub(super) cache_breaker_open: Arc<AtomicBool>,
    pub(super) cache_bypassed_operations: Arc<AtomicU64>,
    pub(super) cache_miss_reason: Arc<Mutex<Option<&'static str>>>,
    pub(super) credential_taint: CredentialTaintState,
}

struct RemoteDataObserver {
    data: RemoteDataPlaneSession,
    lifecycle: Arc<dyn StepStateObserver>,
}

impl StepStateObserver for RemoteDataObserver {
    fn observe(&self, observation: &StepStateObservation) -> Result<(), String> {
        // Record taint before handling a terminal transition so the cache for
        // the credential-releasing step cannot be committed.
        self.data
            .credential_taint
            .observe(observation.credential_taint);
        if observation.to == StepState::Running {
            self.lifecycle.observe(observation)?;
            // Caches are an optimization: an unavailable, corrupt, stale, or
            // rejected entry is always a miss and cannot fail the workflow.
            if self
                .data
                .restore_cache(&observation.step_id, observation.job_attempt)
                .is_err()
            {
                self.data.cache_breaker_open.store(true, Ordering::Release);
                if let Ok(mut reason) = self.data.cache_miss_reason.lock() {
                    *reason = Some("cache_transfer_unavailable_or_unverified");
                }
            }
            return Ok(());
        }
        if observation.from == Some(StepState::Running)
            && observation.to == StepState::Succeeded
            && self
                .data
                .save_cache(&observation.step_id, observation.job_attempt)
                .is_err()
        {
            self.data.cache_breaker_open.store(true, Ordering::Release);
            if let Ok(mut reason) = self.data.cache_miss_reason.lock() {
                *reason = Some("cache_transfer_unavailable_or_unverified");
            }
        }
        self.lifecycle.observe(observation)
    }
}

impl RemoteDataPlaneSession {
    pub(crate) fn new(
        lease: &AdmittedLease,
        workspace: &Path,
        broker: Arc<dyn RunnerBrokerClient>,
    ) -> Self {
        Self {
            lease: lease.clone(),
            workspace: workspace.to_path_buf(),
            broker,
            cache_entry_ids: Arc::new(Mutex::new(BTreeMap::new())),
            cache_breaker_open: Arc::new(AtomicBool::new(false)),
            cache_bypassed_operations: Arc::new(AtomicU64::new(0)),
            cache_miss_reason: Arc::new(Mutex::new(None)),
            credential_taint: CredentialTaintState::default(),
        }
    }

    pub(crate) fn observer(
        &self,
        lifecycle: Arc<dyn StepStateObserver>,
    ) -> Arc<dyn StepStateObserver> {
        Arc::new(RemoteDataObserver {
            data: self.clone(),
            lifecycle,
        })
    }

    pub(crate) fn committed_cache_objects(
        &self,
    ) -> Result<Vec<PersistedCommittedObject>, RunnerError> {
        self.cache_entry_ids
            .lock()
            .map(|ids| {
                ids.iter()
                    .map(|(object_id, job_attempt)| PersistedCommittedObject {
                        kind: PersistedCommittedObjectKind::Cache,
                        object_id: object_id.clone(),
                        declaration_name: None,
                        job_attempt: *job_attempt,
                    })
                    .collect()
            })
            .map_err(|_| RunnerError::DataPlane("cache result state is poisoned".to_owned()))
    }

    pub(super) fn job(&self) -> Result<&runtrue_workflow_ir::PlannedJob, RunnerError> {
        self.lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == self.lease.job_id)
            .ok_or_else(|| RunnerError::OfferedJobMissing(self.lease.job_id.clone()))
    }

    pub(super) fn step(&self, step_id: &str) -> Result<&PlannedStep, RunnerError> {
        self.job()?
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .ok_or_else(|| RunnerError::DataPlane(format!("step `{step_id}` is absent")))
    }
}
