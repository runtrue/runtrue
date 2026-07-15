use super::{
    build_identity, declared_input_digest, open_store, prepare_capsule, restore_outputs,
    save_outputs, LocalCacheConfig, LocalCacheWarning, PreparedCapsule,
};
use runtrue_cache::CacheStore;
use runtrue_engine::{
    Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, StepExecutionRequest,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{ExecutionCapsule, PlannedJob};
use std::{cell::RefCell, collections::BTreeSet};

pub struct LocalCacheExecutor<E> {
    inner: E,
    config: LocalCacheConfig,
    store: Option<CacheStore>,
    store_error: Option<String>,
    prepared: RefCell<Option<PreparedCapsule>>,
    warnings: Vec<LocalCacheWarning>,
    cache_references: BTreeSet<ContentDigest>,
}

impl<E> LocalCacheExecutor<E> {
    #[must_use]
    pub fn new(inner: E, config: LocalCacheConfig) -> Self {
        Self {
            inner,
            config,
            store: None,
            store_error: None,
            prepared: RefCell::new(None),
            warnings: Vec::new(),
            cache_references: BTreeSet::new(),
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

    #[must_use]
    pub fn warnings(&self) -> &[LocalCacheWarning] {
        &self.warnings
    }

    pub fn take_warnings(&mut self) -> Vec<LocalCacheWarning> {
        std::mem::take(&mut self.warnings)
    }

    #[must_use]
    pub fn cache_references(&self) -> Vec<ContentDigest> {
        self.cache_references.iter().cloned().collect()
    }

    fn ensure_store(&mut self) {
        if self.store.is_some() || self.store_error.is_some() {
            return;
        }
        match open_store(&self.config) {
            Ok(store) => self.store = Some(store),
            Err(error) => self.store_error = Some(error),
        }
    }
}

fn attach_warnings(output: &mut ExecutorOutput, job_id: &str, step_id: &str, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    if !output.stderr.is_empty() && !output.stderr.ends_with('\n') {
        output.stderr.push('\n');
    }
    for warning in warnings {
        output.stderr.push_str(&format!(
            "runtrue cache warning [{job_id}.{step_id}]: {warning}\n"
        ));
    }
}

impl<E: Executor> Executor for LocalCacheExecutor<E> {
    fn preflight(&self, capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        self.prepared.replace(None);
        self.inner.preflight(capsule)?;
        let prepared = prepare_capsule(capsule, &self.config).map_err(|message| {
            ExecutorError::UnsupportedCapsuleFeature(format!("local cache: {message}"))
        })?;
        self.prepared.replace(Some(prepared));
        Ok(())
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        let (capsule_digest, cache_step) = {
            let prepared = self.prepared.get_mut().as_ref().ok_or_else(|| {
                ExecutorError::UnsupportedCapsuleFeature(
                    "local cache wrapper has not completed preflight".to_owned(),
                )
            })?;
            let key = (request.job_id.clone(), request.step_id.clone());
            if !prepared.known_steps.contains(&key) {
                return Err(ExecutorError::UnsupportedCapsuleFeature(format!(
                    "execution request {}.{} is absent from the preflighted capsule",
                    request.job_id, request.step_id
                )));
            }
            (
                prepared.capsule_digest.clone(),
                prepared.cache_steps.get(&key).cloned(),
            )
        };

        let Some(cache_step) = cache_step else {
            return self.inner.execute(request);
        };

        // Store creation is delayed until after the entire executor stack has
        // passed preflight, so rejected capsules cannot mutate local cache state.
        self.ensure_store();
        let mut step_warnings = Vec::new();
        let mut identity = None;
        if let Some(store) = self.store.as_ref() {
            match declared_input_digest(
                &self.config.workspace,
                &cache_step.declaration.inputs,
                self.config.cas_limits,
            ) {
                Ok(input_digest) => {
                    let cache_identity =
                        build_identity(&self.config, &capsule_digest, &cache_step, input_digest);
                    match cache_identity.digest(self.config.cache_limits) {
                        Ok(reference) => {
                            self.cache_references.insert(reference);
                            if cache_step.read {
                                restore_outputs(
                                    store,
                                    &self.config,
                                    &cache_step,
                                    &cache_identity,
                                    &mut step_warnings,
                                )?;
                            }
                            identity = Some(cache_identity);
                        }
                        Err(error) => step_warnings.push(format!(
                            "cache identity is unavailable; treating as a miss: {error}"
                        )),
                    }
                }
                Err(error) => step_warnings.push(format!(
                    "declared inputs are unavailable; treating cache as a miss: {error}"
                )),
            }
        } else {
            step_warnings.push(format!(
                "local cache store is unavailable; treating cache as a miss: {}",
                self.store_error
                    .as_deref()
                    .unwrap_or("unknown initialization error")
            ));
        }

        let mut output = self.inner.execute(request)?;
        if output.succeeded() && cache_step.write {
            if let (Some(store), Some(identity)) = (self.store.as_ref(), identity) {
                save_outputs(
                    store,
                    &self.config,
                    &cache_step,
                    &identity,
                    &capsule_digest,
                    request,
                    &mut step_warnings,
                );
            }
        }

        attach_warnings(
            &mut output,
            &request.job_id,
            &request.step_id,
            &step_warnings,
        );
        self.warnings
            .extend(step_warnings.into_iter().map(|message| LocalCacheWarning {
                job_id: request.job_id.clone(),
                step_id: request.step_id.clone(),
                message,
            }));
        Ok(output)
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
