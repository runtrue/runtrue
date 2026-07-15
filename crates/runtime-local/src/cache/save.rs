use super::{
    copy_to_stage, relative_path, resolve_existing_exact, staging_directory, CopyBudget,
    LocalCacheConfig, PreparedCacheStep,
};
use runtrue_cache::{CacheIdentity, CacheProducer, CacheStore};
use runtrue_engine::StepExecutionRequest;
use runtrue_model::ContentDigest;
use std::fs;

pub(crate) fn save_outputs(
    store: &CacheStore,
    config: &LocalCacheConfig,
    step: &PreparedCacheStep,
    identity: &CacheIdentity,
    capsule_digest: &ContentDigest,
    request: &StepExecutionRequest,
    warnings: &mut Vec<String>,
) {
    let stage = match staging_directory(config) {
        Ok(stage) => stage,
        Err(error) => {
            warnings.push(format!("cache save staging is unavailable: {error}"));
            return;
        }
    };
    let mut budget = CopyBudget {
        bytes: 0,
        limit: step.max_size_bytes,
    };
    let mut captured = 0_usize;
    for relative in &step.declaration.outputs {
        let source = match resolve_existing_exact(&config.workspace, relative) {
            Ok(Some(source)) => source,
            Ok(None) => continue,
            Err(error) => {
                warnings.push(format!(
                    "cache output {relative} is unsafe or unavailable: {error}"
                ));
                return;
            }
        };
        let destination = stage.path().join(relative_path(relative));
        if let Some(parent) = destination.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                warnings.push(format!("cache output staging failed: {error}"));
                return;
            }
        }
        if let Err(error) = copy_to_stage(&source, &destination, &mut budget) {
            warnings.push(format!("cache output {relative} was not saved: {error}"));
            return;
        }
        captured += 1;
    }
    if captured == 0 {
        warnings.push("no declared cache output exists after the successful step".to_owned());
        return;
    }

    let expected = match store.inspect(identity) {
        Ok(expected) => expected,
        Err(error) => {
            warnings.push(format!("cache head is unavailable; save skipped: {error}"));
            return;
        }
    };
    let fencing_generation = expected
        .as_ref()
        .map_or(1, |entry| entry.head.fencing_generation.saturating_add(1));
    if fencing_generation == 0 {
        warnings.push("cache fencing generation overflow; save skipped".to_owned());
        return;
    }
    let producer = CacheProducer {
        capsule_digest: capsule_digest.clone(),
        job_id: request.job_id.clone(),
        step_id: request.step_id.clone(),
        lease_id: format!("local-attempt-{}", request.job_attempt),
    };
    if let Err(error) = store.commit_tree(
        &identity.trust_domain,
        identity.clone(),
        stage.path(),
        expected.as_ref().map(|entry| &entry.head),
        fencing_generation,
        producer,
    ) {
        warnings.push(format!("cache save is unavailable: {error}"));
    }
}
