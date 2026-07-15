use crate::{RunnerRecord, SchedulingRequirements};

pub(crate) fn available(runner: &RunnerRecord, requirements: &SchedulingRequirements) -> bool {
    requirements.cpu <= runner.logical_cpus.saturating_sub(runner.used_cpus)
        && requirements.memory_bytes <= runner.memory_bytes.saturating_sub(runner.used_memory_bytes)
        && requirements.storage_bytes
            <= runner
                .storage_bytes
                .saturating_sub(runner.used_storage_bytes)
}

pub(crate) fn reserve(runner: &mut RunnerRecord, requirements: &SchedulingRequirements) {
    runner.active_jobs = runner.active_jobs.saturating_add(1);
    runner.used_cpus = runner.used_cpus.saturating_add(requirements.cpu);
    runner.used_memory_bytes = runner
        .used_memory_bytes
        .saturating_add(requirements.memory_bytes);
    runner.used_storage_bytes = runner
        .used_storage_bytes
        .saturating_add(requirements.storage_bytes);
}

pub(crate) fn release(runner: &mut RunnerRecord, requirements: Option<&SchedulingRequirements>) {
    runner.active_jobs = runner.active_jobs.saturating_sub(1);
    if let Some(requirements) = requirements {
        runner.used_cpus = runner.used_cpus.saturating_sub(requirements.cpu);
        runner.used_memory_bytes = runner
            .used_memory_bytes
            .saturating_sub(requirements.memory_bytes);
        runner.used_storage_bytes = runner
            .used_storage_bytes
            .saturating_sub(requirements.storage_bytes);
    }
}

pub(crate) fn reset(runner: &mut RunnerRecord) {
    runner.active_jobs = 0;
    runner.used_cpus = 0;
    runner.used_memory_bytes = 0;
    runner.used_storage_bytes = 0;
}
