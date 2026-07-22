use crate::{QueuedJob, RunnerRecord, SchedulerError, TenantQuota};

pub(crate) fn runner(runner: &RunnerRecord) -> Result<(), SchedulerError> {
    if runner.id.is_empty()
        || runner.tenant_id.is_empty()
        || runner.pool_id.is_empty()
        || runner.logical_cpus == 0
        || runner.max_concurrent_wasm_jobs == 0
        || runner.max_concurrent_wasm_jobs > 64
        || (runner.max_concurrent_wasm_jobs > 1
            && !runner
                .isolation_backends
                .contains(&runtrue_workflow_ir::Isolation::Wasm))
        || runner.active_wasm_jobs > runner.active_jobs
        || runner.active_wasm_jobs > runner.max_concurrent_wasm_jobs
        || runner.memory_bytes == 0
        || runner.storage_bytes == 0
        || runner.isolation_backends.is_empty()
    {
        return Err(SchedulerError::InvalidRunner);
    }
    Ok(())
}

pub(crate) fn job(job: &QueuedJob) -> Result<(), SchedulerError> {
    if job.id.is_empty()
        || job.tenant_id.is_empty()
        || job.repository_id.is_empty()
        || job.requirements.cpu == 0
        || job.requirements.memory_bytes == 0
    {
        return Err(SchedulerError::InvalidJob);
    }
    Ok(())
}

pub(crate) fn quota(quota: TenantQuota) -> Result<(), SchedulerError> {
    if quota.maximum_running_jobs == 0 || quota.weight == 0 {
        return Err(SchedulerError::InvalidQuota);
    }
    Ok(())
}
