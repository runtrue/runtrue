use crate::{quota, resources, QueuedJob, RunnerRecord, RunnerStatus, TenantQuota};
use std::cmp::Reverse;

pub(crate) type ScoreKey = (u64, Reverse<i64>, Reverse<usize>, u32, String);

pub(crate) fn passes_hard_filters(
    job: &QueuedJob,
    runner: &RunnerRecord,
    quota: TenantQuota,
    running: u32,
) -> bool {
    runner.status == RunnerStatus::Online
        && runner.tenant_id == job.tenant_id
        && quota::has_capacity(quota, running)
        && job.requirements.os == runner.os
        && job.requirements.arch == runner.arch
        && runner
            .isolation_backends
            .contains(&job.requirements.isolation)
        && (job.requirements.allowed_pools.is_empty()
            || job.requirements.allowed_pools.contains(&runner.pool_id))
        && job
            .requirements
            .region
            .as_ref()
            .is_none_or(|region| runner.region.as_ref() == Some(region))
        && job
            .requirements
            .required_capabilities
            .is_subset(&runner.verified_capabilities)
        && resources::available(runner, &job.requirements)
}

pub(crate) fn score(
    job: &QueuedJob,
    runner: &RunnerRecord,
    quota: TenantQuota,
    running: u32,
    now_unix_ms: u64,
    priority_aging_interval_ms: u64,
) -> ScoreKey {
    let fair_share = quota::fair_share(quota, running);
    let age = now_unix_ms.saturating_sub(job.queued_unix_ms) / priority_aging_interval_ms;
    let effective_priority =
        i64::from(job.priority).saturating_add(i64::try_from(age).unwrap_or(i64::MAX));
    let locality_hits = job.preferred_content.intersection(&runner.locality).count();
    (
        fair_share,
        Reverse(effective_priority),
        Reverse(locality_hits),
        runner.active_jobs,
        job.id.clone(),
    )
}
