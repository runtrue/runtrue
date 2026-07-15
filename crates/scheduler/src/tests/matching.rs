use super::fixtures::{job, runner};
use crate::{Scheduler, TenantQuota};
use runtrue_model::ContentDigest;

#[test]
fn self_reported_capabilities_never_satisfy_hard_filter() {
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(runner("runner")).unwrap();
    let mut queued = job("gpu-job", "tenant");
    queued.requirements.required_capabilities = ["gpu".to_owned()].into_iter().collect();
    scheduler.enqueue(queued).unwrap();
    assert_eq!(scheduler.offer_for_runner("runner", 2).unwrap(), None);
}

#[test]
fn empty_pool_allowlist_still_rejects_a_cross_tenant_runner() {
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(runner("runner")).unwrap();
    let mut queued = job("foreign-job", "other-tenant");
    queued.requirements.allowed_pools.clear();
    scheduler.enqueue(queued).unwrap();

    assert_eq!(scheduler.offer_for_runner("runner", 2).unwrap(), None);
}

#[test]
fn empty_pool_allowlist_accepts_a_same_tenant_runner() {
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(runner("runner")).unwrap();
    let mut queued = job("same-tenant-job", "tenant");
    queued.requirements.allowed_pools.clear();
    scheduler.enqueue(queued).unwrap();

    let lease = scheduler.offer_for_runner("runner", 2).unwrap().unwrap();
    assert_eq!(lease.tenant_id, "tenant");
}

#[test]
fn locality_is_only_a_tiebreaker_after_isolation_and_capabilities() {
    let wanted = ContentDigest::sha256(b"wanted");
    let mut warm = runner("warm");
    warm.locality.insert(wanted.clone());
    warm.verified_capabilities.clear();
    let cold = runner("cold");
    let mut queued = job("job", "tenant");
    queued.preferred_content.insert(wanted);
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(warm).unwrap();
    scheduler.register_runner(cold).unwrap();
    scheduler.enqueue(queued).unwrap();
    assert_eq!(scheduler.offer_for_runner("warm", 2).unwrap(), None);
    assert!(scheduler.offer_for_runner("cold", 2).unwrap().is_some());
}

#[test]
fn exact_ties_are_resolved_by_job_id() {
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(runner("runner")).unwrap();
    scheduler.enqueue(job("job-b", "tenant")).unwrap();
    scheduler.enqueue(job("job-a", "tenant")).unwrap();

    let lease = scheduler.offer_for_runner("runner", 2).unwrap().unwrap();
    assert_eq!(lease.job_id, "job-a");
}

#[test]
fn tenant_quota_blocks_until_the_active_job_releases() {
    let mut scheduler = Scheduler::new(1);
    scheduler
        .set_quota(
            "tenant",
            TenantQuota {
                maximum_running_jobs: 1,
                weight: 1,
            },
        )
        .unwrap();
    scheduler.register_runner(runner("runner-a")).unwrap();
    scheduler.register_runner(runner("runner-b")).unwrap();
    scheduler.enqueue(job("job-a", "tenant")).unwrap();
    scheduler.enqueue(job("job-b", "tenant")).unwrap();

    let first = scheduler.offer_for_runner("runner-a", 2).unwrap().unwrap();
    scheduler
        .decide_offer(&first.id, "runner-a", first.fencing_generation, true, 3)
        .unwrap();
    assert_eq!(scheduler.offer_for_runner("runner-b", 4).unwrap(), None);

    scheduler
        .complete(
            &first.id,
            "runner-a",
            first.fencing_generation,
            1,
            ContentDigest::sha256(b"result"),
        )
        .unwrap();
    assert!(scheduler.offer_for_runner("runner-b", 5).unwrap().is_some());
}
