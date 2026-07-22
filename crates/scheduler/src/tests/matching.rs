use super::fixtures::{job, runner};
use crate::{PackagePreparationTier, Scheduler, TenantQuota};
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
fn observed_offer_reports_hard_filters_and_locality_without_changing_selection() {
    let wanted = ContentDigest::sha256(b"prepared-package");
    let mut available = runner("runner");
    available.locality.insert(wanted.clone());
    let mut preferred = job("preferred", "tenant");
    preferred.preferred_content.insert(wanted);
    let mut incompatible = job("incompatible", "tenant");
    incompatible.requirements.region = Some("eu-west".to_owned());

    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(available).unwrap();
    scheduler.enqueue(incompatible).unwrap();
    scheduler.enqueue(preferred).unwrap();

    let observed = scheduler.offer_for_runner_observed("runner", 2).unwrap();
    assert_eq!(observed.lease.as_ref().unwrap().job_id, "preferred");
    assert_eq!(observed.placement.queued_jobs, 2);
    assert_eq!(observed.placement.compatible_jobs, 1);
    assert_eq!(
        observed
            .placement
            .selected_score
            .as_ref()
            .unwrap()
            .preferred_content_hits,
        1
    );
}

#[test]
fn warmer_package_tier_breaks_an_otherwise_equal_job_tie() {
    let warm_digest = ContentDigest::sha256(b"warm");
    let warmish_digest = ContentDigest::sha256(b"warmish");
    let mut available = runner("runner");
    available
        .locality
        .extend([warm_digest.clone(), warmish_digest.clone()]);
    available
        .package_tiers
        .insert(warm_digest.clone(), PackagePreparationTier::Warm);
    available
        .package_tiers
        .insert(warmish_digest.clone(), PackagePreparationTier::Warmish);
    let mut warm_job = job("job-z", "tenant");
    warm_job.preferred_content.insert(warm_digest);
    let mut warmish_job = job("job-a", "tenant");
    warmish_job.preferred_content.insert(warmish_digest);

    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(available).unwrap();
    scheduler.enqueue(warmish_job).unwrap();
    scheduler.enqueue(warm_job).unwrap();
    let observed = scheduler.offer_for_runner_observed("runner", 2).unwrap();
    assert_eq!(observed.lease.unwrap().job_id, "job-z");
    assert_eq!(
        observed
            .placement
            .selected_score
            .unwrap()
            .preferred_package_tier,
        PackagePreparationTier::Warm.placement_rank()
    );
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
