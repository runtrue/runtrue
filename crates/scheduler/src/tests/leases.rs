use super::fixtures::{job, runner};
use crate::{Scheduler, SchedulerError};
use runtrue_model::ContentDigest;

#[test]
fn stale_generation_epoch_and_runner_are_fenced() {
    let mut scheduler = Scheduler::new(7);
    scheduler.register_runner(runner("runner")).unwrap();
    scheduler.enqueue(job("job", "tenant")).unwrap();
    let lease = scheduler.offer_for_runner("runner", 2).unwrap().unwrap();
    scheduler
        .decide_offer(&lease.id, "runner", lease.fencing_generation, true, 3)
        .unwrap();
    assert!(matches!(
        scheduler.heartbeat(&lease.id, "runner", 0, 7, 4),
        Err(SchedulerError::StaleGeneration { .. })
    ));
    assert!(matches!(
        scheduler.heartbeat(&lease.id, "runner", lease.fencing_generation, 6, 4),
        Err(SchedulerError::StaleInstallationEpoch { .. })
    ));
    assert_eq!(
        scheduler.heartbeat(&lease.id, "other", lease.fencing_generation, 7, 4),
        Err(SchedulerError::WrongRunner)
    );
}

#[test]
fn completion_is_idempotent_only_for_identical_result() {
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(runner("runner")).unwrap();
    scheduler.enqueue(job("job", "tenant")).unwrap();
    let lease = scheduler.offer_for_runner("runner", 2).unwrap().unwrap();
    scheduler
        .decide_offer(&lease.id, "runner", lease.fencing_generation, true, 3)
        .unwrap();
    let result = ContentDigest::sha256(b"result");
    scheduler
        .complete(
            &lease.id,
            "runner",
            lease.fencing_generation,
            1,
            result.clone(),
        )
        .unwrap();
    scheduler
        .complete(&lease.id, "runner", lease.fencing_generation, 1, result)
        .unwrap();
    assert_eq!(
        scheduler.complete(
            &lease.id,
            "runner",
            lease.fencing_generation,
            1,
            ContentDigest::sha256(b"other"),
        ),
        Err(SchedulerError::ConflictingCompletion)
    );
}

#[test]
fn restore_epoch_fences_every_old_lease() {
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(runner("runner")).unwrap();
    scheduler.enqueue(job("job", "tenant")).unwrap();
    let lease = scheduler.offer_for_runner("runner", 2).unwrap().unwrap();
    scheduler
        .decide_offer(&lease.id, "runner", lease.fencing_generation, true, 3)
        .unwrap();
    scheduler.restore_fencing_epoch(2).unwrap();
    assert!(matches!(
        scheduler.complete(
            &lease.id,
            "runner",
            lease.fencing_generation,
            1,
            ContentDigest::sha256(b"result"),
        ),
        Err(SchedulerError::StaleInstallationEpoch { .. })
    ));
}

#[test]
fn expired_retryable_lease_requeues_with_a_higher_generation() {
    let mut scheduler = Scheduler::new(1);
    scheduler.register_runner(runner("runner")).unwrap();
    scheduler.enqueue(job("job", "tenant")).unwrap();
    let first = scheduler.offer_for_runner("runner", 2).unwrap().unwrap();
    scheduler
        .decide_offer(&first.id, "runner", first.fencing_generation, true, 3)
        .unwrap();
    let expired = scheduler
        .expire(first.expires_unix_ms.saturating_add(1))
        .unwrap();
    assert_eq!(expired, vec![first.id]);

    let second = scheduler
        .offer_for_runner("runner", first.expires_unix_ms.saturating_add(2))
        .unwrap()
        .unwrap();
    assert_eq!(second.job_id, "job");
    assert!(second.fencing_generation > first.fencing_generation);
}
