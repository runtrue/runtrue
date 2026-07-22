use super::*;

fn add_component_step(job: &mut PlannedJob, reference: String) {
    job.steps.push(PlannedStep {
        id: "component".to_owned(),
        name: "component".to_owned(),
        condition: None,
        action: StepAction::Component { reference },
        inputs: BTreeMap::new(),
        environment: BTreeMap::new(),
        capabilities: StepCapabilitySet::default(),
        cache: None,
        timeout_ms: None,
        continue_on_error: false,
        outputs: BTreeMap::new(),
        working_directory: None,
    });
}

#[test]
fn source_snapshot_digest_contributes_to_runner_locality() {
    let job = planned_job(
        "build",
        &[],
        Trust::UntrustedOk,
        OperatingSystem::Linux,
        None,
    );
    let source = ContentDigest::sha256(b"source snapshot");
    assert_eq!(
        signed_job_locality_hits(&job, Some(&source), &BTreeSet::from([source.clone()])),
        1
    );
    assert_eq!(
        signed_job_locality_hits(
            &job,
            Some(&source),
            &BTreeSet::from([ContentDigest::sha256(b"other snapshot")]),
        ),
        0
    );
}

#[test]
fn signed_component_digest_contributes_to_runner_locality() {
    let mut job = planned_job(
        "wasm",
        &[],
        Trust::UntrustedOk,
        OperatingSystem::Linux,
        None,
    );
    let component = ContentDigest::sha256(b"prepared wasm component");
    add_component_step(
        &mut job,
        format!("wasm://registry.example/action@{component}"),
    );
    assert_eq!(
        signed_job_locality_hits(&job, None, &BTreeSet::from([component])),
        1
    );
}

#[test]
fn signed_component_digest_uses_the_advertised_package_tier() {
    let component = ContentDigest::sha256(b"component");
    let mut job = planned_job(
        "wasm-tier",
        &[],
        Trust::UntrustedOk,
        OperatingSystem::Linux,
        None,
    );
    add_component_step(
        &mut job,
        format!("wasm://registry.example/action@{component}"),
    );
    assert_eq!(
        signed_job_package_tier(
            &job,
            None,
            &BTreeMap::from([(component, runtrue_scheduler::PackagePreparationTier::Warm,)]),
        ),
        runtrue_scheduler::PackagePreparationTier::Warm.placement_rank()
    );
}

#[test]
fn signed_concurrency_group_serializes_across_runs_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("concurrency.sqlite");
    let control = ControlPlane::open(&path, "concurrency", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    add_runner(&control);
    add_runner_to_existing_pool(&control, "runner-2");
    let mut decoded = execution_capsule();
    decoded.jobs = vec![planned_job(
        "deploy",
        &[],
        Trust::UntrustedOk,
        OperatingSystem::Linux,
        Some("production"),
    )];
    let capsule = store_test_capsule(&control, "capsule-concurrency", decoded.clone());
    for (run, at) in [("run-a", NOW), ("run-b", NOW + 1)] {
        let request = run_for_capsule(run, &capsule, &decoded, at);
        control
            .create_run_idempotent(&format!("{run}-key"), &request)
            .unwrap();
    }
    let first = control
        .offer_next_lease_for_runner("runner-1", NOW + 2)
        .unwrap()
        .unwrap();
    assert_eq!(first.job_id, "run-a-deploy");
    assert!(control
        .offer_next_lease_for_runner("runner-2", NOW + 2)
        .unwrap()
        .is_none());
    let active = control
        .accept_lease(
            &first.id,
            "runner-1",
            first.fencing_generation,
            first.installation_fencing_epoch,
            NOW + 3,
        )
        .unwrap();
    drop(control);

    let reopened = ControlPlane::open(&path, "concurrency", NOW + 4).unwrap();
    assert!(reopened
        .offer_next_lease_for_runner("runner-2", NOW + 4)
        .unwrap()
        .is_none());
    reopened
        .transition_job_state("run-a-deploy", JobState::Running, NOW + 5)
        .unwrap();
    reopened
        .transition_job_state("run-a-deploy", JobState::Finalizing, NOW + 6)
        .unwrap();
    reopened
        .complete_lease(
            &active.id,
            "runner-1",
            active.fencing_generation,
            active.installation_fencing_epoch,
            &ContentDigest::sha256(b"done"),
            JobState::Succeeded,
            NOW + 7,
        )
        .unwrap();
    let second = reopened
        .offer_next_lease_for_runner("runner-2", NOW + 8)
        .unwrap()
        .unwrap();
    assert_eq!(second.job_id, "run-b-deploy");
}

#[test]
fn exhausted_concurrency_head_fails_and_releases_the_next_run() {
    let control = ControlPlane::open_in_memory("exhausted-concurrency", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    add_runner(&control);
    let mut decoded = execution_capsule();
    decoded.jobs = vec![planned_job(
        "deploy",
        &[],
        Trust::UntrustedOk,
        OperatingSystem::Linux,
        Some("production"),
    )];
    let capsule = store_test_capsule(&control, "capsule-exhausted", decoded.clone());
    for (run, at) in [("run-a", NOW), ("run-b", NOW + 1)] {
        control
            .create_run_idempotent(
                &format!("{run}-key"),
                &run_for_capsule(run, &capsule, &decoded, at),
            )
            .unwrap();
    }

    for attempt in 0..MAX_RUNNER_JOB_REJECTIONS {
        let at = NOW + 2 + attempt * 2;
        let lease = control
            .offer_next_lease_for_runner("runner-1", at)
            .unwrap()
            .expect("the concurrency head should be retried within its bound");
        assert_eq!(lease.job_id, "run-a-deploy");
        control
            .reject_lease_with_code(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                "executor_preflight_rejected",
                at + 1,
            )
            .unwrap();
    }

    let next = control
        .offer_next_lease_for_runner("runner-1", NOW + 20)
        .unwrap()
        .expect("terminal reconciliation must release the concurrency group");
    assert_eq!(next.job_id, "run-b-deploy");
    assert_eq!(
        control.jobs_for_run("run-a").unwrap()[0].status,
        JobState::BlockedPolicy
    );
    assert_eq!(control.run("run-a").unwrap().status, RunState::Failed);
}

#[test]
fn one_exhausted_runner_does_not_fail_a_job_accepted_by_another_runner() {
    let control = ControlPlane::open_in_memory("multi-runner-rejection", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    add_runner(&control);
    add_runner_to_existing_pool(&control, "runner-2");
    let decoded = execution_capsule();
    let capsule = store_test_capsule(&control, "capsule-multi-runner", decoded.clone());
    control
        .create_run_idempotent(
            "run-multi-key",
            &run_for_capsule("run-multi", &capsule, &decoded, NOW),
        )
        .unwrap();

    for attempt in 0..MAX_RUNNER_JOB_REJECTIONS {
        let at = NOW + 1 + attempt * 2;
        let lease = control
            .offer_next_lease_for_runner("runner-1", at)
            .unwrap()
            .unwrap();
        control
            .reject_lease_with_code(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                "executor_preflight_rejected",
                at + 1,
            )
            .unwrap();
    }
    assert!(control
        .offer_next_lease_for_runner("runner-1", NOW + 20)
        .unwrap()
        .is_none());
    let second_runner = control
        .offer_next_lease_for_runner("runner-2", NOW + 21)
        .unwrap()
        .expect("another structurally eligible runner must still receive the job");
    assert_eq!(second_runner.job_id, "run-multi-build");
}

#[test]
fn bounded_selector_rotates_past_incompatible_pages_and_uses_random_fences() {
    let control = ControlPlane::open_in_memory("scheduler-page", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    add_runner(&control);
    let mut decoded = execution_capsule();
    decoded.jobs = (0..128)
        .map(|index| {
            planned_job(
                &format!("a{index:03}"),
                &[],
                Trust::UntrustedOk,
                OperatingSystem::Macos,
                None,
            )
        })
        .chain(std::iter::once(planned_job(
            "z-compatible",
            &[],
            Trust::UntrustedOk,
            OperatingSystem::Linux,
            None,
        )))
        .collect();
    let capsule = store_test_capsule(&control, "capsule-page", decoded.clone());
    let request = run_for_capsule("run-page", &capsule, &decoded, NOW);
    control
        .create_run_idempotent("run-page-key", &request)
        .unwrap();
    assert!(control
        .offer_next_lease_for_runner("runner-1", NOW + 1)
        .unwrap()
        .is_none());
    let lease = control
        .offer_next_lease_for_runner("runner-1", NOW + 2)
        .unwrap()
        .unwrap();
    assert!(lease.id.starts_with("lease-"));
    assert_eq!(lease.job_id, "run-page-z-compatible");
    assert_eq!(lease.fencing_generation, 1);
}

#[test]
fn durable_scheduler_packs_wasm_leases_up_to_runner_slot_capacity() {
    let control = ControlPlane::open_in_memory("wasm-slot-capacity", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    add_runner_pool_only(&control);
    let mut wasm_runner = runner();
    wasm_runner.isolation_backends = BTreeSet::from([Isolation::Wasm]);
    wasm_runner.max_concurrent_wasm_jobs = 2;
    wasm_runner.verified_capabilities.clear();
    control
        .register_runner_with_inventory(
            &wasm_runner,
            &ContentDigest::sha256(b"wasm-slot-runner-inventory"),
            NOW,
        )
        .unwrap();

    let mut decoded = execution_capsule();
    decoded.jobs[0].runner.isolation = Isolation::Wasm;
    decoded.jobs[0].runner.capabilities.clear();
    let capsule = store_test_capsule(&control, "capsule-wasm-slots", decoded.clone());
    for index in 1..=3 {
        let run_id = format!("run-wasm-{index}");
        let request = run_for_capsule(&run_id, &capsule, &decoded, NOW + index);
        control
            .create_run_idempotent(&format!("{run_id}-key"), &request)
            .unwrap();
    }

    let first = control
        .offer_next_lease_for_runner(&wasm_runner.id, NOW + 10)
        .unwrap()
        .unwrap();
    control
        .accept_lease(
            &first.id,
            &wasm_runner.id,
            first.fencing_generation,
            first.installation_fencing_epoch,
            NOW + 11,
        )
        .unwrap();
    let second = control
        .offer_next_lease_for_runner(&wasm_runner.id, NOW + 12)
        .unwrap()
        .unwrap();
    assert_ne!(first.job_id, second.job_id);
    control
        .accept_lease(
            &second.id,
            &wasm_runner.id,
            second.fencing_generation,
            second.installation_fencing_epoch,
            NOW + 13,
        )
        .unwrap();
    assert!(control
        .offer_next_lease_for_runner(&wasm_runner.id, NOW + 14)
        .unwrap()
        .is_none());
}
