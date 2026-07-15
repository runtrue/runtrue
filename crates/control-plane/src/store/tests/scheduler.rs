use super::*;

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
