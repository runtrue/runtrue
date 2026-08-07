use super::*;

#[test]
fn image_admission_rejection_is_retryable() {
    assert!(transient_runner_rejection("image_admission_pending"));
    assert!(!transient_runner_rejection(
        "wasm_component_assignment_missing"
    ));

    let control = ControlPlane::open_in_memory("image-admission-retry", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    control
        .create_run_idempotent(
            "image-admission-run-key",
            &run_request("image-admission-run", "image-admission-job"),
        )
        .unwrap();

    let mut offer_at = NOW + 1;
    for _ in 0..4 {
        let lease = control
            .offer_next_lease_for_runner("runner-1", offer_at)
            .unwrap()
            .expect("image admission must remain retryable");
        control
            .reject_lease_with_code(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                "image_admission_pending",
                offer_at + 1,
            )
            .unwrap();
        assert!(control
            .offer_next_lease_for_runner("runner-1", offer_at + 1)
            .unwrap()
            .is_none());
        offer_at += IMAGE_ADMISSION_RETRY_DELAY_MILLIS + 1;
    }

    let lease = control
        .offer_next_lease_for_runner("runner-1", offer_at)
        .unwrap()
        .expect("admission retries must not consume normal rejection attempts");
    control
        .reject_lease_with_code(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            "executor_preflight_rejected",
            offer_at + 1,
        )
        .unwrap();
    assert!(control
        .offer_next_lease_for_runner("runner-1", offer_at + 2)
        .unwrap()
        .is_some());
}

#[test]
fn github_check_logs_are_always_present_bounded_and_markdown_safe() {
    let empty = render_check_logs(&[]);
    assert!(empty.contains("<strong>Logs</strong>"));
    assert!(empty.contains("did not write any stdout or stderr"));

    let frames = vec![
        (
            "test".to_owned(),
            "stderr".to_owned(),
            b"failure: expected true\n</details>".to_vec(),
        ),
        (
            "checkout".to_owned(),
            "stdout".to_owned(),
            b"checked out exact commit".to_vec(),
        ),
    ];
    let rendered = render_check_logs(&frames);
    assert!(rendered.contains("<details open>"));
    assert!(rendered.contains("[checkout · stdout]"));
    assert!(rendered.contains("[test · stderr]"));
    assert!(rendered.contains("    failure: expected true"));
    assert!(rendered.contains("    </details>"));

    let oversized = vec![(
        "test".to_owned(),
        "stderr".to_owned(),
        vec![b'x'; 96 * 1024],
    )];
    let rendered = render_check_logs(&oversized);
    assert!(rendered.contains("Log output was truncated"));
    assert!(rendered.len() < 60 * 1024);
}

#[test]
fn terminal_run_enqueues_detailed_idempotent_scm_check_revision() {
    let control = ControlPlane::open_in_memory("terminal-check", NOW).unwrap();
    bootstrap(&control);
    let mut capsule = execution_capsule();
    let template = capsule.jobs[0].clone();
    capsule.jobs = ["build", "lint", "test"]
        .into_iter()
        .map(|job_key| {
            let mut job = template.clone();
            job.id = job_key.to_owned();
            job.base_id = job_key.to_owned();
            job.name = job_key.to_owned();
            job
        })
        .collect();
    let signing_key = CapsuleSigningKey::from_seed([91; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    control
        .store_signed_capsule(
            &SignedCapsuleRecord {
                id: "capsule-multi-check".to_owned(),
                repository_id: "repo-1".to_owned(),
                digest: signature.capsule_digest.clone(),
                canonical_capsule: capsule.canonical_bytes().unwrap(),
                signature,
                created_unix_ms: NOW,
            },
            &signing_key.verifying_key(),
        )
        .unwrap();
    let mut request = run_request("run-check", "job-build");
    request.capsule_id = "capsule-multi-check".to_owned();
    request.remote = false;
    let requirements = request.jobs[0].requirements.clone();
    request.jobs = ["build", "lint", "test"]
        .into_iter()
        .map(|job_key| NewJob {
            id: format!("job-{job_key}"),
            job_key: job_key.to_owned(),
            attempt: 1,
            requirements: requirements.clone(),
        })
        .collect();
    control
        .create_run_idempotent("terminal-check-run", &request)
        .unwrap();
    for job_key in ["build", "lint", "test"] {
        control
            .enqueue_task(&DurableTask {
                id: format!("initial-check-task-{job_key}"),
                kind: "scm.check.publish".to_owned(),
                payload: serde_json::to_value(ScmCheckPublishTask {
                    publication_id: format!("initial-check-{job_key}"),
                    tenant_id: "tenant-1".to_owned(),
                    repository_id: "repo-1".to_owned(),
                    installation_id: "github-installation".to_owned(),
                    installation_external_id: "9001".to_owned(),
                    run_id: "run-check".to_owned(),
                    commit_sha: "a".repeat(40),
                    owner: "octo".to_owned(),
                    repository: "runtrue".to_owned(),
                    external_repository_id: "42".to_owned(),
                    logical_name: format!("job:job-{job_key}"),
                    external_id: format!("runtrue:run-check:job:job-{job_key}"),
                    check_name: format!("Runtrue / {job_key}"),
                    status: "queued".to_owned(),
                    conclusion: None,
                    title: "Runtrue job queued".to_owned(),
                    summary: format!("Job `{job_key}` was accepted and queued."),
                    render_markdown: false,
                    actions: Vec::new(),
                    trusted_base_workflow: true,
                })
                .unwrap(),
                status: DurableTaskStatus::Pending,
                available_unix_ms: NOW,
                attempts: 0,
                lease_owner: None,
                lease_expires_unix_ms: None,
                last_error: None,
                created_unix_ms: NOW,
                completed_unix_ms: None,
            })
            .unwrap();
    }
    control
        .transition_run_state("run-check", RunState::Running, NOW + 1)
        .unwrap();
    for (job_offset, job_key) in ["build", "lint", "test"].into_iter().enumerate() {
        for (state_offset, state) in [
            JobState::Preparing,
            JobState::Running,
            JobState::Finalizing,
            JobState::Succeeded,
        ]
        .into_iter()
        .enumerate()
        {
            control
                .transition_job_state(
                    &format!("job-{job_key}"),
                    state,
                    NOW + 2 + (job_offset * 10 + state_offset) as u64,
                )
                .unwrap();
        }
    }
    assert_eq!(
        control.run("run-check").unwrap().status,
        RunState::Succeeded
    );
    let connection = control.connection().unwrap();
    let mut statement = connection
        .prepare(
            "SELECT payload_json FROM durable_tasks
             WHERE kind = 'scm.check.publish'
               AND json_extract(payload_json, '$.logical_name') LIKE 'job-result:%'
             ORDER BY json_extract(payload_json, '$.check_name')",
        )
        .unwrap();
    let terminals = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|encoded| serde_json::from_str::<ScmCheckPublishTask>(&encoded.unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 3);
    assert_eq!(
        terminals
            .iter()
            .map(|terminal| terminal.check_name.as_str())
            .collect::<Vec<_>>(),
        vec!["Runtrue / build", "Runtrue / lint", "Runtrue / test"]
    );
    for terminal in terminals {
        assert!(terminal.external_id.starts_with("runtrue:run-check:job:"));
        assert_eq!(terminal.status, "completed");
        assert_eq!(terminal.conclusion.as_deref(), Some("success"));
        assert!(terminal.title.starts_with("✅ "));
        assert!(terminal.title.ends_with(" succeeded"));
        assert!(terminal.summary.contains("| **Workflow** | ci |"));
        assert!(terminal.summary.contains("| **Run** | `run-check` |"));
        assert!(terminal.summary.contains("| **Status** | **succeeded** |"));
        assert!(terminal.summary.contains("attempt 1"));
        let expected_duration = match terminal.check_name.as_str() {
            "Runtrue / build" => "| **Duration** | `4 ms` |",
            "Runtrue / lint" => "| **Duration** | `14 ms` |",
            "Runtrue / test" => "| **Duration** | `24 ms` |",
            name => panic!("unexpected terminal check {name}"),
        };
        assert!(terminal.summary.contains(expected_duration));
        assert!(terminal.summary.contains("<strong>Logs</strong>"));
        assert!(terminal
            .summary
            .contains("did not write any stdout or stderr"));
        assert!(terminal.render_markdown);
    }
}

#[test]
fn online_runner_locality_is_replaced_durably() {
    let control = ControlPlane::open_in_memory("runner-locality", NOW).unwrap();
    add_runner_pool_only(&control);
    control.register_runner(&runner(), NOW).unwrap();
    let first = BTreeSet::from([
        ContentDigest::sha256(b"source-a"),
        ContentDigest::sha256(b"source-b"),
    ]);
    let first_tiers = BTreeMap::from([(
        ContentDigest::sha256(b"source-a"),
        runtrue_scheduler::PackagePreparationTier::Warmish,
    )]);
    let updated = control
        .update_runner_locality("runner-1", &first, &first_tiers, NOW + 1)
        .unwrap();
    assert_eq!(updated.runner.locality, first);
    assert_eq!(updated.runner.package_tiers, first_tiers);
    let replacement = BTreeSet::from([ContentDigest::sha256(b"source-c")]);
    control
        .update_runner_locality("runner-1", &replacement, &BTreeMap::new(), NOW + 2)
        .unwrap();
    assert_eq!(
        control.runner("runner-1").unwrap().runner.locality,
        replacement
    );
    assert!(control
        .runner("runner-1")
        .unwrap()
        .runner
        .package_tiers
        .is_empty());

    let mut offline = control.runner("runner-1").unwrap().runner;
    offline.status = RunnerStatus::Offline;
    control.update_runner(&offline, NOW + 3).unwrap();
    assert!(matches!(
        control.update_runner_locality("runner-1", &BTreeSet::new(), &BTreeMap::new(), NOW + 4,),
        Err(ControlPlaneError::InvalidInput(_))
    ));
}

#[test]
fn offline_ephemeral_runner_without_lease_history_is_auto_removed() {
    let control = ControlPlane::open_in_memory("ephemeral-runner", NOW).unwrap();
    add_runner_pool_only(&control);
    let mut disposable = runner();
    disposable.ephemeral = true;
    disposable.status = RunnerStatus::Offline;
    control
        .register_runner_with_inventory(
            &disposable,
            &ContentDigest::sha256(b"ephemeral inventory"),
            NOW,
        )
        .unwrap();

    control
        .perform_scheduler_maintenance(NOW + DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS - 1)
        .unwrap();
    assert!(control.runner("runner-1").is_ok());

    control
        .perform_scheduler_maintenance(NOW + DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS)
        .unwrap();
    assert!(control.runner("runner-1").is_err());
}

#[test]
fn offline_persistent_runner_is_not_auto_removed() {
    let control = ControlPlane::open_in_memory("persistent-runner", NOW).unwrap();
    add_runner_pool_only(&control);
    let mut persistent = runner();
    persistent.status = RunnerStatus::Offline;
    control.register_runner(&persistent, NOW).unwrap();

    control
        .perform_scheduler_maintenance(NOW + DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS * 2)
        .unwrap();
    assert!(control.runner("runner-1").is_ok());
}

#[test]
fn offline_ephemeral_runner_with_lease_history_is_retired_from_fleet() {
    let control = ControlPlane::open_in_memory("ephemeral-runner-history", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    let mut disposable = control.runner("runner-1").unwrap().runner;
    disposable.ephemeral = true;
    control.update_runner(&disposable, NOW + 1).unwrap();
    control
        .create_run_idempotent(
            "ephemeral-history-run",
            &run_request("run-ephemeral-history", "job-ephemeral-history"),
        )
        .unwrap();
    let lease = control
        .offer_next_lease_for_runner("runner-1", NOW + 2)
        .unwrap()
        .unwrap();
    control
        .mark_runner_disconnected("runner-1", NOW + 3)
        .unwrap();

    control
        .perform_scheduler_maintenance(NOW + 3 + DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS)
        .unwrap();

    let retired = control.runner("runner-1").unwrap().runner;
    assert!(retired.retired);
    assert!(control
        .list_runners_for_tenant("tenant-1")
        .unwrap()
        .is_empty());
    assert!(control.lease(&lease.id).is_ok());
    assert!(control
        .mark_runner_connected("runner-1", NOW + 4 + DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS)
        .is_err());
}

#[test]
fn ephemeral_runner_never_receives_a_second_lease() {
    let control = ControlPlane::open_in_memory("ephemeral-single-use", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    let mut disposable = control.runner("runner-1").unwrap().runner;
    disposable.ephemeral = true;
    control.update_runner(&disposable, NOW + 1).unwrap();
    control
        .create_run_idempotent(
            "ephemeral-first-run-key",
            &run_request("run-ephemeral-first", "job-ephemeral-first"),
        )
        .unwrap();
    control
        .create_run_idempotent(
            "ephemeral-second-run-key",
            &run_request("run-ephemeral-second", "job-ephemeral-second"),
        )
        .unwrap();

    let offered = control
        .offer_next_lease_for_runner("runner-1", NOW + 2)
        .unwrap()
        .unwrap();
    let repeated = control
        .offer_next_lease_for_runner("runner-1", NOW + 3)
        .unwrap()
        .unwrap();
    assert_eq!(repeated.id, offered.id);
    control
        .accept_lease(
            &offered.id,
            "runner-1",
            offered.fencing_generation,
            offered.installation_fencing_epoch,
            NOW + 4,
        )
        .unwrap();

    assert!(control
        .offer_next_lease_for_runner("runner-1", NOW + 5)
        .unwrap()
        .is_none());
    let queued = ["run-ephemeral-first", "run-ephemeral-second"]
        .into_iter()
        .flat_map(|run_id| control.jobs_for_run(run_id).unwrap())
        .filter(|job| job.status == JobState::Queued)
        .count();
    assert_eq!(queued, 1);
}

#[test]
fn offline_ephemeral_runner_with_fleet_history_is_retired_from_fleet() {
    let control = ControlPlane::open_in_memory("ephemeral-runner-fleet-history", NOW).unwrap();
    add_runner_pool_only(&control);
    let mut disposable = runner();
    disposable.ephemeral = true;
    disposable.status = RunnerStatus::Offline;
    control
        .register_runner_with_inventory(
            &disposable,
            &ContentDigest::sha256(b"ephemeral fleet inventory"),
            NOW,
        )
        .unwrap();
    control
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO runner_fleet_requests
             (id,pool_id,runtime_compatibility_digest,provider,
              provider_template_id,runner_template_digest,state,runner_id,
              created_unix_ms,updated_unix_ms)
             VALUES('fleet-history','pool-1',?1,'docker','template',?2,
                    'terminated','runner-1',?3,?3)",
            params![
                ContentDigest::sha256(b"fleet runtime").as_str(),
                ContentDigest::sha256(b"fleet template").as_str(),
                to_i64(NOW).unwrap(),
            ],
        )
        .unwrap();

    control
        .perform_scheduler_maintenance(NOW + DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS)
        .unwrap();

    let retired = control.runner("runner-1").unwrap().runner;
    assert!(retired.retired);
    assert_eq!(
        control.list_runner_fleet_requests("pool-1").unwrap().len(),
        1
    );
}

#[test]
fn legacy_unbound_runner_is_quarantined_instead_of_tofu_binding() {
    let control = ControlPlane::open_in_memory("legacy-runner", NOW).unwrap();
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "legacy".to_owned(),
            region: Some("test".to_owned()),
            status: RunnerPoolStatus::Active,
            created_unix_ms: NOW,
        })
        .unwrap();
    control.register_runner(&runner(), NOW).unwrap();
    assert!(matches!(
        control.validate_runner_inventory_binding(
            "runner-1",
            &ContentDigest::sha256(b"attacker-selected reconnect"),
        ),
        Err(ControlPlaneError::RunnerReenrollmentRequired)
    ));
    assert_eq!(
        control.runner("runner-1").unwrap().runner.status,
        RunnerStatus::Quarantined
    );
}

#[test]
fn cancellation_wins_for_offered_and_active_fences() {
    let control = ControlPlane::open_in_memory("cancel-fences", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    for (run, job, at) in [
        ("run-active-cancel", "job-active-cancel", NOW),
        ("run-offer-cancel", "job-offer-cancel", NOW + 1),
    ] {
        control
            .create_run_idempotent(&format!("{run}-key"), &run_request(run, job))
            .unwrap();
        let lease = control
            .offer_next_lease_for_runner("runner-1", at + 2)
            .unwrap()
            .unwrap();
        if run == "run-active-cancel" {
            let active = control
                .accept_lease(
                    &lease.id,
                    "runner-1",
                    lease.fencing_generation,
                    lease.installation_fencing_epoch,
                    at + 3,
                )
                .unwrap();
            let canceled = control
                .cancel_run_idempotent("cancel-active", run, "operator", at + 4)
                .unwrap();
            assert_eq!(canceled.value.status, RunState::Running);
            assert_eq!(
                control.lease(&lease.id).unwrap().state,
                LeaseState::CancelRequested
            );
            control
                .complete_lease(
                    &active.id,
                    "runner-1",
                    active.fencing_generation,
                    active.installation_fencing_epoch,
                    &ContentDigest::sha256(b"late-success"),
                    JobState::Succeeded,
                    at + 5,
                )
                .unwrap();
            assert_eq!(
                control.jobs_for_run(run).unwrap()[0].status,
                JobState::Canceled
            );
            assert_eq!(control.run(run).unwrap().status, RunState::Canceled);
        } else {
            control
                .cancel_run_idempotent("cancel-offer", run, "operator", at + 3)
                .unwrap();
            assert_eq!(
                control.lease(&lease.id).unwrap().state,
                LeaseState::Rejected
            );
            assert_eq!(
                control.jobs_for_run(run).unwrap()[0].status,
                JobState::Canceled
            );
            assert_eq!(control.run(run).unwrap().status, RunState::Canceled);
        }
    }
}

#[test]
fn runner_control_queries_and_rejection_preserve_exact_durable_binding() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    control
        .create_run_idempotent(
            "runner-control-run",
            &run_request("run-control", "job-control"),
        )
        .unwrap();
    control
        .transition_job_state("job-control", JobState::Queued, NOW + 1)
        .unwrap();
    let lease = control
        .create_lease(
            "lease-control",
            "job-control",
            "runner-1",
            NOW + 2,
            NOW + 20,
            NOW + 100,
        )
        .unwrap();

    assert_eq!(
        control.open_leases_for_runner("runner-1", 2).unwrap(),
        vec![lease.clone()]
    );
    assert!(matches!(
        control.open_leases_for_runner("runner-1", 0),
        Err(ControlPlaneError::InvalidInput(_))
    ));
    let (job_key, capsule) = control.signed_capsule_for_lease("lease-control").unwrap();
    assert_eq!(job_key, "build");
    assert_eq!(capsule.id, "capsule-1");
    assert_eq!(capsule.digest, lease.capsule_digest);

    assert!(matches!(
        control.reject_lease(
            "lease-control",
            "runner-other",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            NOW + 3,
        ),
        Err(ControlPlaneError::WrongRunner)
    ));
    assert!(matches!(
        control.reject_lease(
            "lease-control",
            "runner-1",
            lease.fencing_generation + 1,
            lease.installation_fencing_epoch,
            NOW + 3,
        ),
        Err(ControlPlaneError::StaleLeaseGeneration { .. })
    ));
    let rejected = control
        .reject_lease(
            "lease-control",
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(rejected.state, LeaseState::Rejected);
    assert_eq!(
        control
            .reject_lease(
                "lease-control",
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                NOW + 4,
            )
            .unwrap()
            .state,
        LeaseState::Rejected
    );
    assert!(control
        .open_leases_for_runner("runner-1", 2)
        .unwrap()
        .is_empty());
    assert_eq!(
        control.jobs_for_run("run-control").unwrap()[0].status,
        JobState::BlockedPolicy
    );
    assert_eq!(control.run("run-control").unwrap().status, RunState::Failed);
}

#[test]
fn enrollment_identity_mismatch_does_not_consume_token() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    add_runner_pool_only(&control);
    let issued = control
        .create_enrollment_token("pool-1", NOW, NOW + 100)
        .unwrap();
    let mut enrolled_runner = runner();
    enrolled_runner.status = RunnerStatus::Offline;
    let mismatched = runner_certificate("runner-other", b"mismatch", NOW, NOW + 1_000);
    assert!(matches!(
        control.complete_runner_enrollment(
            issued.token.expose(),
            &enrolled_runner,
            &mismatched,
            &ContentDigest::sha256(b"mismatched inventory"),
            NOW + 1,
        ),
        Err(ControlPlaneError::CertificateIdentityMismatch)
    ));
    assert!(control
        .inspect_enrollment_token(issued.token.expose(), NOW + 2)
        .is_ok());
}

#[test]
fn expired_enrollment_token_does_not_create_runner_or_certificate() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    add_runner_pool_only(&control);
    let issued = control
        .create_enrollment_token("pool-1", NOW, NOW + 1)
        .unwrap();
    let mut enrolled_runner = runner();
    enrolled_runner.status = RunnerStatus::Offline;
    let certificate = runner_certificate("runner-1", b"expired", NOW, NOW + 1_000);
    assert!(matches!(
        control.complete_runner_enrollment(
            issued.token.expose(),
            &enrolled_runner,
            &certificate,
            &ContentDigest::sha256(b"expired inventory"),
            NOW + 1,
        ),
        Err(ControlPlaneError::EnrollmentTokenExpired)
    ));
    assert!(control.runner("runner-1").is_err());
    assert!(control
        .runner_certificate(&certificate.fingerprint)
        .is_err());
}

#[test]
fn enrollment_lost_response_replays_the_exact_identity_and_certificate() {
    let control = ControlPlane::open_in_memory("enrollment-replay", NOW).unwrap();
    add_runner_pool_only(&control);
    let issued = control
        .create_enrollment_token("pool-1", NOW, NOW + 100)
        .unwrap();
    let mut enrolled = runner();
    enrolled.status = RunnerStatus::Offline;
    let certificate = runner_certificate("runner-1", b"replay-first", NOW, NOW + 1_000);
    let request_digest = ContentDigest::sha256(b"complete-enrollment-request");
    let inventory_digest = ContentDigest::sha256(b"replay inventory");
    let first = control
        .complete_runner_enrollment_idempotent(
            issued.token.expose(),
            &request_digest,
            &enrolled,
            &certificate,
            b"original certificate chain",
            &inventory_digest,
            1,
            NOW + 1,
        )
        .unwrap();
    let mut ambiguous_retry = enrolled;
    ambiguous_retry.id = "runner-random-retry".into();
    let retry_certificate = runner_certificate(
        "runner-random-retry",
        b"replay-second",
        NOW + 2,
        NOW + 1_000,
    );
    let replay = control
        .complete_runner_enrollment_idempotent(
            issued.token.expose(),
            &request_digest,
            &ambiguous_retry,
            &retry_certificate,
            b"newly issued but discarded certificate chain",
            &inventory_digest,
            1,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(replay.runner_id, "runner-1");
    assert_eq!(replay.certificate_chain_pem, b"original certificate chain");
    assert!(matches!(
        control.replay_runner_enrollment(
            issued.token.expose(),
            &ContentDigest::sha256(b"different request")
        ),
        Err(ControlPlaneError::EnrollmentTokenConsumed)
    ));
}

#[test]
fn concurrent_rotation_requests_serialize_to_one_public_response() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rotation-race.sqlite");
    let old = runner_certificate("runner-1", b"race-old", NOW + 1, NOW + 1_000);
    {
        let control = ControlPlane::open(&path, "rotation-race", NOW).unwrap();
        add_runner_pool_only(&control);
        let issued = control
            .create_enrollment_token("pool-1", NOW, NOW + 500)
            .unwrap();
        let mut enrolled = runner();
        enrolled.status = RunnerStatus::Offline;
        control
            .complete_runner_enrollment(
                issued.token.expose(),
                &enrolled,
                &old,
                &ContentDigest::sha256(b"race inventory"),
                NOW + 1,
            )
            .unwrap();
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = [b'a', b'b'].map(|suffix| {
        let path = path.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        let old = old.clone();
        std::thread::spawn(move || {
            let control = ControlPlane::open(&path, "rotation-race", NOW + 9).unwrap();
            let certificate = runner_certificate(
                "runner-1",
                &[b'r', b'a', b'c', b'e', suffix],
                NOW + 10,
                NOW + 2_000,
            );
            barrier.wait();
            control
                .rotate_runner_certificate_idempotent(
                    &old.fingerprint,
                    "runner-1",
                    &ContentDigest::sha256(b"race csr"),
                    &certificate,
                    &[b'c', b'h', b'a', b'i', b'n', suffix],
                    NOW + 10,
                    20,
                )
                .unwrap()
        })
    });
    let [first_handle, second_handle] = handles;
    let first = first_handle.join().unwrap();
    let second = second_handle.join().unwrap();
    assert_eq!(first.value, second.value);
    assert_ne!(first.replayed, second.replayed);
    let persisted = ControlPlane::open(&path, "rotation-race", NOW + 11)
        .unwrap()
        .runner_certificate_rotation(&old.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(first.value, persisted);
}

#[test]
fn rotation_response_replays_exactly_after_loss_restart_and_old_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rotation-replay.sqlite");
    let old = runner_certificate("runner-1", b"old", NOW + 1, NOW + 1_000);
    let new = runner_certificate("runner-1", b"new", NOW + 10, NOW + 2_000);
    let csr = ContentDigest::sha256(b"exact csr bytes");
    let first_record;
    {
        let control = ControlPlane::open(&path, "rotation", NOW).unwrap();
        add_runner_pool_only(&control);
        let issued = control
            .create_enrollment_token("pool-1", NOW, NOW + 500)
            .unwrap();
        let mut enrolled = runner();
        enrolled.status = RunnerStatus::Offline;
        control
            .complete_runner_enrollment(
                issued.token.expose(),
                &enrolled,
                &old,
                &ContentDigest::sha256(b"rotation inventory"),
                NOW + 1,
            )
            .unwrap();
        let rotated = control
            .rotate_runner_certificate_idempotent(
                &old.fingerprint,
                "runner-1",
                &csr,
                &new,
                b"public certificate chain",
                NOW + 10,
                20,
            )
            .unwrap();
        assert!(!rotated.replayed);
        first_record = rotated.value;
        assert_eq!(
            control.runner_certificate(&old.fingerprint).unwrap().status,
            RunnerCertificateStatus::Overlap
        );
        assert_eq!(
            control
                .audit_events_page(None, None, 100)
                .unwrap()
                .into_iter()
                .filter(|event| event.data.action == "runner.certificate.rotate")
                .count(),
            1
        );
    }

    let reopened = ControlPlane::open(&path, "rotation", NOW + 31).unwrap();
    assert!(matches!(
        reopened.authenticate_runner_certificate(&old.fingerprint, NOW + 31),
        Err(ControlPlaneError::RunnerCertificateUnauthorized)
    ));
    let replay = reopened
        .rotate_runner_certificate_idempotent(
            &old.fingerprint,
            "runner-1",
            &csr,
            &runner_certificate("runner-1", b"discarded", NOW + 31, NOW + 3_000),
            b"discarded response",
            NOW + 31,
            20,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.value, first_record);
    assert!(matches!(
        reopened.rotate_runner_certificate_idempotent(
            &old.fingerprint,
            "runner-1",
            &ContentDigest::sha256(b"different csr"),
            &new,
            b"different response",
            NOW + 32,
            20,
        ),
        Err(ControlPlaneError::RunnerCertificateRotationConflict)
    ));
}

#[test]
fn enrollment_and_certificate_rotation_are_atomic_fenced_and_durable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runner-certificates.sqlite");
    let first = runner_certificate("runner-1", b"first", NOW + 1, NOW + 1_000);
    let second = runner_certificate("runner-1", b"second", NOW + 10, NOW + 2_000);
    {
        let control = ControlPlane::open(&path, "installation", NOW).unwrap();
        add_runner_pool_only(&control);
        let issued = control
            .create_enrollment_token("pool-1", NOW, NOW + 500)
            .unwrap();
        let token = issued.token.expose();
        let inspected = control.inspect_enrollment_token(token, NOW + 1).unwrap();
        assert_eq!(inspected.pool_id, "pool-1");

        let mut enrolled_runner = runner();
        enrolled_runner.status = RunnerStatus::Offline;
        let inventory_digest = ContentDigest::sha256(b"enrollment inventory");
        control
            .complete_runner_enrollment(token, &enrolled_runner, &first, &inventory_digest, NOW + 1)
            .unwrap();
        assert!(matches!(
            control.complete_runner_enrollment(
                token,
                &enrolled_runner,
                &first,
                &inventory_digest,
                NOW + 2,
            ),
            Err(ControlPlaneError::EnrollmentTokenConsumed)
        ));
        let authenticated = control
            .authenticate_runner_certificate(&first.fingerprint, NOW + 2)
            .unwrap();
        assert_eq!(authenticated.runner.runner.id, "runner-1");

        control
            .rotate_runner_certificate(&first.fingerprint, "runner-1", &second, NOW + 10, 20)
            .unwrap();
        assert!(matches!(
            control.rotate_runner_certificate(
                &first.fingerprint,
                "runner-1",
                &runner_certificate("runner-1", b"fork", NOW + 11, NOW + 3_000),
                NOW + 11,
                20,
            ),
            Err(ControlPlaneError::RunnerCertificateUnauthorized)
        ));
        control
            .authenticate_runner_certificate(&first.fingerprint, NOW + 29)
            .unwrap();
        control
            .authenticate_runner_certificate(&second.fingerprint, NOW + 30)
            .unwrap();
        assert!(matches!(
            control.authenticate_runner_certificate(&first.fingerprint, NOW + 30),
            Err(ControlPlaneError::RunnerCertificateUnauthorized)
        ));
        assert_eq!(
            control
                .runner_certificate(&first.fingerprint)
                .unwrap()
                .status,
            RunnerCertificateStatus::Revoked
        );
    }

    let reopened = ControlPlane::open(&path, "installation", NOW + 31).unwrap();
    reopened
        .authenticate_runner_certificate(&second.fingerprint, NOW + 31)
        .unwrap();
    assert_eq!(
        reopened
            .runner_certificate(&first.fingerprint)
            .unwrap()
            .status,
        RunnerCertificateStatus::Revoked
    );
}

#[test]
fn enrollment_tokens_are_hashed_one_time_and_durable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("enrollment.sqlite");
    let token;
    {
        let control = ControlPlane::open(&path, "installation", NOW).unwrap();
        add_runner_pool_only(&control);
        let issued = control
            .create_enrollment_token("pool-1", NOW, NOW + 100)
            .unwrap();
        token = issued.token.expose().to_owned();
        assert!(!format!("{:?}", issued.token).contains(&token));
        let consumed = control.consume_enrollment_token(&token, NOW + 1).unwrap();
        assert_eq!(consumed.consumed_unix_ms, Some(NOW + 1));
        assert!(matches!(
            control.consume_enrollment_token(&token, NOW + 2),
            Err(ControlPlaneError::EnrollmentTokenConsumed)
        ));
    }
    let reopened = ControlPlane::open(&path, "installation", NOW + 2).unwrap();
    assert!(matches!(
        reopened.consume_enrollment_token(&token, NOW + 2),
        Err(ControlPlaneError::EnrollmentTokenConsumed)
    ));
    drop(reopened);
    let database = fs::read(&path).unwrap();
    assert!(!database
        .windows(token.len())
        .any(|window| window == token.as_bytes()));
}
