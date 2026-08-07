use super::*;

#[test]
fn lease_boundaries_requeue_offers_and_hard_deadlines_timeout() {
    let control = ControlPlane::open_in_memory("lease-boundaries", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    let request = run_request("run-boundary", "job-boundary");
    control
        .create_run_idempotent("run-boundary-key", &request)
        .unwrap();
    let first = control
        .offer_next_lease_for_runner("runner-1", NOW + 1)
        .unwrap()
        .unwrap();
    assert!(matches!(
        control.accept_lease(
            &first.id,
            "runner-1",
            first.fencing_generation,
            first.installation_fencing_epoch,
            first.accept_by_unix_ms,
        ),
        Err(ControlPlaneError::LeaseOfferExpired)
    ));
    assert_eq!(
        control.jobs_for_run("run-boundary").unwrap()[0].status,
        JobState::Queued
    );
    let second = control
        .offer_next_lease_for_runner("runner-1", first.accept_by_unix_ms + 1)
        .unwrap()
        .unwrap();
    assert_eq!(second.fencing_generation, first.fencing_generation + 1);
    let active = control
        .accept_lease(
            &second.id,
            "runner-1",
            second.fencing_generation,
            second.installation_fencing_epoch,
            second.issued_unix_ms + 1,
        )
        .unwrap();
    let hard_deadline = control.lease_hard_deadline_unix_ms(&active.id).unwrap();
    control
        .heartbeat_lease(
            &active.id,
            "runner-1",
            active.fencing_generation,
            active.installation_fencing_epoch,
            active.issued_unix_ms + 2,
            hard_deadline,
        )
        .unwrap();
    assert!(matches!(
        control.complete_lease(
            &active.id,
            "runner-1",
            active.fencing_generation,
            active.installation_fencing_epoch,
            &ContentDigest::sha256(b"late"),
            JobState::Succeeded,
            hard_deadline,
        ),
        Err(ControlPlaneError::LeaseExpired)
    ));
    assert_eq!(
        control.jobs_for_run("run-boundary").unwrap()[0].status,
        JobState::TimedOut
    );
}

#[test]
fn expired_lease_evidence_blocks_replay_after_a_clean_completion() {
    let control = ControlPlane::open_in_memory("lease-taint-aggregate", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    control
        .create_run_idempotent(
            "run-taint-aggregate-key",
            &run_request("run-taint-aggregate", "job-taint-aggregate"),
        )
        .unwrap();

    let expired = control
        .offer_next_lease_for_runner("runner-1", NOW + 1)
        .unwrap()
        .unwrap();
    assert_eq!(
        control.run_credential_taint("run-taint-aggregate").unwrap(),
        CredentialTaintState::Unknown
    );
    assert!(matches!(
        control.accept_lease(
            &expired.id,
            "runner-1",
            expired.fencing_generation,
            expired.installation_fencing_epoch,
            expired.accept_by_unix_ms,
        ),
        Err(ControlPlaneError::LeaseOfferExpired)
    ));

    let offered = control
        .offer_next_lease_for_runner("runner-1", expired.accept_by_unix_ms + 1)
        .unwrap()
        .unwrap();
    let active = control
        .accept_lease(
            &offered.id,
            "runner-1",
            offered.fencing_generation,
            offered.installation_fencing_epoch,
            offered.issued_unix_ms + 1,
        )
        .unwrap();
    control
        .transition_job_state(
            "job-taint-aggregate",
            JobState::Running,
            active.issued_unix_ms + 2,
        )
        .unwrap();
    control
        .transition_job_state(
            "job-taint-aggregate",
            JobState::Finalizing,
            active.issued_unix_ms + 3,
        )
        .unwrap();
    control
        .complete_lease_with_objects(
            &active.id,
            "runner-1",
            active.fencing_generation,
            active.installation_fencing_epoch,
            &ContentDigest::sha256(b"clean retry"),
            JobState::Succeeded,
            CredentialTaintState::None,
            1,
            &[],
            &[],
            &[],
            active.issued_unix_ms + 4,
        )
        .unwrap();

    assert_eq!(
        control.run_credential_taint("run-taint-aggregate").unwrap(),
        CredentialTaintState::Unknown
    );
}

#[test]
fn runner_logs_require_clean_completion_or_explicit_operator_opt_in() {
    let control = ControlPlane::open_in_memory("lease-log-taint", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);

    for (suffix, taint, at) in [
        ("clean", CredentialTaintState::None, NOW + 1),
        (
            "tainted",
            CredentialTaintState::CredentialReleased,
            NOW + 100,
        ),
        (
            "tainted-opt-in",
            CredentialTaintState::CredentialReleased,
            NOW + 200,
        ),
    ] {
        let run_id = format!("run-log-{suffix}");
        let job_id = format!("job-log-{suffix}");
        control
            .create_run_idempotent(&format!("{run_id}-key"), &run_request(&run_id, &job_id))
            .unwrap();
        let offered = control
            .offer_next_lease_for_runner("runner-1", at)
            .unwrap()
            .unwrap();
        let lease = control
            .accept_lease(
                &offered.id,
                "runner-1",
                offered.fencing_generation,
                offered.installation_fencing_epoch,
                at + 1,
            )
            .unwrap();
        control
            .transition_job_state(&job_id, JobState::Running, at + 2)
            .unwrap();
        let frame = RunnerLogFrameRecord {
            execution_lease_id: lease.id.clone(),
            fencing_generation: lease.fencing_generation,
            job_attempt: 1,
            step_id: "build".to_owned(),
            stream: "stdout".to_owned(),
            sequence: 0,
            monotonic_nanoseconds: 1,
            wall_time_unix_ms: at + 3,
            payload: format!("{suffix} output").into_bytes(),
            redaction_state: if suffix == "tainted-opt-in" {
                "credential_taint_unredacted_operator_opt_in".to_owned()
            } else {
                "redacted".to_owned()
            },
        };
        control
            .append_runner_logs(
                &AppendRunnerLogsRequest {
                    execution_lease_id: lease.id.clone(),
                    fencing_generation: lease.fencing_generation,
                    runner_id: "runner-1".to_owned(),
                    frames: vec![frame.clone()],
                },
                at + 3,
            )
            .unwrap();
        assert!(control.runner_logs_for_run(&run_id, 10).unwrap().is_empty());
        control
            .transition_job_state(&job_id, JobState::Finalizing, at + 4)
            .unwrap();
        control
            .complete_lease_with_objects(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(suffix.as_bytes()),
                JobState::Succeeded,
                taint,
                1,
                &[],
                &[],
                &[],
                at + 5,
            )
            .unwrap();

        if taint == CredentialTaintState::None || suffix == "tainted-opt-in" {
            assert_eq!(control.runner_logs_for_run(&run_id, 10).unwrap(), [frame]);
        } else {
            assert!(control.runner_logs_for_run(&run_id, 10).unwrap().is_empty());
            assert_eq!(
                control.runner_log_frame_count_for_lease(&lease.id).unwrap(),
                0
            );
        }
    }
}

#[test]
fn observed_taint_survives_rejected_completion_and_cannot_be_downgraded() {
    let control = ControlPlane::open_in_memory("lease-taint-monotonic", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);

    for (suffix, taint, at) in [
        (
            "released",
            CredentialTaintState::CredentialReleased,
            NOW + 1,
        ),
        ("unknown", CredentialTaintState::Unknown, NOW + 100),
    ] {
        let run_id = format!("run-monotonic-{suffix}");
        let job_id = format!("job-monotonic-{suffix}");
        control
            .create_run_idempotent(&format!("{run_id}-key"), &run_request(&run_id, &job_id))
            .unwrap();
        let offered = control
            .offer_next_lease_for_runner("runner-1", at)
            .unwrap()
            .unwrap();
        let lease = control
            .accept_lease(
                &offered.id,
                "runner-1",
                offered.fencing_generation,
                offered.installation_fencing_epoch,
                at + 1,
            )
            .unwrap();
        control
            .transition_job_state(&job_id, JobState::Running, at + 2)
            .unwrap();
        control
            .transition_job_state(&job_id, JobState::Finalizing, at + 3)
            .unwrap();

        assert!(matches!(
            control.complete_lease_with_objects(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(b"rejected tainted completion"),
                JobState::Succeeded,
                taint,
                2,
                &[],
                &[],
                &[],
                at + 4,
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
        assert_eq!(control.run_credential_taint(&run_id).unwrap(), taint);

        assert!(matches!(
            control.complete_lease_with_objects(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(b"tainted object claim"),
                JobState::Succeeded,
                taint,
                1,
                &["forbidden-artifact".to_owned()],
                &[],
                &[],
                at + 5,
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));

        assert!(matches!(
            control.complete_lease_with_objects(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(b"dishonest clean retry"),
                JobState::Succeeded,
                CredentialTaintState::None,
                1,
                &[],
                &[],
                &[],
                at + 6,
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
        assert_eq!(control.run_credential_taint(&run_id).unwrap(), taint);

        control
            .complete_lease_with_objects(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(b"same-taint completion"),
                JobState::Succeeded,
                taint,
                1,
                &[],
                &[],
                &[],
                at + 7,
            )
            .unwrap();
    }
}

#[test]
fn lease_generation_and_installation_epoch_fence_completion() {
    let control = ControlPlane::open_in_memory("installation", NOW).unwrap();
    bootstrap(&control);
    add_runner(&control);
    control
        .create_run_idempotent("run-1-key", &run_request("run-1", "job-1"))
        .unwrap();
    control
        .transition_job_state("job-1", JobState::Queued, NOW + 1)
        .unwrap();
    let lease = control
        .create_lease("lease-1", "job-1", "runner-1", NOW + 2, NOW + 10, NOW + 100)
        .unwrap();
    control
        .accept_lease(
            "lease-1",
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            NOW + 3,
        )
        .unwrap();
    {
        let connection = control.connection().unwrap();
        connection
            .execute(
                "UPDATE job_fencing SET last_generation = 2 WHERE job_id = 'job-1'",
                [],
            )
            .unwrap();
    }
    assert!(matches!(
        control.heartbeat_lease(
            "lease-1",
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            NOW + 3,
            NOW + 200,
        ),
        Err(ControlPlaneError::StaleLeaseGeneration {
            expected: 2,
            actual: 1
        })
    ));
    control
        .connection()
        .unwrap()
        .execute(
            "UPDATE job_fencing SET last_generation = 1 WHERE job_id = 'job-1'",
            [],
        )
        .unwrap();
    control
        .transition_job_state("job-1", JobState::Running, NOW + 4)
        .unwrap();
    control
        .transition_job_state("job-1", JobState::Finalizing, NOW + 5)
        .unwrap();
    let result = ContentDigest::sha256(b"result");
    assert!(matches!(
        control.complete_lease(
            "lease-1",
            "runner-1",
            lease.fencing_generation + 1,
            lease.installation_fencing_epoch,
            &result,
            JobState::Succeeded,
            NOW + 6,
        ),
        Err(ControlPlaneError::StaleLeaseGeneration { .. })
    ));
    assert!(matches!(
        control.complete_lease(
            "lease-1",
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch + 1,
            &result,
            JobState::Succeeded,
            NOW + 6,
        ),
        Err(ControlPlaneError::StaleInstallationEpoch { .. })
    ));
    let completed = control
        .complete_lease(
            "lease-1",
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &result,
            JobState::Succeeded,
            NOW + 6,
        )
        .unwrap();
    assert_eq!(completed.state, LeaseState::Completed);
    assert_eq!(control.run("run-1").unwrap().status, RunState::Succeeded);
    assert_eq!(
        control
            .complete_lease(
                "lease-1",
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &result,
                JobState::Succeeded,
                NOW + 7,
            )
            .unwrap()
            .terminal_result_digest,
        Some(result.clone())
    );
    assert!(matches!(
        control.complete_lease(
            "lease-1",
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &ContentDigest::sha256(b"different"),
            JobState::Succeeded,
            NOW + 7,
        ),
        Err(ControlPlaneError::ConflictingCompletion)
    ));

    control
        .create_run_idempotent("run-2-key", &run_request("run-2", "job-2"))
        .unwrap();
    control
        .transition_job_state("job-2", JobState::Queued, NOW + 10)
        .unwrap();
    let stale = control
        .create_lease(
            "lease-2",
            "job-2",
            "runner-1",
            NOW + 11,
            NOW + 20,
            NOW + 100,
        )
        .unwrap();
    control
        .advance_installation_fencing_epoch(2, NOW + 12)
        .unwrap();
    assert_eq!(control.lease("lease-2").unwrap().state, LeaseState::Expired);
    assert_eq!(
        control.jobs_for_run("run-2").unwrap()[0].status,
        JobState::Lost
    );
    assert!(matches!(
        control.accept_lease(
            "lease-2",
            "runner-1",
            stale.fencing_generation,
            stale.installation_fencing_epoch,
            NOW + 13,
        ),
        Err(ControlPlaneError::StaleInstallationEpoch { .. })
    ));
}

#[test]
fn lease_creation_rechecks_run_approvals_and_runner_pool_tenant_before_mutation() {
    let subject = ContentDigest::sha256(b"lease-approval-subject");
    let control = ControlPlane::open_in_memory("lease-defense", NOW).unwrap();
    control.create_repository(&repository()).unwrap();
    add_runner(&control);

    let (legacy_capsule, legacy_key) = signed_approval_capsule("capsule-legacy-gated", false, true);
    control
        .store_signed_capsule(&legacy_capsule, &legacy_key)
        .unwrap();
    let legacy_run = approval_run_request(
        "capsule-legacy-gated",
        "run-legacy-gated",
        "job-legacy-gated",
        NOW,
    );
    {
        let mut connection = control.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        insert_run_and_jobs_tx(&transaction, &legacy_run).unwrap();
        transaction
            .execute(
                "UPDATE jobs SET status = 'queued' WHERE id = 'job-legacy-gated'",
                [],
            )
            .unwrap();
        transaction.commit().unwrap();
    }
    assert!(matches!(
        control.create_lease(
            "lease-legacy-gated",
            "job-legacy-gated",
            "runner-1",
            NOW + 1,
            NOW + 10,
            NOW + 100,
        ),
        Err(ControlPlaneError::ApprovalRequired)
    ));
    let connection = control.connection().unwrap();
    let (generation, leases): (i64, i64) = connection
        .query_row(
            "SELECT jf.last_generation, (SELECT COUNT(*) FROM leases)
             FROM job_fencing jf WHERE jf.job_id = 'job-legacy-gated'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((generation, leases), (0, 0));
    drop(connection);

    let (approved_capsule, approved_key) =
        signed_approval_capsule("capsule-lease-approved", false, true);
    let approval = pending_approval(
        "approval-lease-approved",
        ApprovalKind::PrivilegedExecution,
        &subject,
        true,
    );
    control
        .store_compiled_capsule_idempotent(
            "capsule-lease-approved-key",
            &approved_capsule,
            &approved_key,
            &CapsuleApiMetadata {
                capsule_id: approved_capsule.id.clone(),
                approval_subject_digest: subject.clone(),
                risk_score: 90,
            },
            &[approval],
        )
        .unwrap();
    approve(&control, "approval-lease-approved", &subject, NOW + 1);
    control
        .create_run_idempotent(
            "run-lease-approved-key",
            &approval_run_request(
                "capsule-lease-approved",
                "run-lease-approved",
                "job-lease-approved",
                NOW + 2,
            ),
        )
        .unwrap();
    control
        .transition_job_state("job-lease-approved", JobState::Queued, NOW + 3)
        .unwrap();
    assert!(control
        .create_lease(
            "lease-approved",
            "job-lease-approved",
            "runner-1",
            NOW + 4,
            NOW + 10,
            NOW + 100,
        )
        .is_ok());

    let cross = ControlPlane::open_in_memory("tenant-defense", NOW).unwrap();
    bootstrap(&cross);
    cross
        .create_run_idempotent("cross-run-key", &run_request("cross-run", "cross-job"))
        .unwrap();
    cross
        .transition_job_state("cross-job", JobState::Queued, NOW + 1)
        .unwrap();
    cross
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-other".to_owned(),
            tenant_id: "tenant-other".to_owned(),
            name: "other".to_owned(),
            region: Some("test".to_owned()),
            status: RunnerPoolStatus::Active,
            created_unix_ms: NOW,
        })
        .unwrap();
    let mut other_runner = runner();
    other_runner.id = "runner-other".to_owned();
    other_runner.tenant_id = "tenant-other".to_owned();
    other_runner.pool_id = "pool-other".to_owned();
    cross.register_runner(&other_runner, NOW).unwrap();
    assert!(matches!(
        cross.create_lease(
            "lease-cross-tenant",
            "cross-job",
            "runner-other",
            NOW + 2,
            NOW + 10,
            NOW + 100,
        ),
        Err(ControlPlaneError::InvalidInput(_))
    ));
    let connection = cross.connection().unwrap();
    let (status, generation, leases): (String, i64, i64) = connection
        .query_row(
            "SELECT j.status, jf.last_generation, (SELECT COUNT(*) FROM leases)
             FROM jobs j JOIN job_fencing jf ON jf.job_id = j.id
             WHERE j.id = 'cross-job'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "queued");
    assert_eq!((generation, leases), (0, 0));
}
