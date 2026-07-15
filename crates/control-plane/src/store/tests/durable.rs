use super::*;

#[test]
fn task_completion_fans_out_atomically_and_accepts_exact_replay() {
    let control = ControlPlane::open_in_memory("task-fanout", NOW).unwrap();
    for id in ["parent-a", "parent-b"] {
        control
            .enqueue_task(&DurableTask {
                id: id.to_owned(),
                kind: "parent".to_owned(),
                payload: serde_json::json!({"id": id}),
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
    let followup = DurableTask {
        id: "shared-followup".to_owned(),
        kind: "child".to_owned(),
        payload: serde_json::json!({"workflow": "ci"}),
        status: DurableTaskStatus::Pending,
        available_unix_ms: NOW + 100,
        attempts: 0,
        lease_owner: None,
        lease_expires_unix_ms: None,
        last_error: None,
        created_unix_ms: NOW,
        completed_unix_ms: None,
    };
    for parent in ["parent-a", "parent-b"] {
        let claimed = control
            .claim_task_by_kind("worker", "parent", NOW, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(claimed.id, parent);
        control
            .complete_task_with_followups(
                &claimed.id,
                "worker",
                std::slice::from_ref(&followup),
                NOW + 1,
            )
            .unwrap();
    }
    assert_eq!(
        control.task("shared-followup").unwrap().status,
        DurableTaskStatus::Pending
    );
    assert_eq!(
        control.task("parent-a").unwrap().status,
        DurableTaskStatus::Completed
    );
    assert_eq!(
        control.task("parent-b").unwrap().status,
        DurableTaskStatus::Completed
    );
}

#[test]
fn durable_completion_objects_replay_exactly_and_reject_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("completion-objects.sqlite");
    let lease;
    {
        let control = ControlPlane::open(&path, "completion-objects", NOW).unwrap();
        bootstrap(&control);
        add_runner(&control);
        control
            .create_run_idempotent("completion-key", &run_request("run-objects", "job-objects"))
            .unwrap();
        let offered = control
            .offer_next_lease_for_runner("runner-1", NOW + 1)
            .unwrap()
            .unwrap();
        lease = control
            .accept_lease(
                &offered.id,
                "runner-1",
                offered.fencing_generation,
                offered.installation_fencing_epoch,
                NOW + 2,
            )
            .unwrap();
        for (kind, object_id, ticket_id, output_name) in [
            (
                RunnerDataCommitKind::Artifact,
                "artifact-1",
                "ticket-artifact",
                Some("package".to_owned()),
            ),
            (RunnerDataCommitKind::Cache, "cache-1", "ticket-cache", None),
        ] {
            let commit = RunnerDataCommit {
                kind,
                object_id: object_id.to_owned(),
                tenant_id: "tenant-1".to_owned(),
                repository_id: "repo-1".to_owned(),
                run_id: "run-objects".to_owned(),
                job_id: "job-objects".to_owned(),
                job_attempt: 1,
                step_id: if kind == RunnerDataCommitKind::Artifact {
                    "job-finalize"
                } else {
                    "build"
                }
                .to_owned(),
                output_name,
                lease_id: lease.id.clone(),
                fencing_generation: lease.fencing_generation,
                ticket_id: ticket_id.to_owned(),
                committed_unix_ms: NOW + 3,
            };
            assert!(!control
                .record_runner_data_commit(&commit, "runner-1")
                .unwrap());
            assert!(control
                .record_runner_data_commit(&commit, "runner-1")
                .unwrap());
            let mut substituted = commit.clone();
            substituted.object_id.push_str("-substituted");
            assert!(matches!(
                control.record_runner_data_commit(&substituted, "runner-1"),
                Err(ControlPlaneError::RunnerBrokerBindingMismatch)
            ));
            let mut stale_attempt = commit.clone();
            stale_attempt.job_attempt = 2;
            stale_attempt.ticket_id.push_str("-stale-attempt");
            stale_attempt.object_id.push_str("-stale-attempt");
            assert!(matches!(
                control.record_runner_data_commit(&stale_attempt, "runner-1"),
                Err(ControlPlaneError::RunnerBrokerBindingMismatch)
            ));
        }
        let cross_tenant = RunnerDataCommit {
            kind: RunnerDataCommitKind::Cache,
            object_id: "cross-tenant-cache".to_owned(),
            tenant_id: "tenant-attacker".to_owned(),
            repository_id: "repo-1".to_owned(),
            run_id: "run-objects".to_owned(),
            job_id: "job-objects".to_owned(),
            job_attempt: 1,
            step_id: "build".to_owned(),
            output_name: None,
            lease_id: lease.id.clone(),
            fencing_generation: lease.fencing_generation,
            ticket_id: "cross-tenant-ticket".to_owned(),
            committed_unix_ms: NOW + 3,
        };
        assert!(matches!(
            control.record_runner_data_commit(&cross_tenant, "runner-1"),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
        let exact_claims = vec![("artifact-1".to_owned(), "package".to_owned())];
        control
            .validate_runner_completion_artifact_claims(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                1,
                &exact_claims,
            )
            .unwrap();
        for substituted_claims in [
            vec![("artifact-1".to_owned(), "wrong-name".to_owned())],
            vec![(
                "guessed-cross-tenant-artifact".to_owned(),
                "package".to_owned(),
            )],
            vec![
                ("artifact-1".to_owned(), "package".to_owned()),
                ("artifact-1".to_owned(), "duplicate".to_owned()),
            ],
            vec![
                ("artifact-1".to_owned(), "package".to_owned()),
                ("guessed-artifact".to_owned(), "package".to_owned()),
            ],
        ] {
            assert!(matches!(
                control.validate_runner_completion_artifact_claims(
                    &lease.id,
                    "runner-1",
                    lease.fencing_generation,
                    lease.installation_fencing_epoch,
                    1,
                    &substituted_claims,
                ),
                Err(ControlPlaneError::RunnerBrokerBindingMismatch)
            ));
        }
        assert!(matches!(
            control.validate_runner_completion_artifact_claims(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                2,
                &exact_claims,
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
        control
            .transition_job_state("job-objects", JobState::Running, NOW + 4)
            .unwrap();
        control
            .transition_job_state("job-objects", JobState::Finalizing, NOW + 5)
            .unwrap();
    }

    let control = ControlPlane::open(&path, "completion-objects", NOW + 6).unwrap();
    let digest = ContentDigest::sha256(b"complete");
    let artifacts = vec!["artifact-1".to_owned()];
    let caches = vec!["cache-1".to_owned()];
    let required = vec!["package".to_owned()];
    let exact_claims = vec![("artifact-1".to_owned(), "package".to_owned())];
    control
        .validate_runner_completion_artifact_claims(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            1,
            &exact_claims,
        )
        .unwrap();
    for substituted_claims in [
        vec![("artifact-1".to_owned(), "wrong-name".to_owned())],
        vec![(
            "guessed-cross-tenant-artifact".to_owned(),
            "package".to_owned(),
        )],
    ] {
        assert!(matches!(
            control.validate_runner_completion_artifact_claims(
                &lease.id,
                "runner-1",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                1,
                &substituted_claims,
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
    }
    assert!(matches!(
        control.complete_lease_with_objects(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &digest,
            JobState::Succeeded,
            1,
            &[],
            &caches,
            &required,
            NOW + 7
        ),
        Err(ControlPlaneError::RunnerBrokerBindingMismatch)
    ));
    control
        .complete_lease_with_objects(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &digest,
            JobState::Succeeded,
            1,
            &artifacts,
            &caches,
            &required,
            NOW + 7,
        )
        .unwrap();
    control
        .validate_runner_completion_artifact_claims(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            1,
            &exact_claims,
        )
        .unwrap();
    for (runner_id, generation, epoch, attempt) in [
        (
            "wrong-runner",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            1,
        ),
        (
            "runner-1",
            lease.fencing_generation + 1,
            lease.installation_fencing_epoch,
            1,
        ),
        (
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch + 1,
            1,
        ),
        (
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            2,
        ),
    ] {
        assert!(matches!(
            control.validate_runner_completion_artifact_claims(
                &lease.id,
                runner_id,
                generation,
                epoch,
                attempt,
                &exact_claims,
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
    }
    control
        .complete_lease_with_objects(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &digest,
            JobState::Succeeded,
            1,
            &artifacts,
            &caches,
            &required,
            NOW + 8,
        )
        .unwrap();
    assert!(matches!(
        control.complete_lease_with_objects(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &digest,
            JobState::Succeeded,
            1,
            &["artifact-substitution".to_owned()],
            &caches,
            &required,
            NOW + 9
        ),
        Err(ControlPlaneError::ConflictingCompletion)
    ));
    assert!(matches!(
        control.complete_lease_with_objects(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            &digest,
            JobState::Succeeded,
            2,
            &artifacts,
            &caches,
            &required,
            NOW + 10
        ),
        Err(ControlPlaneError::RunnerBrokerBindingMismatch)
    ));

    let catalog = ArtifactCatalogRecord {
        artifact_id: "artifact-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        run_id: "run-objects".to_owned(),
        job_id: "job-objects".to_owned(),
        job_attempt: 1,
        step_id: "job-finalize".to_owned(),
        output_name: "package".to_owned(),
        content_digest: ContentDigest::sha256(b"package-content"),
        manifest_digest: ContentDigest::sha256(b"package-manifest"),
        provenance_digest: ContentDigest::sha256(b"package-provenance"),
        size_bytes: 7,
        media_type: "application/octet-stream".to_owned(),
        classification: "verified-test-output".to_owned(),
        scan_state: "pending".to_owned(),
        retention_until_unix_seconds: 10_000,
        legal_hold: false,
        state: "available".to_owned(),
        created_unix_ms: NOW + 11,
    };
    assert!(!control.catalog_artifact(&catalog).unwrap().replayed);
    assert!(control.catalog_artifact(&catalog).unwrap().replayed);
    assert_eq!(
        control
            .artifact_for_tenant("tenant-1", "artifact-1")
            .unwrap(),
        catalog
    );
    assert!(matches!(
        control.artifact_for_tenant("tenant-attacker", "artifact-1"),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let ticket = ArtifactDownloadTicketRecord {
        token_hash: ContentDigest::sha256(b"one-use-artifact-download"),
        artifact_id: catalog.artifact_id.clone(),
        tenant_id: catalog.tenant_id.clone(),
        principal_id: "reader-1".to_owned(),
        classification: catalog.classification.clone(),
        manifest_digest: catalog.manifest_digest.clone(),
        issued_unix_ms: NOW + 12,
        expires_unix_ms: NOW + 60_000,
        used_unix_ms: None,
    };
    assert!(
        !control
            .issue_artifact_download_ticket(&ticket)
            .unwrap()
            .replayed
    );
    assert!(
        control
            .issue_artifact_download_ticket(&ticket)
            .unwrap()
            .replayed
    );
    assert_eq!(
        control
            .consume_artifact_download_ticket(
                &ticket.token_hash,
                Some("tenant-1"),
                "reader-1",
                NOW + 13,
            )
            .unwrap()
            .used_unix_ms,
        Some(NOW + 13)
    );
    assert!(matches!(
        control.consume_artifact_download_ticket(
            &ticket.token_hash,
            Some("tenant-1"),
            "reader-1",
            NOW + 14,
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert_eq!(
        control.artifact_metrics("tenant-1").unwrap(),
        ArtifactMetrics {
            cataloged: 1,
            quarantined: 0,
            download_tickets_issued: 1,
            download_tickets_consumed: 1,
        }
    );

    let scan = ArtifactScanJournalRecord {
        id: "scan-artifact-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        artifact_id: catalog.artifact_id.clone(),
        scanner: "isolated-test-scanner-v1".to_owned(),
        subject_digest: artifact_scan_subject_digest(&catalog, "isolated-test-scanner-v1").unwrap(),
        state: ArtifactScanState::Pending,
        result_digest: None,
        lease_owner: None,
        lease_expires_unix_ms: None,
        attempts: 0,
        created_unix_ms: NOW + 15,
        completed_unix_ms: None,
        last_error_code: None,
    };
    assert!(!control.enqueue_artifact_scan(&scan).unwrap());
    assert!(control.enqueue_artifact_scan(&scan).unwrap());
    let mut cross_tenant = scan.clone();
    cross_tenant.id = "cross-tenant-scan".to_owned();
    cross_tenant.tenant_id = "tenant-attacker".to_owned();
    assert!(matches!(
        control.enqueue_artifact_scan(&cross_tenant),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let claimed = control
        .claim_artifact_scan("scanner-worker", NOW + 16, 1_000)
        .unwrap()
        .unwrap();
    assert_eq!(claimed.id, scan.id);
    assert!(!control
        .finish_artifact_scan(
            "tenant-1",
            &scan.id,
            "scanner-worker",
            ArtifactScanState::Error,
            None,
            Some("scanner-unavailable"),
            NOW + 17,
        )
        .unwrap());
    assert_eq!(
        control
            .artifact_for_tenant("tenant-1", "artifact-1")
            .unwrap()
            .state,
        "quarantined"
    );
    assert_eq!(control.lifecycle_metrics().unwrap().scan_failed_or_error, 1);

    let mut passed_scan = scan.clone();
    passed_scan.id = "scan-artifact-1-passed".to_owned();
    passed_scan.scanner = "isolated-release-scanner-v1".to_owned();
    passed_scan.subject_digest =
        artifact_scan_subject_digest(&catalog, &passed_scan.scanner).unwrap();
    passed_scan.created_unix_ms = NOW + 18;
    control.enqueue_artifact_scan(&passed_scan).unwrap();
    control
        .claim_artifact_scan("release-scanner", NOW + 19, 1_000)
        .unwrap()
        .unwrap();
    let scan_evidence = ContentDigest::sha256(b"passed scan evidence");
    control
        .finish_artifact_scan(
            "tenant-1",
            &passed_scan.id,
            "release-scanner",
            ArtifactScanState::Passed,
            Some(&scan_evidence),
            None,
            NOW + 20,
        )
        .unwrap();
    let evidence = serde_json::json!({
        "kind": "release_approval",
        "evidence_digest": ContentDigest::sha256(b"release approval"),
        "approval_id": "approval-1",
        "policy_version_ids": ["policy-1"]
    });
    let mut promotion = ArtifactPromotionIntent {
        id: "artifact-promotion-1".to_owned(),
        subject_digest: ContentDigest::sha256(b"placeholder"),
        tenant_id: "tenant-1".to_owned(),
        source_artifact_id: catalog.artifact_id.clone(),
        source_manifest_digest: catalog.manifest_digest.clone(),
        source_provenance_digest: catalog.provenance_digest.clone(),
        source_classification: "verified-test-output".to_owned(),
        target_classification: "release-candidate".to_owned(),
        evidence_digest: ContentDigest::sha256(
            serde_json::to_vec(&canonicalize_json(evidence.clone())).unwrap(),
        ),
        evidence,
        scan_evidence_digest: Some(scan_evidence),
        approval_evidence_digest: Some(ContentDigest::sha256(b"approval evidence")),
        status: "pending".to_owned(),
        promoted_artifact_id: None,
        promoted_manifest_digest: None,
        created_unix_ms: NOW + 21,
        completed_unix_ms: None,
        last_error_code: None,
    };
    promotion.subject_digest = artifact_promotion_subject_digest(&promotion).unwrap();
    assert!(!control.create_artifact_promotion(&promotion).unwrap());
    assert!(control.create_artifact_promotion(&promotion).unwrap());
    assert!(matches!(
        control.artifact_promotion("tenant-attacker", &promotion.id),
        Err(ControlPlaneError::NotFound { .. })
    ));
    let promoted = ContentDigest::sha256(b"promoted immutable record");
    assert!(!control
        .complete_artifact_promotion(
            "tenant-1",
            &promotion.id,
            promoted.as_str(),
            &promoted,
            NOW + 22,
        )
        .unwrap());
    assert!(control
        .complete_artifact_promotion(
            "tenant-1",
            &promotion.id,
            promoted.as_str(),
            &promoted,
            NOW + 23,
        )
        .unwrap());
    assert!(matches!(
        control.complete_artifact_promotion(
            "tenant-1",
            &promotion.id,
            ContentDigest::sha256(b"substitution").as_str(),
            &promoted,
            NOW + 24,
        ),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    control
        .connection()
        .unwrap()
        .execute(
            "UPDATE artifacts_catalog SET retention_until_unix_seconds = 0,
                    legal_hold = 1 WHERE artifact_id = 'artifact-1'",
            [],
        )
        .unwrap();
    assert_eq!(control.retire_expired_artifacts(NOW + 25, 10).unwrap(), 0);
    assert_ne!(
        control
            .artifact_for_tenant("tenant-1", "artifact-1")
            .unwrap()
            .state,
        "retired"
    );
    control
        .connection()
        .unwrap()
        .execute(
            "UPDATE artifacts_catalog SET legal_hold = 0
             WHERE artifact_id = 'artifact-1'",
            [],
        )
        .unwrap();
    assert_eq!(control.retire_expired_artifacts(NOW + 26, 10).unwrap(), 1);
    assert_eq!(
        control
            .artifact_for_tenant("tenant-1", "artifact-1")
            .unwrap()
            .state,
        "retired"
    );
}

#[test]
fn tasks_snapshots_secret_metadata_and_audit_are_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("metadata.sqlite");
    let control = ControlPlane::open(&path, "installation", NOW).unwrap();
    control
        .enqueue_task(&DurableTask {
            id: "task".to_owned(),
            kind: "reconcile".to_owned(),
            payload: json!({"b": 2, "a": 1}),
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
    let claimed = control.claim_task("worker", NOW, 10).unwrap().unwrap();
    assert_eq!(claimed.status, DurableTaskStatus::Claimed);
    assert!(matches!(
        control.complete_task("task", "other", NOW + 1),
        Err(ControlPlaneError::TaskNotOwned)
    ));
    assert_eq!(
        control
            .complete_task("task", "worker", NOW + 1)
            .unwrap()
            .status,
        DurableTaskStatus::Completed
    );

    let first = control
        .create_variable_snapshot(
            "vars-1",
            "tenant",
            "repository:repo",
            1,
            [("A".to_owned(), json!({"z": 1, "a": 2}))]
                .into_iter()
                .collect(),
            NOW,
        )
        .unwrap();
    assert_eq!(
        control
            .latest_variable_snapshot("tenant", "repository:repo")
            .unwrap()
            .digest,
        first.digest
    );

    let plaintext_marker = "THIS-IS-SECRET-PLAINTEXT";
    let rejected = format!(
        r#"{{"id":"secret","tenant_id":"tenant","scope":"repository:repo","name":"token","provider":"built-in","secret_type":"opaque","status":"active","created_unix_ms":1,"updated_unix_ms":1,"value":"{plaintext_marker}"}}"#
    );
    assert!(serde_json::from_str::<SecretMetadataReference>(&rejected).is_err());
    control
        .store_secret_metadata(&SecretMetadataReference {
            id: "secret".to_owned(),
            tenant_id: "tenant".to_owned(),
            scope: "repository:repo".to_owned(),
            name: "token".to_owned(),
            provider: "built-in".to_owned(),
            provider_reference: None,
            secret_type: "opaque".to_owned(),
            status: "active".to_owned(),
            current_version: Some(1),
            created_unix_ms: NOW,
            updated_unix_ms: NOW,
        })
        .unwrap();
    control.append_audit_event(audit_data("one")).unwrap();
    control.append_audit_event(audit_data("two")).unwrap();
    assert_eq!(control.audit_events().unwrap().len(), 2);
    drop(control);

    let raw = fs::read(&path).unwrap();
    assert!(!raw
        .windows(plaintext_marker.len())
        .any(|window| window == plaintext_marker.as_bytes()));
    let raw_connection = Connection::open(&path).unwrap();
    assert!(raw_connection
        .execute(
            "UPDATE audit_events SET event_json = '{}' WHERE sequence = 1",
            []
        )
        .is_err());
    assert!(raw_connection
        .execute("DELETE FROM audit_events WHERE sequence = 1", [])
        .is_err());
}
