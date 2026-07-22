use super::*;

#[test]
fn runner_broker_state_is_one_use_cross_scope_safe_and_restart_durable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("runner-brokers.sqlite");
    let master_key = MasterKey::from_bytes([57; 32]);
    let subject = ContentDigest::sha256(b"broker-approval-subject");
    let runner_posture = authoritative_runner_posture_digest(
        &runner(),
        &ContentDigest::sha256(b"test enrolled inventory"),
    )
    .unwrap();
    let secret_lease_id;
    let grant;
    let active;
    {
        let control = ControlPlane::open(&path, "installation", NOW).unwrap();
        control.create_repository(&repository()).unwrap();
        let (capsule, key) = signed_broker_capsule();
        let approval = pending_approval(
            "approval-broker",
            ApprovalKind::PrivilegedExecution,
            &subject,
            true,
        );
        control
            .store_compiled_capsule_idempotent(
                "capsule-broker-key",
                &capsule,
                &key,
                &CapsuleApiMetadata {
                    capsule_id: capsule.id.clone(),
                    approval_subject_digest: subject.clone(),
                    risk_score: 90,
                },
                &[approval],
            )
            .unwrap();
        approve(&control, "approval-broker", &subject, NOW + 1);
        add_runner(&control);
        control
            .create_secret_idempotent(
                "secret-broker-key",
                &SecretMetadataReference {
                    id: "secret-broker".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    scope: "repository:repo-1".to_owned(),
                    name: "TOKEN".to_owned(),
                    provider: "built-in".to_owned(),
                    provider_reference: None,
                    secret_type: "opaque".to_owned(),
                    status: "active".to_owned(),
                    current_version: Some(1),
                    created_unix_ms: NOW,
                    updated_unix_ms: NOW,
                },
                Some(&SecretPlaintext::new(b"restart-secret-marker".to_vec())),
                &master_key,
            )
            .unwrap();
        control
            .create_secret_idempotent(
                "secret-purpose-less-key",
                &SecretMetadataReference {
                    id: "secret-purpose-less".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    scope: "repository:repo-1".to_owned(),
                    name: "NO_PURPOSE".to_owned(),
                    provider: "built-in".to_owned(),
                    provider_reference: None,
                    secret_type: "opaque".to_owned(),
                    status: "active".to_owned(),
                    current_version: Some(1),
                    created_unix_ms: NOW,
                    updated_unix_ms: NOW,
                },
                Some(&SecretPlaintext::new(b"purpose-less-secret".to_vec())),
                &master_key,
            )
            .unwrap();
        control
            .create_secret_idempotent(
                "secret-other-tenant-key",
                &SecretMetadataReference {
                    id: "secret-other-tenant".to_owned(),
                    tenant_id: "tenant-2".to_owned(),
                    scope: "tenant:tenant-2".to_owned(),
                    name: "TOKEN".to_owned(),
                    provider: "built-in".to_owned(),
                    provider_reference: None,
                    secret_type: "opaque".to_owned(),
                    status: "active".to_owned(),
                    current_version: Some(1),
                    created_unix_ms: NOW,
                    updated_unix_ms: NOW,
                },
                Some(&SecretPlaintext::new(b"other-tenant-secret".to_vec())),
                &master_key,
            )
            .unwrap();
        let rotated = control
            .rotate_secret_idempotent(
                "secret-broker-rotated-after-seal",
                "tenant-1",
                "repository:repo-1",
                "TOKEN",
                &SecretPlaintext::new(b"newer-secret-must-not-leak".to_vec()),
                &master_key,
                NOW + 2,
            )
            .unwrap();
        assert_eq!(rotated.value.current_version, Some(2));
        let mut broker_run =
            approval_run_request("capsule-broker", "run-broker", "job-broker", NOW + 2);
        broker_run.jobs[0].job_key = "publish".to_owned();
        control
            .create_run_idempotent("run-broker-key", &broker_run)
            .unwrap();
        control
            .transition_job_state("job-broker", JobState::Queued, NOW + 3)
            .unwrap();
        let offered = control
            .create_lease(
                "lease-broker",
                "job-broker",
                "runner-1",
                NOW + 4,
                NOW + 100,
                NOW + 120_000,
            )
            .unwrap();
        active = control
            .accept_lease(
                "lease-broker",
                "runner-1",
                offered.fencing_generation,
                offered.installation_fencing_epoch,
                NOW + 5,
            )
            .unwrap();
        let first_blob = RecordRunnerBlobUpload {
            ticket_id: "cache-ticket-1".to_owned(),
            blob_digest: ContentDigest::sha256(b"blob-one"),
            ticket_kind: "cache".to_owned(),
            execution_lease_id: active.id.clone(),
            fencing_generation: active.fencing_generation,
            job_attempt: 1,
            size_bytes: 4,
            maximum_ticket_bytes: 10,
            recorded_unix_ms: NOW + 6,
        };
        assert!(!control
            .record_runner_blob_upload(&first_blob, "runner-1")
            .unwrap());
        assert!(control
            .record_runner_blob_upload(&first_blob, "runner-1")
            .unwrap());
        let second_blob = RecordRunnerBlobUpload {
            blob_digest: ContentDigest::sha256(b"blob-two"),
            size_bytes: 6,
            ..first_blob.clone()
        };
        assert!(!control
            .record_runner_blob_upload(&second_blob, "runner-1")
            .unwrap());
        assert!(matches!(
            control.record_runner_blob_upload(
                &RecordRunnerBlobUpload {
                    blob_digest: ContentDigest::sha256(b"over-budget"),
                    size_bytes: 1,
                    ..first_blob.clone()
                },
                "runner-1",
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
        assert!(matches!(
            control.record_runner_blob_upload(
                &RecordRunnerBlobUpload {
                    blob_digest: ContentDigest::sha256(b"cross-attempt"),
                    job_attempt: 2,
                    size_bytes: 0,
                    ..first_blob.clone()
                },
                "runner-1",
            ),
            Err(ControlPlaneError::RunnerBrokerBindingMismatch)
        ));
        let log_frame = RunnerLogFrameRecord {
            execution_lease_id: active.id.clone(),
            fencing_generation: active.fencing_generation,
            job_attempt: 1,
            step_id: "federate".to_owned(),
            stream: "stdout".to_owned(),
            sequence: 0,
            monotonic_nanoseconds: 1,
            wall_time_unix_ms: NOW + 6,
            payload: b"durable runner log".to_vec(),
            redaction_state: "redacted".to_owned(),
        };
        let log_request = AppendRunnerLogsRequest {
            execution_lease_id: active.id.clone(),
            fencing_generation: active.fencing_generation,
            runner_id: "runner-1".to_owned(),
            frames: vec![log_frame.clone()],
        };
        control.append_runner_logs(&log_request, NOW + 6).unwrap();
        assert!(matches!(
            control.append_runner_logs(&log_request, NOW + 6),
            Err(ControlPlaneError::RunnerBrokerReplay)
        ));
        assert_eq!(
            control.runner_logs_for_run("run-broker", 10).unwrap(),
            Vec::<RunnerLogFrameRecord>::new()
        );
        let delivered = control
            .issue_runner_secret(
                &IssueRunnerSecretRequest {
                    execution_lease_id: active.id.clone(),
                    fencing_generation: active.fencing_generation,
                    runner_id: "runner-1".to_owned(),
                    job_id: active.job_id.clone(),
                    job_attempt: 1,
                    step_id: "federate".to_owned(),
                    secret_metadata_id: "secret-broker".to_owned(),
                    purpose: "publish".to_owned(),
                    guest_key_fingerprint: ContentDigest::sha256(b"guest-key"),
                    runner_posture_digest: runner_posture.clone(),
                    issued_unix_ms: NOW + 6,
                    expires_unix_ms: NOW + 60_000,
                },
                &master_key,
            )
            .unwrap();
        assert_eq!(delivered.plaintext.as_bytes(), b"restart-secret-marker");
        secret_lease_id = delivered.lease.id;
        let purpose_less = control
            .issue_runner_secret(
                &IssueRunnerSecretRequest {
                    execution_lease_id: active.id.clone(),
                    fencing_generation: active.fencing_generation,
                    runner_id: "runner-1".to_owned(),
                    job_id: active.job_id.clone(),
                    job_attempt: 1,
                    step_id: "federate".to_owned(),
                    secret_metadata_id: "secret-purpose-less".to_owned(),
                    purpose: String::new(),
                    guest_key_fingerprint: ContentDigest::sha256(b"guest-key"),
                    runner_posture_digest: runner_posture.clone(),
                    issued_unix_ms: NOW + 7,
                    expires_unix_ms: NOW + 60_000,
                },
                &master_key,
            )
            .unwrap();
        assert_eq!(purpose_less.plaintext.as_bytes(), b"purpose-less-secret");
        assert!(matches!(
            control.issue_runner_secret(
                &IssueRunnerSecretRequest {
                    execution_lease_id: active.id.clone(),
                    fencing_generation: active.fencing_generation,
                    runner_id: "runner-1".to_owned(),
                    job_id: active.job_id.clone(),
                    job_attempt: 1,
                    step_id: "federate".to_owned(),
                    secret_metadata_id: "secret-broker".to_owned(),
                    purpose: "publish".to_owned(),
                    guest_key_fingerprint: ContentDigest::sha256(b"other-guest-key"),
                    runner_posture_digest: runner_posture.clone(),
                    issued_unix_ms: NOW + 7,
                    expires_unix_ms: NOW + 60_000,
                },
                &master_key,
            ),
            Err(ControlPlaneError::RunnerBrokerReplay)
        ));
        let retry_delivery = control
            .issue_runner_secret(
                &IssueRunnerSecretRequest {
                    execution_lease_id: active.id.clone(),
                    fencing_generation: active.fencing_generation,
                    runner_id: "runner-1".to_owned(),
                    job_id: active.job_id.clone(),
                    job_attempt: 2,
                    step_id: "federate".to_owned(),
                    secret_metadata_id: "secret-broker".to_owned(),
                    purpose: "publish".to_owned(),
                    guest_key_fingerprint: ContentDigest::sha256(b"retry-guest-key"),
                    runner_posture_digest: runner_posture.clone(),
                    issued_unix_ms: NOW + 7,
                    expires_unix_ms: NOW + 60_000,
                },
                &master_key,
            )
            .expect("a new attempt has an independent one-use secret scope");
        assert_eq!(retry_delivery.lease.job_attempt, 2);
        assert!(matches!(
            control.issue_runner_secret(
                &IssueRunnerSecretRequest {
                    execution_lease_id: active.id.clone(),
                    fencing_generation: active.fencing_generation,
                    runner_id: "runner-1".to_owned(),
                    job_id: active.job_id.clone(),
                    job_attempt: 1,
                    step_id: "federate".to_owned(),
                    secret_metadata_id: "secret-other-tenant".to_owned(),
                    purpose: "publish".to_owned(),
                    guest_key_fingerprint: ContentDigest::sha256(b"guest-key"),
                    runner_posture_digest: runner_posture.clone(),
                    issued_unix_ms: NOW + 7,
                    expires_unix_ms: NOW + 60_000,
                },
                &master_key,
            ),
            Err(ControlPlaneError::RunnerBrokerCapabilityDenied)
        ));
        grant = control
            .authorize_runner_oidc(&AuthorizeRunnerOidcRequest {
                execution_lease_id: active.id.clone(),
                fencing_generation: active.fencing_generation,
                runner_id: "runner-1".to_owned(),
                job_id: active.job_id.clone(),
                job_attempt: 1,
                step_id: "federate".to_owned(),
                audience: "https://registry.example".to_owned(),
                runner_posture_digest: runner_posture.clone(),
                now_unix_ms: NOW + 7,
            })
            .unwrap();
        assert!(matches!(
            control.authorize_runner_oidc(&AuthorizeRunnerOidcRequest {
                audience: "https://evil.example".to_owned(),
                ..AuthorizeRunnerOidcRequest {
                    execution_lease_id: active.id.clone(),
                    fencing_generation: active.fencing_generation,
                    runner_id: "runner-1".to_owned(),
                    job_id: active.job_id.clone(),
                    job_attempt: 1,
                    step_id: "federate".to_owned(),
                    audience: String::new(),
                    runner_posture_digest: runner_posture.clone(),
                    now_unix_ms: NOW + 7,
                }
            }),
            Err(ControlPlaneError::RunnerBrokerCapabilityDenied)
        ));
        control
            .record_runner_oidc_issuance(&RecordRunnerOidcIssuance {
                grant_id: grant.grant_id.clone(),
                audience: "https://registry.example".to_owned(),
                jti: "runner-jti-1".to_owned(),
                runner_id: "runner-1".to_owned(),
                runner_posture_digest: runner_posture.clone(),
                job_attempt: 1,
                issued_unix_ms: NOW + 8,
                expires_unix_ms: NOW + 30_000,
            })
            .unwrap();
        let retry_grant = control
            .authorize_runner_oidc(&AuthorizeRunnerOidcRequest {
                execution_lease_id: active.id.clone(),
                fencing_generation: active.fencing_generation,
                runner_id: "runner-1".to_owned(),
                job_id: active.job_id.clone(),
                job_attempt: 2,
                step_id: "federate".to_owned(),
                audience: "https://registry.example".to_owned(),
                runner_posture_digest: runner_posture.clone(),
                now_unix_ms: NOW + 8,
            })
            .expect("retry OIDC grant");
        assert_ne!(grant.grant_id, retry_grant.grant_id);
        control
            .record_runner_oidc_issuance(&RecordRunnerOidcIssuance {
                grant_id: retry_grant.grant_id,
                audience: "https://registry.example".to_owned(),
                jti: "runner-jti-2".to_owned(),
                runner_id: "runner-1".to_owned(),
                runner_posture_digest: runner_posture.clone(),
                job_attempt: 2,
                issued_unix_ms: NOW + 8,
                expires_unix_ms: NOW + 30_000,
            })
            .expect("retry OIDC issuance");
    }

    let reopened = ControlPlane::open(&path, "installation", NOW + 9).unwrap();
    assert_eq!(
        reopened
            .runner_secret_lease(&secret_lease_id)
            .unwrap()
            .state,
        "delivered"
    );
    assert!(reopened
        .runner_logs_for_run("run-broker", 10)
        .unwrap()
        .is_empty());
    let uploaded_blobs: i64 = reopened
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM runner_blob_uploads WHERE ticket_id = 'cache-ticket-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(uploaded_blobs, 2);
    let verified_transfers: i64 = reopened
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM runner_object_transfers
             WHERE ticket_id = 'cache-ticket-1' AND direction = 'upload'
               AND state = 'verified' AND verified_unix_ms IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(verified_transfers, 2);
    assert!(matches!(
        reopened.record_runner_oidc_issuance(&RecordRunnerOidcIssuance {
            grant_id: grant.grant_id,
            audience: "https://registry.example".to_owned(),
            jti: "runner-jti-replay".to_owned(),
            runner_id: "runner-1".to_owned(),
            runner_posture_digest: runner_posture,
            job_attempt: 1,
            issued_unix_ms: NOW + 9,
            expires_unix_ms: NOW + 30_000,
        }),
        Err(ControlPlaneError::RunnerBrokerReplay)
    ));
    reopened
        .transition_job_state("job-broker", JobState::Running, NOW + 10)
        .unwrap();
    reopened
        .transition_job_state("job-broker", JobState::Finalizing, NOW + 11)
        .unwrap();
    reopened
        .complete_lease(
            &active.id,
            "runner-1",
            active.fencing_generation,
            active.installation_fencing_epoch,
            &ContentDigest::sha256(b"broker-result"),
            JobState::Succeeded,
            NOW + 12,
        )
        .unwrap();
    assert_eq!(
        reopened
            .runner_secret_lease(&secret_lease_id)
            .unwrap()
            .state,
        "revoked"
    );
    let oidc_state: String = reopened
        .connection()
        .unwrap()
        .query_row(
            "SELECT state FROM runner_oidc_issuances WHERE jti = 'runner-jti-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(oidc_state, "revoked");
    verify_chain(&reopened.audit_events().unwrap()).unwrap();
    drop(reopened);
    for candidate in [
        path.clone(),
        sqlite_sidecar_path(&path, "-wal"),
        sqlite_sidecar_path(&path, "-shm"),
    ] {
        if let Ok(bytes) = fs::read(candidate) {
            assert!(!bytes
                .windows(b"restart-secret-marker".len())
                .any(|window| window == b"restart-secret-marker"));
        }
    }
}

#[test]
fn api_variables_secrets_and_enrollment_are_durable_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("api-state.sqlite");
    let master_key = MasterKey::from_bytes([23_u8; 32]);
    let plaintext_marker = "durable-secret-plaintext-marker";
    let enrollment_token;
    {
        let control = ControlPlane::open(&path, "installation", NOW).unwrap();
        let first = control
            .put_variable_idempotent(
                "variable-key",
                "tenant-1",
                "repository:repo-1",
                "MODE",
                json!({"b": 2, "a": 1}),
                NOW,
            )
            .unwrap();
        let replay = control
            .put_variable_idempotent(
                "variable-key",
                "tenant-1",
                "repository:repo-1",
                "MODE",
                json!({"a": 1, "b": 2}),
                NOW + 1,
            )
            .unwrap();
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(first.value, replay.value);
        assert_eq!(
            control
                .list_variables("tenant-1", "repository:repo-1")
                .unwrap(),
            vec![first.value.clone()]
        );
        assert!(control
            .list_variables("tenant-1", "repository:repo-other")
            .unwrap()
            .is_empty());
        assert!(matches!(
            control.put_variable_idempotent(
                "variable-key",
                "tenant-1",
                "repository:repo-1",
                "MODE",
                json!("changed"),
                NOW + 2,
            ),
            Err(ControlPlaneError::IdempotencyConflict)
        ));

        let metadata = SecretMetadataReference {
            id: "secret-api".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            scope: "repository:repo-1".to_owned(),
            name: "registry-token".to_owned(),
            provider: "built-in".to_owned(),
            provider_reference: None,
            secret_type: "opaque".to_owned(),
            status: "active".to_owned(),
            current_version: Some(1),
            created_unix_ms: NOW,
            updated_unix_ms: NOW,
        };
        let plaintext = SecretPlaintext::new(plaintext_marker.as_bytes().to_vec());
        let created = control
            .create_secret_idempotent("secret-key", &metadata, Some(&plaintext), &master_key)
            .unwrap();
        assert_eq!(created.value.current_version, Some(1));
        let rotated = control
            .rotate_secret_idempotent(
                "rotate-key",
                "tenant-1",
                "repository:repo-1",
                "registry-token",
                &SecretPlaintext::new(b"second-secret-value".to_vec()),
                &master_key,
                NOW + 3,
            )
            .unwrap();
        assert_eq!(rotated.value.current_version, Some(2));

        add_runner_pool_only(&control);
        enrollment_token = match control
            .create_enrollment_token_idempotent("enroll-key", "pool-1", 600, NOW, NOW + 600_000)
            .unwrap()
        {
            EnrollmentTokenIssueResult::Issued(issued) => issued.token.expose().to_owned(),
            EnrollmentTokenIssueResult::Replayed(_) => panic!("first issue replayed"),
        };
        assert!(matches!(
            control
                .create_enrollment_token_idempotent(
                    "enroll-key",
                    "pool-1",
                    600,
                    NOW + 1,
                    NOW + 600_001,
                )
                .unwrap(),
            EnrollmentTokenIssueResult::Replayed(_)
        ));
        assert!(matches!(
            control.create_enrollment_token_idempotent(
                "enroll-key",
                "pool-1",
                601,
                NOW + 1,
                NOW + 601_001,
            ),
            Err(ControlPlaneError::IdempotencyConflict)
        ));
    }

    for candidate in [
        path.clone(),
        sqlite_sidecar_path(&path, "-wal"),
        sqlite_sidecar_path(&path, "-shm"),
    ] {
        if let Ok(raw) = fs::read(candidate) {
            assert!(!raw
                .windows(plaintext_marker.len())
                .any(|window| window == plaintext_marker.as_bytes()));
        }
    }
    let reopened = ControlPlane::open(&path, "installation", NOW + 10).unwrap();
    assert_eq!(
        reopened
            .variable("tenant-1", "repository:repo-1", "MODE")
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        reopened
            .secret_metadata_by_name("tenant-1", "repository:repo-1", "registry-token")
            .unwrap()
            .current_version,
        Some(2)
    );
    assert_eq!(
        reopened
            .consume_enrollment_token(&enrollment_token, NOW + 10)
            .unwrap()
            .pool_id,
        "pool-1"
    );
}
