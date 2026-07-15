use super::support::*;

#[tokio::test]
async fn replay_bundle_publication_rejects_explicit_tainted_completion() {
    let (control, application) = application(None);
    control
        .create_repository(&tenant_repository(
            "repo-replay-taint",
            "tenant-1",
            "replay-taint",
        ))
        .unwrap();
    store_tenant_capsule(&control, "repo-replay-taint", "capsule-replay-taint");
    for suffix in ["clean", "tainted"] {
        store_tenant_run(
            &control,
            "repo-replay-taint",
            "capsule-replay-taint",
            &format!("run-{suffix}"),
            &format!("job-{suffix}"),
        );
    }
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-replay-taint".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "replay-taint".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: 1,
        })
        .unwrap();
    control
        .register_runner_with_inventory(
            &RunnerRecord {
                id: "runner-replay-taint".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                pool_id: "pool-replay-taint".to_owned(),
                ephemeral: false,
                retired: false,
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation_backends: BTreeSet::from([Isolation::Microvm]),
                logical_cpus: 2,
                memory_bytes: 4_096,
                storage_bytes: 8_192,
                region: None,
                verified_capabilities: BTreeSet::from(["kvm".to_owned()]),
                self_reported_capabilities: BTreeSet::new(),
                status: RunnerStatus::Online,
                active_jobs: 0,
                used_cpus: 0,
                used_memory_bytes: 0,
                used_storage_bytes: 0,
                locality: BTreeSet::new(),
                last_heartbeat_unix_ms: 1,
            },
            &ContentDigest::sha256(b"replay-taint-runner-inventory"),
            1,
        )
        .unwrap();

    for ordinal in 0_u64..2 {
        let offered = control
            .offer_next_lease_for_runner("runner-replay-taint", 2 + ordinal * 10)
            .unwrap()
            .unwrap();
        let lease = control
            .accept_lease(
                &offered.id,
                "runner-replay-taint",
                offered.fencing_generation,
                offered.installation_fencing_epoch,
                3 + ordinal * 10,
            )
            .unwrap();
        control
            .transition_job_state(&lease.job_id, JobState::Running, 4 + ordinal * 10)
            .unwrap();
        control
            .transition_job_state(&lease.job_id, JobState::Finalizing, 5 + ordinal * 10)
            .unwrap();
        let taint = if lease.job_id == "job-tainted" {
            runtrue_control_plane::CredentialTaintState::CredentialReleased
        } else {
            runtrue_control_plane::CredentialTaintState::None
        };
        control
            .complete_lease_with_objects(
                &lease.id,
                "runner-replay-taint",
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &ContentDigest::sha256(lease.job_id.as_bytes()),
                JobState::Succeeded,
                taint,
                1,
                &[],
                &[],
                &[],
                6 + ordinal * 10,
            )
            .unwrap();
    }

    assert_eq!(
        control.run_credential_taint("run-clean").unwrap(),
        runtrue_control_plane::CredentialTaintState::None
    );

    let tainted = application
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/runs/run-tainted/replay-bundle",
            "tainted-replay",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(tainted.status(), StatusCode::CONFLICT);
    let problem = json_body(tainted).await;
    assert_eq!(problem["title"], "Replay Bundle publication blocked");
    assert!(problem["detail"]
        .as_str()
        .unwrap()
        .contains("released credential material"));
}

#[tokio::test]
async fn duplicate_idempotency_returns_the_original_run_and_conflicts_on_change() {
    let (control_plane, application) = application_with_capsule();
    let request = || {
        let mut request = api_request(
            "POST",
            "/api/v1/capsules/capsule-1/runs",
            r#"{"priority":4}"#,
        );
        request
            .headers_mut()
            .insert("idempotency-key", "same-request".parse().unwrap());
        request
    };

    let first = application.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(first.headers()["idempotency-replayed"], "false");
    let first_body = json_body(first).await;

    let second = application.clone().oneshot(request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);
    assert_eq!(second.headers()["idempotency-replayed"], "true");
    let second_body = json_body(second).await;
    assert_eq!(first_body["id"], second_body["id"]);
    assert_eq!(
        control_plane
            .workflow_semantics_metrics("tenant-1", i64::MAX as u64)
            .unwrap()
            .normalized_triggers,
        1
    );
    assert_eq!(
        control_plane
            .jobs_for_run(first_body["id"].as_str().unwrap())
            .unwrap()
            .len(),
        1
    );

    let mut changed = api_request(
        "POST",
        "/api/v1/capsules/capsule-1/runs",
        r#"{"priority":5}"#,
    );
    changed
        .headers_mut()
        .insert("idempotency-key", "same-request".parse().unwrap());
    let conflict = application.oneshot(changed).await.unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(conflict.headers()[CONTENT_TYPE], "application/problem+json");
    assert_eq!(json_body(conflict).await["status"], 409);
    assert_eq!(
        control_plane
            .workflow_semantics_metrics("tenant-1", i64::MAX as u64)
            .unwrap()
            .normalized_triggers,
        1
    );

    let rejected_local = application_with_capsule()
        .1
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/capsules/capsule-1/runs",
            "caller-local-bypass",
            json!({"remote": false}),
        ))
        .await
        .unwrap();
    assert_eq!(rejected_local.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn source_bound_api_run_binds_ready_snapshot_before_queue_and_trigger() {
    let (control, _) = application(None);
    control
        .create_repository(&tenant_repository(
            "repo-source-http",
            "tenant-1",
            "source-http",
        ))
        .unwrap();
    let tree_digest = ContentDigest::sha256(b"HTTP exact source tree");
    let mut capsule = execution_capsule();
    capsule.context.source_tree_digest = Some(tree_digest.clone());
    let signing_key = CapsuleSigningKey::from_seed([91; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    let capsule_digest = signature.capsule_digest.clone();
    control
        .store_signed_capsule(
            &SignedCapsuleRecord {
                id: "capsule-source-http".to_owned(),
                repository_id: "repo-source-http".to_owned(),
                digest: capsule_digest.clone(),
                canonical_capsule: capsule.canonical_bytes().unwrap(),
                signature,
                created_unix_ms: 1,
            },
            &signing_key.verifying_key(),
        )
        .unwrap();
    let correct = SourceSnapshotRecord {
        id: "snapshot-source-http".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-source-http".to_owned(),
        commit_sha: capsule.context.source_commit.clone(),
        tree_manifest_digest: tree_digest.clone(),
        state: SourceSnapshotState::Building,
        created_unix_ms: 1,
        verified_unix_ms: None,
    };
    control.create_source_snapshot(&correct).unwrap();
    control
        .mark_source_snapshot_ready("tenant-1", &correct.id, &tree_digest, 2)
        .unwrap();
    let wrong = SourceSnapshotRecord {
        id: "snapshot-source-http-wrong".to_owned(),
        commit_sha: "f".repeat(40),
        tree_manifest_digest: ContentDigest::sha256(b"wrong source tree"),
        ..correct.clone()
    };
    control.create_source_snapshot(&wrong).unwrap();
    control
        .mark_source_snapshot_ready("tenant-1", &wrong.id, &wrong.tree_manifest_digest, 2)
        .unwrap();
    let application = router(AppState::new(Arc::clone(&control), TOKEN, None).unwrap());

    let missing = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/capsules/capsule-source-http/runs",
            "source-http-missing",
            json!({"priority": 2}),
        ))
        .await
        .unwrap();
    let missing_status = missing.status();
    let missing_problem = json_body(missing).await;
    assert_eq!(
        missing_status,
        StatusCode::BAD_REQUEST,
        "unexpected problem response: {missing_problem}"
    );
    assert!(control
        .list_runs_page(Some("repo-source-http"), None, 10)
        .unwrap()
        .is_empty());

    let request = |snapshot_id: &str| {
        idempotent_request(
            "POST",
            "/api/v1/capsules/capsule-source-http/runs",
            "source-http-bind",
            json!({"priority": 2, "source_snapshot_id": snapshot_id}),
        )
    };
    let failed_binding = application
        .clone()
        .oneshot(request(&wrong.id))
        .await
        .unwrap();
    assert_eq!(failed_binding.status(), StatusCode::CONFLICT);
    let runs = control
        .list_runs_page(Some("repo-source-http"), None, 10)
        .unwrap();
    assert_eq!(runs.len(), 1);
    let run_id = runs[0].id.clone();
    assert_eq!(
        control.jobs_for_run(&run_id).unwrap()[0].status,
        JobState::Created
    );
    assert!(control.run_source_snapshot("tenant-1", &run_id).is_err());
    assert_eq!(
        control
            .workflow_semantics_metrics("tenant-1", i64::MAX as u64)
            .unwrap()
            .normalized_triggers,
        0
    );

    let recovered = application
        .clone()
        .oneshot(request(&correct.id))
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::CREATED);
    assert_eq!(recovered.headers()["idempotency-replayed"], "true");
    assert_eq!(json_body(recovered).await["id"], run_id);
    assert_eq!(
        control
            .run_source_snapshot("tenant-1", &run_id)
            .unwrap()
            .source_snapshot_id,
        correct.id
    );
    assert_eq!(
        control.jobs_for_run(&run_id).unwrap()[0].status,
        JobState::Queued
    );
    assert_eq!(
        control
            .workflow_semantics_metrics("tenant-1", i64::MAX as u64)
            .unwrap()
            .normalized_triggers,
        1
    );

    let changed = application
        .clone()
        .oneshot(request(&wrong.id))
        .await
        .unwrap();
    assert_eq!(changed.status(), StatusCode::CONFLICT);
    let exact = application.oneshot(request(&correct.id)).await.unwrap();
    assert_eq!(exact.status(), StatusCode::CREATED);
    assert_eq!(exact.headers()["idempotency-replayed"], "true");
    assert_eq!(
        control
            .workflow_semantics_metrics("tenant-1", i64::MAX as u64)
            .unwrap()
            .normalized_triggers,
        1
    );
    assert_eq!(
        control
            .run_source_snapshot("tenant-1", &run_id)
            .unwrap()
            .capsule_digest,
        capsule_digest
    );
}

#[tokio::test]
async fn api_run_trigger_replays_after_restart_and_cross_tenant_callers_cannot_create_it() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite3");
    let control_plane = Arc::new(ControlPlane::open(&database, "api-trigger-restart", 1).unwrap());
    control_plane
        .create_repository(&RepositoryRecord {
            id: "repo-restart".to_owned(),
            tenant_id: "tenant-restart".to_owned(),
            owner: "octo".to_owned(),
            name: "restart".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: 1,
        })
        .unwrap();
    let capsule = execution_capsule();
    let signing_key = CapsuleSigningKey::from_seed([83_u8; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    control_plane
        .store_signed_capsule(
            &SignedCapsuleRecord {
                id: "capsule-restart".to_owned(),
                repository_id: "repo-restart".to_owned(),
                digest: signature.capsule_digest.clone(),
                canonical_capsule: capsule.canonical_bytes().unwrap(),
                signature,
                created_unix_ms: 1,
            },
            &signing_key.verifying_key(),
        )
        .unwrap();
    let application = router(AppState::new(Arc::clone(&control_plane), TOKEN, None).unwrap());
    let request = || {
        idempotent_request(
            "POST",
            "/api/v1/capsules/capsule-restart/runs",
            "restart-api-trigger",
            json!({"priority": 3}),
        )
    };
    let first = application.oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first = json_body(first).await;
    drop(control_plane);

    let reopened = Arc::new(ControlPlane::open(&database, "api-trigger-restart", 2).unwrap());
    let application = router(AppState::new(Arc::clone(&reopened), TOKEN, None).unwrap());
    let replay = application.clone().oneshot(request()).await.unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers()["idempotency-replayed"], "true");
    assert_eq!(json_body(replay).await["id"], first["id"]);
    assert_eq!(
        reopened
            .workflow_semantics_metrics("tenant-restart", i64::MAX as u64)
            .unwrap()
            .normalized_triggers,
        1
    );

    let attacker = issue_http_token(
        &application,
        "cross-tenant-trigger-token",
        "attacker",
        "tenant-other",
        &["api:read", "api:write"],
    )
    .await;
    let denied = application
        .oneshot(token_idempotent_request(
            &attacker,
            "POST",
            "/api/v1/capsules/capsule-restart/runs",
            "cross-tenant-trigger",
            json!({"priority": 3}),
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    let denied_problem = json_body(denied).await;
    assert_eq!(denied_problem["title"], "Resource not found");
    assert!(!denied_problem.to_string().contains("capsule-restart"));
    assert_eq!(
        reopened
            .workflow_semantics_metrics("tenant-restart", i64::MAX as u64)
            .unwrap()
            .normalized_triggers,
        1
    );
}

#[tokio::test]
async fn compiled_capsule_run_replay_secrets_variables_and_promotions_follow_the_contract() {
    let (control_plane, application) = application(None);
    let repository = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/repositories",
            serde_json::to_vec(&json!({
                "id": "repo-api",
                "tenant_id": "tenant-api",
                "owner": "octo",
                "name": "api",
                "default_branch": "main",
                "visibility": "private"
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(repository.status(), StatusCode::CREATED);

    let workflow = r#"version: 1
name: api-test
permissions:
  network: deny
  repository: deny
jobs:
  build:
    runner: { isolation: microvm }
    steps:
      - id: test
        run: { command: ["echo", "ok"] }
"#;
    let capsule = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/repositories/repo-api/capsules",
            "create-capsule-api",
            json!({
                "source_commit": "a".repeat(40),
                "workflow_yaml": workflow,
                "event": {}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(capsule.status(), StatusCode::CREATED);
    assert_eq!(capsule.headers()["idempotency-replayed"], "false");
    let capsule = json_body(capsule).await;
    assert_eq!(capsule["status"], "signed");
    assert_eq!(capsule["approval_required"], true);
    assert_eq!(capsule["approval_requests"].as_array().unwrap().len(), 1);
    assert_eq!(
        capsule["approval_requests"][0]["approval_kind"],
        "workflow-definition"
    );
    assert_eq!(capsule["approval_requests"][0]["status"], "pending");
    assert!(capsule["signature"].is_object());
    assert!(capsule["capsule"].is_object());
    let capsule_id = capsule["id"].as_str().unwrap();
    let blocked = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/capsules/{capsule_id}/runs"),
            "unapproved-direct-workflow",
            json!({"priority": 7}),
        ))
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::CONFLICT);

    let approvals = application
        .clone()
        .oneshot(api_request(
            "GET",
            "/api/v1/approval-requests?status=pending&limit=10",
            Body::empty(),
        ))
        .await
        .unwrap();
    let approvals = json_body(approvals).await;
    let workflow_approval = approvals["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|approval| approval["approval_kind"] == "workflow-definition")
        .unwrap();
    let approval_id = workflow_approval["id"].as_str().unwrap();
    let subject_digest = workflow_approval["subject_digest"].as_str().unwrap();
    let approved = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/approval-requests/{approval_id}/decisions"),
            "approve-direct-workflow",
            json!({
                "decision": "approve",
                "subject_digest": subject_digest,
                "reason": "reviewed caller-supplied workflow",
                "rule_id": "bootstrap-security-review"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::CREATED);

    let run = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/capsules/{capsule_id}/runs"),
            "create-run-api",
            json!({"priority": 7}),
        ))
        .await
        .unwrap();
    assert_eq!(run.status(), StatusCode::CREATED);
    let run = json_body(run).await;
    let run_id = run["id"].as_str().unwrap();

    let listed = application
        .clone()
        .oneshot(api_request(
            "GET",
            "/api/v1/runs?repository_id=repo-api&limit=1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json_body(listed).await;
    assert_eq!(listed["items"][0]["id"], run_id);
    assert!(listed.get("next_cursor").is_some());

    let replay = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/runs/{run_id}/replay-bundle"),
            "replay-api",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    let replay = json_body(replay).await;
    assert_eq!(replay["title"], "Replay Bundle publication blocked");
    let downloaded = application
        .clone()
        .oneshot(api_request(
            "GET",
            &format!("/api/v1/runs/{run_id}/replay-bundle"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(downloaded.status(), StatusCode::NOT_FOUND);

    let secret_value = "never-return-this-plaintext";
    let secret = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/scopes/repository:repo-api/secrets",
            "secret-api",
            json!({
                "name": "registry-token",
                "secret_type": "opaque",
                "value": secret_value
            }),
        ))
        .await
        .unwrap();
    assert_eq!(secret.status(), StatusCode::CREATED);
    let secret = json_body(secret).await;
    assert_eq!(secret["current_version"], 1);
    assert!(secret.get("value").is_none());
    assert!(!secret.to_string().contains(secret_value));
    let secret_metadata = application
        .clone()
        .oneshot(api_request(
            "GET",
            "/api/v1/scopes/repository:repo-api/secrets/registry-token",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert!(!json_body(secret_metadata)
        .await
        .to_string()
        .contains(secret_value));

    let variable = application
        .clone()
        .oneshot(idempotent_request(
            "PUT",
            "/api/v1/scopes/repository:repo-api/variables/MODE",
            "variable-api",
            json!({"value": {"release": true}}),
        ))
        .await
        .unwrap();
    assert_eq!(variable.status(), StatusCode::OK);
    assert_eq!(json_body(variable).await["version"], 1);

    let cache_promotion = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/cache/entries/cache-1/promote",
            "cache-promotion-api",
            json!({
                "target_trust_domain": "verified",
                "evidence": {"attestation": "sha256:test"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(cache_promotion.status(), StatusCode::ACCEPTED);
    let promotion = json_body(cache_promotion).await;
    assert_eq!(promotion["status"], "pending");
    let task_id = format!("promotion-task:{}", promotion["id"].as_str().unwrap());
    assert_eq!(
        control_plane.task(&task_id).unwrap().status,
        DurableTaskStatus::Pending
    );

    let policy = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/policies/default/versions",
            "policy-api",
            json!({"source": "permit(principal, action, resource);", "mode": "draft"}),
        ))
        .await
        .unwrap();
    assert_eq!(policy.status(), StatusCode::CREATED);
    assert_eq!(json_body(policy).await["version"], 1);

    let discovery = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.status(), StatusCode::OK);
    let discovery = json_body(discovery).await;
    assert!(discovery["issuer"].as_str().unwrap().ends_with("/oidc"));
    assert!(discovery.get("token_endpoint").is_none());
    let jwks = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oidc/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwks = json_body(jwks).await;
    assert_eq!(jwks["keys"][0]["alg"], "EdDSA");
    assert!(jwks["keys"][0].get("d").is_none());

    let bootstrap_mint = application
        .clone()
        .oneshot(api_request("POST", "/oidc/token", json!({}).to_string()))
        .await
        .unwrap();
    assert_eq!(bootstrap_mint.status(), StatusCode::NOT_FOUND);
    let token = issue_http_token(
        &application,
        "former-oidc-mint",
        "workload-stealer",
        "tenant-api",
        &["oidc:mint"],
    )
    .await;
    let token_mint = application
        .oneshot(token_request(
            &token,
            "POST",
            "/oidc/token",
            json!({}).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(token_mint.status(), StatusCode::NOT_FOUND);
}
