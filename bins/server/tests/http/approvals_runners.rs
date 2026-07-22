use super::support::*;
#[tokio::test]
async fn approval_subjects_and_one_time_enrollment_retries_fail_closed() {
    let (control_plane, application) = application(None);
    control_plane
        .create_repository(&RepositoryRecord {
            id: "repo-approval".to_owned(),
            tenant_id: "tenant-approval".to_owned(),
            owner: "octo".to_owned(),
            name: "approval".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: 1,
        })
        .unwrap();
    let workflow = r#"version: 1
name: privileged
permissions:
  network: deny
  repository: deny
jobs:
  deploy:
    trust: trusted-only
    environment: production
    runner: { isolation: native }
    steps:
      - id: deploy
        run: { command: ["true"] }
"#;
    let capsule = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/repositories/repo-approval/capsules",
            "approval-capsule",
            json!({
                "source_commit": "b".repeat(40),
                "workflow_yaml": workflow,
                "event": {}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(capsule.status(), StatusCode::CREATED);
    let capsule = json_body(capsule).await;
    assert_eq!(capsule["approval_required"], true);
    let capsule_id = capsule["id"].as_str().unwrap();

    let blocked = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/capsules/{capsule_id}/runs"),
            "blocked-run",
            json!({}),
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
    let approval_items = approvals["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|approval| {
            (
                approval["id"].as_str().unwrap().to_owned(),
                approval["subject_digest"].as_str().unwrap().to_owned(),
                approval["approval_kind"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(approval_items.len(), 2);
    assert!(approval_items
        .iter()
        .any(|(_, _, kind)| kind == "workflow-definition"));
    assert!(approval_items
        .iter()
        .any(|(_, _, kind)| kind == "privileged-execution"));
    let (approval_id, subject_digest, _) = &approval_items[0];

    let wrong_subject = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/approval-requests/{approval_id}/decisions"),
            "wrong-subject",
            json!({
                "decision": "approve",
                "subject_digest": format!("sha256:{}", "0".repeat(64)),
                "reason": "reviewed",
                "rule_id": "bootstrap-security-review"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_subject.status(), StatusCode::CONFLICT);

    for (index, (approval_id, subject_digest, _)) in approval_items.iter().enumerate() {
        let approved = application
            .clone()
            .oneshot(idempotent_request(
                "POST",
                &format!("/api/v1/approval-requests/{approval_id}/decisions"),
                &format!("approve-subject-{index}"),
                json!({
                    "decision": "approve",
                    "subject_digest": subject_digest,
                    "reason": "reviewed exact subject",
                    "rule_id": "bootstrap-security-review"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::CREATED);
        assert_eq!(approved.headers()["idempotency-replayed"], "false");
        assert_eq!(json_body(approved).await["status"], "approved");
    }
    let replayed = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/approval-requests/{approval_id}/decisions"),
            "approve-subject-0",
            json!({
                "decision": "approve",
                "subject_digest": subject_digest,
                "reason": "reviewed exact subject",
                "rule_id": "bootstrap-security-review"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(replayed.status(), StatusCode::CREATED);
    assert_eq!(replayed.headers()["idempotency-replayed"], "true");

    let authorized_request = || {
        idempotent_request(
            "POST",
            &format!("/api/v1/capsules/{capsule_id}/runs"),
            "authorized-run",
            json!({}),
        )
    };
    let authorized = application
        .clone()
        .oneshot(authorized_request())
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::CREATED);
    let authorized_id = json_body(authorized).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let authorized_replay = application
        .clone()
        .oneshot(authorized_request())
        .await
        .unwrap();
    assert_eq!(authorized_replay.status(), StatusCode::CREATED);
    assert_eq!(authorized_replay.headers()["idempotency-replayed"], "true");
    assert_eq!(json_body(authorized_replay).await["id"], authorized_id);
    let second_run = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            &format!("/api/v1/capsules/{capsule_id}/runs"),
            "second-one-shot-run",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(second_run.status(), StatusCode::CONFLICT);

    control_plane
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-api".to_owned(),
            tenant_id: "tenant-approval".to_owned(),
            name: "api".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: 1,
        })
        .unwrap();
    let issue = || {
        idempotent_request(
            "POST",
            "/api/v1/runner-pools/pool-api/enrollment-tokens",
            "enrollment-once",
            json!({"expires_in_seconds": 600}),
        )
    };
    let issued = application.clone().oneshot(issue()).await.unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    assert_eq!(issued.headers()["cache-control"], "no-store");
    assert_eq!(issued.headers()["pragma"], "no-cache");
    let token = json_body(issued).await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!token.is_empty());
    let retry = application.oneshot(issue()).await.unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(retry.headers()["idempotency-replayed"], "true");
    assert!(!json_body(retry).await.to_string().contains(&token));
}

#[tokio::test]
async fn autoscaler_http_contract_is_authenticated_exact_and_fenced() {
    let (control_plane, application) = application(None);
    control_plane
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-fleet-http".to_owned(),
            tenant_id: "tenant-fleet-http".to_owned(),
            name: "fleet-http".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: 1,
        })
        .unwrap();
    let compatibility = ContentDigest::sha256(b"http-compatibility");
    let template_digest = ContentDigest::sha256(b"http-template");
    control_plane
        .upsert_runner_pool_template(&runtrue_control_plane::RunnerPoolTemplateRecord {
            pool_id: "pool-fleet-http".to_owned(),
            runtime_compatibility_digest: compatibility.clone(),
            provider: "fake".to_owned(),
            provider_template_id: "fake-template".to_owned(),
            runner_template_digest: template_digest.clone(),
            created_unix_ms: 1,
            updated_unix_ms: 1,
        })
        .unwrap();
    control_plane
        .upsert_runner_pool_scaling_policy(&runtrue_control_plane::RunnerPoolScalingPolicy {
            pool_id: "pool-fleet-http".to_owned(),
            baseline_runtime_compatibility_digest: Some(compatibility.clone()),
            minimum_workers: 1,
            minimum_idle_workers: 0,
            maximum_workers: 3,
            scale_up_batch: 1,
            idle_timeout_ms: 60_000,
            offline_grace_ms: 60_000,
            cooldown_ms: 1_000,
            enabled: true,
            updated_unix_ms: 1,
        })
        .unwrap();

    let unauthenticated = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/runner-pools/pool-fleet-http/fleet")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let fleet_token = issue_http_token(
        &application,
        "fleet-token",
        "fleet-autoscaler",
        "tenant-fleet-http",
        &["runner-fleet:read", "runner-fleet:write"],
    )
    .await;
    let fleet_read = application
        .clone()
        .oneshot(token_request(
            &fleet_token,
            "GET",
            "/api/v1/runner-pools/pool-fleet-http/fleet",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(fleet_read.status(), StatusCode::OK);
    for (method, path) in [
        (
            "POST",
            "/api/v1/runner-pools/pool-fleet-http/enrollment-tokens",
        ),
        ("GET", "/api/v1/capsules/not-authorized"),
        ("GET", "/api/v1/scopes/tenant:tenant-fleet-http/secrets"),
    ] {
        let denied = application
            .clone()
            .oneshot(token_request(&fleet_token, method, path, Body::empty()))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }

    let lease = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/runner-pools/pool-fleet-http/fleet/lease",
            serde_json::to_vec(&json!({"expires_in_ms": 45000})).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(lease.status(), StatusCode::OK);
    let generation = json_body(lease).await["fencing_generation"]
        .as_u64()
        .unwrap();

    let request_body = json!({
        "fencing_generation": generation,
        "template": {
            "runtime_compatibility_digest": compatibility,
            "provider": "fake",
            "provider_template_id": "fake-template",
            "runner_template_digest": template_digest,
        }
    });
    let stale = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/runner-pools/pool-fleet-http/fleet/requests",
            serde_json::to_vec(&json!({
                "fencing_generation": generation + 1,
                "template": request_body["template"].clone(),
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);

    let created = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/runner-pools/pool-fleet-http/fleet/requests",
            serde_json::to_vec(&request_body).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let fleet_request_id = json_body(created).await["id"].as_str().unwrap().to_owned();

    let provisioning = application
        .clone()
        .oneshot(api_request(
            "POST",
            &format!(
                "/api/v1/runner-pools/pool-fleet-http/fleet/requests/{fleet_request_id}/transition"
            ),
            serde_json::to_vec(&json!({
                "expected_state": "requested",
                "next_state": "provisioning",
                "fencing_generation": generation,
                "detail": "provider-request-http",
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(provisioning.status(), StatusCode::OK);

    let claim = application
        .clone()
        .oneshot(api_request(
            "POST",
            &format!("/api/v1/runner-pools/pool-fleet-http/fleet/requests/{fleet_request_id}/launch-claim"),
            serde_json::to_vec(&json!({
                "fencing_generation": generation,
                "provider_instance_id": "instance-http",
                "identity_proof_digest": ContentDigest::sha256(b"identity-http"),
                "expires_in_ms": 60000,
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(claim.status(), StatusCode::CREATED);
    assert_eq!(claim.headers()["cache-control"], "no-store");
    let token = json_body(claim).await["token"].as_str().unwrap().to_owned();
    assert!(!token.is_empty());

    let fleet = application
        .oneshot(api_request(
            "GET",
            "/api/v1/runner-pools/pool-fleet-http/fleet",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(fleet.status(), StatusCode::OK);
    let serialized = json_body(fleet).await.to_string();
    assert!(serialized.contains(&fleet_request_id));
    assert!(!serialized.contains(&token));
}
