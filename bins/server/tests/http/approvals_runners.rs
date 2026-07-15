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
