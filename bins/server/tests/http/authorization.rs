use super::support::*;
#[tokio::test]
async fn cedar_object_authorization_and_sql_collections_isolate_every_tenant() {
    let (control_plane, application) = application(None);
    for (id, tenant, name) in [
        ("repo-a", "tenant-a", "alpha"),
        ("repo-b", "tenant-b", "beta"),
    ] {
        control_plane
            .create_repository(&tenant_repository(id, tenant, name))
            .unwrap();
        store_tenant_capsule(&control_plane, id, &format!("capsule-{name}"));
        store_tenant_run(
            &control_plane,
            id,
            &format!("capsule-{name}"),
            &format!("run-{name}"),
            &format!("job-{name}"),
        );
        store_tenant_approval(
            &control_plane,
            id,
            &format!("capsule-{name}"),
            &format!("approval-{name}"),
            if tenant == "tenant-a" {
                "tenant-a-user"
            } else {
                "tenant-b-user"
            },
        );
        store_tenant_runner(
            &control_plane,
            tenant,
            &format!("pool-{name}"),
            &format!("runner-{name}"),
        );
        control_plane
            .append_audit_event(tenant_audit(tenant, &format!("audit-{name}")))
            .unwrap();
    }

    let scopes = [
        "api:read",
        "api:write",
        "approvals:read",
        "approvals:write",
        "runners:read",
        "runners:write",
        "secrets:read",
        "secrets:write",
        "audit:read",
        "tokens:read",
        "tokens:write",
        "promotions:write",
        "policies:write",
    ];
    let token_a = issue_http_token(
        &application,
        "token-a",
        "tenant-a-user",
        "tenant-a",
        &scopes,
    )
    .await;
    let _token_b = issue_http_token(
        &application,
        "token-b",
        "tenant-b-user",
        "tenant-b",
        &scopes,
    )
    .await;

    for (path, expected_id) in [
        ("/api/v1/repositories", "repo-a"),
        ("/api/v1/runs", "run-alpha"),
        ("/api/v1/approval-requests", "approval-alpha"),
        ("/api/v1/runner-pools", "pool-alpha"),
        ("/api/v1/runners", "runner-alpha"),
    ] {
        let response = application
            .clone()
            .oneshot(token_request(&token_a, "GET", path, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body = json_body(response).await;
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{path}: {body}");
        let serialized = items[0].to_string();
        assert!(serialized.contains(expected_id), "{path}: {serialized}");
        assert!(!serialized.contains("beta"), "{path}: {serialized}");
    }

    let audit = application
        .clone()
        .oneshot(token_request(
            &token_a,
            "GET",
            "/api/v1/audit-events?limit=100",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(audit.status(), StatusCode::OK);
    let audit = json_body(audit).await;
    assert!(audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event["data"]["tenant_id"] == "tenant-a"));

    for path in [
        "/api/v1/repositories/repo-b",
        "/api/v1/capsules/capsule-beta",
        "/api/v1/runs/run-beta",
        "/api/v1/approval-requests/approval-beta",
        "/api/v1/runner-pools/pool-beta",
        "/api/v1/runners/runner-beta",
        "/api/v1/scopes/repository:repo-b/secrets",
        "/api/v1/scopes/repository:repo-b/variables/missing",
    ] {
        let response = application
            .clone()
            .oneshot(token_request(&token_a, "GET", path, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }

    let canceled = application
        .clone()
        .oneshot(token_request(
            &token_a,
            "POST",
            "/api/v1/runs/run-beta/cancel",
            r#"{"reason":"cross tenant"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(canceled.status(), StatusCode::NOT_FOUND);

    let enrollment = application
        .clone()
        .oneshot(token_request(
            &token_a,
            "POST",
            "/api/v1/runner-pools/pool-beta/enrollment-tokens",
            r#"{"expires_in_seconds":600}"#,
        ))
        .await
        .unwrap();
    assert_eq!(enrollment.status(), StatusCode::NOT_FOUND);
    let drain = application
        .clone()
        .oneshot(token_request(
            &token_a,
            "POST",
            "/api/v1/runners/runner-beta/drain",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(drain.status(), StatusCode::NOT_FOUND);

    let cross_variable = application
        .clone()
        .oneshot(token_idempotent_request(
            &token_a,
            "PUT",
            "/api/v1/scopes/repository:repo-b/variables/value",
            "cross-variable",
            json!({"value":"forbidden"}),
        ))
        .await
        .unwrap();
    assert_eq!(cross_variable.status(), StatusCode::NOT_FOUND);
    assert!(control_plane
        .variable("tenant-b", "repository:repo-b", "value")
        .is_err());

    let cross_revoke = application
        .clone()
        .oneshot(token_request(
            &token_a,
            "DELETE",
            "/api/v1/api-tokens/token-b",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(cross_revoke.status(), StatusCode::NOT_FOUND);

    for (path, body) in [
        (
            "/api/v1/cache/entries/cache-unowned/promote",
            json!({"target_trust_domain":"trusted","evidence":{}}),
        ),
        (
            "/api/v1/policies/unowned/versions",
            json!({"source":"permit(principal, action, resource);","mode":"draft"}),
        ),
    ] {
        let response = application
            .clone()
            .oneshot(token_request(
                &token_a,
                "POST",
                path,
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }

    let own_variable = application
        .clone()
        .oneshot(token_idempotent_request(
            &token_a,
            "PUT",
            "/api/v1/scopes/repository:repo-a/variables/value",
            "own-variable",
            json!({"value":"allowed"}),
        ))
        .await
        .unwrap();
    assert_eq!(own_variable.status(), StatusCode::OK);
    let own_repository = application
        .clone()
        .oneshot(token_request(
            &token_a,
            "GET",
            "/api/v1/repositories/repo-a",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(own_repository.status(), StatusCode::OK);

    let approval = control_plane.approval_request("approval-alpha").unwrap();
    let approved = application
        .clone()
        .oneshot(token_idempotent_request(
            &token_a,
            "POST",
            "/api/v1/approval-requests/approval-alpha/decisions",
            "approve-own",
            json!({
                "decision":"approve",
                "subject_digest":approval.subject_digest,
                "reason":"reviewed own tenant",
                "rule_id":"tenant-review"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::CREATED);
    assert!(control_plane
        .approval_request("approval-alpha")
        .unwrap()
        .decisions
        .contains_key("tenant-a-user"));

    assert_eq!(
        serde_json::to_value(control_plane.run("run-beta").unwrap().status).unwrap(),
        "created"
    );
    assert_eq!(
        control_plane.runner("runner-beta").unwrap().runner.status,
        RunnerStatus::Online
    );
}

#[tokio::test]
async fn cedar_default_deny_and_request_errors_fail_closed_over_http() {
    let control_plane = Arc::new(ControlPlane::open_in_memory("test-installation", 1).unwrap());
    control_plane
        .create_repository(&tenant_repository("repo-a", "tenant-a", "alpha"))
        .unwrap();
    let deny = CedarAuthorizationEngine::new("", DenyFirstPolicy::default()).unwrap();
    let state = AppState::new(control_plane.clone(), TOKEN, None)
        .unwrap()
        .with_authorization_engine(deny);
    let application = router(state);
    let token = issue_http_token(
        &application,
        "deny-token",
        "denied-user",
        "tenant-a",
        &["api:read"],
    )
    .await;
    let denied = application
        .clone()
        .oneshot(token_request(
            &token,
            "GET",
            "/api/v1/repositories/repo-a",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    // Cross-tenant request validation is a Cedar error and is hidden as not
    // found so object existence is not disclosed.
    control_plane
        .create_repository(&tenant_repository("repo-b", "tenant-b", "beta"))
        .unwrap();
    let errored = application
        .oneshot(token_request(
            &token,
            "GET",
            "/api/v1/repositories/repo-b",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(errored.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn restore_safe_mode_keeps_reads_available_and_blocks_every_mutation() {
    let (control_plane, application) = application(None);
    let recovery = control_plane.enter_restore_safe_mode(10).unwrap();
    assert_eq!(recovery.fencing_epoch, 2);

    let read = application
        .clone()
        .oneshot(api_request("GET", "/api/v1/repositories", Body::empty()))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);

    let mutation = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/repositories",
            r#"{"owner":"octo","name":"blocked"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(mutation.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(mutation.headers()[CONTENT_TYPE], "application/problem+json");

    let readiness = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(readiness.status(), StatusCode::SERVICE_UNAVAILABLE);

    control_plane.leave_restore_safe_mode(2).unwrap();
    let allowed = application
        .oneshot(api_request(
            "POST",
            "/api/v1/repositories",
            r#"{"owner":"octo","name":"allowed"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::CREATED);
}
