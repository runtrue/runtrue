use super::support::*;
#[tokio::test]
async fn api_routes_require_auth_and_fail_with_rfc7807() {
    let (_, application) = application(None);
    let health = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let disabled_browser_auth = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login?tenant_id=tenant&provider_id=provider")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disabled_browser_auth.status(), StatusCode::NOT_FOUND);

    let response = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/repositories")
                .header("x-request-id", "client-request-7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
    assert_eq!(response.headers()["x-request-id"], "client-request-7");
    let problem = json_body(response).await;
    assert_eq!(problem["status"], 401);
    assert_eq!(problem["request_id"], "client-request-7");
    assert!(!problem.to_string().contains(TOKEN));

    let method_error = application
        .oneshot(api_request("POST", "/api/v1/runners", Body::empty()))
        .await
        .unwrap();
    assert_eq!(method_error.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        method_error.headers()[CONTENT_TYPE],
        "application/problem+json"
    );
}

#[tokio::test]
async fn durable_api_tokens_are_one_time_scoped_tenant_bound_and_revocable() {
    let (control_plane, application) = application_with_capsule();
    let issued = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/api-tokens",
            serde_json::to_vec(&json!({
                "id": "api-http-1",
                "principal_id": "automation-1",
                "tenant_id": "tenant-1",
                "name": "read automation",
                "scopes": ["api:read", "approvals:read", "approvals:write", "tokens:read", "tokens:write"],
                "ttl_seconds": 600
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    assert_eq!(issued.headers()["cache-control"], "no-store");
    assert_eq!(issued.headers()["pragma"], "no-cache");
    let issued = json_body(issued).await;
    let token = issued["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 64);
    assert_eq!(issued["id"], "api-http-1");
    assert!(!issued.to_string().contains("hmac-sha256"));

    let read = application
        .clone()
        .oneshot(token_request(
            &token,
            "GET",
            "/api/v1/repositories",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);

    let write = application
        .clone()
        .oneshot(token_request(
            &token,
            "POST",
            "/api/v1/repositories",
            r#"{"owner":"octo","name":"forbidden"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(write.status(), StatusCode::FORBIDDEN);

    let escalation = application
        .clone()
        .oneshot(token_request(
            &token,
            "POST",
            "/api/v1/api-tokens",
            serde_json::to_vec(&json!({
                "principal_id": "bootstrap",
                "name": "identity forgery must fail",
                "scopes": ["api:read"],
                "ttl_seconds": 60
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(escalation.status(), StatusCode::FORBIDDEN);

    let forged_reviewer = application
        .clone()
        .oneshot(token_request(
            &token,
            "POST",
            "/api/v1/api-tokens",
            serde_json::to_vec(&json!({
                "principal_id": "reviewer-2",
                "name": "reviewer forgery must fail",
                "scopes": ["approvals:write"],
                "ttl_seconds": 60
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(forged_reviewer.status(), StatusCode::FORBIDDEN);

    let outliving_child = application
        .clone()
        .oneshot(token_request(
            &token,
            "POST",
            "/api/v1/api-tokens",
            serde_json::to_vec(&json!({
                "principal_id": "automation-1",
                "name": "must not outlive parent",
                "scopes": ["api:read"],
                "ttl_seconds": 601
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(outliving_child.status(), StatusCode::FORBIDDEN);

    let delegated = application
        .clone()
        .oneshot(token_request(
            &token,
            "POST",
            "/api/v1/api-tokens",
            serde_json::to_vec(&json!({
                "id": "api-http-child",
                "principal_id": "automation-1",
                "name": "exact self delegation",
                "scopes": ["api:read", "approvals:write"],
                "ttl_seconds": 60
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    let delegated_status = delegated.status();
    let delegated = json_body(delegated).await;
    assert_eq!(delegated_status, StatusCode::CREATED, "{delegated}");
    let child_token = delegated["token"].as_str().unwrap().to_owned();

    let subject = ContentDigest::sha256(b"two-distinct-identities");
    control_plane
        .create_approval_request(
            "repo-1",
            "capsule-1",
            &ApprovalRequest::create(
                "approval-distinct-identities",
                ApprovalKind::PrivilegedExecution,
                subject.clone(),
                90,
                1,
                4_000_000_000_000,
                ApprovalRule {
                    id: "two-identities".to_owned(),
                    required_approvals: 2,
                    eligible_approvers: BTreeSet::from([
                        "automation-1".to_owned(),
                        "reviewer-2".to_owned(),
                    ]),
                    forbidden_approvers: BTreeSet::new(),
                    one_shot: true,
                },
            )
            .unwrap(),
        )
        .unwrap();
    let decision = |bearer: &str, key: &str| {
        token_idempotent_request(
            bearer,
            "POST",
            "/api/v1/approval-requests/approval-distinct-identities/decisions",
            key,
            json!({
                "decision": "approve",
                "subject_digest": subject.to_string(),
                "reason": "distinct identity review",
                "rule_id": "two-identities"
            }),
        )
    };
    let parent_decision = application
        .clone()
        .oneshot(decision(&token, "parent-identity-decision"))
        .await
        .unwrap();
    assert_eq!(parent_decision.status(), StatusCode::CREATED);
    assert_eq!(json_body(parent_decision).await["status"], "pending");
    let child_duplicate = application
        .clone()
        .oneshot(decision(&child_token, "child-identity-decision"))
        .await
        .unwrap();
    assert_eq!(child_duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(
        control_plane
            .approval_request("approval-distinct-identities")
            .unwrap()
            .status,
        runtrue_policy::ApprovalStatus::Pending
    );

    let cross_tenant = application
        .clone()
        .oneshot(token_request(
            &token,
            "GET",
            "/api/v1/api-tokens?tenant_id=tenant-2",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(cross_tenant.status(), StatusCode::FORBIDDEN);

    let revoke = application
        .clone()
        .oneshot(api_request(
            "DELETE",
            "/api/v1/api-tokens/api-http-1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
    let after_revoke = application
        .clone()
        .oneshot(token_request(
            &token,
            "GET",
            "/api/v1/repositories",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(after_revoke.status(), StatusCode::UNAUTHORIZED);
    let child_after_parent_revoke = application
        .oneshot(token_request(
            &child_token,
            "GET",
            "/api/v1/repositories",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(child_after_parent_revoke.status(), StatusCode::UNAUTHORIZED);
}
