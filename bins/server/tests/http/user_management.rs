use super::support::*;

#[tokio::test]
async fn users_teams_and_repository_access_are_managed_through_core_api() {
    let (control, application) = application(None);
    let now = unix_ms_now();
    control
        .put_tenant_identity(
            &TenantIdentityRecord {
                id: "tenant-access".to_owned(),
                slug: "tenant-access".to_owned(),
                name: "Access Tenant".to_owned(),
                status: "active".to_owned(),
                settings: json!({}),
                created_unix_ms: now,
                updated_unix_ms: now,
                version: 1,
            },
            None,
        )
        .unwrap();
    control
        .create_repository(&RepositoryRecord {
            id: "repo-access".to_owned(),
            tenant_id: "tenant-access".to_owned(),
            owner: "acme".to_owned(),
            name: "backend".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: now,
        })
        .unwrap();

    for user in ["alice", "bob"] {
        let response = application
            .clone()
            .oneshot(api_request(
                "POST",
                "/api/v1/tenants/tenant-access/users",
                serde_json::to_vec(&json!({
                    "id": user,
                    "display_name": user,
                    "primary_email": format!("{user}@example.test")
                }))
                .unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let team = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/tenants/tenant-access/teams",
            r#"{"id":"platform","name":"Platform","description":"Platform team"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(team.status(), StatusCode::CREATED);

    let member = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/tenants/tenant-access/teams/platform/members",
            r#"{"user_id":"alice","role":"maintainer"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(member.status(), StatusCode::CREATED);

    for grant in [
        json!({"id":"direct","subject_kind":"user","subject_id":"alice","permission":"read"}),
        json!({"id":"team","subject_kind":"team","subject_id":"platform","permission":"admin"}),
    ] {
        let response = application
            .clone()
            .oneshot(api_request(
                "POST",
                "/api/v1/repositories/repo-access/access",
                serde_json::to_vec(&grant).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let effective = application
        .clone()
        .oneshot(api_request(
            "GET",
            "/api/v1/tenants/tenant-access/users/alice/repositories",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(effective.status(), StatusCode::OK);
    let effective = json_body(effective).await;
    assert_eq!(effective["items"][0]["repository_id"], "repo-access");
    assert_eq!(effective["items"][0]["permission"], "admin");
    assert_eq!(effective["items"][0]["direct"], true);
    assert_eq!(effective["items"][0]["team_ids"], json!(["platform"]));

    let disabled = application
        .clone()
        .oneshot(api_request(
            "PATCH",
            "/api/v1/tenants/tenant-access/teams/platform",
            r#"{"expected_version":1,"status":"disabled"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(disabled.status(), StatusCode::OK);
    let effective = application
        .clone()
        .oneshot(api_request(
            "GET",
            "/api/v1/tenants/tenant-access/users/alice/repositories",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(json_body(effective).await["items"][0]["permission"], "read");

    let bob = application
        .clone()
        .oneshot(api_request(
            "GET",
            "/api/v1/tenants/tenant-access/users/bob/repositories",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(json_body(bob).await["items"], json!([]));
}

#[tokio::test]
async fn identity_browser_api_requires_an_authorized_session_and_csrf() {
    let (control, oidc, _, application) = human_application();
    let anonymous = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/identity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    oidc.respond(&nonce, "subject-browser");
    let login = finish_human_login(&application, &login_cookie, &oidc_state).await;
    let cookies = browser_cookie_header(&login);
    let session = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csrf = json_body(session).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let missing_csrf = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ui/teams")
                .header("cookie", &cookies)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=Security"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

    let added_user = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ui/users")
                .header("cookie", &cookies)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={csrf}&display_name=New+User&primary_email=new%40example.test"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(added_user.status(), StatusCode::OK);
    let identity = json_body(added_user).await;
    let added_user = identity["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["primary_email"] == "new@example.test")
        .unwrap();
    assert_eq!(added_user["display_name"], "New User");
    assert_eq!(added_user["status"], "active");
    assert!(added_user["last_seen_at"].is_null());
    assert_eq!(added_user["team_ids"], json!([]));
    let added_user_id = added_user["id"].as_str().unwrap();
    assert!(added_user_id.starts_with("user_"));
    let persisted = control
        .human_user_for_tenant("tenant-browser", added_user_id)
        .unwrap();
    assert_eq!(persisted.last_seen_unix_ms, None);

    let created = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ui/teams")
                .header("cookie", &cookies)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={csrf}&id=security&name=Security&description=Production+reviewers"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let identity = json_body(created).await;
    assert_eq!(identity["teams"][0]["id"], "security");
    assert_eq!(identity["teams"][0]["name"], "Security");
    assert!(identity["users"]
        .as_array()
        .unwrap()
        .iter()
        .any(|user| user["display_name"] == "User <script>alert(1)</script>"));

    let loaded = application
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/identity")
                .header("cookie", cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(loaded.status(), StatusCode::OK);
    assert_eq!(json_body(loaded).await["teams"][0]["name"], "Security");
}
