use super::support::*;
#[tokio::test]
async fn github_app_setup_binds_exact_tenant_repository_and_one_use_callback() {
    let control = Arc::new(ControlPlane::open_in_memory("github-api-http", 1).unwrap());
    seed_human_identity(&control);
    seed_active_tenant(&control, "tenant-other");
    control
        .create_repository(&tenant_repository(
            "repo-other-same-name",
            "tenant-other",
            "runtrue",
        ))
        .unwrap();
    // The installation callback synchronizes the provider catalog but does
    // not implicitly onboard repositories. Seed the tenant's explicit local
    // repository choice so the callback can bind only that existing record.
    control
        .create_repository(&tenant_repository(
            "github-repository-77",
            "tenant-browser",
            "runtrue",
        ))
        .unwrap();
    let provider = Arc::new(FakeGitHubInstallationProvider::new());
    let state = github_state(Arc::clone(&control), Arc::clone(&provider));
    let application = router(state.clone());

    let setup_request = || {
        idempotent_request(
            "POST",
            "/api/v1/scm/github/setup-transactions",
            "github-api-setup",
            json!({
                "tenant_id": "tenant-browser",
                "return_path": "/?github=installed"
            }),
        )
    };
    let first = application.clone().oneshot(setup_request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(first.headers()["idempotency-replayed"], "false");
    let first = json_body(first).await;
    assert_eq!(first["replayed"], false);
    let install_url = first["install_url"].as_str().unwrap().to_owned();
    assert!(install_url
        .starts_with("https://github.com/apps/runtrue-http-test/installations/new?state="));
    assert!(!install_url.contains(GITHUB_CREDENTIAL_REFERENCE));
    let setup_state = location_parameter(&install_url, "state");
    assert!(setup_state.len() >= 43);

    let replay = application.clone().oneshot(setup_request()).await.unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers()["idempotency-replayed"], "true");
    let replay = json_body(replay).await;
    assert_eq!(replay["id"], first["id"]);
    assert_eq!(replay["install_url"], first["install_url"]);
    assert_eq!(replay["expires_unix_ms"], first["expires_unix_ms"]);
    assert_eq!(replay["replayed"], true);

    let changed_replay = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/scm/github/setup-transactions",
            "github-api-setup",
            json!({
                "tenant_id": "tenant-browser",
                "return_path": "/ui/policy"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(changed_replay.status(), StatusCode::CONFLICT);
    let changed_problem = json_body(changed_replay).await.to_string();
    assert!(!changed_problem.contains(&setup_state));
    assert!(!changed_problem.contains(GITHUB_CREDENTIAL_REFERENCE));

    let invalid_action = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/github/app/callback?state={setup_state}&installation_id=9001&setup_action=delete"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_action.status(), StatusCode::UNAUTHORIZED);
    assert_github_callback_is_protected(&invalid_action);
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);

    let substituted_installation = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/github/app/callback?state={setup_state}&installation_id=9002&setup_action=install"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(substituted_installation.status(), StatusCode::BAD_GATEWAY);
    assert_github_callback_is_protected(&substituted_installation);
    let substitution_problem = json_body(substituted_installation).await.to_string();
    assert!(!substitution_problem.contains(&setup_state));
    assert!(!substitution_problem.contains(GITHUB_CREDENTIAL_REFERENCE));
    assert!(control
        .github_installation_for_tenant("tenant-browser", "github-installation-9001")
        .is_err());

    let callback = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/github/app/callback?state={setup_state}&installation_id=9001&setup_action=install"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(callback.headers()[LOCATION], "/?github=installed");
    assert_github_callback_is_protected(&callback);

    let callback_replay = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/github/app/callback?state={setup_state}&installation_id=9001&setup_action=install"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback_replay.status(), StatusCode::UNAUTHORIZED);
    assert_github_callback_is_protected(&callback_replay);
    let callback_replay = json_body(callback_replay).await.to_string();
    assert!(!callback_replay.contains(&setup_state));
    assert!(!callback_replay.contains(GITHUB_CREDENTIAL_REFERENCE));

    let (repository, installation, link) = control
        .github_repository_for_event("9001", "77", "octo", "runtrue")
        .unwrap();
    assert_eq!(repository.id, "github-repository-77");
    assert_eq!(repository.tenant_id, "tenant-browser");
    assert_eq!(installation.tenant_id, "tenant-browser");
    assert_eq!(link.tenant_id, "tenant-browser");
    assert_eq!(link.clone_url, "https://github.com/octo/runtrue.git");
    for substituted in [
        control.github_repository_for_event("9002", "77", "octo", "runtrue"),
        control.github_repository_for_event("9001", "78", "octo", "runtrue"),
        control.github_repository_for_event("9001", "77", "attacker", "runtrue"),
        control.github_repository_for_event("9001", "77", "octo", "other"),
    ] {
        assert!(substituted.is_err());
    }

    let status = application
        .clone()
        .oneshot(api_request(
            "GET",
            "/api/v1/scm/github?tenant_id=tenant-browser",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let status_text = text_body(status).await;
    assert!(!status_text.contains(GITHUB_CREDENTIAL_REFERENCE));
    assert!(!status_text.contains("private-key"));
    assert!(!status_text.contains(&setup_state));
    let status: Value = serde_json::from_str(&status_text).unwrap();
    assert_eq!(status["configured"], true);
    assert_eq!(status["app_id"], 123);
    assert_eq!(status["installations"][0]["external_id"], "9001");
    assert_eq!(status["installations"][0]["status"], "active");
    assert_eq!(
        status["repositories"][0]["linked_repository_id"],
        "github-repository-77"
    );

    let other_setup = application
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/scm/github/setup-transactions",
            "github-other-tenant-setup",
            json!({"tenant_id": "tenant-other"}),
        ))
        .await
        .unwrap();
    assert_eq!(other_setup.status(), StatusCode::CREATED);
    let other_setup = json_body(other_setup).await;
    let other_state = location_parameter(other_setup["install_url"].as_str().unwrap(), "state");
    let cross_tenant_callback = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/github/app/callback?state={other_state}&installation_id=9001&setup_action=install"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_tenant_callback.status(), StatusCode::UNAUTHORIZED);
    assert_github_callback_is_protected(&cross_tenant_callback);
    assert!(control
        .list_github_installations_for_tenant("tenant-other", None, 100)
        .unwrap()
        .is_empty());
    assert_eq!(
        control
            .github_installation_for_tenant("tenant-browser", "github-installation-9001")
            .unwrap()
            .installation
            .status,
        "active"
    );

    let lifecycle_body = serde_json::to_vec(&json!({
        "action": "suspend",
        "installation": {
            "id": 9001,
            "app_id": 123,
            "account": {
                "id": 501,
                "login": "octo",
                "type": "Organization"
            },
            "target_id": 501,
            "target_type": "Organization",
            "repository_selection": "selected",
            "permissions": {
                "metadata": "read",
                "contents": "read",
                "pull_requests": "read",
                "checks": "write"
            },
            "suspended_at": "2026-07-13T00:00:00Z"
        }
    }))
    .unwrap();
    let lifecycle_request = || {
        let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET).unwrap();
        mac.update(&lifecycle_body);
        Request::builder()
            .method("POST")
            .uri("/webhooks/github")
            .header(
                "x-hub-signature-256",
                format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
            )
            .header("x-github-delivery", "github-lifecycle-suspend-1")
            .header("x-github-event", "installation")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(lifecycle_body.clone()))
            .unwrap()
    };
    let lifecycle_reserved = application
        .clone()
        .oneshot(lifecycle_request())
        .await
        .unwrap();
    assert_eq!(lifecycle_reserved.status(), StatusCode::ACCEPTED);
    let lifecycle_replay = application
        .clone()
        .oneshot(lifecycle_request())
        .await
        .unwrap();
    assert_eq!(lifecycle_replay.status(), StatusCode::ACCEPTED);
    let metrics = state.github_installation_metrics().unwrap();
    assert_eq!(metrics.lifecycle_deliveries_reserved, 1);
    assert_eq!(metrics.lifecycle_delivery_replays, 1);

    assert!(state
        .process_github_lifecycle_once_at("github-http-lifecycle-worker", unix_ms_now(),)
        .await
        .unwrap());
    assert!(!state
        .process_github_lifecycle_once_at("github-http-lifecycle-worker", unix_ms_now(),)
        .await
        .unwrap());
    assert_eq!(
        control
            .github_installation_for_tenant("tenant-browser", "github-installation-9001")
            .unwrap()
            .installation
            .status,
        "suspended"
    );
    assert!(control
        .github_repository_for_event("9001", "77", "octo", "runtrue")
        .is_err());

    let other_token = issue_http_token(
        &application,
        "github-other-tenant-token",
        "other-principal",
        "tenant-other",
        &["api:read", "api:write", "scm:read", "scm:write"],
    )
    .await;
    let cross_tenant_status = application
        .clone()
        .oneshot(token_request(
            &other_token,
            "GET",
            "/api/v1/scm/github?tenant_id=tenant-browser",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(cross_tenant_status.status(), StatusCode::NOT_FOUND);
    let cross_tenant_problem = json_body(cross_tenant_status).await.to_string();
    assert!(!cross_tenant_problem.contains("9001"));
    assert!(!cross_tenant_problem.contains("octo"));
    assert!(!cross_tenant_problem.contains(GITHUB_CREDENTIAL_REFERENCE));

    let revoked = application
        .clone()
        .oneshot(api_request(
            "DELETE",
            "/api/v1/scm/github/installations/github-installation-9001?tenant_id=tenant-browser",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    assert!(control
        .github_repository_for_event("9001", "77", "octo", "runtrue")
        .is_err());

    let resync_revoked = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/scm/github/installations/github-installation-9001/sync?tenant_id=tenant-browser",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resync_revoked.status(), StatusCode::CONFLICT);
    assert_eq!(
        control
            .github_installation_for_tenant("tenant-browser", "github-installation-9001")
            .unwrap()
            .installation
            .status,
        "revoked"
    );
    let metrics = state.github_installation_metrics().unwrap();
    assert_eq!(metrics.setup_started, 2);
    assert_eq!(metrics.callbacks_completed, 1);
    assert!(metrics.callbacks_rejected >= 3);
    assert_eq!(metrics.installations_revoked, 1);
}

#[tokio::test]
async fn github_enterprise_setup_binds_exact_web_api_and_clone_origins() {
    const ENTERPRISE_WEB: &str = "https://github.example.com";
    const ENTERPRISE_API: &str = "https://github.example.com/api/v3";

    let control = Arc::new(ControlPlane::open_in_memory("github-ghes-http", 1).unwrap());
    seed_human_identity(&control);
    control
        .create_repository(&tenant_repository(
            "github-repository-77",
            "tenant-browser",
            "runtrue",
        ))
        .unwrap();
    let provider = Arc::new(FakeGitHubInstallationProvider::new());
    let enterprise_config = GitHubAppPublicConfig::new_with_origins(
        123,
        "runtrue-http-test",
        ENTERPRISE_WEB,
        ENTERPRISE_API,
    )
    .unwrap();
    let enterprise_state = github_state_with_public_config(
        Arc::clone(&control),
        Arc::clone(&provider),
        enterprise_config,
    );
    let enterprise = router(enterprise_state);

    let setup = enterprise
        .clone()
        .oneshot(idempotent_request(
            "POST",
            "/api/v1/scm/github/setup-transactions",
            "github-ghes-setup",
            json!({"tenant_id": "tenant-browser"}),
        ))
        .await
        .unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let setup = json_body(setup).await;
    let install_url = setup["install_url"].as_str().unwrap();
    assert!(install_url.starts_with(
        "https://github.example.com/github-apps/runtrue-http-test/installations/new?state="
    ));
    assert!(!install_url.contains("api/v3"));
    let setup_state = location_parameter(install_url, "state");

    // A restart with a different provider origin must reject the durable setup
    // before calling that provider, even when App and installation ids collide.
    let dot_com_state = github_state(Arc::clone(&control), Arc::clone(&provider));
    let changed_origin_callback = router(dot_com_state)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/github/app/callback?state={setup_state}&installation_id=9001&setup_action=install"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(changed_origin_callback.status(), StatusCode::UNAUTHORIZED);
    assert_github_callback_is_protected(&changed_origin_callback);
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);

    let callback = enterprise
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/github/app/callback?state={setup_state}&installation_id=9001&setup_action=install"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_github_callback_is_protected(&callback);
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);

    let (_, installation, link) = control
        .github_repository_for_event("9001", "77", "octo", "runtrue")
        .unwrap();
    assert_eq!(installation.external_id, "9001");
    assert_eq!(
        link.clone_url,
        "https://github.example.com/octo/runtrue.git"
    );
    let durable = control
        .github_installation_for_tenant("tenant-browser", "github-installation-9001")
        .unwrap();
    assert_eq!(durable.web_origin, ENTERPRISE_WEB);
    assert_eq!(durable.api_origin, ENTERPRISE_API);

    let status = enterprise
        .oneshot(api_request(
            "GET",
            "/api/v1/scm/github?tenant_id=tenant-browser",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let status = json_body(status).await;
    assert_eq!(status["web_origin"], ENTERPRISE_WEB);
    assert_eq!(status["api_origin"], ENTERPRISE_API);
    assert_eq!(status["provider_host"], "github.example.com");
    assert_eq!(status["installations"][0]["web_origin"], ENTERPRISE_WEB);
    assert_eq!(status["repositories"][0]["web_origin"], ENTERPRISE_WEB);
}

#[tokio::test]
async fn github_browser_api_requires_session_csrf_and_never_leaks_credentials() {
    let (control, oidc, provider, _, application) = github_human_application();
    control
        .create_repository(&tenant_repository(
            "repo-browser-approval",
            "tenant-browser",
            "approval-target",
        ))
        .unwrap();
    store_tenant_capsule(
        &control,
        "repo-browser-approval",
        "capsule-browser-approval",
    );
    store_tenant_approval_kind(
        &control,
        "repo-browser-approval",
        "capsule-browser-approval",
        "approval-browser-privileged",
        "runtrue-workflow-approver",
        ApprovalKind::PrivilegedExecution,
    );

    let anonymous = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/github")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    oidc.respond(&nonce, "subject-browser");
    let login = finish_human_login(&application, &login_cookie, &oidc_state).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
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
    assert_eq!(session.status(), StatusCode::OK);
    let csrf = json_body(session).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let page = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/github")
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()["cache-control"], "no-store");
    assert!(page.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let page = json_body(page).await;
    assert_eq!(page["session"]["csrfToken"], csrf);
    assert_eq!(page["session"]["avatarUrl"], Value::Null);
    assert_eq!(
        page["session"]["principalName"],
        "User <script>alert(1)</script>"
    );
    assert_eq!(page["capabilities"]["runs"], true);
    assert_eq!(page["capabilities"]["approvals"], true);
    assert_eq!(page["capabilities"]["runners"], true);
    assert_eq!(page["capabilities"]["apiTokens"], true);
    assert_eq!(page["capabilities"]["audit"], true);
    assert!(page["runs"].is_array());
    assert!(page["approvals"].is_array());
    let privileged = &page["approvals"][0];
    assert_eq!(privileged["id"], "approval-browser-privileged");
    assert_eq!(privileged["kind"], "privileged-execution");
    assert_eq!(privileged["repositoryId"], "repo-browser-approval");
    assert_eq!(privileged["repository"], "octo/approval-target");
    assert_eq!(privileged["workflow"]["name"], "ci");
    assert_eq!(privileged["workflow"]["path"], ".runtrue/workflows/ci.yaml");
    assert_eq!(privileged["jobs"][0]["name"], "Build");
    assert_eq!(privileged["remainingApprovals"], 1);
    assert_eq!(privileged["canDecide"], true);
    let approval_subject = privileged["subjectDigest"].as_str().unwrap().to_owned();
    assert!(page["runners"]["items"].is_array());
    assert!(page["apiTokens"].is_array());
    assert!(page["audit"].is_array());
    let page = page.to_string();
    assert!(!page.contains(GITHUB_CREDENTIAL_REFERENCE));
    assert!(!page.contains("private-key"));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);

    let decision = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ui/approvals/approval-browser-privileged/decisions")
                .header("cookie", &cookies)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={csrf}&idempotency_key=browser-privileged-decision&subject_digest={approval_subject}&decision=approve"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decision.status(), StatusCode::OK);
    assert_eq!(json_body(decision).await["status"], "approved");

    let post_form = |csrf_value: Option<&str>| {
        let mut fields = Vec::new();
        if let Some(csrf_value) = csrf_value {
            fields.push(format!("csrf_token={csrf_value}"));
        }
        fields.push("idempotency_key=github-ui-setup".to_owned());
        Request::builder()
            .method("POST")
            .uri("/github/installations/start")
            .header("cookie", &cookies)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(fields.join("&")))
            .unwrap()
    };

    let missing_csrf = application.clone().oneshot(post_form(None)).await.unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
    let wrong_csrf = application
        .clone()
        .oneshot(post_form(Some("wrong-csrf")))
        .await
        .unwrap();
    assert_eq!(wrong_csrf.status(), StatusCode::UNAUTHORIZED);
    let anonymous_mutation = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/github/installations/start")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={csrf}&idempotency_key=anonymous-ui-setup"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous_mutation.status(), StatusCode::UNAUTHORIZED);

    let started = application
        .clone()
        .oneshot(post_form(Some(&csrf)))
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::SEE_OTHER);
    assert_eq!(started.headers()["cache-control"], "no-store");
    assert_eq!(started.headers()["referrer-policy"], "no-referrer");
    let install_location = started.headers()[LOCATION].to_str().unwrap().to_owned();
    assert!(install_location
        .starts_with("https://github.com/apps/runtrue-http-test/installations/new?state="));
    assert!(!install_location.contains(GITHUB_CREDENTIAL_REFERENCE));

    let replay = application
        .clone()
        .oneshot(post_form(Some(&csrf)))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        replay.headers()[LOCATION].to_str().unwrap(),
        install_location
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn github_browser_manages_organization_secrets_and_variables_in_tenant_scope() {
    let (control, oidc, _, _, application) = github_human_application();
    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    oidc.respond(&nonce, "subject-browser");
    let login = finish_human_login(&application, &login_cookie, &oidc_state).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
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

    let form_request = |uri: &str, body: String| {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("cookie", &cookies)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    };
    let secret = application
        .clone()
        .oneshot(form_request(
            "/api/v1/ui/organization/secrets",
            format!("csrf_token={csrf}&idempotency_key=org-secret-1&name=TOKEN&value=secret-value"),
        ))
        .await
        .unwrap();
    assert_eq!(secret.status(), StatusCode::OK);
    assert_eq!(secret.headers()["cache-control"], "no-store");

    let variable = application
        .clone()
        .oneshot(form_request(
            "/api/v1/ui/organization/variables",
            format!("csrf_token={csrf}&idempotency_key=org-variable-1&name=REGION&value=us-east"),
        ))
        .await
        .unwrap();
    assert_eq!(variable.status(), StatusCode::OK);

    let settings = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/organization/settings")
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(settings.status(), StatusCode::OK);
    assert_eq!(settings.headers()["cache-control"], "no-store");
    let settings = json_body(settings).await;
    assert_eq!(settings["secrets"][0]["scope"], "tenant:tenant-browser");
    assert_eq!(settings["secrets"][0]["name"], "TOKEN");
    assert_eq!(settings["variables"][0]["scope"], "tenant:tenant-browser");
    assert_eq!(settings["variables"][0]["name"], "REGION");
    assert_eq!(settings["variables"][0]["value"], "us-east");
    assert_eq!(
        control
            .secret_metadata_by_name("tenant-browser", "tenant:tenant-browser", "TOKEN")
            .unwrap()
            .scope,
        "tenant:tenant-browser"
    );

    let delete_secret = application
        .clone()
        .oneshot(form_request(
            "/api/v1/ui/organization/secrets/delete",
            format!("csrf_token={csrf}&name=TOKEN"),
        ))
        .await
        .unwrap();
    assert_eq!(delete_secret.status(), StatusCode::OK);
    let delete_variable = application
        .oneshot(form_request(
            "/api/v1/ui/organization/variables/delete",
            format!("csrf_token={csrf}&name=REGION"),
        ))
        .await
        .unwrap();
    assert_eq!(delete_variable.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn github_secret_inventory_and_project_retargeting_enforce_each_target_policy() {
    let (control, oidc, _, _, application) = github_human_application();
    for (id, name) in [
        ("repo-secret-visible", "visible"),
        ("repo-secret-denied", "denied"),
    ] {
        control
            .create_repository(&tenant_repository(id, "tenant-browser", name))
            .unwrap();
        control
            .store_secret_metadata(&runtrue_control_plane::SecretMetadataReference {
                id: format!("secret-{name}"),
                tenant_id: "tenant-browser".to_owned(),
                scope: format!("repository:{id}"),
                name: format!("{name}-token"),
                provider: "external-test".to_owned(),
                provider_reference: Some(format!("provider://{name}")),
                secret_type: "opaque".to_owned(),
                status: "active".to_owned(),
                current_version: None,
                created_unix_ms: 1,
                updated_unix_ms: 1,
            })
            .unwrap();
    }
    control
        .put_configuration_project(&runtrue_control_plane::PutConfigurationProject {
            id: "project-protected".to_owned(),
            tenant_id: "tenant-browser".to_owned(),
            name: "protected".to_owned(),
            description: String::new(),
            status: "active".to_owned(),
            expected_version: 0,
            targets: vec![runtrue_control_plane::ConfigurationProjectTarget {
                kind: runtrue_control_plane::ConfigurationProjectTargetKind::Repository,
                id: "repo-secret-denied".to_owned(),
                created_unix_ms: 1,
            }],
            updated_unix_ms: 1,
        })
        .unwrap();

    let mut policy = ActivePolicyBundleState::new("tenant-browser").unwrap();
    policy
        .replace_emergency_denies(
            DenyFirstPolicy {
                emergency_denies: vec![EmergencyDeny {
                    id: "deny-protected-secret-target".to_owned(),
                    actions: BTreeSet::from([
                        "ReadSecretMetadata".to_owned(),
                        "WriteSecret".to_owned(),
                    ]),
                    repository_id: Some("repo-secret-denied".to_owned()),
                    minimum_risk_score: None,
                    deny_privileged: false,
                    deny_untrusted: false,
                }],
            },
            0,
        )
        .unwrap();
    control
        .replace_emergency_denies(
            &policy,
            0,
            &R9AuditMetadata {
                actor_id: "user-<browser>".to_owned(),
                correlation_id: "secret-scope-policy-test".to_owned(),
                occurred_unix_ms: unix_ms_now(),
            },
        )
        .unwrap();

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

    let inventory = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/secrets")
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inventory.status(), StatusCode::OK);
    let inventory = json_body(inventory).await;
    let encoded = inventory.to_string();
    assert!(!encoded.contains("denied-token"));
    assert!(!encoded.contains("repo-secret-denied"));
    assert!(inventory["secrets"].as_array().unwrap().is_empty());
    assert!(inventory["projects"].as_array().unwrap().is_empty());
    assert!(inventory["repositories"].as_array().unwrap().is_empty());

    let retarget = application
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ui/secret-projects")
                .header("cookie", &cookies)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={csrf}&id=project-protected&expected_version=1&name=protected&targets=%5B%5D"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retarget.status(), StatusCode::FORBIDDEN);
    let project = control
        .configuration_project("tenant-browser", "project-protected")
        .unwrap();
    assert_eq!(project.version, 1);
    assert_eq!(project.targets.len(), 1);
    assert_eq!(project.targets[0].id, "repo-secret-denied");
}

#[tokio::test]
async fn github_browser_sets_an_arbitrary_repository_relative_workflow_directory() {
    let (control, oidc, _, _, application) = github_human_application();
    control
        .create_repository(&tenant_repository(
            "repo-browser-workflow",
            "tenant-browser",
            "browser-workflow",
        ))
        .unwrap();
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

    let settings_uri = "/api/v1/ui/repositories/repo-browser-workflow/settings";
    let inherited = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(settings_uri)
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inherited.status(), StatusCode::OK);
    let inherited = json_body(inherited).await;
    assert_eq!(inherited["workflow_directory"], ".runtrue/workflows");
    assert_eq!(inherited["workflow_directory_inherited"], true);

    let save = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ui/repositories/repo-browser-workflow/workflow-directory")
                .header("cookie", &cookies)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={csrf}&workflow_directory=automation%2Fworkflows"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(save.status(), StatusCode::OK);
    assert_eq!(
        control
            .repository_workflow_directory("tenant-browser", "repo-browser-workflow")
            .unwrap()
            .as_deref(),
        Some("automation/workflows")
    );

    let settings = application
        .clone()
        .oneshot(
            Request::builder()
                .uri(settings_uri)
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let settings = json_body(settings).await;
    assert_eq!(settings["workflow_directory"], "automation/workflows");
    assert_eq!(settings["workflow_directory_inherited"], false);

    let traversal = application
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ui/repositories/repo-browser-workflow/workflow-directory")
                .header("cookie", &cookies)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "csrf_token={csrf}&workflow_directory=..%2Fworkflows"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(traversal.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn browser_run_detail_requires_a_session_and_returns_tenant_scoped_jobs() {
    let (control, oidc, _, _, application) = github_human_application();
    control
        .create_repository(&tenant_repository(
            "repo-browser-run",
            "tenant-browser",
            "browser-run",
        ))
        .unwrap();
    store_tenant_capsule(&control, "repo-browser-run", "capsule-browser-run");
    store_tenant_run(
        &control,
        "repo-browser-run",
        "capsule-browser-run",
        "run-browser-detail",
        "job-browser-detail",
    );

    let anonymous = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/runs/run-browser-detail")
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
    let detail = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/runs/run-browser-detail")
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(detail.headers()["cache-control"], "no-store");
    let detail = json_body(detail).await;
    assert_eq!(detail["jobs"][0]["id"], "job-browser-detail");
    assert_eq!(detail["jobs"][0]["key"], "build");
    assert_eq!(detail["jobs"][0]["name"], "Build");
    assert!(detail["jobs"][0]["steps"].is_array());
    assert_eq!(detail["jobs"][0]["status"], "queued");
    assert_eq!(detail["jobs"][0]["requirements"]["isolation"], "microvm");
    assert_eq!(detail["logs"], json!([]));
    assert_eq!(detail["logsTruncated"], false);

    seed_active_tenant(&control, "tenant-other");
    control
        .create_repository(&tenant_repository(
            "repo-other-run",
            "tenant-other",
            "other-run",
        ))
        .unwrap();
    store_tenant_capsule(&control, "repo-other-run", "capsule-other-run");
    store_tenant_run(
        &control,
        "repo-other-run",
        "capsule-other-run",
        "run-other-detail",
        "job-other-detail",
    );
    let cross_tenant = application
        .oneshot(
            Request::builder()
                .uri("/api/v1/ui/runs/run-other-detail")
                .header("cookie", cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn github_webhook_rejects_bad_hmac_and_durably_deduplicates_valid_delivery() {
    let (control_plane, application) = application(Some(WEBHOOK_SECRET));
    control_plane
        .create_repository(&tenant_repository(
            "repo-webhook",
            "tenant-webhook",
            "runtrue",
        ))
        .unwrap();
    let installation = runtrue_control_plane::ScmInstallationRecord {
        id: "github-installation-9001".to_owned(),
        tenant_id: "tenant-webhook".to_owned(),
        provider: "github".to_owned(),
        external_id: "9001".to_owned(),
        credential_reference: "provider://github-app/webhook-test".to_owned(),
        permissions: json!({
            "checks": "write",
            "contents": "read",
            "metadata": "read",
            "pull_requests": "read"
        }),
        status: "active".to_owned(),
        created_unix_ms: 1,
        updated_unix_ms: 1,
    };
    control_plane
        .create_scm_installation(&installation)
        .unwrap();
    control_plane
        .link_scm_repository(&runtrue_control_plane::ScmRepositoryLinkRecord {
            repository_id: "repo-webhook".to_owned(),
            tenant_id: "tenant-webhook".to_owned(),
            installation_id: installation.id,
            external_repository_id: "42".to_owned(),
            clone_url: "https://github.com/octo/runtrue.git".to_owned(),
            status: "active".to_owned(),
            created_unix_ms: 1,
            updated_unix_ms: 1,
        })
        .unwrap();
    let body = serde_json::to_vec(&json!({
        "installation": {"id": 9001},
        "repository": {
            "id": 42,
            "owner": {"login": "octo"},
            "name": "runtrue",
            "full_name": "octo/runtrue",
            "private": true,
            "default_branch": "main"
        },
        "sender": {"id": 7, "login": "builder", "type": "User"},
        "ref": "refs/heads/main",
        "after": "a".repeat(40),
        "before": "b".repeat(40),
        "commits": [{"added": ["src/main.rs"], "modified": [], "removed": []}]
    }))
    .unwrap();
    let delivery_id = "delivery-123";

    let request = |signature: String| {
        Request::builder()
            .method("POST")
            .uri("/webhooks/github")
            .header("x-hub-signature-256", signature)
            .header("x-github-delivery", delivery_id)
            .header("x-github-event", "push")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .unwrap()
    };

    let bad = application
        .clone()
        .oneshot(request(format!("sha256={}", "0".repeat(64))))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(bad.headers()[CONTENT_TYPE], "application/problem+json");

    let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET).unwrap();
    mac.update(&body);
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let accepted = application
        .clone()
        .oneshot(request(signature.clone()))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let replay = application
        .clone()
        .oneshot(request(signature))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);

    let digest = ContentDigest::sha256(delivery_id.as_bytes());
    let task_id = format!(
        "scm-github-{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let task = control_plane.task(&task_id).unwrap();
    assert_eq!(task.kind, "scm.event");
    assert_eq!(task.payload["event_id"], delivery_id);
    assert!(task.payload["provider"].is_string());
    assert_eq!(task.attempts, 0);

    let event_id = format!(
        "event-scm-github-{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let event = application
        .clone()
        .oneshot(api_request(
            "GET",
            &format!("/api/v1/events/{event_id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(event.status(), StatusCode::OK);
    let event = json_body(event).await;
    assert_eq!(event["source"], "backend");
    assert_eq!(event["status"], "pending");

    let claim_now = task.created_unix_ms + 1;
    let claimed = control_plane
        .claim_task_by_kind("scm-replay-test", "scm.event", claim_now, 1_000)
        .unwrap()
        .unwrap();
    control_plane
        .fail_task(
            &claimed.id,
            "scm-replay-test",
            "transient test failure",
            claim_now + 1,
            None,
            None,
        )
        .unwrap();
    let replay_request = || {
        idempotent_request(
            "POST",
            &format!("/api/v1/events/{event_id}/replay"),
            "replay-delivery-123",
            json!({}),
        )
    };
    let queued = application.clone().oneshot(replay_request()).await.unwrap();
    assert_eq!(queued.status(), StatusCode::ACCEPTED);
    assert_eq!(queued.headers()["idempotency-replayed"], "false");
    let queued_body = json_body(queued).await;
    let replay_task_id = queued_body["task_id"].as_str().unwrap().to_owned();
    let queued_again = application.oneshot(replay_request()).await.unwrap();
    assert_eq!(queued_again.status(), StatusCode::ACCEPTED);
    assert_eq!(queued_again.headers()["idempotency-replayed"], "true");
    let replay_task = control_plane.task(&replay_task_id).unwrap();
    assert_eq!(replay_task.kind, "scm.event");
    assert_eq!(replay_task.payload, task.payload);
}
