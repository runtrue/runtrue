use super::support::*;
#[tokio::test]
async fn human_oidc_session_refresh_replay_restart_and_ui_are_fail_closed() {
    let (control, adapter, state, application) = human_application();
    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    assert!(!login_cookie.contains(&nonce));
    assert!(!login_cookie.contains(&oidc_state));
    adapter.respond(&nonce, "subject-browser");
    let callback = finish_human_login(&application, &login_cookie, &oidc_state).await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(callback.headers()[LOCATION], "/ui/session");
    let session_cookies = browser_cookie_header(&callback);
    for name in ["runtrue_access", "runtrue_refresh", "runtrue_csrf"] {
        let cookie = callback
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .find_map(|value| {
                let value = value.to_str().ok()?;
                value.starts_with(&format!("{name}=")).then_some(value)
            })
            .unwrap();
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        if matches!(name, "runtrue_access" | "runtrue_csrf") {
            assert!(cookie.contains("SameSite=Lax"));
        } else {
            assert!(cookie.contains("SameSite=Strict"));
        }
    }

    let status = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(status.headers()["cache-control"], "no-store");
    let status = json_body(status).await;
    let csrf = status["csrf_token"].as_str().unwrap().to_owned();
    assert!(!session_cookies.contains(&csrf));
    assert_eq!(status["principal_id"], "user-<browser>");

    let page = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/session")
                .header("cookie", &session_cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
    let page = text_body(page).await;
    assert!(page.contains("user-&lt;browser&gt;"));
    assert!(!page.contains("user-<browser>"));
    assert!(page.contains(&csrf));

    let refresh = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/session/refresh")
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::NO_CONTENT);
    let rotated_cookies = browser_cookie_header(&refresh);
    assert_ne!(rotated_cookies, session_cookies);

    let replay = application
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/session/refresh")
                .header("cookie", &session_cookies)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let restarted = router(human_state(Arc::clone(&control), Arc::clone(&adapter)));
    let revoked = restarted
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header("cookie", rotated_cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let metrics = state.human_auth_metrics().unwrap();
    assert_eq!(metrics.login_started, 1);
    assert_eq!(metrics.callback_succeeded, 1);
    assert_eq!(metrics.session_rotated, 1);
    assert_eq!(metrics.refresh_replay_revoked, 1);
}

#[tokio::test]
async fn human_oidc_wrong_state_unknown_identity_and_provider_are_uniform_terminal_rejections() {
    let (_, adapter, _, application) = human_application();
    let unknown_tenant = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login?tenant_id=missing&provider_id=provider-browser")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let unknown_provider = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login?tenant_id=tenant-browser&provider_id=missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_tenant.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown_provider.status(), StatusCode::NOT_FOUND);
    let tenant_problem = json_body(unknown_tenant).await;
    let provider_problem = json_body(unknown_provider).await;
    assert_eq!(tenant_problem["title"], provider_problem["title"]);
    assert_eq!(tenant_problem["detail"], provider_problem["detail"]);

    let open_redirect = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login?tenant_id=tenant-browser&provider_id=provider-browser&return_to=https%3A%2F%2Fattacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(open_redirect.status(), StatusCode::BAD_REQUEST);

    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    adapter.respond(&nonce, "subject-browser");
    let wrong = finish_human_login(&application, &login_cookie, "wrong-state").await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(adapter.calls.load(Ordering::Relaxed), 0);
    let replay = finish_human_login(&application, &login_cookie, &oidc_state).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(adapter.calls.load(Ordering::Relaxed), 0);

    let (missing_cookie, missing_state, missing_nonce) = begin_human_login(&application).await;
    adapter.respond(&missing_nonce, "unprovisioned-subject");
    let missing = finish_human_login(&application, &missing_cookie, &missing_state).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(adapter.calls.load(Ordering::Relaxed), 1);
    adapter.respond(&missing_nonce, "subject-browser");
    let missing_replay = finish_human_login(&application, &missing_cookie, &missing_state).await;
    assert_eq!(missing_replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(adapter.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_exchanging_callback_remains_one_use_after_handler_restart() {
    let (control, adapter, _, application) = human_application();
    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    let (started, release) = adapter.block_next(&nonce);
    let callback_application = application.clone();
    let callback_request = Request::builder()
        .uri(format!(
            "/auth/oidc/callback?code=code-1&state={oidc_state}"
        ))
        .header("cookie", format!("runtrue_login={login_cookie}"))
        .body(Body::empty())
        .unwrap();
    let callback = tokio::spawn(callback_application.oneshot(callback_request));
    tokio::task::spawn_blocking(move || started.wait())
        .await
        .unwrap();
    let (second_cookie, second_state, _) = begin_human_login(&application).await;
    let saturated = finish_human_login(&application, &second_cookie, &second_state).await;
    assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(adapter.calls.load(Ordering::Relaxed), 1);
    callback.abort();
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .unwrap();
    let restarted = router(human_state(control, Arc::clone(&adapter)));
    let replay = finish_human_login(&restarted, &login_cookie, &oidc_state).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(adapter.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn concurrent_refresh_revokes_the_winning_family_and_survives_restart() {
    let (control, adapter, _, application) = human_application();
    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    adapter.respond(&nonce, "subject-browser");
    let callback = finish_human_login(&application, &login_cookie, &oidc_state).await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let cookies = browser_cookie_header(&callback);
    let status = application
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
    let csrf = json_body(status).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let refresh_request = || {
        Request::builder()
            .method("POST")
            .uri("/auth/session/refresh")
            .header("cookie", &cookies)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap()
    };
    let (first, second) = tokio::join!(
        application.clone().oneshot(refresh_request()),
        application.clone().oneshot(refresh_request())
    );
    let first = first.unwrap();
    let second = second.unwrap();
    let statuses = BTreeSet::from([first.status(), second.status()]);
    assert_eq!(
        statuses,
        BTreeSet::from([StatusCode::NO_CONTENT, StatusCode::UNAUTHORIZED])
    );
    let winning_cookies = if first.status() == StatusCode::NO_CONTENT {
        browser_cookie_header(&first)
    } else {
        browser_cookie_header(&second)
    };
    let restarted = router(human_state(control, adapter));
    let revoked = restarted
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header("cookie", winning_cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn preactivation_emergency_denies_browser_and_bootstrap_without_fallback() {
    let (control, adapter, _, application) = human_application();
    control
        .create_repository(&tenant_repository(
            "repo-browser-policy",
            "tenant-browser",
            "browser-policy",
        ))
        .unwrap();
    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    adapter.respond(&nonce, "subject-browser");
    let callback = finish_human_login(&application, &login_cookie, &oidc_state).await;
    let cookies = browser_cookie_header(&callback);
    let before = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policy-status")
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(before.status(), StatusCode::OK);

    let mut policy = ActivePolicyBundleState::new("tenant-browser").unwrap();
    policy
        .replace_emergency_denies(
            DenyFirstPolicy {
                emergency_denies: vec![EmergencyDeny {
                    id: "deny-browser-policy".to_owned(),
                    actions: BTreeSet::from([
                        "ManagePolicy".to_owned(),
                        "ViewRepository".to_owned(),
                    ]),
                    repository_id: None,
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
                correlation_id: "emergency-http-test".to_owned(),
                occurred_unix_ms: unix_ms_now(),
            },
        )
        .unwrap();
    let browser_denied = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policy-status")
                .header("cookie", &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(browser_denied.status(), StatusCode::FORBIDDEN);
    let bootstrap_denied = application
        .oneshot(api_request(
            "GET",
            "/api/v1/repositories/repo-browser-policy",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(bootstrap_denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn corrupt_live_policy_state_denies_browser_status_without_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control-plane.sqlite");
    let control = Arc::new(ControlPlane::open(&database, "human-policy-corrupt", 1).unwrap());
    seed_human_identity(&control);
    let adapter = Arc::new(FakeHumanOidcAdapter::default());
    let application = router(human_state(Arc::clone(&control), Arc::clone(&adapter)));
    let (login_cookie, oidc_state, nonce) = begin_human_login(&application).await;
    adapter.respond(&nonce, "subject-browser");
    let callback = finish_human_login(&application, &login_cookie, &oidc_state).await;
    let cookies = browser_cookie_header(&callback);

    let mut policy = ActivePolicyBundleState::new("tenant-browser").unwrap();
    policy
        .replace_emergency_denies(
            DenyFirstPolicy {
                emergency_denies: vec![EmergencyDeny {
                    id: "corruption-root".to_owned(),
                    actions: BTreeSet::from(["ManagePolicy".to_owned()]),
                    repository_id: None,
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
                correlation_id: "corrupt-policy-http-test".to_owned(),
                occurred_unix_ms: unix_ms_now(),
            },
        )
        .unwrap();
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE tenant_policy_states SET state_digest = ?2 WHERE tenant_id = ?1",
            rusqlite::params![
                "tenant-browser",
                ContentDigest::sha256(b"substituted live policy state").as_str()
            ],
        )
        .unwrap();
    let denied = application
        .oneshot(
            Request::builder()
                .uri("/api/v1/policy-status")
                .header("cookie", cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let problem = json_body(denied).await;
    assert_eq!(problem["title"], "Internal server error");
    assert!(!problem.to_string().contains("substituted"));
}
