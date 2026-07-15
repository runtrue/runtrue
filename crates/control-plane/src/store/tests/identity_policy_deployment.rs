use super::*;
#[test]
fn schema_twenty_two_upgrades_and_reopens_with_required_r9_tables() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema-twenty-two.sqlite");
    let mut connection = Connection::open(&path).unwrap();
    let migrations = [
        MIGRATION_1,
        MIGRATION_2,
        MIGRATION_3,
        MIGRATION_4,
        MIGRATION_5,
        MIGRATION_6,
        MIGRATION_7,
        MIGRATION_8,
        MIGRATION_9,
        MIGRATION_10,
        MIGRATION_11,
        MIGRATION_12,
        MIGRATION_13,
        MIGRATION_14,
        MIGRATION_15,
        MIGRATION_16,
        MIGRATION_17,
        MIGRATION_18,
        MIGRATION_19,
        MIGRATION_20,
        MIGRATION_21,
        MIGRATION_22,
    ];
    for (offset, migration) in migrations.iter().enumerate() {
        apply_migration(
            &mut connection,
            migration,
            u32::try_from(offset + 1).unwrap(),
            NOW,
        )
        .unwrap();
    }
    connection
        .execute(
            "INSERT INTO installation_state(singleton, installation_id, fencing_epoch)
                 VALUES (1, 'r9-upgrade', 1)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO repositories
                 (id, tenant_id, owner, name, default_branch, visibility, created_unix_ms)
                 VALUES ('legacy-repo', 'legacy-tenant', 'owner', 'repo', 'main', 'private', ?1)",
            [to_i64(NOW).unwrap()],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    drop(ControlPlane::open(&path, "r9-upgrade", NOW + 1).unwrap());
    let control = ControlPlane::open(&path, "r9-upgrade", NOW + 2).unwrap();
    assert_eq!(control.tenant_identity("legacy-tenant").unwrap().version, 1);
    let connection = control.connection().unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    let violations: u64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0);
}

#[test]
fn r9_identity_provider_and_tenant_bindings_fail_closed() {
    let control = ControlPlane::open_in_memory("r9-identity", NOW).unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-a"), None)
        .unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-b"), None)
        .unwrap();
    let provider_a = r9_provider("tenant-a", "provider-a");
    let provider_b = r9_provider("tenant-b", "provider-b");
    control
        .put_tenant_oidc_provider_configuration(&provider_a, None)
        .unwrap();
    control
        .put_tenant_oidc_provider_configuration(&provider_b, None)
        .unwrap();
    add_r9_user(&control, "tenant-a", "victim", "viewer");

    assert!(matches!(
        control.put_human_user("tenant-b", &r9_user("victim"), None),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert!(matches!(
        control.put_tenant_membership(&r9_membership("tenant-b", "victim", "viewer"), None),
        Err(ControlPlaneError::NotFound { .. })
    ));
    assert!(matches!(
        control.human_user_for_tenant("tenant-b", "victim"),
        Err(ControlPlaneError::NotFound { .. })
    ));

    add_r9_user(&control, "tenant-b", "bob", "viewer");
    let identity = HumanIdentityRecord {
        id: "identity-bob".to_owned(),
        tenant_id: "tenant-b".to_owned(),
        user_id: "bob".to_owned(),
        provider_configuration_id: provider_b.id.clone(),
        issuer: provider_b.issuer.clone(),
        subject: "subject-bob".to_owned(),
        provider_kind: "oidc".to_owned(),
        claims_digest: ContentDigest::sha256(b"claims-1"),
        created_unix_ms: NOW,
        last_authenticated_unix_ms: NOW,
    };
    assert!(control.put_human_identity("tenant-b", &identity).unwrap());
    assert!(!control.put_human_identity("tenant-b", &identity).unwrap());
    assert_eq!(
        control
            .human_identity_for_subject(
                "tenant-b",
                &provider_b.id,
                &provider_b.issuer,
                &identity.subject,
            )
            .unwrap(),
        identity
    );
    for (tenant, provider, issuer, subject) in [
        (
            "tenant-a",
            provider_b.id.as_str(),
            provider_b.issuer.as_str(),
            identity.subject.as_str(),
        ),
        (
            "tenant-b",
            provider_a.id.as_str(),
            provider_a.issuer.as_str(),
            identity.subject.as_str(),
        ),
        (
            "tenant-b",
            provider_b.id.as_str(),
            provider_b.issuer.as_str(),
            "guessed-subject",
        ),
    ] {
        assert!(matches!(
            control.human_identity_for_subject(tenant, provider, issuer, subject),
            Err(ControlPlaneError::NotFound { .. })
        ));
    }
    let mut relogin = identity.clone();
    relogin.claims_digest = ContentDigest::sha256(b"claims-2");
    relogin.last_authenticated_unix_ms += 1;
    assert!(control.put_human_identity("tenant-b", &relogin).unwrap());
    let mut substituted = relogin;
    substituted.subject = "attacker-subject".to_owned();
    substituted.last_authenticated_unix_ms += 1;
    assert!(matches!(
        control.put_human_identity("tenant-b", &substituted),
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let mut provider_change = provider_b;
    provider_change.version = 2;
    provider_change.updated_unix_ms += 1;
    provider_change.token_endpoint.push_str("-substituted");
    provider_change.jwks_uri.push_str("-substituted");
    provider_change.mfa_claim = json!({"name":"groups","value":"admin"});
    provider_change.configuration_digest = provider_change.expected_configuration_digest().unwrap();
    assert!(matches!(
        control.put_tenant_oidc_provider_configuration(&provider_change, Some(1)),
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let mut suspended = r9_tenant("tenant-a");
    suspended.status = "suspended".to_owned();
    suspended.version = 2;
    suspended.updated_unix_ms += 1;
    control.put_tenant_identity(&suspended, Some(1)).unwrap();
    assert!(matches!(
        control.tenant_oidc_provider_configuration("tenant-a", "provider-a"),
        Err(ControlPlaneError::NotFound { .. })
    ));
}

#[test]
fn r9_oidc_and_session_restart_replay_expiry_and_tamper_are_bounded() {
    use runtrue_auth::{
        BeginOidcExchange, IssueOidcAuthorization, IssueSession, RotateSessionRequest,
        SessionPolicy,
    };

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("r9-auth.sqlite");
    let control = ControlPlane::open(&path, "r9-auth", NOW).unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-auth"), None)
        .unwrap();
    let provider = r9_provider("tenant-auth", "provider-auth");
    control
        .put_tenant_oidc_provider_configuration(&provider, None)
        .unwrap();
    add_r9_user(&control, "tenant-auth", "alice", "viewer");
    let hasher = TokenHasher::from_key([9; 32]);
    let issued = OidcAuthorizationTransaction::issue(
        &hasher,
        IssueOidcAuthorization {
            id: "login-1".to_owned(),
            tenant_id: "tenant-auth".to_owned(),
            provider_configuration_id: provider.id.clone(),
            issuer: provider.issuer.clone(),
            client_id: provider.client_id.clone(),
            redirect_uri: provider.redirect_uri.clone(),
            created_unix_ms: NOW,
            expires_unix_ms: NOW + 100,
        },
    )
    .unwrap();
    let state_plaintext = issued.state.expose().to_owned();
    let nonce_plaintext = issued.nonce.expose().to_owned();
    let verifier_plaintext = issued.pkce_verifier.expose().to_owned();
    let mut transaction_record = issued.record;
    assert!(control
        .persist_oidc_browser_transaction(
            &transaction_record,
            &r9_audit("anonymous-login", "login-created", NOW),
        )
        .unwrap());
    assert!(!control
        .persist_oidc_browser_transaction(
            &transaction_record,
            &r9_audit("anonymous-login", "login-created", NOW),
        )
        .unwrap());
    let mut rejected = OidcAuthorizationTransaction::issue(
        &hasher,
        IssueOidcAuthorization {
            id: "login-rejected".to_owned(),
            tenant_id: "tenant-auth".to_owned(),
            provider_configuration_id: provider.id.clone(),
            issuer: provider.issuer.clone(),
            client_id: provider.client_id.clone(),
            redirect_uri: provider.redirect_uri.clone(),
            created_unix_ms: NOW,
            expires_unix_ms: NOW + 100,
        },
    )
    .unwrap()
    .record;
    control
        .persist_oidc_browser_transaction(
            &rejected,
            &r9_audit("anonymous-login", "rejected-created", NOW),
        )
        .unwrap();
    rejected.reject_callback(NOW + 1).unwrap();
    assert!(control
        .persist_oidc_browser_transaction(
            &rejected,
            &r9_audit("anonymous-login", "rejected-callback", NOW + 1),
        )
        .unwrap());
    assert!(!control
        .persist_oidc_browser_transaction(
            &rejected,
            &r9_audit("anonymous-login", "rejected-callback", NOW + 1),
        )
        .unwrap());
    transaction_record
        .begin_exchange(
            &hasher,
            BeginOidcExchange {
                tenant_id: "tenant-auth",
                provider_configuration_id: &provider.id,
                issuer: &provider.issuer,
                client_id: &provider.client_id,
                redirect_uri: &provider.redirect_uri,
                state: &state_plaintext,
                pkce_verifier: &verifier_plaintext,
                now_unix_ms: NOW + 1,
            },
        )
        .unwrap();
    control
        .persist_oidc_browser_transaction(
            &transaction_record,
            &r9_audit("anonymous-login", "login-exchange", NOW + 1),
        )
        .unwrap();
    drop(control);

    let control = ControlPlane::open(&path, "r9-auth", NOW + 2).unwrap();
    assert_eq!(
        control
            .oidc_browser_transaction("tenant-auth", "login-1")
            .unwrap()
            .status,
        OidcTransactionStatus::Exchanging
    );
    assert_eq!(
        control
            .oidc_browser_transaction("tenant-auth", "login-rejected")
            .unwrap()
            .status,
        OidcTransactionStatus::Rejected
    );
    transaction_record
        .finish_identity(&hasher, &nonce_plaintext, NOW + 2)
        .unwrap();
    control
        .persist_oidc_browser_transaction(
            &transaction_record,
            &r9_audit("anonymous-login", "login-finished", NOW + 2),
        )
        .unwrap();
    {
        let connection = control.connection().unwrap();
        connection
            .execute(
                "UPDATE oidc_browser_transactions SET status = 'pending'
                     WHERE id = 'login-1'",
                [],
            )
            .unwrap();
    }
    assert!(matches!(
        control.oidc_browser_transaction("tenant-auth", "login-1"),
        Err(ControlPlaneError::CorruptState(_))
    ));

    let version_bound = OidcAuthorizationTransaction::issue(
        &hasher,
        IssueOidcAuthorization {
            id: "login-version-bound".to_owned(),
            tenant_id: "tenant-auth".to_owned(),
            provider_configuration_id: provider.id.clone(),
            issuer: provider.issuer.clone(),
            client_id: provider.client_id.clone(),
            redirect_uri: provider.redirect_uri.clone(),
            created_unix_ms: NOW + 3,
            expires_unix_ms: NOW + 90,
        },
    )
    .unwrap();
    let mut version_bound_record = version_bound.record;
    control
        .persist_oidc_browser_transaction(
            &version_bound_record,
            &r9_audit("anonymous-login", "version-bound", NOW + 3),
        )
        .unwrap();
    version_bound_record
        .begin_exchange(
            &hasher,
            BeginOidcExchange {
                tenant_id: "tenant-auth",
                provider_configuration_id: &provider.id,
                issuer: &provider.issuer,
                client_id: &provider.client_id,
                redirect_uri: &provider.redirect_uri,
                state: version_bound.state.expose(),
                pkce_verifier: version_bound.pkce_verifier.expose(),
                now_unix_ms: NOW + 4,
            },
        )
        .unwrap();
    let mut disabled_provider = provider.clone();
    disabled_provider.status = "disabled".to_owned();
    disabled_provider.version = 2;
    disabled_provider.updated_unix_ms += 4;
    disabled_provider.configuration_digest =
        disabled_provider.expected_configuration_digest().unwrap();
    control
        .put_tenant_oidc_provider_configuration(&disabled_provider, Some(1))
        .unwrap();
    assert!(matches!(
        control.persist_oidc_browser_transaction(
            &version_bound_record,
            &r9_audit("anonymous-login", "changed-provider-version", NOW + 4),
        ),
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let expired = OidcAuthorizationTransaction::issue(
        &hasher,
        IssueOidcAuthorization {
            id: "login-expired".to_owned(),
            tenant_id: "tenant-auth".to_owned(),
            provider_configuration_id: provider.id.clone(),
            issuer: provider.issuer.clone(),
            client_id: provider.client_id.clone(),
            redirect_uri: provider.redirect_uri.clone(),
            created_unix_ms: NOW,
            expires_unix_ms: NOW + 10,
        },
    )
    .unwrap();
    assert!(matches!(
        control.persist_oidc_browser_transaction(
            &expired.record,
            &r9_audit("anonymous-login", "late-login", NOW + 10),
        ),
        Err(ControlPlaneError::InvalidInput(_))
    ));

    let issued_session = SessionRecord::issue(
        &hasher,
        SessionPolicy::default(),
        IssueSession {
            id: "session-1".to_owned(),
            principal_id: "alice".to_owned(),
            tenant_id: "tenant-auth".to_owned(),
            device_id: "device-1".to_owned(),
            scopes: BTreeSet::from(["runs:read".to_owned()]),
            now_unix_ms: NOW,
            mfa_authenticated_unix_ms: Some(NOW),
        },
    )
    .unwrap();
    let original_refresh = issued_session.refresh_token.expose().to_owned();
    let original_csrf = issued_session.csrf_token.expose().to_owned();
    let mut session = issued_session.record;
    control
        .persist_browser_session(&session, None, &r9_audit("alice", "session-created", NOW))
        .unwrap();
    let rotated = session
        .rotate(
            &hasher,
            SessionPolicy::default(),
            RotateSessionRequest {
                refresh_token: &original_refresh,
                csrf_token: &original_csrf,
                require_mfa_within_ms: Some(100),
                now_unix_ms: NOW + 1,
            },
        )
        .unwrap();
    control
        .persist_browser_session(
            &session,
            Some(1),
            &r9_audit("alice", "session-rotated", NOW + 1),
        )
        .unwrap();
    let mut cleared_mfa = session.clone();
    cleared_mfa.mfa_authenticated_unix_ms = None;
    assert!(matches!(
        control.persist_browser_session(
            &cleared_mfa,
            Some(2),
            &r9_audit("alice", "mfa-cleared", NOW + 2),
        ),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(matches!(
        session.rotate(
            &hasher,
            SessionPolicy::default(),
            RotateSessionRequest {
                refresh_token: &original_refresh,
                csrf_token: rotated.csrf_token.expose(),
                require_mfa_within_ms: None,
                now_unix_ms: NOW + 2,
            },
        ),
        Err(AuthError::RefreshReplay)
    ));
    control
        .persist_browser_session(
            &session,
            Some(2),
            &r9_audit("alice", "session-replay-revoked", NOW + 2),
        )
        .unwrap();
    assert!(!control
        .persist_browser_session(
            &session,
            Some(2),
            &r9_audit("alice", "session-replay-revoked", NOW + 2),
        )
        .unwrap());

    let mut user = r9_user("alice");
    user.status = "suspended".to_owned();
    user.version = 2;
    user.updated_unix_ms += 3;
    control
        .put_human_user("tenant-auth", &user, Some(1))
        .unwrap();
    assert!(matches!(
        control.persist_browser_session(
            &session,
            Some(2),
            &r9_audit("alice", "suspended", NOW + 3),
        ),
        Err(ControlPlaneError::NotFound { .. })
    ));

    {
        let connection = control.connection().unwrap();
        connection
                .execute(
                    "UPDATE browser_sessions SET record_digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                     WHERE id = 'session-1'",
                    [],
                )
                .unwrap();
    }
    assert!(matches!(
        control.browser_session("tenant-auth", "session-1"),
        Err(ControlPlaneError::CorruptState(_))
    ));

    let database = fs::read(&path).unwrap();
    for plaintext in [
        state_plaintext,
        nonce_plaintext,
        verifier_plaintext,
        original_refresh,
        original_csrf,
    ] {
        assert!(!database
            .windows(plaintext.len())
            .any(|window| window == plaintext.as_bytes()));
    }
}

#[test]
fn r9_policy_evidence_activation_emergency_and_tamper_fail_closed() {
    use runtrue_policy::{
        ActivatePolicyBundle, ActivePolicyBundleState, CedarAction, CedarAuthorizationRequest,
        CedarPrincipal, CedarPrincipalKind, CedarRequestContext, CedarResource, CedarResourceKind,
        EmergencyDeny, PolicyBundleDraft, PolicySimulationCase,
    };

    const PERMIT: &str = r#"permit (
            principal,
            action == Action::"ViewRepository",
            resource is Repository
        );"#;
    fn policy_case() -> PolicySimulationCase {
        PolicySimulationCase {
            id: "stored-case".to_owned(),
            request: CedarAuthorizationRequest {
                principal: CedarPrincipal {
                    kind: CedarPrincipalKind::User,
                    id: "author".to_owned(),
                    tenant_id: "tenant-policy".to_owned(),
                    groups: BTreeSet::new(),
                },
                action: CedarAction::ViewRepository,
                resource: CedarResource {
                    kind: CedarResourceKind::Repository,
                    id: "repo-1".to_owned(),
                    tenant_id: "tenant-policy".to_owned(),
                    repository_id: Some("repo-1".to_owned()),
                    author_id: None,
                    risk_score: 0,
                    privileged: false,
                    untrusted: false,
                },
                context: CedarRequestContext::default(),
            },
            expected_allowed: Some(true),
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("r9-policy.sqlite");
    let control = ControlPlane::open(&path, "r9-policy", NOW).unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-policy"), None)
        .unwrap();
    add_r9_user(&control, "tenant-policy", "author", "policy-admin");
    add_r9_user(&control, "tenant-policy", "reviewer", "policy-admin");

    let mut state = ActivePolicyBundleState::new("tenant-policy").unwrap();
    let mut draft =
        PolicyBundleDraft::new("draft-policy", "tenant-policy", "author", PERMIT, NOW).unwrap();
    control
        .persist_policy_draft(&draft, &r9_audit("author", "draft", NOW))
        .unwrap();
    let simulation = state.simulate(&mut draft, &[policy_case()], &[]).unwrap();
    control
        .persist_policy_simulation(
            &draft,
            &simulation,
            &r9_audit("author", "simulation", NOW + 1),
        )
        .unwrap();
    let mut forged = simulation.clone();
    forged.results[0].allowed = false;
    assert!(forged.verify().is_err());
    draft.enter_shadow(&simulation.report_digest).unwrap();
    let shadow = state.compare_shadow(&draft, &[policy_case()]).unwrap();
    control
        .persist_policy_shadow(
            &draft,
            Some(&shadow),
            &r9_audit("author", "shadow", NOW + 2),
        )
        .unwrap();
    let activation = ActivatePolicyBundle {
        draft_digest: draft.digest.clone(),
        simulation_digest: simulation.report_digest.clone(),
        expected_policy_epoch: 0,
        approval_id: "approval-policy".to_owned(),
        approved_by: "reviewer".to_owned(),
        approved_unix_ms: NOW + 3,
    };
    state.activate(&mut draft, &activation).unwrap();
    let mut substituted_state = state.clone();
    substituted_state.emergency_denies = DenyFirstPolicy {
        emergency_denies: vec![EmergencyDeny {
            id: "substituted-deny".to_owned(),
            actions: BTreeSet::new(),
            repository_id: None,
            minimum_risk_score: None,
            deny_privileged: false,
            deny_untrusted: false,
        }],
    };
    assert!(matches!(
        control.activate_policy_bundle(
            &draft,
            &substituted_state,
            &activation,
            &r9_audit("reviewer", "activation-substitution", NOW + 3),
        ),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    assert!(matches!(
        control.activate_policy_bundle(
            &draft,
            &state,
            &activation,
            &r9_audit("author", "self-activation", NOW + 3),
        ),
        Err(ControlPlaneError::InvalidInput(_))
    ));
    control
        .activate_policy_bundle(
            &draft,
            &state,
            &activation,
            &r9_audit("reviewer", "activation", NOW + 3),
        )
        .unwrap();
    assert!(!control
        .activate_policy_bundle(
            &draft,
            &state,
            &activation,
            &r9_audit("reviewer", "activation", NOW + 3),
        )
        .unwrap());
    drop(control);

    let control = ControlPlane::open(&path, "r9-policy", NOW + 4).unwrap();
    assert_eq!(control.active_policy_state("tenant-policy").unwrap(), state);
    let previous_generation = state.decision_cache_generation;
    state
        .replace_emergency_denies(
            DenyFirstPolicy {
                emergency_denies: vec![EmergencyDeny {
                    id: "halt".to_owned(),
                    actions: BTreeSet::from(["ViewRepository".to_owned()]),
                    repository_id: Some("repo-1".to_owned()),
                    minimum_risk_score: None,
                    deny_privileged: false,
                    deny_untrusted: false,
                }],
            },
            previous_generation,
        )
        .unwrap();
    control
        .replace_emergency_denies(
            &state,
            previous_generation,
            &r9_audit("reviewer", "emergency", NOW + 5),
        )
        .unwrap();
    assert!(!control
        .replace_emergency_denies(
            &state,
            previous_generation,
            &r9_audit("reviewer", "emergency", NOW + 5),
        )
        .unwrap());
    assert!(matches!(
        control.replace_emergency_denies(
            &state,
            previous_generation + 9,
            &r9_audit("reviewer", "changed-replay", NOW + 5),
        ),
        Err(ControlPlaneError::IdempotencyConflict)
    ));
    {
        let connection = control.connection().unwrap();
        connection
            .execute(
                "UPDATE tenant_policy_states SET state_digest =
                     'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                     WHERE tenant_id = 'tenant-policy'",
                [],
            )
            .unwrap();
    }
    assert!(matches!(
        control.active_policy_state("tenant-policy"),
        Err(ControlPlaneError::CorruptState(_))
    ));
}

#[test]
fn r10_external_secret_authority_is_exact_tenant_safe_and_restart_durable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("external-authority.sqlite");
    let subject_digest = ContentDigest::sha256(b"external-authority-approval");
    let active;
    {
        let control = ControlPlane::open(&path, "external-authority", NOW).unwrap();
        control.create_repository(&repository()).unwrap();
        control
            .put_tenant_identity(&r9_tenant("tenant-1"), None)
            .unwrap();
        let provider = r10_provider("tenant-1", "external-provider", "external-secret");
        control
            .put_tenant_provider_configuration(&provider, None)
            .unwrap();
        control
            .create_secret_idempotent(
                "external-secret-key",
                &SecretMetadataReference {
                    id: "external-secret".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    scope: "repository:repo-1".to_owned(),
                    name: "TOKEN".to_owned(),
                    provider: provider.id.clone(),
                    provider_reference: Some("secret/data/releases#token".to_owned()),
                    secret_type: "dynamic".to_owned(),
                    status: "active".to_owned(),
                    current_version: None,
                    created_unix_ms: NOW,
                    updated_unix_ms: NOW,
                },
                None,
                &MasterKey::from_bytes([91; 32]),
            )
            .unwrap();
        add_r9_user(&control, "tenant-1", "policy-author", "policy-admin");
        {
            let connection = control.connection().unwrap();
            connection
                .execute(
                    "INSERT INTO policy_bundle_drafts
                         (id, tenant_id, author_id, policy_digest, draft_json, status,
                          simulation_digest, activated_policy_epoch, audit_correlation_id,
                          created_unix_ms, updated_unix_ms)
                         VALUES ('external-policy', 'tenant-1', 'policy-author', ?1,
                                 CAST('{}' AS BLOB),
                                 'activated', ?2, 1, 'external-policy-activation', ?3, ?3)",
                    params![
                        ContentDigest::sha256(b"external-policy").as_str(),
                        ContentDigest::sha256(b"external-policy-simulation").as_str(),
                        to_i64(NOW).unwrap(),
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO tenant_policy_states
                         (tenant_id, policy_epoch, decision_cache_generation, active_draft_id,
                          active_policy_digest, state_digest, state_json, version, actor_id,
                          audit_correlation_id, updated_unix_ms)
                         VALUES ('tenant-1', 1, 1, 'external-policy', ?1, ?2,
                                 CAST('{}' AS BLOB), 1,
                                 'policy-author', 'external-policy-activation', ?3)",
                    params![
                        ContentDigest::sha256(b"external-policy").as_str(),
                        ContentDigest::sha256(b"external-policy-state").as_str(),
                        to_i64(NOW).unwrap(),
                    ],
                )
                .unwrap();
        }
        let mut environment = EnvironmentRecord {
            id: "environment-production".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            repository_id: "repo-1".to_owned(),
            name: "production".to_owned(),
            deployment_target_reference: "deployment-target://production".to_owned(),
            deployment_target_digest: ContentDigest::sha256(b"placeholder"),
            status: "active".to_owned(),
            protection_rules: crate::types::EnvironmentProtectionRules {
                require_approval: false,
                minimum_approvals: 0,
                approval_ttl_ms: 0,
                approval_rule_digest: None,
                require_signed_artifact: false,
                required_artifact_classification: "release".to_owned(),
                require_passed_scan: false,
                require_promotion_evidence: false,
                allowed_deployment_actors: Vec::new(),
                allowed_signing_purposes: Vec::new(),
                allowed_signer_policy_ids: Vec::new(),
            },
            protection_rules_digest: ContentDigest::sha256(b"placeholder"),
            wait_timer_ms: 0,
            concurrency_limit: 1,
            secret_provider_configuration_id: Some(provider.id.clone()),
            signing_provider_configuration_id: None,
            required_policy_epoch: 1,
            last_concurrency_fence: 0,
            created_unix_ms: NOW,
            updated_unix_ms: NOW,
            version: 1,
        };
        environment.deployment_target_digest = environment.expected_deployment_target_digest();
        environment.protection_rules_digest =
            environment.expected_protection_rules_digest().unwrap();
        control.put_environment(&environment, None).unwrap();

        let mut capsule = execution_capsule();
        capsule.approval.privileged_execution = true;
        capsule.jobs[0].id = "publish".to_owned();
        capsule.jobs[0].base_id = "publish".to_owned();
        capsule.jobs[0].name = "publish".to_owned();
        capsule.jobs[0].environment = Some("production".to_owned());
        capsule.jobs[0].steps = vec![PlannedStep {
            id: "release".to_owned(),
            name: "release".to_owned(),
            condition: None,
            action: StepAction::Command {
                program: "true".to_owned(),
                args: Vec::new(),
            },
            inputs: BTreeMap::new(),
            environment: BTreeMap::new(),
            capabilities: StepCapabilitySet {
                secrets: vec![SecretReference {
                    metadata_id: "external-secret".to_owned(),
                    name: "TOKEN".to_owned(),
                    purpose: Some("publish".to_owned()),
                }],
                ..StepCapabilitySet::default()
            },
            cache: None,
            timeout_ms: None,
            continue_on_error: false,
            outputs: BTreeMap::new(),
            working_directory: None,
        }];
        let signing_key = CapsuleSigningKey::from_seed([81; 32]);
        let signature = signing_key.sign_capsule(&capsule).unwrap();
        let signed = SignedCapsuleRecord {
            id: "capsule-external".to_owned(),
            repository_id: "repo-1".to_owned(),
            digest: signature.capsule_digest.clone(),
            canonical_capsule: capsule.canonical_bytes().unwrap(),
            signature,
            created_unix_ms: NOW,
        };
        let approval = pending_approval(
            "approval-external",
            ApprovalKind::PrivilegedExecution,
            &subject_digest,
            false,
        );
        control
            .store_compiled_capsule_idempotent(
                "capsule-external-key",
                &signed,
                &signing_key.verifying_key(),
                &CapsuleApiMetadata {
                    capsule_id: signed.id.clone(),
                    approval_subject_digest: subject_digest.clone(),
                    risk_score: 90,
                },
                &[approval],
            )
            .unwrap();
        approve(&control, "approval-external", &subject_digest, NOW + 1);
        add_runner(&control);

        let producer_capsule = execution_capsule();
        let producer_signing_key = CapsuleSigningKey::from_seed([82; 32]);
        let producer_signature = producer_signing_key
            .sign_capsule(&producer_capsule)
            .unwrap();
        let producer_signed = SignedCapsuleRecord {
            id: "capsule-producer".to_owned(),
            repository_id: "repo-1".to_owned(),
            digest: producer_signature.capsule_digest.clone(),
            canonical_capsule: producer_capsule.canonical_bytes().unwrap(),
            signature: producer_signature,
            created_unix_ms: NOW + 2,
        };
        control
            .store_compiled_capsule_idempotent(
                "capsule-producer-key",
                &producer_signed,
                &producer_signing_key.verifying_key(),
                &CapsuleApiMetadata {
                    capsule_id: producer_signed.id.clone(),
                    approval_subject_digest: ContentDigest::sha256(b"producer-approval-subject"),
                    risk_score: 0,
                },
                &[],
            )
            .unwrap();
        let producer_run =
            approval_run_request("capsule-producer", "run-producer", "job-producer", NOW + 3);
        control
            .create_run_idempotent("run-producer-key", &producer_run)
            .unwrap();
        let producer_offer = control
            .offer_next_lease_for_runner("runner-1", NOW + 4)
            .unwrap()
            .unwrap();
        assert_eq!(producer_offer.job_id, "job-producer");
        let producer_lease = control
            .accept_lease(
                &producer_offer.id,
                "runner-1",
                producer_offer.fencing_generation,
                producer_offer.installation_fencing_epoch,
                NOW + 5,
            )
            .unwrap();
        let artifact_digest = ContentDigest::sha256(b"external-deployment-artifact");
        let manifest_digest = ContentDigest::sha256(b"external-deployment-manifest");
        let provenance_digest = ContentDigest::sha256(b"external-deployment-provenance");
        control
            .record_runner_data_commit(
                &RunnerDataCommit {
                    kind: RunnerDataCommitKind::Artifact,
                    object_id: "artifact-external".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    repository_id: "repo-1".to_owned(),
                    run_id: "run-producer".to_owned(),
                    job_id: "job-producer".to_owned(),
                    job_attempt: 1,
                    step_id: "build".to_owned(),
                    output_name: Some("bundle".to_owned()),
                    lease_id: producer_lease.id.clone(),
                    fencing_generation: producer_lease.fencing_generation,
                    ticket_id: "artifact-external-ticket".to_owned(),
                    committed_unix_ms: NOW + 6,
                },
                "runner-1",
            )
            .unwrap();
        control
            .transition_job_state("job-producer", JobState::Running, NOW + 7)
            .unwrap();
        control
            .transition_job_state("job-producer", JobState::Finalizing, NOW + 8)
            .unwrap();
        control
            .complete_lease_with_objects(
                &producer_lease.id,
                "runner-1",
                producer_lease.fencing_generation,
                producer_lease.installation_fencing_epoch,
                &ContentDigest::sha256(b"producer-completion"),
                JobState::Succeeded,
                1,
                &["artifact-external".to_owned()],
                &[],
                &["bundle".to_owned()],
                NOW + 9,
            )
            .unwrap();
        control
            .catalog_artifact(&ArtifactCatalogRecord {
                artifact_id: "artifact-external".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                repository_id: "repo-1".to_owned(),
                run_id: "run-producer".to_owned(),
                job_id: "job-producer".to_owned(),
                job_attempt: 1,
                step_id: "build".to_owned(),
                output_name: "bundle".to_owned(),
                content_digest: artifact_digest.clone(),
                manifest_digest: manifest_digest.clone(),
                provenance_digest: provenance_digest.clone(),
                size_bytes: 128,
                media_type: "application/octet-stream".to_owned(),
                classification: "release".to_owned(),
                scan_state: "passed".to_owned(),
                retention_until_unix_seconds: 3_600,
                legal_hold: false,
                state: "available".to_owned(),
                created_unix_ms: NOW + 10,
            })
            .unwrap();

        let mut run =
            approval_run_request("capsule-external", "run-external", "job-external", NOW + 11);
        run.jobs[0].job_key = "publish".to_owned();
        control
            .create_run_idempotent("run-external-key", &run)
            .unwrap();
        control
            .transition_job_state("job-external", JobState::Queued, NOW + 12)
            .unwrap();
        let mut deployment_request = DeploymentRequestRecord {
            id: "deployment-request-external".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            environment_id: environment.id.clone(),
            environment_version: environment.version,
            policy_epoch: environment.required_policy_epoch,
            repository_id: "repo-1".to_owned(),
            run_id: "run-external".to_owned(),
            job_id: "job-external".to_owned(),
            job_attempt: 1,
            artifact_id: "artifact-external".to_owned(),
            promoted_artifact_id: None,
            artifact_source_run_id: "run-producer".to_owned(),
            artifact_source_job_id: "job-producer".to_owned(),
            artifact_source_job_attempt: 1,
            artifact_digest,
            manifest_digest,
            provenance_digest,
            target_digest: environment.deployment_target_digest.clone(),
            deployment_capsule_digest: signed.digest.clone(),
            request_digest: ContentDigest::sha256(b"placeholder"),
            approval_subject_digest: ContentDigest::sha256(b"placeholder"),
            approval_request_id: None,
            rollback_of_deployment_id: None,
            status: DeploymentRequestStatus::AwaitingConcurrency,
            wait_until_unix_ms: NOW + 12,
            concurrency_fence: None,
            execution_lease_id: None,
            lease_fencing_generation: None,
            installation_fencing_epoch: None,
            actor_id: "deployer".to_owned(),
            audit_correlation_id: "deployment-reserve".to_owned(),
            created_unix_ms: NOW + 12,
            updated_unix_ms: NOW + 12,
            completed_unix_ms: None,
            version: 1,
        };
        deployment_request.request_digest = deployment_request.expected_request_digest().unwrap();
        deployment_request.approval_subject_digest = deployment_request
            .expected_approval_subject_digest()
            .unwrap();
        control
            .reserve_deployment_request(&deployment_request)
            .unwrap();
        control
            .acquire_environment_gate(&AcquireEnvironmentGate {
                tenant_id: "tenant-1".to_owned(),
                deployment_request_id: deployment_request.id.clone(),
                installation_fencing_epoch: 1,
                gate_lease_id: "environment-gate-external".to_owned(),
                gate_expires_unix_ms: NOW + 120_000,
                actor_id: "deployer".to_owned(),
                audit_correlation_id: "deployment-gate".to_owned(),
                now_unix_ms: NOW + 13,
            })
            .unwrap();
        let offered = control
            .create_lease(
                "lease-external",
                "job-external",
                "runner-1",
                NOW + 14,
                NOW + 30,
                NOW + 120_000,
            )
            .unwrap();
        active = control
            .accept_lease(
                "lease-external",
                "runner-1",
                offered.fencing_generation,
                offered.installation_fencing_epoch,
                NOW + 15,
            )
            .unwrap();
        control
            .mark_deployment_started(
                "tenant-1",
                &deployment_request.id,
                &active.id,
                active.fencing_generation,
                active.installation_fencing_epoch,
                "deployer",
                "deployment-started",
                NOW + 16,
            )
            .unwrap();
        let request = RunnerExternalSecretRequest {
            runner_id: "runner-1".to_owned(),
            execution_lease_id: active.id.clone(),
            fencing_generation: active.fencing_generation,
            installation_fencing_epoch: active.installation_fencing_epoch,
            job_id: active.job_id.clone(),
            job_attempt: 1,
            step_id: "release".to_owned(),
            secret_metadata_id: "external-secret".to_owned(),
            purpose: "publish".to_owned(),
            expires_unix_ms: NOW + 60_000,
        };
        let authorized =
            ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 17).unwrap();
        assert_eq!(authorized.provider_id, "external-provider");
        assert_eq!(authorized.provider_reference, "secret/data/releases#token");
        assert_eq!(
            ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 17).unwrap(),
            authorized
        );
    }

    let control = ControlPlane::open(&path, "external-authority", NOW + 18).unwrap();
    let request = RunnerExternalSecretRequest {
        runner_id: "runner-1".to_owned(),
        execution_lease_id: active.id,
        fencing_generation: active.fencing_generation,
        installation_fencing_epoch: active.installation_fencing_epoch,
        job_id: active.job_id,
        job_attempt: 1,
        step_id: "release".to_owned(),
        secret_metadata_id: "external-secret".to_owned(),
        purpose: "publish".to_owned(),
        expires_unix_ms: NOW + 60_000,
    };
    ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 18).unwrap();
    for changed in [
        RunnerExternalSecretRequest {
            fencing_generation: request.fencing_generation + 1,
            ..request.clone()
        },
        RunnerExternalSecretRequest {
            job_attempt: 2,
            ..request.clone()
        },
        RunnerExternalSecretRequest {
            secret_metadata_id: "guessed-cross-tenant-secret".to_owned(),
            ..request.clone()
        },
        RunnerExternalSecretRequest {
            purpose: "different-purpose".to_owned(),
            ..request.clone()
        },
    ] {
        assert!(matches!(
            ExternalSecretReleaseAuthority::authorize(&control, &changed, NOW + 18),
            Err(ExternalSecretBrokerError::AuthorizationDenied)
                | Err(ExternalSecretBrokerError::AuthorizationBindingMismatch)
        ));
    }
    let mut disabled = r10_provider("tenant-1", "external-provider", "external-secret");
    disabled.status = "disabled".to_owned();
    disabled.version = 2;
    disabled.updated_unix_ms = NOW + 19;
    disabled.configuration_digest = disabled.expected_configuration_digest().unwrap();
    control
        .put_tenant_provider_configuration(&disabled, Some(1))
        .unwrap();
    assert!(matches!(
        ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 19),
        Err(ExternalSecretBrokerError::AuthorizationDenied)
    ));
    let mut enabled = r10_provider("tenant-1", "external-provider", "external-secret");
    enabled.version = 3;
    enabled.updated_unix_ms = NOW + 20;
    enabled.configuration_digest = enabled.expected_configuration_digest().unwrap();
    control
        .put_tenant_provider_configuration(&enabled, Some(2))
        .unwrap();
    ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 20).unwrap();

    {
        let connection = control.connection().unwrap();
        connection
            .execute(
                "UPDATE environment_concurrency_leases SET expires_unix_ms = ?1
                     WHERE tenant_id = 'tenant-1'
                       AND deployment_request_id = 'deployment-request-external'",
                [to_i64(NOW + 20).unwrap()],
            )
            .unwrap();
    }
    assert!(matches!(
        ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 21),
        Err(ExternalSecretBrokerError::AuthorizationDenied)
    ));
    {
        let connection = control.connection().unwrap();
        connection
            .execute(
                "UPDATE environment_concurrency_leases SET expires_unix_ms = ?1
                     WHERE tenant_id = 'tenant-1'
                       AND deployment_request_id = 'deployment-request-external'",
                [to_i64(NOW + 120_000).unwrap()],
            )
            .unwrap();
    }
    ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 21).unwrap();

    let mut changed_environment = control
        .environment("tenant-1", "environment-production")
        .unwrap();
    changed_environment.concurrency_limit = 2;
    changed_environment.updated_unix_ms = NOW + 22;
    changed_environment.version = 2;
    control
        .put_environment(&changed_environment, Some(1))
        .unwrap();
    assert!(matches!(
        ExternalSecretReleaseAuthority::authorize(&control, &request, NOW + 22),
        Err(ExternalSecretBrokerError::AuthorizationDenied)
    ));
}

#[test]
fn r10_provider_and_signer_policy_versions_reject_ambient_or_mutated_identity() {
    let control = ControlPlane::open_in_memory("r10-provider", NOW).unwrap();
    control
        .put_tenant_identity(&r9_tenant("tenant-r10"), None)
        .unwrap();

    let mut ambient = r10_provider("tenant-r10", "provider-ambient", "external-secret");
    ambient.credential_reference = "env:VAULT_TOKEN".to_owned();
    ambient.configuration_digest = ambient.expected_configuration_digest().unwrap();
    assert!(matches!(
        control.put_tenant_provider_configuration(&ambient, None),
        Err(ControlPlaneError::InvalidInput(_))
    ));

    let provider = r10_provider("tenant-r10", "provider-signing", "signing");
    assert!(control
        .put_tenant_provider_configuration(&provider, None)
        .unwrap());
    assert!(!control
        .put_tenant_provider_configuration(&provider, None)
        .unwrap());
    let provider_debug = format!("{provider:?}");
    assert!(!provider_debug.contains(&provider.credential_reference));

    let mut substituted = provider.clone();
    substituted.endpoint_origin = "https://attacker.example.test".to_owned();
    substituted.version = 2;
    substituted.updated_unix_ms += 1;
    substituted.configuration_digest = substituted.expected_configuration_digest().unwrap();
    assert!(matches!(
        control.put_tenant_provider_configuration(&substituted, Some(1)),
        Err(ControlPlaneError::IdempotencyConflict)
    ));

    let mut policy = SignerPolicyRecord {
        id: "release-policy".to_owned(),
        tenant_id: "tenant-r10".to_owned(),
        provider_configuration_id: provider.id.clone(),
        provider_configuration_digest: provider.configuration_digest.clone(),
        provider_configuration_version: provider.version,
        backend_key_reference: "signer-key://release-key-v1".to_owned(),
        purpose: "release-artifact".to_owned(),
        operation: "sign-digest".to_owned(),
        public_key_digest: provider.public_key_digest.clone().unwrap(),
        policy_digest: ContentDigest::sha256([]),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
        version: 1,
    };
    policy.policy_digest = policy.expected_policy_digest().unwrap();
    assert!(control.put_signer_policy(&policy, None).unwrap());
    assert!(!control.put_signer_policy(&policy, None).unwrap());
    let policy_debug = format!("{policy:?}");
    assert!(!policy_debug.contains(&policy.backend_key_reference));
    assert!(matches!(
        control.signer_policy("other-tenant", &policy.id),
        Err(ControlPlaneError::NotFound { .. })
    ));

    let connection = control.connection().unwrap();
    assert!(connection
            .execute(
                "UPDATE tenant_provider_configuration_versions
                 SET snapshot_digest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                 WHERE tenant_id = ?1 AND provider_configuration_id = ?2 AND version = 1",
                params![provider.tenant_id, provider.id],
            )
            .is_err());
    drop(connection);
    assert_eq!(
        control
            .tenant_provider_configuration("tenant-r10", "provider-signing")
            .unwrap(),
        provider
    );
}
