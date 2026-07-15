pub(super) use axum::{
    body::{Body, HttpBody as _},
    http::{
        header::{CONTENT_TYPE, LOCATION, SET_COOKIE},
        Request, StatusCode,
    },
    response::Response,
    Router,
};
pub(super) use hmac::{Hmac, Mac as _};
pub(super) use runtrue_attest::CapsuleSigningKey;
pub(super) use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource};
pub(super) use runtrue_compiler::{
    CompileContext, Compiler, ReusableWorkflowSource, ReusableWorkflowSources,
};
pub(super) use runtrue_control_plane::{
    ArtifactCatalogRecord, ControlPlane, CreateRunRequest, DurableTaskStatus, HumanIdentityRecord,
    HumanUserRecord, NewJob, R9AuditMetadata, RepositoryRecord, RunnerDataCommit,
    RunnerDataCommitKind, RunnerPoolRecord, RunnerPoolStatus, SignedCapsuleRecord,
    SourceSnapshotRecord, SourceSnapshotState, TenantIdentityRecord, TenantMembershipRecord,
    TenantOidcProviderConfiguration,
};
pub(super) use runtrue_lifecycle::JobState;
pub(super) use runtrue_lock::LockFile;
pub(super) use runtrue_model::ContentDigest;
pub(super) use runtrue_policy::{
    ActivePolicyBundleState, ApprovalKind, ApprovalRequest, ApprovalRule, CedarAuthorizationEngine,
    DenyFirstPolicy, EmergencyDeny,
};
pub(super) use runtrue_scheduler::{RunnerRecord, RunnerStatus, SchedulingRequirements};
pub(super) use runtrue_scm::{
    GitHubAccount, GitHubAccountKind, GitHubAppPublicConfig, GitHubError,
    GitHubInstallationProvider, GitHubInstallationRepository, GitHubInstallationSnapshot,
    GitHubPermission, GitHubPermissionLevel, GitHubRepositorySelection, GitHubRepositoryVisibility,
};
pub(super) use runtrue_server::{
    router, AppState, HumanOidcAdapter, HumanOidcError, HumanOidcLimits, VerifiedHumanIdentity,
};
pub(super) use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, RunnerRequirements, SourceTrust,
    Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
pub(super) use serde_json::{json, Value};
pub(super) use sha2::Sha256;
pub(super) use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
pub(super) use tower::ServiceExt as _;

pub(super) const TOKEN: &str = "test-bootstrap-token";
pub(super) const WEBHOOK_SECRET: &[u8] = b"test-webhook-secret";
pub(super) const GITHUB_CREDENTIAL_REFERENCE: &str =
    "provider://github-app/http-test-private-key-reference";

pub(super) fn application(webhook_secret: Option<&[u8]>) -> (Arc<ControlPlane>, Router) {
    let control_plane = Arc::new(ControlPlane::open_in_memory("test-installation", 1).unwrap());
    let state = AppState::new(Arc::clone(&control_plane), TOKEN, webhook_secret).unwrap();
    (control_plane, router(state))
}

#[derive(Default)]
pub(super) struct FakeHumanOidcAdapter {
    pub(super) response: Mutex<Option<Result<VerifiedHumanIdentity, HumanOidcError>>>,
    pub(super) gates: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    pub(super) calls: AtomicU64,
}

impl FakeHumanOidcAdapter {
    pub(super) fn respond(&self, nonce: &str, subject: &str) {
        *self.response.lock().unwrap() = Some(Ok(VerifiedHumanIdentity {
            issuer: "https://identity.example".to_owned(),
            subject: subject.to_owned(),
            nonce: nonce.to_owned(),
            display_name: Some("OIDC User".to_owned()),
            email: Some("user@example.test".to_owned()),
            claims_digest: ContentDigest::sha256(format!("claims:{subject}")),
            mfa_authenticated: true,
        }));
    }

    pub(super) fn block_next(&self, nonce: &str) -> (Arc<Barrier>, Arc<Barrier>) {
        self.respond(nonce, "subject-browser");
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *self.gates.lock().unwrap() = Some((Arc::clone(&started), Arc::clone(&release)));
        (started, release)
    }
}

impl HumanOidcAdapter for FakeHumanOidcAdapter {
    fn exchange_authorization_code(
        &self,
        _provider: &TenantOidcProviderConfiguration,
        _authorization_code: &str,
        _pkce_verifier: &str,
        _now_unix_seconds: u64,
    ) -> Result<VerifiedHumanIdentity, HumanOidcError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let gates = self.gates.lock().unwrap().take();
        if let Some((started, release)) = gates {
            started.wait();
            release.wait();
        }
        self.response
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Err(HumanOidcError::InvalidTokenResponse))
    }
}

pub(super) fn unix_ms_now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

pub(super) fn seed_human_identity(control: &ControlPlane) {
    let now = unix_ms_now().saturating_sub(1_000);
    control
        .put_tenant_identity(
            &TenantIdentityRecord {
                id: "tenant-browser".to_owned(),
                slug: "tenant-browser".to_owned(),
                name: "Tenant <Browser>".to_owned(),
                status: "active".to_owned(),
                settings: json!({}),
                created_unix_ms: now,
                updated_unix_ms: now,
                version: 1,
            },
            None,
        )
        .unwrap();
    let mut provider = TenantOidcProviderConfiguration {
        id: "provider-browser".to_owned(),
        tenant_id: "tenant-browser".to_owned(),
        issuer: "https://identity.example".to_owned(),
        client_id: "runtrue-browser".to_owned(),
        authorization_endpoint: "https://identity.example/authorize".to_owned(),
        token_endpoint: "https://identity.example/token".to_owned(),
        jwks_uri: "https://identity.example/jwks".to_owned(),
        redirect_uri: "https://runtrue.example/auth/oidc/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        mfa_claim: json!({"claim": "amr", "value": "mfa"}),
        status: "active".to_owned(),
        configuration_digest: ContentDigest::sha256(b"placeholder"),
        created_unix_ms: now,
        updated_unix_ms: now,
        version: 1,
    };
    provider.configuration_digest = provider.expected_configuration_digest().unwrap();
    control
        .put_tenant_oidc_provider_configuration(&provider, None)
        .unwrap();
    control
        .put_human_user(
            "tenant-browser",
            &HumanUserRecord {
                id: "user-<browser>".to_owned(),
                display_name: "User <script>alert(1)</script>".to_owned(),
                primary_email: "user@example.test".to_owned(),
                status: "active".to_owned(),
                created_unix_ms: now,
                updated_unix_ms: now,
                last_seen_unix_ms: None,
                version: 1,
            },
            None,
        )
        .unwrap();
    control
        .put_human_identity(
            "tenant-browser",
            &HumanIdentityRecord {
                id: "identity-browser".to_owned(),
                tenant_id: "tenant-browser".to_owned(),
                user_id: "user-<browser>".to_owned(),
                provider_configuration_id: "provider-browser".to_owned(),
                issuer: "https://identity.example".to_owned(),
                subject: "subject-browser".to_owned(),
                provider_kind: "oidc".to_owned(),
                claims_digest: ContentDigest::sha256(b"initial claims"),
                created_unix_ms: now,
                last_authenticated_unix_ms: now,
            },
        )
        .unwrap();
    let mut membership = TenantMembershipRecord {
        id: "membership-browser".to_owned(),
        tenant_id: "tenant-browser".to_owned(),
        user_id: "user-<browser>".to_owned(),
        role_template: "policy-administrator".to_owned(),
        attributes: json!({}),
        attributes_digest: ContentDigest::sha256(b"placeholder"),
        status: "active".to_owned(),
        created_unix_ms: now,
        updated_unix_ms: now,
        version: 1,
    };
    membership.attributes_digest = membership.expected_attributes_digest().unwrap();
    control.put_tenant_membership(&membership, None).unwrap();
}

pub(super) fn human_state(
    control: Arc<ControlPlane>,
    adapter: Arc<FakeHumanOidcAdapter>,
) -> AppState {
    AppState::new_with_security_seed(
        control,
        TOKEN,
        None,
        [19; 32],
        "https://runtrue.example/oidc".to_owned(),
    )
    .unwrap()
    .with_human_oidc(
        "https://runtrue.example".to_owned(),
        &[23; 32],
        adapter,
        HumanOidcLimits {
            maximum_concurrent_exchanges: 1,
            ..HumanOidcLimits::default()
        },
    )
    .unwrap()
}

pub(super) fn human_application() -> (
    Arc<ControlPlane>,
    Arc<FakeHumanOidcAdapter>,
    AppState,
    Router,
) {
    let control = Arc::new(ControlPlane::open_in_memory("human-http", 1).unwrap());
    seed_human_identity(&control);
    let adapter = Arc::new(FakeHumanOidcAdapter::default());
    let state = human_state(Arc::clone(&control), Arc::clone(&adapter));
    let application = router(state.clone());
    (control, adapter, state, application)
}

#[derive(Debug)]
pub(super) struct FakeGitHubInstallationProvider {
    pub(super) snapshot: GitHubInstallationSnapshot,
    pub(super) calls: AtomicU64,
}

impl FakeGitHubInstallationProvider {
    pub(super) fn new() -> Self {
        let account = GitHubAccount {
            id: 501,
            login: "octo".to_owned(),
            kind: GitHubAccountKind::Organization,
        };
        Self {
            snapshot: GitHubInstallationSnapshot {
                installation_id: 9_001,
                app_id: 123,
                account: account.clone(),
                target_id: account.id,
                target_kind: account.kind,
                repository_selection: GitHubRepositorySelection::Selected,
                permissions: BTreeMap::from([
                    (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
                    (GitHubPermission::Contents, GitHubPermissionLevel::Read),
                    (GitHubPermission::PullRequests, GitHubPermissionLevel::Read),
                    (GitHubPermission::Checks, GitHubPermissionLevel::Write),
                ]),
                suspended_at: None,
                repository_catalog_complete: true,
                repositories: vec![GitHubInstallationRepository {
                    id: 77,
                    owner: account,
                    name: "runtrue".to_owned(),
                    full_name: "octo/runtrue".to_owned(),
                    visibility: GitHubRepositoryVisibility::Private,
                    default_branch: Some("main".to_owned()),
                    archived: false,
                    disabled: false,
                }],
            },
            calls: AtomicU64::new(0),
        }
    }
}

impl GitHubInstallationProvider for FakeGitHubInstallationProvider {
    fn inspect_installation(
        &self,
        installation_id: u64,
        _now_unix_seconds: u64,
    ) -> Result<GitHubInstallationSnapshot, GitHubError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if installation_id != self.snapshot.installation_id {
            return Err(GitHubError::InstallationSubstitution);
        }
        Ok(self.snapshot.clone())
    }
}

pub(super) fn github_state(
    control: Arc<ControlPlane>,
    provider: Arc<FakeGitHubInstallationProvider>,
) -> AppState {
    github_state_with_public_config(
        control,
        provider,
        GitHubAppPublicConfig::new(123, "runtrue-http-test").unwrap(),
    )
}

pub(super) fn github_state_with_public_config(
    control: Arc<ControlPlane>,
    provider: Arc<FakeGitHubInstallationProvider>,
    public_config: GitHubAppPublicConfig,
) -> AppState {
    AppState::new_with_security_seed(
        control,
        TOKEN,
        Some(WEBHOOK_SECRET),
        [31; 32],
        "https://runtrue.example/oidc".to_owned(),
    )
    .unwrap()
    .with_github_installation_provider(
        public_config,
        GITHUB_CREDENTIAL_REFERENCE.to_owned(),
        provider,
    )
    .unwrap()
}

pub(super) fn seed_active_tenant(control: &ControlPlane, tenant_id: &str) {
    let now = unix_ms_now().saturating_sub(1_000);
    control
        .put_tenant_identity(
            &TenantIdentityRecord {
                id: tenant_id.to_owned(),
                slug: tenant_id.to_owned(),
                name: tenant_id.to_owned(),
                status: "active".to_owned(),
                settings: json!({}),
                created_unix_ms: now,
                updated_unix_ms: now,
                version: 1,
            },
            None,
        )
        .unwrap();
}

pub(super) fn github_human_application() -> (
    Arc<ControlPlane>,
    Arc<FakeHumanOidcAdapter>,
    Arc<FakeGitHubInstallationProvider>,
    AppState,
    Router,
) {
    let control = Arc::new(ControlPlane::open_in_memory("github-human-http", 1).unwrap());
    seed_human_identity(&control);
    let oidc = Arc::new(FakeHumanOidcAdapter::default());
    let provider = Arc::new(FakeGitHubInstallationProvider::new());
    let state = github_state(Arc::clone(&control), Arc::clone(&provider))
        .with_human_oidc(
            "https://runtrue.example".to_owned(),
            &[23; 32],
            Arc::clone(&oidc) as Arc<dyn HumanOidcAdapter>,
            HumanOidcLimits {
                maximum_concurrent_exchanges: 1,
                ..HumanOidcLimits::default()
            },
        )
        .unwrap();
    let application = router(state.clone());
    (control, oidc, provider, state, application)
}

pub(super) fn response_cookie(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value
                .strip_prefix(&format!("{name}="))?
                .split(';')
                .next()
                .map(str::to_owned)
        })
}

pub(super) fn browser_cookie_header(response: &Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next().map(str::to_owned))
        .filter(|cookie| !cookie.ends_with('='))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn location_parameter(location: &str, name: &str) -> String {
    location
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .find_map(|pair| {
            let (candidate, value) = pair.split_once('=')?;
            (candidate == name).then(|| value.to_owned())
        })
        .unwrap()
}

pub(super) async fn begin_human_login(application: &Router) -> (String, String, String) {
    let response = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login?tenant_id=tenant-browser&provider_id=provider-browser&return_to=%2Fui%2Fsession")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let login_cookie = response_cookie(&response, "runtrue_login").unwrap();
    let location = response.headers()[LOCATION].to_str().unwrap();
    assert!(location.starts_with("https://identity.example/authorize?"));
    for cookie in response.headers().get_all(SET_COOKIE) {
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/auth/oidc/callback"));
    }
    (
        login_cookie,
        location_parameter(location, "state"),
        location_parameter(location, "nonce"),
    )
}

pub(super) async fn finish_human_login(
    application: &Router,
    login_cookie: &str,
    state: &str,
) -> Response {
    application
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/oidc/callback?code=code-1&state={state}"))
                .header("cookie", format!("runtrue_login={login_cookie}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn text_body(response: Response) -> String {
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    String::from_utf8(bytes).unwrap()
}

pub(super) fn assert_github_callback_is_protected(response: &Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
}

pub(super) fn application_with_capsule() -> (Arc<ControlPlane>, Router) {
    let (control_plane, application) = application(None);
    control_plane
        .create_repository(&RepositoryRecord {
            id: "repo-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            owner: "octo".to_owned(),
            name: "runtrue".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: 1,
        })
        .unwrap();
    let capsule = execution_capsule();
    let signing_key = CapsuleSigningKey::from_seed([7_u8; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    control_plane
        .store_signed_capsule(
            &SignedCapsuleRecord {
                id: "capsule-1".to_owned(),
                repository_id: "repo-1".to_owned(),
                digest: signature.capsule_digest.clone(),
                canonical_capsule: capsule.canonical_bytes().unwrap(),
                signature,
                created_unix_ms: 1,
            },
            &signing_key.verifying_key(),
        )
        .unwrap();
    (control_plane, application)
}

pub(super) fn execution_capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "ci".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/ci.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "a".repeat(40),
            source_tree_digest: None,
            base_commit: None,
            source_trust: SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: vec![PlannedJob {
            id: "build".to_owned(),
            base_id: "build".to_owned(),
            name: "Build".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::TrustedOnly,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Microvm,
                image: None,
                cpu: 2,
                memory_bytes: 1024,
                storage_bytes: Some(2048),
                region: None,
                capabilities: vec!["kvm".to_owned()],
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: Vec::new(),
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::AExact,
    }
}

pub(super) fn api_request(method: &str, uri: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

pub(super) fn token_request(
    token: &str,
    method: &str,
    uri: &str,
    body: impl Into<Body>,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

pub(super) async fn json_body(response: Response) -> Value {
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    serde_json::from_slice(&bytes).unwrap()
}

pub(super) fn idempotent_request(method: &str, uri: &str, key: &str, body: Value) -> Request<Body> {
    let mut request = api_request(method, uri, serde_json::to_vec(&body).unwrap());
    request
        .headers_mut()
        .insert("idempotency-key", key.parse().unwrap());
    request
}

pub(super) fn token_idempotent_request(
    token: &str,
    method: &str,
    uri: &str,
    key: &str,
    body: Value,
) -> Request<Body> {
    let mut request = token_request(token, method, uri, serde_json::to_vec(&body).unwrap());
    request
        .headers_mut()
        .insert("idempotency-key", key.parse().unwrap());
    request
}

pub(super) async fn issue_http_token(
    application: &Router,
    id: &str,
    principal_id: &str,
    tenant_id: &str,
    scopes: &[&str],
) -> String {
    let issued = application
        .clone()
        .oneshot(api_request(
            "POST",
            "/api/v1/api-tokens",
            serde_json::to_vec(&json!({
                "id": id,
                "principal_id": principal_id,
                "tenant_id": tenant_id,
                "name": format!("{id} test token"),
                "scopes": scopes,
                "ttl_seconds": 600
            }))
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::CREATED);
    json_body(issued).await["token"]
        .as_str()
        .unwrap()
        .to_owned()
}

pub(super) fn tenant_repository(id: &str, tenant_id: &str, name: &str) -> RepositoryRecord {
    RepositoryRecord {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        owner: "octo".to_owned(),
        name: name.to_owned(),
        default_branch: "main".to_owned(),
        visibility: "private".to_owned(),
        created_unix_ms: 1,
    }
}

pub(super) fn store_tenant_capsule(
    control_plane: &ControlPlane,
    repository_id: &str,
    capsule_id: &str,
) {
    let capsule = execution_capsule();
    let signing_key = CapsuleSigningKey::from_seed([41_u8; 32]);
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    control_plane
        .store_signed_capsule(
            &SignedCapsuleRecord {
                id: capsule_id.to_owned(),
                repository_id: repository_id.to_owned(),
                digest: signature.capsule_digest.clone(),
                canonical_capsule: capsule.canonical_bytes().unwrap(),
                signature,
                created_unix_ms: 1,
            },
            &signing_key.verifying_key(),
        )
        .unwrap();
}

pub(super) fn store_tenant_run(
    control_plane: &ControlPlane,
    repository_id: &str,
    capsule_id: &str,
    run_id: &str,
    job_id: &str,
) {
    control_plane
        .create_run_idempotent(
            &format!("create-{run_id}"),
            &CreateRunRequest {
                id: run_id.to_owned(),
                repository_id: repository_id.to_owned(),
                capsule_id: capsule_id.to_owned(),
                priority: 0,
                remote: true,
                created_unix_ms: 1,
                jobs: vec![NewJob {
                    id: job_id.to_owned(),
                    job_key: "build".to_owned(),
                    attempt: 1,
                    requirements: SchedulingRequirements {
                        os: OperatingSystem::Linux,
                        arch: Architecture::Amd64,
                        isolation: Isolation::Microvm,
                        cpu: 2,
                        memory_bytes: 1024,
                        storage_bytes: 2048,
                        region: None,
                        required_capabilities: BTreeSet::from(["kvm".to_owned()]),
                        allowed_pools: BTreeSet::new(),
                    },
                }],
            },
        )
        .unwrap();
}

pub(super) fn store_tenant_approval(
    control_plane: &ControlPlane,
    repository_id: &str,
    capsule_id: &str,
    approval_id: &str,
    reviewer: &str,
) {
    let request = ApprovalRequest::create(
        approval_id,
        ApprovalKind::WorkflowDefinition,
        ContentDigest::sha256(approval_id.as_bytes()),
        10,
        1,
        9_000_000_000_000,
        ApprovalRule {
            id: "tenant-review".to_owned(),
            required_approvals: 1,
            eligible_approvers: BTreeSet::from([reviewer.to_owned()]),
            forbidden_approvers: BTreeSet::new(),
            one_shot: true,
        },
    )
    .unwrap();
    control_plane
        .create_approval_request(repository_id, capsule_id, &request)
        .unwrap();
}

pub(super) fn store_tenant_runner(
    control_plane: &ControlPlane,
    tenant_id: &str,
    pool_id: &str,
    runner_id: &str,
) {
    control_plane
        .create_runner_pool(&RunnerPoolRecord {
            id: pool_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            name: pool_id.to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: 1,
        })
        .unwrap();
    control_plane
        .register_runner(
            &RunnerRecord {
                id: runner_id.to_owned(),
                tenant_id: tenant_id.to_owned(),
                pool_id: pool_id.to_owned(),
                ephemeral: false,
                retired: false,
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation_backends: BTreeSet::from([Isolation::Microvm]),
                logical_cpus: 2,
                memory_bytes: 4096,
                storage_bytes: 8192,
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
            1,
        )
        .unwrap();
}

pub(super) fn tenant_audit(tenant_id: &str, action: &str) -> AuditEventData {
    AuditEventData {
        observed_unix_ms: 1,
        tenant_id: tenant_id.to_owned(),
        actor: AuditPrincipal {
            kind: "test".to_owned(),
            id: "setup".to_owned(),
        },
        action: action.to_owned(),
        resource: AuditResource {
            kind: "tenant".to_owned(),
            id: tenant_id.to_owned(),
        },
        result: "success".to_owned(),
        request_id: format!("request-{tenant_id}-{action}"),
        decision_id: None,
        metadata: BTreeMap::new(),
    }
}
