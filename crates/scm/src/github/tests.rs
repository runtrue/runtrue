use super::*;
use super::{
    pagination::{
        parse_account, parse_repository_array, parse_utc_timestamp, valid_default_branch,
    },
    validation::{headers, is_public_ip, validate_token_request},
};
use crate::{
    CheckRunEventAction, EventType, GitHubWebhookVerifier, IssueCommentAction, PullRequestAction,
    ScmError, VerifiedDelivery, WebhookHeaders, WebhookLimits,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use hmac::{Hmac, Mac as _};
use runtrue_model::ContentDigest;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, VecDeque};
use zeroize::Zeroizing;

const NOW: u64 = 1_783_728_000; // 2026-07-11T00:00:00Z

struct FixedJwt;

impl GitHubAppJwtProvider for FixedJwt {
    fn mint(&mut self, _now_unix_seconds: u64) -> Result<SensitiveToken, GitHubError> {
        SensitiveToken::new("app.jwt.secret".to_owned())
    }
}

#[derive(Debug)]
struct RecordedRequest {
    method: GitHubMethod,
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Default)]
struct MockTransport {
    responses: VecDeque<GitHubResponse>,
    requests: Vec<RecordedRequest>,
}

impl MockTransport {
    fn respond(&mut self, status: u16, body: Value) {
        self.responses
            .push_back(GitHubResponse::new(status, serde_json::to_vec(&body).unwrap()).unwrap());
    }
}

impl GitHubTransport for MockTransport {
    fn send(&mut self, request: GitHubRequest) -> Result<GitHubResponse, GitHubError> {
        assert!(matches!(
            request.bearer_token(),
            "app.jwt.secret" | "ghs_installation_secret" | "ghs_catalog_secret"
        ));
        assert!(!request.body().windows(6).any(|bytes| bytes == b"secret"));
        self.requests.push(RecordedRequest {
            method: request.method,
            url: request.url.clone(),
            headers: request.headers().clone(),
            body: request.body().to_vec(),
        });
        self.responses.pop_front().ok_or(GitHubError::Transport)
    }
}

fn token_request() -> InstallationTokenRequest {
    InstallationTokenRequest {
        installation_id: 7,
        repository_ids: vec![42],
        permissions: BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Checks, GitHubPermissionLevel::Write),
        ]),
    }
}

fn token_response() -> Value {
    json!({
        "token": "ghs_installation_secret",
        "expires_at": "2026-07-11T01:00:00Z",
        "repository_selection": "selected",
        "repositories": [{"id": 42}],
        "permissions": {"metadata": "read", "checks": "write"}
    })
}

fn broker_with_token() -> (GitHubAppBroker<MockTransport, FixedJwt>, InstallationToken) {
    let mut transport = MockTransport::default();
    transport.respond(201, token_response());
    let mut broker =
        GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").expect("broker");
    let token = broker
        .mint_installation_token(token_request(), NOW)
        .expect("token");
    (broker, token)
}

fn account() -> Value {
    json!({"id": 99, "login": "octo-org", "type": "Organization"})
}

fn installation() -> Value {
    json!({
        "id": 7,
        "app_id": 123,
        "account": account(),
        "target_id": 99,
        "target_type": "Organization",
        "repository_selection": "selected",
        "permissions": {
            "metadata": "read",
            "contents": "read",
            "pull_requests": "read",
            "checks": "write"
        },
        "suspended_at": null
    })
}

fn repository(id: u64, name: &str) -> Value {
    json!({
        "id": id,
        "owner": account(),
        "name": name,
        "full_name": format!("octo-org/{name}"),
        "private": true,
        "visibility": "private",
        "default_branch": "main",
        "archived": false,
        "disabled": false
    })
}

fn catalog_token_response() -> Value {
    json!({
        "token": "ghs_catalog_secret",
        "expires_at": "2026-07-11T01:00:00Z",
        "repository_selection": "selected",
        "permissions": {"metadata": "read"}
    })
}

fn installation_service(
    installation_response: Value,
    repository_response: Value,
) -> GitHubInstallationService<MockTransport, FixedJwt> {
    let mut transport = MockTransport::default();
    transport.respond(200, installation_response);
    transport.respond(201, catalog_token_response());
    transport.respond(200, repository_response);
    let broker = GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").unwrap();
    GitHubInstallationService::new(broker, 123).unwrap()
}

fn verified_webhook(event: &str, body: Vec<u8>) -> VerifiedDelivery {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"webhook-secret").unwrap();
    mac.update(&body);
    let signature = hex::encode(mac.finalize().into_bytes());
    let limits = WebhookLimits::default();
    let headers = WebhookHeaders::from_pairs(
        [
            ("X-Hub-Signature-256", format!("sha256={signature}")),
            ("X-GitHub-Delivery", "delivery-1".to_owned()),
            ("X-GitHub-Event", event.to_owned()),
        ],
        limits,
    )
    .unwrap();
    GitHubWebhookVerifier::new(b"webhook-secret", WebhookLimits::default())
        .unwrap()
        .verify(&headers, body)
        .unwrap()
}

mod installation {
    use super::*;

    #[test]
    fn mints_only_exact_repository_and_permission_scopes() {
        let (broker, token) = broker_with_token();
        assert_eq!(token.repository_ids, vec![42]);
        assert_eq!(
            token.permissions.get(&GitHubPermission::Checks),
            Some(&GitHubPermissionLevel::Write)
        );
        let debug = format!("{token:?}");
        assert!(!debug.contains("ghs_installation_secret"));
        assert!(debug.contains("[REDACTED]"));

        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests.len(), 1);
        let request = &transport.requests[0];
        assert_eq!(request.method, GitHubMethod::Post);
        assert_eq!(
            request.url,
            "https://api.github.com/app/installations/7/access_tokens"
        );
        assert_eq!(
            request
                .headers
                .get("x-github-api-version")
                .map(String::as_str),
            Some(GITHUB_API_VERSION)
        );
        assert!(!String::from_utf8_lossy(&request.body).contains("ghs_"));
    }

    #[test]
    fn resolves_exact_default_branch_with_repository_scoped_contents_token() {
        let mut request = token_request();
        request.permissions = BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Contents, GitHubPermissionLevel::Read),
        ]);
        let mut response = token_response();
        response["permissions"] = json!({"metadata": "read", "contents": "read"});
        let mut transport = MockTransport::default();
        transport.respond(201, response);
        transport.respond(
            200,
            json!({"ref": "refs/heads/release/1.2", "object": {"sha": "ABCDEF0123456789ABCDEF0123456789ABCDEF01", "type": "commit"}}),
        );
        let mut broker =
            GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").unwrap();
        let token = broker.mint_installation_token(request, NOW).unwrap();
        let sha = broker
            .resolve_repository_branch_head(&token, 42, "octo-org", "runtrue", "release/1.2")
            .unwrap();
        assert_eq!(sha, "abcdef0123456789abcdef0123456789abcdef01");
        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests.len(), 2);
        assert_eq!(
            transport.requests[1].url,
            "https://api.github.com/repos/octo-org/runtrue/git/ref/heads/release%2F1.2"
        );
    }

    #[test]
    fn workflow_approval_rechecks_actor_permission_and_current_pr_head() {
        let mut request = token_request();
        request.permissions = BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::PullRequests, GitHubPermissionLevel::Read),
        ]);
        let mut response = token_response();
        response["permissions"] = json!({"metadata": "read", "pull_requests": "read"});
        let mut transport = MockTransport::default();
        transport.respond(201, response);
        transport.respond(
            200,
            json!({"permission": "write", "user": {"id": 1234, "login": "maintainer"}}),
        );
        transport.respond(
            200,
            json!({"state": "open", "head": {"sha": "ABCDEF0123456789ABCDEF0123456789ABCDEF01"}}),
        );
        let mut broker =
            GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").unwrap();
        let token = broker.mint_installation_token(request, NOW).unwrap();
        let permission = broker
            .repository_permission_for_user(&token, 42, "octo-org", "runtrue", 1234, "maintainer")
            .unwrap();
        assert!(permission.can_approve_workflow());
        assert_eq!(
            broker
                .pull_request_head(&token, 42, "octo-org", "runtrue", 28)
                .unwrap(),
            "abcdef0123456789abcdef0123456789abcdef01"
        );
        let (transport, _) = broker.into_parts();
        assert!(transport.requests[1]
            .url
            .ends_with("/collaborators/maintainer/permission"));
        assert!(transport.requests[2].url.ends_with("/pulls/28"));
    }

    #[test]
    fn public_install_url_requires_valid_slug_and_high_entropy_state_shape() {
        let config = GitHubAppPublicConfig::new(123, "runtrue").unwrap();
        let state = "A".repeat(MIN_INSTALL_STATE_BYTES);
        assert_eq!(
            config.installation_url(&state).unwrap(),
            format!("https://github.com/apps/runtrue/installations/new?state={state}")
        );
        assert!(GitHubAppPublicConfig::new(0, "runtrue").is_err());
        assert!(GitHubAppPublicConfig::new(123, "Project_Runtrue").is_err());
        assert!(matches!(
            config.installation_url("short"),
            Err(GitHubError::InvalidInstallState)
        ));
        assert!(config
            .installation_url(&format!("{}=", "A".repeat(42)))
            .is_err());
        assert_eq!(
            config
                .installation_url_for_repositories(&state, 7, &[41, 42])
                .unwrap(),
            format!("https://github.com/apps/runtrue/installations/new/permissions?state={state}&suggested_target_id=7&repository_ids%5B%5D=41&repository_ids%5B%5D=42")
        );
        assert!(config
            .installation_url_for_repositories(&state, 7, &[41, 41])
            .is_err());

        let enterprise = GitHubAppPublicConfig::new_with_origins(
            123,
            "runtrue",
            "https://github.example.com:8443",
            "https://github.example.com:8443/api/v3",
        )
        .unwrap();
        assert_eq!(enterprise.provider_host(), "github.example.com");
        assert_eq!(enterprise.provider_port(), 8443);
        assert_eq!(
            enterprise.api_origin(),
            "https://github.example.com:8443/api/v3"
        );
        assert_eq!(
            enterprise.installation_url(&state).unwrap(),
            format!(
                "https://github.example.com:8443/github-apps/runtrue/installations/new?state={state}"
            )
        );
        assert_eq!(
            enterprise
                .repository_clone_url("octo-org", "runtrue")
                .unwrap(),
            "https://github.example.com:8443/octo-org/runtrue.git"
        );
        assert!(GitHubAppPublicConfig::new_with_origins(
            123,
            "runtrue",
            "https://github.example.com",
            "https://api.github.com",
        )
        .is_err());
        assert!(GitHubAppPublicConfig::new_with_origins(
            123,
            "runtrue",
            "https://github.com",
            "https://github.com/api/v3",
        )
        .is_err());
    }

    #[test]
    fn installation_inspection_is_exact_bounded_and_metadata_only() {
        let service = installation_service(
            installation(),
            json!({"total_count": 2, "repositories": [
                repository(42, "runtrue"),
                repository(43, "docs")
            ]}),
        );
        let snapshot = service.inspect_installation(7, NOW).unwrap();
        assert_eq!(snapshot.installation_id, 7);
        assert_eq!(snapshot.app_id, 123);
        assert_eq!(snapshot.account.id, 99);
        assert_eq!(snapshot.account.login, "octo-org");
        assert_eq!(snapshot.account.kind, GitHubAccountKind::Organization);
        assert_eq!(snapshot.target_id, snapshot.account.id);
        assert_eq!(
            snapshot.repository_selection,
            GitHubRepositorySelection::Selected
        );
        assert!(snapshot.repository_catalog_complete);
        assert_eq!(
            snapshot
                .repositories
                .iter()
                .map(|repository| repository.id)
                .collect::<Vec<_>>(),
            vec![42, 43]
        );
        snapshot.validate_runtrue_ci_permissions().unwrap();
        assert!(!format!("{service:?}").contains("ghs_catalog_secret"));

        let broker = service.broker.into_inner().unwrap();
        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests.len(), 3);
        assert!(transport.requests.iter().all(|request| request
            .headers
            .get("x-github-api-version")
            .is_some_and(|version| version == GITHUB_API_VERSION)));
        assert_eq!(
            transport.requests[0].url,
            "https://api.github.com/app/installations/7"
        );
        assert_eq!(transport.requests[0].method, GitHubMethod::Get);
        assert_eq!(
            transport.requests[1].url,
            "https://api.github.com/app/installations/7/access_tokens"
        );
        assert_eq!(transport.requests[1].method, GitHubMethod::Post);
        let catalog_scope: Value = serde_json::from_slice(&transport.requests[1].body).unwrap();
        assert_eq!(catalog_scope, json!({"permissions": {"metadata": "read"}}));
        assert_eq!(
            transport.requests[2].url,
            "https://api.github.com/installation/repositories?per_page=100&page=1"
        );
    }

    #[test]
    fn enterprise_installation_api_uses_only_the_exact_configured_origin() {
        let mut transport = MockTransport::default();
        transport.respond(200, installation());
        transport.respond(201, catalog_token_response());
        transport.respond(
            200,
            json!({"total_count": 1, "repositories": [repository(42, "runtrue")]}),
        );
        let api_origin = "https://github.example.com:8443/api/v3";
        let broker = GitHubAppBroker::new(transport, FixedJwt, api_origin).unwrap();
        let service = GitHubInstallationService::new(broker, 123).unwrap();
        service.inspect_installation(7, NOW).unwrap();
        let broker = service.broker.into_inner().unwrap();
        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests.len(), 3);
        assert!(transport
            .requests
            .iter()
            .all(|request| !request.headers.contains_key("x-github-api-version")));
        assert_eq!(
            transport.requests[0].url,
            "https://github.example.com:8443/api/v3/app/installations/7"
        );
        assert_eq!(
            transport.requests[1].url,
            "https://github.example.com:8443/api/v3/app/installations/7/access_tokens"
        );
        assert_eq!(
            transport.requests[2].url,
            "https://github.example.com:8443/api/v3/installation/repositories?per_page=100&page=1"
        );
    }

    #[test]
    fn installation_substitution_oversize_and_permissions_fail_closed() {
        let mut substituted = installation();
        substituted["id"] = json!(8);
        let service =
            installation_service(substituted, json!({"total_count": 0, "repositories": []}));
        assert!(matches!(
            service.inspect_installation(7, NOW),
            Err(GitHubError::InstallationSubstitution)
        ));

        let service = installation_service(
            installation(),
            json!({"total_count": MAX_SELECTED_REPOSITORIES + 1, "repositories": []}),
        );
        assert!(matches!(
            service.inspect_installation(7, NOW),
            Err(GitHubError::RepositoryCatalogTooLarge)
        ));

        let mut underprivileged = installation();
        underprivileged["permissions"]["checks"] = json!("read");
        let service = installation_service(
            underprivileged,
            json!({"total_count": 0, "repositories": []}),
        );
        let snapshot = service.inspect_installation(7, NOW).unwrap();
        assert!(matches!(
            snapshot.validate_runtrue_ci_permissions(),
            Err(GitHubError::InsufficientInstallationPermissions)
        ));

        let mut capability_ceiling = installation();
        capability_ceiling["permissions"]["contents"] = json!("write");
        capability_ceiling["permissions"]["pull_requests"] = json!("write");
        capability_ceiling["permissions"]["issues"] = json!("write");
        let service = installation_service(
            capability_ceiling,
            json!({"total_count": 0, "repositories": []}),
        );
        let snapshot = service.inspect_installation(7, NOW).unwrap();
        assert!(snapshot.validate_runtrue_ci_permissions().is_ok());

        assert!(matches!(
            GitHubResponse::new(200, vec![0; MAX_RESPONSE_BYTES + 1]),
            Err(GitHubError::ResponseTooLarge)
        ));
        let oversized_repositories = Value::Array(
            (0..=MAX_SELECTED_REPOSITORIES)
                .map(|index| repository(u64::try_from(index + 1).unwrap(), "runtrue"))
                .collect(),
        );
        assert!(matches!(
            parse_repository_array(
                Some(&oversized_repositories),
                &parse_account(&account()).unwrap(),
                true
            ),
            Err(GitHubError::RepositoryCatalogTooLarge)
        ));
        for branch in ["../main", ".hidden", "release.lock", "main@{1}", "a//b"] {
            assert!(!valid_default_branch(branch), "{branch}");
        }
    }

    #[test]
    fn suspended_installation_is_observable_without_minting_a_token() {
        let mut suspended = installation();
        suspended["suspended_at"] = json!("2026-07-11T00:00:00Z");
        let mut transport = MockTransport::default();
        transport.respond(200, suspended);
        let broker = GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").unwrap();
        let service = GitHubInstallationService::new(broker, 123).unwrap();
        let snapshot = service.inspect_installation(7, NOW).unwrap();
        assert!(snapshot.suspended_at.is_some());
        assert!(!snapshot.repository_catalog_complete);
        assert!(snapshot.repositories.is_empty());
        let broker = service.broker.into_inner().unwrap();
        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests.len(), 1);
    }
}

mod webhook {
    use super::*;

    #[test]
    fn authenticated_installation_webhooks_are_typed_and_identity_bound() {
        let body = serde_json::to_vec(&json!({
            "action": "added",
            "installation": installation(),
            "repositories_added": [repository(42, "runtrue")],
            "repositories_removed": []
        }))
        .unwrap();
        let delivery = verified_webhook("installation_repositories", body);
        let parsed = parse_github_installation_webhook(&delivery, 123).unwrap();
        let GitHubInstallationWebhook::RepositoriesChanged {
            action,
            installation: installation_snapshot,
            repositories_added,
            repositories_removed,
        } = parsed
        else {
            panic!("expected repository change");
        };
        assert_eq!(action, GitHubInstallationRepositoriesAction::Added);
        assert_eq!(installation_snapshot.installation_id, 7);
        assert_eq!(repositories_added[0].id, 42);
        assert!(repositories_removed.is_empty());

        let mut suspended = installation();
        suspended["suspended_at"] = json!("2026-07-11T00:00:00Z");
        let body = serde_json::to_vec(&json!({
            "action": "suspend",
            "installation": suspended
        }))
        .unwrap();
        let delivery = verified_webhook("installation", body);
        assert!(matches!(
            parse_github_installation_webhook(&delivery, 123),
            Ok(GitHubInstallationWebhook::Installation {
                action: GitHubInstallationAction::Suspend,
                ..
            })
        ));
    }

    #[test]
    fn installation_webhooks_reject_unknown_duplicate_and_substituted_metadata() {
        let unknown = verified_webhook(
            "installation",
            serde_json::to_vec(&json!({
                "action": "transferred",
                "installation": installation()
            }))
            .unwrap(),
        );
        assert!(matches!(
            parse_github_installation_webhook(&unknown, 123),
            Err(GitHubError::MalformedResponse)
        ));

        let duplicate = verified_webhook(
            "installation",
            br#"{"action":"created","action":"deleted","installation":{}}"#.to_vec(),
        );
        assert!(matches!(
            parse_github_installation_webhook(&duplicate, 123),
            Err(GitHubError::MalformedResponse)
        ));

        let mut substituted_repository = repository(42, "runtrue");
        substituted_repository["owner"]["id"] = json!(100);
        let substituted = verified_webhook(
            "installation_repositories",
            serde_json::to_vec(&json!({
                "action": "added",
                "installation": installation(),
                "repositories_added": [substituted_repository],
                "repositories_removed": []
            }))
            .unwrap(),
        );
        assert!(matches!(
            parse_github_installation_webhook(&substituted, 123),
            Err(GitHubError::InstallationSubstitution)
        ));
        assert!(matches!(
            parse_github_installation_webhook(&substituted, 124),
            Err(GitHubError::InstallationSubstitution)
        ));
    }
}

mod installation_validation {
    use super::*;

    #[test]
    fn token_scope_digest_is_stable_across_credential_renewal() {
        let mut first_transport = MockTransport::default();
        first_transport.respond(201, token_response());
        let mut first_broker =
            GitHubAppBroker::new(first_transport, FixedJwt, "https://api.github.com")
                .expect("broker");
        let first = first_broker
            .mint_installation_token(token_request(), NOW)
            .expect("first token");

        let mut second_transport = MockTransport::default();
        let mut renewed = token_response();
        renewed["token"] = json!("renewed-installation-token-secret");
        renewed["expires_at"] = json!("2026-07-11T01:00:30Z");
        second_transport.respond(201, renewed);
        let mut second_broker =
            GitHubAppBroker::new(second_transport, FixedJwt, "https://api.github.com")
                .expect("broker");
        let second = second_broker
            .mint_installation_token(token_request(), NOW)
            .expect("renewed token");

        assert_eq!(first.scope_digest, second.scope_digest);
        assert_ne!(first.expires_at, second.expires_at);
    }

    #[test]
    fn accepts_one_hour_installation_tokens_with_bounded_provider_clock_skew() {
        let mut transport = MockTransport::default();
        let mut response = token_response();
        response["expires_at"] = json!("2026-07-11T01:01:00Z");
        transport.respond(201, response);
        let mut broker =
            GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").expect("broker");
        assert!(broker.mint_installation_token(token_request(), NOW).is_ok());

        let mut transport = MockTransport::default();
        let mut response = token_response();
        response["expires_at"] = json!("2026-07-11T01:01:01Z");
        transport.respond(201, response);
        let mut broker =
            GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").expect("broker");
        assert!(matches!(
            broker.mint_installation_token(token_request(), NOW),
            Err(GitHubError::MalformedResponse)
        ));
    }

    #[test]
    fn rejects_unscoped_elevated_or_mismatched_tokens() {
        let mut unscoped = token_request();
        unscoped.repository_ids.clear();
        assert!(matches!(
            validate_token_request(&unscoped),
            Err(GitHubError::InvalidTokenScope)
        ));
        let mut elevated = token_request();
        elevated
            .permissions
            .insert(GitHubPermission::Actions, GitHubPermissionLevel::Write);
        assert!(validate_token_request(&elevated).is_err());

        let mut transport = MockTransport::default();
        let mut response = token_response();
        response["repositories"] = json!([{"id": 99}]);
        transport.respond(201, response);
        let mut broker =
            GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").expect("broker");
        assert!(matches!(
            broker.mint_installation_token(token_request(), NOW),
            Err(GitHubError::InvalidTokenScope)
        ));
    }
}

mod checks {
    use super::*;
    use crate::github::checks::check_body;

    #[test]
    fn backend_generated_check_markdown_is_rendered_without_unescaping_dynamic_content() {
        let request = CheckRunRequest {
            repository_id: 42,
            owner: "octo".to_owned(),
            repository: "runtrue".to_owned(),
            name: "Runtrue / test".to_owned(),
            head_sha: "a".repeat(40),
            details_url: None,
            external_id: "run-1-job-test".to_owned(),
            status: CheckStatus::Completed,
            conclusion: Some(CheckConclusion::Success),
            title: "Test succeeded".to_owned(),
            summary: "### ✅ Test\n\n| **Status** | **succeeded** |\n\n    safe log".to_owned(),
            render_markdown: true,
            actions: vec![CheckRunRequestedAction {
                label: "Approve & run".to_owned(),
                description: "Run this exact workflow".to_owned(),
                identifier: "approve_proposed".to_owned(),
            }],
            trusted_base_workflow: true,
            annotations: Vec::new(),
        };
        let body: Value =
            serde_json::from_slice(&check_body(&request, &[], true).unwrap()).unwrap();
        let summary = body["output"]["summary"].as_str().unwrap();
        assert!(summary.starts_with("### ✅ Test"));
        assert!(summary.contains("| **Status** | **succeeded** |"));
        assert!(!summary.contains("\\#\\#\\#"));
        assert!(summary.ends_with("Trusted-base workflow executed: yes"));
        assert_eq!(body["actions"][0]["label"], "Approve & run");
        assert_eq!(body["actions"][0]["identifier"], "approve_proposed");
    }

    #[test]
    fn check_annotations_are_sanitized_and_batched_at_fifty() {
        let (mut broker, token) = broker_with_token();
        broker.transport.respond(201, json!({"id": 9001}));
        broker.transport.respond(200, json!({"id": 9001}));
        let annotation = CheckAnnotation {
            path: "src/lib.rs".to_owned(),
            start_line: 2,
            end_line: 2,
            start_column: Some(1),
            end_column: Some(4),
            level: CheckAnnotationLevel::Failure,
            message: "<b>[click](https://evil.invalid)</b>".to_owned(),
            title: Some("rule#1".to_owned()),
        };
        let request = CheckRunRequest {
            repository_id: 42,
            owner: "octo".to_owned(),
            repository: "runtrue".to_owned(),
            name: "Runtrue / test".to_owned(),
            head_sha: "a".repeat(40),
            details_url: Some("https://runtrue.example/runs/1".to_owned()),
            external_id: "run-1-capsule-abc".to_owned(),
            status: CheckStatus::Completed,
            conclusion: Some(CheckConclusion::Failure),
            title: "Test report".to_owned(),
            summary: "Untrusted [summary](https://evil.invalid)".to_owned(),
            render_markdown: false,
            actions: Vec::new(),
            trusted_base_workflow: true,
            annotations: vec![annotation; 51],
        };
        let published = broker
            .publish_check_run(&token, &request, NOW)
            .expect("publish");
        assert_eq!(published.check_run_id, 9001);
        assert_eq!(published.annotation_requests, 2);

        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests.len(), 3);
        let create: Value = serde_json::from_slice(&transport.requests[1].body).unwrap();
        let update: Value = serde_json::from_slice(&transport.requests[2].body).unwrap();
        assert_eq!(
            create["output"]["annotations"].as_array().unwrap().len(),
            50
        );
        assert_eq!(update["output"]["annotations"].as_array().unwrap().len(), 1);
        assert!(create["output"]["summary"]
            .as_str()
            .unwrap()
            .contains("Trusted-base workflow executed: yes"));
        let message = create["output"]["annotations"][0]["message"]
            .as_str()
            .unwrap();
        assert!(message.contains("\\<b\\>"));
        assert!(message.contains("\\[click\\]\\(https\\://evil\\.invalid\\)"));
    }

    #[test]
    fn check_scope_expiry_and_paths_fail_closed() {
        let (mut broker, token) = broker_with_token();
        let request = CheckRunRequest {
            repository_id: 42,
            owner: "octo".to_owned(),
            repository: "runtrue".to_owned(),
            name: "test".to_owned(),
            head_sha: "b".repeat(40),
            details_url: None,
            external_id: "run-1".to_owned(),
            status: CheckStatus::InProgress,
            conclusion: None,
            title: "test".to_owned(),
            summary: "running".to_owned(),
            render_markdown: false,
            actions: Vec::new(),
            trusted_base_workflow: false,
            annotations: vec![CheckAnnotation {
                path: "../secret".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: None,
                end_column: None,
                level: CheckAnnotationLevel::Warning,
                message: "bad".to_owned(),
                title: None,
            }],
        };
        assert!(matches!(
            broker.publish_check_run(&token, &request, NOW),
            Err(GitHubError::InvalidCheckRequest)
        ));
        let mut safe = request;
        safe.annotations.clear();
        assert!(matches!(
            broker.publish_check_run(&token, &safe, token.expires_at_unix_seconds),
            Err(GitHubError::InvalidCheckRequest)
        ));
    }

    #[test]
    fn partial_annotation_publication_is_explicitly_reconcilable() {
        let (mut broker, token) = broker_with_token();
        broker.transport.respond(201, json!({"id": 77}));
        broker.transport.respond(500, json!({"message": "failure"}));
        let annotation = CheckAnnotation {
            path: "src/lib.rs".to_owned(),
            start_line: 1,
            end_line: 1,
            start_column: None,
            end_column: None,
            level: CheckAnnotationLevel::Notice,
            message: "notice".to_owned(),
            title: None,
        };
        let request = CheckRunRequest {
            repository_id: 42,
            owner: "octo".to_owned(),
            repository: "runtrue".to_owned(),
            name: "test".to_owned(),
            head_sha: "c".repeat(40),
            details_url: None,
            external_id: "run-2".to_owned(),
            status: CheckStatus::Completed,
            conclusion: Some(CheckConclusion::Success),
            title: "test".to_owned(),
            summary: "done".to_owned(),
            render_markdown: false,
            actions: Vec::new(),
            trusted_base_workflow: false,
            annotations: vec![annotation; 51],
        };
        assert!(matches!(
            broker.publish_check_run(&token, &request, NOW),
            Err(GitHubError::PartialPublish {
                check_run_id: 77,
                confirmed_annotations: 50
            })
        ));
    }

    #[test]
    fn lost_create_response_reconciles_exact_external_id_and_resumes_cursor() {
        let (mut broker, token) = broker_with_token();
        let annotation = CheckAnnotation {
            path: "src/lib.rs".to_owned(),
            start_line: 1,
            end_line: 1,
            start_column: None,
            end_column: None,
            level: CheckAnnotationLevel::Notice,
            message: "notice".to_owned(),
            title: None,
        };
        let request = CheckRunRequest {
            repository_id: 42,
            owner: "octo".to_owned(),
            repository: "runtrue".to_owned(),
            name: "Runtrue / test".to_owned(),
            head_sha: "d".repeat(40),
            details_url: None,
            external_id: "run-exact-capsule-exact".to_owned(),
            status: CheckStatus::Completed,
            conclusion: Some(CheckConclusion::Success),
            title: "test".to_owned(),
            summary: "done".to_owned(),
            render_markdown: false,
            actions: Vec::new(),
            trusted_base_workflow: true,
            annotations: vec![annotation; 51],
        };
        broker.transport.respond(
            200,
            json!({"check_runs": [{
                "id": 88,
                "name": request.name,
                "head_sha": request.head_sha,
                "external_id": request.external_id
            }]}),
        );
        broker.transport.respond(
            200,
            json!({
                "id": 88,
                "name": request.name,
                "head_sha": request.head_sha,
                "external_id": request.external_id,
                "output": {"annotations_count": 50}
            }),
        );
        broker.transport.respond(200, json!({"id": 88}));

        let reconciled = broker
            .reconcile_check_run(&token, &request, NOW)
            .expect("reconcile")
            .expect("existing exact check");
        assert_eq!(reconciled.confirmed_annotations, 50);
        let resumed = broker
            .resume_check_run(&token, &request, reconciled, NOW)
            .expect("resume");
        assert_eq!(resumed.check_run_id, 88);
        assert_eq!(resumed.annotation_requests, 1);
        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests[1].method, GitHubMethod::Get);
        assert_eq!(transport.requests[2].method, GitHubMethod::Get);
        assert_eq!(transport.requests[3].method, GitHubMethod::Patch);
        let update: Value = serde_json::from_slice(&transport.requests[3].body).unwrap();
        assert_eq!(update["output"]["annotations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn reconciled_check_without_annotations_still_patches_terminal_status() {
        let (mut broker, token) = broker_with_token();
        let request = CheckRunRequest {
            repository_id: 42,
            owner: "octo".to_owned(),
            repository: "runtrue".to_owned(),
            name: "Runtrue / test".to_owned(),
            head_sha: "d".repeat(40),
            details_url: None,
            external_id: "run-terminal-no-annotations".to_owned(),
            status: CheckStatus::Completed,
            conclusion: Some(CheckConclusion::Success),
            title: "succeeded".to_owned(),
            summary: "done".to_owned(),
            render_markdown: false,
            actions: Vec::new(),
            trusted_base_workflow: true,
            annotations: Vec::new(),
        };
        broker.transport.respond(200, json!({"id": 88}));

        let resumed = broker
            .resume_check_run(
                &token,
                &request,
                ReconciledCheckRun {
                    check_run_id: 88,
                    confirmed_annotations: 0,
                },
                NOW,
            )
            .expect("resume terminal check");
        assert_eq!(resumed.check_run_id, 88);
        assert_eq!(resumed.annotation_requests, 0);
        let (transport, _) = broker.into_parts();
        assert_eq!(transport.requests.len(), 2);
        assert_eq!(transport.requests[1].method, GitHubMethod::Patch);
        let update: Value = serde_json::from_slice(&transport.requests[1].body).unwrap();
        assert_eq!(update["status"], "completed");
        assert_eq!(update["conclusion"], "success");
        assert!(update["output"].get("annotations").is_none());
    }
}

mod client_validation {
    use super::*;

    #[test]
    fn rate_limit_retry_after_is_bounded_and_typed() {
        let mut transport = MockTransport::default();
        transport.responses.push_back(
            GitHubResponse::new(429, br#"{"message":"rate limited"}"#.to_vec())
                .unwrap()
                .with_retry_after_seconds(37)
                .unwrap(),
        );
        let mut broker =
            GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").unwrap();
        assert!(matches!(
            broker.mint_installation_token(token_request(), NOW),
            Err(GitHubError::RateLimited {
                retry_after_seconds: 37
            })
        ));
        assert!(GitHubResponse::new(429, Vec::new())
            .unwrap()
            .with_retry_after_seconds(3_601)
            .is_err());
    }

    #[test]
    fn repository_credential_requires_exact_read_only_scope_and_redacts() {
        let mut request = token_request();
        request.permissions = BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Contents, GitHubPermissionLevel::Read),
        ]);
        let mut response = token_response();
        response["permissions"] = json!({"metadata": "read", "contents": "read"});
        let mut transport = MockTransport::default();
        transport.respond(201, response);
        let mut broker =
            GitHubAppBroker::new(transport, FixedJwt, "https://api.github.com").unwrap();
        let token = broker.mint_installation_token(request, NOW).unwrap();
        let credential = token.into_repository_read_credential(42).unwrap();
        assert_eq!(credential.installation_id, 7);
        assert_eq!(credential.repository_id, 42);
        assert!(credential
            .authorization_header()
            .starts_with("Authorization: Basic "));
        let encoded = credential
            .authorization_header()
            .strip_prefix("Authorization: Basic ")
            .unwrap();
        assert_eq!(
            base64ct::Base64::decode_vec(encoded).unwrap(),
            b"x-access-token:ghs_installation_secret"
        );
        assert!(!format!("{credential:?}").contains("ghs_installation_secret"));
    }

    #[test]
    fn dns_policy_rejects_private_special_and_mapped_answers() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ip("140.82.112.3".parse().unwrap()));
        assert!(is_public_ip("2606:50c0:8000::154".parse().unwrap()));
    }

    #[test]
    fn app_jwt_claims_bind_app_clock_and_lifetime() {
        fn jwt(app_id: u64, issued_at: u64, expires_at: u64) -> String {
            let header = Base64UrlUnpadded::encode_string(br#"{"alg":"RS256","typ":"JWT"}"#);
            let claims = Base64UrlUnpadded::encode_string(
                serde_json::to_string(&json!({
                    "iss": app_id,
                    "iat": issued_at,
                    "exp": expires_at
                }))
                .unwrap()
                .as_bytes(),
            );
            let signature = Base64UrlUnpadded::encode_string(b"opaque-signature");
            format!("{header}.{claims}.{signature}")
        }

        let valid = jwt(123, NOW - 30, NOW + 8 * 60);
        assert!(validate_github_app_jwt(valid, 123, NOW).is_ok());
        assert!(validate_github_app_jwt(jwt(124, NOW - 30, NOW + 60), 123, NOW).is_err());
        assert!(validate_github_app_jwt(jwt(123, NOW - 61, NOW + 60), 123, NOW).is_err());
        assert!(validate_github_app_jwt(jwt(123, NOW, NOW + 601), 123, NOW).is_err());
    }

    #[test]
    fn timestamps_and_origins_are_strict() {
        assert_eq!(parse_utc_timestamp("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_utc_timestamp("1970-01-02T00:00:00Z").unwrap(), 86_400);
        assert!(parse_utc_timestamp("2026-02-29T00:00:00Z").is_err());
        assert!(validate_api_origin("http://api.github.com").is_err());
        assert!(validate_api_origin("https://user@api.github.com").is_err());
        assert!(validate_api_origin("https://github.example/api/v3").is_ok());
        assert!(validate_api_origin("https://127.0.0.1/api/v3").is_err());
        assert!(validate_api_origin("https://GitHub.example/api/v3").is_err());
        assert!(validate_api_origin("https://github.example:443/api/v3").is_err());
        assert!(validate_api_origin("https://github.example/api/v4").is_err());
    }

    #[test]
    fn request_and_response_debug_never_disclose_credentials_or_bodies() {
        let request = GitHubRequest {
            method: GitHubMethod::Post,
            url: "https://api.github.com/test".to_owned(),
            headers: headers("https://api.github.com"),
            bearer_token: SensitiveToken::new("super-secret".to_owned()).unwrap(),
            body: Zeroizing::new(b"also-secret".to_vec()),
        };
        let response = GitHubResponse::new(200, b"response-secret".to_vec()).unwrap();
        assert!(!format!("{request:?}").contains("secret"));
        assert!(!format!("{response:?}").contains("secret"));
    }
}

mod webhook_normalization {
    use super::*;

    const SECRET: &[u8] = b"correct horse battery staple";
    const DELIVERY: &str = "8d54ab51-8c3c-4a42-84a3-76b4f1715db6";

    fn github_headers(event: &str, body: &[u8]) -> WebhookHeaders {
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).expect("test key");
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        WebhookHeaders::from_pairs(
            [
                ("X-Hub-Signature-256", signature.as_str()),
                ("x-github-delivery", DELIVERY),
                ("X-GitHub-Event", event),
            ],
            WebhookLimits::default(),
        )
        .expect("headers")
    }

    fn verify(event: &str, body: Vec<u8>) -> VerifiedDelivery {
        let headers = github_headers(event, &body);
        GitHubWebhookVerifier::new(SECRET, WebhookLimits::default())
            .expect("verifier")
            .verify(&headers, body)
            .expect("verified")
    }

    fn common_payload() -> Value {
        json!({
            "repository": {
                "id": 42,
                "owner": {"login": "octo"},
                "name": "runtrue",
                "full_name": "octo/runtrue",
                "private": true,
                "default_branch": "main"
            },
            "sender": {"id": 7, "login": "builder", "type": "User"}
        })
    }

    fn push_payload() -> Value {
        let mut payload = common_payload();
        let object = payload.as_object_mut().expect("object");
        object.insert("ref".to_owned(), json!("refs/heads/main"));
        object.insert("after".to_owned(), json!("a".repeat(40)));
        object.insert("before".to_owned(), json!("b".repeat(40)));
        object.insert(
            "commits".to_owned(),
            json!([
                {
                    "added": ["src/z.rs", "src/a.rs"],
                    "modified": ["src/a.rs"],
                    "removed": []
                }
            ]),
        );
        payload
    }

    #[test]
    fn authenticates_exact_bytes_before_normalizing_push() {
        let body = serde_json::to_vec(&push_payload()).expect("json");
        let delivery = verify("push", body.clone());
        assert_eq!(delivery.raw_payload_digest, ContentDigest::sha256(&body));
        let envelope =
            normalize_github(&delivery, "installation-1", 1234, WebhookLimits::default())
                .expect("normalize");
        assert_eq!(envelope.event_type, EventType::Push);
        assert_eq!(envelope.source.commit, "a".repeat(40));
        assert_eq!(
            envelope.changed_paths,
            vec!["src/a.rs".to_owned(), "src/z.rs".to_owned()]
        );
        envelope
            .verify(WebhookLimits::default())
            .expect("digest verifies");
    }

    #[test]
    fn signature_is_constant_time_verified_against_exact_body() {
        let body = serde_json::to_vec(&push_payload()).expect("json");
        let headers = github_headers("push", &body);
        let mut modified = body;
        modified.push(b' ');
        let error = GitHubWebhookVerifier::new(SECRET, WebhookLimits::default())
            .expect("verifier")
            .verify(&headers, modified)
            .expect_err("modified body must fail");
        assert!(matches!(error, ScmError::SignatureMismatch));
    }

    #[test]
    fn secrets_and_payloads_are_redacted_from_debug() {
        let verifier =
            GitHubWebhookVerifier::new(SECRET, WebhookLimits::default()).expect("verifier");
        let body = serde_json::to_vec(&push_payload()).expect("json");
        let delivery = verify("push", body);
        let verifier_debug = format!("{verifier:?}");
        let delivery_debug = format!("{delivery:?}");
        assert!(!verifier_debug.contains("correct horse"));
        assert!(!delivery_debug.contains("octo/runtrue"));
        assert!(verifier_debug.contains("[REDACTED]"));
        assert!(delivery_debug.contains("[REDACTED]"));
    }

    #[test]
    fn normalized_digest_excludes_raw_format_and_receipt_time() {
        let compact = serde_json::to_vec(&push_payload()).expect("json");
        let pretty = serde_json::to_vec_pretty(&push_payload()).expect("json");
        let first = normalize_github(
            &verify("push", compact),
            "installation-1",
            1,
            WebhookLimits::default(),
        )
        .expect("first");
        let second = normalize_github(
            &verify("push", pretty),
            "installation-1",
            999,
            WebhookLimits::default(),
        )
        .expect("second");
        assert_ne!(first.raw_payload_digest, second.raw_payload_digest);
        assert_eq!(first.normalized_digest, second.normalized_digest);
    }

    #[test]
    fn normalizes_pull_request_head_and_trusted_base_separately() {
        let mut payload = common_payload();
        let object = payload.as_object_mut().expect("object");
        object.insert("action".to_owned(), json!("synchronize"));
        object.insert("number".to_owned(), json!(17));
        object.insert(
            "pull_request".to_owned(),
            json!({
                "draft": false,
                "merged": false,
                "head": {
                    "sha": "c".repeat(40),
                    "ref": "feature",
                    "repo": {"full_name": "contributor/fork"}
                },
                "base": {
                    "sha": "d".repeat(40),
                    "ref": "main",
                    "repo": {"full_name": "octo/runtrue"}
                }
            }),
        );
        let body = serde_json::to_vec(&payload).expect("json");
        let envelope = normalize_github(
            &verify("pull_request", body),
            "installation-1",
            1,
            WebhookLimits::default(),
        )
        .expect("pull request");
        assert_eq!(
            envelope.event_type,
            EventType::PullRequest {
                action: PullRequestAction::Synchronize
            }
        );
        assert_eq!(
            envelope.source.repository_full_name.as_deref(),
            Some("contributor/fork")
        );
        assert_eq!(
            envelope
                .base
                .as_ref()
                .and_then(|base| base.repository_full_name.as_deref()),
            Some("octo/runtrue")
        );
    }

    #[test]
    fn normalizes_issue_comment_as_bounded_non_code_event() {
        let mut payload = common_payload();
        payload["installation"] = json!({"id": 9001});
        payload["action"] = json!("created");
        payload["issue"] = json!({"number": 17});
        payload["comment"] = json!({"id": 99, "body": "untrusted command text"});
        let body = serde_json::to_vec(&payload).expect("json");
        let delivery = verify("issue_comment", body);
        let envelope = normalize_github(&delivery, "fallback", 1, WebhookLimits::default())
            .expect("normalized issue comment");
        assert_eq!(
            envelope.event_type,
            EventType::IssueComment {
                action: IssueCommentAction::Created
            }
        );
        let comment = envelope.issue_comment.as_ref().expect("comment metadata");
        assert_eq!(comment.issue_number, 17);
        assert_eq!(comment.comment_id, 99);
        assert!(!comment.issue_is_pull_request);
        assert_eq!(comment.body, "untrusted command text");
        assert!(envelope.source.commit.bytes().all(|byte| byte == b'0'));
        let metadata = inspect_github_delivery(&delivery, "fallback", WebhookLimits::default())
            .expect("inspect authenticated delivery");
        assert_eq!(metadata.installation_id, "9001");
        assert_eq!(metadata.repository.external_id, "42");
        assert_eq!(metadata.actor.login, "builder");
        assert_eq!(metadata.action.as_deref(), Some("created"));
    }

    #[test]
    fn normalizes_requested_check_action_with_exact_identifier_and_actor() {
        let mut payload = common_payload();
        payload["installation"] = json!({"id": 9001});
        payload["action"] = json!("requested_action");
        payload["requested_action"] = json!({"identifier": "approve_proposed"});
        payload["check_run"] = json!({
            "id": 77,
            "pull_requests": [{"number": 28}]
        });
        let delivery = verify("check_run", serde_json::to_vec(&payload).unwrap());
        let envelope = normalize_github(&delivery, "fallback", 1, WebhookLimits::default())
            .expect("requested check action");
        assert_eq!(
            envelope.event_type,
            EventType::CheckRun {
                action: CheckRunEventAction::RequestedAction
            }
        );
        let check = envelope.check_run.unwrap();
        assert_eq!(check.check_run_id, 77);
        assert_eq!(check.pull_requests[0].number, 28);
        assert_eq!(
            check.requested_action_identifier.as_deref(),
            Some("approve_proposed")
        );
        assert_eq!(envelope.actor.login, "builder");
    }

    #[test]
    fn merge_queue_only_accepts_checks_requested_and_binds_synthetic_sha() {
        let mut payload = common_payload();
        payload["action"] = json!("checks_requested");
        payload["merge_group"] = json!({
            "head_sha": "e".repeat(40),
            "head_ref": "refs/heads/gh-readonly-queue/main/pr-17",
            "base_sha": "f".repeat(40),
            "base_ref": "refs/heads/main"
        });
        let body = serde_json::to_vec(&payload).expect("json");
        let envelope = normalize_github(
            &verify("merge_group", body),
            "installation-1",
            1,
            WebhookLimits::default(),
        )
        .expect("merge group");
        assert_eq!(envelope.event_type, EventType::MergeGroup);
        assert_eq!(envelope.source.commit, "e".repeat(40));
        assert_eq!(envelope.base.as_ref().unwrap().commit, "f".repeat(40));

        payload["action"] = json!("destroyed");
        let body = serde_json::to_vec(&payload).expect("json");
        assert!(matches!(
            normalize_github(
                &verify("merge_group", body),
                "installation-1",
                1,
                WebhookLimits::default()
            ),
            Err(ScmError::UnsupportedAction(_))
        ));
    }

    #[test]
    fn duplicate_json_keys_are_rejected_at_any_depth() {
        let body = br#"{"repository":{"id":1,"id":2}}"#.to_vec();
        let error = normalize_github(
            &verify("push", body),
            "installation-1",
            1,
            WebhookLimits::default(),
        )
        .expect_err("duplicates must fail");
        assert!(matches!(error, ScmError::InvalidJson(_)));
    }

    #[test]
    fn headers_are_case_insensitive_but_duplicates_are_rejected() {
        let error = WebhookHeaders::from_pairs(
            [("X-GitHub-Event", "push"), ("x-github-event", "push")],
            WebhookLimits::default(),
        )
        .expect_err("duplicate");
        assert!(matches!(error, ScmError::DuplicateHeader(_)));
    }

    #[test]
    fn tampered_normalized_projection_is_detected() {
        let body = serde_json::to_vec(&push_payload()).expect("json");
        let mut envelope = normalize_github(
            &verify("push", body),
            "installation-1",
            1,
            WebhookLimits::default(),
        )
        .expect("normalize");
        envelope.source.commit = "e".repeat(40);
        let error = envelope
            .verify(WebhookLimits::default())
            .expect_err("tamper");
        assert!(matches!(error, ScmError::NormalizedDigestMismatch));
    }

    #[test]
    fn unsafe_changed_paths_and_body_overruns_fail_closed() {
        let mut payload = push_payload();
        payload["commits"][0]["added"] = json!(["../secret"]);
        let body = serde_json::to_vec(&payload).expect("json");
        let error = normalize_github(
            &verify("push", body),
            "installation-1",
            1,
            WebhookLimits::default(),
        )
        .expect_err("unsafe path");
        assert!(matches!(error, ScmError::InvalidPath(_)));

        let limits = WebhookLimits {
            max_body_bytes: 1,
            ..WebhookLimits::default()
        };
        let body = b"{}".to_vec();
        let headers = github_headers("ping", &body);
        let error = GitHubWebhookVerifier::new(SECRET, limits)
            .expect("verifier")
            .verify(&headers, body)
            .expect_err("overrun");
        assert!(matches!(error, ScmError::LimitExceeded(_)));
    }
}
