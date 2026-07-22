//! Display-safe response models for the authenticated GitHub browser API.
//!
//! This module contains no HTML, CSS, JavaScript, authorization, persistence,
//! provider calls, credentials, private keys, webhook secrets, or installation
//! tokens. The standalone Node application owns all frontend rendering.

mod model;
mod payload;

pub use model::{
    ComponentHealth, GitHubAccountKind, GitHubAppHealth, GitHubInstallAction,
    GitHubInstallationState, GitHubInstallationView, GitHubInstallationsPage, GitHubPermission,
    GitHubRepositoryCandidateAction, GitHubRepositoryEventView, GitHubRepositoryLinkView,
    GitHubUiAlert, RepositoryLinkState, RepositorySelection, RepositoryVisibility,
};
pub use payload::github_installations_payload;
pub(crate) use payload::repository_url;

/// The response contains a session-bound CSRF proof and one-use idempotency key.
pub const GITHUB_BROWSER_API_CACHE_CONTROL: &str = "no-store";

#[cfg(test)]
mod tests {
    use super::*;

    fn populated_page() -> GitHubInstallationsPage {
        GitHubInstallationsPage {
            tenant_name: "Forge".to_owned(),
            principal_name: "Ada".to_owned(),
            session_csrf_token: "session-csrf".to_owned(),
            app: GitHubAppHealth {
                app_id: Some(42),
                app_slug: Some("runtrue-ci".to_owned()),
                provider_host: "github.example".to_owned(),
                app: ComponentHealth::Ready,
                signer: ComponentHealth::Ready,
                webhook: ComponentHealth::Ready,
                callback: ComponentHealth::Ready,
            },
            installations: vec![GitHubInstallationView {
                installation_id: 7,
                account_login: "octo".to_owned(),
                account_kind: GitHubAccountKind::Organization,
                state: GitHubInstallationState::Active,
                repository_selection: RepositorySelection::Selected(1),
                permissions: vec![
                    GitHubPermission::MetadataRead,
                    GitHubPermission::ChecksWrite,
                ],
            }],
            repositories: vec![GitHubRepositoryLinkView {
                repository_id: 9,
                control_plane_id: Some("repo-9".to_owned()),
                owner: "octo".to_owned(),
                name: "runtrue".to_owned(),
                web_origin: "https://github.example".to_owned(),
                visibility: RepositoryVisibility::Private,
                installation_account: "octo".to_owned(),
                default_branch: "main".to_owned(),
                state: RepositoryLinkState::Ready,
            }],
            repository_candidates: vec![GitHubRepositoryCandidateAction {
                installation_id: "installation-7".to_owned(),
                external_repository_id: "9".to_owned(),
                owner: "octo".to_owned(),
                name: "available".to_owned(),
                visibility: RepositoryVisibility::Internal,
                default_branch: "trunk".to_owned(),
                csrf_token: "candidate-csrf".to_owned(),
            }],
            events: vec![GitHubRepositoryEventView {
                delivery_id: "delivery-1".to_owned(),
                repository: "octo/runtrue".to_owned(),
                provider_event_name: "push".to_owned(),
                event_kind: "push".to_owned(),
                actor_login: "ada".to_owned(),
                ref_name: Some("refs/heads/main".to_owned()),
                received_at: "2026-07-13T00:00:00Z".to_owned(),
            }],
            alert: Some(GitHubUiAlert::InstallationQueued),
            install_action: Some(GitHubInstallAction {
                csrf_token: "csrf&proof".to_owned(),
                idempotency_key: "setup-once".to_owned(),
            }),
        }
    }

    #[test]
    fn payload_contains_only_supported_backend_data() {
        let payload = github_installations_payload(&populated_page());

        assert_eq!(payload["session"]["principalName"], "Ada");
        assert_eq!(payload["repositories"][0]["id"], "repo-9");
        assert_eq!(payload["repositories"][0]["key"], "octo/runtrue");
        assert_eq!(
            payload["repositories"][0]["repositoryUrl"],
            "https://github.example/octo/runtrue"
        );
        assert_eq!(
            payload["organizations"][0]["repositories"][0]["name"],
            "available"
        );
        assert!(payload["organizations"][0]["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|repository| repository["name"] == "runtrue" && repository["state"] == "added"));
        assert_eq!(
            payload["github"]["installations"][0]["accountLogin"],
            "octo"
        );
        assert_eq!(payload["github"]["events"][0]["deliveryId"], "delivery-1");
        assert!(payload.get("runs").is_none());
        assert!(payload.get("approvals").is_none());
        assert!(payload.get("runners").is_none());
        assert!(payload.get("tokens").is_none());
        assert!(payload.get("audit").is_none());
        assert_eq!(GITHUB_BROWSER_API_CACHE_CONTROL, "no-store");
    }

    #[test]
    fn repository_url_keeps_owner_and_name_inside_the_configured_origin() {
        let mut page = populated_page();
        page.repositories[0].owner = "octo space".to_owned();
        page.repositories[0].name = "runtrue/preview".to_owned();

        let payload = github_installations_payload(&page);

        assert_eq!(
            payload["repositories"][0]["repositoryUrl"],
            "https://github.example/octo%20space/runtrue%2Fpreview"
        );
    }

    #[test]
    fn unlinked_catalog_entries_are_import_candidates_not_managed_repositories() {
        let mut page = populated_page();
        page.repositories.push(GitHubRepositoryLinkView {
            repository_id: 2_078_151,
            control_plane_id: None,
            owner: "bob-pr".to_owned(),
            name: "candidate-repository".to_owned(),
            web_origin: "https://github.example".to_owned(),
            visibility: RepositoryVisibility::Private,
            installation_account: "bob-pr".to_owned(),
            default_branch: "main".to_owned(),
            state: RepositoryLinkState::AwaitingEvent,
        });
        page.repository_candidates
            .push(GitHubRepositoryCandidateAction {
                installation_id: "installation-7".to_owned(),
                external_repository_id: "2078151".to_owned(),
                owner: "bob-pr".to_owned(),
                name: "candidate-repository".to_owned(),
                visibility: RepositoryVisibility::Private,
                default_branch: "main".to_owned(),
                csrf_token: "candidate-csrf".to_owned(),
            });

        let payload = github_installations_payload(&page);

        assert_eq!(payload["repositories"].as_array().unwrap().len(), 1);
        assert_eq!(payload["repositories"][0]["id"], "repo-9");
        assert!(payload["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .all(|repository| !repository["id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("github:")));
        assert!(payload["organizations"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|organization| organization["repositories"].as_array().unwrap())
            .any(|repository| repository["externalRepositoryId"] == "2078151"));
    }

    #[test]
    fn mutation_proofs_are_redacted_from_debug_output() {
        let page = populated_page();
        let debug = format!("{:?}", page.install_action.as_ref().unwrap());

        assert!(!debug.contains("csrf&proof"));
        assert!(!debug.contains("setup-once"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn dynamic_text_remains_data_in_json() {
        let mut page = populated_page();
        page.principal_name = "<script>alert(1)</script>".to_owned();
        page.repositories[0].default_branch = "main<&\"'".to_owned();

        let payload = github_installations_payload(&page);

        assert_eq!(
            payload["session"]["principalName"],
            "<script>alert(1)</script>"
        );
        assert_eq!(payload["repositories"][0]["defaultBranch"], "main<&\"'");
    }
}
