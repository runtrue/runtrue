use super::model::{GitHubInstallationsPage, StatusTone};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Builds the display-safe browser API payload consumed by the Node frontend.
#[must_use]
pub fn github_installations_payload(page: &GitHubInstallationsPage) -> Value {
    let organizations = organization_catalog(page);
    let repositories = page
        .repositories
        .iter()
        // The managed repository list contains only durable Runtrue links.
        // Provider-selected repositories without a link remain available in
        // `organizations` for import; they must never receive settings or
        // uninstall controls backed by a synthetic provider identifier.
        .filter_map(|repository| {
            repository
                .control_plane_id
                .as_ref()
                .map(|control_plane_id| {
                    json!({
                        "id": control_plane_id,
                        "externalId": repository.repository_id,
                        "key": format!("{}/{}", repository.owner, repository.name),
                        "repositoryUrl": repository_url(repository),
                        "organization": repository.owner,
                        "name": repository.name,
                        "source": "GitHub App",
                        "installationAccount": repository.installation_account,
                        "state": repository.state.label(),
                        "defaultBranch": repository.default_branch,
                        "visibility": repository.visibility.label(),
                    })
                })
        })
        .collect::<Vec<_>>();
    let installations = page
        .installations
        .iter()
        .map(|installation| {
            json!({
                "installationId": installation.installation_id,
                "accountLogin": installation.account_login,
                "accountKind": installation.account_kind.label(),
                "state": installation.state.label(),
                "repositorySelection": installation.repository_selection.label(),
                "permissions": installation
                    .permissions
                    .iter()
                    .map(|permission| permission.label())
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let events = page
        .events
        .iter()
        .map(|event| {
            json!({
                "deliveryId": event.delivery_id,
                "repository": event.repository,
                "providerEventName": event.provider_event_name,
                "eventKind": event.event_kind,
                "actorLogin": event.actor_login,
                "refName": event.ref_name,
                "receivedAt": event.received_at,
            })
        })
        .collect::<Vec<_>>();
    let alert = page.alert.map(|alert| {
        let (title, detail, tone) = alert.content();
        json!({"title": title, "detail": detail, "tone": tone_label(tone)})
    });
    let install_action = page.install_action.as_ref().map(|action| {
        json!({
            "csrfToken": action.csrf_token,
            "idempotencyKey": action.idempotency_key,
        })
    });

    json!({
        "session": {
            "principalName": page.principal_name,
            "tenantName": page.tenant_name,
            "csrfToken": page.session_csrf_token,
        },
        "repositories": repositories,
        "organizations": organizations,
        "installAction": install_action,
        "github": {
            "overall": page.app.overall().label(),
            "health": {
                "app": page.app.app.label(),
                "signer": page.app.signer.label(),
                "webhook": page.app.webhook.label(),
                "callback": page.app.callback.label(),
            },
            "metadata": {
                "providerHost": page.app.provider_host,
                "appSlug": page.app.app_slug,
                "appId": page.app.app_id,
            },
            "installations": installations,
            "events": events,
            "alert": alert,
        },
    })
}

fn repository_url(repository: &super::model::GitHubRepositoryLinkView) -> String {
    format!(
        "{}/{}/{}",
        repository.web_origin.trim_end_matches('/'),
        url_path_component(&repository.owner),
        url_path_component(&repository.name),
    )
}

fn url_path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    encoded
}

fn organization_catalog(page: &GitHubInstallationsPage) -> Value {
    let mut organizations = BTreeMap::<String, Vec<Value>>::new();
    for repository in &page.repository_candidates {
        organizations
            .entry(repository.owner.clone())
            .or_default()
            .push(json!({
                "name": repository.name,
                "visibility": repository.visibility.label(),
                "installationId": repository.installation_id,
                "externalRepositoryId": repository.external_repository_id,
                "csrfToken": repository.csrf_token,
                "defaultBranch": repository.default_branch,
                "state": "available",
            }));
    }
    Value::Array(
        organizations
            .into_iter()
            .map(|(name, repositories)| {
                json!({
                    "id": name,
                    "name": name,
                    "initials": initials(&name),
                    "repositories": repositories,
                })
            })
            .collect(),
    )
}

fn initials(name: &str) -> String {
    let letters = name
        .split(|character: char| !character.is_alphanumeric())
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect::<String>();
    if letters.is_empty() {
        "GH".to_owned()
    } else {
        letters.to_uppercase()
    }
}

fn tone_label(tone: StatusTone) -> &'static str {
    match tone {
        StatusTone::Good => "good",
        StatusTone::Warn => "warn",
        StatusTone::Bad => "bad",
    }
}
