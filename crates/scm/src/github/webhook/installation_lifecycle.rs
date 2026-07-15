use super::super::{
    installation::{GitHubInstallationRepository, GitHubInstallationSnapshot},
    pagination::{parse_installation_metadata, parse_repository_array},
    validation::parse_strict_json,
    GitHubError,
};
use crate::{ProviderKind, VerifiedDelivery};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubInstallationAction {
    Created,
    Deleted,
    NewPermissionsAccepted,
    Suspend,
    Unsuspend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubInstallationRepositoriesAction {
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GitHubInstallationWebhook {
    Installation {
        action: GitHubInstallationAction,
        installation: GitHubInstallationSnapshot,
        repositories: Vec<GitHubInstallationRepository>,
    },
    RepositoriesChanged {
        action: GitHubInstallationRepositoriesAction,
        installation: GitHubInstallationSnapshot,
        repositories_added: Vec<GitHubInstallationRepository>,
        repositories_removed: Vec<GitHubInstallationRepository>,
    },
}

/// Parse an already authenticated GitHub installation lifecycle delivery.
/// Duplicate JSON keys are rejected by the shared strict parser. Only the two
/// provider event names and their documented actions are admitted; all
/// security-relevant identities are parsed as positive numeric values and
/// related back to the exact configured App and installation account.
pub fn parse_github_installation_webhook(
    delivery: &VerifiedDelivery,
    expected_app_id: u64,
) -> Result<GitHubInstallationWebhook, GitHubError> {
    if delivery.provider != ProviderKind::GitHub || expected_app_id == 0 {
        return Err(GitHubError::InvalidInstallation);
    }
    let payload =
        parse_strict_json(delivery.raw_payload()).map_err(|_| GitHubError::MalformedResponse)?;
    let object = payload.as_object().ok_or(GitHubError::MalformedResponse)?;
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)?;
    let mut installation = object
        .get("installation")
        .ok_or(GitHubError::MalformedResponse)
        .and_then(|value| parse_installation_metadata(value, expected_app_id))?;
    installation.repositories.clear();
    installation.repository_catalog_complete = false;
    match delivery.event_name.as_str() {
        "installation" => {
            let action = match action {
                "created" => GitHubInstallationAction::Created,
                "deleted" => GitHubInstallationAction::Deleted,
                "new_permissions_accepted" => GitHubInstallationAction::NewPermissionsAccepted,
                "suspend" => GitHubInstallationAction::Suspend,
                "unsuspend" => GitHubInstallationAction::Unsuspend,
                _ => return Err(GitHubError::MalformedResponse),
            };
            if (action == GitHubInstallationAction::Suspend && installation.suspended_at.is_none())
                || (action == GitHubInstallationAction::Unsuspend
                    && installation.suspended_at.is_some())
            {
                return Err(GitHubError::InstallationSubstitution);
            }
            let repositories =
                parse_repository_array(object.get("repositories"), &installation.account, false)?;
            Ok(GitHubInstallationWebhook::Installation {
                action,
                installation,
                repositories,
            })
        }
        "installation_repositories" => {
            let action = match action {
                "added" => GitHubInstallationRepositoriesAction::Added,
                "removed" => GitHubInstallationRepositoriesAction::Removed,
                _ => return Err(GitHubError::MalformedResponse),
            };
            let repositories_added = parse_repository_array(
                object.get("repositories_added"),
                &installation.account,
                true,
            )?;
            let repositories_removed = parse_repository_array(
                object.get("repositories_removed"),
                &installation.account,
                true,
            )?;
            if (action == GitHubInstallationRepositoriesAction::Added
                && repositories_added.is_empty())
                || (action == GitHubInstallationRepositoriesAction::Removed
                    && repositories_removed.is_empty())
                || repositories_added.iter().any(|added| {
                    repositories_removed
                        .iter()
                        .any(|removed| removed.id == added.id)
                })
            {
                return Err(GitHubError::InstallationSubstitution);
            }
            Ok(GitHubInstallationWebhook::RepositoriesChanged {
                action,
                installation,
                repositories_added,
                repositories_removed,
            })
        }
        _ => Err(GitHubError::InvalidInstallation),
    }
}
