mod events;
mod installation_lifecycle;
mod normalization;
mod validation;
mod verification;

const NORMALIZED_EVENT_VERSION: u32 = 1;

pub use installation_lifecycle::{
    parse_github_installation_webhook, GitHubInstallationAction,
    GitHubInstallationRepositoriesAction, GitHubInstallationWebhook,
};
pub use normalization::{inspect_github_delivery, normalize_github};
pub use verification::GitHubWebhookVerifier;

pub(crate) use validation::validate_git_commit;
