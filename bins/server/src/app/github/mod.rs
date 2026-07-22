mod installations;
mod lifecycle;
mod setup;
mod ui;
mod ui_secrets;
mod webhooks;

pub(in crate::app) use installations::{
    github_app_status, revoke_github_installation, sync_github_installation,
};
pub(in crate::app) use lifecycle::reconcile_claimed_github_lifecycle;
pub(in crate::app) use setup::{create_github_setup, finish_github_installation, GitHubSetupView};
pub(in crate::app) use ui::{
    browser_decide_workflow_approval, browser_organization_settings, browser_repository_settings,
    browser_run_detail, delete_browser_organization_secret, delete_browser_organization_variable,
    delete_browser_repository_secret, delete_browser_repository_variable, github_browser_state,
    link_github_repository_from_ui, save_browser_organization_secret,
    save_browser_organization_variable, save_browser_repository_secret,
    save_browser_repository_variable, save_browser_repository_workflow_directory,
    start_github_installation_from_ui, uninstall_browser_repository,
};
pub(in crate::app) use ui_secrets::{
    browser_secret_inventory, delete_browser_scoped_secret, save_browser_configuration_project,
    save_browser_scoped_secret,
};
pub(in crate::app) use webhooks::github_webhook;
