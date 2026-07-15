use std::fmt;

/// Session-bound authorization material for the installation-start mutation.
///
/// These values authorize only Runtrue's fixed local POST route. They are not
/// GitHub credentials and must never be forwarded to the provider.
#[derive(Clone, Eq, PartialEq)]
pub struct GitHubInstallAction {
    /// Browser-session CSRF proof.
    pub csrf_token: String,
    /// One-use idempotency key for durable setup-state creation.
    pub idempotency_key: String,
}

impl fmt::Debug for GitHubInstallAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubInstallAction")
            .field("csrf_token", &"<redacted>")
            .field("idempotency_key", &"<redacted>")
            .finish()
    }
}

/// Coarse health for a configured, non-secret operator component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentHealth {
    /// The component is configured and responding.
    Ready,
    /// The component is configured but currently degraded.
    Degraded,
    /// Required operator configuration is absent.
    Missing,
}

impl ComponentHealth {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Degraded => "Degraded",
            Self::Missing => "Missing",
        }
    }
}

/// Non-secret operator status for the configured GitHub App.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubAppHealth {
    /// Numeric GitHub App identifier. GitHub App IDs are public metadata.
    pub app_id: Option<u64>,
    /// Public application slug, when configured.
    pub app_slug: Option<String>,
    /// Public provider hostname (for example, `github.com`).
    pub provider_host: String,
    /// Whether the application identity is configured.
    pub app: ComponentHealth,
    /// Whether the non-exportable signer is reachable.
    pub signer: ComponentHealth,
    /// Whether signed webhook ingestion is configured and healthy.
    pub webhook: ComponentHealth,
    /// Whether the setup callback is configured and healthy.
    pub callback: ComponentHealth,
}

impl GitHubAppHealth {
    pub(super) fn overall(&self) -> ComponentHealth {
        let states = [self.app, self.signer, self.webhook, self.callback];
        if states.contains(&ComponentHealth::Missing) {
            ComponentHealth::Missing
        } else if states.contains(&ComponentHealth::Degraded) {
            ComponentHealth::Degraded
        } else {
            ComponentHealth::Ready
        }
    }
}

/// GitHub account kind owning an installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubAccountKind {
    /// A GitHub organization.
    Organization,
    /// An individual GitHub account.
    User,
}

impl GitHubAccountKind {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Organization => "Organization",
            Self::User => "User",
        }
    }
}

/// Durable lifecycle state of an installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubInstallationState {
    /// Active and eligible for repository access.
    Active,
    /// Temporarily suspended by GitHub or an operator.
    Suspended,
    /// Awaiting successful provider reconciliation.
    Pending,
    /// Uninstalled and denied access.
    Removed,
}

impl GitHubInstallationState {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Suspended => "Suspended",
            Self::Pending => "Pending",
            Self::Removed => "Removed",
        }
    }
}

/// GitHub permissions relevant to native Runtrue CI.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GitHubPermission {
    /// Repository metadata read access.
    MetadataRead,
    /// Repository contents read access.
    ContentsRead,
    /// Repository contents write access.
    ContentsWrite,
    /// Pull request read access.
    PullRequestsRead,
    /// Pull request write access.
    PullRequestsWrite,
    /// Issue write access.
    IssuesWrite,
    /// Actions read access.
    ActionsRead,
    /// Checks read/write access.
    ChecksWrite,
    /// Commit statuses read/write access when checks alone are insufficient.
    CommitStatusesWrite,
}

impl GitHubPermission {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::MetadataRead => "Metadata: read",
            Self::ContentsRead => "Contents: read",
            Self::ContentsWrite => "Contents: write",
            Self::PullRequestsRead => "Pull requests: read",
            Self::PullRequestsWrite => "Pull requests: write",
            Self::IssuesWrite => "Issues: write",
            Self::ActionsRead => "Actions: read",
            Self::ChecksWrite => "Checks: write",
            Self::CommitStatusesWrite => "Commit statuses: write",
        }
    }
}

/// Whether GitHub grants access to all or selected repositories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositorySelection {
    /// All current and future repositories for the account.
    All,
    /// Only the reported number of explicitly selected repositories.
    Selected(u64),
}

impl RepositorySelection {
    pub(super) fn label(self) -> String {
        match self {
            Self::All => "All repositories".to_owned(),
            Self::Selected(count) => format!("{count} selected"),
        }
    }
}

/// Display-safe installation summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubInstallationView {
    /// GitHub's numeric installation identifier.
    pub installation_id: u64,
    /// Public GitHub account login.
    pub account_login: String,
    /// Account kind.
    pub account_kind: GitHubAccountKind,
    /// Current lifecycle state.
    pub state: GitHubInstallationState,
    /// Repository selection reported by GitHub.
    pub repository_selection: RepositorySelection,
    /// Granted non-secret permission names.
    pub permissions: Vec<GitHubPermission>,
}

/// Visibility of a linked GitHub repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryVisibility {
    /// Public repository.
    Public,
    /// Private repository.
    Private,
    /// Internal enterprise repository.
    Internal,
}

impl RepositoryVisibility {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Private => "Private",
            Self::Internal => "Internal",
        }
    }
}

/// Authorization and reconciliation state of a tenant repository link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryLinkState {
    /// Exact tenant, installation, repository, and permission bindings are ready.
    Ready,
    /// Link exists but no authenticated event has been observed yet.
    AwaitingEvent,
    /// Repository is no longer selected by the installation.
    SelectionRequired,
    /// Required permissions are missing.
    PermissionMismatch,
    /// Installation is suspended or removed; access is denied.
    Blocked,
}

impl RepositoryLinkState {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::AwaitingEvent => "Awaiting event",
            Self::SelectionRequired => "Needs selection",
            Self::PermissionMismatch => "Permissions changed",
            Self::Blocked => "Blocked",
        }
    }
}

/// Display-safe tenant repository link summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubRepositoryLinkView {
    /// GitHub's numeric repository identifier.
    pub repository_id: u64,
    /// Durable control-plane repository identifier, once explicitly linked.
    pub control_plane_id: Option<String>,
    /// Public owner login.
    pub owner: String,
    /// Public repository name.
    pub name: String,
    /// Exact configured GitHub web origin for this repository.
    pub web_origin: String,
    /// GitHub visibility.
    pub visibility: RepositoryVisibility,
    /// Public installation account login.
    pub installation_account: String,
    /// Default branch reported by the authenticated provider response.
    pub default_branch: String,
    /// Exact durable link state.
    pub state: RepositoryLinkState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubRepositoryCandidateAction {
    pub installation_id: String,
    pub external_repository_id: String,
    pub owner: String,
    pub name: String,
    pub visibility: RepositoryVisibility,
    pub default_branch: String,
    pub csrf_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubRepositoryEventView {
    pub delivery_id: String,
    pub repository: String,
    pub provider_event_name: String,
    pub event_kind: String,
    pub actor_login: String,
    pub ref_name: Option<String>,
    pub received_at: String,
}

/// Fixed, redaction-safe message shown at the top of the page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubUiAlert {
    /// An installation callback was accepted and queued for reconciliation.
    InstallationQueued,
    /// A repository link was created or refreshed.
    RepositoryLinked,
    /// Operator application configuration is incomplete.
    ConfigurationIncomplete,
    /// GitHub granted fewer permissions than Runtrue requires.
    PermissionMismatch,
    /// GitHub is unavailable and reconciliation will retry.
    ProviderUnavailable,
    /// A callback failed its state, identity, or ownership checks.
    CallbackRejected,
}

impl GitHubUiAlert {
    pub(super) fn content(self) -> (&'static str, &'static str, StatusTone) {
        match self {
            Self::InstallationQueued => (
                "Installation received",
                "Runtrue will show repositories after the authenticated installation reconciliation completes.",
                StatusTone::Good,
            ),
            Self::RepositoryLinked => (
                "Repository linked",
                "The repository is bound to this tenant and will accept only events from its exact installation.",
                StatusTone::Good,
            ),
            Self::ConfigurationIncomplete => (
                "Operator configuration required",
                "The GitHub App identity, signer, webhook, and setup callback must all be ready before installation.",
                StatusTone::Warn,
            ),
            Self::PermissionMismatch => (
                "Permission review required",
                "The installation no longer grants every permission required for configured Runtrue features.",
                StatusTone::Bad,
            ),
            Self::ProviderUnavailable => (
                "GitHub is temporarily unavailable",
                "Existing access remains fail-closed and the bounded reconciliation worker will retry.",
                StatusTone::Warn,
            ),
            Self::CallbackRejected => (
                "Installation callback rejected",
                "No tenant or repository link was changed because the callback binding could not be verified.",
                StatusTone::Bad,
            ),
        }
    }
}

/// Complete, display-only model for the GitHub App administration page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubInstallationsPage {
    /// Tenant name from the authenticated request snapshot.
    pub tenant_name: String,
    /// Current principal's display name.
    pub principal_name: String,
    /// Browser-session CSRF proof used only by fixed local form actions.
    pub session_csrf_token: String,
    /// Non-secret provider configuration health.
    pub app: GitHubAppHealth,
    /// Tenant-filtered installation summaries.
    pub installations: Vec<GitHubInstallationView>,
    /// Tenant-filtered repository links.
    pub repositories: Vec<GitHubRepositoryLinkView>,
    /// Provider-selected repositories awaiting explicit tenant onboarding.
    pub repository_candidates: Vec<GitHubRepositoryCandidateAction>,
    /// Recent verified webhook receipts for linked repositories.
    pub events: Vec<GitHubRepositoryEventView>,
    /// Optional fixed message selected by the application service.
    pub alert: Option<GitHubUiAlert>,
    /// Authorized local mutation binding; absent when installation is forbidden.
    pub install_action: Option<GitHubInstallAction>,
}

#[derive(Clone, Copy)]
pub(super) enum StatusTone {
    Good,
    Warn,
    Bad,
}
