//! Authenticated HTTP façade for the durable Runtrue control plane.

mod app;
mod github_install_ui;
mod human_oidc;
mod runner_broker;
mod runner_certificates;
mod runner_service;
mod scm_worker;

pub use app::{
    router, AppState, BootstrapAuth, GitHubInstallationMetricsSnapshot, GitHubLifecycleWorkerError,
    GitHubOauthQuickstartConfig, ServerBuildError,
};
pub use github_install_ui::{
    github_installations_payload, ComponentHealth, GitHubAccountKind, GitHubAppHealth,
    GitHubInstallAction, GitHubInstallationState, GitHubInstallationView, GitHubInstallationsPage,
    GitHubPermission, GitHubRepositoryCandidateAction, GitHubRepositoryEventView,
    GitHubRepositoryLinkView, GitHubUiAlert, RepositoryLinkState, RepositorySelection,
    RepositoryVisibility, GITHUB_BROWSER_API_CACHE_CONTROL,
};
pub use human_oidc::{
    GitHubAccessToken, GitHubOauthAdapter, GitHubUserCatalog, GitHubUserRepository,
    HardenedGitHubOauthClient, HardenedHumanOidcClient, HumanAuthMetricsSnapshot, HumanOidcAdapter,
    HumanOidcError, HumanOidcLimits, VerifiedGitHubIdentity, VerifiedHumanIdentity,
};
pub use runner_certificates::{
    IssuedRunnerCertificate, RunnerCertificateAuthority, RunnerCertificateError,
    DEFAULT_RUNNER_CERTIFICATE_LIFETIME, DEFAULT_RUNNER_CERTIFICATE_OVERLAP,
    DEFAULT_RUNNER_ROTATION_NOTICE, MAX_RUNNER_CSR_BYTES,
};
pub use runner_service::{
    RunnerControlConfig, RunnerControlService, RunnerEnrollmentService,
    RunnerProtocolMetricsSnapshot, RunnerServiceError,
};
pub use scm_worker::{
    FetchedScmRepository, GitHubAppInstallationTokenProvider, GitHubCheckPublisher,
    GitHubInstallationTokenProvider, GitHubMirrorSourceFetcher, GitHubRepositoryAccessToken,
    MirrorPathError, PublishedScmCheck, ScmCheckPublishError, ScmSourceFetchError,
    ScmSourceFetchRequest, ScmSourceFetcher, ScmTaskWorker, ScmWorkerBuildError, ScmWorkerConfig,
    ScmWorkerError, ScmWorkerMetricsSnapshot, ScmWorkerTick, DEFAULT_SCM_WORKFLOW_DIRECTORY,
};
