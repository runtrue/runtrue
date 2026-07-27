//! Authenticated HTTP façade for the durable Runtrue control plane.

extern crate self as runtrue_server;

mod app;
mod database_runtime;
mod database_url_file;
mod github_install_ui;
mod human_oidc;
mod runner_broker;
mod runner_certificates;
mod runner_service;
mod scm_worker;
mod secret_resolution;
#[doc(hidden)]
pub mod startup;
mod workflow_frontends;

use axum::Router;

pub use app::{
    router, AppState, BootstrapAuth, GitHubInstallationMetricsSnapshot, GitHubLifecycleWorkerError,
    GitHubOauthQuickstartConfig, ServerBuildError,
};
pub use database_runtime::{
    postgres_server_runtime_inventory, postgres_server_runtime_ready, PostgresServerRuntimeGap,
};
pub use database_url_file::{read_database_url_file, DatabaseUrlFileError, MAX_DATABASE_URL_BYTES};
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
pub use workflow_frontends::WorkflowFrontendComposition;

/// Provider-neutral assembly points for a product-owned server executable.
///
/// The normal `runtrue-server` uses [`ServerComposition::core`]. An external
/// distribution can statically register workflow frontends and add same-origin
/// HTTP routes while reusing the exact core backend and worker lifecycle.
#[derive(Clone)]
pub struct ServerComposition {
    workflow_frontends: WorkflowFrontendComposition,
    decorate_http_router: fn(Router) -> Router,
}

impl std::fmt::Debug for ServerComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerComposition")
            .field("workflow_frontends", &self.workflow_frontends)
            .field("decorate_http_router", &"[STATIC ROUTER DECORATOR]")
            .finish()
    }
}

impl ServerComposition {
    /// The dependency-free core server composition.
    #[must_use]
    pub fn core() -> Self {
        Self {
            workflow_frontends: WorkflowFrontendComposition::core(),
            decorate_http_router: std::convert::identity,
        }
    }

    /// Select the product-owned workflow frontend registry and bounded options.
    #[must_use]
    pub fn with_workflow_frontends(
        mut self,
        workflow_frontends: WorkflowFrontendComposition,
    ) -> Self {
        self.workflow_frontends = workflow_frontends;
        self
    }

    /// Add product-owned same-origin routes around the core router.
    #[must_use]
    pub fn with_http_router_decorator(mut self, decorator: fn(Router) -> Router) -> Self {
        self.decorate_http_router = decorator;
        self
    }

    #[doc(hidden)]
    #[must_use]
    pub fn workflow_frontends(&self) -> WorkflowFrontendComposition {
        self.workflow_frontends.clone()
    }

    #[doc(hidden)]
    pub fn decorate_http_router(&self, router: Router) -> Router {
        (self.decorate_http_router)(router)
    }
}
pub use scm_worker::{
    FetchedScmRepository, GitHubAppInstallationTokenProvider, GitHubCheckPublisher,
    GitHubInstallationTokenProvider, GitHubMirrorSourceFetcher, GitHubRepositoryAccessToken,
    MirrorPathError, PreparedRepositoryAction, PublishedScmCheck, RepositoryActionResolveError,
    RepositoryActionResolver, ScmCheckPublishError, ScmSourceFetchError, ScmSourceFetchRequest,
    ScmSourceFetcher, ScmTaskWorker, ScmWorkerBuildError, ScmWorkerConfig, ScmWorkerError,
    ScmWorkerMetricsSnapshot, ScmWorkerTick, DEFAULT_SCM_WORKFLOW_DIRECTORY,
};

#[cfg(test)]
mod composition_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt as _;

    fn product_routes(router: Router) -> Router {
        router.route("/product-healthz", get(|| async { StatusCode::NO_CONTENT }))
    }

    #[tokio::test]
    async fn external_composition_can_add_routes_without_changing_core() {
        let core = ServerComposition::core();
        let product = ServerComposition::core().with_http_router_decorator(product_routes);

        let core_response = core
            .decorate_http_router(Router::new())
            .oneshot(
                Request::get("/product-healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let product_response = product
            .decorate_http_router(Router::new())
            .oneshot(
                Request::get("/product-healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(core_response.status(), StatusCode::NOT_FOUND);
        assert_eq!(product_response.status(), StatusCode::NO_CONTENT);
        assert!(core
            .workflow_frontends()
            .registry()
            .discovery_roots()
            .is_empty());
    }
}
