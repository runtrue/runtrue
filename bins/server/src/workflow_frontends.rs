//! Workflow source frontend composition for the server binary.
//!
//! The SCM worker consumes only the neutral registry. Feature-selected adapter
//! implementations are assembled here so discovery and planning share one
//! validated composition root.

#[cfg(feature = "github-actions")]
use runtrue_gha_import::{GithubActionsFrontend, DEFAULT_JOB_CONTAINER_IMAGE_OPTION};
use runtrue_workflow_frontend::{
    WorkflowFrontendOptions, WorkflowFrontendOptionsError, WorkflowFrontendRegistry,
    WorkflowSourceFrontend,
};
use std::sync::OnceLock;

#[cfg(feature = "github-actions")]
static GITHUB_ACTIONS_FRONTEND: GithubActionsFrontend = GithubActionsFrontend;

#[cfg(feature = "github-actions")]
static REGISTERED_WORKFLOW_FRONTENDS: [&'static dyn WorkflowSourceFrontend; 1] =
    [&GITHUB_ACTIONS_FRONTEND];

#[cfg(not(feature = "github-actions"))]
static REGISTERED_WORKFLOW_FRONTENDS: [&'static dyn WorkflowSourceFrontend; 0] = [];

/// Return the validated, feature-selected frontend registry used by every
/// server workflow discovery and planning path.
pub(crate) fn registry() -> &'static WorkflowFrontendRegistry<'static> {
    static REGISTRY: OnceLock<WorkflowFrontendRegistry<'static>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        WorkflowFrontendRegistry::new(&REGISTERED_WORKFLOW_FRONTENDS)
            .expect("compiled workflow frontend registry must be valid")
    })
}

/// Build the bounded adapter option set selected by the server composition.
/// Adapter-specific keys remain here rather than leaking into the planner.
pub(crate) fn options(
    default_job_container_image: Option<&str>,
) -> Result<WorkflowFrontendOptions, WorkflowFrontendOptionsError> {
    let options = WorkflowFrontendOptions::default();
    #[cfg(feature = "github-actions")]
    let mut options = options;
    #[cfg(feature = "github-actions")]
    if let Some(image) = default_job_container_image {
        options.set(DEFAULT_JOB_CONTAINER_IMAGE_OPTION, image)?;
    }
    #[cfg(not(feature = "github-actions"))]
    let _ = default_job_container_image;
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "github-actions")]
    #[test]
    fn default_composition_registers_github_actions() {
        let registry = registry();

        assert_eq!(registry.discovery_roots(), &[".github/workflows"]);
        assert!(registry
            .frontend_for(".github/workflows/ci.yml")
            .unwrap()
            .is_some());
    }

    #[cfg(feature = "github-actions")]
    #[test]
    fn default_composition_binds_github_actions_options() {
        let options = options(Some("registry.example/runtrue/job@sha256:abc")).unwrap();

        assert_eq!(
            options.value(DEFAULT_JOB_CONTAINER_IMAGE_OPTION),
            Some("registry.example/runtrue/job@sha256:abc")
        );
    }

    #[cfg(not(feature = "github-actions"))]
    #[test]
    fn native_only_composition_has_no_external_frontends() {
        let registry = registry();

        assert!(registry.discovery_roots().is_empty());
        assert!(registry
            .frontend_for(".github/workflows/ci.yml")
            .unwrap()
            .is_none());
    }

    #[cfg(not(feature = "github-actions"))]
    #[test]
    fn native_only_composition_ignores_external_adapter_options() {
        assert_eq!(
            options(Some("registry.example/runtrue/job@sha256:abc")).unwrap(),
            WorkflowFrontendOptions::default()
        );
    }
}
