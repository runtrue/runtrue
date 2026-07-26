//! Workflow source frontend composition for the server binary.
//!
//! The SCM worker consumes only the neutral registry. Core does not select or
//! link a concrete external workflow frontend.

#[cfg(test)]
use runtrue_workflow_frontend::WorkflowFrontendOptionsError;
use runtrue_workflow_frontend::{
    WorkflowFrontendOptions, WorkflowFrontendRegistry, WorkflowSourceFrontend,
};
use std::sync::OnceLock;

/// Provider-neutral workflow frontend composition supplied by an assembled
/// server distribution.
///
/// Core's default remains empty. Product-owned binaries may statically link
/// adapters and pass their validated registry and bounded options through this
/// value without making `runtrue-server` depend on those adapters.
#[derive(Clone)]
pub struct WorkflowFrontendComposition {
    registry: &'static WorkflowFrontendRegistry<'static>,
    options: WorkflowFrontendOptions,
}

impl std::fmt::Debug for WorkflowFrontendComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkflowFrontendComposition")
            .field("discovery_roots", &self.registry.discovery_roots())
            .field("options", &self.options)
            .finish()
    }
}

impl WorkflowFrontendComposition {
    /// Build a product composition from a statically owned validated registry.
    #[must_use]
    pub fn new(
        registry: &'static WorkflowFrontendRegistry<'static>,
        options: WorkflowFrontendOptions,
    ) -> Self {
        Self { registry, options }
    }

    /// Core's provider-neutral composition.
    #[must_use]
    pub fn core() -> Self {
        Self::new(registry(), WorkflowFrontendOptions::default())
    }

    #[must_use]
    pub(crate) const fn registry(&self) -> &'static WorkflowFrontendRegistry<'static> {
        self.registry
    }

    #[must_use]
    pub(crate) fn options(&self) -> WorkflowFrontendOptions {
        self.options.clone()
    }
}

static REGISTERED_WORKFLOW_FRONTENDS: [&'static dyn WorkflowSourceFrontend; 0] = [];

/// Return the empty external-frontend registry used by core.
pub(crate) fn registry() -> &'static WorkflowFrontendRegistry<'static> {
    static REGISTRY: OnceLock<WorkflowFrontendRegistry<'static>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        WorkflowFrontendRegistry::new(&REGISTERED_WORKFLOW_FRONTENDS)
            .expect("compiled workflow frontend registry must be valid")
    })
}

/// Build the bounded adapter option set selected by the server composition.
#[cfg(test)]
pub(crate) fn options(
    default_job_container_image: Option<&str>,
) -> Result<WorkflowFrontendOptions, WorkflowFrontendOptionsError> {
    let options = WorkflowFrontendOptions::default();
    let _ = default_job_container_image;
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_composition_has_no_external_frontends() {
        let registry = registry();

        assert!(registry.discovery_roots().is_empty());
        assert!(registry
            .frontend_for(".github/workflows/ci.yml")
            .unwrap()
            .is_none());
    }

    #[test]
    fn core_composition_ignores_external_adapter_options() {
        assert_eq!(
            options(Some("registry.example/runtrue/job@sha256:abc")).unwrap(),
            WorkflowFrontendOptions::default()
        );
    }
}
