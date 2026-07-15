use crate::validation::{validate_platform, validate_source};
use crate::{EntryKind, LockError};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockRequirements {
    pub(crate) components: BTreeSet<String>,
    pub(crate) images: BTreeSet<ImageRequirement>,
    pub(crate) workflows: BTreeSet<String>,
}

impl LockRequirements {
    pub fn require_component(&mut self, source: impl Into<String>) {
        self.components.insert(source.into());
    }

    pub fn require_image(&mut self, source: impl Into<String>, platform: impl Into<String>) {
        self.images.insert(ImageRequirement {
            source: source.into(),
            platform: platform.into(),
        });
    }

    pub fn require_workflow(&mut self, source: impl Into<String>) {
        self.workflows.insert(source.into());
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty() && self.images.is_empty() && self.workflows.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<(), LockError> {
        for source in &self.components {
            validate_source(EntryKind::Component, source)?;
        }
        for image in &self.images {
            validate_source(EntryKind::Image, &image.source)?;
            validate_platform(&image.platform)?;
        }
        for source in &self.workflows {
            validate_source(EntryKind::Workflow, source)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRequirement {
    pub source: String,
    pub platform: String,
}
