use crate::{EntryKind, ImageRequirement, LockError, LockFile, LockRequirements};
use runtrue_model::ContentDigest;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedWorkflow {
    pub commit: String,
    pub digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedLock {
    digest: ContentDigest,
    components: BTreeMap<String, String>,
    images: BTreeMap<ImageRequirement, String>,
    workflows: BTreeMap<String, ResolvedWorkflow>,
}

impl ResolvedLock {
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    #[must_use]
    pub fn component(&self, source: &str) -> Option<&str> {
        self.components.get(source).map(String::as_str)
    }

    #[must_use]
    pub fn image(&self, source: &str, platform: &str) -> Option<&str> {
        self.images
            .get(&ImageRequirement {
                source: source.to_owned(),
                platform: platform.to_owned(),
            })
            .map(String::as_str)
    }

    #[must_use]
    pub fn workflow(&self, source: &str) -> Option<&ResolvedWorkflow> {
        self.workflows.get(source)
    }
}

impl LockFile {
    /// Resolve every requested external reference and reject every unused lock
    /// entry. This makes stale lock content an admission error, not a warning.
    pub fn resolve(&self, requirements: &LockRequirements) -> Result<ResolvedLock, LockError> {
        requirements.validate()?;
        let component_entries = self
            .components
            .iter()
            .map(|entry| (entry.source.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let image_entries = self
            .images
            .iter()
            .map(|entry| {
                (
                    ImageRequirement {
                        source: entry.source.clone(),
                        platform: entry.platform.clone(),
                    },
                    entry,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let workflow_entries = self
            .workflows
            .iter()
            .map(|entry| (entry.source.as_str(), entry))
            .collect::<BTreeMap<_, _>>();

        let mut components = BTreeMap::new();
        for source in &requirements.components {
            let entry =
                component_entries
                    .get(source.as_str())
                    .ok_or_else(|| LockError::MissingEntry {
                        kind: EntryKind::Component,
                        logical_source: source.clone(),
                    })?;
            components.insert(source.clone(), entry.immutable_reference()?);
        }
        let mut images = BTreeMap::new();
        for requirement in &requirements.images {
            let entry =
                image_entries
                    .get(requirement)
                    .ok_or_else(|| LockError::MissingImageEntry {
                        logical_source: requirement.source.clone(),
                        platform: requirement.platform.clone(),
                    })?;
            images.insert(requirement.clone(), entry.resolved.clone());
        }
        let mut workflows = BTreeMap::new();
        for source in &requirements.workflows {
            let entry =
                workflow_entries
                    .get(source.as_str())
                    .ok_or_else(|| LockError::MissingEntry {
                        kind: EntryKind::Workflow,
                        logical_source: source.clone(),
                    })?;
            workflows.insert(
                source.clone(),
                ResolvedWorkflow {
                    commit: entry.commit.clone(),
                    digest: entry.digest.clone(),
                },
            );
        }

        if let Some(entry) = self
            .components
            .iter()
            .find(|entry| !requirements.components.contains(&entry.source))
        {
            return Err(LockError::UnusedEntry {
                kind: EntryKind::Component,
                logical_source: entry.source.clone(),
            });
        }
        if let Some(entry) = self.images.iter().find(|entry| {
            !requirements.images.contains(&ImageRequirement {
                source: entry.source.clone(),
                platform: entry.platform.clone(),
            })
        }) {
            return Err(LockError::UnusedImageEntry {
                logical_source: entry.source.clone(),
                platform: entry.platform.clone(),
            });
        }
        if let Some(entry) = self
            .workflows
            .iter()
            .find(|entry| !requirements.workflows.contains(&entry.source))
        {
            return Err(LockError::UnusedEntry {
                kind: EntryKind::Workflow,
                logical_source: entry.source.clone(),
            });
        }

        Ok(ResolvedLock {
            digest: self.digest()?,
            components,
            images,
            workflows,
        })
    }
}

impl crate::ComponentEntry {
    pub(crate) fn immutable_reference(&self) -> Result<String, LockError> {
        let base = self
            .source
            .rsplit_once('@')
            .map_or(self.source.as_str(), |(base, _)| base);
        if base.is_empty() {
            return Err(LockError::InvalidField {
                path: "component.source".to_owned(),
                reason: "source must contain a non-empty component locator".to_owned(),
            });
        }
        Ok(format!("{base}@{}", self.resolved))
    }
}
