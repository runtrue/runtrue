use crate::{EntryKind, LockFile};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockChangeKind {
    Added,
    Removed,
    ResolutionChanged,
    MetadataChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockChange {
    pub kind: EntryKind,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub change: LockChangeKind,
    pub security_sensitive: bool,
}

impl LockChange {
    fn new(key: ChangeKey, change: LockChangeKind) -> Self {
        Self {
            kind: key.kind,
            source: key.source,
            platform: key.platform,
            change,
            security_sensitive: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ChangeKey {
    kind: EntryKind,
    source: String,
    platform: Option<String>,
}

impl ChangeKey {
    fn new(kind: EntryKind, source: &str, platform: Option<&str>) -> Self {
        Self {
            kind,
            source: source.to_owned(),
            platform: platform.map(str::to_owned),
        }
    }
}

struct ChangeRecord {
    resolution: String,
    metadata: String,
}

impl LockFile {
    /// Return deterministic changes between two validated lockfiles. Every
    /// returned change is security-sensitive and must invalidate approval.
    #[must_use]
    pub fn security_changes(&self, proposed: &Self) -> Vec<LockChange> {
        let base = self.change_records();
        let next = proposed.change_records();
        let keys = base
            .keys()
            .chain(next.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        keys.into_iter()
            .filter_map(|key| match (base.get(&key), next.get(&key)) {
                (None, Some(_)) => Some(LockChange::new(key, LockChangeKind::Added)),
                (Some(_), None) => Some(LockChange::new(key, LockChangeKind::Removed)),
                (Some(previous), Some(current)) if previous.resolution != current.resolution => {
                    Some(LockChange::new(key, LockChangeKind::ResolutionChanged))
                }
                (Some(previous), Some(current)) if previous.metadata != current.metadata => {
                    Some(LockChange::new(key, LockChangeKind::MetadataChanged))
                }
                _ => None,
            })
            .collect()
    }

    fn change_records(&self) -> BTreeMap<ChangeKey, ChangeRecord> {
        let mut records = BTreeMap::new();
        for entry in &self.components {
            records.insert(
                ChangeKey::new(EntryKind::Component, &entry.source, None),
                ChangeRecord {
                    resolution: entry.resolved.to_string(),
                    metadata: format!("{}\0{}", entry.signature_identity, entry.wit_world),
                },
            );
        }
        for entry in &self.images {
            records.insert(
                ChangeKey::new(EntryKind::Image, &entry.source, Some(&entry.platform)),
                ChangeRecord {
                    resolution: entry.resolved.clone(),
                    metadata: entry.platform.clone(),
                },
            );
        }
        for entry in &self.workflows {
            records.insert(
                ChangeKey::new(EntryKind::Workflow, &entry.source, None),
                ChangeRecord {
                    resolution: format!("{}\0{}", entry.commit, entry.digest),
                    metadata: String::new(),
                },
            );
        }
        records
    }
}
