use crate::{validation, ContentDigest, ExecutionModelError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_RESOURCE_BYTES: u64 = 1 << 60;
const MAX_DURATION_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRequirement {
    pub class: String,
    pub compatibility_digest: ContentDigest,
    pub count: u32,
}

impl DeviceRequirement {
    fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::identifier("device class", &self.class)?;
        if self.count == 0 {
            return Err(ExecutionModelError::InvalidField {
                field: "device count",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementConstraints {
    pub allowed_provider_ids: BTreeSet<String>,
    pub allowed_pool_trust_profiles: BTreeSet<ContentDigest>,
    pub administrative_trust_domains: BTreeSet<String>,
    pub allowed_regions: BTreeSet<String>,
    pub allowed_localities: BTreeSet<String>,
    pub data_residency: BTreeSet<String>,
    pub required_devices: BTreeMap<String, DeviceRequirement>,
}

impl PlacementConstraints {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::identifiers(
            "allowed Provider identities",
            &self.allowed_provider_ids,
            true,
        )?;
        validation::identifiers(
            "administrative trust domains",
            &self.administrative_trust_domains,
            true,
        )?;
        validation::identifiers("allowed regions", &self.allowed_regions, false)?;
        validation::identifiers("allowed localities", &self.allowed_localities, false)?;
        validation::identifiers("data residency", &self.data_residency, false)?;
        validation::bounded(
            "pool trust profiles",
            self.allowed_pool_trust_profiles.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        if self.allowed_pool_trust_profiles.is_empty() {
            return Err(ExecutionModelError::InvalidField {
                field: "pool trust profiles",
                reason: "must contain at least one exact trust profile",
            });
        }
        validation::bounded(
            "device requirements",
            self.required_devices.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        for (identity, device) in &self.required_devices {
            validation::identifier("device requirement identity", identity)?;
            device.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, child: &Self) -> bool {
        set_contains(&self.allowed_provider_ids, &child.allowed_provider_ids)
            && set_contains(
                &self.allowed_pool_trust_profiles,
                &child.allowed_pool_trust_profiles,
            )
            && set_contains(
                &self.administrative_trust_domains,
                &child.administrative_trust_domains,
            )
            && set_contains(&self.allowed_regions, &child.allowed_regions)
            && set_contains(&self.allowed_localities, &child.allowed_localities)
            && set_contains(&self.data_residency, &child.data_residency)
            && self.required_devices == child.required_devices
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    pub task_count: u32,
    pub process_count: u32,
    pub network_egress_bytes: u64,
    pub maximum_duration_ms: u64,
}

impl ResourceLimits {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        if self.cpu_millis == 0
            || self.memory_bytes == 0
            || self.storage_bytes == 0
            || self.task_count == 0
            || self.process_count == 0
            || self.memory_bytes > MAX_RESOURCE_BYTES
            || self.storage_bytes > MAX_RESOURCE_BYTES
            || self.network_egress_bytes > MAX_RESOURCE_BYTES
            || self.maximum_duration_ms == 0
            || self.maximum_duration_ms > MAX_DURATION_MS
        {
            return Err(ExecutionModelError::InvalidField {
                field: "resource limits",
                reason: "must be positive and within canonical bounds",
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn contains(&self, child: &Self) -> bool {
        child.cpu_millis <= self.cpu_millis
            && child.memory_bytes <= self.memory_bytes
            && child.storage_bytes <= self.storage_bytes
            && child.task_count <= self.task_count
            && child.process_count <= self.process_count
            && child.network_egress_bytes <= self.network_egress_bytes
            && child.maximum_duration_ms <= self.maximum_duration_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    pub class: String,
    pub resource: String,
    pub operations: BTreeSet<String>,
    pub destinations: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_effect_class: Option<String>,
    pub budget: CapabilityBudget,
    pub constraints_digest: ContentDigest,
}

impl CapabilityGrant {
    fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::identifier("capability class", &self.class)?;
        validation::text("capability resource", &self.resource)?;
        validation::identifiers("capability operations", &self.operations, true)?;
        validation::identifiers("capability destinations", &self.destinations, false)?;
        if let Some(effect_class) = &self.external_effect_class {
            validation::identifier("external-effect class", effect_class)?;
        }
        self.budget.validate()
    }

    #[must_use]
    fn contains(&self, child: &Self) -> bool {
        self.class == child.class
            && self.resource == child.resource
            && child.operations.is_subset(&self.operations)
            && set_contains(&self.destinations, &child.destinations)
            && self.external_effect_class == child.external_effect_class
            && self.budget.contains(&child.budget)
            && self.constraints_digest == child.constraints_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBudget {
    pub maximum_calls: u64,
    pub maximum_request_bytes: u64,
    pub maximum_response_bytes: u64,
    pub maximum_external_effects: u64,
}

impl CapabilityBudget {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        if self.maximum_calls > MAX_RESOURCE_BYTES
            || self.maximum_request_bytes > MAX_RESOURCE_BYTES
            || self.maximum_response_bytes > MAX_RESOURCE_BYTES
            || self.maximum_external_effects > MAX_RESOURCE_BYTES
        {
            return Err(ExecutionModelError::InvalidField {
                field: "capability budget",
                reason: "exceeds canonical bound",
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn contains(&self, child: &Self) -> bool {
        child.maximum_calls <= self.maximum_calls
            && child.maximum_request_bytes <= self.maximum_request_bytes
            && child.maximum_response_bytes <= self.maximum_response_bytes
            && child.maximum_external_effects <= self.maximum_external_effects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityContract {
    pub grants: BTreeMap<String, CapabilityGrant>,
    pub aggregate_budget: CapabilityBudget,
}

impl CapabilityContract {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::bounded(
            "capability grants",
            self.grants.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        for (identity, grant) in &self.grants {
            validation::identifier("capability identity", identity)?;
            grant.validate()?;
        }
        self.aggregate_budget.validate()
    }

    #[must_use]
    pub fn classes(&self) -> BTreeSet<String> {
        self.grants
            .values()
            .map(|grant| grant.class.clone())
            .collect()
    }

    #[must_use]
    pub fn contains(&self, child: &Self) -> bool {
        self.aggregate_budget.contains(&child.aggregate_budget)
            && child.grants.iter().all(|(identity, child_grant)| {
                self.grants
                    .get(identity)
                    .is_some_and(|parent_grant| parent_grant.contains(child_grant))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputContract {
    pub stdout_max_bytes: u64,
    pub stderr_max_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_output_schema: Option<ContentDigest>,
    pub artifact_classes: BTreeSet<String>,
    pub filesystem_change_roots: BTreeSet<String>,
}

impl OutputContract {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        if self.stdout_max_bytes > MAX_RESOURCE_BYTES || self.stderr_max_bytes > MAX_RESOURCE_BYTES
        {
            return Err(ExecutionModelError::InvalidField {
                field: "output byte limit",
                reason: "exceeds canonical bound",
            });
        }
        validation::identifiers("artifact classes", &self.artifact_classes, false)?;
        validation::bounded(
            "filesystem change roots",
            self.filesystem_change_roots.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        for root in &self.filesystem_change_roots {
            validation::relative_path("filesystem change root", root)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, child: &Self) -> bool {
        child.stdout_max_bytes <= self.stdout_max_bytes
            && child.stderr_max_bytes <= self.stderr_max_bytes
            && child
                .structured_output_schema
                .as_ref()
                .is_none_or(|schema| self.structured_output_schema.as_ref() == Some(schema))
            && child.artifact_classes.is_subset(&self.artifact_classes)
            && child.filesystem_change_roots.iter().all(|child_root| {
                self.filesystem_change_roots.iter().any(|parent_root| {
                    child_root == parent_root
                        || child_root
                            .strip_prefix(parent_root)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceProfile {
    Baseline,
    Enhanced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceContract {
    pub profile: EvidenceProfile,
    pub maximum_events: u64,
    pub maximum_log_bytes: u64,
    pub retention_ms: u64,
}

impl EvidenceContract {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        if self.maximum_events == 0
            || self.maximum_log_bytes > MAX_RESOURCE_BYTES
            || self.retention_ms == 0
            || self.retention_ms > MAX_DURATION_MS
        {
            return Err(ExecutionModelError::InvalidField {
                field: "Evidence contract",
                reason: "must be positive and within canonical bounds",
            });
        }
        Ok(())
    }
}

fn set_contains<T: Ord>(parent: &BTreeSet<T>, child: &BTreeSet<T>) -> bool {
    child.is_subset(parent)
}
