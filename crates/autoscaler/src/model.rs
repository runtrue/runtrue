use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalingPolicy {
    pub pool_id: String,
    #[serde(default)]
    pub baseline_runtime_compatibility_digest: String,
    pub minimum_workers: u32,
    pub minimum_idle_workers: u32,
    pub maximum_workers: u32,
    pub scale_up_batch: u32,
    pub idle_timeout_ms: u64,
    pub offline_grace_ms: u64,
    pub cooldown_ms: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemandGroup {
    pub runtime_compatibility_digest: String,
    pub queued_jobs: u64,
    pub active_slots: u64,
    pub available_slots: u64,
    pub pending_slots: u64,
    pub slots_per_worker: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolTemplate {
    pub runtime_compatibility_digest: String,
    pub provider: String,
    pub provider_template_id: String,
    pub runner_template_digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRequest {
    pub id: String,
    pub pool_id: String,
    pub runtime_compatibility_digest: String,
    pub provider: String,
    pub provider_template_id: String,
    pub runner_template_digest: String,
    pub state: String,
    #[serde(default)]
    pub provider_instance_id: String,
    #[serde(default)]
    pub runner_id: String,
    #[serde(default)]
    pub runner_active_jobs: u32,
    #[serde(default)]
    pub runner_last_heartbeat_unix_ms: u64,
    #[serde(default, deserialize_with = "null_string")]
    pub runner_status: String,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetView {
    pub policy: ScalingPolicy,
    pub demand: Vec<DemandGroup>,
    pub templates: Vec<PoolTemplate>,
    pub requests: Vec<FleetRequest>,
    #[serde(default)]
    pub replacements: Vec<Replacement>,
    pub online_workers: u64,
    pub draining_workers: u64,
    pub observed_unix_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replacement {
    pub id: String,
    pub pool_id: String,
    #[serde(default)]
    pub target_fleet_request_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedReplacement {
    pub replacement: Replacement,
    pub fleet_request: FleetRequest,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipLease {
    pub pool_id: String,
    pub owner_id: String,
    pub fencing_generation: u64,
    pub expires_unix_ms: u64,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchClaim {
    pub version: u32,
    pub enrollment_token: String,
    pub provider: String,
    pub provider_instance_id: String,
    pub evidence_hex: String,
    pub endorsement_hex: String,
    pub nonce_digest: String,
}

impl std::fmt::Debug for LaunchClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchClaim")
            .field("version", &self.version)
            .field("enrollment_token", &"[REDACTED]")
            .field("provider", &self.provider)
            .field("provider_instance_id", &self.provider_instance_id)
            .field("evidence_hex", &self.evidence_hex)
            .field("endorsement_hex", &self.endorsement_hex)
            .field("nonce_digest", &self.nonce_digest)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub provider: String,
    pub provider_instance_id: String,
    pub evidence: Vec<u8>,
    pub endorsement: Vec<u8>,
    pub nonce_digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreparedInstance {
    pub provider_request_id: String,
    pub claim_directory: PathBuf,
    pub state_directory: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderInstance {
    pub id: String,
    pub fleet_request_id: String,
    pub identity: ProviderIdentity,
}

fn null_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_view_accepts_the_richer_closed_server_contract() {
        let view: FleetView = serde_json::from_value(serde_json::json!({
            "policy": {
                "pool_id": "pool",
                "minimum_workers": 0,
                "minimum_idle_workers": 0,
                "maximum_workers": 2,
                "scale_up_batch": 1,
                "idle_timeout_ms": 1000,
                "offline_grace_ms": 1000,
                "cooldown_ms": 1000,
                "enabled": true,
                "updated_unix_ms": 1
            },
            "templates": [{
                "pool_id": "pool",
                "runtime_compatibility_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "provider": "docker",
                "provider_template_id": "template",
                "runner_template_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_unix_ms": 1,
                "updated_unix_ms": 1
            }],
            "requests": [{
                "id": "fleet-one",
                "pool_id": "pool",
                "runtime_compatibility_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "provider": "docker",
                "provider_template_id": "template",
                "runner_template_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "state": "requested",
                "created_unix_ms": 1,
                "updated_unix_ms": 1,
                "runner_active_jobs": 0,
                "runner_last_heartbeat_unix_ms": 0,
                "runner_status": null
            }],
            "replacements": [],
            "pool_id": "pool",
            "observed_unix_ms": 1,
            "demand": [{
                "runtime_compatibility_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "requirements": {"labels": []},
                "queued_jobs": 1,
                "active_slots": 0,
                "available_slots": 0,
                "pending_slots": 0,
                "slots_per_worker": 1
            }],
            "online_workers": 0,
            "draining_workers": 0,
            "offline_workers": 0,
            "quarantined_workers": 0
        }))
        .unwrap();
        assert_eq!(view.requests[0].runner_status, "");
        assert_eq!(view.demand[0].queued_jobs, 1);
    }
}
