use runtrue_model::ContentDigest;
pub use runtrue_update::RunnerComponentProfile;
use serde::{Deserialize, Serialize};

fn utc_window(value: &str) -> Option<(u64, u64)> {
    if value == "always" {
        return Some((0, 1_440));
    }
    let value = value.strip_suffix('Z')?;
    let (start, end) = value.split_once('-')?;
    fn minute(value: &str) -> Option<u64> {
        let (hour, minute) = value.split_once(':')?;
        let hour: u64 = hour.parse().ok()?;
        let minute: u64 = minute.parse().ok()?;
        (hour < 24 && minute < 60).then_some(hour * 60 + minute)
    }
    let range = (minute(start)?, minute(end)?);
    (range.0 != range.1).then_some(range)
}

pub(crate) fn valid_update_windows(windows: &[String]) -> bool {
    !windows.is_empty() && windows.iter().all(|value| utc_window(value).is_some())
}

pub(crate) fn update_window_allows(windows: &[String], now_unix_ms: u64) -> bool {
    let current = (now_unix_ms / 60_000) % 1_440;
    windows.iter().any(|value| {
        utc_window(value).is_some_and(|(start, end)| {
            end == 1_440
                || if start < end {
                    (start..end).contains(&current)
                } else {
                    current >= start || current < end
                }
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerUpdateRelease {
    pub id: String,
    pub channel: String,
    pub profile: RunnerComponentProfile,
    pub component_profile_digest: ContentDigest,
    pub update_root_digest: ContentDigest,
    pub targets_metadata_digest: ContentDigest,
    pub snapshot_metadata_digest: ContentDigest,
    pub timestamp_metadata_digest: ContentDigest,
    pub created_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRunnerUpdateReleaseRegistration {
    pub release: RunnerUpdateRelease,
    pub target_path: String,
    pub bundle: runtrue_update::ReleaseBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_trusted_state: Option<runtrue_update::TrustedState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerPoolUpdatePolicy {
    pub pool_id: String,
    pub version: u64,
    pub enabled: bool,
    pub release_id: String,
    pub runtime_compatibility_digest: ContentDigest,
    pub provider: String,
    pub provider_template_id: String,
    pub runner_template_digest: ContentDigest,
    pub channel: String,
    pub maintenance_windows: Vec<String>,
    pub rings: Vec<String>,
    pub minimum_healthy: u32,
    pub maximum_surge: u32,
    pub maximum_unavailable: u32,
    pub failure_threshold: u32,
    pub required_attestation_grade: String,
    pub protocol_min: u32,
    pub protocol_max: u32,
    pub paused: bool,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerReplacementMode {
    Autoscaled,
    FixedHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerReplacementState {
    Requested,
    ClaimIssued,
    Enrolled,
    Probationary,
    Active,
    DrainingSource,
    Completed,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerReplacementRecord {
    pub id: String,
    pub pool_id: String,
    pub mode: RunnerReplacementMode,
    pub source_runner_id: String,
    pub source_posture_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_runner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_posture_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_slot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fleet_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_fleet_request_id: Option<String>,
    pub generation: u64,
    pub policy_version: u64,
    pub release_id: String,
    pub channel: String,
    pub rollout_ring: u32,
    pub state: RunnerReplacementState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSlotRecord {
    pub id: String,
    pub pool_id: String,
    pub updater_identity_digest: ContentDigest,
    pub active_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_runner_id: Option<String>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSoftwareUpdateClaim {
    pub id: String,
    pub replacement_id: String,
    pub enrollment_token_id: String,
    pub pool_id: String,
    pub mode: RunnerReplacementMode,
    pub source_runner_id: String,
    pub source_posture_digest: ContentDigest,
    pub runner_slot_id: Option<String>,
    pub fleet_request_id: Option<String>,
    pub provider: Option<String>,
    pub provider_instance_id: Option<String>,
    pub updater_identity_digest: Option<ContentDigest>,
    pub runner_template_digest: ContentDigest,
    pub identity_proof_digest: ContentDigest,
    pub generation: u64,
    pub artifact_digest: ContentDigest,
    pub installed_digest: ContentDigest,
    pub release_id: String,
    pub component_profile_digest: ContentDigest,
    pub update_root_digest: ContentDigest,
    pub targets_metadata_digest: ContentDigest,
    pub snapshot_metadata_digest: ContentDigest,
    pub timestamp_metadata_digest: ContentDigest,
    pub policy_version: u64,
    pub channel: String,
    pub rollout_ring: u32,
    pub protocol_min: u32,
    pub protocol_max: u32,
    pub required_attestation_grade: String,
    pub attestation_nonce_digest: ContentDigest,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub canceled_unix_ms: Option<u64>,
    pub consumed_unix_ms: Option<u64>,
    pub runner_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedRunnerReplacement {
    pub replacement: RunnerReplacementRecord,
    pub fleet_request: super::RunnerFleetRequestRecord,
}

#[derive(Debug)]
pub struct IssuedRunnerSoftwareUpdateClaim {
    pub metadata: RunnerSoftwareUpdateClaim,
    pub token: super::RunnerLaunchClaimToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerEnrollmentReplay {
    pub request_digest: ContentDigest,
    pub runner_id: String,
    pub pool_id: String,
    pub certificate_chain_pem: Vec<u8>,
    pub certificate_expires_unix_ms: u64,
    pub authoritative_posture_digest: ContentDigest,
    pub selected_protocol_version: u32,
    pub created_unix_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_maintenance_windows_are_closed_and_support_midnight_wrap() {
        assert!(valid_update_windows(&["always".into()]));
        assert!(valid_update_windows(&["23:00-01:00Z".into()]));
        assert!(!valid_update_windows(&[]));
        assert!(!valid_update_windows(&["23:00-23:00Z".into()]));
        assert!(update_window_allows(
            &["23:00-01:00Z".into()],
            23 * 60 * 60 * 1_000
        ));
        assert!(!update_window_allows(
            &["23:00-01:00Z".into()],
            12 * 60 * 60 * 1_000
        ));
    }
}
