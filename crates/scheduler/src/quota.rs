use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantQuota {
    pub maximum_running_jobs: u32,
    pub weight: u32,
}

impl Default for TenantQuota {
    fn default() -> Self {
        Self {
            maximum_running_jobs: u32::MAX,
            weight: 1,
        }
    }
}

pub(crate) fn has_capacity(quota: TenantQuota, running: u32) -> bool {
    running < quota.maximum_running_jobs
}

pub(crate) fn fair_share(quota: TenantQuota, running: u32) -> u64 {
    u64::from(running).saturating_mul(1_000) / u64::from(quota.weight)
}
