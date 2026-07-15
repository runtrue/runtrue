use runtrue_cache::CacheLimits;
use runtrue_storage::CasLimits;
use std::path::PathBuf;

pub(crate) const LOCAL_CACHE_FORMAT_VERSION: u32 = 1;

/// Local trust scope and resource limits.
#[derive(Debug, Clone)]
pub struct LocalCacheConfig {
    pub workspace: PathBuf,
    pub cache_root: PathBuf,
    pub installation_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub policy_epoch: u64,
    pub default_max_entry_bytes: u64,
    pub cas_limits: CasLimits,
    pub cache_limits: CacheLimits,
}

impl LocalCacheConfig {
    #[must_use]
    pub fn for_workspace(workspace: impl Into<PathBuf>) -> Self {
        let workspace = workspace.into();
        let cas_limits = CasLimits::default();
        Self {
            cache_root: workspace.join(".runtrue/cache"),
            workspace,
            installation_id: "local-installation".to_owned(),
            tenant_id: "local-tenant".to_owned(),
            repository_id: "local-workspace".to_owned(),
            policy_epoch: 1,
            default_max_entry_bytes: cas_limits.max_tree_total_bytes,
            cas_limits,
            cache_limits: CacheLimits::default(),
        }
    }
}

/// A non-fatal cache diagnostic retained for callers and attached to stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCacheWarning {
    pub job_id: String,
    pub step_id: String,
    pub message: String,
}
