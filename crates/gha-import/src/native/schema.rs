use crate::validation::{merge_cache_read, merge_cache_write};
use runtrue_workflow_ast as ast;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeWorkflow {
    pub(crate) version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(rename = "on")]
    pub(crate) triggers: NativeTriggers,
    pub(crate) permissions: NativePermissions,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) vars: BTreeMap<String, ast::Scalar>,
    pub(crate) jobs: BTreeMap<String, NativeJob>,
}

#[derive(Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeTriggers {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) push: Option<NativeGitTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pull_request: Option<NativeGitTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pull_request_target: Option<NativeWebhookTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issue_comment: Option<NativeWebhookTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) check_run: Option<NativeWebhookTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) merge_queue: Option<NativeEmpty>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) schedule: Vec<NativeSchedule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) manual: Option<NativeManual>,
}

#[derive(Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeWebhookTrigger {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) types: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeGitTrigger {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) branches: Vec<String>,
    #[serde(
        default,
        rename = "branches-ignore",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub(crate) branches_ignore: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) paths: Vec<String>,
    #[serde(
        default,
        rename = "paths-ignore",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub(crate) paths_ignore: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeEmpty {}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeSchedule {
    pub(crate) cron: String,
    pub(crate) timezone: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeManual {
    pub(crate) inputs: BTreeMap<String, NativeManualInput>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeManualInput {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) default: Option<ast::Scalar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) options: Vec<ast::Scalar>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PermissionState {
    pub(crate) repository: ast::Access,
    pub(crate) scm_contents: ast::Access,
    pub(crate) scm_issues: ast::Access,
    pub(crate) scm_pull_requests: ast::Access,
    pub(crate) scm_checks: ast::Access,
    pub(crate) scm_statuses: ast::Access,
    pub(crate) checks: ast::Access,
    pub(crate) artifacts: ast::Access,
    pub(crate) registry: ast::Access,
    pub(crate) cache_read: ast::CacheRead,
    pub(crate) cache_write: ast::CacheWrite,
    pub(crate) secrets: BTreeMap<String, String>,
}

impl Default for PermissionState {
    fn default() -> Self {
        Self {
            repository: ast::Access::Deny,
            scm_contents: ast::Access::Deny,
            scm_issues: ast::Access::Deny,
            scm_pull_requests: ast::Access::Deny,
            scm_checks: ast::Access::Deny,
            scm_statuses: ast::Access::Deny,
            checks: ast::Access::Deny,
            artifacts: ast::Access::Deny,
            registry: ast::Access::Deny,
            cache_read: ast::CacheRead::Deny,
            cache_write: ast::CacheWrite::Deny,
            secrets: BTreeMap::new(),
        }
    }
}

impl PermissionState {
    pub(crate) fn merge_maximum(&mut self, other: &Self) {
        self.repository = self.repository.max(other.repository);
        self.scm_contents = self.scm_contents.max(other.scm_contents);
        self.scm_issues = self.scm_issues.max(other.scm_issues);
        self.scm_pull_requests = self.scm_pull_requests.max(other.scm_pull_requests);
        self.scm_checks = self.scm_checks.max(other.scm_checks);
        self.scm_statuses = self.scm_statuses.max(other.scm_statuses);
        self.checks = self.checks.max(other.checks);
        self.artifacts = self.artifacts.max(other.artifacts);
        self.registry = self.registry.max(other.registry);
        self.cache_read = merge_cache_read(self.cache_read, other.cache_read);
        self.cache_write = merge_cache_write(self.cache_write, other.cache_write);
        self.secrets.extend(other.secrets.clone());
    }

    pub(crate) fn native(&self) -> NativePermissions {
        NativePermissions {
            repository: self.repository,
            scm: NativeScmPermissions {
                contents: self.scm_contents,
                issues: self.scm_issues,
                pull_requests: self.scm_pull_requests,
                checks: self.scm_checks,
                statuses: self.scm_statuses,
            },
            checks: self.checks,
            artifacts: self.artifacts,
            registry: self.registry,
            network: "deny",
            oidc: "deny",
            cache: NativeCachePermissions {
                read: self.cache_read,
                write: self.cache_write,
            },
            secrets: self
                .secrets
                .iter()
                .map(|(name, purpose)| NativeSecretRequest {
                    name: name.clone(),
                    purpose: purpose.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativePermissions {
    pub(crate) repository: ast::Access,
    #[serde(skip_serializing_if = "NativeScmPermissions::is_denied")]
    pub(crate) scm: NativeScmPermissions,
    pub(crate) checks: ast::Access,
    pub(crate) artifacts: ast::Access,
    pub(crate) registry: ast::Access,
    pub(crate) network: &'static str,
    pub(crate) oidc: &'static str,
    pub(crate) cache: NativeCachePermissions,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) secrets: Vec<NativeSecretRequest>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeScmPermissions {
    pub(crate) contents: ast::Access,
    pub(crate) issues: ast::Access,
    #[serde(rename = "pull-requests")]
    pub(crate) pull_requests: ast::Access,
    pub(crate) checks: ast::Access,
    pub(crate) statuses: ast::Access,
}

impl NativeScmPermissions {
    pub(crate) const fn is_denied(&self) -> bool {
        matches!(self.contents, ast::Access::Deny)
            && matches!(self.issues, ast::Access::Deny)
            && matches!(self.pull_requests, ast::Access::Deny)
            && matches!(self.checks, ast::Access::Deny)
            && matches!(self.statuses, ast::Access::Deny)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeCachePermissions {
    pub(crate) read: ast::CacheRead,
    pub(crate) write: ast::CacheWrite,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeJob {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) needs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "if")]
    pub(crate) condition: Option<String>,
    pub(crate) runner: NativeRunner,
    pub(crate) permissions: NativePermissions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) concurrency: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) matrix: BTreeMap<String, Vec<ast::Scalar>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) vars: BTreeMap<String, ast::Scalar>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) services: BTreeMap<String, NativeService>,
    pub(crate) steps: Vec<NativeStep>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) outputs: BTreeMap<String, NativeOutput>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeRunner {
    pub(crate) os: &'static str,
    pub(crate) arch: &'static str,
    pub(crate) isolation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) image: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeService {
    pub(crate) image: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, ast::Scalar>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeStep {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "if")]
    pub(crate) condition: Option<String>,
    pub(crate) run: NativeRun,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, ast::Scalar>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) capabilities: Option<NativeStepCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cache: Option<NativeCache>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) timeout: Option<String>,
    #[serde(
        default,
        rename = "continue-on-error",
        skip_serializing_if = "is_false"
    )]
    pub(crate) continue_on_error: bool,
}

pub(crate) const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum NativeRun {
    Command(NativeCommand),
    Script(NativeScript),
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeCommand {
    pub(crate) command: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "working-directory")]
    pub(crate) working_directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeScript {
    pub(crate) shell: &'static str,
    pub(crate) script: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "working-directory")]
    pub(crate) working_directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeStepCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cache: Option<NativeCachePermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) artifacts: Option<ast::Access>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) secrets: Vec<NativeSecretRequest>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeSecretRequest {
    pub(crate) name: String,
    pub(crate) purpose: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeCache {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) outputs: Vec<String>,
    pub(crate) mode: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeOutput {
    pub(crate) path: String,
    pub(crate) retention: String,
    pub(crate) classification: &'static str,
}
