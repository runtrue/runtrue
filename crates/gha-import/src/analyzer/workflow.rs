use super::{
    has_expression, has_secret_expression, is_empty_scalar, looks_like_secret_name, static_string,
    static_string_list, yaml_string_map, Analyzer,
};
use crate::{
    github::{GithubPermissions, GithubTriggers},
    native::{
        NativeEmpty, NativeGitTrigger, NativeManual, NativeManualInput, NativeSchedule,
        NativeTriggers, NativeWebhookTrigger, PermissionState,
    },
    report::CompatibilityStatus,
    validation::{is_null_or_empty_mapping, valid_environment_name, valid_identifier, yaml_text},
};
use runtrue_workflow_ast as ast;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;
impl Analyzer {
    pub(crate) fn convert_triggers(&mut self, triggers: Option<GithubTriggers>) -> NativeTriggers {
        let Some(triggers) = triggers else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "missing-trigger",
                "on",
                "the workflow has no statically declared trigger",
                Some("Declare a supported `on` event.".to_owned()),
            );
            return NativeTriggers::default();
        };
        let entries = match triggers {
            GithubTriggers::One(name) => vec![(name, YamlValue::Null)],
            GithubTriggers::Many(names) => names
                .into_iter()
                .map(|name| (name, YamlValue::Null))
                .collect(),
            GithubTriggers::Map(entries) => entries.into_iter().collect(),
        };
        let mut native = NativeTriggers::default();
        for (name, config) in entries {
            let path = format!("on.{name}");
            match name.as_str() {
                "push" => {
                    native.push = Some(self.convert_git_trigger(&config, &path));
                }
                "pull_request" => {
                    native.pull_request = Some(self.convert_git_trigger(&config, &path));
                }
                "pull_request_target" => {
                    native.pull_request_target = Some(self.convert_webhook_trigger(&config, &path));
                    self.pull_request_target_requested = true;
                }
                "issue_comment" => {
                    native.issue_comment = Some(self.convert_webhook_trigger(&config, &path));
                    self.finding(
                        CompatibilityStatus::Supported,
                        "issue-comment-trigger",
                        path,
                        "issue_comment maps to a bounded normalized repository event",
                        None,
                    );
                }
                "check_run" => {
                    native.check_run = Some(self.convert_webhook_trigger(&config, &path));
                    self.finding(
                        CompatibilityStatus::Supported,
                        "check-run-trigger",
                        path,
                        "check_run maps to a bounded normalized repository event",
                        None,
                    );
                }
                "workflow_dispatch" => {
                    native.manual = self.convert_manual_trigger(&config, &path);
                }
                "schedule" => {
                    native
                        .schedule
                        .extend(self.convert_schedules(&config, &path));
                }
                "merge_group" => {
                    if is_null_or_empty_mapping(&config) {
                        native.merge_queue = Some(NativeEmpty {});
                        self.finding(
                            CompatibilityStatus::Supported,
                            "merge-queue-trigger",
                            path,
                            "merge_group maps to the native merge queue trigger",
                            None,
                        );
                    } else {
                        self.finding(
                            CompatibilityStatus::Unsupported,
                            "merge-group-options",
                            path,
                            "configured merge_group options are not implemented",
                            Some("Remove merge_group options or declare a native merge_queue trigger.".to_owned()),
                        );
                    }
                }
                "workflow_call" | "repository_dispatch" => {
                    self.finding(
                        CompatibilityStatus::RequiresGithub,
                        "github-dispatch-api",
                        path,
                        format!("the `{name}` event depends on GitHub dispatch or reusable-workflow APIs"),
                        Some(format!(
                            "Replace `{name}` with a Runtrue manual/API trigger and explicit typed inputs."
                        )),
                    );
                }
                _ => {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "unsupported-event",
                        path,
                        format!("the GitHub `{name}` event has no native mapping"),
                        Some(format!(
                            "Replace the `{name}` event with a supported Runtrue trigger."
                        )),
                    );
                }
            }
        }
        native
    }

    pub(crate) fn convert_webhook_trigger(
        &mut self,
        value: &YamlValue,
        path: &str,
    ) -> NativeWebhookTrigger {
        if is_null_or_empty_mapping(value) {
            return NativeWebhookTrigger::default();
        }
        let Some(mapping) = yaml_string_map(value) else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-webhook-trigger",
                path,
                "webhook trigger configuration must be a static mapping",
                Some(format!("Rewrite `{path}` with a static `types` list.")),
            );
            return NativeWebhookTrigger::default();
        };
        let mut native = NativeWebhookTrigger::default();
        for (key, value) in mapping {
            if key == "types" {
                if let Some(types) = static_string_list(value) {
                    native.types = types;
                } else {
                    self.dynamic_or_unsupported(
                        value,
                        &format!("{path}.types"),
                        "webhook event types must be static strings",
                    );
                }
            } else {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "unsupported-webhook-option",
                    format!("{path}.{key}"),
                    format!("webhook trigger option `{key}` has no native mapping"),
                    Some(format!("Remove `{path}.{key}`.")),
                );
            }
        }
        native
    }

    pub(crate) fn convert_git_trigger(
        &mut self,
        value: &YamlValue,
        path: &str,
    ) -> NativeGitTrigger {
        if value.is_null() {
            self.finding(
                CompatibilityStatus::Supported,
                "git-trigger",
                path,
                "GitHub git trigger maps to the native git trigger",
                None,
            );
            return NativeGitTrigger::default();
        }
        let Some(mapping) = yaml_string_map(value) else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-git-trigger",
                path,
                "git trigger configuration must be a static mapping",
                Some(format!(
                    "Rewrite `{path}` as a static branch/path filter mapping."
                )),
            );
            return NativeGitTrigger::default();
        };
        let mut native = NativeGitTrigger::default();
        for (key, value) in mapping {
            let target = match key.as_str() {
                "branches" => Some(&mut native.branches),
                "branches-ignore" => Some(&mut native.branches_ignore),
                "paths" => Some(&mut native.paths),
                "paths-ignore" => Some(&mut native.paths_ignore),
                _ => None,
            };
            if let Some(target) = target {
                if let Some(values) = static_string_list(value) {
                    *target = values;
                    self.finding(
                        CompatibilityStatus::Supported,
                        "git-trigger-filter",
                        format!("{path}.{key}"),
                        "static GitHub filter maps exactly to the native trigger filter",
                        None,
                    );
                } else {
                    self.dynamic_or_unsupported(
                        value,
                        &format!("{path}.{key}"),
                        "trigger filters must be static strings",
                    );
                }
            } else {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "unsupported-trigger-option",
                    format!("{path}.{key}"),
                    format!("GitHub trigger option `{key}` has no native mapping"),
                    Some(format!(
                        "Remove `{path}.{key}` or express it in native policy."
                    )),
                );
            }
        }
        native
    }

    pub(crate) fn convert_manual_trigger(
        &mut self,
        value: &YamlValue,
        path: &str,
    ) -> Option<NativeManual> {
        if is_null_or_empty_mapping(value) {
            self.finding(
                CompatibilityStatus::Supported,
                "manual-trigger",
                path,
                "workflow_dispatch maps to the native manual trigger",
                None,
            );
            return Some(NativeManual {
                inputs: BTreeMap::new(),
            });
        }
        let Some(mapping) = yaml_string_map(value) else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-manual-trigger",
                path,
                "workflow_dispatch configuration must be a static mapping",
                Some("Rewrite workflow_dispatch with static typed inputs.".to_owned()),
            );
            return None;
        };
        let mut native_inputs = BTreeMap::new();
        for (field, field_value) in mapping {
            if field != "inputs" {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "unsupported-manual-option",
                    format!("{path}.{field}"),
                    format!("workflow_dispatch option `{field}` is not supported"),
                    Some(format!("Remove `{path}.{field}`.")),
                );
                continue;
            }
            let Some(inputs) = yaml_string_map(field_value) else {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-manual-inputs",
                    format!("{path}.inputs"),
                    "manual inputs must be a static mapping",
                    Some(
                        "Rewrite workflow_dispatch inputs as static typed definitions.".to_owned(),
                    ),
                );
                continue;
            };
            for (input_name, definition) in inputs {
                if let Some(converted) = self.convert_manual_input(
                    &input_name,
                    definition,
                    &format!("{path}.inputs.{input_name}"),
                ) {
                    native_inputs.insert(input_name.clone(), converted);
                }
            }
        }
        Some(NativeManual {
            inputs: native_inputs,
        })
    }

    pub(crate) fn convert_manual_input(
        &mut self,
        input_name: &str,
        value: &YamlValue,
        path: &str,
    ) -> Option<NativeManualInput> {
        if !valid_identifier(input_name) {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-input-name",
                path,
                "manual input name is not a native identifier",
                Some(format!("Rename `{input_name}` to a valid identifier.")),
            );
            return None;
        }
        let Some(mapping) = yaml_string_map(value) else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-manual-input",
                path,
                "manual input definition must be a static mapping",
                Some(format!("Rewrite `{path}` as a typed input definition.")),
            );
            return None;
        };
        let mut kind = "string".to_owned();
        let mut required = false;
        let mut default = None;
        let mut options = Vec::new();
        for (field, field_value) in mapping {
            match field.as_str() {
                "description" => {
                    if static_string(field_value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "input-description",
                            format!("{path}.description"),
                            "input descriptions are report metadata and are not part of the native execution capsule",
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            field_value,
                            &format!("{path}.description"),
                            "input description must be a static scalar",
                        );
                    }
                }
                "type" => {
                    let Some(value) = field_value.as_str() else {
                        self.dynamic_or_unsupported(
                            field_value,
                            &format!("{path}.type"),
                            "input type must be a static string",
                        );
                        continue;
                    };
                    if matches!(value, "string" | "boolean" | "number" | "choice") {
                        value.clone_into(&mut kind);
                    } else if value == "environment" {
                        self.finding(
                            CompatibilityStatus::RequiresGithub,
                            "github-environment-input",
                            format!("{path}.type"),
                            "environment inputs depend on GitHub Environment objects",
                            Some(format!("Change `{path}.type` to string and enforce environment policy natively.")),
                        );
                    } else {
                        self.finding(
                            CompatibilityStatus::Unsupported,
                            "unsupported-input-type",
                            format!("{path}.type"),
                            format!("input type `{value}` is unsupported"),
                            Some(format!("Use a supported type for `{path}`.")),
                        );
                    }
                }
                "required" => {
                    if let Some(value) = field_value.as_bool() {
                        required = value;
                    } else {
                        self.dynamic_or_unsupported(
                            field_value,
                            &format!("{path}.required"),
                            "required must be a static boolean",
                        );
                    }
                }
                "default" => {
                    default = self.convert_scalar(field_value, &format!("{path}.default"));
                }
                "options" => {
                    let Some(values) = field_value.as_sequence() else {
                        self.dynamic_or_unsupported(
                            field_value,
                            &format!("{path}.options"),
                            "choice options must be a static sequence",
                        );
                        continue;
                    };
                    for (index, value) in values.iter().enumerate() {
                        if let Some(value) =
                            self.convert_scalar(value, &format!("{path}.options[{index}]"))
                        {
                            options.push(value);
                        }
                    }
                }
                _ => self.finding(
                    CompatibilityStatus::Unsupported,
                    "unsupported-input-option",
                    format!("{path}.{field}"),
                    format!("manual input field `{field}` is unsupported"),
                    Some(format!("Remove `{path}.{field}`.")),
                ),
            }
        }
        self.finding(
            CompatibilityStatus::Supported,
            "manual-input",
            path,
            "static workflow_dispatch input maps to a native manual input",
            None,
        );
        Some(NativeManualInput {
            kind,
            required,
            default,
            options,
        })
    }

    pub(crate) fn convert_schedules(
        &mut self,
        value: &YamlValue,
        path: &str,
    ) -> Vec<NativeSchedule> {
        let Some(entries) = value.as_sequence() else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-schedule",
                path,
                "schedule must be a static sequence of cron mappings",
                Some("Rewrite the schedule as a static cron list.".to_owned()),
            );
            return Vec::new();
        };
        let mut native = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let entry_path = format!("{path}[{index}]");
            let Some(mapping) = yaml_string_map(entry) else {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-schedule-entry",
                    entry_path,
                    "schedule entry must be a static mapping",
                    Some("Use `{ cron: '...' }` for each schedule entry.".to_owned()),
                );
                continue;
            };
            let mut cron = None;
            for (field, field_value) in mapping {
                if field == "cron" {
                    cron = static_string(field_value);
                    if cron.is_none() {
                        self.dynamic_or_unsupported(
                            field_value,
                            &format!("{entry_path}.cron"),
                            "cron must be a static string",
                        );
                    }
                } else {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "unsupported-schedule-option",
                        format!("{entry_path}.{field}"),
                        format!("schedule option `{field}` is unsupported"),
                        Some(format!("Remove `{entry_path}.{field}`.")),
                    );
                }
            }
            if let Some(cron) = cron {
                native.push(NativeSchedule {
                    cron,
                    timezone: "UTC".to_owned(),
                });
                self.finding(
                    CompatibilityStatus::Supported,
                    "schedule-trigger",
                    entry_path,
                    "GitHub cron schedule maps to a native UTC schedule",
                    None,
                );
            }
        }
        native
    }

    pub(crate) fn convert_permissions(
        &mut self,
        permissions: Option<&GithubPermissions>,
        path: &str,
        inherited: &PermissionState,
    ) -> PermissionState {
        let Some(permissions) = permissions else {
            self.finding(
                CompatibilityStatus::Emulated,
                "default-token-permissions",
                path,
                "GitHub's repository-dependent GITHUB_TOKEN defaults are replaced with native least privilege inferred from mapped steps",
                None,
            );
            return inherited.clone();
        };
        let GithubPermissions::Map(mapping) = permissions else {
            let GithubPermissions::Keyword(keyword) = permissions else {
                unreachable!()
            };
            self.finding(
                CompatibilityStatus::RequiresGithub,
                "github-token-permission-set",
                path,
                format!("permission keyword `{keyword}` covers GitHub-specific token scopes"),
                Some("Replace read-all/write-all with explicit native permissions.".to_owned()),
            );
            return PermissionState::default();
        };
        let mut native = PermissionState::default();
        for (scope, value) in mapping {
            let Some(access) = value.as_str() else {
                self.dynamic_or_unsupported(
                    value,
                    &format!("{path}.{scope}"),
                    "permission access must be read, write, or none",
                );
                continue;
            };
            let access_value = match access {
                "read" => Some(ast::Access::Read),
                "write" => Some(ast::Access::Write),
                "none" => Some(ast::Access::Deny),
                _ => None,
            };
            let Some(access_value) = access_value else {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-permission-access",
                    format!("{path}.{scope}"),
                    format!("permission access `{access}` is unsupported"),
                    Some(format!("Set `{path}.{scope}` to read, write, or none.")),
                );
                continue;
            };
            match scope.as_str() {
                "contents" => native.scm_contents = access_value,
                "issues" => {
                    native.scm_issues = access_value;
                    self.finding(
                        CompatibilityStatus::Emulated,
                        "repository-mutation-permission",
                        format!("{path}.{scope}"),
                        format!(
                            "GitHub `{scope}` access is retained in the scoped provider credential behind the native repository capability"
                        ),
                        None,
                    );
                }
                "pull-requests" => {
                    native.scm_pull_requests = access_value;
                    self.finding(
                        CompatibilityStatus::Emulated,
                        "repository-mutation-permission",
                        format!("{path}.{scope}"),
                        "GitHub `pull-requests` access is retained as an exact scoped provider capability",
                        None,
                    );
                }
                "checks" => native.scm_checks = access_value,
                "statuses" => native.scm_statuses = access_value,
                "packages" => native.registry = access_value,
                "actions" => {
                    native.cache_read = match access_value {
                        ast::Access::Deny => ast::CacheRead::Deny,
                        ast::Access::Read | ast::Access::Write => ast::CacheRead::Run,
                    };
                    native.cache_write = match access_value {
                        ast::Access::Write => ast::CacheWrite::Quarantine,
                        ast::Access::Deny | ast::Access::Read => ast::CacheWrite::Deny,
                    };
                }
                "id-token" => self.finding(
                    CompatibilityStatus::RequiresGithub,
                    "github-oidc-token",
                    format!("{path}.{scope}"),
                    "GitHub OIDC claims cannot be translated to native OIDC without an explicit audience policy",
                    Some("Declare native OIDC audiences and replace GitHub claim assumptions.".to_owned()),
                ),
                _ => self.finding(
                    CompatibilityStatus::RequiresGithub,
                    "github-token-scope",
                    format!("{path}.{scope}"),
                    format!("GitHub token scope `{scope}` has no native capability equivalent"),
                    Some(format!("Remove `{path}.{scope}` or replace its API use with a native capability.")),
                ),
            }
            if matches!(
                scope.as_str(),
                "contents" | "checks" | "statuses" | "packages" | "actions"
            ) {
                self.finding(
                    CompatibilityStatus::Supported,
                    "permission-mapping",
                    format!("{path}.{scope}"),
                    format!("GitHub `{scope}` access maps to a native least-privilege capability"),
                    None,
                );
            }
        }
        native
    }

    pub(crate) fn convert_env(
        &mut self,
        values: &BTreeMap<String, YamlValue>,
        path: &str,
    ) -> BTreeMap<String, ast::Scalar> {
        let mut result = BTreeMap::new();
        for (name, value) in values {
            let value_path = format!("{path}.{name}");
            if !valid_environment_name(name) {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-env-name",
                    &value_path,
                    "environment variable name is not accepted by the native compiler",
                    Some(format!(
                        "Rename `{name}` to a portable environment variable name."
                    )),
                );
                continue;
            }
            if looks_like_secret_name(name) && !is_empty_scalar(value) {
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "raw-secret-literal",
                    &value_path,
                    "a secret-like environment variable contains a raw workflow value",
                    Some(format!(
                        "Move `{name}` to Runtrue's secret store and request it by metadata name."
                    )),
                );
            }
            if let Some(converted) = self.convert_scalar(value, &value_path) {
                result.insert(name.clone(), converted);
                self.finding(
                    CompatibilityStatus::Supported,
                    "static-environment",
                    value_path,
                    "static environment value maps to a native variable binding",
                    None,
                );
            }
        }
        result
    }

    pub(crate) fn convert_display_name(
        &mut self,
        value: Option<String>,
        path: &str,
    ) -> Option<String> {
        let value = value?;
        if has_secret_expression(&value) {
            self.finding(
                CompatibilityStatus::Unsafe,
                "raw-github-secret",
                path,
                "GitHub secret expressions cannot be copied into native workflow metadata",
                Some("Replace the dynamic display name with static non-secret text.".to_owned()),
            );
            None
        } else if has_expression(&value) {
            self.finding(
                CompatibilityStatus::Unsupported,
                "dynamic-display-name",
                path,
                "dynamic GitHub display names are not statically importable",
                Some("Replace the dynamic display name with static text.".to_owned()),
            );
            None
        } else if value.contains('\0') {
            self.finding(
                CompatibilityStatus::Unsupported,
                "nul-value",
                path,
                "display name contains a NUL byte",
                Some("Remove the NUL byte from the display name.".to_owned()),
            );
            None
        } else {
            Some(value)
        }
    }

    pub(crate) fn convert_scalar(&mut self, value: &YamlValue, path: &str) -> Option<ast::Scalar> {
        match value {
            YamlValue::Bool(value) => Some(ast::Scalar::Boolean(*value)),
            YamlValue::Number(value) => {
                if let Some(value) = value.as_i64() {
                    Some(ast::Scalar::Integer(value))
                } else if let Some(value) = value.as_u64() {
                    match i64::try_from(value) {
                        Ok(value) => Some(ast::Scalar::Integer(value)),
                        Err(_) => {
                            self.finding(
                                CompatibilityStatus::Unsupported,
                                "integer-range",
                                path,
                                "integer is outside the native signed 64-bit range",
                                Some(format!("Use a signed 64-bit value at `{path}`.")),
                            );
                            None
                        }
                    }
                } else {
                    value.as_f64().map(ast::Scalar::Number)
                }
            }
            YamlValue::String(value) => {
                if has_secret_expression(value) {
                    self.finding(
                        CompatibilityStatus::Unsafe,
                        "raw-github-secret",
                        path,
                        "GitHub secret expressions cannot be copied into native workflow data",
                        Some(
                            "Replace GitHub secret interpolation with a Runtrue secret request."
                                .to_owned(),
                        ),
                    );
                    None
                } else if has_expression(value) {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "dynamic-expression",
                        path,
                        "dynamic GitHub expression is not statically importable",
                        Some(format!(
                            "Replace `{path}` with a static value or a typed native binding."
                        )),
                    );
                    None
                } else if value.contains('\0') {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "nul-value",
                        path,
                        "string contains a NUL byte",
                        Some(format!("Remove the NUL byte from `{path}`.")),
                    );
                    None
                } else {
                    Some(ast::Scalar::String(value.clone()))
                }
            }
            _ => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "non-scalar-value",
                    path,
                    "native environment and matrix values must be scalar",
                    Some(format!("Replace `{path}` with a static scalar.")),
                );
                None
            }
        }
    }

    pub(crate) fn dynamic_or_unsupported(&mut self, value: &YamlValue, path: &str, message: &str) {
        let text = yaml_text(value);
        let (status, code, required) = if has_secret_expression(&text) {
            (
                CompatibilityStatus::Unsafe,
                "raw-github-secret",
                "Replace GitHub secret interpolation with a Runtrue secret request.".to_owned(),
            )
        } else if has_expression(&text) {
            (
                CompatibilityStatus::Unsupported,
                "dynamic-expression",
                format!("Replace `{path}` with static syntax or a typed native binding."),
            )
        } else {
            (
                CompatibilityStatus::Unsupported,
                "unsupported-syntax",
                format!("Rewrite `{path}` using supported static syntax."),
            )
        };
        self.finding(status, code, path, message, Some(required));
    }
}
