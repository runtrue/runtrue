use super::{
    contains_github_runtime, has_expression, has_privileged_or_host_feature, static_string,
    ActionMapping, Analyzer, JobEffects,
};
use crate::{
    github::GithubStep,
    native::{NativeRun, NativeScript, NativeStep},
    report::CompatibilityStatus,
    validation::{normalize_relative, safe_relative_path, valid_identifier},
};
use serde_yaml::Value as YamlValue;
impl Analyzer {
    pub(crate) fn convert_step(
        &mut self,
        step: GithubStep,
        job_path: &str,
        index: usize,
        effects: &mut JobEffects,
    ) -> NativeStep {
        let path = format!("{job_path}.steps[{index}]");
        self.unsupported_extras(&path, &step.extra);
        let name = self.convert_display_name(step.name, &format!("{path}.name"));
        let id = if let Some(id) = step.id {
            if valid_identifier(&id) {
                Some(id)
            } else {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-step-id",
                    format!("{path}.id"),
                    "step id is not a native identifier",
                    Some("Rename the step id to a portable identifier.".to_owned()),
                );
                None
            }
        } else {
            None
        };
        let condition = self.convert_condition(step.condition.as_ref(), &format!("{path}.if"));
        let mut env = self.convert_env(&step.env, &format!("{path}.env"));
        let timeout = self.convert_timeout(
            step.timeout_minutes.as_ref(),
            &format!("{path}.timeout-minutes"),
        );
        let continue_on_error = if let Some(value) = &step.continue_on_error {
            if let Some(value) = value.as_bool() {
                self.finding(
                    CompatibilityStatus::Supported,
                    "continue-on-error",
                    format!("{path}.continue-on-error"),
                    "static step continue-on-error maps to the native step flag",
                    None,
                );
                value
            } else {
                self.dynamic_or_unsupported(
                    value,
                    &format!("{path}.continue-on-error"),
                    "continue-on-error must be a static boolean",
                );
                false
            }
        } else {
            false
        };

        let working_directory = step.working_directory.as_ref().and_then(|value| {
            self.convert_working_directory(value, &format!("{path}.working-directory"))
        });
        let mapping = match (&step.run, &step.uses) {
            (Some(_), Some(_)) | (None, None) => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-step-action",
                    &path,
                    "a step must contain exactly one of run or uses",
                    Some(format!("Rewrite `{path}` with exactly one action.")),
                );
                ActionMapping::placeholder()
            }
            (Some(run), None) => {
                if !step.inputs.is_empty() {
                    for input in step.inputs.keys() {
                        self.finding(
                            CompatibilityStatus::Unsupported,
                            "run-with-input",
                            format!("{path}.with.{input}"),
                            "with inputs are not valid for native run steps",
                            Some(format!(
                                "Move `{path}.with.{input}` to env or script arguments."
                            )),
                        );
                    }
                }
                self.convert_run_step(run, step.shell.as_ref(), working_directory, &path)
            }
            (None, Some(uses)) => {
                if step.shell.is_some() {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "action-shell",
                        format!("{path}.shell"),
                        "shell is valid only for run steps",
                        Some(format!("Remove `{path}.shell`.")),
                    );
                }
                if step.working_directory.is_some() {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "action-working-directory",
                        format!("{path}.working-directory"),
                        "working-directory is not preserved for action steps",
                        Some(format!(
                            "Remove `{path}.working-directory` or apply it to a native run step."
                        )),
                    );
                }
                self.convert_action_step(uses, &step.inputs, &path, effects)
            }
        };
        if mapping.mapped {
            self.mapped_steps += 1;
        }
        for (name, value) in mapping.env {
            if env.insert(name.clone(), value).is_some() {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "action-input-env-collision",
                    format!("{path}.env.{name}"),
                    "step environment collides with the normalized container-action input",
                    Some(format!("Remove the explicit `{name}` environment value.")),
                );
            }
        }
        NativeStep {
            id,
            name,
            condition,
            run: mapping.run,
            env,
            capabilities: mapping.capabilities,
            cache: mapping.cache,
            timeout,
            continue_on_error,
        }
    }

    pub(crate) fn convert_working_directory(
        &mut self,
        value: &YamlValue,
        path: &str,
    ) -> Option<String> {
        let Some(value) = static_string(value) else {
            self.dynamic_or_unsupported(
                value,
                path,
                "working-directory must be a static repository-relative path",
            );
            return None;
        };
        if safe_relative_path(&value, false) {
            self.finding(
                CompatibilityStatus::Supported,
                "working-directory",
                path,
                "static repository-relative working directory maps to native syntax",
                None,
            );
            Some(normalize_relative(&value))
        } else {
            self.finding(
                CompatibilityStatus::Unsafe,
                "unsafe-working-directory",
                path,
                "working-directory is absolute, traversing, or host-relative",
                Some(format!("Use a repository-relative path at `{path}`.")),
            );
            None
        }
    }

    pub(crate) fn convert_run_step(
        &mut self,
        value: &YamlValue,
        shell: Option<&YamlValue>,
        working_directory: Option<String>,
        path: &str,
    ) -> ActionMapping {
        let Some(script) = value.as_str() else {
            self.dynamic_or_unsupported(
                value,
                &format!("{path}.run"),
                "run must be a static script string",
            );
            return ActionMapping::placeholder();
        };
        if has_expression(script) {
            self.finding(
                CompatibilityStatus::Unsafe,
                "expression-shell-injection",
                format!("{path}.run"),
                "GitHub expression interpolation in shell source can inject executable syntax",
                Some("Pass reviewed values through typed native env/args bindings instead of interpolating shell source.".to_owned()),
            );
        }
        if script.contains('\0') {
            self.finding(
                CompatibilityStatus::Unsupported,
                "nul-value",
                format!("{path}.run"),
                "shell source contains a NUL byte",
                Some("Remove the NUL byte from the shell source.".to_owned()),
            );
        }
        if contains_github_runtime(script) {
            self.finding(
                CompatibilityStatus::RequiresGithub,
                "github-runner-command-channel",
                format!("{path}.run"),
                "script references GitHub runner files, commands, or hosted environment variables",
                Some("Replace GitHub runner command channels with native outputs, checks, or artifacts.".to_owned()),
            );
        }
        if has_privileged_or_host_feature(script) {
            self.finding(
                CompatibilityStatus::Unsafe,
                "privileged-shell-feature",
                format!("{path}.run"),
                "script requests privileged or host-level behavior denied by native isolation",
                Some(
                    "Remove sudo, host namespaces, devices, sockets, and privileged flags."
                        .to_owned(),
                ),
            );
        }
        let shell = match shell {
            None => Some("bash"),
            Some(value) if value.as_str() == Some("bash") => Some("bash"),
            Some(value) if value.as_str() == Some("sh") => Some("sh"),
            Some(value) if value.as_str().is_some_and(has_expression) => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "dynamic-shell",
                    format!("{path}.shell"),
                    "dynamic shell selection is unsupported",
                    Some("Use a static bash or sh shell.".to_owned()),
                );
                None
            }
            Some(value) => {
                let value = value.as_str().unwrap_or("<non-string>");
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "unsupported-shell",
                    format!("{path}.shell"),
                    format!("shell `{value}` is not supported by the native compiler"),
                    Some("Use bash or sh, or rewrite the step as an argv command.".to_owned()),
                );
                None
            }
        };
        let mapped = shell.is_some()
            && !has_expression(script)
            && !contains_github_runtime(script)
            && !script.contains('\0');
        if mapped {
            self.finding(
                CompatibilityStatus::Supported,
                "static-run-step",
                format!("{path}.run"),
                "static shell source maps to a native script step",
                None,
            );
        }
        ActionMapping {
            run: NativeRun::Script(NativeScript {
                shell: shell.unwrap_or("bash"),
                script: script.to_owned(),
                working_directory,
            }),
            env: Default::default(),
            cache: None,
            capabilities: None,
            mapped,
        }
    }
}
