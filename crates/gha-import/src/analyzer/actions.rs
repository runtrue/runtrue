mod artifacts;
mod buildx;
mod cache;
mod checkout;
mod docker;

use super::{
    has_secret_expression, is_github_token_expression, looks_like_secret_name, static_string,
    ActionMapping, Analyzer, JobEffects,
};
use crate::{
    native::{NativeCommand, NativeRun, NativeSecretRequest, NativeStepCapabilities},
    report::CompatibilityStatus,
    validation::{is_full_git_commit, is_full_sha256_image, yaml_text},
};
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

impl Analyzer {
    pub(crate) fn convert_action_step(
        &mut self,
        uses: &YamlValue,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        for (name, value) in inputs {
            if has_secret_expression(&yaml_text(value))
                && !is_github_token_expression(&yaml_text(value))
            {
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "raw-github-secret",
                    format!("{path}.with.{name}"),
                    "GitHub secret or token expressions cannot be passed through an imported action",
                    Some(
                        "Replace GitHub secret interpolation with a reviewed native secret request."
                            .to_owned(),
                    ),
                );
            }
        }
        let Some(reference) = static_string(uses) else {
            self.dynamic_or_unsupported(
                uses,
                &format!("{path}.uses"),
                "action reference must be a static immutable or recognized built-in reference",
            );
            return ActionMapping::placeholder();
        };
        let Some((action, selector)) = reference.rsplit_once('@') else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "action-without-selector",
                format!("{path}.uses"),
                format!("action `{reference}` has no selector"),
                Some(format!("Add an immutable selector to `{reference}`.")),
            );
            return ActionMapping::placeholder();
        };
        if action.is_empty() || selector.is_empty() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-action-reference",
                format!("{path}.uses"),
                format!("action reference `{reference}` has an empty action name or selector"),
                Some("Use a complete action reference with a non-empty selector.".to_owned()),
            );
            return ActionMapping::placeholder();
        }
        let normalized = action.to_ascii_lowercase();
        match normalized.as_str() {
            "actions/checkout" => self.map_checkout(&reference, inputs, path, effects),
            "actions/cache" => self.map_cache(&reference, inputs, path, effects, "read-write"),
            "actions/cache/restore" => {
                self.map_cache(&reference, inputs, path, effects, "read-only")
            }
            "actions/cache/save" => self.map_cache(&reference, inputs, path, effects, "write-only"),
            "actions/upload-artifact" => {
                self.map_upload_artifact(&reference, inputs, path, effects)
            }
            "actions/download-artifact" => self.map_download_artifact(&reference, inputs, path),
            "docker/build-push-action" => self.map_docker_build(&reference, inputs, path, effects),
            "docker/setup-buildx-action" => {
                self.map_setup_buildx(&reference, inputs, path, effects)
            }
            _ if action.starts_with("./") => {
                self.unresolved_action_inputs(inputs, path, CompatibilityStatus::Unsupported);
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "local-github-action",
                    format!("{path}.uses"),
                    "local JavaScript/composite/Docker action metadata is not imported by this static front end",
                    Some("Replace the local action with native steps or package it as an approved native component.".to_owned()),
                );
                ActionMapping::placeholder()
            }
            _ if action.starts_with("docker://") => {
                self.map_container_action(&reference, inputs, path, effects)
            }
            _ if is_full_git_commit(selector) => {
                self.unresolved_action_inputs(inputs, path, CompatibilityStatus::RequiresGithub);
                self.finding(
                    CompatibilityStatus::RequiresGithub,
                    "unresolved-pinned-action",
                    format!("{path}.uses"),
                    format!("pinned action `{reference}` has no approved native component digest, signature identity, or runtime adapter"),
                    Some(format!("Resolve `{reference}` to an approved native component/adapter lock entry; do not invent a digest.")),
                );
                ActionMapping::placeholder()
            }
            _ => {
                self.unresolved_action_inputs(inputs, path, CompatibilityStatus::Unsafe);
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "mutable-third-party-action",
                    format!("{path}.uses"),
                    format!("third-party action `{reference}` is mutable or not pinned to a full commit"),
                    Some(format!("Pin `{action}` to a full 40-character commit and approve a native runtime lock entry.")),
                );
                ActionMapping::placeholder()
            }
        }
    }

    pub(crate) fn unresolved_action_inputs(
        &mut self,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        status: CompatibilityStatus,
    ) {
        for (name, value) in inputs {
            let input_path = format!("{path}.with.{name}");
            let value_text = yaml_text(value);
            let actual_status =
                if has_secret_expression(&value_text) || looks_like_secret_name(name) {
                    CompatibilityStatus::Unsafe
                } else {
                    status
                };
            self.finding(
                actual_status,
                "unresolved-action-input",
                input_path,
                format!("input `{name}` belongs to an unresolved GitHub action"),
                Some(
                    "Replace the action and all inputs with a reviewed native equivalent."
                        .to_owned(),
                ),
            );
        }
    }

    fn map_container_action(
        &mut self,
        reference: &str,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        let image = reference.trim_start_matches("docker://");
        if !is_full_sha256_image(image) {
            self.unresolved_action_inputs(inputs, path, CompatibilityStatus::Unsafe);
            self.finding(
                CompatibilityStatus::Unsafe,
                "mutable-container-action-image",
                format!("{path}.uses"),
                "Docker container action image is not pinned to a full lowercase sha256 digest",
                Some(
                    "Pin the docker:// action image as name@sha256:<64 lowercase hex>.".to_owned(),
                ),
            );
            return ActionMapping::placeholder();
        }
        if effects
            .container_action_image
            .as_ref()
            .is_some_and(|current| current != image)
        {
            self.finding(
                CompatibilityStatus::Unsupported,
                "multiple-container-action-images",
                format!("{path}.uses"),
                "one native OCI job cannot execute actions from different container images",
                Some("Place each pinned container action in a separate job.".to_owned()),
            );
            return ActionMapping::placeholder();
        }

        let mut env = BTreeMap::new();
        let mut needs_scm_credential = false;
        for (name, value) in inputs {
            let input_path = format!("{path}.with.{name}");
            if is_github_token_expression(&yaml_text(value)) {
                needs_scm_credential = true;
                env.insert(
                    "RUNTRUE_GITHUB_TOKEN_FILE".to_owned(),
                    runtrue_workflow_ast::Scalar::String(
                        "/workspace/.runtrue-runtime/scm-token".to_owned(),
                    ),
                );
                self.finding(
                    CompatibilityStatus::Emulated,
                    "scoped-github-token",
                    input_path,
                    "github.token maps to an execution-scoped provider credential file and is never placed in the environment",
                    None,
                );
                continue;
            }
            if has_secret_expression(&yaml_text(value)) || looks_like_secret_name(name) {
                continue;
            }
            let normalized = format!(
                "INPUT_{}",
                name.chars()
                    .map(|character| if character.is_ascii_alphanumeric() {
                        character.to_ascii_uppercase()
                    } else {
                        '_'
                    })
                    .collect::<String>()
            );
            if let Some(value) = self.convert_scalar(value, &input_path) {
                if env.insert(normalized.clone(), value).is_some() {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "container-action-input-collision",
                        input_path,
                        format!("multiple action inputs normalize to `{normalized}`"),
                        Some(
                            "Rename the colliding action inputs or split the action adapter."
                                .to_owned(),
                        ),
                    );
                }
            }
        }
        effects.container_action_image = Some(image.to_owned());
        if needs_scm_credential {
            effects.permissions.secrets.insert(
                "runtrue-scm-provider-token".to_owned(),
                "provider-api".to_owned(),
            );
        }
        self.lock_images.insert(crate::native::GeneratedImageLock {
            source: image.to_owned(),
            resolved: image.to_owned(),
            platform: "linux/amd64".to_owned(),
        });
        self.finding(
            CompatibilityStatus::Emulated,
            "pinned-container-action",
            format!("{path}.uses"),
            "pinned Docker action maps to its exact OCI image and the Runtrue container-action entrypoint contract",
            None,
        );
        ActionMapping {
            run: NativeRun::Command(NativeCommand {
                command: vec!["/usr/local/bin/runtrue-action".to_owned()],
                working_directory: None,
            }),
            env,
            cache: None,
            capabilities: needs_scm_credential.then_some(NativeStepCapabilities {
                cache: None,
                artifacts: None,
                secrets: vec![NativeSecretRequest {
                    name: "runtrue-scm-provider-token".to_owned(),
                    purpose: "provider-api".to_owned(),
                }],
            }),
            mapped: true,
        }
    }
}

impl ActionMapping {
    pub(crate) fn placeholder() -> Self {
        Self::noop(false)
    }

    pub(crate) fn noop(mapped: bool) -> Self {
        Self {
            run: NativeRun::Command(NativeCommand {
                command: vec!["true".to_owned()],
                working_directory: None,
            }),
            env: Default::default(),
            cache: None,
            capabilities: None,
            mapped,
        }
    }
}
