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
    native::{
        GeneratedComponentLock, NativeCommand, NativeComponentRun, NativeContainerInvocation,
        NativeContainerRun, NativeRun, NativeSecretRequest, NativeStepCapabilities,
    },
    report::CompatibilityStatus,
    validation::{is_exact_wasm_component, is_full_git_commit, is_full_sha256_image, yaml_text},
};
use runtrue_workflow_ast as ast;
use runtrue_workflow_frontend::{ResolvedRepositoryAction, ResolvedRepositoryProgram};
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

struct PreparedContainerAction<'a> {
    source: &'a str,
    image: &'a str,
    metadata: Option<&'a ResolvedRepositoryAction>,
    finding_code: &'a str,
}

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
                if !is_canonical_repository_action(action) {
                    self.unresolved_action_inputs(inputs, path, CompatibilityStatus::Unsupported);
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "unsupported-repository-action-reference",
                        format!("{path}.uses"),
                        "repository Docker actions currently require an exact owner/repository@commit reference",
                        Some("Use owner/repository@<full-40-character-commit> without a subpath.".to_owned()),
                    );
                    ActionMapping::placeholder()
                } else if let Some(image) =
                    self.resolved_repository_actions.get(&reference).cloned()
                {
                    self.map_resolved_repository_action(&reference, &image, inputs, path, effects)
                } else {
                    self.unresolved_action_inputs(
                        inputs,
                        path,
                        CompatibilityStatus::RequiresGithub,
                    );
                    self.finding(
                        CompatibilityStatus::RequiresGithub,
                        "unresolved-pinned-action",
                        format!("{path}.uses"),
                        format!("pinned action `{reference}` has not been prepared by the trusted repository-action resolver"),
                        Some(format!("Resolve and build `{reference}` through the trusted repository-action preparation provider.")),
                    );
                    ActionMapping::placeholder()
                }
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
        self.map_prepared_container_action(
            PreparedContainerAction {
                source: image,
                image,
                metadata: None,
                finding_code: "pinned-container-action",
            },
            inputs,
            path,
            effects,
        )
    }

    fn map_resolved_repository_action(
        &mut self,
        reference: &str,
        action: &ResolvedRepositoryAction,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        match &action.program {
            ResolvedRepositoryProgram::Container { image, .. } => {
                if !is_full_sha256_image(image) {
                    self.unresolved_action_inputs(inputs, path, CompatibilityStatus::Unsafe);
                    self.finding(
                        CompatibilityStatus::Unsafe,
                        "mutable-repository-action-resolution",
                        format!("{path}.uses"),
                        "trusted repository-action resolution is not a complete lowercase OCI digest pin",
                        Some("Rebuild the exact action commit and record its immutable OCI manifest digest.".to_owned()),
                    );
                    return ActionMapping::placeholder();
                }
                self.map_prepared_container_action(
                    PreparedContainerAction {
                        source: reference,
                        image,
                        metadata: Some(action),
                        finding_code: "pinned-repository-docker-action",
                    },
                    inputs,
                    path,
                    effects,
                )
            }
            ResolvedRepositoryProgram::Component {
                reference: component,
                scm_api_url,
                signature_identity,
                wit_world,
            } => self.map_prepared_component_action(
                reference,
                component,
                scm_api_url,
                signature_identity,
                wit_world,
                action,
                inputs,
                path,
                effects,
            ),
        }
    }

    fn map_prepared_component_action(
        &mut self,
        source: &str,
        component: &str,
        scm_api_url: &str,
        signature_identity: &str,
        wit_world: &str,
        metadata: &ResolvedRepositoryAction,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        if !is_exact_wasm_component(component) {
            self.unresolved_action_inputs(inputs, path, CompatibilityStatus::Unsafe);
            self.finding(
                CompatibilityStatus::Unsafe,
                "mutable-repository-component-resolution",
                format!("{path}.uses"),
                "trusted repository-action resolution is not an exact Wasm component digest",
                Some(
                    "Publish and admit the exact component payload before importing the workflow."
                        .to_owned(),
                ),
            );
            return ActionMapping::placeholder();
        }
        let Some((scm_host, scm_port)) = https_endpoint(scm_api_url) else {
            self.unresolved_action_inputs(inputs, path, CompatibilityStatus::Unsafe);
            self.finding(
                CompatibilityStatus::Unsafe,
                "invalid-component-scm-endpoint",
                format!("{path}.uses"),
                "trusted repository-action resolution supplied an invalid SCM API endpoint",
                None,
            );
            return ActionMapping::placeholder();
        };
        let mut effective_inputs = metadata
            .inputs
            .iter()
            .filter_map(|(name, input)| {
                input
                    .default
                    .as_ref()
                    .map(|value| (name.clone(), YamlValue::String(value.clone())))
            })
            .collect::<BTreeMap<_, _>>();
        effective_inputs.extend(inputs.clone());
        let mut native_inputs = BTreeMap::new();
        for (name, value) in &effective_inputs {
            let input_path = format!("{path}.with.{name}");
            if is_github_token_expression(&yaml_text(value)) {
                continue;
            }
            if has_secret_expression(&yaml_text(value)) || looks_like_secret_name(name) {
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "raw-component-secret",
                    input_path,
                    "raw secret expressions cannot be passed into a component input",
                    Some("Use the execution-scoped SCM credential capability.".to_owned()),
                );
                continue;
            }
            if let Some(value) = self.convert_scalar(value, &input_path) {
                native_inputs.insert(name.to_ascii_lowercase(), value);
            }
        }
        let missing_required = metadata.inputs.iter().any(|(name, input)| {
            if input.required && !effective_inputs.contains_key(name) {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "missing-required-action-input",
                    format!("{path}.with.{name}"),
                    format!("required action input `{name}` was not supplied and has no default"),
                    Some(format!("Supply `{name}` under `{path}.with`.")),
                );
                true
            } else {
                false
            }
        });
        if missing_required {
            return ActionMapping::placeholder();
        }
        effects.wasm_component = true;
        effects.permissions.secrets.insert(
            "runtrue-scm-provider-token".to_owned(),
            "provider-api".to_owned(),
        );
        effects
            .network_destinations
            .insert((scm_host.clone(), scm_port));
        effects.allow_private_network |= scm_api_url != "https://api.github.com";
        let digest = component
            .rsplit_once('@')
            .map(|(_, digest)| digest.to_owned())
            .expect("exact component reference has a digest");
        self.lock_components.insert(GeneratedComponentLock {
            source: component.to_owned(),
            resolved: digest,
            signature_identity: signature_identity.to_owned(),
            wit_world: wit_world.to_owned(),
        });
        self.finding(
            CompatibilityStatus::Emulated,
            "pinned-repository-wasm-component",
            format!("{path}.uses"),
            format!("full-commit repository action `{source}` maps to an admitted digest-pinned Wasm component"),
            None,
        );
        ActionMapping {
            run: NativeRun::Component(NativeComponentRun {
                reference: component.to_owned(),
                inputs: native_inputs,
            }),
            env: BTreeMap::new(),
            cache: None,
            capabilities: Some(NativeStepCapabilities {
                network: Some(ast::NetworkPolicy {
                    dns: ast::DnsPolicy::Restricted,
                    deny_private_ranges: scm_api_url == "https://api.github.com",
                    allow: vec![ast::NetworkDestination {
                        host: scm_host,
                        port: scm_port,
                        protocol: ast::NetworkProtocol::Tcp,
                    }],
                    listen: Vec::new(),
                }),
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

    fn map_prepared_container_action(
        &mut self,
        prepared: PreparedContainerAction<'_>,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        let PreparedContainerAction {
            source,
            image,
            metadata,
            finding_code,
        } = prepared;
        if effects
            .container_action_image
            .as_ref()
            .is_some_and(|current| current != source)
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

        let mut effective_inputs = metadata.map_or_else(BTreeMap::new, |metadata| {
            metadata
                .inputs
                .iter()
                .filter_map(|(name, input)| {
                    input
                        .default
                        .as_ref()
                        .map(|value| (name.clone(), YamlValue::String(value.clone())))
                })
                .collect()
        });
        effective_inputs.extend(inputs.clone());
        let missing_required = metadata
            .into_iter()
            .flat_map(|metadata| &metadata.inputs)
            .any(|(name, input)| {
                if input.required && !effective_inputs.contains_key(name) {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "missing-required-action-input",
                        format!("{path}.with.{name}"),
                        format!(
                            "required action input `{name}` was not supplied and has no default"
                        ),
                        Some(format!("Supply `{name}` under `{path}.with`.")),
                    );
                    true
                } else {
                    false
                }
            });
        if missing_required {
            return ActionMapping::placeholder();
        }

        let mut env = BTreeMap::new();
        let mut input_text = BTreeMap::new();
        let mut needs_scm_credential = false;
        for (name, value) in &effective_inputs {
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
                    .map(|character| if character == ' ' { '_' } else { character })
                    .flat_map(char::to_uppercase)
                    .collect::<String>()
            );
            if let Some(value) = self.convert_scalar(value, &input_path) {
                input_text.insert(name.to_ascii_lowercase(), scalar_text(&value));
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
        effects.container_action_image = Some(source.to_owned());
        if needs_scm_credential {
            effects.permissions.secrets.insert(
                "runtrue-scm-provider-token".to_owned(),
                "provider-api".to_owned(),
            );
        }
        self.lock_images.insert(crate::native::GeneratedImageLock {
            source: source.to_owned(),
            resolved: image.to_owned(),
            platform: "linux/amd64".to_owned(),
        });
        self.finding(
            CompatibilityStatus::Emulated,
            finding_code,
            format!("{path}.uses"),
            if finding_code == "pinned-repository-docker-action" {
                "full-commit repository Docker action maps to its prepared immutable OCI image and declared Docker entrypoint/CMD semantics"
            } else {
                "pinned Docker action maps to its exact OCI image and image entrypoint/CMD semantics"
            },
            None,
        );
        let (entrypoint, args) =
            metadata.map_or((None, None), |metadata| match &metadata.program {
                ResolvedRepositoryProgram::Container {
                    entrypoint, args, ..
                } => (
                    entrypoint.clone(),
                    args.as_ref().and_then(|args| {
                        args.iter()
                            .map(|argument| render_action_argument(argument, &input_text))
                            .collect::<Option<Vec<_>>>()
                    }),
                ),
                ResolvedRepositoryProgram::Component { .. } => (None, None),
            });
        if metadata
            .and_then(|metadata| match &metadata.program {
                ResolvedRepositoryProgram::Container { args, .. } => args.as_ref(),
                ResolvedRepositoryProgram::Component { .. } => None,
            })
            .is_some()
            && args.is_none()
        {
            self.finding(
                CompatibilityStatus::Unsupported,
                "unsupported-action-argument-expression",
                format!("{path}.uses"),
                "runs.args contains an expression other than a statically resolved inputs value",
                Some("Use only static text and `${{ inputs.<name> }}` in runs.args.".to_owned()),
            );
            return ActionMapping::placeholder();
        }
        ActionMapping {
            run: NativeRun::Container(NativeContainerRun {
                container: NativeContainerInvocation { entrypoint, args },
            }),
            env,
            cache: None,
            capabilities: needs_scm_credential.then_some(NativeStepCapabilities {
                network: None,
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

fn https_endpoint(value: &str) -> Option<(String, u16)> {
    let authority = value.strip_prefix("https://")?.split('/').next()?;
    if authority.is_empty() || authority.contains(['@', '[', ']']) {
        return None;
    }
    let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
        (host, port.parse().ok()?)
    } else {
        (authority, 443)
    };
    if host.is_empty() || host.chars().any(char::is_whitespace) || port == 0 {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

fn scalar_text(value: &runtrue_workflow_ast::Scalar) -> String {
    match value {
        runtrue_workflow_ast::Scalar::String(value) => value.clone(),
        runtrue_workflow_ast::Scalar::Integer(value) => value.to_string(),
        runtrue_workflow_ast::Scalar::Number(value) => value.to_string(),
        runtrue_workflow_ast::Scalar::Boolean(value) => value.to_string(),
    }
}

fn render_action_argument(template: &str, inputs: &BTreeMap<String, String>) -> Option<String> {
    let mut rendered = String::new();
    let mut remaining = template;
    while let Some(start) = remaining.find("${{") {
        rendered.push_str(&remaining[..start]);
        let expression = &remaining[start + 3..];
        let end = expression.find("}}")?;
        let path = expression[..end].trim().strip_prefix("inputs.")?;
        let value = inputs.get(&path.to_ascii_lowercase())?;
        rendered.push_str(value);
        remaining = &expression[end + 2..];
    }
    rendered.push_str(remaining);
    Some(rendered)
}

pub(crate) fn is_canonical_repository_action(action: &str) -> bool {
    let mut components = action.split('/');
    let owner = components.next().unwrap_or_default();
    let repository = components.next().unwrap_or_default();
    components.next().is_none()
        && valid_repository_component(owner)
        && valid_repository_component(repository)
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
