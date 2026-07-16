use super::{
    has_expression, has_privileged_or_host_feature, positive_u64, static_runner_labels,
    static_string, yaml_string_map, Analyzer, ConvertedJob, JobEffects,
};
use crate::{
    github::{GithubJob, GithubService, GithubStrategy},
    native::{GeneratedImageLock, NativeJob, NativeRunner, NativeService, PermissionState},
    report::CompatibilityStatus,
    validation::{is_full_sha256_image, valid_identifier, yaml_text},
};
use runtrue_workflow_ast as ast;
use serde_yaml::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};
impl Analyzer {
    pub(crate) fn convert_job(
        &mut self,
        job_id: &str,
        job: GithubJob,
        workflow_permissions: &PermissionState,
    ) -> ConvertedJob {
        let path = format!("jobs.{job_id}");
        self.unsupported_extras(&path, &job.extra);
        let name = self.convert_display_name(job.name, &format!("{path}.name"));
        if !valid_identifier(job_id) {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-job-id",
                &path,
                "job id is not a valid native identifier",
                Some(format!(
                    "Rename job `{job_id}` to a valid native identifier."
                )),
            );
        }

        let needs = self.convert_needs(job.needs.as_ref(), &format!("{path}.needs"));
        let condition = self.convert_condition(job.condition.as_ref(), &format!("{path}.if"));
        let vars = self.convert_env(&job.env, &format!("{path}.env"));
        let matrix = self.convert_matrix(job.strategy.as_ref(), &format!("{path}.strategy"));
        let services = self.convert_services(&job.services, &format!("{path}.services"));
        let timeout = self.convert_timeout(
            job.timeout_minutes.as_ref(),
            &format!("{path}.timeout-minutes"),
        );
        let concurrency = if job.concurrency.is_some() {
            self.convert_concurrency(job.concurrency.as_ref(), &format!("{path}.concurrency"))
        } else {
            self.workflow_concurrency.clone()
        };

        let base_permissions = if job.permissions.is_some() {
            self.convert_permissions(
                job.permissions.as_ref(),
                &format!("{path}.permissions"),
                workflow_permissions,
            )
        } else {
            workflow_permissions.clone()
        };
        let mut effects = JobEffects {
            permissions: base_permissions,
            outputs: BTreeMap::new(),
            runner_capabilities: BTreeSet::new(),
            container_action_image: None,
            wasm_component: false,
            network_destinations: BTreeSet::new(),
            allow_private_network: false,
        };
        let mut steps = Vec::new();
        for (index, step) in job.steps.into_iter().enumerate() {
            steps.push(self.convert_step(step, &path, index, &mut effects));
        }
        if steps.is_empty() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "job-without-steps",
                format!("{path}.steps"),
                "native jobs require statically declared steps",
                Some(format!("Replace `{path}` with a supported step-based job.")),
            );
        } else {
            self.mapped_jobs += 1;
            self.finding(
                CompatibilityStatus::Supported,
                "job-dag-node",
                &path,
                "job maps to a native DAG node",
                None,
            );
        }

        if !job.outputs.is_empty() {
            for output in job.outputs.keys() {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "github-job-output",
                    format!("{path}.outputs.{output}"),
                    "GitHub expression-based job outputs are not statically importable",
                    Some(format!("Replace `{path}.outputs.{output}` with a native artifact output or typed dependency result.")),
                );
            }
        }
        if let Some(value) = &job.uses {
            self.dynamic_or_unsupported(
                value,
                &format!("{path}.uses"),
                "reusable workflow jobs require explicit immutable native workflow resolution",
            );
            self.finding(
                CompatibilityStatus::RequiresGithub,
                "reusable-github-workflow",
                format!("{path}.uses"),
                "GitHub reusable-workflow execution is unresolved",
                Some("Import the reusable workflow separately and bind an approved native workflow lock entry.".to_owned()),
            );
        }
        if job.secrets.is_some() {
            self.finding(
                CompatibilityStatus::Unsafe,
                "reusable-workflow-secrets",
                format!("{path}.secrets"),
                "GitHub reusable-workflow secret forwarding cannot be copied safely",
                Some("Replace forwarded secrets with explicit Runtrue secret requests.".to_owned()),
            );
        }
        let explicit_runner_image = job
            .container
            .as_ref()
            .and_then(|value| self.convert_job_container(value, &format!("{path}.container")));
        let mut runner_image = match (
            explicit_runner_image,
            effects.container_action_image.clone(),
        ) {
            (Some(_), Some(_)) => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "nested-container-action",
                    format!("{path}.container"),
                    "a Docker container action cannot be flattened into a separate GitHub job container",
                    Some("Remove the job container or move the container action into its own job.".to_owned()),
                );
                None
            }
            (explicit, action) => explicit.or(action),
        };
        if effects.wasm_component && runner_image.is_some() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "mixed-wasm-and-oci-job",
                &path,
                "a Wasm component action cannot share a job with an OCI job container",
                Some("Place the component action in its own job.".to_owned()),
            );
            runner_image = None;
        }
        if runner_image.is_none() && !effects.wasm_component {
            if let Some(image) = self.default_job_container_image.clone() {
                if is_full_sha256_image(&image) {
                    self.lock_images.insert(GeneratedImageLock {
                        source: image.clone(),
                        resolved: image.clone(),
                        platform: "linux/amd64".to_owned(),
                    });
                    self.finding(
                        CompatibilityStatus::Supported,
                        "operator-default-job-container",
                        format!("{path}.runs-on"),
                        "hosted Linux runner maps to the installation's pinned OCI fallback image",
                        None,
                    );
                    runner_image = Some(image);
                } else {
                    self.finding(
                        CompatibilityStatus::Unsafe,
                        "mutable-default-job-container",
                        format!("{path}.runs-on"),
                        "the installation OCI fallback image is not pinned to a full lowercase sha256 digest",
                        Some("Configure an immutable installation OCI fallback image.".to_owned()),
                    );
                }
            }
        }
        for (field, value, code, message) in [
            (
                "defaults",
                job.defaults.as_ref(),
                "job-defaults",
                "GitHub run defaults are not imported implicitly",
            ),
            (
                "environment",
                job.environment.as_ref(),
                "github-environment",
                "GitHub Environment approvals and secrets require GitHub",
            ),
            (
                "continue-on-error",
                job.continue_on_error.as_ref(),
                "job-continue-on-error",
                "job-level continue-on-error is not implemented",
            ),
        ] {
            if value.is_some() {
                let status = if field == "environment" {
                    CompatibilityStatus::RequiresGithub
                } else {
                    CompatibilityStatus::Unsupported
                };
                self.finding(
                    status,
                    code,
                    format!("{path}.{field}"),
                    message,
                    Some(format!(
                        "Replace `{path}.{field}` with explicit native workflow policy."
                    )),
                );
            }
        }

        let runner = self.convert_runner(
            job.runs_on.as_ref(),
            &format!("{path}.runs-on"),
            effects.runner_capabilities.iter().cloned().collect(),
            runner_image,
            effects.wasm_component,
        );
        effects.permissions.network_destinations = effects.network_destinations;
        effects.permissions.allow_private_network = effects.allow_private_network;
        let permission_state = effects.permissions.clone();
        ConvertedJob {
            job: NativeJob {
                name,
                needs,
                condition,
                runner,
                permissions: effects.permissions.native(),
                timeout,
                concurrency,
                matrix,
                vars,
                services,
                steps,
                outputs: effects.outputs,
            },
            permission_state,
        }
    }

    pub(crate) fn convert_concurrency(
        &mut self,
        value: Option<&YamlValue>,
        path: &str,
    ) -> Option<String> {
        let value = value?;
        let (group, cancel_in_progress) = match value {
            YamlValue::String(group) => (group.as_str(), false),
            YamlValue::Mapping(mapping) => {
                let group = mapping
                    .get(YamlValue::String("group".to_owned()))
                    .and_then(YamlValue::as_str);
                let cancel = mapping
                    .get(YamlValue::String("cancel-in-progress".to_owned()))
                    .and_then(YamlValue::as_bool)
                    .unwrap_or(false);
                let Some(group) = group else {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "github-concurrency-group",
                        format!("{path}.group"),
                        "concurrency group must be a non-empty string",
                        Some(format!("Set `{path}.group` to a stable string.")),
                    );
                    return None;
                };
                (group, cancel)
            }
            _ => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "github-concurrency-group",
                    path,
                    "concurrency must be a string or a group mapping",
                    Some(format!("Set `{path}` to a stable group string.")),
                );
                return None;
            }
        };

        if cancel_in_progress {
            self.finding(
                CompatibilityStatus::Unsupported,
                "github-concurrency-cancellation",
                format!("{path}.cancel-in-progress"),
                "cancel-in-progress cannot be preserved by Runtrue's signed job scheduler",
                Some("Set `cancel-in-progress: false`.".to_owned()),
            );
            return None;
        }

        let static_group = group
            .split("${{")
            .next()
            .unwrap_or_default()
            .trim()
            .trim_end_matches(['-', '_', '.', '/'])
            .to_owned();
        if static_group.is_empty() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "github-concurrency-expression",
                format!("{path}.group"),
                "a concurrency group must have a stable prefix",
                Some(format!(
                    "Prefix `{path}.group` with a stable workflow-specific name."
                )),
            );
            return None;
        }

        let message = if has_expression(group) {
            "dynamic GitHub concurrency maps to a conservative repository-scoped Runtrue group"
        } else {
            "GitHub concurrency maps to a repository-scoped Runtrue scheduler group"
        };
        self.finding(
            CompatibilityStatus::Emulated,
            "repository-scoped-concurrency",
            path,
            message,
            None,
        );
        Some(static_group)
    }

    pub(crate) fn convert_needs(&mut self, value: Option<&YamlValue>, path: &str) -> Vec<String> {
        let Some(value) = value else {
            return Vec::new();
        };
        let values = if let Some(value) = value.as_str() {
            vec![value.to_owned()]
        } else if let Some(sequence) = value.as_sequence() {
            sequence
                .iter()
                .filter_map(|item| {
                    let Some(value) = item.as_str() else {
                        self.dynamic_or_unsupported(
                            item,
                            path,
                            "needs entries must be static job ids",
                        );
                        return None;
                    };
                    Some(value.to_owned())
                })
                .collect()
        } else {
            self.dynamic_or_unsupported(value, path, "needs must be a static job id or list");
            Vec::new()
        };
        let mut result = Vec::new();
        for needed in values {
            if has_expression(&needed) || !valid_identifier(&needed) {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "dynamic-or-invalid-needs",
                    path,
                    format!("dependency `{needed}` is not a static native job id"),
                    Some(format!("Replace `{needed}` with a static valid job id.")),
                );
            } else {
                result.push(needed);
            }
        }
        if !result.is_empty() {
            self.finding(
                CompatibilityStatus::Supported,
                "job-needs",
                path,
                "static GitHub needs map exactly to native DAG dependencies",
                None,
            );
        }
        result
    }

    pub(crate) fn convert_condition(
        &mut self,
        value: Option<&YamlValue>,
        path: &str,
    ) -> Option<String> {
        let value = value?;
        let condition = if let Some(value) = value.as_bool() {
            Some(value.to_string())
        } else if let Some(value) = value.as_str() {
            let trimmed = value.trim();
            if matches!(trimmed, "true" | "false") {
                Some(trimmed.to_owned())
            } else {
                None
            }
        } else {
            None
        };
        if condition.is_some() {
            self.finding(
                CompatibilityStatus::Supported,
                "static-condition",
                path,
                "static boolean condition maps to a native condition",
                None,
            );
        } else {
            self.dynamic_or_unsupported(
                value,
                path,
                "only static boolean GitHub conditions are importable",
            );
        }
        condition
    }

    pub(crate) fn convert_timeout(
        &mut self,
        value: Option<&YamlValue>,
        path: &str,
    ) -> Option<String> {
        let value = value?;
        if let Some(minutes) = positive_u64(value) {
            self.finding(
                CompatibilityStatus::Supported,
                "timeout",
                path,
                "GitHub timeout-minutes maps to a native duration",
                None,
            );
            Some(format!("{minutes}m"))
        } else {
            self.dynamic_or_unsupported(value, path, "timeout-minutes must be a positive integer");
            None
        }
    }

    pub(crate) fn convert_runner(
        &mut self,
        value: Option<&YamlValue>,
        path: &str,
        mut capabilities: Vec<String>,
        image: Option<String>,
        wasm_component: bool,
    ) -> NativeRunner {
        capabilities.sort();
        let labels = value.and_then(static_runner_labels);
        match labels {
            Some(labels) if labels.iter().any(|label| label == "self-hosted") => {
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "self-hosted-runner",
                    path,
                    "self-hosted runner labels can request unreviewed host capabilities",
                    Some(
                        "Select an isolated native runner profile with explicit capabilities."
                            .to_owned(),
                    ),
                );
            }
            Some(labels)
                if labels.len() == 1
                    && (labels[0] == "ubuntu-latest" || labels[0].starts_with("ubuntu-")) =>
            {
                let isolation = if image.is_some() {
                    "OCI job"
                } else {
                    "microVM"
                };
                self.finding(
                    CompatibilityStatus::Emulated,
                    "hosted-runner-image",
                    path,
                    format!("GitHub runner `{}` maps to a Runtrue linux/amd64 {isolation}; the hosted image toolset may differ", labels[0]),
                    None,
                );
            }
            Some(labels) if labels.iter().any(|label| label.starts_with("windows-")) => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "windows-runner",
                    path,
                    "Windows GitHub hosted runners are not implemented by this importer",
                    Some("Move the job to a supported Linux runner or author native Windows runner requirements.".to_owned()),
                );
            }
            Some(labels) if labels.iter().any(|label| label.starts_with("macos-")) => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "macos-runner",
                    path,
                    "macOS GitHub hosted runners are not implemented by this importer",
                    Some("Move the job to a supported Linux runner or author native macOS runner requirements.".to_owned()),
                );
            }
            Some(labels) => {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "runner-labels",
                    path,
                    format!(
                        "runner labels `{}` have no approved native profile",
                        labels.join(", ")
                    ),
                    Some("Select ubuntu-latest or an explicit native runner profile.".to_owned()),
                );
            }
            None => {
                if let Some(value) = value {
                    self.dynamic_or_unsupported(
                        value,
                        path,
                        "runs-on must be a supported static runner label",
                    );
                } else {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "missing-runner",
                        path,
                        "job does not declare runs-on",
                        Some("Declare a supported static runner.".to_owned()),
                    );
                }
            }
        }
        NativeRunner {
            os: "linux",
            arch: "amd64",
            isolation: if wasm_component {
                "wasm"
            } else if image.is_some() {
                "oci"
            } else {
                "microvm"
            },
            // A repository component is bounded by the WASM executor rather
            // than by the GitHub-hosted VM profile named in `runs-on`.
            // Declare that smaller profile explicitly so the native workflow
            // does not inherit the AST's 4 GiB microVM default and get
            // rejected by the executor's 256 MiB ceiling.
            cpu: wasm_component.then_some(1),
            memory: wasm_component.then_some("256MiB"),
            image,
            capabilities,
        }
    }

    pub(crate) fn convert_job_container(
        &mut self,
        value: &YamlValue,
        path: &str,
    ) -> Option<String> {
        let (image_value, extra_fields) = if value.as_mapping().is_some() {
            let Some(mut mapping) = yaml_string_map(value) else {
                self.dynamic_or_unsupported(
                    value,
                    path,
                    "job container must be a static image or mapping with an image field",
                );
                return None;
            };
            let image = mapping.remove("image");
            (image, mapping)
        } else {
            (Some(value), BTreeMap::new())
        };

        let mut unsupported_options = false;
        for (field, option) in extra_fields {
            unsupported_options = true;
            let text = yaml_text(option);
            let unsafe_option = matches!(field.as_str(), "credentials" | "volumes")
                || has_privileged_or_host_feature(&text);
            self.finding(
                if unsafe_option {
                    CompatibilityStatus::Unsafe
                } else {
                    CompatibilityStatus::Unsupported
                },
                if unsafe_option {
                    "unsafe-job-container-option"
                } else {
                    "job-container-option"
                },
                format!("{path}.{field}"),
                format!("GitHub job container option `{field}` is not represented by native OCI runner requirements"),
                Some(format!(
                    "Remove `{path}.{field}` and express the requirement through reviewed native workflow fields."
                )),
            );
        }

        let Some(image_value) = image_value else {
            self.finding(
                CompatibilityStatus::Unsupported,
                "missing-job-container-image",
                format!("{path}.image"),
                "job container mapping does not declare an image",
                Some(format!("Declare a pinned `{path}.image` value.")),
            );
            return None;
        };
        let Some(image) = static_string(image_value) else {
            self.dynamic_or_unsupported(
                image_value,
                &format!("{path}.image"),
                "job container image must be a static immutable reference",
            );
            return None;
        };
        if !is_full_sha256_image(&image) {
            self.finding(
                CompatibilityStatus::Unsafe,
                "mutable-job-container-image",
                format!("{path}.image"),
                format!(
                    "job container image `{image}` is not pinned to a full lowercase sha256 digest"
                ),
                Some(format!("Pin `{image}` as name@sha256:<64 lowercase hex>.")),
            );
            return None;
        }
        if unsupported_options {
            return None;
        }

        self.lock_images.insert(GeneratedImageLock {
            source: image.clone(),
            resolved: image.clone(),
            platform: "linux/amd64".to_owned(),
        });
        self.finding(
            CompatibilityStatus::Supported,
            "pinned-job-container-image",
            format!("{path}.image"),
            "immutable job container maps to the exact native OCI runner image lock",
            None,
        );
        Some(image)
    }

    pub(crate) fn convert_matrix(
        &mut self,
        strategy: Option<&GithubStrategy>,
        path: &str,
    ) -> BTreeMap<String, Vec<ast::Scalar>> {
        let Some(strategy) = strategy else {
            return BTreeMap::new();
        };
        self.unsupported_extras(path, &strategy.extra);
        if let Some(value) = &strategy.fail_fast {
            if value.as_bool().is_some() {
                self.finding(
                    CompatibilityStatus::Emulated,
                    "matrix-fail-fast",
                    format!("{path}.fail-fast"),
                    "matrix values are preserved, but GitHub's sibling-cancellation timing is not part of the native capsule",
                    None,
                );
            } else {
                self.dynamic_or_unsupported(
                    value,
                    &format!("{path}.fail-fast"),
                    "fail-fast must be a static boolean",
                );
            }
        }
        if let Some(value) = &strategy.max_parallel {
            self.dynamic_or_unsupported(
                value,
                &format!("{path}.max-parallel"),
                "matrix max-parallel scheduling is not represented in native workflow syntax",
            );
        }
        let Some(matrix) = &strategy.matrix else {
            return BTreeMap::new();
        };
        let Some(mapping) = yaml_string_map(matrix) else {
            self.dynamic_or_unsupported(
                matrix,
                &format!("{path}.matrix"),
                "matrix must be a static mapping of axes to scalar lists",
            );
            return BTreeMap::new();
        };
        let mut native = BTreeMap::new();
        for (axis, values) in mapping {
            let axis_path = format!("{path}.matrix.{axis}");
            if matches!(axis.as_str(), "include" | "exclude") {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "matrix-include-exclude",
                    axis_path,
                    format!("matrix `{axis}` transformations are not implemented"),
                    Some(
                        "Expand include/exclude entries into explicit static native axes or jobs."
                            .to_owned(),
                    ),
                );
                continue;
            }
            if !valid_identifier(&axis) {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-matrix-axis",
                    &axis_path,
                    "matrix axis is not a native identifier",
                    Some(format!("Rename matrix axis `{axis}`.")),
                );
                continue;
            }
            let Some(sequence) = values.as_sequence() else {
                self.dynamic_or_unsupported(
                    values,
                    &axis_path,
                    "matrix axis values must be a static scalar sequence",
                );
                continue;
            };
            let mut converted = Vec::new();
            for (index, value) in sequence.iter().enumerate() {
                if let Some(value) = self.convert_scalar(value, &format!("{axis_path}[{index}]")) {
                    converted.push(value);
                }
            }
            if converted.is_empty() {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "empty-matrix-axis",
                    &axis_path,
                    "matrix axis has no importable values",
                    Some(format!("Provide at least one static value for `{axis}`.")),
                );
            } else {
                native.insert(axis.clone(), converted);
                self.finding(
                    CompatibilityStatus::Supported,
                    "static-matrix-axis",
                    axis_path,
                    "static matrix axis maps exactly to native matrix expansion",
                    None,
                );
            }
        }
        native
    }

    pub(crate) fn convert_services(
        &mut self,
        services: &BTreeMap<String, GithubService>,
        path: &str,
    ) -> BTreeMap<String, NativeService> {
        let mut native = BTreeMap::new();
        for (service_id, service) in services {
            let service_path = format!("{path}.{service_id}");
            self.unsupported_extras(&service_path, &service.extra);
            if !valid_identifier(service_id) {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "invalid-service-id",
                    &service_path,
                    "service id is not a native identifier",
                    Some(format!("Rename service `{service_id}`.")),
                );
            }
            if service.image.is_none() {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "missing-service-image",
                    format!("{service_path}.image"),
                    "service does not declare an image",
                    Some("Declare a service image pinned by a full sha256 digest.".to_owned()),
                );
            }
            let image = service
                .image
                .as_ref()
                .and_then(|value| {
                    self.convert_service_image(value, &format!("{service_path}.image"))
                })
                .unwrap_or_else(|| "invalid@sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned());
            let env = self.convert_env(&service.env, &format!("{service_path}.env"));
            let mut ports = Vec::new();
            for (index, port) in service.ports.iter().enumerate() {
                if let Some(port) =
                    self.convert_service_port(port, &format!("{service_path}.ports[{index}]"))
                {
                    ports.push(port);
                }
            }
            if let Some(options) = &service.options {
                let text = yaml_text(options);
                let unsafe_feature = has_privileged_or_host_feature(&text);
                self.finding(
                    if unsafe_feature {
                        CompatibilityStatus::Unsafe
                    } else {
                        CompatibilityStatus::Unsupported
                    },
                    if unsafe_feature {
                        "privileged-service-options"
                    } else {
                        "service-options"
                    },
                    format!("{service_path}.options"),
                    "Docker service options are not passed through to native isolated services",
                    Some(
                        "Remove service options and use native ports, env, and healthcheck fields."
                            .to_owned(),
                    ),
                );
            }
            if service.credentials.is_some() {
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "service-registry-credentials",
                    format!("{service_path}.credentials"),
                    "raw GitHub service registry credentials cannot be imported",
                    Some(
                        "Use a native registry credential capability without embedding values."
                            .to_owned(),
                    ),
                );
            }
            if service.volumes.is_some() {
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "service-host-volume",
                    format!("{service_path}.volumes"),
                    "service volume mounts can expose host or workspace paths",
                    Some(
                        "Remove host volumes and use declared native artifact or cache paths."
                            .to_owned(),
                    ),
                );
            }
            native.insert(service_id.clone(), NativeService { image, ports, env });
        }
        native
    }

    pub(crate) fn convert_service_image(
        &mut self,
        value: &YamlValue,
        path: &str,
    ) -> Option<String> {
        let Some(image) = static_string(value) else {
            self.dynamic_or_unsupported(
                value,
                path,
                "service image must be a static immutable reference",
            );
            return None;
        };
        if !is_full_sha256_image(&image) {
            self.finding(
                CompatibilityStatus::Unsafe,
                "mutable-service-image",
                path,
                format!("service image `{image}` is not pinned to a full lowercase sha256 digest"),
                Some(format!("Pin `{image}` as name@sha256:<64 lowercase hex>.")),
            );
            return None;
        }
        self.lock_images.insert(GeneratedImageLock {
            source: image.clone(),
            resolved: image.clone(),
            platform: "linux/amd64".to_owned(),
        });
        self.finding(
            CompatibilityStatus::Supported,
            "pinned-service-image",
            path,
            "immutable service image is preserved through an exact native lock requirement",
            None,
        );
        Some(image)
    }

    pub(crate) fn convert_service_port(&mut self, value: &YamlValue, path: &str) -> Option<u16> {
        let parsed = if let Some(port) = positive_u64(value) {
            u16::try_from(port).ok()
        } else if let Some(value) = value.as_str() {
            if has_expression(value) {
                None
            } else if let Some((host, container)) = value.split_once(':') {
                if host == container {
                    container.parse::<u16>().ok()
                } else {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "service-port-remap",
                        path,
                        "native service ports do not preserve differing host/container port remaps",
                        Some(format!("Use the same host and container port at `{path}`.")),
                    );
                    return None;
                }
            } else {
                value.parse::<u16>().ok()
            }
        } else {
            None
        };
        if let Some(port) = parsed.filter(|port| *port != 0) {
            self.finding(
                CompatibilityStatus::Supported,
                "service-port",
                path,
                "static service port maps to a native isolated service port",
                None,
            );
            Some(port)
        } else {
            self.dynamic_or_unsupported(
                value,
                path,
                "service port must be a static value from 1 through 65535",
            );
            None
        }
    }
}
