use super::{ActionMapping, Analyzer, JobEffects};
use crate::{
    analyzer::{has_expression, looks_like_secret_name, static_bool, static_string},
    native::{NativeCommand, NativeRun},
    report::CompatibilityStatus,
    validation::{normalize_relative, safe_relative_path},
};
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

impl Analyzer {
    pub(crate) fn map_docker_build(
        &mut self,
        reference: &str,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        let mut context = ".".to_owned();
        let mut dockerfile = "Dockerfile".to_owned();
        let mut extra_args = Vec::new();
        for (input, value) in inputs {
            let input_path = format!("{path}.with.{input}");
            match input.as_str() {
                "context" => {
                    let Some(value) = static_string(value) else {
                        self.dynamic_or_unsupported(value, &input_path, "Docker build context must be static");
                        continue;
                    };
                    if value == "." || safe_relative_path(&value, false) {
                        context = value;
                    } else {
                        self.finding(
                            CompatibilityStatus::Unsafe,
                            "unsafe-build-context",
                            input_path,
                            "Docker build context must stay within the repository",
                            Some("Use `.` or a repository-relative build context.".to_owned()),
                        );
                    }
                }
                "file" => {
                    let Some(value) = static_string(value) else {
                        self.dynamic_or_unsupported(value, &input_path, "Dockerfile path must be static");
                        continue;
                    };
                    if safe_relative_path(&value, false) {
                        dockerfile = normalize_relative(&value);
                    } else {
                        self.finding(
                            CompatibilityStatus::Unsafe,
                            "unsafe-dockerfile-path",
                            input_path,
                            "Dockerfile path must stay within the repository",
                            Some("Use a repository-relative Dockerfile path.".to_owned()),
                        );
                    }
                }
                "push" => match static_bool(value) {
                    Some(false) => {}
                    Some(true) => self.finding(
                        CompatibilityStatus::RequiresGithub,
                        "docker-registry-push",
                        input_path,
                        "pushing build output needs explicit native registry credentials and destination policy",
                        Some("Split build from a protected native publish job with registry-write permission.".to_owned()),
                    ),
                    None => self.dynamic_or_unsupported(value, &input_path, "push must be a static boolean"),
                },
                "load" => match static_bool(value) {
                    Some(false) => {}
                    Some(true) => self.finding(
                        CompatibilityStatus::Unsupported,
                        "docker-load",
                        input_path,
                        "loading into a mutable Docker daemon is not available in the isolated BuildKit mapping",
                        Some("Emit an OCI output or consume the build result through native artifacts.".to_owned()),
                    ),
                    None => self.dynamic_or_unsupported(value, &input_path, "load must be a static boolean"),
                },
                "platforms" => {
                    if let Some(value) = static_string(value) {
                        extra_args.push("--opt".to_owned());
                        extra_args.push(format!("platform={}", value.replace('\n', ",")));
                    } else {
                        self.dynamic_or_unsupported(value, &input_path, "platforms must be static");
                    }
                }
                "target" => {
                    if let Some(value) = static_string(value) {
                        extra_args.push("--opt".to_owned());
                        extra_args.push(format!("target={value}"));
                    } else {
                        self.dynamic_or_unsupported(value, &input_path, "target must be static");
                    }
                }
                "build-args" => {
                    let Some(value) = static_string(value) else {
                        self.dynamic_or_unsupported(value, &input_path, "build arguments must be static");
                        continue;
                    };
                    for argument in value.lines().map(str::trim).filter(|line| !line.is_empty()) {
                        let key = argument.split('=').next().unwrap_or_default();
                        if has_expression(argument) || looks_like_secret_name(key) {
                            self.finding(
                                CompatibilityStatus::Unsafe,
                                "secret-or-dynamic-build-arg",
                                &input_path,
                                format!("build argument `{key}` is secret-like or dynamic"),
                                Some("Use a reviewed non-secret static build argument or a native secret mount capability.".to_owned()),
                            );
                        } else {
                            extra_args.push("--opt".to_owned());
                            extra_args.push(format!("build-arg:{argument}"));
                        }
                    }
                }
                "tags" | "labels" | "annotations" => {
                    if static_string(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "build-metadata",
                            input_path,
                            format!("Docker `{input}` metadata is not a published object until a protected native publish step consumes the build result"),
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(value, &input_path, "build metadata must be static");
                    }
                }
                "no-cache" => match static_bool(value) {
                    Some(true) => extra_args.push("--no-cache".to_owned()),
                    Some(false) => {}
                    None => self.dynamic_or_unsupported(value, &input_path, "no-cache must be static"),
                },
                "pull" => {
                    if static_bool(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "build-pull-policy",
                            input_path,
                            "native BuildKit resolves base images under runner/network policy rather than GitHub's pull flag",
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "pull must be a static boolean",
                        );
                    }
                }
                "network" => {
                    if static_string(value).as_deref() == Some("none") {
                        extra_args.push("--opt".to_owned());
                        extra_args.push("network=none".to_owned());
                    } else {
                        self.finding(
                            CompatibilityStatus::Unsafe,
                            "docker-build-network",
                            input_path,
                            "Docker build network access cannot be inferred or passed through safely",
                            Some("Use network: none, or declare reviewed native network destinations.".to_owned()),
                        );
                    }
                }
                "secrets" | "secret-files" | "ssh" => {
                    self.finding(
                        CompatibilityStatus::Unsafe,
                        "docker-build-secret",
                        input_path,
                        format!("Docker build input `{input}` can expose credentials to build instructions"),
                        Some("Replace GitHub build secrets/SSH forwarding with an explicit native secret mount policy.".to_owned()),
                    );
                }
                "cache-from" | "cache-to" => {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "docker-cache-backend",
                        input_path,
                        "external Buildx cache backends do not map to native trust-scoped BuildKit snapshots",
                        Some("Remove external cache configuration and use the native trust-scoped BuildKit cache.".to_owned()),
                    );
                }
                "outputs" => {
                    self.finding(
                        CompatibilityStatus::Unsupported,
                        "docker-custom-output",
                        input_path,
                        "custom Buildx output exporters require an explicit native artifact/registry mapping",
                        Some("Replace custom outputs with a declared native artifact or protected registry publish step.".to_owned()),
                    );
                }
                "provenance" | "sbom" => {
                    if static_string(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "native-build-attestation",
                            input_path,
                            format!("`{input}` is replaced by Runtrue's capsule-bound attestation pipeline"),
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "attestation selection must be static",
                        );
                    }
                }
                "github-token" => self.finding(
                    CompatibilityStatus::Unsafe,
                    "github-build-token",
                    input_path,
                    "GitHub token forwarding into BuildKit is denied",
                    Some("Remove github-token and use explicit native SCM/registry capabilities.".to_owned()),
                ),
                _ => self.finding(
                    CompatibilityStatus::Unsupported,
                    "unknown-docker-build-input",
                    input_path,
                    format!("docker/build-push input `{input}` is not implemented"),
                    Some(format!("Remove unsupported Docker build input `{input}`.")),
                ),
            }
        }
        let dockerfile_directory = dockerfile
            .rsplit_once('/')
            .map_or(".".to_owned(), |(directory, _)| directory.to_owned());
        let dockerfile_name = dockerfile
            .rsplit_once('/')
            .map_or(dockerfile.as_str(), |(_, name)| name);
        let mut command = vec![
            "buildctl".to_owned(),
            "build".to_owned(),
            "--frontend".to_owned(),
            "dockerfile.v0".to_owned(),
            "--local".to_owned(),
            format!("context={context}"),
            "--local".to_owned(),
            format!("dockerfile={dockerfile_directory}"),
            "--opt".to_owned(),
            format!("filename={dockerfile_name}"),
        ];
        command.extend(extra_args);
        effects.runner_capabilities.insert("buildkit".to_owned());
        self.finding(
            CompatibilityStatus::Emulated,
            "native-buildkit-build",
            format!("{path}.uses"),
            format!("`{reference}` maps to isolated BuildKit through an explicit native runner capability"),
            None,
        );
        ActionMapping {
            run: NativeRun::Command(NativeCommand {
                command,
                working_directory: None,
            }),
            env: Default::default(),
            cache: None,
            capabilities: None,
            mapped: true,
        }
    }
}
