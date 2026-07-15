use super::{ActionMapping, Analyzer, JobEffects};
use crate::{
    analyzer::{has_secret_expression, positive_u64, static_string},
    native::{NativeCommand, NativeOutput, NativeRun, NativeStepCapabilities},
    report::CompatibilityStatus,
    validation::{normalize_relative, safe_relative_path, valid_identifier, yaml_text},
};
use runtrue_workflow_ast as ast;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

impl Analyzer {
    pub(crate) fn map_upload_artifact(
        &mut self,
        reference: &str,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        let mut name = "artifact".to_owned();
        let mut artifact_path = None;
        let mut retention = "7d".to_owned();
        for (input, value) in inputs {
            let input_path = format!("{path}.with.{input}");
            match input.as_str() {
                "name" => {
                    if let Some(value) = static_string(value) {
                        name = value;
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "artifact name must be static",
                        );
                    }
                }
                "path" => {
                    let Some(value) = static_string(value) else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "artifact path must be static",
                        );
                        continue;
                    };
                    if value.lines().count() == 1
                        && !value.contains(['*', '?', '[', ']'])
                        && safe_relative_path(&value, false)
                    {
                        artifact_path = Some(normalize_relative(&value));
                    } else {
                        self.finding(
                            CompatibilityStatus::Unsupported,
                            "artifact-path-set",
                            &input_path,
                            "native job output mapping requires one static repository-relative path without globs",
                            Some("Replace the upload path set with one native output path.".to_owned()),
                        );
                    }
                }
                "retention-days" => {
                    if let Some(days) = positive_u64(value).filter(|days| *days <= 90) {
                        retention = format!("{days}d");
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "retention-days must be a static integer from 1 through 90",
                        );
                    }
                }
                "if-no-files-found" => {
                    if static_string(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "artifact-missing-policy",
                            input_path,
                            "native artifact capture reports missing declared outputs but does not reproduce every GitHub warning mode",
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "artifact missing-file policy must be static",
                        );
                    }
                }
                "compression-level" | "overwrite" | "include-hidden-files" => {
                    if static_string(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "artifact-option",
                            input_path,
                            format!("artifact input `{input}` is handled by native artifact storage with different packaging semantics"),
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "artifact option must be a static scalar",
                        );
                    }
                }
                _ => self.finding(
                    CompatibilityStatus::Unsupported,
                    "unknown-upload-artifact-input",
                    input_path,
                    format!("upload-artifact input `{input}` is not implemented"),
                    Some(format!("Remove unsupported artifact input `{input}`.")),
                ),
            }
        }
        if !valid_identifier(&name) {
            self.finding(
                CompatibilityStatus::Unsupported,
                "invalid-artifact-name",
                format!("{path}.with.name"),
                format!("artifact name `{name}` is not a native output identifier"),
                Some(
                    "Use a 1-64 character letter/underscore-prefixed artifact identifier."
                        .to_owned(),
                ),
            );
        }
        if artifact_path.is_none() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "missing-artifact-path",
                format!("{path}.with.path"),
                "upload-artifact has no importable path",
                Some("Provide one static repository-relative artifact path.".to_owned()),
            );
        }
        match effects.outputs.entry(name) {
            std::collections::btree_map::Entry::Occupied(entry) => self.finding(
                CompatibilityStatus::Unsupported,
                "duplicate-artifact-name",
                format!("{path}.with.name"),
                format!(
                    "native job output `{}` is declared more than once",
                    entry.key()
                ),
                Some("Give each uploaded artifact a unique native identifier.".to_owned()),
            ),
            std::collections::btree_map::Entry::Vacant(entry) => {
                if let Some(artifact_path) = &artifact_path {
                    entry.insert(NativeOutput {
                        path: artifact_path.clone(),
                        retention,
                        classification: "untrusted-build",
                    });
                }
            }
        }
        effects.permissions.artifacts = effects.permissions.artifacts.max(ast::Access::Write);
        self.finding(
            CompatibilityStatus::Emulated,
            "native-artifact-output",
            format!("{path}.uses"),
            format!("`{reference}` maps to a native immutable job artifact output"),
            None,
        );
        ActionMapping {
            run: NativeRun::Command(NativeCommand {
                command: vec!["true".to_owned()],
                working_directory: None,
            }),
            env: Default::default(),
            cache: None,
            capabilities: Some(NativeStepCapabilities {
                cache: None,
                artifacts: Some(ast::Access::Write),
                secrets: Vec::new(),
            }),
            mapped: artifact_path.is_some(),
        }
    }

    pub(crate) fn map_download_artifact(
        &mut self,
        reference: &str,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
    ) -> ActionMapping {
        for (input, value) in inputs {
            let input_path = format!("{path}.with.{input}");
            if matches!(
                input.as_str(),
                "name"
                    | "path"
                    | "pattern"
                    | "merge-multiple"
                    | "github-token"
                    | "repository"
                    | "run-id"
            ) {
                let status = if input.contains("token") || has_secret_expression(&yaml_text(value))
                {
                    CompatibilityStatus::Unsafe
                } else {
                    CompatibilityStatus::RequiresGithub
                };
                self.finding(
                    status,
                    "download-artifact-input",
                    input_path,
                    format!("download-artifact input `{input}` depends on GitHub run-artifact lookup/materialization"),
                    Some("Replace download-artifact with a declared native dependency artifact binding.".to_owned()),
                );
            } else {
                self.finding(
                    CompatibilityStatus::Unsupported,
                    "unknown-download-artifact-input",
                    input_path,
                    format!("download-artifact input `{input}` is not implemented"),
                    Some(format!("Remove unsupported artifact input `{input}`.")),
                );
            }
        }
        self.finding(
            CompatibilityStatus::RequiresGithub,
            "github-artifact-download",
            format!("{path}.uses"),
            format!("`{reference}` needs GitHub's artifact service and run lookup API"),
            Some("Replace it with a native dependency artifact binding.".to_owned()),
        );
        ActionMapping::placeholder()
    }
}
