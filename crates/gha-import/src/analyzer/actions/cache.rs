use super::{ActionMapping, Analyzer, JobEffects};
use crate::{
    analyzer::static_string,
    native::{
        NativeCache, NativeCachePermissions, NativeCommand, NativeRun, NativeStepCapabilities,
    },
    report::CompatibilityStatus,
    validation::{merge_cache_read, merge_cache_write, normalize_relative, safe_relative_path},
};
use runtrue_workflow_ast as ast;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

impl Analyzer {
    pub(crate) fn map_cache(
        &mut self,
        reference: &str,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
        mode: &'static str,
    ) -> ActionMapping {
        let mut paths = Vec::new();
        let mut has_key = false;
        for (name, value) in inputs {
            let input_path = format!("{path}.with.{name}");
            match name.as_str() {
                "path" => {
                    let Some(value) = static_string(value) else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "cache path must be static",
                        );
                        continue;
                    };
                    for candidate in value.lines().map(str::trim).filter(|line| !line.is_empty()) {
                        if safe_relative_path(candidate, true) && !candidate.starts_with('~') {
                            paths.push(normalize_relative(candidate));
                        } else {
                            self.finding(
                                CompatibilityStatus::Unsafe,
                                "unsafe-cache-path",
                                &input_path,
                                format!("cache path `{candidate}` is not repository-relative"),
                                Some("Use repository-relative cache paths without traversal or home expansion.".to_owned()),
                            );
                        }
                    }
                }
                "key" => {
                    if let Some(key) = static_string(value) {
                        has_key = !key.is_empty();
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "cache-key-semantics",
                            &input_path,
                            "the static GitHub key is recorded in this report; native cache identity also binds capsule, platform, trust, and declared paths",
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(value, &input_path, "cache key must be static");
                    }
                }
                "restore-keys" => {
                    if static_string(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "cache-restore-prefix",
                            &input_path,
                            "GitHub restore-key prefix fallback is not identical to native trust-scoped fallback",
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "restore-keys must be static",
                        );
                    }
                }
                "fail-on-cache-miss" | "lookup-only" | "enableCrossOsArchive" => {
                    if static_string(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "cache-option",
                            &input_path,
                            format!("cache input `{name}` differs under the native cache adapter"),
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "cache option must be a static scalar",
                        );
                    }
                }
                _ => self.finding(
                    CompatibilityStatus::Unsupported,
                    "unknown-cache-input",
                    input_path,
                    format!("cache input `{name}` is not implemented"),
                    Some(format!("Remove unsupported cache input `{name}`.")),
                ),
            }
        }
        if paths.is_empty() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "missing-cache-path",
                format!("{path}.with.path"),
                "cache action has no safe static path",
                Some("Provide at least one repository-relative static cache path.".to_owned()),
            );
        }
        if !has_key {
            self.finding(
                CompatibilityStatus::Unsupported,
                "missing-cache-key",
                format!("{path}.with.key"),
                "cache action has no non-empty static key",
                Some("Provide a non-empty static cache key.".to_owned()),
            );
        }
        let (inputs_list, outputs_list, read, write) = match mode {
            "read-only" => (
                paths.clone(),
                Vec::new(),
                ast::CacheRead::Run,
                ast::CacheWrite::Deny,
            ),
            "write-only" => (
                Vec::new(),
                paths.clone(),
                ast::CacheRead::Deny,
                ast::CacheWrite::Quarantine,
            ),
            _ => (
                paths.clone(),
                paths.clone(),
                ast::CacheRead::Run,
                ast::CacheWrite::Quarantine,
            ),
        };
        effects.permissions.cache_read = merge_cache_read(effects.permissions.cache_read, read);
        effects.permissions.cache_write = merge_cache_write(effects.permissions.cache_write, write);
        self.finding(
            CompatibilityStatus::Emulated,
            "native-cache",
            format!("{path}.uses"),
            format!("`{reference}` maps to a native trust-scoped cache declaration"),
            None,
        );
        ActionMapping {
            run: NativeRun::Command(NativeCommand {
                command: vec!["true".to_owned()],
                working_directory: None,
            }),
            env: Default::default(),
            cache: Some(NativeCache {
                inputs: inputs_list,
                outputs: outputs_list,
                mode,
            }),
            capabilities: Some(NativeStepCapabilities {
                network: None,
                cache: Some(NativeCachePermissions { read, write }),
                artifacts: None,
                secrets: Vec::new(),
            }),
            mapped: !paths.is_empty() && has_key,
        }
    }
}
