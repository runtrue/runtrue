use super::{ActionMapping, Analyzer, JobEffects};
use crate::{
    analyzer::{has_privileged_or_host_feature, static_string},
    report::CompatibilityStatus,
    validation::yaml_text,
};
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

impl Analyzer {
    pub(crate) fn map_setup_buildx(
        &mut self,
        reference: &str,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        for (input, value) in inputs {
            let input_path = format!("{path}.with.{input}");
            match input.as_str() {
                "install" | "use" | "cleanup" if static_string(value).is_some() => {
                    self.finding(
                        CompatibilityStatus::Emulated,
                        "buildx-setup-option",
                        input_path,
                        format!("Buildx setup option `{input}` is replaced by the selected native BuildKit runner capability"),
                        None,
                    );
                }
                "driver" | "driver-opts" | "buildkitd-flags" | "buildkitd-config" | "endpoint"
                | "platforms" | "append" | "cache-binary" => {
                    let text = yaml_text(value);
                    let status = if has_privileged_or_host_feature(&text) {
                        CompatibilityStatus::Unsafe
                    } else {
                        CompatibilityStatus::Unsupported
                    };
                    self.finding(
                        status,
                        "buildx-runtime-option",
                        input_path,
                        format!("Buildx runtime option `{input}` cannot modify the isolated native BuildKit service"),
                        Some("Remove custom Buildx daemon/driver configuration and use an approved native BuildKit profile.".to_owned()),
                    );
                }
                _ => self.finding(
                    CompatibilityStatus::Unsupported,
                    "unknown-buildx-input",
                    input_path,
                    format!("setup-buildx input `{input}` is not implemented"),
                    Some(format!("Remove setup-buildx input `{input}`.")),
                ),
            }
        }
        effects.runner_capabilities.insert("buildkit".to_owned());
        self.finding(
            CompatibilityStatus::Emulated,
            "native-buildkit-setup",
            format!("{path}.uses"),
            format!("`{reference}` maps to an isolated native BuildKit runner capability"),
            None,
        );
        ActionMapping::noop(true)
    }
}
