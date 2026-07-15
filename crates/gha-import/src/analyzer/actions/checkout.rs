use super::{ActionMapping, Analyzer, JobEffects};
use crate::{analyzer::static_string, report::CompatibilityStatus};
use runtrue_workflow_ast as ast;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

impl Analyzer {
    pub(crate) fn map_checkout(
        &mut self,
        reference: &str,
        inputs: &BTreeMap<String, YamlValue>,
        path: &str,
        effects: &mut JobEffects,
    ) -> ActionMapping {
        for (name, value) in inputs {
            let input_path = format!("{path}.with.{name}");
            match name.as_str() {
                "fetch-depth"
                | "fetch-tags"
                | "lfs"
                | "submodules"
                | "clean"
                | "show-progress"
                | "set-safe-directory"
                | "sparse-checkout-cone-mode" => {
                    if static_string(value).is_some() {
                        self.finding(
                            CompatibilityStatus::Emulated,
                            "checkout-option",
                            input_path,
                            format!("checkout option `{name}` is recorded but native repository materialization may differ"),
                            None,
                        );
                    } else {
                        self.dynamic_or_unsupported(
                            value,
                            &input_path,
                            "checkout input must be static",
                        );
                    }
                }
                "token" | "ssh-key" => {
                    self.finding(
                        CompatibilityStatus::Unsafe,
                        "checkout-credential",
                        input_path,
                        "checkout credentials cannot be embedded or forwarded from GitHub",
                        Some("Use native SCM installation credentials with repository-read capability.".to_owned()),
                    );
                }
                "repository"
                | "ref"
                | "path"
                | "ssh-user"
                | "ssh-known-hosts"
                | "ssh-strict"
                | "persist-credentials"
                | "sparse-checkout"
                | "github-server-url" => {
                    self.finding(
                        CompatibilityStatus::RequiresGithub,
                        "checkout-repository-option",
                        input_path,
                        format!("checkout option `{name}` changes GitHub repository materialization semantics"),
                        Some("Express additional repository/ref materialization through the native SCM and lock model.".to_owned()),
                    );
                }
                _ => self.finding(
                    CompatibilityStatus::Unsupported,
                    "unknown-checkout-input",
                    input_path,
                    format!("checkout input `{name}` is not implemented"),
                    Some(format!("Remove unsupported checkout input `{name}`.")),
                ),
            }
        }
        effects.permissions.repository = effects.permissions.repository.max(ast::Access::Read);
        self.finding(
            CompatibilityStatus::Emulated,
            "native-checkout",
            format!("{path}.uses"),
            format!(
                "`{reference}` maps to Runtrue's verified, runner-local cached pre-step repository materialization"
            ),
            None,
        );
        ActionMapping::noop(true)
    }
}
