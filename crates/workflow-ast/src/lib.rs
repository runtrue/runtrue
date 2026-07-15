//! Strict syntax tree for native Runtrue workflow version 1.
//!
//! All security-relevant objects deny unknown fields. Semantic checks such as
//! DAG validity, immutable references, and path safety live in the compiler.

mod bindings;
mod error;
mod jobs;
mod map;
mod outputs;
mod parse;
mod permissions;
mod runners;
mod services;
mod steps;
mod triggers;
mod workflow;

pub use bindings::*;
pub use error::*;
pub use jobs::*;
pub use map::*;
pub use outputs::*;
pub use parse::*;
pub use permissions::*;
pub use runners::*;
pub use services::*;
pub use steps::*;
pub use triggers::*;
pub use workflow::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_permission_fails_closed() {
        let source = r#"
version: 1
permissions:
  repository: read
  root-shell: write
jobs:
  test:
    steps:
      - run: { command: ["true"] }
"#;
        assert!(parse_yaml(source).is_err());
    }

    #[test]
    fn integer_scalars_are_valid() {
        let source = r#"
version: 1
vars: { ATTEMPTS: 3 }
jobs:
  test:
    steps:
      - run: { command: ["true"] }
"#;
        let workflow = parse_yaml(source).unwrap();
        assert_eq!(workflow.vars["ATTEMPTS"], Scalar::Integer(3));
    }

    #[test]
    fn duplicate_dynamic_mapping_keys_fail_closed() {
        let duplicate_jobs = r#"
version: 1
jobs:
  test:
    steps: [{ run: { command: ["true"] } }]
  test:
    steps: [{ run: { command: ["false"] } }]
"#;
        let error = parse_yaml(duplicate_jobs).unwrap_err().to_string();
        assert!(error.contains("duplicate mapping key `test`"), "{error}");

        let duplicate_environment = r#"
version: 1
jobs:
  test:
    steps:
      - env:
          VALUE: first
          VALUE: second
        run: { command: ["true"] }
"#;
        let error = parse_yaml(duplicate_environment).unwrap_err().to_string();
        assert!(error.contains("duplicate mapping key `VALUE`"), "{error}");
    }

    #[test]
    fn integers_outside_the_exact_ir_range_are_rejected() {
        for value in ["9223372036854775808", "9223372036854775809"] {
            let source = format!(
                "version: 1\nvars: {{ VALUE: {value} }}\njobs:\n  test:\n    steps: [{{ run: {{ command: [\"true\"] }} }}]\n"
            );
            let error = parse_yaml(&source).unwrap_err().to_string();
            assert!(error.contains("signed 64-bit range"), "{error}");
        }
    }

    #[test]
    fn default_permissions_are_deny() {
        let source =
            "version: 1\njobs:\n  test:\n    steps:\n      - run: { command: [\"true\"] }\n";
        let workflow = parse_yaml(source).unwrap();
        assert_eq!(workflow.permissions.repository, Access::Deny);
        assert!(matches!(
            workflow.runner_default_isolation(),
            Isolation::Microvm
        ));
        assert!(workflow.permissions.signing.is_empty());
        assert!(workflow.jobs["test"].steps[0]
            .capabilities
            .signing
            .is_empty());
    }

    #[test]
    fn signing_key_policy_is_explicit_at_job_and_step_scope() {
        let source = r#"
version: 1
permissions:
  signing:
    - purpose: release-artifact
      operation: sign-digest
      key-policy: production-release-v1
jobs:
  publish:
    steps:
      - capabilities:
          signing:
            - purpose: release-artifact
              operation: sign-digest
              key-policy: production-release-v1
        run: { command: ["true"] }
"#;
        let workflow = parse_yaml(source).unwrap();
        assert_eq!(
            workflow.permissions.signing[0].key_policy,
            "production-release-v1"
        );
        assert_eq!(
            workflow.jobs["publish"].steps[0].capabilities.signing,
            workflow.permissions.signing
        );
    }

    #[test]
    fn alias_expansion_is_bounded_before_ast_allocation() {
        let repeated = "x".repeat(4_096);
        let aliases = std::iter::repeat_n("*large", 2_100)
            .collect::<Vec<_>>()
            .join(", ");
        let source = format!(
            "version: 1\nvars:\n  anchor: &large {repeated}\njobs:\n  test:\n    matrix:\n      value: [{aliases}]\n    steps: [{{ run: {{ command: [\"true\"] }} }}]\n"
        );
        assert!(source.len() < 1024 * 1024);
        let error = parse_yaml(&source).unwrap_err().to_string();
        assert!(error.contains("expanded YAML exceeds"), "{error}");
    }

    #[test]
    fn reusable_call_and_typed_interface_parse_strictly() {
        let source = r#"
version: 1
inputs:
  mode: { type: choice, options: [fast, full], default: fast }
outputs:
  bundle: { from: needs.call.outputs.bundle }
jobs:
  call:
    uses: git+https://example.test/workflows.git//build.yaml@v1
    with: { release: true, attempts: 2 }
"#;
        let workflow = parse_yaml(source).unwrap();
        assert_eq!(workflow.inputs["mode"].kind, InputType::Choice);
        assert_eq!(workflow.outputs["bundle"].from, "needs.call.outputs.bundle");
        assert_eq!(
            workflow.jobs["call"].uses.as_deref(),
            Some("git+https://example.test/workflows.git//build.yaml@v1")
        );
        assert!(workflow.jobs["call"].steps.is_empty());

        let unknown = source.replace("with: {", "with: {\n      unexpected: { value: true },");
        assert!(parse_yaml(&unknown).is_err());
    }

    impl Workflow {
        fn runner_default_isolation(&self) -> Isolation {
            self.jobs.values().next().unwrap().runner.isolation
        }
    }
}
