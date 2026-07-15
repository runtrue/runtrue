use super::*;
#[test]
fn yaml_merge_keys_cannot_inject_typed_job_fields() {
    let source = r#"
on: push
jobs:
  template: &defaults
    runs-on: ubuntu-latest
    steps:
      - run: "true"
  test:
    <<: *defaults
"#;
    let result = import_github_actions(source, "merge.yml").unwrap();
    assert!(!result.report.compatible);
    assert!(result.native_yaml.is_none());
    assert!(result.report.findings.iter().any(|finding| {
        finding.path == "jobs.test.<<" && finding.code == "unknown-field" && finding.blocking
    }));
}

#[test]
fn empty_builtin_action_selector_is_not_treated_as_a_native_builtin() {
    let source = r#"
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: "actions/checkout@"
"#;
    let result = import_github_actions(source, "empty-selector.yml").unwrap();
    assert!(!result.report.compatible);
    assert!(result.native_yaml.is_none());
    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "invalid-action-reference"
            && finding.path == "jobs.test.steps[0].uses"
            && finding.blocking
    }));
}

#[test]
fn github_only_and_pinned_unresolved_actions_do_not_invent_digests() {
    let result = import_github_actions(GITHUB_ONLY, "github-only.yml").unwrap();
    assert!(!result.report.compatible);
    assert!(result.native_yaml.is_none());
    assert!(result.lockfile_toml.is_none());
    for code in ["github-artifact-download", "unresolved-pinned-action"] {
        assert!(result.report.findings.iter().any(|finding| {
            finding.code == code
                && finding.status == CompatibilityStatus::RequiresGithub
                && finding.blocking
        }));
    }
}

#[test]
fn unknown_fields_are_not_silently_dropped() {
    let source = r#"
name: unknown
on: push
unexpected-root: true
jobs:
  test:
    runs-on: ubuntu-latest
    mystery-job: value
    steps:
      - run: "true"
        mystery-step: value
"#;
    let result = import_github_actions(source, "unknown.yml").unwrap();
    assert!(!result.report.compatible);
    assert!(result.native_yaml.is_none());
    for path in [
        "workflow.unexpected-root",
        "jobs.test.mystery-job",
        "jobs.test.steps[0].mystery-step",
    ] {
        assert!(result.report.findings.iter().any(|finding| {
            finding.path == path
                && finding.code == "unknown-field"
                && finding.status == CompatibilityStatus::Unsupported
        }));
    }
}

#[test]
fn source_size_is_bounded() {
    let source = "x".repeat(MAX_GITHUB_WORKFLOW_BYTES + 1);
    assert!(matches!(
        import_github_actions(&source, "large.yml"),
        Err(ImportError::TooLarge)
    ));
}

#[test]
fn multiple_yaml_documents_are_rejected() {
    let source = "name: first\non: push\njobs: {}\n---\nname: second\n";
    let error = import_github_actions(source, "multi.yml")
        .unwrap_err()
        .to_string();
    assert!(error.contains("exactly one YAML document"), "{error}");
}
