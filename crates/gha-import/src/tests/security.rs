use super::*;
#[test]
fn unsafe_features_are_all_reported_and_block_output() {
    let result = import_github_actions(UNSAFE, "unsafe.yml").unwrap();
    assert!(!result.report.compatible);
    assert!(result.native_yaml.is_none());
    for code in [
        "pull-request-target-source-execution",
        "self-hosted-runner",
        "mutable-service-image",
        "privileged-service-options",
        "expression-shell-injection",
        "privileged-shell-feature",
        "mutable-third-party-action",
        "unresolved-action-input",
    ] {
        assert!(
            result
                .report
                .findings
                .iter()
                .any(|finding| finding.code == code),
            "missing {code}: {}",
            result.report.render_human()
        );
    }
    assert!(result
        .report
        .findings
        .iter()
        .filter(|finding| finding.status == CompatibilityStatus::Unsafe)
        .all(|finding| finding.blocking));
}

#[test]
fn duplicate_keys_fail_before_typed_deserialization() {
    let error = import_github_actions(DUPLICATE, "duplicate.yml")
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate mapping key `VALUE`"), "{error}");
}

#[test]
fn yaml_alias_expansion_and_recursion_are_bounded() {
    let mut alias_bomb = String::from("x0: &x0 [a, a]\n");
    for depth in 1..=17 {
        alias_bomb.push_str(&format!(
            "x{depth}: &x{depth} [*x{}, *x{}]\n",
            depth - 1,
            depth - 1
        ));
    }
    let error = import_github_actions(&alias_bomb, "aliases.yml")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("expanded YAML exceeds") || error.contains("repetition limit exceeded"),
        "{error}"
    );

    let deeply_nested = format!("value: {}null{}\n", "[".repeat(140), "]".repeat(140));
    let error = import_github_actions(&deeply_nested, "deep.yml")
        .unwrap_err()
        .to_string();
    assert!(error.contains("recursion limit exceeded"), "{error}");
}

#[test]
fn alternate_secret_context_syntax_and_dynamic_ignored_inputs_block_output() {
    let source = r#"
name: "${{ secrets['WORKFLOW_NAME'] }}"
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: "${{ github [ 'token' ] }}"
        uses: actions/cache@v4
        with:
          path: target
          key: stable
          lookup-only: "${{ secrets [ 'CACHE_MODE' ] }}"
"#;
    let result = import_github_actions(source, "secret-context.yml").unwrap();
    assert!(!result.report.compatible);
    assert!(result.native_yaml.is_none());
    for path in [
        "name",
        "jobs.test.steps[0].name",
        "jobs.test.steps[0].with.lookup-only",
    ] {
        assert!(
            result.report.findings.iter().any(|finding| {
                finding.path == path
                    && finding.code == "raw-github-secret"
                    && finding.status == CompatibilityStatus::Unsafe
                    && finding.blocking
            }),
            "missing unsafe finding for {path}: {}",
            result.report.render_human()
        );
    }

    let dynamic = source.replace(
        "${{ secrets [ 'CACHE_MODE' ] }}",
        "${{ matrix.lookup_only }}",
    );
    let result = import_github_actions(&dynamic, "dynamic-option.yml").unwrap();
    assert!(!result.report.compatible);
    assert!(result.report.findings.iter().any(|finding| {
        finding.path == "jobs.test.steps[0].with.lookup-only"
            && finding.code == "dynamic-expression"
            && finding.blocking
    }));
}
