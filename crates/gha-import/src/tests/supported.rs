use super::*;
#[test]
fn report_has_stable_machine_and_human_status_names() {
    let result = import_github_actions(UNSAFE, "unsafe.yml").unwrap();
    for (status, expected) in [
        (CompatibilityStatus::Supported, "\"SUPPORTED\""),
        (CompatibilityStatus::Emulated, "\"EMULATED\""),
        (CompatibilityStatus::RequiresGithub, "\"REQUIRES_GITHUB\""),
        (CompatibilityStatus::Unsafe, "\"UNSAFE\""),
        (CompatibilityStatus::Unsupported, "\"UNSUPPORTED\""),
    ] {
        assert_eq!(serde_json::to_string(&status).unwrap(), expected);
    }
    let human = result.report.render_human();
    assert!(human.contains("Overall compatibility:"));
    assert!(human.contains("Required changes:"));
    assert!(human.contains("[UNSAFE]"));
}

#[test]
fn operator_default_container_maps_hosted_linux_job_to_oci() {
    let image = format!("registry.example/runtrue-runner@sha256:{}", "a".repeat(64));
    let result = import_github_actions_with_options(
        "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ok\n",
        "fallback.github.yml",
        ImportOptions {
            default_job_container_image: Some(image.clone()),
        },
    )
    .expect("import");
    let workflow = ast::parse_yaml(result.native_yaml.as_deref().expect("native workflow"))
        .expect("parse native workflow");
    assert_eq!(workflow.jobs["test"].runner.isolation, ast::Isolation::Oci);
    assert_eq!(
        workflow.jobs["test"].runner.image.as_deref(),
        Some(image.as_str())
    );
    assert!(result
        .report
        .findings
        .iter()
        .any(|finding| { finding.code == "operator-default-job-container" && !finding.blocking }));
}
