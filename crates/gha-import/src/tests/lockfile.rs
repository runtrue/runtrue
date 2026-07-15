use super::*;
#[test]
fn supported_workflow_emits_compiler_validated_native_yaml_and_exact_lock() {
    let result = import_github_actions(SUPPORTED, "supported.yml").unwrap();
    assert!(result.report.compatible, "{}", result.report.render_human());
    assert!(result.report.native_ast_validated);
    assert!(result.report.schema_validated);
    assert!(result.report.compiler_validated);
    assert_eq!(result.report.mapped_jobs, 2);
    assert_eq!(result.report.mapped_steps, 6);

    let yaml = result.native_yaml.as_deref().expect("native YAML");
    let workflow = ast::parse_yaml(yaml).unwrap();
    assert_eq!(workflow.jobs.len(), 2);
    assert_eq!(workflow.jobs["prepare"].needs, Vec::<String>::new());
    assert_eq!(workflow.jobs["image"].needs, vec!["prepare"]);
    assert_eq!(workflow.jobs["image"].matrix.len(), 1);
    assert_eq!(workflow.jobs["prepare"].services.len(), 1);
    assert_eq!(workflow.jobs["prepare"].outputs.len(), 1);

    let lock_text = result.lockfile_toml.as_deref().expect("service lock");
    let lock = LockFile::parse(lock_text.as_bytes()).unwrap();
    assert_eq!(lock.images().len(), 1);
    assert_eq!(
        lock.images()[0].source(),
        "postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(lock.images()[0].source(), lock.images()[0].resolved());
    assert!(!lock_text.contains("0123456789abcdef"));

    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "native-buildkit-build" && finding.status == CompatibilityStatus::Emulated
    }));
    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "cache-key-semantics" && finding.status == CompatibilityStatus::Emulated
    }));
}

#[test]
fn pinned_job_containers_become_locked_oci_runner_images_only_for_container_jobs() {
    let image = format!("registry.example/build@sha256:{}", "c".repeat(64));
    let source = format!(
        r#"
on: push
jobs:
  container:
    runs-on: ubuntu-latest
    container:
      image: {image}
    steps:
      - run: "true"
  host:
    runs-on: ubuntu-latest
    steps:
      - run: "true"
"#
    );
    let result = import_github_actions(&source, "container.yml").unwrap();
    assert!(result.report.compatible, "{}", result.report.render_human());
    assert!(result.report.compiler_validated);

    let workflow = ast::parse_yaml(result.native_yaml.as_deref().unwrap()).unwrap();
    assert_eq!(
        workflow.jobs["container"].runner.isolation,
        ast::Isolation::Oci
    );
    assert_eq!(
        workflow.jobs["container"].runner.image.as_deref(),
        Some(image.as_str())
    );
    assert_eq!(
        workflow.jobs["host"].runner.isolation,
        ast::Isolation::Microvm
    );
    assert_eq!(workflow.jobs["host"].runner.image, None);

    let lock = LockFile::parse(result.lockfile_toml.as_deref().unwrap().as_bytes()).unwrap();
    assert_eq!(lock.images().len(), 1);
    assert_eq!(lock.images()[0].source(), image);
    assert_eq!(lock.images()[0].resolved(), image);
    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "pinned-job-container-image"
            && finding.status == CompatibilityStatus::Supported
    }));
}

#[test]
fn mutable_or_optioned_job_containers_do_not_emit_runner_images() {
    for (container, expected_code) in [
            ("container: registry.example/build:latest", "mutable-job-container-image"),
            (
                "container:\n      image: registry.example/build@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n      volumes: [/host:/work]",
                "unsafe-job-container-option",
            ),
        ] {
            let source = format!(
                "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    {container}\n    steps:\n      - run: \"true\"\n"
            );
            let result = import_github_actions(&source, "blocked-container.yml").unwrap();
            assert!(!result.report.compatible);
            assert!(result.native_yaml.is_none());
            assert!(result.lockfile_toml.is_none());
            assert!(
                result.report.findings.iter().any(|finding| {
                    finding.code == expected_code && finding.blocking
                }),
                "missing {expected_code}: {}",
                result.report.render_human()
            );
        }
}

#[test]
fn pinned_docker_actions_use_the_exact_oci_image_and_generic_entrypoint() {
    let image = format!(
        "registry.example/runtrue/scm-automation@sha256:{}",
        "d".repeat(64)
    );
    let source = format!(
        r#"
on: push
permissions:
  contents: read
jobs:
  reconcile:
    runs-on: ubuntu-24.04
    steps:
      - uses: docker://{image}
        with:
          config-path: .runtrue/scm-automation.yml
"#
    );
    let result = import_github_actions(&source, "scm-automation.yml").unwrap();
    assert!(result.report.compatible, "{}", result.report.render_human());
    assert!(result.report.compiler_validated);
    let yaml = result.native_yaml.as_deref().unwrap();
    let workflow = ast::parse_yaml(yaml).unwrap();
    assert_eq!(
        workflow.jobs["reconcile"].runner.image.as_deref(),
        Some(image.as_str())
    );
    assert!(yaml.contains("/usr/local/bin/runtrue-action"));
    assert!(yaml.contains("INPUT_CONFIG_PATH"));
    let lock = LockFile::parse(result.lockfile_toml.as_deref().unwrap().as_bytes()).unwrap();
    assert_eq!(lock.images()[0].source(), image);
    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "pinned-container-action" && finding.status == CompatibilityStatus::Emulated
    }));
}

#[test]
fn scoped_container_actions_can_report_commit_and_pull_request_status() {
    let image = format!("registry.example/runtrue/review@sha256:{}", "e".repeat(64));
    let source = format!(
        r#"
on: pull_request
permissions:
  contents: read
  pull-requests: write
  checks: write
  statuses: write
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/build.sh
        shell: bash
      - uses: docker://{image}
        with:
          github-token: ${{{{ github.token }}}}
"#
    );
    let result = import_github_actions(&source, "review.yml").unwrap();
    assert!(result.report.compatible, "{}", result.report.render_human());
    assert!(result.report.compiler_validated);

    let yaml = result.native_yaml.as_deref().expect("native YAML");
    let workflow = ast::parse_yaml(yaml).unwrap();
    assert_eq!(workflow.permissions.scm.contents, ast::Access::Read);
    assert_eq!(workflow.permissions.scm.pull_requests, ast::Access::Write);
    assert_eq!(workflow.permissions.scm.checks, ast::Access::Write);
    assert_eq!(workflow.permissions.scm.statuses, ast::Access::Write);
    assert!(yaml.contains("runtrue-scm-provider-token"));
    assert!(yaml.contains("/workspace/.runtrue-runtime/scm-token"));
    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "native-checkout" && finding.status == CompatibilityStatus::Emulated
    }));
    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "static-run-step" && finding.status == CompatibilityStatus::Supported
    }));
}
