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
    assert!(yaml.contains("container:"));
    assert!(yaml.contains("INPUT_CONFIG-PATH"));
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

#[test]
fn full_commit_repository_docker_action_uses_trusted_prepared_image() {
    let commit = "a".repeat(40);
    let reference = format!("ci/backport@{commit}");
    let image = format!(
        "containers.example/runtrue/action-cache@sha256:{}",
        "b".repeat(64)
    );
    let source = format!(
        r#"
on: pull_request_target
permissions:
  contents: write
  pull-requests: write
jobs:
  reconcile:
    runs-on: ubuntu-24.04
    steps:
      - uses: {reference}
        with:
          config-path: .github/backport.yml
"#
    );
    let result = import_github_actions_with_options(
        &source,
        "backport.yml",
        ImportOptions {
            resolved_repository_actions: std::collections::BTreeMap::from([(
                reference.clone(),
                runtrue_workflow_frontend::ResolvedRepositoryAction {
                    program: runtrue_workflow_frontend::ResolvedRepositoryProgram::Container {
                        image: image.clone(),
                        entrypoint: Some("/bin/backport".to_owned()),
                        args: Some(vec![
                            "--config".to_owned(),
                            "${{ inputs.config-path }}".to_owned(),
                        ]),
                    },
                    inputs: std::collections::BTreeMap::from([(
                        "config-path".to_owned(),
                        runtrue_workflow_frontend::ResolvedActionInput {
                            required: false,
                            default: Some(".github/default.yml".to_owned()),
                        },
                    )]),
                },
            )]),
            ..ImportOptions::default()
        },
    )
    .unwrap();
    assert!(result.report.compatible, "{}", result.report.render_human());
    assert!(result.report.compiler_validated);
    let yaml = result.native_yaml.as_deref().unwrap();
    let workflow = ast::parse_yaml(yaml).unwrap();
    assert_eq!(
        workflow.jobs["reconcile"].runner.image.as_deref(),
        Some(reference.as_str())
    );
    let lock = LockFile::parse(result.lockfile_toml.as_deref().unwrap().as_bytes()).unwrap();
    assert_eq!(lock.images()[0].source(), reference);
    assert_eq!(lock.images()[0].resolved(), image);
    let ast::Run::Container(invocation) = workflow.jobs["reconcile"].steps[0]
        .run
        .as_ref()
        .expect("container invocation")
    else {
        panic!("expected container invocation");
    };
    assert_eq!(
        invocation.container.entrypoint.as_deref(),
        Some("/bin/backport")
    );
    assert_eq!(
        invocation.container.args.as_deref(),
        Some(
            [
                ast::ValueBinding::Scalar(ast::Scalar::String("--config".to_owned())),
                ast::ValueBinding::Scalar(ast::Scalar::String(".github/backport.yml".to_owned())),
            ]
            .as_slice()
        )
    );
    assert!(yaml.contains("INPUT_CONFIG-PATH"));
    assert!(result.report.findings.iter().any(|finding| {
        finding.code == "pinned-repository-docker-action"
            && finding.status == CompatibilityStatus::Emulated
    }));
}

#[test]
fn repository_action_requires_missing_inputs_and_applies_metadata_defaults() {
    let reference = format!("owner/action@{}", "a".repeat(40));
    let image = format!("registry.example/action@sha256:{}", "b".repeat(64));
    let action = runtrue_workflow_frontend::ResolvedRepositoryAction {
        program: runtrue_workflow_frontend::ResolvedRepositoryProgram::Container {
            image,
            entrypoint: None,
            args: None,
        },
        inputs: std::collections::BTreeMap::from([
            (
                "optional".to_owned(),
                runtrue_workflow_frontend::ResolvedActionInput {
                    required: false,
                    default: Some("fallback".to_owned()),
                },
            ),
            (
                "required".to_owned(),
                runtrue_workflow_frontend::ResolvedActionInput {
                    required: true,
                    default: None,
                },
            ),
        ]),
    };
    let source = format!(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {reference}\n"
    );
    let result = import_github_actions_with_options(
        &source,
        "required.yml",
        ImportOptions {
            resolved_repository_actions: std::collections::BTreeMap::from([(
                reference.clone(),
                action.clone(),
            )]),
            ..ImportOptions::default()
        },
    )
    .unwrap();
    assert!(!result.report.compatible);
    assert!(result
        .report
        .findings
        .iter()
        .any(|finding| { finding.code == "missing-required-action-input" && finding.blocking }));

    let source = format!(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {reference}\n        with:\n          required: supplied\n"
    );
    let result = import_github_actions_with_options(
        &source,
        "defaults.yml",
        ImportOptions {
            resolved_repository_actions: std::collections::BTreeMap::from([(reference, action)]),
            ..ImportOptions::default()
        },
    )
    .unwrap();
    assert!(result.report.compatible, "{}", result.report.render_human());
    let yaml = result.native_yaml.as_deref().expect("native YAML");
    assert!(yaml.contains("INPUT_OPTIONAL: fallback"));
    assert!(yaml.contains("INPUT_REQUIRED: supplied"));
}

#[test]
fn repository_component_action_maps_to_wasm_with_an_exact_lock() {
    let source_reference = format!("ci/backport@{}", "a".repeat(40));
    let digest = "b".repeat(64);
    let component = format!("wasm://ghcr.io/runtrue/backport@sha256:{digest}");
    let source = format!(
        r#"on: push
permissions:
  contents: write
  issues: write
  pull-requests: write
jobs:
  backport:
    runs-on: ubuntu-latest
    steps:
      - uses: {source_reference}
        with:
          config-path: .github/backport.yml
          github-token: ${{{{ github.token }}}}
"#
    );
    let result = import_github_actions_with_options(
        &source,
        "component.yml",
        ImportOptions {
            resolved_repository_actions: std::collections::BTreeMap::from([(
                source_reference,
                runtrue_workflow_frontend::ResolvedRepositoryAction {
                    program: runtrue_workflow_frontend::ResolvedRepositoryProgram::Component {
                        reference: component.clone(),
                        scm_api_url: "https://github.example.test/api/v3".to_owned(),
                        signature_identity: "release@runtrue.dev".to_owned(),
                        wit_world: "runtrue:action/run@1.0.0".to_owned(),
                    },
                    inputs: std::collections::BTreeMap::from([
                        (
                            "config-path".to_owned(),
                            runtrue_workflow_frontend::ResolvedActionInput {
                                required: false,
                                default: Some(".github/backport.yml".to_owned()),
                            },
                        ),
                        (
                            "github-token".to_owned(),
                            runtrue_workflow_frontend::ResolvedActionInput {
                                required: false,
                                default: None,
                            },
                        ),
                    ]),
                },
            )]),
            ..ImportOptions::default()
        },
    )
    .unwrap();
    assert!(result.report.compatible, "{}", result.report.render_human());
    let yaml = result.native_yaml.as_deref().unwrap();
    let workflow = ast::parse_yaml(yaml).unwrap();
    let job = &workflow.jobs["backport"];
    assert_eq!(job.runner.isolation, ast::Isolation::Wasm);
    assert_eq!(job.runner.cpu, 1);
    assert_eq!(job.runner.memory, "256MiB");
    assert_eq!(job.steps[0].uses.as_deref(), Some(component.as_str()));
    let network = job.steps[0]
        .capabilities
        .network
        .as_ref()
        .expect("repository component has an exact SCM endpoint");
    assert_eq!(network.dns, ast::DnsPolicy::Restricted);
    assert!(!network.deny_private_ranges);
    assert_eq!(network.allow.len(), 1);
    assert_eq!(network.allow[0].host, "github.example.test");
    assert_eq!(network.allow[0].port, 443);
    assert!(job.steps[0].run.is_none());
    let lock = LockFile::parse(result.lockfile_toml.as_deref().unwrap().as_bytes()).unwrap();
    assert_eq!(lock.components()[0].source(), component);
    assert_eq!(
        lock.components()[0].resolved().as_str(),
        format!("sha256:{digest}")
    );
    assert!(yaml.contains("github.example.test"));
}
