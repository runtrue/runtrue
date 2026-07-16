use super::*;
use runtrue_workflow_frontend::{WorkflowFrontendOptions, WorkflowSourceFrontend};

#[test]
fn github_frontend_is_deterministic_and_binds_translation_identity() {
    let source = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n";
    let options = WorkflowFrontendOptions {
        default_job_container_image: Some(format!(
            "registry.example/runtrue-ci@sha256:{}",
            "a".repeat(64)
        )),
        ..WorkflowFrontendOptions::default()
    };
    assert_eq!(
        GithubActionsFrontend.discovery_roots(),
        &[".github/workflows"]
    );
    let first = GithubActionsFrontend
        .prepare(source, ".github/workflows/ci.yml", &options)
        .unwrap();
    let second = GithubActionsFrontend
        .prepare(source, ".github/workflows/ci.yml", &options)
        .unwrap();

    first.validate_for(source).unwrap();
    second.validate_for(source).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.input_digest,
        runtrue_model::ContentDigest::sha256(source)
    );
    assert_eq!(
        first.native_digest,
        runtrue_model::ContentDigest::sha256(first.native_yaml.as_bytes())
    );
    let report = first.report.unwrap();
    assert_eq!(
        report.digest,
        runtrue_model::ContentDigest::sha256(&report.bytes)
    );
}

#[test]
fn explicit_runtrue_files_remain_native_inside_the_github_directory() {
    assert!(GithubActionsFrontend.supports(".github/workflows/ci.yml"));
    assert!(GithubActionsFrontend.supports("automation/ci.github.yaml"));
    assert!(!GithubActionsFrontend.supports(".github/workflows/native.runtrue.yaml"));
    assert!(!GithubActionsFrontend.supports(".github/workflows/release.runtrue.yml"));
}

#[test]
fn github_frontend_fails_closed_on_blocking_semantics() {
    let source = "name: unsafe\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: unknown/remote-action@main\n";
    let error = GithubActionsFrontend
        .prepare(
            source,
            ".github/workflows/deploy.yml",
            &WorkflowFrontendOptions::default(),
        )
        .unwrap_err();
    assert!(!error.is_empty());
}
