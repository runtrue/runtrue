use serde_json::Value;
use std::fs;
use tempfile::tempdir;

mod support;
use support::*;

#[test]
fn unsupported_local_features_fail_before_any_step_runs() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("services.yaml");
    let image = "docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fs::write(
        &workflow,
        format!(
            r#"
version: 1
jobs:
  build:
    trust: trusted-only
    runner: {{ isolation: native }}
    services:
      database:
        image: "{image}"
    steps:
      - run: {{ command: ["/bin/echo", "must-not-run"] }}
"#,
        ),
    )
    .unwrap();
    fs::write(
        directory.path().join(".runtrue.lock"),
        format!(
            r#"lock_version = 1
[[image]]
source = "{image}"
resolved = "{image}"
platform = "linux/amd64"
"#
        ),
    )
    .unwrap();
    let result = runtrue()
        .current_dir(directory.path())
        .args(["run", "build", "--workflow"])
        .arg(workflow)
        .arg("--allow-native")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(10));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("must-not-run"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("service containers"));
}

#[test]
fn unavailable_context_is_rejected_before_earlier_steps_can_run() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("context.yaml");
    let marker = directory.path().join("must-not-exist");
    fs::write(
        &workflow,
        format!(
            r#"
version: 1
jobs:
  build:
    trust: trusted-only
    runner: {{ isolation: native }}
    steps:
      - run: {{ command: ["/usr/bin/touch", "{}"] }}
      - run:
          command: ["/bin/echo"]
          args:
            - from: inputs.message
"#,
            marker.display()
        ),
    )
    .unwrap();
    let result = runtrue()
        .current_dir(directory.path())
        .args(["run", "build", "--workflow"])
        .arg(workflow)
        .arg("--allow-native")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(10));
    assert!(!marker.exists());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("cannot be passed to process arguments")
    );
}

#[test]
fn validate_capsule_and_run_fail_closed_on_malformed_lockfiles() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("workflow.yaml");
    fs::write(
        &workflow,
        r#"version: 1
jobs:
  build:
    trust: trusted-only
    runner: { isolation: native }
    steps:
      - run: { command: ["/bin/true"] }
"#,
    )
    .unwrap();
    fs::write(
        directory.path().join(".runtrue.lock"),
        "lock_version = 1\nunknown_security_field = true\n",
    )
    .unwrap();

    for command in ["validate", "capsule", "run"] {
        let mut invocation = runtrue();
        invocation
            .current_dir(directory.path())
            .arg(command)
            .args(["--workflow"])
            .arg(&workflow)
            .arg("--json");
        if command == "run" {
            invocation.arg("--allow-native");
        }
        let output = invocation.output().unwrap();
        assert_eq!(output.status.code(), Some(10), "{command}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["code"], "invalid_lockfile", "{command}");
    }
}

#[test]
fn validate_capsule_and_run_require_lock_entries_for_external_references() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("workflow.yaml");
    fs::write(
        &workflow,
        r#"version: 1
jobs:
  build:
    trust: trusted-only
    runner: { isolation: native }
    steps:
      - uses: wasm://registry.example/action@v1
"#,
    )
    .unwrap();

    for command in ["validate", "capsule", "run"] {
        let mut invocation = runtrue();
        invocation
            .current_dir(directory.path())
            .arg(command)
            .args(["--workflow"])
            .arg(&workflow)
            .arg("--json");
        if command == "run" {
            invocation.arg("--allow-native");
        }
        let output = invocation.output().unwrap();
        assert_eq!(output.status.code(), Some(10), "{command}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("validated lockfile is required"),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
