use serde_json::Value;
use std::fs;
use tempfile::tempdir;

mod support;
use support::*;

#[test]
fn validate_and_capsule_report_the_same_digest() {
    let validate = runtrue()
        .args(["validate", "--workflow"])
        .arg(example_path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let validation: Value = serde_json::from_slice(&validate.stdout).unwrap();

    let capsule = runtrue()
        .args(["capsule", "smoke", "--workflow"])
        .arg(example_path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        capsule.status.success(),
        "{}",
        String::from_utf8_lossy(&capsule.stderr)
    );
    let capsule: Value = serde_json::from_slice(&capsule.stdout).unwrap();

    assert_eq!(
        validation["workflows"][0]["capsule_digest"],
        capsule["capsule_digest"]
    );
    assert_eq!(capsule["capsule"]["approval"]["privileged_execution"], true);
}

#[test]
fn capsule_output_contains_the_exact_canonical_hashed_bytes() {
    let directory = tempdir().unwrap();
    let output_path = directory.path().join("capsule.json");
    let output = runtrue()
        .args(["capsule", "smoke", "--workflow"])
        .arg(example_path())
        .arg("--output")
        .arg(&output_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let bytes = fs::read(output_path).unwrap();
    assert_eq!(
        runtrue_model::ContentDigest::sha256(&bytes).to_string(),
        report["capsule_digest"].as_str().unwrap()
    );
    let capsule: runtrue_workflow_ir::ExecutionCapsule = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(capsule.canonical_bytes().unwrap(), bytes);
}

#[test]
fn native_run_is_gated_and_then_executes_the_same_capsule() {
    let denied = runtrue()
        .args(["run", "smoke", "--workflow"])
        .arg(example_path())
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&denied.stderr).unwrap();
    assert_eq!(error["error"]["code"], "native_acknowledgement_required");
    assert_eq!(error["error"]["exit_code"], 10);

    let allowed = runtrue()
        .args(["run", "smoke", "--workflow"])
        .arg(example_path())
        .arg("--allow-native")
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let stdout = String::from_utf8(allowed.stdout).unwrap();
    assert!(stdout.contains("runtrue: local native smoke test"));
    assert!(stdout.contains("run: Succeeded"));
}

#[test]
fn replay_bundle_round_trips_and_compares_exact_capsule_identity() {
    let directory = tempdir().unwrap();
    let bundle = directory.path().join("run.replay.json");
    let recorded = runtrue()
        .current_dir(directory.path())
        .args(["run", "smoke", "--workflow"])
        .arg(example_path())
        .arg("--allow-native")
        .arg("--replay-bundle")
        .arg(&bundle)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let report: Value = serde_json::from_slice(&recorded.stdout).unwrap();
    assert!(report["replay_bundle_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let replayed = runtrue()
        .current_dir(directory.path())
        .arg("replay")
        .arg(&bundle)
        .args(["--allow-native", "--json"])
        .output()
        .unwrap();
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replay_report: Value = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(replay_report["outcome_matches"], true);

    let matching = runtrue()
        .current_dir(directory.path())
        .arg("compare-capsule")
        .arg(&bundle)
        .arg("smoke")
        .arg("--workflow")
        .arg(example_path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(matching.status.success());
    let comparison: Value = serde_json::from_slice(&matching.stdout).unwrap();
    assert_eq!(comparison["matches"], true);

    let mismatching = runtrue()
        .current_dir(directory.path())
        .arg("compare-capsule")
        .arg(&bundle)
        .arg("smoke")
        .arg("--workflow")
        .arg(example_path())
        .args(["--source-commit", "different"])
        .output()
        .unwrap();
    assert_eq!(mismatching.status.code(), Some(20));
}

#[test]
fn local_cache_round_trips_through_run_and_replay() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("cache.yaml");
    let bundle = directory.path().join("cache.replay.json");
    let host_arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    fs::write(directory.path().join("input.txt"), b"stable input").unwrap();
    fs::write(
        &workflow,
        format!(
            r#"
version: 1
permissions:
  network: deny
  cache: {{ read: run, write: quarantine }}
jobs:
  build:
    trust: trusted-only
    runner: {{ isolation: native, arch: {host_arch} }}
    steps:
      - id: build
        run:
          shell: sh
          script: |
            if [ -f build/output.txt ]; then
              printf cache-hit
            else
              mkdir -p build
              printf cached > build/output.txt
            fi
        capabilities:
          cache: {{ read: run, write: quarantine }}
        cache:
          inputs: [input.txt]
          outputs: [build/output.txt]
          mode: read-write
          max-size: 1MiB
"#
        ),
    )
    .unwrap();

    let recorded = runtrue()
        .current_dir(directory.path())
        .args(["run", "build", "--workflow"])
        .arg(&workflow)
        .arg("--allow-native")
        .arg("--replay-bundle")
        .arg(&bundle)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let envelope: Value = serde_json::from_slice(&fs::read(&bundle).unwrap()).unwrap();
    assert_eq!(
        envelope["bundle"]["cache_references"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    fs::remove_file(directory.path().join("build/output.txt")).unwrap();

    let replayed = runtrue()
        .current_dir(directory.path())
        .arg("replay")
        .arg(&bundle)
        .args(["--allow-native", "--json"])
        .output()
        .unwrap();
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let report: Value = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(
        report["result"]["jobs"]["build"]["attempts"][0]["steps"][0]["output"]["stdout"],
        "cache-hit"
    );
    assert_eq!(
        fs::read(directory.path().join("build/output.txt")).unwrap(),
        b"cached"
    );
}

#[test]
fn local_artifacts_are_reported_and_bound_into_replay() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("artifact.yaml");
    let bundle = directory.path().join("artifact.replay.json");
    let host_arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    fs::write(
        &workflow,
        format!(
            r#"
version: 1
permissions:
  network: deny
  artifacts: write
jobs:
  build:
    trust: trusted-only
    runner: {{ isolation: native, arch: {host_arch} }}
    steps:
      - id: build
        run:
          shell: sh
          script: |
            mkdir -p build
            printf durable > build/output.txt
    outputs:
      result:
        path: build/output.txt
        retention: 1d
        classification: untrusted-build
"#
        ),
    )
    .unwrap();

    let recorded = runtrue()
        .current_dir(directory.path())
        .args(["run", "build", "--workflow"])
        .arg(&workflow)
        .arg("--allow-native")
        .arg("--replay-bundle")
        .arg(&bundle)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let report: Value = serde_json::from_slice(&recorded.stdout).unwrap();
    let artifact_id = report["artifacts"][0]["artifact_id"].as_str().unwrap();
    assert!(artifact_id.starts_with("sha256:"));
    let envelope: Value = serde_json::from_slice(&fs::read(&bundle).unwrap()).unwrap();
    assert_eq!(
        envelope["bundle"]["artifact_references"][0],
        report["artifacts"][0]["artifact_id"]
    );

    let replayed = runtrue()
        .current_dir(directory.path())
        .arg("replay")
        .arg(&bundle)
        .args(["--allow-native", "--json"])
        .output()
        .unwrap();
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replay_report: Value = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(
        replay_report["recorded_artifact_references"][0],
        artifact_id
    );
    assert!(replay_report["artifacts"][0]["artifact_id"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn missing_declared_artifact_fails_the_run_after_successful_job() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("missing-artifact.yaml");
    let host_arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    fs::write(
        &workflow,
        format!(
            r#"
version: 1
permissions:
  network: deny
  artifacts: write
jobs:
  build:
    trust: trusted-only
    runner: {{ isolation: native, arch: {host_arch} }}
    steps:
      - run: {{ command: ["/bin/true"] }}
    outputs:
      missing:
        path: build/missing
        retention: 1d
        classification: untrusted-build
"#
        ),
    )
    .unwrap();
    let output = runtrue()
        .current_dir(directory.path())
        .args(["run", "build", "--workflow"])
        .arg(workflow)
        .args(["--allow-native", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(20));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "artifact_capture_failed");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("does not exist"));
}

#[test]
fn replay_requires_exact_canonical_file_bytes() {
    let directory = tempdir().unwrap();
    let bundle = directory.path().join("run.replay.json");
    let recorded = runtrue()
        .current_dir(directory.path())
        .args(["run", "smoke", "--workflow"])
        .arg(example_path())
        .arg("--allow-native")
        .arg("--replay-bundle")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(recorded.status.success());
    let mut bytes = fs::read(&bundle).unwrap();
    bytes.push(b'\n');
    fs::write(&bundle, bytes).unwrap();

    let rejected = runtrue()
        .current_dir(directory.path())
        .arg("replay")
        .arg(bundle)
        .args(["--allow-native", "--json"])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&rejected.stderr).unwrap();
    assert_eq!(error["error"]["code"], "invalid_replay_bundle");
}

#[test]
fn doctor_reports_security_boundaries_without_mutating_workspace() {
    let directory = tempdir().unwrap();
    let output = runtrue()
        .current_dir(directory.path())
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["healthy"], true);
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["name"] == "native-execution" && check["status"] == "warn"));
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}
