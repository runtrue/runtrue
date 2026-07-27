use runtrue_compiler::MAX_REUSABLE_SOURCE_BYTES;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

mod support;
use support::*;

#[test]
fn reusable_store_hydrates_validate_capsule_run_and_compare_capsule() {
    let workspace = reusable_workspace(native_reusable_source());
    let validated = validate_reusable_workspace(&workspace);
    assert!(
        validated.status.success(),
        "{}",
        String::from_utf8_lossy(&validated.stderr)
    );

    let planned = runtrue()
        .current_dir(workspace.directory.path())
        .args(["capsule", "shared", "--workflow"])
        .arg(&workspace.workflow)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let capsule: Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(capsule["capsule"]["jobs"][0]["id"], "shared__build");

    let replay = workspace.directory.path().join("reusable.replay.json");
    let run = runtrue()
        .current_dir(workspace.directory.path())
        .args(["run", "shared", "--workflow"])
        .arg(&workspace.workflow)
        .arg("--allow-native")
        .arg("--replay-bundle")
        .arg(&replay)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let compared = runtrue()
        .current_dir(workspace.directory.path())
        .arg("compare-capsule")
        .arg(&replay)
        .arg("shared")
        .arg("--workflow")
        .arg(&workspace.workflow)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        compared.status.success(),
        "{}",
        String::from_utf8_lossy(&compared.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&compared.stdout).unwrap()["matches"],
        true
    );
}

#[test]
fn reusable_store_rejects_missing_tampered_symlink_insecure_and_extra_sources() {
    let missing = reusable_workspace(native_reusable_source());
    fs::remove_file(&missing.source_path).unwrap();
    let output = validate_reusable_workspace(&missing);
    assert_eq!(output.status.code(), Some(10));

    let tampered = reusable_workspace(native_reusable_source());
    fs::write(&tampered.source_path, b"tampered").unwrap();
    let output = validate_reusable_workspace(&tampered);
    assert_eq!(output.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&output.stderr).contains("digest mismatch"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let linked = reusable_workspace(native_reusable_source());
        let target = linked.directory.path().join("outside.yaml");
        fs::write(&target, native_reusable_source()).unwrap();
        fs::remove_file(&linked.source_path).unwrap();
        symlink(&target, &linked.source_path).unwrap();
        assert_eq!(validate_reusable_workspace(&linked).status.code(), Some(10));

        let insecure = reusable_workspace(native_reusable_source());
        fs::set_permissions(&insecure.source_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            validate_reusable_workspace(&insecure).status.code(),
            Some(10)
        );
    }

    let extra = reusable_workspace(native_reusable_source());
    fs::write(
        extra.source_path.parent().unwrap().join("extra.yaml"),
        b"extra",
    )
    .unwrap();
    let output = validate_reusable_workspace(&extra);
    assert_eq!(output.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected"));
}

#[test]
fn reusable_store_rejects_a_source_over_the_compiler_bound() {
    let oversized = vec![b' '; MAX_REUSABLE_SOURCE_BYTES + 1];
    let workspace = reusable_workspace(&oversized);
    let output = validate_reusable_workspace(&workspace);
    assert_eq!(output.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds"));
}

#[test]
fn cli_binds_canonical_lock_digest_instead_of_raw_toml_bytes() {
    let mut lock_digests = Vec::new();
    let mut raw_digests = Vec::new();
    for reversed in [false, true] {
        let directory = tempdir().unwrap();
        let workflow = directory.path().join("workflow.yaml");
        fs::write(
            &workflow,
            r#"version: 1
jobs:
  build:
    steps:
      - uses: wasm://registry.example/action@v1
"#,
        )
        .unwrap();
        let fields = if reversed {
            r#"wit_world = "runtrue:action/run@1.0.0"
signature_identity = "release@runtrue.example"
resolved = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
source = "wasm://registry.example/action@v1""#
        } else {
            r#"source = "wasm://registry.example/action@v1"
resolved = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
signature_identity = "release@runtrue.example"
wit_world = "runtrue:action/run@1.0.0""#
        };
        let lock = format!("lock_version = 1\n[[component]]\n{fields}\n");
        fs::write(directory.path().join(".runtrue.lock"), &lock).unwrap();
        raw_digests.push(runtrue_model::ContentDigest::sha256(lock.as_bytes()));
        let output = runtrue()
            .current_dir(directory.path())
            .args(["capsule", "--workflow"])
            .arg(&workflow)
            .arg("--json")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        lock_digests.push(
            report["capsule"]["context"]["lockfile_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_ne!(raw_digests[0], raw_digests[1]);
    assert_eq!(lock_digests[0], lock_digests[1]);
}

#[test]
fn incompatible_later_runner_is_rejected_before_any_job_runs() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("platform.yaml");
    let marker = directory.path().join("first-job-must-not-run");
    let (host_arch, other_arch) = if cfg!(target_arch = "aarch64") {
        ("arm64", "amd64")
    } else {
        ("amd64", "arm64")
    };
    fs::write(
        &workflow,
        format!(
            r#"
version: 1
jobs:
  a_first:
    trust: trusted-only
    runner: {{ isolation: native, arch: {host_arch} }}
    steps:
      - run: {{ command: ["/usr/bin/touch", "{}"] }}
  z_incompatible:
    trust: trusted-only
    runner: {{ isolation: native, arch: {other_arch} }}
    steps:
      - run: {{ command: ["/bin/true"] }}
"#,
            marker.display()
        ),
    )
    .unwrap();
    let result = runtrue()
        .current_dir(directory.path())
        .args(["run", "--workflow"])
        .arg(workflow)
        .arg("--allow-native")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(10));
    assert!(!marker.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("but this host is"));
}

#[test]
fn event_projection_is_bound_into_the_capsule_and_consumed_by_run() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("event.yaml");
    let event = directory.path().join("event.json");
    fs::write(
        &workflow,
        r#"
version: 1
jobs:
  event:
    trust: trusted-only
    runner: { isolation: native }
    if: event.run == true
    steps:
      - if: event.message == "bound event value"
        run:
          command: ["/bin/echo", "bound event condition matched"]
"#,
    )
    .unwrap();
    fs::write(
        &event,
        r#"{"run":true,"message":"bound event value","unused":"private projection noise"}"#,
    )
    .unwrap();

    let planned = runtrue()
        .current_dir(directory.path())
        .args(["capsule", "event", "--workflow"])
        .arg(&workflow)
        .arg("--event")
        .arg(&event)
        .arg("--json")
        .output()
        .unwrap();
    assert!(planned.status.success());
    let capsule: Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(
        capsule["capsule"]["context"]["event_context"]["event.message"],
        "bound event value"
    );
    assert_eq!(
        capsule["capsule"]["context"]["event_context"]["event.run"],
        true
    );
    assert!(capsule["capsule"]["context"]["event_context"]
        .get("event.unused")
        .is_none());

    let executed = runtrue()
        .current_dir(directory.path())
        .args(["run", "event", "--workflow"])
        .arg(workflow)
        .arg("--event")
        .arg(event)
        .arg("--allow-native")
        .output()
        .unwrap();
    assert!(executed.status.success());
    assert!(String::from_utf8_lossy(&executed.stdout).contains("bound event condition matched"));
}
