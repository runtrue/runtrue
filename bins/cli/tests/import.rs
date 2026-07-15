#![allow(unused_imports)]

use runtrue_compiler::{
    CompileContext, Compiler, ReusableWorkflowSource, ReusableWorkflowSources,
    MAX_REUSABLE_SOURCE_BYTES,
};
use runtrue_lock::LockFile;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::ExecutionCapsule;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};
use tempfile::tempdir;

mod support;
use support::*;

#[test]
fn github_import_writes_validated_native_yaml_lock_and_report() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("imported.yaml");
    let lockfile = directory.path().join(".runtrue.lock");
    let report = directory.path().join("compatibility.json");
    let output = runtrue()
        .args(["import", "github"])
        .arg(github_fixture("supported.yml"))
        .arg("--output")
        .arg(&workflow)
        .arg("--lock-output")
        .arg(&lockfile)
        .arg("--report-output")
        .arg(&report)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["report"]["compatible"], true);
    assert_eq!(result["report"]["schema_validated"], true);
    assert_eq!(result["report"]["native_ast_validated"], true);
    assert_eq!(result["report"]["compiler_validated"], true);
    assert!(result["native_yaml"]
        .as_str()
        .unwrap()
        .contains("version: 1"));

    let native = fs::read_to_string(workflow).unwrap();
    assert!(native.contains("buildkit"));
    assert!(native.contains("postgres@sha256:"));
    let lock = fs::read_to_string(lockfile).unwrap();
    assert!(lock.contains("[[image]]"));
    assert!(lock.contains(&"a".repeat(64)));
    let report: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert_eq!(report["compatible"], true);
}

#[test]
fn blocked_github_import_returns_validation_exit_without_native_output() {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("must-not-exist.yaml");
    let output = runtrue()
        .args(["import", "github"])
        .arg(github_fixture("unsafe.yml"))
        .arg("--output")
        .arg(&workflow)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["report"]["compatible"], false);
    assert!(result["native_yaml"].is_null());
    assert!(!workflow.exists());
    assert!(result["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["status"] == "UNSAFE"));
}

#[cfg(unix)]
#[test]
fn github_import_stages_every_output_before_publish_and_refuses_symlink_lock() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let workflow = directory.path().join("imported.yaml");
    let report = directory.path().join("compatibility.json");
    fs::write(&workflow, b"preserve-old-workflow").unwrap();

    let victim = directory.path().join("victim.lock");
    fs::write(&victim, b"preserve-lock-target").unwrap();
    let linked_lock = directory.path().join("linked.lock");
    symlink(&victim, &linked_lock).unwrap();

    let output = runtrue()
        .args(["import", "github"])
        .arg(github_fixture("supported.yml"))
        .arg("--output")
        .arg(&workflow)
        .arg("--lock-output")
        .arg(&linked_lock)
        .arg("--report-output")
        .arg(&report)
        .arg("--json")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "unsafe_output_path");
    assert_eq!(fs::read(&workflow).unwrap(), b"preserve-old-workflow");
    assert_eq!(fs::read(&victim).unwrap(), b"preserve-lock-target");
    assert!(!report.exists());
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".runtrue-output.tmp-")
    }));
}

#[test]
fn github_import_rejects_colliding_native_and_lock_destinations() {
    let directory = tempdir().unwrap();
    let collision = directory.path().join("same-output");
    let output = runtrue()
        .args(["import", "github"])
        .arg(github_fixture("supported.yml"))
        .arg("--output")
        .arg(&collision)
        .arg("--lock-output")
        .arg(&collision)
        .arg("--json")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "unsafe_output_path");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("destinations must be distinct"));
    assert!(!collision.exists());
}

#[test]
fn duplicate_github_yaml_is_a_structured_cli_error() {
    let output = runtrue()
        .args(["import", "github"])
        .arg(github_fixture("duplicate.yml"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "github_import_invalid");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("duplicate mapping key `VALUE`"));
}
