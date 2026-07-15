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
fn init_creates_a_discoverable_valid_workflow_without_overwriting() {
    let directory = tempdir().unwrap();
    let created = runtrue()
        .current_dir(directory.path())
        .args(["init", "--json"])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(directory
        .path()
        .join(".runtrue/workflows/ci.yaml")
        .is_file());

    let validation = runtrue()
        .current_dir(directory.path())
        .args(["validate", "--json"])
        .output()
        .unwrap();
    assert!(
        validation.status.success(),
        "{}",
        String::from_utf8_lossy(&validation.stderr)
    );
    let report: Value = serde_json::from_slice(&validation.stdout).unwrap();
    assert_eq!(report["valid"], true);

    let second = runtrue()
        .current_dir(directory.path())
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(10));
}

#[cfg(unix)]
#[test]
fn init_refuses_symlink_targets_even_with_force() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let workflows = directory.path().join(".runtrue/workflows");
    fs::create_dir_all(&workflows).unwrap();
    let victim = directory.path().join("victim");
    fs::write(&victim, "preserve me").unwrap();
    symlink(&victim, workflows.join("ci.yaml")).unwrap();

    let result = runtrue()
        .current_dir(directory.path())
        .args(["init", "--force", "--json"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(10));
    assert_eq!(fs::read_to_string(victim).unwrap(), "preserve me");
    let error: Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["error"]["code"], "unsafe_init_path");
}
