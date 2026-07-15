use super::*;
use runtrue_artifacts::ArtifactClassification as StoredArtifactClassification;
use runtrue_cache::{CacheKeyMaterial, TrustDomain};
use runtrue_compiler::{CompileContext, Compiler};
use runtrue_engine::{
    Engine, Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome, JobState, PreparedAction,
    StepExecutionRequest,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{ExecutionCapsule, PlannedJob};
use std::{
    cell::Cell,
    fs,
    path::{Path, PathBuf},
};
use tempfile::tempdir;

#[derive(Debug, Clone)]
enum FakeAction {
    Write(&'static [u8]),
    Expect(&'static [u8]),
    ExpectMissingThenWrite(&'static [u8]),
    WriteDirectory,
    ExpectDirectory,
    Fail,
    Noop,
}

#[derive(Debug)]
struct FakeExecutor {
    workspace: PathBuf,
    action: FakeAction,
    reject_preflight: bool,
    executions: Cell<usize>,
}

impl FakeExecutor {
    fn new(workspace: &Path, action: FakeAction) -> Self {
        Self {
            workspace: workspace.to_path_buf(),
            action,
            reject_preflight: false,
            executions: Cell::new(0),
        }
    }
}

impl Executor for FakeExecutor {
    fn preflight(&self, _capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        if self.reject_preflight {
            Err(ExecutorError::UnsupportedCapsuleFeature(
                "fake backend veto".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    fn execute(&mut self, request: &StepExecutionRequest) -> Result<ExecutorOutput, ExecutorError> {
        assert!(matches!(request.action, PreparedAction::Command { .. }));
        self.executions.set(self.executions.get() + 1);
        let output = self.workspace.join("build/output.txt");
        match self.action {
            FakeAction::Write(bytes) => {
                fs::create_dir_all(output.parent().unwrap()).unwrap();
                fs::write(output, bytes).unwrap();
            }
            FakeAction::Expect(bytes) => {
                assert_eq!(fs::read(output).unwrap(), bytes);
            }
            FakeAction::ExpectMissingThenWrite(bytes) => {
                assert!(!output.exists());
                fs::create_dir_all(output.parent().unwrap()).unwrap();
                fs::write(output, bytes).unwrap();
            }
            FakeAction::WriteDirectory => {
                let nested = self.workspace.join("build/cache/nested/value");
                fs::create_dir_all(nested.parent().unwrap()).unwrap();
                fs::write(nested, b"directory-cache").unwrap();
            }
            FakeAction::ExpectDirectory => {
                assert_eq!(
                    fs::read(self.workspace.join("build/cache/nested/value")).unwrap(),
                    b"directory-cache"
                );
            }
            FakeAction::Fail => return Ok(ExecutorOutput::failure(1)),
            FakeAction::Noop => {}
        }
        Ok(ExecutorOutput::success())
    }

    fn finish_job_attempt(
        &mut self,
        _job: &PlannedJob,
        _attempt: u32,
        _outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        Ok(())
    }
}

fn workflow(cache: &str, capabilities: &str) -> String {
    format!(
        r#"version: 1
name: cache-test
permissions:
  network: deny
  cache: {{ read: run, write: quarantine }}
jobs:
  build:
    trust: trusted-only
    runner:
      os: linux
      arch: amd64
      isolation: native
    steps:
      - id: build
        run:
          command: ["/bin/true"]
        capabilities:
          cache: {capabilities}
        cache:
{cache}
"#
    )
}

fn compile(source: &str) -> ExecutionCapsule {
    Compiler::default()
        .compile_yaml(
            source,
            CompileContext {
                workflow_path: ".runtrue/workflows/cache.yaml".to_owned(),
                source_commit: "test-source".to_owned(),
                ..CompileContext::default()
            },
        )
        .unwrap()
        .capsule
}

fn read_write_capsule() -> ExecutionCapsule {
    compile(&workflow(
            "          inputs: [input.txt]\n          outputs: [build/output.txt]\n          mode: read-write\n          max-size: 1MiB",
            "{ read: run, write: quarantine }",
        ))
}

fn artifact_capsule(permission: &str) -> ExecutionCapsule {
    compile(&format!(
        r#"version: 1
name: artifact-test
permissions:
  network: deny
  artifacts: {permission}
jobs:
  build:
    trust: trusted-only
    runner:
      os: linux
      arch: amd64
      isolation: native
    steps:
      - id: build
        run:
          command: ["/bin/true"]
    outputs:
      result:
        path: build/output.txt
        retention: 1d
        classification: untrusted-build
"#
    ))
}

fn multi_artifact_capsule() -> ExecutionCapsule {
    compile(
        r#"version: 1
name: multi-artifact-test
permissions:
  network: deny
  artifacts: write
jobs:
  build:
    trust: trusted-only
    runner:
      os: linux
      arch: amd64
      isolation: native
    steps:
      - id: build
        run:
          command: ["/bin/true"]
    outputs:
      a-result:
        path: build/first.txt
        retention: 1d
        classification: untrusted-build
      z-missing:
        path: build/missing.txt
        retention: 1d
        classification: untrusted-build
"#,
    )
}

fn first_regular_file(path: &Path) -> Option<PathBuf> {
    let mut entries = fs::read_dir(path)
        .ok()?
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).ok()?;
        if metadata.is_file() {
            return Some(path);
        }
        if metadata.is_dir() {
            if let Some(file) = first_regular_file(&path) {
                return Some(file);
            }
        }
    }

    None
}

fn tree_contains_named_file(path: &Path, name: &str) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_file() && path.file_name().and_then(|value| value.to_str()) == Some(name) {
            return true;
        }
        if metadata.is_dir() && tree_contains_named_file(&path, name) {
            return true;
        }
    }
    false
}

fn find_named_file(path: &Path, name: &str) -> Option<PathBuf> {
    let mut entries = fs::read_dir(path)
        .ok()?
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).ok()?;
        if metadata.is_file() && entry.file_name() == name {
            return Some(path);
        }
        if metadata.is_dir() {
            if let Some(found) = find_named_file(&path, name) {
                return Some(found);
            }
        }
    }
    None
}

#[cfg(unix)]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn make_writable(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).unwrap();
}

mod artifacts;
mod cache;
