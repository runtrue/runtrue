mod bisim;
mod capsule;
mod compare;
mod doctor;
mod import;
mod init;
mod replay;
mod run;
mod validate;

pub(super) use bisim::bisim;
pub(super) use capsule::capsule;
pub(super) use compare::compare_capsule;
pub(super) use doctor::doctor;
pub(super) use import::{import_workflow, write_atomic_output};
pub(super) use init::init;
pub(super) use replay::replay;
pub(super) use run::{run, validate_local_capsule};
pub(super) use validate::validate;

use super::{display_path, read_bounded_file, reusable, CliError, MAX_WORKFLOW_BYTES};
use runtrue_compiler::{Compilation, CompileContext, Compiler};
use runtrue_lock::{LockFile, MAX_LOCKFILE_BYTES};
use serde_json::Value;
use std::{fs, io, path::Path};

pub(super) fn compile_path(
    workspace: &Path,
    path: &Path,
    event: Value,
    source_commit: String,
    base_commit: Option<String>,
    selected_job: Option<String>,
) -> Result<Compilation, CliError> {
    let source_bytes = read_bounded_file(path, MAX_WORKFLOW_BYTES, "workflow")?;
    let source = String::from_utf8(source_bytes).map_err(|source| CliError::Utf8 {
        path: path.to_path_buf(),
        source,
    })?;
    let lock_path = workspace.join(".runtrue.lock");
    let lockfile = match fs::symlink_metadata(&lock_path) {
        Ok(_) => {
            let bytes = read_bounded_file(
                &lock_path,
                u64::try_from(MAX_LOCKFILE_BYTES).expect("lockfile limit fits u64"),
                "lock file",
            )?;
            Some(LockFile::parse(&bytes)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(CliError::Read {
                path: lock_path,
                source,
            });
        }
    };
    let context = CompileContext {
        workflow_path: display_path(workspace, path),
        source_commit,
        base_commit,
        event,
        reusable_workflows: reusable::hydrate_workspace_sources(workspace, lockfile.as_ref())?
            .compiler,
        lockfile,
        selected_job,
        ..CompileContext::default()
    };
    Compiler::default()
        .compile_yaml(&source, context)
        .map_err(CliError::Compile)
}
