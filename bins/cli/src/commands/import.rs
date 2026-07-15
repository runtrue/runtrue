use super::super::{
    absolute, display_path, print_json, read_bounded_file, CliError, GithubImportArgs, ImportArgs,
    ImportSource, EXIT_OK, EXIT_VALIDATION,
};
use runtrue_gha_import::{import_github_actions, ImportResult, MAX_GITHUB_WORKFLOW_BYTES};
use rustix::{
    fd::OwnedFd,
    fs::{
        fsync as fsync_fd, openat, openat2, renameat, unlinkat, AtFlags, Mode, OFlags,
        ResolveFlags, ABS,
    },
};
use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, Write as _},
    path::{Component, Path, PathBuf},
};

pub(crate) fn import_workflow(workspace: &Path, args: ImportArgs) -> Result<u8, CliError> {
    match args.source {
        ImportSource::Github(args) => import_github(workspace, args),
    }
}

fn import_github(workspace: &Path, args: GithubImportArgs) -> Result<u8, CliError> {
    let input = absolute(workspace, args.workflow.clone());
    let bytes = read_bounded_file(
        &input,
        u64::try_from(MAX_GITHUB_WORKFLOW_BYTES).expect("GitHub workflow limit fits u64"),
        "GitHub Actions workflow",
    )?;
    let source = String::from_utf8(bytes).map_err(|source| CliError::Utf8 {
        path: input.clone(),
        source,
    })?;
    let result = import_github_actions(&source, display_path(workspace, &input))?;

    let report_output = args
        .report_output
        .as_ref()
        .map(|path| absolute(workspace, path.clone()));
    let native_output = args.output.as_ref().and_then(|path| {
        result
            .native_yaml
            .as_ref()
            .map(|_| absolute(workspace, path.clone()))
    });
    let lock_output = args.lock_output.as_ref().and_then(|path| {
        result
            .lockfile_toml
            .as_ref()
            .map(|_| absolute(workspace, path.clone()))
    });
    let destinations = [
        report_output.as_deref(),
        native_output.as_deref(),
        lock_output.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    ensure_distinct_output_paths(&destinations)?;

    let report_bytes = if report_output.is_some() {
        let mut report = serde_json::to_vec_pretty(&result.report)?;
        report.push(b'\n');
        Some(report)
    } else {
        None
    };

    // Prepare every requested file before publishing any of them. The native
    // workflow is committed last, so any staging/publication failure leaves no
    // newly imported workflow that is missing its exact lock requirements.
    let prepared_report = report_output
        .as_deref()
        .zip(report_bytes.as_deref())
        .map(|(path, bytes)| prepare_atomic_output(path, bytes))
        .transpose()?;
    let prepared_lock = lock_output
        .as_deref()
        .zip(result.lockfile_toml.as_deref())
        .map(|(path, lockfile)| prepare_atomic_output(path, lockfile.as_bytes()))
        .transpose()?;
    let prepared_native = native_output
        .as_deref()
        .zip(result.native_yaml.as_deref())
        .map(|(path, yaml)| prepare_atomic_output(path, yaml.as_bytes()))
        .transpose()?;

    if let Some(prepared) = prepared_lock {
        prepared.commit()?;
    }
    if let Some(prepared) = prepared_report {
        prepared.commit()?;
    }
    if let Some(prepared) = prepared_native {
        prepared.commit()?;
    }

    if args.json {
        print_json(&result)?;
    } else {
        print_human_import(workspace, &args, &result);
    }
    Ok(if result.report.compatible {
        EXIT_OK
    } else {
        EXIT_VALIDATION
    })
}

fn print_human_import(workspace: &Path, args: &GithubImportArgs, result: &ImportResult) {
    print!("{}", result.report.render_human());
    let Some(yaml) = &result.native_yaml else {
        println!("\nNo native workflow was emitted because blocking findings remain.");
        return;
    };
    if let Some(output) = &args.output {
        println!(
            "\nNative workflow: {}",
            display_path(workspace, &absolute(workspace, output.clone()))
        );
    } else {
        println!("\nNative workflow YAML:\n{yaml}");
    }
    if let Some(lockfile) = &result.lockfile_toml {
        if let Some(lock_output) = &args.lock_output {
            println!(
                "Lock requirements: {}",
                display_path(workspace, &absolute(workspace, lock_output.clone()))
            );
        } else {
            println!("Exact lock requirements:\n{lockfile}");
        }
    }
}

struct PreparedAtomicOutput {
    path: PathBuf,
    parent_path: PathBuf,
    parent: OwnedFd,
    temporary_name: OsString,
    destination_name: OsString,
    committed: bool,
}

impl PreparedAtomicOutput {
    fn commit(mut self) -> Result<(), CliError> {
        // Recheck the pathname before the descriptor-relative rename. The
        // held parent descriptor prevents a later symlink swap from changing
        // which directory receives the file.
        reject_output_symlink_components(&self.path)?;
        renameat(
            &self.parent,
            self.temporary_name.as_os_str(),
            &self.parent,
            self.destination_name.as_os_str(),
        )
        .map_err(|source| CliError::Write {
            path: self.path.clone(),
            source: source.into(),
        })?;
        self.committed = true;
        fsync_fd(&self.parent).map_err(|source| CliError::Write {
            path: self.parent_path.clone(),
            source: source.into(),
        })?;
        Ok(())
    }
}

impl Drop for PreparedAtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = unlinkat(
                &self.parent,
                self.temporary_name.as_os_str(),
                AtFlags::empty(),
            );
        }
    }
}

fn ensure_distinct_output_paths(paths: &[&Path]) -> Result<(), CliError> {
    let mut normalized = Vec::with_capacity(paths.len());
    for path in paths {
        let identity = normalized_absolute_output(path)?;
        if normalized.contains(&identity) {
            return Err(CliError::UnsafeOutputPath {
                path: (*path).to_path_buf(),
                reason: "import output destinations must be distinct",
            });
        }
        normalized.push(identity);
    }
    Ok(())
}

fn prepare_atomic_output(path: &Path, bytes: &[u8]) -> Result<PreparedAtomicOutput, CliError> {
    reject_output_symlink_components(path)?;
    let absolute_path = normalized_absolute_output(path)?;
    let parent = absolute_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let parent_metadata = fs::symlink_metadata(&parent).map_err(|source| CliError::Write {
        path: parent.clone(),
        source,
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(CliError::UnsafeOutputPath {
            path: absolute_path.clone(),
            reason: "the output parent must be a real directory",
        });
    }
    match fs::symlink_metadata(&absolute_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CliError::UnsafeOutputPath {
                path: absolute_path.clone(),
                reason: "an existing output must be a regular non-symlink file",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CliError::Write {
                path: absolute_path.clone(),
                source,
            });
        }
    }

    let parent_fd = openat2(
        ABS,
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| CliError::UnsafeOutputPath {
        path: absolute_path.clone(),
        reason: "the output parent could not be opened without following symbolic links",
    })?;
    let destination_name = absolute_path
        .file_name()
        .ok_or_else(|| CliError::UnsafeOutputPath {
            path: absolute_path.clone(),
            reason: "the output path has no file name",
        })?
        .to_os_string();

    let (temporary_name, mut temporary) = (0_u16..1000)
        .find_map(|attempt| {
            let candidate = OsString::from(format!(
                ".runtrue-output.tmp-{}-{attempt}",
                std::process::id()
            ));
            match openat(
                &parent_fd,
                candidate.as_os_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => Some(Ok((candidate, File::from(file)))),
                Err(error) if error == rustix::io::Errno::EXIST => None,
                Err(source) => Some(Err(CliError::Write {
                    path: parent.join(&candidate),
                    source: source.into(),
                })),
            }
        })
        .transpose()?
        .ok_or_else(|| CliError::UnsafeOutputPath {
            path: absolute_path.clone(),
            reason: "could not reserve a same-directory output file",
        })?;
    let write_result = temporary
        .write_all(bytes)
        .and_then(|()| temporary.sync_all());
    drop(temporary);
    if let Err(source) = write_result {
        let _ = unlinkat(&parent_fd, temporary_name.as_os_str(), AtFlags::empty());
        return Err(CliError::Write {
            path: parent.join(&temporary_name),
            source,
        });
    }
    Ok(PreparedAtomicOutput {
        path: absolute_path,
        parent_path: parent,
        parent: parent_fd,
        temporary_name,
        destination_name,
        committed: false,
    })
}

/// Durably replace a user-selected output without following a symbolic link.
/// Capsule and replay files can contain event projections, so outputs are private
/// and a crash exposes either the old complete file or the new complete file.
pub(crate) fn write_atomic_output(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    prepare_atomic_output(path, bytes)?.commit()
}

fn normalized_absolute_output(path: &Path) -> Result<PathBuf, CliError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CliError::UnsafeOutputPath {
            path: path.to_path_buf(),
            reason: "the output path contains parent traversal or a platform prefix",
        });
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(CliError::CurrentDirectory)?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CliError::UnsafeOutputPath {
                    path: path.to_path_buf(),
                    reason: "the output path contains an unsupported component",
                });
            }
        }
    }
    Ok(normalized)
}

fn reject_output_symlink_components(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CliError::UnsafeOutputPath {
            path: path.to_path_buf(),
            reason: "the output path contains parent traversal or a platform prefix",
        });
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(CliError::CurrentDirectory)?
            .join(path)
    };
    let mut current = PathBuf::new();
    let components: Vec<OsString> = absolute
        .components()
        .filter_map(|component| match component {
            Component::RootDir => {
                current.push(Path::new("/"));
                None
            }
            Component::Normal(value) => Some(value.to_os_string()),
            Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => Some(OsString::new()),
        })
        .collect();
    for (index, component) in components.iter().enumerate() {
        if component.is_empty() {
            return Err(CliError::UnsafeOutputPath {
                path: path.to_path_buf(),
                reason: "the output path contains an unsupported component",
            });
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CliError::UnsafeOutputPath {
                    path: path.to_path_buf(),
                    reason: "the output path contains a symbolic link",
                });
            }
            Ok(metadata) if index + 1 < components.len() && !metadata.is_dir() => {
                return Err(CliError::UnsafeOutputPath {
                    path: path.to_path_buf(),
                    reason: "an output ancestor is not a directory",
                });
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && index + 1 == components.len() => {}
            Err(source) => {
                return Err(CliError::Write {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}
