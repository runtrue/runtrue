use super::super::{display_path, print_json, CliError, InitArgs, EXIT_OK};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

pub(crate) fn init(workspace: &Path, args: InitArgs) -> Result<u8, CliError> {
    let directory = ensure_init_directory(workspace)?;
    let path = directory.join("ci.yaml");
    write_starter_atomic(&directory, &path, args.force)?;

    if args.json {
        print_json(&serde_json::json!({
            "created": display_path(workspace, &path),
            "native_execution_requires": "--allow-native"
        }))?;
    } else {
        println!("Created {}", display_path(workspace, &path));
        println!(
            "The starter uses native host execution; review it and pass --allow-native to run."
        );
    }
    Ok(EXIT_OK)
}

fn ensure_init_directory(workspace: &Path) -> Result<PathBuf, CliError> {
    let mut current = workspace.to_path_buf();
    for component in [".runtrue", "workflows"] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            }
            Ok(_) => {
                return Err(CliError::UnsafeInitPath {
                    path: current,
                    reason: "path component is a symlink or is not a directory",
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Err(source) = fs::create_dir(&current) {
                    if source.kind() != io::ErrorKind::AlreadyExists {
                        return Err(CliError::Write {
                            path: current,
                            source,
                        });
                    }
                    let metadata =
                        fs::symlink_metadata(&current).map_err(|source| CliError::Write {
                            path: current.clone(),
                            source,
                        })?;
                    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                        return Err(CliError::UnsafeInitPath {
                            path: current,
                            reason: "raced path component is not a real directory",
                        });
                    }
                }
            }
            Err(source) => {
                return Err(CliError::Write {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(current)
}

fn write_starter_atomic(directory: &Path, path: &Path, force: bool) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(CliError::UnsafeInitPath {
                    path: path.to_path_buf(),
                    reason: "starter target is a symlink or is not a regular file",
                });
            }
            if !force {
                return Err(CliError::AlreadyExists(path.to_path_buf()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CliError::Write {
                path: path.to_path_buf(),
                source,
            });
        }
    }

    let (temporary_path, mut temporary) = (0_u16..1000)
        .find_map(|attempt| {
            let candidate =
                directory.join(format!(".ci.yaml.tmp-{}-{attempt}", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => Some(Ok((candidate, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(source) => Some(Err(CliError::Write {
                    path: candidate,
                    source,
                })),
            }
        })
        .transpose()?
        .ok_or_else(|| CliError::UnsafeInitPath {
            path: directory.to_path_buf(),
            reason: "could not reserve an atomic starter file",
        })?;

    let write_result = temporary
        .write_all(STARTER_WORKFLOW.as_bytes())
        .and_then(|()| temporary.sync_all());
    drop(temporary);
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(CliError::Write {
            path: temporary_path,
            source,
        });
    }

    if force {
        return fs::rename(&temporary_path, path).map_err(|source| CliError::Write {
            path: path.to_path_buf(),
            source,
        });
    }

    if let Err(source) = fs::hard_link(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        if !force && source.kind() == io::ErrorKind::AlreadyExists {
            return Err(CliError::AlreadyExists(path.to_path_buf()));
        }
        return Err(CliError::Write {
            path: path.to_path_buf(),
            source,
        });
    }
    fs::remove_file(&temporary_path).map_err(|source| CliError::Write {
        path: temporary_path,
        source,
    })?;
    Ok(())
}

const STARTER_WORKFLOW: &str = r#"version: 1
name: local-ci

"on":
  manual: {}

permissions:
  repository: deny
  checks: deny
  artifacts: deny
  registry: deny
  network: deny
  oidc: deny
  cache: { read: deny, write: deny }

jobs:
  smoke:
    trust: trusted-only
    runner:
      os: linux
      arch: amd64
      isolation: native
    timeout: 1m
    steps:
      - id: hello
        run:
          command: ["/bin/echo", "runtrue: local native smoke test"]
"#;
