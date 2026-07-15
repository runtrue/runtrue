use crate::{command::safe_path, GitError, GitLimits, GitRepository};
use runtrue_model::normalize_relative_path;
use std::{
    env, fs,
    fs::File,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

pub(crate) fn parse_ls_tree(bytes: &[u8]) -> Result<(&str, &str, &str, String), GitError> {
    let entry = bytes
        .strip_suffix(&[0])
        .ok_or(GitError::InvalidGitOutput("ls-tree terminator"))?;
    if entry.contains(&0) {
        return Err(GitError::InvalidGitOutput("multiple ls-tree entries"));
    }
    let text =
        std::str::from_utf8(entry).map_err(|_| GitError::InvalidGitOutput("ls-tree UTF-8"))?;
    let (metadata, path) = text
        .split_once('\t')
        .ok_or(GitError::InvalidGitOutput("ls-tree record"))?;
    let mut fields = metadata.split(' ');
    let mode = fields
        .next()
        .ok_or(GitError::InvalidGitOutput("ls-tree mode"))?;
    let kind = fields
        .next()
        .ok_or(GitError::InvalidGitOutput("ls-tree kind"))?;
    let object = fields
        .next()
        .ok_or(GitError::InvalidGitOutput("ls-tree object"))?;
    if fields.next().is_some() {
        return Err(GitError::InvalidGitOutput("ls-tree fields"));
    }
    Ok((mode, kind, object, path.to_owned()))
}

pub(crate) fn parse_changed_paths(
    bytes: &[u8],
    limits: GitLimits,
) -> Result<Vec<String>, GitError> {
    if bytes.last().is_some_and(|byte| *byte != 0) {
        return Err(GitError::InvalidGitOutput("diff path terminator"));
    }
    let mut paths = std::collections::BTreeSet::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
    {
        if paths.len() >= limits.max_changed_paths {
            return Err(GitError::OutputLimit {
                kind: "changed path count",
                limit: limits.max_changed_paths,
            });
        }
        let path =
            std::str::from_utf8(raw).map_err(|_| GitError::InvalidGitOutput("diff path UTF-8"))?;
        paths.insert(validate_repo_path(path, limits)?);
    }
    Ok(paths.into_iter().collect())
}

pub(crate) fn validate_repo_path(path: &str, limits: GitLimits) -> Result<String, GitError> {
    if path.len() > limits.max_path_bytes || path.contains(':') {
        return Err(GitError::UnsafePath(path.to_owned()));
    }
    let normalized =
        normalize_relative_path(path).map_err(|_| GitError::UnsafePath(path.to_owned()))?;
    if normalized != path {
        return Err(GitError::UnsafePath(path.to_owned()));
    }
    Ok(normalized)
}

pub(crate) fn parse_ls_tree_record(record: &[u8]) -> Result<(&str, &str, &str, &str), GitError> {
    let record =
        std::str::from_utf8(record).map_err(|_| GitError::InvalidGitOutput("tree entry UTF-8"))?;
    let (metadata, path) = record
        .split_once('\t')
        .ok_or(GitError::InvalidGitOutput("tree entry"))?;
    let mut fields = metadata.split(' ');
    let mode = fields
        .next()
        .ok_or(GitError::InvalidGitOutput("tree mode"))?;
    let kind = fields
        .next()
        .ok_or(GitError::InvalidGitOutput("tree kind"))?;
    let object_id = fields
        .next()
        .ok_or(GitError::InvalidGitOutput("tree object"))?;
    if fields.next().is_some() {
        return Err(GitError::InvalidGitOutput("tree metadata"));
    }
    Ok((mode, kind, object_id, path))
}

pub(crate) fn git_object_size(
    repository: &GitRepository,
    object_id: &str,
) -> Result<usize, GitError> {
    parse_one_line(
        &repository
            .run_git(&["cat-file", "-s", object_id], 1024)?
            .stdout,
        "blob size",
    )?
    .parse()
    .map_err(|_| GitError::InvalidGitOutput("blob size"))
}

pub(crate) fn validate_symlink_target(path: &str, target: &str) -> Result<(), GitError> {
    if target.is_empty() || target.contains('\0') || Path::new(target).is_absolute() {
        return Err(GitError::UnsafeSymlink(path.to_owned()));
    }
    let parent = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
    let joined = parent.join(target);
    let mut depth = 0_usize;
    for component in joined.components() {
        match component {
            std::path::Component::Normal(_) => depth = depth.saturating_add(1),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir if depth > 0 => depth -= 1,
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(GitError::UnsafeSymlink(path.to_owned()));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_object_id(value: &str) -> Result<(), GitError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GitError::MutableOrInvalidRevision);
    }
    Ok(())
}

pub(crate) fn parse_one_line<'a>(bytes: &'a [u8], kind: &'static str) -> Result<&'a str, GitError> {
    let value = std::str::from_utf8(bytes).map_err(|_| GitError::InvalidGitOutput(kind))?;
    let value = value
        .strip_suffix('\n')
        .or_else(|| value.strip_suffix("\r\n"))
        .unwrap_or(value);
    if value.is_empty() || value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(GitError::InvalidGitOutput(kind));
    }
    Ok(value)
}

pub(crate) fn open_null_directory_placeholder() -> Result<File, GitError> {
    open_real_directory(Path::new("/")).map(|(_, file)| file)
}

pub(crate) fn open_real_directory(path: &Path) -> Result<(PathBuf, File), GitError> {
    if !path.is_absolute() {
        return Err(GitError::UnsafeRepositoryRoot(path.to_owned()));
    }
    let mut checked = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Normal(_) => {
                checked.push(component.as_os_str());
            }
            std::path::Component::CurDir => continue,
            std::path::Component::Prefix(_) | std::path::Component::ParentDir => {
                return Err(GitError::UnsafeRepositoryRoot(path.to_owned()));
            }
        }
        let metadata = fs::symlink_metadata(&checked)
            .map_err(|source| GitError::Filesystem(checked.clone(), source))?;
        if metadata.file_type().is_symlink() {
            return Err(GitError::UnsafeRepositoryRoot(checked));
        }
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(GitError::UnsafeRepositoryRoot(path.to_owned()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    if canonical != path {
        return Err(GitError::UnsafeRepositoryRoot(path.to_owned()));
    }
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
    #[cfg(unix)]
    {
        let opened = file
            .metadata()
            .map_err(|source| GitError::Filesystem(path.to_owned(), source))?;
        if opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.file_type().is_symlink()
            || !opened.is_dir()
        {
            return Err(GitError::UnsafeRepositoryRoot(path.to_owned()));
        }
    }
    Ok((canonical, file))
}

pub(crate) fn find_git() -> Result<PathBuf, GitError> {
    #[cfg(unix)]
    let path = safe_path().into_os_string();
    #[cfg(not(unix))]
    let path = env::var_os("PATH").ok_or(GitError::GitUnavailable)?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(if cfg!(windows) { "git.exe" } else { "git" });
        if fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file()) {
            return Ok(candidate);
        }
    }
    Err(GitError::GitUnavailable)
}
