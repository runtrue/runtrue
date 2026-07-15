use crate::daemon::RunnerError;
use runtrue_model::normalize_relative_path;
use runtrue_storage::CasLimits;
use std::{collections::BTreeSet, fs, path::Path};

pub(super) fn normalized_path(value: &str) -> Result<String, RunnerError> {
    normalize_relative_path(value)
        .map_err(|error| RunnerError::DataPlane(format!("invalid declared path: {error}")))
}

pub(super) fn expand_patterns(
    root: &Path,
    patterns: &[String],
) -> Result<Vec<String>, RunnerError> {
    let mut paths = BTreeSet::new();
    for pattern in patterns {
        paths.extend(expand_pattern(root, pattern)?);
    }
    let mut minimal = Vec::new();
    for path in paths {
        if !minimal.iter().any(|ancestor: &String| {
            path.len() > ancestor.len()
                && path.starts_with(ancestor)
                && path.as_bytes().get(ancestor.len()) == Some(&b'/')
        }) {
            minimal.push(path);
        }
    }
    Ok(minimal)
}

pub(super) fn expand_pattern(root: &Path, pattern: &str) -> Result<Vec<String>, RunnerError> {
    let pattern = normalized_path(pattern)?;
    if !pattern.contains(['*', '?']) {
        return Ok(vec![pattern]);
    }
    let limits = CasLimits::default();
    let mut pending = vec![(root.to_path_buf(), String::new(), 0_usize)];
    let mut matches = BTreeSet::new();
    let mut visited = 0_usize;
    while let Some((directory, prefix, depth)) = pending.pop() {
        if depth >= limits.max_tree_depth {
            return Err(RunnerError::DataPlane(
                "cache pattern traversal exceeds the tree depth bound".to_owned(),
            ));
        }
        let entries =
            fs::read_dir(&directory).map_err(|error| RunnerError::DataPlane(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            visited = visited.saturating_add(1);
            if visited > limits.max_tree_entries {
                return Err(RunnerError::DataPlane(
                    "cache pattern traversal exceeds the entry bound".to_owned(),
                ));
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if relative.len() > limits.max_relative_path_bytes {
                return Err(RunnerError::DataPlane(
                    "cache pattern traversal exceeds the path bound".to_owned(),
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            if glob_matches(&pattern, &relative) {
                matches.insert(relative.clone());
            }
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push((entry.path(), relative, depth + 1));
            }
        }
    }
    Ok(matches.into_iter().collect())
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    fn segments(pattern: &[&str], path: &[&str]) -> bool {
        match pattern.split_first() {
            None => path.is_empty(),
            Some((&"**", rest)) => {
                segments(rest, path)
                    || path
                        .split_first()
                        .is_some_and(|(_, tail)| segments(pattern, tail))
            }
            Some((head, rest)) => path
                .split_first()
                .is_some_and(|(value, tail)| segment_matches(head, value) && segments(rest, tail)),
        }
    }
    segments(
        &pattern.split('/').collect::<Vec<_>>(),
        &path.split('/').collect::<Vec<_>>(),
    )
}

fn segment_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let value = value.chars().collect::<Vec<_>>();
    let mut reachable = vec![false; value.len() + 1];
    reachable[0] = true;
    for token in pattern {
        let mut next = vec![false; value.len() + 1];
        if token == '*' {
            next[0] = reachable[0];
            for index in 1..=value.len() {
                next[index] = reachable[index] || next[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                next[index] = reachable[index - 1] && (token == '?' || token == value[index - 1]);
            }
        }
        reachable = next;
    }
    reachable[value.len()]
}

pub(super) fn ensure_real_parent(root: &Path, relative: &str) -> Result<(), RunnerError> {
    let mut current = root.to_path_buf();
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(RunnerError::DataPlane(format!(
                    "cache restore parent `{}` is not a real directory",
                    current.display()
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            }
            Err(error) => return Err(RunnerError::DataPlane(error.to_string())),
        }
    }
    Ok(())
}
