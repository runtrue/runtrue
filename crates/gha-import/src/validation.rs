use runtrue_workflow_ast as ast;
use serde_yaml::Value as YamlValue;

pub(crate) fn valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

pub(crate) fn valid_environment_name(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

pub(crate) fn safe_relative_path(value: &str, allow_glob: bool) -> bool {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('~')
        || value.contains('\0')
        || value.contains('\\')
        || (!allow_glob && value.contains(['*', '?', '[', ']']))
    {
        return false;
    }
    let mut meaningful = false;
    for segment in value.split('/') {
        if segment == ".." {
            return false;
        }
        if !segment.is_empty() && segment != "." {
            meaningful = true;
        }
    }
    meaningful
}

pub(crate) fn normalize_relative(value: &str) -> String {
    value
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn is_full_sha256_image(value: &str) -> bool {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && !repository.contains('@')
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_exact_wasm_component(value: &str) -> bool {
    value
        .strip_prefix("wasm://")
        .is_some_and(is_full_sha256_image)
}

pub(crate) fn is_full_git_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_null_or_empty_mapping(value: &YamlValue) -> bool {
    value.is_null()
        || value
            .as_mapping()
            .is_some_and(serde_yaml::Mapping::is_empty)
}

pub(crate) fn yaml_text(value: &YamlValue) -> String {
    serde_yaml::to_string(value).unwrap_or_else(|_| "<invalid-yaml-value>".to_owned())
}

pub(crate) const fn merge_cache_read(
    left: ast::CacheRead,
    right: ast::CacheRead,
) -> ast::CacheRead {
    match (left, right) {
        (ast::CacheRead::Deny, value) => value,
        (value, ast::CacheRead::Deny) => value,
        (value, _) => value,
    }
}

pub(crate) const fn merge_cache_write(
    left: ast::CacheWrite,
    right: ast::CacheWrite,
) -> ast::CacheWrite {
    match (left, right) {
        (ast::CacheWrite::Deny, value) => value,
        (value, ast::CacheWrite::Deny) => value,
        (value, _) => value,
    }
}
