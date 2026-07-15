pub(crate) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), OciError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(OciError::InvalidRequest(format!(
            "{kind} must be a bounded ASCII identifier"
        )));
    }
    Ok(())
}

pub(crate) fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn container_name(request: &StepExecutionRequest) -> String {
    format!(
        "runtrue-{}",
        short_identity(&format!(
            "{}\0{}\0{}",
            request.job_id, request.job_attempt, request.step_id
        ))
    )
}

pub(crate) fn service_container_name(request: &StepExecutionRequest, service_id: &str) -> String {
    format!(
        "runtrue-svc-{}",
        short_identity(&format!(
            "{}\0{}\0{}",
            request.job_id, request.job_attempt, service_id
        ))
    )
}

pub(crate) fn network_name(request: &StepExecutionRequest) -> String {
    format!(
        "runtrue-net-{}",
        short_identity(&format!("{}\0{}", request.job_id, request.job_attempt))
    )
}

pub(crate) fn short_identity(value: &str) -> String {
    ContentDigest::sha256(value.as_bytes())
        .as_str()
        .strip_prefix("sha256:")
        .expect("model digest has sha256 prefix")[..24]
        .to_owned()
}

pub(crate) fn utf8_path<'a>(path: &'a Path, kind: &'static str) -> Result<&'a str, OciError> {
    path.to_str().ok_or_else(|| OciError::UnsafePath {
        kind,
        path: path.to_path_buf(),
    })
}

pub(crate) fn ensure_descendant(root: &Path, path: &Path) -> Result<(), OciError> {
    if path == root || !path.starts_with(root) {
        return Err(OciError::UnsafePath {
            kind: "job runtime state",
            path: path.to_path_buf(),
        });
    }
    Ok(())
}
use crate::{ContentDigest, OciError, Path, StepExecutionRequest};
