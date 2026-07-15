use super::NORMALIZED_EVENT_VERSION;
use crate::{
    ActorIdentity, EventEnvelope, EventType, GitRevision, RepositoryIdentity, ScmError,
    WebhookHeaders, WebhookLimits,
};
use runtrue_model::normalize_relative_path;
use serde_json::Value;

pub(super) fn validate_envelope(
    envelope: &EventEnvelope,
    limits: WebhookLimits,
) -> Result<(), ScmError> {
    if envelope.version != NORMALIZED_EVENT_VERSION {
        return Err(ScmError::UnsupportedNormalizedVersion(envelope.version));
    }
    validate_identifier("installation id", &envelope.installation_id, limits)?;
    validate_identifier("event id", &envelope.event_id, limits)?;
    validate_repository(&envelope.repository, limits)?;
    validate_actor(&envelope.actor, limits)?;
    validate_revision(&envelope.source, limits)?;
    if let Some(base) = &envelope.base {
        validate_revision(base, limits)?;
    }
    if let Some(reference) = &envelope.ref_name {
        validate_identifier("ref name", reference, limits)?;
    }
    let mut paths = envelope.changed_paths.clone();
    normalize_paths(&mut paths, limits)?;
    if paths != envelope.changed_paths {
        return Err(ScmError::InvalidPayload(
            "changed paths must be normalized, sorted, and unique".to_owned(),
        ));
    }
    validate_event_shape(envelope)?;
    Ok(())
}

pub(super) fn validate_event_shape(envelope: &EventEnvelope) -> Result<(), ScmError> {
    let expected_repository = envelope.repository.full_name.as_str();
    let repository_matches = |revision: &GitRevision| {
        revision.repository_full_name.as_deref() == Some(expected_repository)
    };
    let invalid = || {
        ScmError::InvalidPayload(
            "normalized event fields are inconsistent with the event type".to_owned(),
        )
    };
    match envelope.event_type {
        EventType::Push => {
            if !repository_matches(&envelope.source)
                || envelope
                    .base
                    .as_ref()
                    .is_some_and(|base| !repository_matches(base))
                || envelope.pull_request.is_some()
                || envelope.issue_comment.is_some()
                || envelope.check_run.is_some()
                || is_zero_commit(&envelope.source.commit)
            {
                return Err(invalid());
            }
        }
        EventType::PullRequest { .. } => {
            let base = envelope.base.as_ref().ok_or_else(invalid)?;
            let pull_request = envelope.pull_request.as_ref().ok_or_else(invalid)?;
            if !repository_matches(base)
                || envelope.source.repository_full_name.is_none()
                || envelope.ref_name != base.ref_name
                || pull_request.number == 0
                || is_zero_commit(&envelope.source.commit)
                || is_zero_commit(&base.commit)
                || envelope.issue_comment.is_some()
                || envelope.check_run.is_some()
            {
                return Err(invalid());
            }
        }
        EventType::IssueComment { .. } => {
            let comment = envelope.issue_comment.as_ref().ok_or_else(invalid)?;
            if !repository_matches(&envelope.source)
                || !is_zero_commit(&envelope.source.commit)
                || envelope.base.is_some()
                || envelope.pull_request.is_some()
                || envelope.check_run.is_some()
                || comment.issue_number == 0
                || comment.comment_id == 0
                || envelope.ref_name != envelope.source.ref_name
            {
                return Err(invalid());
            }
        }
        EventType::CheckRun { .. } => {
            let check = envelope.check_run.as_ref().ok_or_else(invalid)?;
            if !repository_matches(&envelope.source)
                || !is_zero_commit(&envelope.source.commit)
                || envelope.base.is_some()
                || envelope.pull_request.is_some()
                || envelope.issue_comment.is_some()
                || check.check_run_id == 0
                || check.pull_requests.iter().any(|pull| pull.number == 0)
                || matches!(
                    envelope.event_type,
                    EventType::CheckRun {
                        action: crate::CheckRunEventAction::RequestedAction
                    }
                ) != check.requested_action_identifier.is_some()
                || envelope.ref_name != envelope.source.ref_name
            {
                return Err(invalid());
            }
        }
        EventType::MergeGroup => {
            let base = envelope.base.as_ref().ok_or_else(invalid)?;
            if !repository_matches(&envelope.source)
                || !repository_matches(base)
                || envelope.ref_name != base.ref_name
                || envelope.pull_request.is_some()
                || envelope.issue_comment.is_some()
                || envelope.check_run.is_some()
                || is_zero_commit(&envelope.source.commit)
                || is_zero_commit(&base.commit)
            {
                return Err(invalid());
            }
        }
        EventType::Ping => {
            if !repository_matches(&envelope.source)
                || !is_zero_commit(&envelope.source.commit)
                || envelope.base.is_some()
                || envelope.pull_request.is_some()
                || envelope.issue_comment.is_some()
                || envelope.check_run.is_some()
                || !envelope.changed_paths.is_empty()
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

pub(super) fn validate_repository(
    repository: &RepositoryIdentity,
    limits: WebhookLimits,
) -> Result<(), ScmError> {
    validate_identifier("repository external id", &repository.external_id, limits)?;
    validate_identifier("repository owner", &repository.owner, limits)?;
    validate_identifier("repository name", &repository.name, limits)?;
    validate_identifier("repository full name", &repository.full_name, limits)?;
    if repository.full_name != format!("{}/{}", repository.owner, repository.name) {
        return Err(ScmError::InvalidPayload(
            "repository full name does not match owner/name".to_owned(),
        ));
    }
    if let Some(branch) = &repository.default_branch {
        validate_identifier("default branch", branch, limits)?;
    }
    Ok(())
}

pub(super) fn validate_actor(actor: &ActorIdentity, limits: WebhookLimits) -> Result<(), ScmError> {
    validate_identifier("actor external id", &actor.external_id, limits)?;
    validate_identifier("actor login", &actor.login, limits)?;
    Ok(())
}

pub(super) fn validate_revision(
    revision: &GitRevision,
    limits: WebhookLimits,
) -> Result<(), ScmError> {
    validate_git_commit(&revision.commit)?;
    if let Some(reference) = &revision.ref_name {
        validate_identifier("revision ref", reference, limits)?;
    }
    if let Some(repository) = &revision.repository_full_name {
        validate_identifier("revision repository", repository, limits)?;
    }
    Ok(())
}

pub(super) fn normalize_paths(
    paths: &mut Vec<String>,
    limits: WebhookLimits,
) -> Result<(), ScmError> {
    if paths.len() > limits.max_changed_paths {
        return Err(ScmError::LimitExceeded("changed path count"));
    }
    for path in paths.iter_mut() {
        if path.len() > limits.max_changed_path_bytes {
            return Err(ScmError::LimitExceeded("changed path bytes"));
        }
        *path = normalize_relative_path(path)
            .map_err(|error| ScmError::InvalidPath(error.to_string()))?;
    }
    paths.sort();
    paths.dedup();
    Ok(())
}

pub(crate) fn validate_git_commit(value: &str) -> Result<(), ScmError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ScmError::InvalidGitCommit);
    }
    Ok(())
}

pub(super) fn is_zero_commit(value: &str) -> bool {
    value.bytes().all(|byte| byte == b'0')
}

pub(super) fn validate_identifier(
    kind: &'static str,
    value: &str,
    limits: WebhookLimits,
) -> Result<String, ScmError> {
    if value.is_empty()
        || value.len() > limits.max_identifier_bytes
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ScmError::InvalidIdentifier(kind));
    }
    Ok(value.to_owned())
}

pub(super) fn required_header<'a>(
    headers: &'a WebhookHeaders,
    name: &'static str,
) -> Result<&'a str, ScmError> {
    headers.get(name).ok_or(ScmError::MissingHeader(name))
}

pub(super) fn object_at<'a>(value: &'a Value, field: &'static str) -> Result<&'a Value, ScmError> {
    value
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| ScmError::InvalidPayload(format!("`{field}` must be an object")))
}

pub(super) fn object_field<'a>(
    object: &'a Value,
    field: &'static str,
) -> Result<&'a Value, ScmError> {
    object_at(object, field)
}

pub(super) fn required_string(
    object: &Value,
    field: &'static str,
    limits: WebhookLimits,
) -> Result<String, ScmError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ScmError::InvalidPayload(format!("`{field}` must be a string")))
        .and_then(|value| validate_identifier(field, value, limits))
}

pub(super) fn optional_string(
    object: &Value,
    field: &'static str,
    limits: WebhookLimits,
) -> Result<Option<String>, ScmError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .ok_or_else(|| ScmError::InvalidPayload(format!("`{field}` must be a string or null")))
            .and_then(|value| validate_identifier(field, value, limits))
            .map(Some),
    }
}

pub(super) fn required_bool(object: &Value, field: &'static str) -> Result<bool, ScmError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| ScmError::InvalidPayload(format!("`{field}` must be a boolean")))
}

pub(super) fn required_u64(object: &Value, field: &'static str) -> Result<u64, ScmError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ScmError::InvalidPayload(format!("`{field}` must be an unsigned integer")))
}

pub(super) fn integer_or_string(
    object: &Value,
    field: &'static str,
    limits: WebhookLimits,
) -> Result<String, ScmError> {
    let value = object
        .get(field)
        .ok_or_else(|| ScmError::InvalidPayload(format!("missing `{field}`")))?;
    let rendered = if let Some(value) = value.as_u64() {
        value.to_string()
    } else if let Some(value) = value.as_str() {
        value.to_owned()
    } else {
        return Err(ScmError::InvalidPayload(format!(
            "`{field}` must be an unsigned integer or string"
        )));
    };
    validate_identifier(field, &rendered, limits)
}

pub(super) fn git_commit(object: &Value, field: &'static str) -> Result<String, ScmError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ScmError::InvalidPayload(format!("`{field}` must be a Git object id")))?;
    validate_git_commit(value)?;
    Ok(value.to_owned())
}
