use super::validation::{
    git_commit, is_zero_commit, normalize_paths, object_at, object_field, required_bool,
    required_string, required_u64,
};
use crate::{
    CheckRunEvent, CheckRunEventAction, CheckRunPullRequest, IssueCommentAction, IssueCommentEvent,
};
use crate::{EventType, GitRevision, PullRequestAction, PullRequestEvent, ScmError, WebhookLimits};
use serde_json::Value;

pub(super) type NormalizedParts = (
    EventType,
    GitRevision,
    Option<GitRevision>,
    Option<String>,
    Option<PullRequestEvent>,
    Option<IssueCommentEvent>,
    Option<CheckRunEvent>,
    Vec<String>,
);

pub(super) fn normalize_github_push(
    payload: &Value,
    limits: WebhookLimits,
) -> Result<NormalizedParts, ScmError> {
    let ref_name = required_string(payload, "ref", limits)?;
    let source = GitRevision {
        commit: git_commit(payload, "after")?,
        ref_name: Some(ref_name.clone()),
        repository_full_name: Some(required_string(
            object_at(payload, "repository")?,
            "full_name",
            limits,
        )?),
    };
    let before = git_commit(payload, "before")?;
    let base = (!is_zero_commit(&before)).then_some(GitRevision {
        commit: before,
        ref_name: Some(ref_name.clone()),
        repository_full_name: source.repository_full_name.clone(),
    });
    let mut paths = Vec::new();
    if let Some(commits) = payload.get("commits").and_then(Value::as_array) {
        for commit in commits {
            for field in ["added", "modified", "removed"] {
                if let Some(values) = commit.get(field).and_then(Value::as_array) {
                    for path in values {
                        paths.push(
                            path.as_str()
                                .ok_or_else(|| {
                                    ScmError::InvalidPayload(format!(
                                        "`commits[].{field}[]` must be a string"
                                    ))
                                })?
                                .to_owned(),
                        );
                    }
                }
            }
        }
    }
    normalize_paths(&mut paths, limits)?;
    Ok((
        EventType::Push,
        source,
        base,
        Some(ref_name),
        None,
        None,
        None,
        paths,
    ))
}

pub(super) fn normalize_github_pull_request(
    payload: &Value,
    limits: WebhookLimits,
) -> Result<NormalizedParts, ScmError> {
    let action = match required_string(payload, "action", limits)?.as_str() {
        "opened" => PullRequestAction::Opened,
        "synchronize" => PullRequestAction::Synchronize,
        "reopened" => PullRequestAction::Reopened,
        "edited" => PullRequestAction::Edited,
        "labeled" => PullRequestAction::Labeled,
        "unlabeled" => PullRequestAction::Unlabeled,
        "ready_for_review" => PullRequestAction::ReadyForReview,
        "converted_to_draft" => PullRequestAction::ConvertedToDraft,
        "closed" => PullRequestAction::Closed,
        action => return Err(ScmError::UnsupportedAction(action.to_owned())),
    };
    let pull = object_at(payload, "pull_request")?;
    let head = object_field(pull, "head")?;
    let base_value = object_field(pull, "base")?;
    let head_repo = object_field(head, "repo")?;
    let base_repo = object_field(base_value, "repo")?;
    let source = GitRevision {
        commit: git_commit(head, "sha")?,
        ref_name: Some(required_string(head, "ref", limits)?),
        repository_full_name: Some(required_string(head_repo, "full_name", limits)?),
    };
    let base = GitRevision {
        commit: git_commit(base_value, "sha")?,
        ref_name: Some(required_string(base_value, "ref", limits)?),
        repository_full_name: Some(required_string(base_repo, "full_name", limits)?),
    };
    let ref_name = base.ref_name.clone();
    let pull_request = PullRequestEvent {
        number: required_u64(payload, "number")?,
        draft: required_bool(pull, "draft")?,
        merged: required_bool(pull, "merged")?,
    };
    Ok((
        EventType::PullRequest { action },
        source,
        Some(base),
        ref_name,
        Some(pull_request),
        None,
        None,
        Vec::new(),
    ))
}

pub(super) fn normalize_github_issue_comment(
    payload: &Value,
    limits: WebhookLimits,
) -> Result<NormalizedParts, ScmError> {
    let action = match required_string(payload, "action", limits)?.as_str() {
        "created" => IssueCommentAction::Created,
        "edited" => IssueCommentAction::Edited,
        action => return Err(ScmError::UnsupportedAction(action.to_owned())),
    };
    let repository = object_at(payload, "repository")?;
    let full_name = required_string(repository, "full_name", limits)?;
    let default_branch = required_string(repository, "default_branch", limits)?;
    let issue = object_at(payload, "issue")?;
    let comment = object_at(payload, "comment")?;
    let previous_body = payload
        .get("changes")
        .and_then(|changes| changes.get("body"))
        .and_then(|body| body.get("from"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    for body in [
        comment.get("body").and_then(Value::as_str),
        previous_body.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if body.len() > limits.max_body_bytes {
            return Err(ScmError::LimitExceeded("comment body bytes"));
        }
    }
    let ref_name = format!("refs/heads/{default_branch}");
    Ok((
        EventType::IssueComment { action },
        GitRevision {
            // Non-code events are resolved to the authoritative default-branch
            // head by the SCM worker before trusted planning.
            commit: "0000000000000000000000000000000000000000".to_owned(),
            ref_name: Some(ref_name.clone()),
            repository_full_name: Some(full_name),
        },
        None,
        Some(ref_name),
        None,
        Some(IssueCommentEvent {
            issue_number: required_u64(issue, "number")?,
            issue_is_pull_request: issue.get("pull_request").is_some_and(Value::is_object),
            comment_id: required_u64(comment, "id")?,
            body: comment
                .get("body")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ScmError::InvalidPayload("`comment.body` must be a string".to_owned())
                })?
                .to_owned(),
            previous_body,
        }),
        None,
        Vec::new(),
    ))
}

pub(super) fn normalize_github_check_run(
    payload: &Value,
    limits: WebhookLimits,
) -> Result<NormalizedParts, ScmError> {
    let action = match required_string(payload, "action", limits)?.as_str() {
        "completed" => CheckRunEventAction::Completed,
        "rerequested" => CheckRunEventAction::Rerequested,
        "requested_action" => CheckRunEventAction::RequestedAction,
        action => return Err(ScmError::UnsupportedAction(action.to_owned())),
    };
    let repository = object_at(payload, "repository")?;
    let full_name = required_string(repository, "full_name", limits)?;
    let default_branch = required_string(repository, "default_branch", limits)?;
    let check_run = object_at(payload, "check_run")?;
    let pull_requests = check_run
        .get("pull_requests")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ScmError::InvalidPayload("`check_run.pull_requests` must be a list".to_owned())
        })?;
    if pull_requests.len() > limits.max_changed_paths {
        return Err(ScmError::LimitExceeded("check run pull request count"));
    }
    let pull_requests = pull_requests
        .iter()
        .map(|pull| {
            Ok(CheckRunPullRequest {
                number: required_u64(pull, "number")?,
            })
        })
        .collect::<Result<Vec<_>, ScmError>>()?;
    let ref_name = format!("refs/heads/{default_branch}");
    let requested_action_identifier = if action == CheckRunEventAction::RequestedAction {
        Some(required_string(
            object_at(payload, "requested_action")?,
            "identifier",
            limits,
        )?)
    } else {
        None
    };
    Ok((
        EventType::CheckRun { action },
        GitRevision {
            commit: "0000000000000000000000000000000000000000".to_owned(),
            ref_name: Some(ref_name.clone()),
            repository_full_name: Some(full_name),
        },
        None,
        Some(ref_name),
        None,
        None,
        Some(CheckRunEvent {
            check_run_id: required_u64(check_run, "id")?,
            pull_requests,
            requested_action_identifier,
        }),
        Vec::new(),
    ))
}

pub(super) fn normalize_github_merge_group(
    payload: &Value,
    limits: WebhookLimits,
) -> Result<NormalizedParts, ScmError> {
    if required_string(payload, "action", limits)? != "checks_requested" {
        return Err(ScmError::UnsupportedAction(
            payload
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("invalid")
                .to_owned(),
        ));
    }
    let group = object_at(payload, "merge_group")?;
    let head_ref = required_string(group, "head_ref", limits)?;
    let base_ref = required_string(group, "base_ref", limits)?;
    Ok((
        EventType::MergeGroup,
        GitRevision {
            commit: git_commit(group, "head_sha")?,
            ref_name: Some(head_ref),
            repository_full_name: Some(required_string(
                object_at(payload, "repository")?,
                "full_name",
                limits,
            )?),
        },
        Some(GitRevision {
            commit: git_commit(group, "base_sha")?,
            ref_name: Some(base_ref.clone()),
            repository_full_name: Some(required_string(
                object_at(payload, "repository")?,
                "full_name",
                limits,
            )?),
        }),
        Some(base_ref),
        None,
        None,
        None,
        Vec::new(),
    ))
}

pub(super) fn normalize_github_ping(
    payload: &Value,
    limits: WebhookLimits,
) -> Result<NormalizedParts, ScmError> {
    let repository = object_at(payload, "repository")?;
    let default_branch = required_string(repository, "default_branch", limits)?;
    Ok((
        EventType::Ping,
        GitRevision {
            // Ping carries no revision; a fixed all-zero Git SHA is an explicit sentinel.
            commit: "0000000000000000000000000000000000000000".to_owned(),
            ref_name: Some(default_branch.clone()),
            repository_full_name: Some(required_string(repository, "full_name", limits)?),
        },
        None,
        Some(default_branch),
        None,
        None,
        None,
        Vec::new(),
    ))
}
