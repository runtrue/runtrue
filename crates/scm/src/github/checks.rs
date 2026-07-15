use super::{
    client::{GitHubAppJwtProvider, GitHubMethod, GitHubRequest, GitHubTransport},
    installation::{GitHubPermission, GitHubPermissionLevel, InstallationToken},
    response_error,
    validation::{headers, parse_strict_json, serialize_body},
    webhook::validate_git_commit,
    GitHubAppBroker, GitHubError, MAX_ANNOTATIONS_PER_REQUEST, MAX_ANNOTATIONS_TOTAL,
    MAX_CHECK_ACTIONS, MAX_CHECK_ACTION_DESCRIPTION_BYTES, MAX_CHECK_ACTION_IDENTIFIER_BYTES,
    MAX_CHECK_ACTION_LABEL_BYTES, MAX_CHECK_NAME_BYTES, MAX_CHECK_TEXT_BYTES,
    MAX_CHECK_TITLE_BYTES, MAX_EXTERNAL_ID_BYTES,
};
use runtrue_model::normalize_relative_path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Queued,
    InProgress,
    Completed,
}

impl CheckStatus {
    pub(super) const fn api_name(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    ActionRequired,
    Cancelled,
    Failure,
    Neutral,
    Success,
    Skipped,
    TimedOut,
}

impl CheckConclusion {
    pub(super) const fn api_name(self) -> &'static str {
        match self {
            Self::ActionRequired => "action_required",
            Self::Cancelled => "cancelled",
            Self::Failure => "failure",
            Self::Neutral => "neutral",
            Self::Success => "success",
            Self::Skipped => "skipped",
            Self::TimedOut => "timed_out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckAnnotationLevel {
    Notice,
    Warning,
    Failure,
}

impl CheckAnnotationLevel {
    pub(super) const fn api_name(self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckAnnotation {
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub start_column: Option<u64>,
    pub end_column: Option<u64>,
    pub level: CheckAnnotationLevel,
    pub message: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRunRequestedAction {
    pub label: String,
    pub description: String,
    pub identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRunRequest {
    pub repository_id: u64,
    pub owner: String,
    pub repository: String,
    pub name: String,
    pub head_sha: String,
    pub details_url: Option<String>,
    pub external_id: String,
    pub status: CheckStatus,
    pub conclusion: Option<CheckConclusion>,
    pub title: String,
    pub summary: String,
    pub render_markdown: bool,
    pub actions: Vec<CheckRunRequestedAction>,
    pub trusted_base_workflow: bool,
    pub annotations: Vec<CheckAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedCheckRun {
    pub check_run_id: u64,
    pub annotation_requests: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciledCheckRun {
    pub check_run_id: u64,
    pub confirmed_annotations: usize,
}

impl<T, J> GitHubAppBroker<T, J>
where
    T: GitHubTransport,
    J: GitHubAppJwtProvider,
{
    /// Create a check run and append annotations in batches of at most 50.
    /// The installation token is never returned to a caller or included in a
    /// request body, result, loggable debug value, or error.
    pub fn publish_check_run(
        &mut self,
        token: &InstallationToken,
        request: &CheckRunRequest,
        now_unix_seconds: u64,
    ) -> Result<PublishedCheckRun, GitHubError> {
        validate_check_request(token, request, now_unix_seconds)?;
        let chunks = annotation_chunks(&request.annotations);
        let first_annotations = chunks.first().copied().unwrap_or(&[]);
        let create_body = check_body(request, first_annotations, true)?;
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Post,
            url: format!(
                "{}/repos/{}/{}/check-runs",
                self.api_origin, request.owner, request.repository
            ),
            headers: headers(&self.api_origin),
            bearer_token: token.token.clone(),
            body: create_body,
        })?;
        if response.status != 201 {
            return Err(response_error(&response));
        }
        let check_run_id = response_id(response.body())?;
        let mut confirmed_annotations = first_annotations.len();
        self.append_check_annotations(
            token,
            request,
            check_run_id,
            confirmed_annotations,
            &mut confirmed_annotations,
        )?;
        Ok(PublishedCheckRun {
            check_run_id,
            annotation_requests: chunks.len().max(1),
        })
    }

    /// Find the exact provider projection after a response may have been lost.
    /// Matching is deliberately over the immutable commit, logical name, and
    /// external id; a same-name check from another run is never adopted.
    pub fn reconcile_check_run(
        &mut self,
        token: &InstallationToken,
        request: &CheckRunRequest,
        now_unix_seconds: u64,
    ) -> Result<Option<ReconciledCheckRun>, GitHubError> {
        validate_check_request(token, request, now_unix_seconds)?;
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Get,
            url: format!(
                "{}/repos/{}/{}/commits/{}/check-runs?filter=all&per_page=100",
                self.api_origin, request.owner, request.repository, request.head_sha
            ),
            headers: headers(&self.api_origin),
            bearer_token: token.token.clone(),
            body: Zeroizing::new(Vec::new()),
        })?;
        if response.status != 200 {
            return Err(response_error(&response));
        }
        let body =
            parse_strict_json(response.body()).map_err(|_| GitHubError::MalformedResponse)?;
        let runs = body
            .get("check_runs")
            .and_then(Value::as_array)
            .ok_or(GitHubError::MalformedResponse)?;
        if runs.len() > 100 {
            return Err(GitHubError::MalformedResponse);
        }
        let mut matching_ids = Vec::new();
        for run in runs {
            if run.get("name").and_then(Value::as_str) == Some(request.name.as_str())
                && run.get("head_sha").and_then(Value::as_str) == Some(request.head_sha.as_str())
                && run.get("external_id").and_then(Value::as_str)
                    == Some(request.external_id.as_str())
            {
                let id = run
                    .get("id")
                    .and_then(Value::as_u64)
                    .filter(|id| *id != 0)
                    .ok_or(GitHubError::MalformedResponse)?;
                matching_ids.push(id);
            }
        }
        if matching_ids.len() > 1 {
            return Err(GitHubError::AmbiguousCheckReconciliation);
        }
        let Some(check_run_id) = matching_ids.pop() else {
            return Ok(None);
        };
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Get,
            url: format!(
                "{}/repos/{}/{}/check-runs/{check_run_id}",
                self.api_origin, request.owner, request.repository
            ),
            headers: headers(&self.api_origin),
            bearer_token: token.token.clone(),
            body: Zeroizing::new(Vec::new()),
        })?;
        if response.status != 200 {
            return Err(response_error(&response));
        }
        let run = parse_strict_json(response.body()).map_err(|_| GitHubError::MalformedResponse)?;
        if run.get("id").and_then(Value::as_u64) != Some(check_run_id)
            || run.get("name").and_then(Value::as_str) != Some(request.name.as_str())
            || run.get("head_sha").and_then(Value::as_str) != Some(request.head_sha.as_str())
            || run.get("external_id").and_then(Value::as_str) != Some(request.external_id.as_str())
        {
            return Err(GitHubError::MalformedResponse);
        }
        let confirmed_annotations = run
            .get("output")
            .and_then(|output| output.get("annotations_count"))
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(GitHubError::MalformedResponse)?;
        if confirmed_annotations > request.annotations.len() {
            return Err(GitHubError::AmbiguousCheckReconciliation);
        }
        Ok(Some(ReconciledCheckRun {
            check_run_id,
            confirmed_annotations,
        }))
    }

    /// Resume an exact reconciled check without re-creating it. The provider's
    /// confirmed annotation count is used as the append cursor.
    pub fn resume_check_run(
        &mut self,
        token: &InstallationToken,
        request: &CheckRunRequest,
        reconciled: ReconciledCheckRun,
        now_unix_seconds: u64,
    ) -> Result<PublishedCheckRun, GitHubError> {
        validate_check_request(token, request, now_unix_seconds)?;
        let mut confirmed_annotations = reconciled.confirmed_annotations;
        self.append_check_annotations(
            token,
            request,
            reconciled.check_run_id,
            reconciled.confirmed_annotations,
            &mut confirmed_annotations,
        )?;
        Ok(PublishedCheckRun {
            check_run_id: reconciled.check_run_id,
            annotation_requests: request.annotations[reconciled.confirmed_annotations..]
                .chunks(MAX_ANNOTATIONS_PER_REQUEST)
                .count(),
        })
    }

    fn append_check_annotations(
        &mut self,
        token: &InstallationToken,
        request: &CheckRunRequest,
        check_run_id: u64,
        start: usize,
        confirmed_annotations: &mut usize,
    ) -> Result<(), GitHubError> {
        let remaining = &request.annotations[start..];
        // Reconciliation is also how queued/in-progress checks advance to a
        // terminal state. A check with no new annotations still needs one
        // PATCH carrying status, conclusion, title, and summary.
        if remaining.is_empty() {
            let body = check_body(request, &[], false)?;
            let response = self
                .transport
                .send(GitHubRequest {
                    method: GitHubMethod::Patch,
                    url: format!(
                        "{}/repos/{}/{}/check-runs/{check_run_id}",
                        self.api_origin, request.owner, request.repository
                    ),
                    headers: headers(&self.api_origin),
                    bearer_token: token.token.clone(),
                    body,
                })
                .map_err(|_| GitHubError::PartialPublish {
                    check_run_id,
                    confirmed_annotations: *confirmed_annotations,
                })?;
            if response.status != 200 {
                if response.status == 429 {
                    return Err(response_error(&response));
                }
                return Err(GitHubError::PartialPublish {
                    check_run_id,
                    confirmed_annotations: *confirmed_annotations,
                });
            }
            return Ok(());
        }
        for annotations in remaining.chunks(MAX_ANNOTATIONS_PER_REQUEST) {
            let body = check_body(request, annotations, false)?;
            let response = match self.transport.send(GitHubRequest {
                method: GitHubMethod::Patch,
                url: format!(
                    "{}/repos/{}/{}/check-runs/{check_run_id}",
                    self.api_origin, request.owner, request.repository
                ),
                headers: headers(&self.api_origin),
                bearer_token: token.token.clone(),
                body,
            }) {
                Ok(response) => response,
                Err(_) => {
                    return Err(GitHubError::PartialPublish {
                        check_run_id,
                        confirmed_annotations: *confirmed_annotations,
                    })
                }
            };
            if response.status != 200 {
                if response.status == 429 {
                    return Err(response_error(&response));
                }
                return Err(GitHubError::PartialPublish {
                    check_run_id,
                    confirmed_annotations: *confirmed_annotations,
                });
            }
            *confirmed_annotations += annotations.len();
        }
        Ok(())
    }
}
pub(super) fn validate_check_request(
    token: &InstallationToken,
    request: &CheckRunRequest,
    now_unix_seconds: u64,
) -> Result<(), GitHubError> {
    if token.expires_at_unix_seconds <= now_unix_seconds.saturating_add(30)
        || request.repository_id == 0
        || token
            .repository_ids
            .binary_search(&request.repository_id)
            .is_err()
        || token.permissions.get(&GitHubPermission::Checks) != Some(&GitHubPermissionLevel::Write)
        || request.annotations.len() > MAX_ANNOTATIONS_TOTAL
        || request.actions.len() > MAX_CHECK_ACTIONS
        || !valid_repository_segment(&request.owner)
        || !valid_repository_segment(&request.repository)
        || !valid_bounded_text(&request.name, MAX_CHECK_NAME_BYTES, false)
        || !valid_bounded_text(&request.external_id, MAX_EXTERNAL_ID_BYTES, false)
        || !valid_bounded_text(&request.title, MAX_CHECK_TITLE_BYTES, false)
        || !valid_bounded_text(&request.summary, MAX_CHECK_TEXT_BYTES, true)
    {
        return Err(GitHubError::InvalidCheckRequest);
    }
    validate_git_commit(&request.head_sha).map_err(|_| GitHubError::InvalidCheckRequest)?;
    if (request.status == CheckStatus::Completed) != request.conclusion.is_some() {
        return Err(GitHubError::InvalidCheckRequest);
    }
    if let Some(details_url) = &request.details_url {
        if details_url.len() > 2048
            || !details_url.starts_with("https://")
            || details_url.bytes().any(|byte| byte.is_ascii_control())
            || details_url.contains(['<', '>', '"', '\'', ' '])
        {
            return Err(GitHubError::InvalidCheckRequest);
        }
    }
    for annotation in &request.annotations {
        validate_annotation(annotation)?;
    }
    for action in &request.actions {
        if !valid_bounded_text(&action.label, MAX_CHECK_ACTION_LABEL_BYTES, false)
            || !valid_bounded_text(
                &action.description,
                MAX_CHECK_ACTION_DESCRIPTION_BYTES,
                false,
            )
            || !valid_bounded_text(&action.identifier, MAX_CHECK_ACTION_IDENTIFIER_BYTES, false)
        {
            return Err(GitHubError::InvalidCheckRequest);
        }
    }
    Ok(())
}

pub(super) fn valid_repository_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) fn valid_bounded_text(value: &str, max_bytes: usize, multiline: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            !byte.is_ascii_control() || (multiline && matches!(byte, b'\n' | b'\r' | b'\t'))
        })
}

pub(super) fn validate_annotation(annotation: &CheckAnnotation) -> Result<(), GitHubError> {
    let normalized =
        normalize_relative_path(&annotation.path).map_err(|_| GitHubError::InvalidCheckRequest)?;
    if annotation.path.len() > 4096
        || normalized != annotation.path
        || annotation.start_line == 0
        || annotation.end_line < annotation.start_line
        || !valid_bounded_text(&annotation.message, MAX_CHECK_TEXT_BYTES, true)
        || annotation
            .title
            .as_ref()
            .is_some_and(|title| !valid_bounded_text(title, 255, false))
    {
        return Err(GitHubError::InvalidCheckRequest);
    }
    match (annotation.start_column, annotation.end_column) {
        (None, None) => {}
        (Some(start), Some(end))
            if annotation.start_line == annotation.end_line && start > 0 && end >= start => {}
        _ => return Err(GitHubError::InvalidCheckRequest),
    }
    Ok(())
}

pub(super) fn annotation_chunks(annotations: &[CheckAnnotation]) -> Vec<&[CheckAnnotation]> {
    annotations.chunks(MAX_ANNOTATIONS_PER_REQUEST).collect()
}

pub(super) fn check_body(
    request: &CheckRunRequest,
    annotations: &[CheckAnnotation],
    create: bool,
) -> Result<Zeroizing<Vec<u8>>, GitHubError> {
    let annotations = annotations
        .iter()
        .map(|annotation| {
            let message = escape_public_markdown(&annotation.message);
            if message.len() > MAX_CHECK_TEXT_BYTES {
                return Err(GitHubError::InvalidCheckRequest);
            }
            let mut value = serde_json::Map::from_iter([
                ("path".to_owned(), json!(annotation.path)),
                ("start_line".to_owned(), json!(annotation.start_line)),
                ("end_line".to_owned(), json!(annotation.end_line)),
                (
                    "annotation_level".to_owned(),
                    json!(annotation.level.api_name()),
                ),
                ("message".to_owned(), json!(message)),
            ]);
            if let Some(column) = annotation.start_column {
                value.insert("start_column".to_owned(), json!(column));
            }
            if let Some(column) = annotation.end_column {
                value.insert("end_column".to_owned(), json!(column));
            }
            if let Some(title) = &annotation.title {
                let title = escape_public_markdown(title);
                if title.len() > MAX_CHECK_TITLE_BYTES {
                    return Err(GitHubError::InvalidCheckRequest);
                }
                value.insert("title".to_owned(), json!(title));
            }
            Ok(Value::Object(value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut summary = if request.render_markdown {
        request.summary.clone()
    } else {
        escape_public_markdown(&request.summary)
    };
    summary.push_str(if request.trusted_base_workflow {
        "\n\nTrusted-base workflow executed: yes"
    } else {
        "\n\nTrusted-base workflow executed: no"
    });
    let title = if request.render_markdown {
        plain_public_text(&request.title)
    } else {
        escape_public_markdown(&request.title)
    };
    if title.len() > MAX_CHECK_TITLE_BYTES || summary.len() > MAX_CHECK_TEXT_BYTES {
        return Err(GitHubError::InvalidCheckRequest);
    }
    let mut output = serde_json::Map::from_iter([
        ("title".to_owned(), json!(title)),
        ("summary".to_owned(), json!(summary)),
    ]);
    if !annotations.is_empty() {
        output.insert("annotations".to_owned(), Value::Array(annotations));
    }
    let mut body = serde_json::Map::from_iter([
        ("name".to_owned(), json!(request.name)),
        ("external_id".to_owned(), json!(request.external_id)),
        ("status".to_owned(), json!(request.status.api_name())),
        ("output".to_owned(), Value::Object(output)),
    ]);
    if create {
        body.insert("head_sha".to_owned(), json!(request.head_sha));
    }
    if let Some(url) = &request.details_url {
        body.insert("details_url".to_owned(), json!(url));
    }
    if let Some(conclusion) = request.conclusion {
        body.insert("conclusion".to_owned(), json!(conclusion.api_name()));
    }
    if !request.actions.is_empty() {
        body.insert(
            "actions".to_owned(),
            Value::Array(
                request
                    .actions
                    .iter()
                    .map(|action| {
                        json!({
                            "label": plain_public_text(&action.label),
                            "description": plain_public_text(&action.description),
                            "identifier": plain_public_text(&action.identifier),
                        })
                    })
                    .collect(),
            ),
        );
    }
    serialize_body(&Value::Object(body))
}

pub(super) fn escape_public_markdown(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '`'
                | '*'
                | '_'
                | '{'
                | '}'
                | '['
                | ']'
                | '<'
                | '>'
                | '('
                | ')'
                | '#'
                | '+'
                | '-'
                | '.'
                | '!'
                | '|'
                | ':'
                | '~'
                | '@'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn plain_public_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub(super) fn response_id(body: &[u8]) -> Result<u64, GitHubError> {
    parse_strict_json(body)
        .ok()
        .and_then(|value| value.get("id").and_then(Value::as_u64))
        .filter(|id| *id != 0)
        .ok_or(GitHubError::MalformedResponse)
}
