use super::checks::{valid_bounded_text, valid_repository_segment};
use super::{
    client::{GitHubAppJwtProvider, GitHubMethod, GitHubRequest, GitHubTransport, SensitiveToken},
    installation::{
        GitHubAccount, GitHubAccountKind, GitHubInstallationRepository, GitHubInstallationSnapshot,
        GitHubPermission, GitHubPermissionLevel, GitHubRepositorySelection,
        GitHubRepositoryVisibility, InstallationCatalogToken, InstallationToken,
        InstallationTokenRequest,
    },
    response_error,
    validation::{headers, parse_strict_json},
    GitHubAppBroker, GitHubError, MAX_ACCOUNT_LOGIN_BYTES, MAX_DEFAULT_BRANCH_BYTES,
    MAX_REPOSITORIES, MAX_REPOSITORIES_PER_PAGE, MAX_SELECTED_REPOSITORIES,
};
use runtrue_model::ContentDigest;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
pub(super) fn parse_installation_token(
    body: &[u8],
    request: InstallationTokenRequest,
    now_unix_seconds: u64,
) -> Result<InstallationToken, GitHubError> {
    let response = parse_strict_json(body).map_err(|_| GitHubError::MalformedResponse)?;
    let response = response.as_object().ok_or(GitHubError::MalformedResponse)?;
    let token = response
        .get("token")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)?;
    let expires_at = response
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)?;
    let expires_at_unix_seconds = parse_utc_timestamp(expires_at)?;
    if expires_at_unix_seconds <= now_unix_seconds.saturating_add(30)
        || expires_at_unix_seconds > now_unix_seconds.saturating_add(60 * 60 + 60)
    {
        return Err(GitHubError::MalformedResponse);
    }
    if response.get("repository_selection").and_then(Value::as_str) != Some("selected") {
        return Err(GitHubError::InvalidTokenScope);
    }
    let mut returned_ids = response
        .get("repositories")
        .and_then(Value::as_array)
        .ok_or(GitHubError::MalformedResponse)?
        .iter()
        .map(|repository| {
            repository
                .get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id != 0)
                .ok_or(GitHubError::MalformedResponse)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if returned_ids.len() > MAX_REPOSITORIES {
        return Err(GitHubError::MalformedResponse);
    }
    let returned_count = returned_ids.len();
    returned_ids.sort_unstable();
    returned_ids.dedup();
    if returned_ids.len() != returned_count || returned_ids != request.repository_ids {
        return Err(GitHubError::InvalidTokenScope);
    }
    let returned_permissions = parse_permissions(
        response
            .get("permissions")
            .and_then(Value::as_object)
            .ok_or(GitHubError::MalformedResponse)?,
    )?;
    if returned_permissions != request.permissions {
        return Err(GitHubError::InvalidTokenScope);
    }

    let scope_bytes = serde_json::to_vec(&json!({
        "scope_version": "runtrue.github.installation-token-scope.v1",
        "installation_id": request.installation_id,
        "repository_ids": request.repository_ids,
        "permissions": request.permissions.iter().map(|(permission, level)| {
            (permission.api_name(), level.api_name())
        }).collect::<BTreeMap<_, _>>(),
    }))
    .map_err(|_| GitHubError::MalformedResponse)?;
    Ok(InstallationToken {
        token: SensitiveToken::new(token.to_owned()).map_err(|_| GitHubError::MalformedResponse)?,
        installation_id: request.installation_id,
        repository_ids: request.repository_ids,
        permissions: request.permissions,
        expires_at: expires_at.to_owned(),
        scope_digest: ContentDigest::sha256(scope_bytes),
        expires_at_unix_seconds,
    })
}

pub(super) fn parse_permissions(
    object: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<GitHubPermission, GitHubPermissionLevel>, GitHubError> {
    object
        .iter()
        .map(|(name, value)| {
            let permission = match name.as_str() {
                "metadata" => GitHubPermission::Metadata,
                "contents" => GitHubPermission::Contents,
                "pull_requests" => GitHubPermission::PullRequests,
                "checks" => GitHubPermission::Checks,
                "statuses" => GitHubPermission::Statuses,
                "actions" => GitHubPermission::Actions,
                "merge_queues" => GitHubPermission::MergeQueues,
                "issues" => GitHubPermission::Issues,
                _ => return Err(GitHubError::InvalidTokenScope),
            };
            let level = match value.as_str() {
                Some("read") => GitHubPermissionLevel::Read,
                Some("write") => GitHubPermissionLevel::Write,
                _ => return Err(GitHubError::MalformedResponse),
            };
            Ok((permission, level))
        })
        .collect()
}

pub(super) fn parse_catalog_token(
    body: &[u8],
    installation_id: u64,
    expected_selection: GitHubRepositorySelection,
    now_unix_seconds: u64,
) -> Result<InstallationCatalogToken, GitHubError> {
    let response = parse_strict_json(body).map_err(|_| GitHubError::MalformedResponse)?;
    let response = response.as_object().ok_or(GitHubError::MalformedResponse)?;
    let token = response
        .get("token")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)?;
    let expires_at = response
        .get("expires_at")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)?;
    let expires_at_unix_seconds = parse_utc_timestamp(expires_at)?;
    if expires_at_unix_seconds <= now_unix_seconds.saturating_add(30)
        || expires_at_unix_seconds > now_unix_seconds.saturating_add(60 * 60)
    {
        return Err(GitHubError::MalformedResponse);
    }
    let selection = response
        .get("repository_selection")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)
        .and_then(GitHubRepositorySelection::from_api)?;
    if selection != expected_selection {
        return Err(GitHubError::InstallationSubstitution);
    }
    let permissions = parse_permissions(
        response
            .get("permissions")
            .and_then(Value::as_object)
            .ok_or(GitHubError::MalformedResponse)?,
    )?;
    if permissions != BTreeMap::from([(GitHubPermission::Metadata, GitHubPermissionLevel::Read)]) {
        return Err(GitHubError::InvalidTokenScope);
    }
    Ok(InstallationCatalogToken {
        token: SensitiveToken::new(token.to_owned()).map_err(|_| GitHubError::MalformedResponse)?,
        installation_id,
        expires_at_unix_seconds,
    })
}

pub(super) fn parse_account(value: &Value) -> Result<GitHubAccount, GitHubError> {
    let object = value.as_object().ok_or(GitHubError::MalformedResponse)?;
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or(GitHubError::MalformedResponse)?;
    let login = object
        .get("login")
        .and_then(Value::as_str)
        .filter(|value| valid_account_login(value))
        .ok_or(GitHubError::MalformedResponse)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)
        .and_then(GitHubAccountKind::from_api)?;
    Ok(GitHubAccount {
        id,
        login: login.to_owned(),
        kind,
    })
}

pub(super) fn parse_installation_metadata(
    value: &Value,
    expected_app_id: u64,
) -> Result<GitHubInstallationSnapshot, GitHubError> {
    let object = value.as_object().ok_or(GitHubError::MalformedResponse)?;
    let installation_id = object
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or(GitHubError::MalformedResponse)?;
    let app_id = object
        .get("app_id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or(GitHubError::MalformedResponse)?;
    if app_id != expected_app_id {
        return Err(GitHubError::InstallationSubstitution);
    }
    let account = object
        .get("account")
        .ok_or(GitHubError::MalformedResponse)
        .and_then(parse_account)?;
    let target_id = object
        .get("target_id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or(GitHubError::MalformedResponse)?;
    let target_kind = object
        .get("target_type")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)
        .and_then(GitHubAccountKind::from_api)?;
    if target_id != account.id || target_kind != account.kind {
        return Err(GitHubError::InstallationSubstitution);
    }
    let repository_selection = object
        .get("repository_selection")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)
        .and_then(GitHubRepositorySelection::from_api)?;
    let permissions = parse_permissions(
        object
            .get("permissions")
            .and_then(Value::as_object)
            .ok_or(GitHubError::MalformedResponse)?,
    )?;
    let suspended_at = match object.get("suspended_at") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if valid_bounded_text(value, 64, false) => {
            Some(value.to_owned())
        }
        _ => return Err(GitHubError::MalformedResponse),
    };
    Ok(GitHubInstallationSnapshot {
        installation_id,
        app_id,
        account,
        target_id,
        target_kind,
        repository_selection,
        permissions,
        suspended_at,
        repository_catalog_complete: false,
        repositories: Vec::new(),
    })
}

pub(super) fn parse_installation_repository(
    value: &Value,
    expected_owner: &GitHubAccount,
) -> Result<GitHubInstallationRepository, GitHubError> {
    let object = value.as_object().ok_or(GitHubError::MalformedResponse)?;
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or(GitHubError::MalformedResponse)?;
    let owner = object
        .get("owner")
        .ok_or(GitHubError::MalformedResponse)
        .and_then(parse_account)?;
    if &owner != expected_owner {
        return Err(GitHubError::InstallationSubstitution);
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| valid_repository_segment(value))
        .ok_or(GitHubError::MalformedResponse)?;
    let full_name = object
        .get("full_name")
        .and_then(Value::as_str)
        .ok_or(GitHubError::MalformedResponse)?;
    if full_name != format!("{}/{name}", owner.login) {
        return Err(GitHubError::InstallationSubstitution);
    }
    let private = object
        .get("private")
        .and_then(Value::as_bool)
        .ok_or(GitHubError::MalformedResponse)?;
    let visibility = match object.get("visibility").and_then(Value::as_str) {
        Some("public") if !private => GitHubRepositoryVisibility::Public,
        Some("private") if private => GitHubRepositoryVisibility::Private,
        Some("internal") if private => GitHubRepositoryVisibility::Internal,
        _ => return Err(GitHubError::InstallationSubstitution),
    };
    let default_branch = match object.get("default_branch") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if valid_default_branch(value) => Some(value.to_owned()),
        _ => return Err(GitHubError::MalformedResponse),
    };
    let archived = optional_bool(object, "archived")?;
    let disabled = optional_bool(object, "disabled")?;
    Ok(GitHubInstallationRepository {
        id,
        owner,
        name: name.to_owned(),
        full_name: full_name.to_owned(),
        visibility,
        default_branch,
        archived,
        disabled,
    })
}

pub(super) fn parse_repository_array(
    value: Option<&Value>,
    expected_owner: &GitHubAccount,
    required: bool,
) -> Result<Vec<GitHubInstallationRepository>, GitHubError> {
    let Some(value) = value else {
        return if required {
            Err(GitHubError::MalformedResponse)
        } else {
            Ok(Vec::new())
        };
    };
    let values = value.as_array().ok_or(GitHubError::MalformedResponse)?;
    if values.len() > MAX_SELECTED_REPOSITORIES {
        return Err(GitHubError::RepositoryCatalogTooLarge);
    }
    let mut repositories = values
        .iter()
        .map(|value| parse_installation_repository(value, expected_owner))
        .collect::<Result<Vec<_>, _>>()?;
    repositories.sort_by_key(|repository| repository.id);
    if repositories.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(GitHubError::InstallationSubstitution);
    }
    Ok(repositories)
}

pub(super) fn optional_bool(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<bool, GitHubError> {
    match object.get(name) {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or(GitHubError::MalformedResponse),
    }
}

pub(super) fn valid_account_login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ACCOUNT_LOGIN_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(super) fn valid_default_branch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DEFAULT_BRANCH_BYTES
        && !matches!(value, "." | ".." | "@")
        && !value.starts_with('.')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.ends_with(".lock")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && value
            .split('/')
            .all(|component| !component.starts_with('.') && !component.ends_with(".lock"))
        && !value.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

pub(super) fn parse_utc_timestamp(value: &str) -> Result<u64, GitHubError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(GitHubError::MalformedResponse);
    }
    fn number(bytes: &[u8]) -> Result<u32, GitHubError> {
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(GitHubError::MalformedResponse);
        }
        bytes.iter().try_fold(0_u32, |value, digit| {
            value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u32::from(*digit - b'0')))
                .ok_or(GitHubError::MalformedResponse)
        })
    }
    let year = number(&bytes[0..4])?;
    let month = number(&bytes[5..7])?;
    let day = number(&bytes[8..10])?;
    let hour = number(&bytes[11..13])?;
    let minute = number(&bytes[14..16])?;
    let second = number(&bytes[17..19])?;
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(GitHubError::MalformedResponse);
    }
    let days = days_before_year(year)
        .checked_add(days_before_month(year, month))
        .and_then(|days| days.checked_add(u64::from(day - 1)))
        .ok_or(GitHubError::MalformedResponse)?;
    days.checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(u64::from(hour) * 3_600))
        .and_then(|seconds| seconds.checked_add(u64::from(minute) * 60))
        .and_then(|seconds| seconds.checked_add(u64::from(second)))
        .ok_or(GitHubError::MalformedResponse)
}

const fn leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

pub(super) fn days_before_year(year: u32) -> u64 {
    let years = u64::from(year - 1970);
    let before = u64::from(year - 1);
    let before_epoch = 1969_u64;
    years * 365 + (before / 4 - before / 100 + before / 400)
        - (before_epoch / 4 - before_epoch / 100 + before_epoch / 400)
}

pub(super) fn days_before_month(year: u32, month: u32) -> u64 {
    (1..month)
        .map(|current| u64::from(days_in_month(year, current)))
        .sum()
}

impl<T, J> GitHubAppBroker<T, J>
where
    T: GitHubTransport,
    J: GitHubAppJwtProvider,
{
    pub(super) fn list_installation_repositories(
        &mut self,
        token: &InstallationCatalogToken,
        account: &GitHubAccount,
        now_unix_seconds: u64,
    ) -> Result<Vec<GitHubInstallationRepository>, GitHubError> {
        if token.expires_at_unix_seconds <= now_unix_seconds.saturating_add(30) {
            return Err(GitHubError::MalformedResponse);
        }
        let mut repositories = Vec::new();
        let mut total_count = None;
        for page in 1..=(MAX_SELECTED_REPOSITORIES / MAX_REPOSITORIES_PER_PAGE) {
            let response = self.transport.send(GitHubRequest {
                method: GitHubMethod::Get,
                url: format!(
                    "{}/installation/repositories?per_page={MAX_REPOSITORIES_PER_PAGE}&page={page}",
                    self.api_origin
                ),
                headers: headers(&self.api_origin),
                bearer_token: token.token.clone(),
                body: Zeroizing::new(Vec::new()),
            })?;
            if response.status != 200 {
                return Err(response_error(&response));
            }
            let value =
                parse_strict_json(response.body()).map_err(|_| GitHubError::MalformedResponse)?;
            let object = value.as_object().ok_or(GitHubError::MalformedResponse)?;
            let observed_total = object
                .get("total_count")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(GitHubError::MalformedResponse)?;
            if observed_total > MAX_SELECTED_REPOSITORIES {
                return Err(GitHubError::RepositoryCatalogTooLarge);
            }
            if total_count
                .replace(observed_total)
                .is_some_and(|prior| prior != observed_total)
            {
                return Err(GitHubError::InstallationSubstitution);
            }
            let page_values = object
                .get("repositories")
                .and_then(Value::as_array)
                .ok_or(GitHubError::MalformedResponse)?;
            if page_values.len() > MAX_REPOSITORIES_PER_PAGE
                || repositories.len().saturating_add(page_values.len()) > observed_total
            {
                return Err(GitHubError::MalformedResponse);
            }
            for repository in page_values {
                repositories.push(parse_installation_repository(repository, account)?);
            }
            if repositories.len() == observed_total {
                break;
            }
            if page_values.is_empty() {
                return Err(GitHubError::MalformedResponse);
            }
        }
        if Some(repositories.len()) != total_count {
            return Err(GitHubError::RepositoryCatalogTooLarge);
        }
        repositories.sort_by_key(|repository| repository.id);
        if repositories.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(GitHubError::InstallationSubstitution);
        }
        Ok(repositories)
    }
}
