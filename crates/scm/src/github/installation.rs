use super::{
    client::{GitHubAppJwtProvider, GitHubMethod, GitHubRequest, GitHubTransport, SensitiveToken},
    pagination::{parse_catalog_token, parse_installation_metadata, parse_installation_token},
    response_error, valid_account_login, valid_repository_segment,
    validation::{headers, parse_strict_json, serialize_body, validate_token_request},
    GitHubAppBroker, GitHubError,
};
use base64ct::{Base64, Encoding as _};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubPermission {
    Metadata,
    Contents,
    PullRequests,
    Checks,
    Statuses,
    Actions,
    MergeQueues,
    Issues,
}

impl GitHubPermission {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Contents => "contents",
            Self::PullRequests => "pull_requests",
            Self::Checks => "checks",
            Self::Statuses => "statuses",
            Self::Actions => "actions",
            Self::MergeQueues => "merge_queues",
            Self::Issues => "issues",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitHubPermissionLevel {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHubRepositoryPermission {
    None,
    Read,
    Triage,
    Write,
    Maintain,
    Admin,
}

impl GitHubRepositoryPermission {
    #[must_use]
    pub const fn can_approve_workflow(self) -> bool {
        matches!(self, Self::Write | Self::Maintain | Self::Admin)
    }
}

impl GitHubPermissionLevel {
    pub(super) const fn api_name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub const fn satisfies(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::Read, Self::Read) | (Self::Write, Self::Read | Self::Write)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubAccountKind {
    Organization,
    User,
}

impl GitHubAccountKind {
    pub(super) fn from_api(value: &str) -> Result<Self, GitHubError> {
        match value {
            "Organization" => Ok(Self::Organization),
            "User" => Ok(Self::User),
            _ => Err(GitHubError::MalformedResponse),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubAccount {
    pub id: u64,
    pub login: String,
    pub kind: GitHubAccountKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubRepositorySelection {
    All,
    Selected,
}

impl GitHubRepositorySelection {
    pub(super) fn from_api(value: &str) -> Result<Self, GitHubError> {
        match value {
            "all" => Ok(Self::All),
            "selected" => Ok(Self::Selected),
            _ => Err(GitHubError::MalformedResponse),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubRepositoryVisibility {
    Internal,
    Private,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubInstallationRepository {
    pub id: u64,
    pub owner: GitHubAccount,
    pub name: String,
    pub full_name: String,
    pub visibility: GitHubRepositoryVisibility,
    pub default_branch: Option<String>,
    pub archived: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubInstallationSnapshot {
    pub installation_id: u64,
    pub app_id: u64,
    pub account: GitHubAccount,
    pub target_id: u64,
    pub target_kind: GitHubAccountKind,
    pub repository_selection: GitHubRepositorySelection,
    pub permissions: BTreeMap<GitHubPermission, GitHubPermissionLevel>,
    pub suspended_at: Option<String>,
    /// False only when an installation is suspended. The service deliberately
    /// avoids minting any installation token in that state.
    pub repository_catalog_complete: bool,
    pub repositories: Vec<GitHubInstallationRepository>,
}

impl GitHubInstallationSnapshot {
    /// Validate the minimum permissions used by Runtrue's source, pull-request,
    /// and check projection paths. Extra known read/write permissions remain
    /// visible to policy; unknown permission names fail during parsing.
    pub fn validate_runtrue_ci_permissions(&self) -> Result<(), GitHubError> {
        let required = [
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Contents, GitHubPermissionLevel::Read),
            (GitHubPermission::PullRequests, GitHubPermissionLevel::Read),
            (GitHubPermission::Checks, GitHubPermissionLevel::Write),
        ];
        if required.iter().all(|(permission, level)| {
            self.permissions
                .get(permission)
                .is_some_and(|granted| granted.satisfies(*level))
        }) {
            Ok(())
        } else {
            Err(GitHubError::InsufficientInstallationPermissions)
        }
    }
}

/// Object-safe provider boundary consumed by HTTP setup callbacks and durable
/// reconciliation workers. Implementations return metadata only; App JWTs and
/// installation tokens cannot cross this interface.
pub trait GitHubInstallationProvider: Send + Sync {
    fn inspect_installation(
        &self,
        installation_id: u64,
        now_unix_seconds: u64,
    ) -> Result<GitHubInstallationSnapshot, GitHubError>;
}

pub type SharedGitHubInstallationProvider = Arc<dyn GitHubInstallationProvider>;

pub struct GitHubInstallationService<T, J> {
    pub(super) broker: Mutex<GitHubAppBroker<T, J>>,
    app_id: u64,
}

impl<T, J> fmt::Debug for GitHubInstallationService<T, J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubInstallationService")
            .field("broker", &"[REDACTED]")
            .field("app_id", &self.app_id)
            .finish()
    }
}

impl<T, J> GitHubInstallationService<T, J>
where
    T: GitHubTransport,
    J: GitHubAppJwtProvider,
{
    pub fn new(broker: GitHubAppBroker<T, J>, app_id: u64) -> Result<Self, GitHubError> {
        if app_id == 0 {
            return Err(GitHubError::InvalidConfiguration);
        }
        Ok(Self {
            broker: Mutex::new(broker),
            app_id,
        })
    }
}

impl<T, J> GitHubInstallationProvider for GitHubInstallationService<T, J>
where
    T: GitHubTransport + Send,
    J: GitHubAppJwtProvider + Send,
{
    fn inspect_installation(
        &self,
        installation_id: u64,
        now_unix_seconds: u64,
    ) -> Result<GitHubInstallationSnapshot, GitHubError> {
        if installation_id == 0 {
            return Err(GitHubError::InvalidInstallation);
        }
        self.broker
            .lock()
            .map_err(|_| GitHubError::Transport)?
            .inspect_installation(installation_id, self.app_id, now_unix_seconds)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationTokenRequest {
    pub installation_id: u64,
    pub repository_ids: Vec<u64>,
    pub permissions: BTreeMap<GitHubPermission, GitHubPermissionLevel>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct InstallationToken {
    pub(super) token: SensitiveToken,
    pub installation_id: u64,
    pub repository_ids: Vec<u64>,
    pub permissions: BTreeMap<GitHubPermission, GitHubPermissionLevel>,
    pub expires_at: String,
    pub scope_digest: ContentDigest,
    pub(super) expires_at_unix_seconds: u64,
}

pub(super) struct InstallationCatalogToken {
    pub(super) token: SensitiveToken,
    pub(super) installation_id: u64,
    pub(super) expires_at_unix_seconds: u64,
}

impl fmt::Debug for InstallationCatalogToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationCatalogToken")
            .field("token", &"[REDACTED]")
            .field("installation_id", &self.installation_id)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

impl fmt::Debug for InstallationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationToken")
            .field("token", &"[REDACTED]")
            .field("installation_id", &self.installation_id)
            .field("repository_ids", &self.repository_ids)
            .field("permissions", &self.permissions)
            .field("expires_at", &self.expires_at)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

/// Opaque repository-read credential for the Git child-process credential
/// channel. The bearer value is zeroized and cannot appear in Debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct GitHubRepositoryCredential {
    authorization_header: Zeroizing<String>,
    pub installation_id: u64,
    pub repository_id: u64,
    pub expires_at_unix_seconds: u64,
    pub scope_digest: ContentDigest,
}

/// Opaque, exact-repository provider credential released only through the
/// encrypted runner broker. Debug output and cloning never expose the bearer.
#[derive(Clone, PartialEq, Eq)]
pub struct GitHubProviderCredential {
    bearer_token: Zeroizing<String>,
    pub installation_id: u64,
    pub repository_id: u64,
    pub permissions: BTreeMap<GitHubPermission, GitHubPermissionLevel>,
    pub expires_at_unix_seconds: u64,
    pub scope_digest: ContentDigest,
}

impl fmt::Debug for GitHubProviderCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubProviderCredential")
            .field("bearer_token", &"[REDACTED]")
            .field("installation_id", &self.installation_id)
            .field("repository_id", &self.repository_id)
            .field("permissions", &self.permissions)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl GitHubProviderCredential {
    /// This is the only export point and is intended for immediate encrypted
    /// runner delivery. Callers must not persist, log, or interpolate it.
    #[must_use]
    pub fn bearer_token(&self) -> &str {
        self.bearer_token.as_str()
    }
}

impl fmt::Debug for GitHubRepositoryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubRepositoryCredential")
            .field("authorization_header", &"[REDACTED]")
            .field("installation_id", &self.installation_id)
            .field("repository_id", &self.repository_id)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl GitHubRepositoryCredential {
    /// Intended only for the hardened Git credential callback. Callers must
    /// neither persist nor log this value.
    #[must_use]
    pub fn authorization_header(&self) -> &str {
        self.authorization_header.as_str()
    }
}

impl InstallationToken {
    pub fn into_provider_credential(
        self,
        repository_id: u64,
    ) -> Result<GitHubProviderCredential, GitHubError> {
        if self.repository_ids.as_slice() != [repository_id] {
            return Err(GitHubError::InvalidTokenScope);
        }
        Ok(GitHubProviderCredential {
            bearer_token: Zeroizing::new(self.token.expose().to_owned()),
            installation_id: self.installation_id,
            repository_id,
            permissions: self.permissions,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            scope_digest: self.scope_digest,
        })
    }

    pub fn into_repository_read_credential(
        self,
        repository_id: u64,
    ) -> Result<GitHubRepositoryCredential, GitHubError> {
        let expected_permissions = BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Contents, GitHubPermissionLevel::Read),
        ]);
        if self.repository_ids.as_slice() != [repository_id]
            || self.permissions != expected_permissions
        {
            return Err(GitHubError::InvalidTokenScope);
        }
        let mut basic = Zeroizing::new(String::with_capacity(
            "x-access-token:".len() + self.token.expose().len(),
        ));
        basic.push_str("x-access-token:");
        basic.push_str(self.token.expose());
        let encoded = Zeroizing::new(Base64::encode_string(basic.as_bytes()));
        Ok(GitHubRepositoryCredential {
            authorization_header: Zeroizing::new(format!(
                "Authorization: Basic {}",
                encoded.as_str()
            )),
            installation_id: self.installation_id,
            repository_id,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            scope_digest: self.scope_digest,
        })
    }
}

impl<T, J> GitHubAppBroker<T, J>
where
    T: GitHubTransport,
    J: GitHubAppJwtProvider,
{
    pub fn mint_installation_token(
        &mut self,
        request: InstallationTokenRequest,
        now_unix_seconds: u64,
    ) -> Result<InstallationToken, GitHubError> {
        validate_token_request(&request)?;
        let jwt = self.jwt_provider.mint(now_unix_seconds)?;
        let permissions = request
            .permissions
            .iter()
            .map(|(permission, level)| (permission.api_name(), level.api_name()))
            .collect::<BTreeMap<_, _>>();
        let body = serialize_body(&json!({
            "repository_ids": request.repository_ids,
            "permissions": permissions,
        }))?;
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Post,
            url: format!(
                "{}/app/installations/{}/access_tokens",
                self.api_origin, request.installation_id
            ),
            headers: headers(&self.api_origin),
            bearer_token: jwt,
            body,
        })?;
        if response.status != 201 {
            return Err(response_error(&response));
        }
        parse_installation_token(response.body(), request, now_unix_seconds)
    }

    /// Resolve an exact branch head using a one-repository contents token.
    /// The returned object id is provider-authoritative and contains no
    /// payload-supplied URL or repository identity.
    pub fn resolve_repository_branch_head(
        &mut self,
        token: &InstallationToken,
        repository_id: u64,
        owner: &str,
        repository: &str,
        branch: &str,
    ) -> Result<String, GitHubError> {
        let expected_permissions = BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::Contents, GitHubPermissionLevel::Read),
        ]);
        if token.repository_ids.as_slice() != [repository_id]
            || token.permissions != expected_permissions
            || !valid_account_login(owner)
            || !valid_repository_segment(repository)
            || !valid_branch_name(branch)
        {
            return Err(GitHubError::InvalidTokenScope);
        }
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Get,
            url: format!(
                "{}/repos/{owner}/{repository}/git/ref/heads/{}",
                self.api_origin,
                encode_path_segment(branch)
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
        let object = value
            .as_object()
            .and_then(|value| value.get("object"))
            .and_then(serde_json::Value::as_object)
            .ok_or(GitHubError::MalformedResponse)?;
        let sha = object
            .get("sha")
            .and_then(serde_json::Value::as_str)
            .filter(|sha| sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(GitHubError::MalformedResponse)?;
        Ok(sha.to_ascii_lowercase())
    }

    /// Re-fetch the authoritative repository permission for the exact webhook
    /// actor before accepting a GitHub-native approval action.
    pub fn repository_permission_for_user(
        &mut self,
        token: &InstallationToken,
        repository_id: u64,
        owner: &str,
        repository: &str,
        user_id: u64,
        login: &str,
    ) -> Result<GitHubRepositoryPermission, GitHubError> {
        let expected_permissions = BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::PullRequests, GitHubPermissionLevel::Read),
        ]);
        if token.repository_ids.as_slice() != [repository_id]
            || token.permissions != expected_permissions
            || user_id == 0
            || !valid_account_login(owner)
            || !valid_repository_segment(repository)
            || !valid_account_login(login)
        {
            return Err(GitHubError::InvalidTokenScope);
        }
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Get,
            url: format!(
                "{}/repos/{owner}/{repository}/collaborators/{login}/permission",
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
        let user = value
            .get("user")
            .and_then(serde_json::Value::as_object)
            .ok_or(GitHubError::MalformedResponse)?;
        if user.get("id").and_then(serde_json::Value::as_u64) != Some(user_id)
            || !user
                .get("login")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(login))
        {
            return Err(GitHubError::MalformedResponse);
        }
        match value.get("permission").and_then(serde_json::Value::as_str) {
            Some("none") => Ok(GitHubRepositoryPermission::None),
            Some("read") => Ok(GitHubRepositoryPermission::Read),
            Some("triage") => Ok(GitHubRepositoryPermission::Triage),
            Some("write") => Ok(GitHubRepositoryPermission::Write),
            Some("maintain") => Ok(GitHubRepositoryPermission::Maintain),
            Some("admin") => Ok(GitHubRepositoryPermission::Admin),
            _ => Err(GitHubError::MalformedResponse),
        }
    }

    pub fn pull_request_head(
        &mut self,
        token: &InstallationToken,
        repository_id: u64,
        owner: &str,
        repository: &str,
        pull_request_number: u64,
    ) -> Result<String, GitHubError> {
        let expected_permissions = BTreeMap::from([
            (GitHubPermission::Metadata, GitHubPermissionLevel::Read),
            (GitHubPermission::PullRequests, GitHubPermissionLevel::Read),
        ]);
        if token.repository_ids.as_slice() != [repository_id]
            || token.permissions != expected_permissions
            || pull_request_number == 0
            || !valid_account_login(owner)
            || !valid_repository_segment(repository)
        {
            return Err(GitHubError::InvalidTokenScope);
        }
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Get,
            url: format!(
                "{}/repos/{owner}/{repository}/pulls/{pull_request_number}",
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
        if value.get("state").and_then(serde_json::Value::as_str) != Some("open") {
            return Err(GitHubError::InvalidCheckRequest);
        }
        value
            .pointer("/head/sha")
            .and_then(serde_json::Value::as_str)
            .filter(|sha| sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase)
            .ok_or(GitHubError::MalformedResponse)
    }

    fn inspect_installation(
        &mut self,
        installation_id: u64,
        expected_app_id: u64,
        now_unix_seconds: u64,
    ) -> Result<GitHubInstallationSnapshot, GitHubError> {
        if installation_id == 0 || expected_app_id == 0 {
            return Err(GitHubError::InvalidInstallation);
        }
        let jwt = self.jwt_provider.mint(now_unix_seconds)?;
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Get,
            url: format!("{}/app/installations/{installation_id}", self.api_origin),
            headers: headers(&self.api_origin),
            bearer_token: jwt,
            body: Zeroizing::new(Vec::new()),
        })?;
        if response.status != 200 {
            return Err(response_error(&response));
        }
        let value =
            parse_strict_json(response.body()).map_err(|_| GitHubError::MalformedResponse)?;
        let mut snapshot = parse_installation_metadata(&value, expected_app_id)?;
        if snapshot.installation_id != installation_id {
            return Err(GitHubError::InstallationSubstitution);
        }
        if snapshot.suspended_at.is_some() {
            snapshot.repository_catalog_complete = false;
            return Ok(snapshot);
        }

        let catalog_token = self.mint_catalog_token(
            installation_id,
            snapshot.repository_selection,
            now_unix_seconds,
        )?;
        snapshot.repositories = self.list_installation_repositories(
            &catalog_token,
            &snapshot.account,
            now_unix_seconds,
        )?;
        snapshot.repository_catalog_complete = true;
        Ok(snapshot)
    }

    fn mint_catalog_token(
        &mut self,
        installation_id: u64,
        repository_selection: GitHubRepositorySelection,
        now_unix_seconds: u64,
    ) -> Result<InstallationCatalogToken, GitHubError> {
        let jwt = self.jwt_provider.mint(now_unix_seconds)?;
        let body = serialize_body(&json!({
            "permissions": {"metadata": "read"}
        }))?;
        let response = self.transport.send(GitHubRequest {
            method: GitHubMethod::Post,
            url: format!(
                "{}/app/installations/{installation_id}/access_tokens",
                self.api_origin
            ),
            headers: headers(&self.api_origin),
            bearer_token: jwt,
            body,
        })?;
        if response.status != 201 {
            return Err(response_error(&response));
        }
        parse_catalog_token(
            response.body(),
            installation_id,
            repository_selection,
            now_unix_seconds,
        )
    }
}

fn valid_branch_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && value.bytes().all(|byte| {
            byte >= 0x21
                && byte != 0x7f
                && !matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}
