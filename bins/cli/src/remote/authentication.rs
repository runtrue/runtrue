use super::{
    super::{absolute, CliError},
    client::{RemoteClient, ServerOrigin},
    submit::bounded_request_bytes,
    SubmitError, MAX_TOKEN_BYTES,
};
use runtrue_model::ContentDigest;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags, ABS};

/// Reuse the hardened submit transport for authenticated control-plane
/// mutations without duplicating bearer-file or origin validation.
pub(crate) struct AuthenticatedRemote {
    client: RemoteClient,
}

impl AuthenticatedRemote {
    pub(crate) fn new(
        workspace: &Path,
        server: &str,
        allow_loopback_http: bool,
        token_file: PathBuf,
    ) -> Result<Self, CliError> {
        let origin = ServerOrigin::parse(server, allow_loopback_http)?;
        let token_path = absolute(workspace, token_file);
        let token = read_bearer_token(&token_path)?;
        Ok(Self {
            client: RemoteClient::new(origin, token),
        })
    }

    /// The API path is included in the idempotency subject so equal request
    /// bodies for different resources can never share a key.
    pub(crate) fn post_json<T: DeserializeOwned>(
        &self,
        operation: &'static str,
        path: &str,
        idempotency_prefix: &str,
        request: &impl Serialize,
    ) -> Result<(T, bool), CliError> {
        let request_bytes = bounded_request_bytes(request)?;
        let mut subject = Vec::with_capacity(path.len() + request_bytes.len() + 1);
        subject.extend_from_slice(path.as_bytes());
        subject.push(0);
        subject.extend_from_slice(&request_bytes);
        let key = idempotency_key(idempotency_prefix, &subject);
        self.client
            .post_json(operation, path, &key, &request_bytes)
            .map_err(CliError::from)
    }
}

pub(super) fn idempotency_key(prefix: &str, subject: &[u8]) -> String {
    let digest = ContentDigest::sha256(subject);
    format!("{prefix}-{}", digest.as_str().trim_start_matches("sha256:"))
}

pub(crate) fn valid_api_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(super) fn read_bearer_token(path: &Path) -> Result<Zeroizing<String>, SubmitError> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[cfg(target_os = "linux")]
    let file = openat2(
        ABS,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|source| SubmitError::TokenIo {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    #[cfg(not(target_os = "linux"))]
    compile_error!("runtrue submit currently requires Linux openat2 for no-follow token loading");
    let metadata = file.metadata().map_err(|source| SubmitError::TokenIo {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(SubmitError::UnsafeTokenFile {
            path: path.to_path_buf(),
            reason: "token path must be a regular file",
        });
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        return Err(SubmitError::UnsafeTokenFile {
            path: path.to_path_buf(),
            reason: "token file must have mode 0600 and exactly one hard link",
        });
    }

    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_TOKEN_BYTES + 1)
        .read_to_end(bytes.as_mut())
        .map_err(|source| SubmitError::TokenIo {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Err(SubmitError::UnsafeTokenFile {
            path: path.to_path_buf(),
            reason: "token file must contain between 1 and 4096 bytes",
        });
    }
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    if bytes.is_empty()
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(SubmitError::UnsafeTokenFile {
            path: path.to_path_buf(),
            reason: "token must be non-empty visible ASCII without whitespace",
        });
    }
    let owned = std::mem::take(bytes.as_mut());
    String::from_utf8(owned)
        .map(Zeroizing::new)
        .map_err(|_| SubmitError::UnsafeTokenFile {
            path: path.to_path_buf(),
            reason: "token must be valid UTF-8",
        })
}
