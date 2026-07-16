use clap::Parser;
use rand_core::{OsRng, RngCore as _};
use runtrue_control_plane::ControlPlane;
use runtrue_scm::{
    validate_github_app_jwt, GitHubAppBroker, GitHubAppJwtProvider, GitHubAppPublicConfig,
    GitHubError, GitHubInstallationService, GitHubProviderEndpoints, GitHubTransportLimits,
    HardenedGitHubTransport, SensitiveToken, SharedGitHubInstallationProvider,
};
use runtrue_server::{
    router, AppState, GitHubAppInstallationTokenProvider, GitHubInstallationTokenProvider,
    GitHubOauthQuickstartConfig, HardenedGitHubOauthClient, HardenedHumanOidcClient,
    HumanOidcLimits, RunnerCertificateAuthority, RunnerControlConfig, RunnerControlService,
    RunnerEnrollmentService, ScmTaskWorker, ScmWorkerConfig, DEFAULT_RUNNER_CERTIFICATE_LIFETIME,
    DEFAULT_SCM_WORKFLOW_DIRECTORY,
};
#[cfg(feature = "github-actions")]
use runtrue_server::{RepositoryActionBuilder, UnixRepositoryActionBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::{self, Read as _, Write as _},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::watch;
use tonic::transport::{Certificate, Identity, Server as GrpcServer, ServerTlsConfig};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::{
    fd::AsRawFd as _,
    unix::{
        fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        net::UnixStream,
    },
};

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_DATABASE: &str = ".runtrue/server/control-plane.sqlite";
const DEFAULT_SECURITY_KEY: &str = ".runtrue/server/security.key";
const MAX_SECRET_FILE_BYTES: u64 = 4096;
const MAX_RUNNER_TLS_FILE_BYTES: u64 = 1024 * 1024;
const MAX_GITHUB_SIGNER_FRAME_BYTES: usize = 16 * 1024;
const GITHUB_SIGNER_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DUE_SCHEDULES_PER_MAINTENANCE_TICK: usize = 100;

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-server",
    about = "Runtrue durable control-plane HTTP server"
)]
struct Args {
    /// HTTP listen address. Defaults to a loopback-only socket.
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Durable SQLite control-plane database.
    #[arg(long)]
    database: Option<PathBuf>,

    /// Stable installation identifier used by fencing and normalized events.
    #[arg(long)]
    installation_id: Option<String>,

    /// Mode-0600 file containing the bootstrap bearer token.
    #[arg(long)]
    bootstrap_token_file: Option<PathBuf>,

    /// Optional mode-0600 file containing the GitHub webhook HMAC secret.
    #[arg(long)]
    github_webhook_secret_file: Option<PathBuf>,

    /// Numeric GitHub App id used to validate non-exportable signer JWTs.
    #[arg(long)]
    github_app_id: Option<u64>,

    /// Public GitHub App slug used to build provider-owned installation URLs.
    #[arg(long)]
    github_app_slug: Option<String>,

    /// Exact provider reference admitted for stored GitHub App installations.
    #[arg(long)]
    github_app_credential_reference: Option<String>,

    /// Local Unix socket for the non-exportable GitHub App JWT signer.
    #[arg(long)]
    github_app_jwt_provider_socket: Option<PathBuf>,

    /// Exact GitHub web HTTPS origin. Defaults to https://github.com. A GHES
    /// origin also becomes the sole admitted Git mirror authority.
    #[arg(long)]
    github_web_origin: Option<String>,

    /// Exact GitHub API HTTPS origin. GHES requires the configured web origin
    /// plus `/api/v3`; this cannot independently broaden Git mirror origins.
    #[arg(long)]
    github_api_origin: Option<String>,

    /// Durable mode-0600 32-byte installation key (created when absent).
    #[arg(long)]
    security_key_file: Option<PathBuf>,

    /// Public OIDC issuer URL. HTTPS is required except on loopback.
    #[arg(long)]
    oidc_issuer: Option<String>,

    /// Exact public HTTPS origin used for browser OIDC redirects and cookies.
    /// Browser authentication is disabled unless this and the sealing key are
    /// configured together.
    #[arg(long)]
    public_origin: Option<String>,

    /// Mode-0600 file containing the separate 32-byte browser-cookie sealing
    /// key. The installation security key is deliberately not reused.
    #[arg(long)]
    browser_cookie_sealing_key_file: Option<PathBuf>,

    /// Optional mode-0700 root containing owner/name secure local Git mirrors.
    #[arg(long)]
    git_mirror_root: Option<PathBuf>,

    /// Durable local CAS/cache/artifact root used by runner data-plane RPCs.
    #[arg(long)]
    data_root: Option<PathBuf>,

    /// Optional separate runner gRPC listen address. Enabling it requires all
    /// runner TLS, enrollment-listener, and CA options below.
    #[arg(long)]
    runner_grpc_listen: Option<SocketAddr>,

    /// Separate TLS-server-auth-only listener used exclusively for one-time
    /// runner enrollment.
    #[arg(long)]
    runner_enrollment_listen: Option<SocketAddr>,

    /// Mode-0600 PEM server certificate chain for runner gRPC.
    #[arg(long)]
    runner_tls_certificate: Option<PathBuf>,

    /// Mode-0600 PEM private key for runner gRPC.
    #[arg(long)]
    runner_tls_private_key: Option<PathBuf>,

    /// Mode-0600 PEM installation CA used to verify runner client certificates
    /// and form the issued client certificate chain.
    #[arg(long)]
    runner_ca_certificate: Option<PathBuf>,

    /// Mode-0600 PEM installation CA private key used only to sign validated
    /// runner CSRs.
    #[arg(long)]
    runner_ca_private_key: Option<PathBuf>,

    /// Oldest runner protocol generation admitted by enrollment and Open.
    #[arg(long)]
    runner_protocol_minimum: Option<u32>,
}

struct RunnerGrpcPaths {
    control_listen: SocketAddr,
    enrollment_listen: SocketAddr,
    server_certificate: PathBuf,
    server_private_key: PathBuf,
    ca_certificate: PathBuf,
    ca_private_key: PathBuf,
    protocol_minimum: u32,
}

struct GitHubAppConfig {
    app_id: u64,
    public: Option<GitHubAppPublicConfig>,
    credential_reference: String,
    jwt_provider_socket: PathBuf,
    endpoints: GitHubProviderEndpoints,
}

struct HumanOidcStartupConfig {
    public_origin: String,
    cookie_sealing_key_file: PathBuf,
}

struct GitHubOauthStartupConfig {
    tenant_id: String,
    tenant_name: String,
    web_origin: String,
    api_origin: String,
    client_id: String,
    client_secret: Zeroizing<String>,
    allowed_roles: BTreeMap<u64, String>,
}

struct Config {
    listen: SocketAddr,
    database: PathBuf,
    installation_id: String,
    bootstrap_token: Zeroizing<String>,
    github_webhook_secret: Option<Zeroizing<Vec<u8>>>,
    github_app: Option<GitHubAppConfig>,
    security_key_file: PathBuf,
    oidc_issuer: String,
    human_oidc: Option<HumanOidcStartupConfig>,
    github_oauth: Option<GitHubOauthStartupConfig>,
    git_mirror_root: Option<PathBuf>,
    data_root: PathBuf,
    runner_grpc: Option<RunnerGrpcPaths>,
}

impl Config {
    fn load(args: Args) -> Result<Self, StartupError> {
        let listen = match args.listen {
            Some(listen) => listen,
            None => env::var("RUNTRUE_LISTEN")
                .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
                .parse()
                .map_err(|_| StartupError::InvalidListen)?,
        };
        let database = args
            .database
            .or_else(|| env::var_os("RUNTRUE_DATABASE").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATABASE));
        let installation_id = args
            .installation_id
            .or_else(|| env::var("RUNTRUE_INSTALLATION_ID").ok())
            .unwrap_or_else(|| "local".to_owned());

        let bootstrap_token_file = args
            .bootstrap_token_file
            .or_else(|| env::var_os("RUNTRUE_BOOTSTRAP_TOKEN_FILE").map(PathBuf::from));
        let bootstrap_token = if let Some(path) = bootstrap_token_file {
            read_secret_string(&path)?
        } else {
            env::var("RUNTRUE_BOOTSTRAP_TOKEN")
                .map(Zeroizing::new)
                .map_err(|_| StartupError::MissingBootstrapToken)?
        };

        let github_webhook_secret_file = args
            .github_webhook_secret_file
            .or_else(|| env::var_os("RUNTRUE_GITHUB_WEBHOOK_SECRET_FILE").map(PathBuf::from));
        let github_webhook_secret = if let Some(path) = github_webhook_secret_file {
            Some(read_secret_bytes(&path)?)
        } else {
            env::var("RUNTRUE_GITHUB_WEBHOOK_SECRET")
                .ok()
                .map(String::into_bytes)
                .map(Zeroizing::new)
        };
        let github_app_id = match args.github_app_id {
            Some(value) => Some(value),
            None => match env::var("RUNTRUE_GITHUB_APP_ID") {
                Ok(value) => Some(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|value| *value != 0)
                        .ok_or(StartupError::InvalidGitHubAppConfiguration)?,
                ),
                Err(env::VarError::NotPresent) => None,
                Err(env::VarError::NotUnicode(_)) => {
                    return Err(StartupError::InvalidGitHubAppConfiguration)
                }
            },
        };
        let github_app_slug = match args.github_app_slug {
            Some(value) => Some(value),
            None => github_app_env("RUNTRUE_GITHUB_APP_SLUG")?,
        };
        let github_app_credential_reference = match args.github_app_credential_reference {
            Some(value) => Some(value),
            None => github_app_env("RUNTRUE_GITHUB_APP_CREDENTIAL_REFERENCE")?,
        };
        let github_app_jwt_provider_socket = args
            .github_app_jwt_provider_socket
            .or_else(|| env::var_os("RUNTRUE_GITHUB_APP_JWT_PROVIDER_SOCKET").map(PathBuf::from));
        let github_web_origin = match args.github_web_origin {
            Some(value) => Some(value),
            None => github_app_env("RUNTRUE_GITHUB_WEB_ORIGIN")?,
        };
        let github_api_origin = match args.github_api_origin {
            Some(value) => Some(value),
            None => github_app_env("RUNTRUE_GITHUB_API_ORIGIN")?,
        };
        let github_app = github_app_config(
            github_app_id,
            github_app_slug,
            github_app_credential_reference,
            github_app_jwt_provider_socket,
            github_web_origin,
            github_api_origin,
        )?;
        let security_key_file = args
            .security_key_file
            .or_else(|| env::var_os("RUNTRUE_SECURITY_KEY_FILE").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SECURITY_KEY));
        let oidc_issuer = match args
            .oidc_issuer
            .or_else(|| env::var("RUNTRUE_OIDC_ISSUER").ok())
        {
            Some(issuer) => issuer,
            None if listen.ip().is_loopback() => format!("http://{listen}/oidc"),
            None => return Err(StartupError::MissingOidcIssuer),
        };
        let public_origin = args
            .public_origin
            .or_else(|| env::var("RUNTRUE_PUBLIC_ORIGIN").ok());
        let browser_cookie_sealing_key_file = args
            .browser_cookie_sealing_key_file
            .or_else(|| env::var_os("RUNTRUE_BROWSER_COOKIE_SEALING_KEY_FILE").map(PathBuf::from));
        let human_oidc = human_oidc_startup_config(
            public_origin,
            browser_cookie_sealing_key_file,
            &security_key_file,
        )?;
        let github_oauth = github_oauth_startup_config(&human_oidc)?;
        let git_mirror_root = args
            .git_mirror_root
            .or_else(|| env::var_os("RUNTRUE_GIT_MIRROR_ROOT").map(PathBuf::from));
        if github_app.is_some() && git_mirror_root.is_none() {
            return Err(StartupError::GitHubAppRequiresMirrorRoot);
        }
        let data_root = args
            .data_root
            .or_else(|| env::var_os("RUNTRUE_DATA_ROOT").map(PathBuf::from))
            .unwrap_or_else(|| database.with_extension("data"));
        let runner_grpc_listen = args
            .runner_grpc_listen
            .or_else(|| env::var("RUNTRUE_RUNNER_GRPC_LISTEN").ok()?.parse().ok());
        if env::var("RUNTRUE_RUNNER_GRPC_LISTEN").is_ok()
            && args.runner_grpc_listen.is_none()
            && runner_grpc_listen.is_none()
        {
            return Err(StartupError::InvalidRunnerGrpcListen);
        }
        let runner_enrollment_listen = args.runner_enrollment_listen.or_else(|| {
            env::var("RUNTRUE_RUNNER_ENROLLMENT_LISTEN")
                .ok()?
                .parse()
                .ok()
        });
        if env::var("RUNTRUE_RUNNER_ENROLLMENT_LISTEN").is_ok()
            && args.runner_enrollment_listen.is_none()
            && runner_enrollment_listen.is_none()
        {
            return Err(StartupError::InvalidRunnerEnrollmentListen);
        }
        let runner_protocol_minimum = match args.runner_protocol_minimum {
            Some(value) => value,
            None => match env::var("RUNTRUE_RUNNER_PROTOCOL_MINIMUM") {
                Ok(value) => value
                    .parse::<u32>()
                    .map_err(|_| StartupError::InvalidRunnerProtocolMinimum)?,
                Err(env::VarError::NotPresent) => runtrue_protocol::PROTOCOL_MIN,
                Err(env::VarError::NotUnicode(_)) => {
                    return Err(StartupError::InvalidRunnerProtocolMinimum)
                }
            },
        };
        if !runtrue_protocol::supports_protocol_version(runner_protocol_minimum) {
            return Err(StartupError::InvalidRunnerProtocolMinimum);
        }
        let runner_grpc = runner_grpc_paths(
            listen,
            runner_grpc_listen,
            runner_enrollment_listen,
            args.runner_tls_certificate
                .or_else(|| env::var_os("RUNTRUE_RUNNER_TLS_CERTIFICATE").map(PathBuf::from)),
            args.runner_tls_private_key
                .or_else(|| env::var_os("RUNTRUE_RUNNER_TLS_PRIVATE_KEY").map(PathBuf::from)),
            args.runner_ca_certificate
                .or_else(|| env::var_os("RUNTRUE_RUNNER_CA_CERTIFICATE").map(PathBuf::from)),
            args.runner_ca_private_key
                .or_else(|| env::var_os("RUNTRUE_RUNNER_CA_PRIVATE_KEY").map(PathBuf::from)),
        )?
        .map(|mut paths| {
            paths.protocol_minimum = runner_protocol_minimum;
            paths
        });

        Ok(Self {
            listen,
            database,
            installation_id,
            bootstrap_token,
            github_webhook_secret,
            github_app,
            security_key_file,
            oidc_issuer,
            human_oidc,
            github_oauth,
            git_mirror_root,
            data_root,
            runner_grpc,
        })
    }
}

fn github_app_env(name: &'static str) -> Result<Option<String>, StartupError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(StartupError::InvalidGitHubAppConfiguration),
    }
}

fn human_oidc_startup_config(
    public_origin: Option<String>,
    cookie_sealing_key_file: Option<PathBuf>,
    installation_security_key_file: &Path,
) -> Result<Option<HumanOidcStartupConfig>, StartupError> {
    match (public_origin, cookie_sealing_key_file) {
        (None, None) => Ok(None),
        (Some(_), Some(cookie_sealing_key_file))
            if cookie_sealing_key_file == installation_security_key_file =>
        {
            Err(StartupError::HumanOidcReusesInstallationKey)
        }
        (Some(public_origin), Some(cookie_sealing_key_file)) => Ok(Some(HumanOidcStartupConfig {
            public_origin,
            cookie_sealing_key_file,
        })),
        _ => Err(StartupError::IncompleteHumanOidcConfiguration),
    }
}

fn github_oauth_startup_config(
    human: &Option<HumanOidcStartupConfig>,
) -> Result<Option<GitHubOauthStartupConfig>, StartupError> {
    let client_id = env::var("RUNTRUE_GITHUB_OAUTH_CLIENT_ID").ok();
    let secret_file = env::var_os("RUNTRUE_GITHUB_OAUTH_CLIENT_SECRET_FILE").map(PathBuf::from);
    let admin_ids = env::var("RUNTRUE_GITHUB_OAUTH_ADMIN_USER_IDS").ok();
    let operator_ids = env::var("RUNTRUE_GITHUB_OAUTH_OPERATOR_USER_IDS").ok();
    if client_id.is_none() && secret_file.is_none() && admin_ids.is_none() && operator_ids.is_none()
    {
        return Ok(None);
    }
    let (Some(client_id), Some(secret_file)) = (client_id, secret_file) else {
        return Err(StartupError::IncompleteGitHubOauthConfiguration);
    };
    if human.is_none() {
        return Err(StartupError::IncompleteGitHubOauthConfiguration);
    }
    let mut allowed_roles = BTreeMap::new();
    for (value, role) in [
        (admin_ids.as_deref(), "admin"),
        (operator_ids.as_deref(), "operator"),
    ] {
        if let Some(value) = value {
            for item in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                let id = item
                    .parse::<u64>()
                    .map_err(|_| StartupError::InvalidGitHubOauthUserId)?;
                if id == 0 || allowed_roles.insert(id, role.to_owned()).is_some() {
                    return Err(StartupError::InvalidGitHubOauthUserId);
                }
            }
        }
    }
    if allowed_roles.is_empty() {
        return Err(StartupError::InvalidGitHubOauthUserId);
    }
    Ok(Some(GitHubOauthStartupConfig {
        tenant_id: env::var("RUNTRUE_GITHUB_OAUTH_TENANT_ID")
            .unwrap_or_else(|_| "quickstart".to_owned()),
        tenant_name: env::var("RUNTRUE_GITHUB_OAUTH_TENANT_NAME")
            .unwrap_or_else(|_| "Runtrue".to_owned()),
        web_origin: env::var("RUNTRUE_GITHUB_WEB_ORIGIN")
            .unwrap_or_else(|_| "https://github.com".to_owned()),
        api_origin: env::var("RUNTRUE_GITHUB_API_ORIGIN")
            .unwrap_or_else(|_| "https://api.github.com".to_owned()),
        client_id,
        client_secret: read_secret_string(&secret_file)?,
        allowed_roles,
    }))
}

fn github_app_config(
    app_id: Option<u64>,
    app_slug: Option<String>,
    credential_reference: Option<String>,
    jwt_provider_socket: Option<PathBuf>,
    web_origin: Option<String>,
    api_origin: Option<String>,
) -> Result<Option<GitHubAppConfig>, StartupError> {
    match (app_id, app_slug, credential_reference, jwt_provider_socket) {
        (None, None, None, None) if web_origin.is_none() && api_origin.is_none() => Ok(None),
        (Some(app_id), app_slug, Some(credential_reference), Some(jwt_provider_socket))
            if credential_reference.starts_with("provider://github-app/")
                && credential_reference.len() <= 255
                && !credential_reference
                    .bytes()
                    .any(|byte| byte.is_ascii_control()) =>
        {
            if app_id == 0 {
                return Err(StartupError::InvalidGitHubAppConfiguration);
            }
            let web_origin = web_origin.unwrap_or_else(|| {
                api_origin
                    .as_deref()
                    .and_then(|origin| origin.strip_suffix("/api/v3"))
                    .unwrap_or("https://github.com")
                    .to_owned()
            });
            let api_origin = api_origin.unwrap_or_else(|| {
                if web_origin == "https://github.com" {
                    "https://api.github.com".to_owned()
                } else {
                    format!("{web_origin}/api/v3")
                }
            });
            let endpoints = GitHubProviderEndpoints::new(web_origin, api_origin)
                .map_err(|_| StartupError::InvalidGitHubAppConfiguration)?;
            let public = app_slug
                .map(|app_slug| {
                    GitHubAppPublicConfig::new_with_endpoints(app_id, app_slug, endpoints.clone())
                })
                .transpose()
                .map_err(|_| StartupError::InvalidGitHubAppConfiguration)?;
            Ok(Some(GitHubAppConfig {
                app_id,
                public,
                credential_reference,
                jwt_provider_socket,
                endpoints,
            }))
        }
        _ => Err(StartupError::InvalidGitHubAppConfiguration),
    }
}

fn runner_grpc_paths(
    http_listen: SocketAddr,
    control_listen: Option<SocketAddr>,
    enrollment_listen: Option<SocketAddr>,
    server_certificate: Option<PathBuf>,
    server_private_key: Option<PathBuf>,
    ca_certificate: Option<PathBuf>,
    ca_private_key: Option<PathBuf>,
) -> Result<Option<RunnerGrpcPaths>, StartupError> {
    match (
        control_listen,
        enrollment_listen,
        server_certificate,
        server_private_key,
        ca_certificate,
        ca_private_key,
    ) {
        (None, None, None, None, None, None) => Ok(None),
        (
            Some(control_listen),
            Some(enrollment_listen),
            Some(server_certificate),
            Some(server_private_key),
            Some(ca_certificate),
            Some(ca_private_key),
        ) => {
            if control_listen == http_listen
                || enrollment_listen == http_listen
                || control_listen == enrollment_listen
            {
                return Err(StartupError::RunnerGrpcListenConflict);
            }
            Ok(Some(RunnerGrpcPaths {
                control_listen,
                enrollment_listen,
                server_certificate,
                server_private_key,
                ca_certificate,
                ca_private_key,
                protocol_minimum: runtrue_protocol::PROTOCOL_MIN,
            }))
        }
        _ => Err(StartupError::IncompleteRunnerGrpcTls),
    }
}

#[derive(Debug, Error)]
enum StartupError {
    #[error("RUNTRUE_LISTEN is not a valid socket address")]
    InvalidListen,
    #[error(
        "configure a bootstrap token with --bootstrap-token-file, RUNTRUE_BOOTSTRAP_TOKEN_FILE, or RUNTRUE_BOOTSTRAP_TOKEN"
    )]
    MissingBootstrapToken,
    #[error("configure --oidc-issuer or RUNTRUE_OIDC_ISSUER when listening beyond loopback")]
    MissingOidcIssuer,
    #[error(
        "browser OIDC requires --public-origin/RUNTRUE_PUBLIC_ORIGIN and --browser-cookie-sealing-key-file/RUNTRUE_BROWSER_COOKIE_SEALING_KEY_FILE together"
    )]
    IncompleteHumanOidcConfiguration,
    #[error("the browser cookie sealing key must not reuse the installation security key file")]
    HumanOidcReusesInstallationKey,
    #[error("GitHub OAuth quickstart requires browser auth, client id, a mode-0600 client-secret file, and at least one stable allowed user id")]
    IncompleteGitHubOauthConfiguration,
    #[error("GitHub OAuth allowed user ids must be unique positive integers")]
    InvalidGitHubOauthUserId,
    #[error(
        "GitHub App integration requires app id, credential reference, and non-exportable JWT provider socket together; tenant installation setup also requires a valid App slug and exact GitHub web/API origin pair"
    )]
    InvalidGitHubAppConfiguration,
    #[error("configured GitHub App source fetching requires RUNTRUE_GIT_MIRROR_ROOT")]
    GitHubAppRequiresMirrorRoot,
    #[error("repository-action building requires both RUNTRUE_REPOSITORY_ACTION_BUILDER_SOCKET and RUNTRUE_REPOSITORY_ACTION_CONTEXT_ROOT, plus a live secure builder socket")]
    InvalidRepositoryActionBuilder,
    #[error("GitHub App JWT provider socket `{0}` is not a secure local Unix socket")]
    InvalidGitHubSignerSocket(PathBuf),
    #[error("RUNTRUE_RUNNER_GRPC_LISTEN is not a valid socket address")]
    InvalidRunnerGrpcListen,
    #[error("RUNTRUE_RUNNER_ENROLLMENT_LISTEN is not a valid socket address")]
    InvalidRunnerEnrollmentListen,
    #[error("runner protocol minimum must be a supported positive generation")]
    InvalidRunnerProtocolMinimum,
    #[error(
        "runner gRPC requires distinct control and enrollment listen addresses, server certificate/key, and installation CA certificate/key together"
    )]
    IncompleteRunnerGrpcTls,
    #[error("runner control, enrollment, and HTTP listen addresses must all differ")]
    RunnerGrpcListenConflict,
    #[error("runner TLS file `{0}` is not a supported PEM document")]
    InvalidRunnerTlsPem(PathBuf),
    #[error("runner TLS or CA file `{0}` must contain 1 to 1048576 bytes")]
    InvalidRunnerConfigSize(PathBuf),
    #[error("unsafe path component in `{0}`")]
    UnsafePath(PathBuf),
    #[error("secret file `{0}` must be a regular file and not a symbolic link")]
    InvalidSecretFile(PathBuf),
    #[error(
        "secret file `{0}` must use mode 0600, or mode 0400/0440 as a direct trusted systemd credential"
    )]
    InsecureSecretPermissions(PathBuf),
    #[error("secret file `{0}` must contain 1 to 4096 bytes")]
    InvalidSecretSize(PathBuf),
    #[error("bootstrap token file `{0}` is not UTF-8")]
    InvalidSecretEncoding(PathBuf),
    #[error("installation key `{0}` must contain exactly 32 bytes")]
    InvalidSecurityKey(PathBuf),
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("filesystem operation for `{path}` failed: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug)]
struct UnixSocketGitHubAppJwtProvider {
    socket_path: PathBuf,
    app_id: u64,
    credential_reference: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GitHubSignerRequest<'a> {
    version: u32,
    operation: &'static str,
    app_id: u64,
    credential_reference: &'a str,
    now_unix_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitHubSignerResponse {
    version: u32,
    jwt: String,
}

impl UnixSocketGitHubAppJwtProvider {
    fn open(config: &GitHubAppConfig) -> Result<Self, StartupError> {
        #[cfg(unix)]
        {
            validate_github_signer_parent_path(&config.jwt_provider_socket)?;
            reject_symlink_components(&config.jwt_provider_socket)?;
            let metadata = fs::symlink_metadata(&config.jwt_provider_socket)
                .map_err(|source| io_error(&config.jwt_provider_socket, source))?;
            let effective_uid = nix::unistd::geteuid().as_raw();
            if !metadata.file_type().is_socket()
                || (metadata.uid() != 0 && metadata.uid() != effective_uid)
                || metadata.permissions().mode() & 0o7777 != 0o600
            {
                return Err(StartupError::InvalidGitHubSignerSocket(
                    config.jwt_provider_socket.clone(),
                ));
            }
        }
        #[cfg(not(unix))]
        {
            return Err(StartupError::InvalidGitHubSignerSocket(
                config.jwt_provider_socket.clone(),
            ));
        }
        Ok(Self {
            socket_path: config.jwt_provider_socket.clone(),
            app_id: config.app_id,
            credential_reference: config.credential_reference.clone(),
        })
    }
}

#[cfg(unix)]
fn validate_github_signer_parent_path(path: &Path) -> Result<(), StartupError> {
    if !path.is_absolute() {
        return Err(StartupError::InvalidGitHubSignerSocket(path.to_owned()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StartupError::InvalidGitHubSignerSocket(path.to_owned()))?;
    let effective_uid = nix::unistd::geteuid().as_raw();
    let mut checked = PathBuf::new();
    for component in parent.components() {
        checked.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&checked).map_err(|source| io_error(&checked, source))?;
        let mode = metadata.permissions().mode() & 0o7777;
        let root_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || (mode & 0o022 != 0 && !root_sticky)
        {
            return Err(StartupError::InvalidGitHubSignerSocket(checked.clone()));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn connect_github_signer(path: &Path) -> Result<UnixStream, GitHubError> {
    use nix::{
        errno::Errno,
        poll::{poll, PollFd, PollFlags},
        sys::socket::{
            connect, getsockopt, socket, sockopt::SocketError, AddressFamily, SockFlag, SockType,
            UnixAddr,
        },
    };

    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|_| GitHubError::JwtProvider)?;
    let address = UnixAddr::new(path).map_err(|_| GitHubError::JwtProvider)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(Errno::EINPROGRESS) => {
            let mut events = [PollFd::new(&descriptor, PollFlags::POLLOUT)];
            let ready = poll(
                &mut events,
                i32::try_from(GITHUB_SIGNER_IO_TIMEOUT.as_millis())
                    .map_err(|_| GitHubError::JwtProvider)?,
            )
            .map_err(|_| GitHubError::JwtProvider)?;
            let observed = events[0].revents().unwrap_or_else(PollFlags::empty);
            if ready != 1
                || !observed.contains(PollFlags::POLLOUT)
                || observed.intersects(PollFlags::POLLERR | PollFlags::POLLHUP)
                || getsockopt(&descriptor, SocketError).map_err(|_| GitHubError::JwtProvider)? != 0
            {
                return Err(GitHubError::JwtProvider);
            }
        }
        Err(_) => return Err(GitHubError::JwtProvider),
    }
    let stream = UnixStream::from(descriptor);
    stream
        .set_nonblocking(false)
        .map_err(|_| GitHubError::JwtProvider)?;
    Ok(stream)
}

impl GitHubAppJwtProvider for UnixSocketGitHubAppJwtProvider {
    fn mint(&mut self, now_unix_seconds: u64) -> Result<SensitiveToken, GitHubError> {
        #[cfg(unix)]
        {
            let request = serde_json::to_vec(&GitHubSignerRequest {
                version: 1,
                operation: "github.app-jwt.mint",
                app_id: self.app_id,
                credential_reference: &self.credential_reference,
                now_unix_seconds,
            })
            .map_err(|_| GitHubError::JwtProvider)?;
            if request.is_empty() || request.len() > MAX_GITHUB_SIGNER_FRAME_BYTES {
                return Err(GitHubError::JwtProvider);
            }
            let mut stream = connect_github_signer(&self.socket_path)?;
            stream
                .set_read_timeout(Some(GITHUB_SIGNER_IO_TIMEOUT))
                .and_then(|()| stream.set_write_timeout(Some(GITHUB_SIGNER_IO_TIMEOUT)))
                .map_err(|_| GitHubError::JwtProvider)?;
            let request_length = u32::try_from(request.len())
                .map_err(|_| GitHubError::JwtProvider)?
                .to_be_bytes();
            stream
                .write_all(&request_length)
                .and_then(|()| stream.write_all(&request))
                .and_then(|()| stream.flush())
                .map_err(|_| GitHubError::JwtProvider)?;
            let mut length = [0_u8; 4];
            stream
                .read_exact(&mut length)
                .map_err(|_| GitHubError::JwtProvider)?;
            let length = usize::try_from(u32::from_be_bytes(length))
                .map_err(|_| GitHubError::JwtProvider)?;
            if length == 0 || length > MAX_GITHUB_SIGNER_FRAME_BYTES {
                return Err(GitHubError::JwtProvider);
            }
            let mut response = Zeroizing::new(vec![0_u8; length]);
            stream
                .read_exact(response.as_mut_slice())
                .map_err(|_| GitHubError::JwtProvider)?;
            let response: GitHubSignerResponse =
                serde_json::from_slice(&response).map_err(|_| GitHubError::JwtProvider)?;
            if response.version != 1 {
                return Err(GitHubError::JwtProvider);
            }
            validate_github_app_jwt(response.jwt, self.app_id, now_unix_seconds)
        }
        #[cfg(not(unix))]
        {
            let _ = now_unix_seconds;
            Err(GitHubError::JwtProvider)
        }
    }
}

fn load_github_installation_provider(
    config: &GitHubAppConfig,
) -> Result<SharedGitHubInstallationProvider, Box<dyn Error + Send + Sync>> {
    let jwt_provider = UnixSocketGitHubAppJwtProvider::open(config)?;
    let api_origin = config.endpoints.api_origin().to_owned();
    let transport =
        HardenedGitHubTransport::new(api_origin.clone(), GitHubTransportLimits::default())?;
    let broker = GitHubAppBroker::new(transport, jwt_provider, api_origin)?;
    let service = GitHubInstallationService::new(broker, config.app_id)?;
    Ok(Arc::new(service))
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("runtrue-server: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Config::load(Args::parse())?;
    let scm_workflow_directory = env::var("RUNTRUE_SCM_WORKFLOW_DIRECTORY")
        .unwrap_or_else(|_| DEFAULT_SCM_WORKFLOW_DIRECTORY.to_owned());
    let listen = config.listen;
    prepare_database_path(&config.database)?;
    let now = unix_ms()?;
    let control_plane = Arc::new(ControlPlane::open(
        &config.database,
        config.installation_id.as_str(),
        now,
    )?);
    secure_database_file(&config.database)?;
    let security_seed = load_or_create_security_seed(&config.security_key_file)?;
    let mut state = AppState::new_with_security_seed(
        Arc::clone(&control_plane),
        &config.bootstrap_token,
        config
            .github_webhook_secret
            .as_ref()
            .map(|value| value.as_slice()),
        *security_seed,
        config.oidc_issuer.clone(),
    )?
    .with_runner_data_plane(&config.data_root)?
    .with_scm_workflow_directory(scm_workflow_directory.clone())?;
    let browser_cookie_key = config
        .human_oidc
        .as_ref()
        .map(|human| read_security_seed(&human.cookie_sealing_key_file))
        .transpose()?;
    if let (Some(human), Some(cookie_key)) =
        (config.human_oidc.as_ref(), browser_cookie_key.as_ref())
    {
        let limits = HumanOidcLimits::default();
        let adapter = Arc::new(HardenedHumanOidcClient::new(limits)?);
        state = state.with_human_oidc(human.public_origin.clone(), cookie_key, adapter, limits)?;
    }
    if let Some(github) = config.github_oauth.as_ref() {
        let limits = HumanOidcLimits::default();
        let adapter = Arc::new(HardenedGitHubOauthClient::new(
            &github.web_origin,
            &github.api_origin,
            github.client_id.clone(),
            github.client_secret.clone(),
            limits,
        )?);
        state = state.with_github_oauth_quickstart(GitHubOauthQuickstartConfig {
            tenant_id: github.tenant_id.clone(),
            tenant_name: github.tenant_name.clone(),
            web_origin: github.web_origin.clone(),
            client_id: github.client_id.clone(),
            adapter,
            allowed_roles: github.allowed_roles.clone(),
            now_unix_ms: now,
        })?;
    }
    if let Some(github) = config.github_app.as_ref() {
        if let Some(public) = github.public.as_ref() {
            let provider = load_github_installation_provider(github)?;
            state = state.with_github_installation_provider(
                public.clone(),
                github.credential_reference.clone(),
                provider,
            )?;
        }
        let jwt_provider = UnixSocketGitHubAppJwtProvider::open(github)?;
        let transport = HardenedGitHubTransport::new(
            github.endpoints.api_origin().to_owned(),
            GitHubTransportLimits::default(),
        )?;
        let broker = GitHubAppBroker::new(
            transport,
            jwt_provider,
            github.endpoints.api_origin().to_owned(),
        )?;
        let provider: Arc<dyn GitHubInstallationTokenProvider> =
            Arc::new(GitHubAppInstallationTokenProvider::new(
                broker,
                github.credential_reference.clone(),
                github.endpoints.clone(),
            )?);
        state = state.with_scm_credential_provider(provider);
    }
    let runner_grpc = config
        .runner_grpc
        .as_ref()
        .map(|paths| load_runner_grpc(paths, &state))
        .transpose()?;
    let worker = match config.git_mirror_root.as_ref() {
        Some(root) => {
            let mut nonce = [0_u8; 12];
            OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| StartupError::RandomnessUnavailable)?;
            let mut worker_config = ScmWorkerConfig::new(
                root.clone(),
                format!("scm-worker-{}-{}", std::process::id(), hex::encode(nonce)),
            );
            worker_config.workflow_directory = scm_workflow_directory.clone();
            if let Ok(image) = env::var("RUNTRUE_GHA_DEFAULT_JOB_CONTAINER_IMAGE") {
                worker_config.default_job_container_image = Some(image);
            }
            if let Some(github) = config.github_app.as_ref() {
                worker_config.github_provider_endpoints = github.endpoints.clone();
                let jwt_provider = UnixSocketGitHubAppJwtProvider::open(github)?;
                let transport = HardenedGitHubTransport::new(
                    github.endpoints.api_origin().to_owned(),
                    GitHubTransportLimits::default(),
                )?;
                let broker = GitHubAppBroker::new(
                    transport,
                    jwt_provider,
                    github.endpoints.api_origin().to_owned(),
                )?;
                let tokens = Arc::new(GitHubAppInstallationTokenProvider::new(
                    broker,
                    github.credential_reference.clone(),
                    github.endpoints.clone(),
                )?);
                #[cfg(feature = "github-actions")]
                {
                    let action_builder = match (
                        env::var_os("RUNTRUE_REPOSITORY_ACTION_BUILDER_SOCKET"),
                        env::var_os("RUNTRUE_REPOSITORY_ACTION_CONTEXT_ROOT"),
                    ) {
                        (None, None) => None,
                        (Some(socket), Some(context_root)) => {
                            let builder = UnixRepositoryActionBuilder::open(
                                PathBuf::from(socket),
                                PathBuf::from(context_root),
                                Duration::from_secs(30 * 60),
                            )
                            .map_err(|_| StartupError::InvalidRepositoryActionBuilder)?;
                            Some(Arc::new(builder) as Arc<dyn RepositoryActionBuilder>)
                        }
                        _ => return Err(StartupError::InvalidRepositoryActionBuilder.into()),
                    };
                    Some(if let Some(builder) = action_builder {
                        state.scm_task_worker_with_github_app_and_action_builder(
                            worker_config,
                            tokens,
                            load_github_installation_provider(github)?,
                            builder,
                        )?
                    } else {
                        state.scm_task_worker_with_github_app(worker_config, tokens)?
                    })
                }
                #[cfg(not(feature = "github-actions"))]
                {
                    if env::var_os("RUNTRUE_REPOSITORY_ACTION_BUILDER_SOCKET").is_some()
                        || env::var_os("RUNTRUE_REPOSITORY_ACTION_CONTEXT_ROOT").is_some()
                    {
                        return Err(StartupError::InvalidRepositoryActionBuilder.into());
                    }
                    Some(state.scm_task_worker_with_github_app(worker_config, tokens)?)
                }
            } else {
                Some(state.scm_task_worker(worker_config)?)
            }
        }
        None => None,
    };
    // The verifier state has its own protected representation; do not retain
    // raw environment/file secret bytes for the lifetime of the server.
    drop(security_seed);
    drop(browser_cookie_key);
    drop(config);

    let stop_worker = Arc::new(AtomicBool::new(false));
    let worker_thread = worker
        .map(|worker| {
            let stop = Arc::clone(&stop_worker);
            std::thread::Builder::new()
                .name("runtrue-scm-worker".to_owned())
                .spawn(move || run_scm_worker(worker, &stop))
        })
        .transpose()?;
    let server_result = serve_servers(listen, state, runner_grpc, Arc::clone(&stop_worker)).await;
    if let Some(worker_thread) = worker_thread {
        worker_thread
            .join()
            .map_err(|_| io::Error::other("SCM worker thread panicked during shutdown"))?;
    }
    server_result?;
    Ok(())
}

struct RunnerGrpcRuntime {
    control_listen: SocketAddr,
    enrollment_listen: SocketAddr,
    control_tls: ServerTlsConfig,
    enrollment_tls: ServerTlsConfig,
    control_service: RunnerControlService,
    enrollment_service: RunnerEnrollmentService,
}

fn load_runner_grpc(
    paths: &RunnerGrpcPaths,
    state: &AppState,
) -> Result<RunnerGrpcRuntime, Box<dyn Error + Send + Sync>> {
    let certificate = read_runner_config_bytes(&paths.server_certificate)?;
    require_pem(&paths.server_certificate, &certificate, &["CERTIFICATE"])?;
    let private_key = Zeroizing::new(read_runner_config_bytes(&paths.server_private_key)?);
    require_pem(
        &paths.server_private_key,
        &private_key,
        &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
    )?;
    let ca_certificate = read_runner_config_bytes(&paths.ca_certificate)?;
    require_pem(&paths.ca_certificate, &ca_certificate, &["CERTIFICATE"])?;
    let ca_private_key = Zeroizing::new(read_runner_config_bytes(&paths.ca_private_key)?);
    require_pem(&paths.ca_private_key, &ca_private_key, &["PRIVATE KEY"])?;
    let authority = Arc::new(RunnerCertificateAuthority::load(
        &ca_certificate,
        &ca_private_key,
        DEFAULT_RUNNER_CERTIFICATE_LIFETIME,
    )?);
    let control_tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            certificate.as_slice(),
            private_key.as_slice(),
        ))
        .client_ca_root(Certificate::from_pem(ca_certificate.as_slice()))
        .client_auth_optional(false);
    let enrollment_tls = ServerTlsConfig::new().identity(Identity::from_pem(
        certificate.as_slice(),
        private_key.as_slice(),
    ));
    let control_service = state.runner_control_service_with_config(
        authority,
        RunnerControlConfig {
            protocol_minimum: paths.protocol_minimum,
            ..RunnerControlConfig::default()
        },
    )?;
    let enrollment_service = control_service.enrollment_service();
    Ok(RunnerGrpcRuntime {
        control_listen: paths.control_listen,
        enrollment_listen: paths.enrollment_listen,
        control_tls,
        enrollment_tls,
        control_service,
        enrollment_service,
    })
}

type ServerTaskResult = Result<(), Box<dyn Error + Send + Sync>>;

async fn serve_servers(
    http_listen: SocketAddr,
    state: AppState,
    runner_grpc: Option<RunnerGrpcRuntime>,
    stop_worker: Arc<AtomicBool>,
) -> ServerTaskResult {
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let maintenance_control_plane = Arc::clone(&state.control_plane);
    let mut lifecycle_task = tokio::spawn(github_lifecycle_reconciliation_loop(
        state.clone(),
        shutdown_receiver.clone(),
    ));
    let mut http_task = tokio::spawn(serve_http(http_listen, state, shutdown_receiver.clone()));
    let mut grpc_task = runner_grpc
        .map(|runtime| tokio::spawn(serve_runner_grpc(runtime, shutdown_receiver.clone())));
    let mut maintenance_task = tokio::spawn(scheduler_maintenance_loop(
        maintenance_control_plane,
        shutdown_receiver.clone(),
    ));
    let mut first_http_result = None;
    let mut first_grpc_result = None;
    let mut first_maintenance_result = None;
    let mut first_lifecycle_result = None;

    if let Some(grpc) = grpc_task.as_mut() {
        tokio::select! {
            () = shutdown_signal() => {}
            result = &mut http_task => first_http_result = Some(result),
            result = grpc => first_grpc_result = Some(result),
            result = &mut maintenance_task => first_maintenance_result = Some(result),
            result = &mut lifecycle_task => first_lifecycle_result = Some(result),
        }
    } else {
        tokio::select! {
            () = shutdown_signal() => {}
            result = &mut http_task => first_http_result = Some(result),
            result = &mut maintenance_task => first_maintenance_result = Some(result),
            result = &mut lifecycle_task => first_lifecycle_result = Some(result),
        }
    }

    stop_worker.store(true, Ordering::Release);
    let _ = shutdown_sender.send(true);
    let http_result = match first_http_result {
        Some(result) => result,
        None => http_task.await,
    };
    let grpc_result = match (first_grpc_result, grpc_task) {
        (Some(result), _) => Some(result),
        (None, Some(task)) => Some(task.await),
        (None, None) => None,
    };
    let maintenance_result = match first_maintenance_result {
        Some(result) => result,
        None => maintenance_task.await,
    };
    let lifecycle_result = match first_lifecycle_result {
        Some(result) => result,
        None => lifecycle_task.await,
    };
    flatten_server_task(http_result)?;
    if let Some(result) = grpc_result {
        flatten_server_task(result)?;
    }
    flatten_server_task(maintenance_result)?;
    flatten_server_task(lifecycle_result)?;
    Ok(())
}

async fn serve_http(
    listen: SocketAddr,
    state: AppState,
    shutdown: watch::Receiver<bool>,
) -> ServerTaskResult {
    axum::Server::bind(&listen)
        .serve(router(state).into_make_service())
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await?;
    Ok(())
}

async fn serve_runner_grpc(
    runtime: RunnerGrpcRuntime,
    shutdown: watch::Receiver<bool>,
) -> ServerTaskResult {
    let v2_service = runtime.control_service.clone().into_v2_server();
    let control = GrpcServer::builder()
        .tls_config(runtime.control_tls)?
        .add_service(v2_service)
        .add_service(runtime.control_service.into_server())
        .serve_with_shutdown(runtime.control_listen, wait_for_shutdown(shutdown.clone()));
    let enrollment = GrpcServer::builder()
        .tls_config(runtime.enrollment_tls)?
        .add_service(runtime.enrollment_service.into_server())
        .serve_with_shutdown(runtime.enrollment_listen, wait_for_shutdown(shutdown));
    tokio::try_join!(control, enrollment)?;
    Ok(())
}

async fn scheduler_maintenance_loop(
    control_plane: Arc<ControlPlane>,
    mut shutdown: watch::Receiver<bool>,
) -> ServerTaskResult {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = unix_ms()?;
                if let Err(error) = control_plane.perform_scheduler_maintenance(now) {
                    eprintln!("runtrue-server: scheduler maintenance failed: {error}");
                }
                if let Err(error) = control_plane.reconcile_due_schedules(
                    now,
                    MAX_DUE_SCHEDULES_PER_MAINTENANCE_TICK,
                ) {
                    eprintln!("runtrue-server: schedule reconciliation failed: {error}");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

async fn github_lifecycle_reconciliation_loop(
    state: AppState,
    mut shutdown: watch::Receiver<bool>,
) -> ServerTaskResult {
    let mut nonce = [0_u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| io::Error::other("GitHub lifecycle worker randomness is unavailable"))?;
    let worker_id = format!(
        "github-lifecycle-{}-{}",
        std::process::id(),
        hex::encode(nonce)
    );
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(error) = state.process_github_lifecycle_once(&worker_id).await {
                    eprintln!("runtrue-server: GitHub lifecycle reconciliation failed: {error}");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

fn flatten_server_task(
    result: Result<ServerTaskResult, tokio::task::JoinError>,
) -> ServerTaskResult {
    match result {
        Ok(result) => result,
        Err(error) => Err(Box::new(error)),
    }
}

fn run_scm_worker(worker: ScmTaskWorker, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        if let Err(error) = worker.process_once() {
            eprintln!("runtrue-server: SCM worker tick failed: {error}");
        }
        if !stop.load(Ordering::Acquire) {
            std::thread::sleep(worker.poll_interval());
        }
    }
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("runtrue-server: could not install shutdown signal handler: {error}");
    }
}

fn unix_ms() -> Result<u64, io::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| io::Error::other("system clock is before Unix epoch"))
}

fn prepare_database_path(path: &Path) -> Result<(), StartupError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    reject_symlink_components(parent)?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    reject_symlink_components(parent)?;
    secure_directory(parent)?;

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(StartupError::UnsafePath(path.to_owned()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error(path, source)),
    }
    Ok(())
}

fn secure_database_file(path: &Path) -> Result<(), StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StartupError::UnsafePath(path.to_owned()));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(StartupError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn secure_directory(path: &Path) -> Result<(), StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StartupError::UnsafePath(path.to_owned()));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(path, source))?;
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), StartupError> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                checked.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => return Err(StartupError::UnsafePath(path.to_owned())),
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StartupError::UnsafePath(checked));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&checked, source)),
        }
    }
    Ok(())
}

fn load_or_create_security_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, StartupError> {
    prepare_private_file_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => return read_security_seed(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error(path, source)),
    }

    let mut seed = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|_| StartupError::RandomnessUnavailable)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| StartupError::UnsafePath(path.to_owned()))?;

    for _ in 0..16 {
        let mut nonce = [0_u8; 12];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| StartupError::RandomnessUnavailable)?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            file_name.to_string_lossy(),
            hex::encode(nonce)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error(&temporary, source)),
        };
        if let Err(source) = file.write_all(seed.as_ref()).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(&temporary, source));
        }
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                fs::remove_file(&temporary).map_err(|source| io_error(&temporary, source))?;
                sync_directory(parent)?;
                return read_security_seed(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary).map_err(|source| io_error(&temporary, source))?;
                return read_security_seed(path);
            }
            Err(source) => {
                let _ = fs::remove_file(&temporary);
                return Err(io_error(path, source));
            }
        }
    }
    Err(StartupError::RandomnessUnavailable)
}

fn prepare_private_file_parent(path: &Path) -> Result<(), StartupError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    reject_symlink_components(parent)?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    reject_symlink_components(parent)?;
    secure_directory(parent)
}

fn read_security_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, StartupError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StartupError::InvalidSecretFile(path.to_owned()));
    }
    if metadata.len() != 32 {
        return Err(StartupError::InvalidSecurityKey(path.to_owned()));
    }
    #[cfg(unix)]
    if !private_file_metadata_is_secure(path, &metadata, None) {
        return Err(StartupError::InsecureSecretPermissions(path.to_owned()));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let opened_metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !opened_metadata.is_file() || opened_metadata.len() != 32 {
        return Err(StartupError::InvalidSecurityKey(path.to_owned()));
    }
    #[cfg(unix)]
    if opened_metadata.dev() != metadata.dev()
        || opened_metadata.ino() != metadata.ino()
        || !private_file_metadata_is_secure(path, &opened_metadata, None)
    {
        return Err(StartupError::UnsafePath(path.to_owned()));
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    file.read_exact(bytes.as_mut())
        .map_err(|source| io_error(path, source))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|source| io_error(path, source))?
        != 0
    {
        return Err(StartupError::InvalidSecurityKey(path.to_owned()));
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), StartupError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn read_secret_string(path: &Path) -> Result<Zeroizing<String>, StartupError> {
    let bytes = read_secret_bytes(path)?;
    let mut value = String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| StartupError::InvalidSecretEncoding(path.to_owned()))?;
    trim_secret_newline(&mut value);
    if value.is_empty() {
        return Err(StartupError::InvalidSecretSize(path.to_owned()));
    }
    Ok(value)
}

fn read_secret_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>, StartupError> {
    let mut value = read_bounded_private_bytes(path, MAX_SECRET_FILE_BYTES, |path| {
        StartupError::InvalidSecretSize(path)
    })?;
    while matches!(value.last(), Some(b'\r' | b'\n')) {
        value.pop();
    }
    if value.is_empty() {
        return Err(StartupError::InvalidSecretSize(path.to_owned()));
    }
    Ok(value)
}

fn read_runner_config_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>, StartupError> {
    read_bounded_private_bytes(path, MAX_RUNNER_TLS_FILE_BYTES, |path| {
        StartupError::InvalidRunnerConfigSize(path)
    })
}

fn read_bounded_private_bytes(
    path: &Path,
    maximum_bytes: u64,
    size_error: fn(PathBuf) -> StartupError,
) -> Result<Zeroizing<Vec<u8>>, StartupError> {
    let credentials_directory = systemd_credentials_directory();
    read_bounded_private_bytes_with_credentials(
        path,
        maximum_bytes,
        size_error,
        credentials_directory.as_deref(),
    )
}

fn read_bounded_private_bytes_with_credentials(
    path: &Path,
    maximum_bytes: u64,
    size_error: fn(PathBuf) -> StartupError,
    credentials_directory: Option<&Path>,
) -> Result<Zeroizing<Vec<u8>>, StartupError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StartupError::InvalidSecretFile(path.to_owned()));
    }
    if metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(size_error(path.to_owned()));
    }
    #[cfg(unix)]
    if !private_file_metadata_is_secure(path, &metadata, credentials_directory) {
        return Err(StartupError::InsecureSecretPermissions(path.to_owned()));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let opened_metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !opened_metadata.is_file() {
        return Err(StartupError::InvalidSecretFile(path.to_owned()));
    }
    #[cfg(unix)]
    if opened_metadata.dev() != metadata.dev()
        || opened_metadata.ino() != metadata.ino()
        || !private_file_metadata_is_secure(path, &opened_metadata, credentials_directory)
    {
        return Err(StartupError::UnsafePath(path.to_owned()));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| size_error(path.to_owned()))?;
    let mut value = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(value.as_mut())
        .map_err(|source| io_error(path, source))?;
    let length = u64::try_from(value.len()).map_err(|_| size_error(path.to_owned()))?;
    if value.is_empty() || length > maximum_bytes {
        return Err(size_error(path.to_owned()));
    }
    Ok(value)
}

fn systemd_credentials_directory() -> Option<PathBuf> {
    let directory = PathBuf::from(env::var_os("CREDENTIALS_DIRECTORY")?);
    normalized_absolute_path(&directory).then_some(directory)
}

fn normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn is_direct_systemd_credential(path: &Path, credentials_directory: Option<&Path>) -> bool {
    let Some(directory) = credentials_directory else {
        return false;
    };
    normalized_absolute_path(directory)
        && normalized_absolute_path(path)
        && path.parent() == Some(directory)
        && path.file_name().is_some()
        && systemd_credentials_directory_is_secure(directory)
}

#[cfg(unix)]
fn systemd_credentials_directory_is_secure(directory: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return false;
    };
    let effective_uid = nix::unistd::geteuid().as_raw();
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.uid() == 0 {
        metadata.gid() == 0 && mode & 0o027 == 0
    } else {
        metadata.uid() == effective_uid && mode & 0o077 == 0
    }
}

#[cfg(not(unix))]
const fn systemd_credentials_directory_is_secure(_directory: &Path) -> bool {
    false
}

#[cfg(unix)]
fn private_file_metadata_is_secure(
    path: &Path,
    metadata: &fs::Metadata,
    credentials_directory: Option<&Path>,
) -> bool {
    if !metadata.is_file() || metadata.nlink() != 1 {
        return false;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    let effective_uid = nix::unistd::geteuid().as_raw();
    let effective_gid = nix::unistd::getegid().as_raw();
    if is_direct_systemd_credential(path, credentials_directory) {
        let safe_owner = metadata.uid() == 0 || metadata.uid() == effective_uid;
        let safe_group = mode == 0o400
            || (metadata.uid() == 0 && metadata.gid() == 0)
            || (metadata.uid() == effective_uid && metadata.gid() == effective_gid);
        return matches!(mode, 0o400 | 0o440) && safe_owner && safe_group;
    }
    mode == 0o600 && metadata.uid() == effective_uid
}

fn require_pem(path: &Path, bytes: &[u8], labels: &[&str]) -> Result<(), StartupError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| StartupError::InvalidRunnerTlsPem(path.to_owned()))?;
    if labels.iter().any(|label| {
        text.contains(&format!("-----BEGIN {label}-----"))
            && text.contains(&format!("-----END {label}-----"))
    }) {
        Ok(())
    } else {
        Err(StartupError::InvalidRunnerTlsPem(path.to_owned()))
    }
}

fn trim_secret_newline(value: &mut String) {
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
}

fn io_error(path: &Path, source: io::Error) -> StartupError {
    StartupError::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_schedule_reconciliation_survives_restart_without_duplicate_trigger() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("schedule.sqlite3");
        let control = ControlPlane::open(&database, "schedule-maintenance", 1).unwrap();
        control
            .create_repository(&runtrue_control_plane::RepositoryRecord {
                id: "schedule-repo".to_owned(),
                tenant_id: "schedule-tenant".to_owned(),
                owner: "octo".to_owned(),
                name: "schedule".to_owned(),
                default_branch: "main".to_owned(),
                visibility: "private".to_owned(),
                created_unix_ms: 1,
            })
            .unwrap();
        control
            .put_schedule_cursor(
                &runtrue_control_plane::ScheduleTriggerCursor {
                    tenant_id: "schedule-tenant".to_owned(),
                    repository_id: "schedule-repo".to_owned(),
                    workflow_identity: "sha256:scheduled-workflow".to_owned(),
                    schedule_key: "each-minute".to_owned(),
                    cron_utc: "* * * * *".to_owned(),
                    catch_up_policy: "latest".to_owned(),
                    maximum_catch_up: 1,
                    next_fire_unix_ms: 60_000,
                    last_fire_unix_ms: None,
                    version: 1,
                    updated_unix_ms: 1,
                },
                None,
            )
            .unwrap();
        let first = control
            .reconcile_due_schedules(125_000, MAX_DUE_SCHEDULES_PER_MAINTENANCE_TICK)
            .unwrap();
        assert_eq!(first.cursors_advanced, 1);
        assert_eq!(first.triggers_inserted, 1);
        assert_eq!(first.due_cursors_remaining, 0);
        drop(control);

        let reopened = ControlPlane::open(&database, "schedule-maintenance", 130_000).unwrap();
        let replay = reopened
            .reconcile_due_schedules(125_000, MAX_DUE_SCHEDULES_PER_MAINTENANCE_TICK)
            .unwrap();
        assert_eq!(replay.cursors_considered, 0);
        assert_eq!(
            reopened
                .workflow_semantics_metrics("schedule-tenant", 125_000)
                .unwrap()
                .normalized_triggers,
            1
        );
        let cursor = reopened
            .schedule_cursor(
                "schedule-tenant",
                "schedule-repo",
                "sha256:scheduled-workflow",
                "each-minute",
            )
            .unwrap();
        assert_eq!(cursor.last_fire_unix_ms, Some(120_000));
        assert_eq!(cursor.next_fire_unix_ms, 180_000);
        assert_eq!(cursor.version, 2);
    }

    #[test]
    fn relative_parent_components_are_rejected() {
        let error = reject_symlink_components(Path::new("safe/../unsafe")).unwrap_err();
        assert!(matches!(error, StartupError::UnsafePath(_)));
    }

    #[test]
    fn newline_trimming_preserves_non_newline_whitespace() {
        let mut value = " token \r\n".to_owned();
        trim_secret_newline(&mut value);
        assert_eq!(value, " token ");
    }

    #[test]
    fn runner_grpc_configuration_is_all_or_none_and_never_plaintext() {
        let http: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let grpc: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let enrollment: SocketAddr = "127.0.0.1:8444".parse().unwrap();
        assert!(runner_grpc_paths(http, None, None, None, None, None, None,)
            .unwrap()
            .is_none());
        assert!(matches!(
            runner_grpc_paths(http, Some(grpc), None, None, None, None, None,),
            Err(StartupError::IncompleteRunnerGrpcTls)
        ));
        assert!(matches!(
            runner_grpc_paths(
                http,
                Some(http),
                Some(enrollment),
                Some(PathBuf::from("server.pem")),
                Some(PathBuf::from("server.key")),
                Some(PathBuf::from("ca.pem")),
                Some(PathBuf::from("ca.key")),
            ),
            Err(StartupError::RunnerGrpcListenConflict)
        ));
        let configured = runner_grpc_paths(
            http,
            Some(grpc),
            Some(enrollment),
            Some(PathBuf::from("server.pem")),
            Some(PathBuf::from("server.key")),
            Some(PathBuf::from("ca.pem")),
            Some(PathBuf::from("ca.key")),
        )
        .unwrap()
        .unwrap();
        assert_eq!(configured.control_listen, grpc);
        assert_eq!(configured.enrollment_listen, enrollment);
    }

    #[test]
    fn github_app_configuration_is_all_or_none_and_provider_referenced() {
        assert!(github_app_config(None, None, None, None, None, None)
            .unwrap()
            .is_none());
        assert!(matches!(
            github_app_config(
                Some(123),
                Some("runtrue".to_owned()),
                None,
                Some(PathBuf::from("/run/runtrue/github-signer.sock")),
                None,
                None,
            ),
            Err(StartupError::InvalidGitHubAppConfiguration)
        ));
        assert!(matches!(
            github_app_config(
                Some(123),
                Some("runtrue".to_owned()),
                Some("file:///tmp/exported-key.pem".to_owned()),
                Some(PathBuf::from("/run/runtrue/github-signer.sock")),
                None,
                None,
            ),
            Err(StartupError::InvalidGitHubAppConfiguration)
        ));
        assert!(matches!(
            github_app_config(
                Some(123),
                Some("Project_Runtrue".to_owned()),
                Some("provider://github-app/production".to_owned()),
                Some(PathBuf::from("/run/runtrue/github-signer.sock")),
                None,
                None,
            ),
            Err(StartupError::InvalidGitHubAppConfiguration)
        ));
        let configured = github_app_config(
            Some(123),
            Some("runtrue".to_owned()),
            Some("provider://github-app/production".to_owned()),
            Some(PathBuf::from("/run/runtrue/github-signer.sock")),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let public = configured.public.as_ref().unwrap();
        assert_eq!(public.app_id(), 123);
        assert_eq!(public.app_slug(), "runtrue");
        assert_eq!(
            configured.credential_reference,
            "provider://github-app/production"
        );
        let enterprise_worker_only = github_app_config(
            Some(123),
            None,
            Some("provider://github-app/production".to_owned()),
            Some(PathBuf::from("/run/runtrue/github-signer.sock")),
            Some("https://github.example".to_owned()),
            Some("https://github.example/api/v3".to_owned()),
        )
        .unwrap()
        .unwrap();
        assert!(enterprise_worker_only.public.is_none());
        let enterprise = github_app_config(
            Some(123),
            Some("runtrue".to_owned()),
            Some("provider://github-app/production".to_owned()),
            Some(PathBuf::from("/run/runtrue/github-signer.sock")),
            Some("https://github.example.com".to_owned()),
            Some("https://github.example.com/api/v3".to_owned()),
        )
        .unwrap()
        .unwrap();
        let public = enterprise.public.unwrap();
        assert_eq!(public.web_origin(), "https://github.example.com");
        assert_eq!(public.api_origin(), "https://github.example.com/api/v3");
        assert!(public
            .installation_url(&"A".repeat(43))
            .unwrap()
            .starts_with("https://github.example.com/github-apps/runtrue/"));
        let derived_from_web = github_app_config(
            Some(123),
            Some("runtrue".to_owned()),
            Some("provider://github-app/production".to_owned()),
            Some(PathBuf::from("/run/runtrue/github-signer.sock")),
            Some("https://github.example.com:8443".to_owned()),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            derived_from_web.endpoints.api_origin(),
            "https://github.example.com:8443/api/v3"
        );
        let derived_from_api = github_app_config(
            Some(123),
            Some("runtrue".to_owned()),
            Some("provider://github-app/production".to_owned()),
            Some(PathBuf::from("/run/runtrue/github-signer.sock")),
            None,
            Some("https://github.example.com/api/v3".to_owned()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            derived_from_api.endpoints.web_origin(),
            "https://github.example.com"
        );
        let parsed = Args::try_parse_from([
            "runtrue-server",
            "--github-web-origin",
            "https://github.example.com",
        ])
        .unwrap();
        assert_eq!(
            parsed.github_web_origin.as_deref(),
            Some("https://github.example.com")
        );
        assert!(matches!(
            github_app_config(
                Some(123),
                Some("runtrue".to_owned()),
                Some("provider://github-app/production".to_owned()),
                Some(PathBuf::from("/run/runtrue/github-signer.sock")),
                Some("https://github.example.com".to_owned()),
                Some("https://api.github.com".to_owned()),
            ),
            Err(StartupError::InvalidGitHubAppConfiguration)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn github_app_signer_socket_is_bounded_claim_checked_and_non_exportable() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        use std::{os::unix::net::UnixListener, thread};

        const NOW_SECONDS: u64 = 1_783_728_000;
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("github-signer.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let signer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let length = usize::try_from(u32::from_be_bytes(length)).unwrap();
            assert!(length <= MAX_GITHUB_SIGNER_FRAME_BYTES);
            let mut request = vec![0_u8; length];
            stream.read_exact(&mut request).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["version"], 1);
            assert_eq!(request["operation"], "github.app-jwt.mint");
            assert_eq!(request["app_id"], 123);
            assert_eq!(
                request["credential_reference"],
                "provider://github-app/production"
            );
            let header = Base64UrlUnpadded::encode_string(br#"{"alg":"RS256","typ":"JWT"}"#);
            let claims = Base64UrlUnpadded::encode_string(
                serde_json::to_string(&serde_json::json!({
                    "iss": 123,
                    "iat": NOW_SECONDS - 30,
                    "exp": NOW_SECONDS + 8 * 60
                }))
                .unwrap()
                .as_bytes(),
            );
            let signature = Base64UrlUnpadded::encode_string(b"non-exportable-signature");
            let jwt = format!("{header}.{claims}.{signature}");
            let response = serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "jwt": jwt
            }))
            .unwrap();
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let config = GitHubAppConfig {
            app_id: 123,
            public: Some(GitHubAppPublicConfig::new(123, "runtrue").unwrap()),
            credential_reference: "provider://github-app/production".to_owned(),
            jwt_provider_socket: socket,
            endpoints: GitHubProviderEndpoints::github_dot_com(),
        };
        let mut provider = UnixSocketGitHubAppJwtProvider::open(&config).unwrap();
        let token = provider.mint(NOW_SECONDS).unwrap();
        assert!(!format!("{token:?}").contains("signature"));
        signer.join().unwrap();

        fs::set_permissions(
            &config.jwt_provider_socket,
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(matches!(
            UnixSocketGitHubAppJwtProvider::open(&config),
            Err(StartupError::InvalidGitHubSignerSocket(_))
        ));

        let unsafe_parent = directory.path().join("world-writable");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let unsafe_socket = unsafe_parent.join("signer.sock");
        let _unsafe_listener = UnixListener::bind(&unsafe_socket).unwrap();
        fs::set_permissions(&unsafe_socket, fs::Permissions::from_mode(0o600)).unwrap();
        let unsafe_config = GitHubAppConfig {
            jwt_provider_socket: unsafe_socket,
            ..config
        };
        assert!(matches!(
            UnixSocketGitHubAppJwtProvider::open(&unsafe_config),
            Err(StartupError::InvalidGitHubSignerSocket(_))
        ));
    }

    #[test]
    fn installation_security_key_is_private_stable_and_exactly_sized() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys").join("security.key");
        let first = load_or_create_security_seed(&path).unwrap();
        let second = load_or_create_security_seed(&path).unwrap();
        assert_eq!(first.as_ref(), second.as_ref());
        assert_eq!(fs::metadata(&path).unwrap().len(), 32);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );

        let extra_link = directory.path().join("security-key-hard-link");
        fs::hard_link(&path, &extra_link).unwrap();
        assert!(matches!(
            load_or_create_security_seed(&path),
            Err(StartupError::InsecureSecretPermissions(_))
        ));
        fs::remove_file(extra_link).unwrap();

        let invalid = directory.path().join("keys").join("invalid.key");
        fs::write(&invalid, [7_u8; 31]).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&invalid, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_or_create_security_seed(&invalid),
            Err(StartupError::InvalidSecurityKey(_))
        ));
    }

    #[test]
    fn browser_oidc_startup_requires_origin_and_separate_key_together() {
        assert!(
            human_oidc_startup_config(None, None, Path::new("security.key"))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            human_oidc_startup_config(
                Some("https://runtrue.example".to_owned()),
                None,
                Path::new("security.key")
            ),
            Err(StartupError::IncompleteHumanOidcConfiguration)
        ));
        assert!(matches!(
            human_oidc_startup_config(
                None,
                Some(PathBuf::from("cookie.key")),
                Path::new("security.key")
            ),
            Err(StartupError::IncompleteHumanOidcConfiguration)
        ));
        let configured = human_oidc_startup_config(
            Some("https://runtrue.example".to_owned()),
            Some(PathBuf::from("cookie.key")),
            Path::new("security.key"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(configured.public_origin, "https://runtrue.example");
        assert_eq!(configured.cookie_sealing_key_file, Path::new("cookie.key"));
        assert!(matches!(
            human_oidc_startup_config(
                Some("https://runtrue.example".to_owned()),
                Some(PathBuf::from("security.key")),
                Path::new("security.key")
            ),
            Err(StartupError::HumanOidcReusesInstallationKey)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_require_exact_private_permissions_and_no_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        fs::write(&path, b"correct-token\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&*read_secret_string(&path).unwrap(), "correct-token");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_secret_string(&path),
            Err(StartupError::InsecureSecretPermissions(_))
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("token-link");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            read_secret_string(&link),
            Err(StartupError::UnsafePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn only_direct_systemd_credentials_accept_read_only_modes() {
        let directory = tempfile::tempdir().unwrap();
        let credentials_directory = directory.path().join("credentials");
        fs::create_dir(&credentials_directory).unwrap();
        fs::set_permissions(&credentials_directory, fs::Permissions::from_mode(0o500)).unwrap();

        let ordinary = directory.path().join("ordinary-token");
        fs::write(&ordinary, b"ordinary").unwrap();
        for mode in [0o400, 0o440] {
            fs::set_permissions(&ordinary, fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                read_bounded_private_bytes_with_credentials(
                    &ordinary,
                    100,
                    StartupError::InvalidSecretSize,
                    Some(&credentials_directory),
                ),
                Err(StartupError::InsecureSecretPermissions(_))
            ));
        }

        let credential = credentials_directory.join("token");
        fs::write(&credential, b"credential").unwrap();
        for mode in [0o400, 0o440] {
            fs::set_permissions(&credential, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                read_bounded_private_bytes_with_credentials(
                    &credential,
                    100,
                    StartupError::InvalidSecretSize,
                    Some(&credentials_directory),
                )
                .unwrap()
                .as_slice(),
                b"credential"
            );
        }

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            read_bounded_private_bytes_with_credentials(
                &credential,
                100,
                StartupError::InvalidSecretSize,
                Some(&credentials_directory),
            ),
            Err(StartupError::InsecureSecretPermissions(_))
        ));

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o400)).unwrap();
        let extra_link = directory.path().join("credential-hard-link");
        fs::hard_link(&credential, &extra_link).unwrap();
        assert!(matches!(
            read_bounded_private_bytes_with_credentials(
                &credential,
                100,
                StartupError::InvalidSecretSize,
                Some(&credentials_directory),
            ),
            Err(StartupError::InsecureSecretPermissions(_))
        ));
    }
}
