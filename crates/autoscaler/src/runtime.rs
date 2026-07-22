use crate::{AutoscalerError, DockerProvider, HttpControlPlane, Reconciler};
use rand_core::{OsRng, RngCore as _};
use std::{
    env,
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::watch;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct AutoscalerConfig {
    pub control_plane_origin: String,
    pub pool_id: String,
    pub token_file: PathBuf,
    pub docker_socket: PathBuf,
    pub docker_template_file: PathBuf,
    pub claim_root: PathBuf,
    pub trust_root: PathBuf,
    pub owner_id: Option<String>,
    pub reconcile_interval: Duration,
}

impl AutoscalerConfig {
    pub fn from_env() -> Result<Self, AutoscalerError> {
        Ok(Self {
            control_plane_origin: required("RUNTRUE_AUTOSCALER_CONTROL_PLANE")?,
            pool_id: required("RUNTRUE_AUTOSCALER_POOL_ID")?,
            token_file: required_path("RUNTRUE_AUTOSCALER_TOKEN_FILE")?,
            docker_socket: env::var_os("RUNTRUE_AUTOSCALER_DOCKER_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/run/docker.sock")),
            docker_template_file: required_path("RUNTRUE_AUTOSCALER_DOCKER_TEMPLATE_FILE")?,
            claim_root: required_path("RUNTRUE_AUTOSCALER_CLAIM_ROOT")?,
            trust_root: required_path("RUNTRUE_AUTOSCALER_TRUST_ROOT")?,
            owner_id: env::var("RUNTRUE_AUTOSCALER_OWNER_ID")
                .ok()
                .map(|value| validate_text(value, "autoscaler owner ID"))
                .transpose()?,
            reconcile_interval: Duration::from_secs(15),
        })
    }
}

pub struct AutoscalerRuntime {
    reconciler: Reconciler<HttpControlPlane, DockerProvider>,
    interval: Duration,
}

impl AutoscalerRuntime {
    pub fn new(config: AutoscalerConfig) -> Result<Self, AutoscalerError> {
        validate_text(config.pool_id.clone(), "autoscaler pool ID")?;
        if config.reconcile_interval.is_zero() {
            return Err(AutoscalerError::InvalidConfiguration(
                "reconcile interval must be positive",
            ));
        }
        let token = read_private_token(&config.token_file)?;
        let control_plane = HttpControlPlane::new(&config.control_plane_origin, token)?;
        let provider = DockerProvider::open(
            config.docker_socket,
            config.claim_root,
            config.trust_root,
            config.docker_template_file,
        )?;
        let owner_id = match config.owner_id {
            Some(value) => value,
            None => random_owner_id()?,
        };
        Ok(Self {
            reconciler: Reconciler::new(control_plane, provider, config.pool_id, owner_id),
            interval: config.reconcile_interval,
        })
    }

    pub async fn run_until_signal(self) -> Result<(), AutoscalerError> {
        let (sender, receiver) = watch::channel(false);
        let signal = tokio::spawn(async move {
            #[cfg(unix)]
            let result = {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                tokio::select! {
                    result = tokio::signal::ctrl_c() => result,
                    _ = terminate.recv() => Ok(()),
                }
            };
            #[cfg(not(unix))]
            let result = tokio::signal::ctrl_c().await;
            let _ = sender.send(true);
            result
        });
        let result = self.run_until_shutdown(receiver).await;
        signal.abort();
        result
    }

    pub async fn run_until_shutdown(
        self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), AutoscalerError> {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = self.reconciler.reconcile().await {
                        eprintln!("runtrue-autoscaler: reconciliation failed: {error}");
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
}

pub fn read_private_token(path: &Path) -> Result<Zeroizing<String>, AutoscalerError> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| AutoscalerError::file("inspect API token", path, error))?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.permissions().mode() & 0o077 != 0
        || before.nlink() != 1
        || before.uid() != nix::unistd::geteuid().as_raw()
        || before.len() == 0
        || before.len() > 8192
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "API token must be a private, owner-controlled regular file",
        ));
    }
    let file =
        File::open(path).map_err(|error| AutoscalerError::file("open API token", path, error))?;
    let after = file
        .metadata()
        .map_err(|error| AutoscalerError::file("inspect opened API token", path, error))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || after.nlink() != 1
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "API token changed while opening",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() as usize));
    file.take(before.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| AutoscalerError::file("read API token", path, error))?;
    if bytes.len() as u64 != before.len() {
        return Err(AutoscalerError::InvalidConfiguration(
            "API token changed while reading",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| AutoscalerError::InvalidConfiguration("API token is not UTF-8"))?;
    let token = text.trim_end_matches(['\r', '\n']);
    if token.is_empty()
        || token
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "API token is empty or malformed",
        ));
    }
    Ok(Zeroizing::new(token.to_owned()))
}

fn required(name: &'static str) -> Result<String, AutoscalerError> {
    let value = env::var(name).map_err(|_| AutoscalerError::MissingConfiguration(name))?;
    validate_text(value, name)
}

fn required_path(name: &'static str) -> Result<PathBuf, AutoscalerError> {
    let value = env::var_os(name).ok_or(AutoscalerError::MissingConfiguration(name))?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(AutoscalerError::InvalidConfiguration(
            "autoscaler paths must be absolute",
        ));
    }
    Ok(path)
}

fn validate_text(value: String, _field: &'static str) -> Result<String, AutoscalerError> {
    if value.is_empty()
        || value.len() > 4096
        || value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "autoscaler text configuration is malformed",
        ));
    }
    Ok(value)
}

fn random_owner_id() -> Result<String, AutoscalerError> {
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| AutoscalerError::RandomnessUnavailable)?;
    Ok(format!(
        "autoscaler-{}-{}",
        std::process::id(),
        hex::encode(nonce)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_token_is_exact_and_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        fs::write(&path, b"secret-token\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private_token(&path).unwrap().as_str(), "secret-token");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_token(&path).is_err());
    }
}
