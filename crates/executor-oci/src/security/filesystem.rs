pub(crate) fn canonical_real_directory(
    path: &Path,
    kind: &'static str,
) -> Result<PathBuf, OciError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(OciError::UnsafePath {
            kind,
            path: path.to_path_buf(),
        });
    }
    path.canonicalize()
        .map_err(|source| io_error("canonicalize", path, source))
}

pub(crate) fn prepare_private_state_root(path: &Path) -> Result<PathBuf, OciError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(OciError::UnsafePath {
                    kind: "runtime state root",
                    path: path.to_path_buf(),
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|source| io_error("create runtime state root", path, source))?;
        }
        Err(source) => return Err(io_error("inspect runtime state root", path, source)),
    }
    set_private_directory_permissions(path)?;
    canonical_real_directory(path, "runtime state root")
}

pub(crate) fn canonical_regular_file(
    path: &Path,
    kind: &'static str,
    max_bytes: u64,
) -> Result<PathBuf, OciError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect", path, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(OciError::UnsafePath {
            kind,
            path: path.to_path_buf(),
        });
    }
    path.canonicalize()
        .map_err(|source| io_error("canonicalize", path, source))
}

pub(crate) fn ensure_mount_tree_is_safe(root: &Path, limit: usize) -> Result<(), OciError> {
    let mut pending = vec![root.to_path_buf()];
    let mut observed = 0_usize;
    while let Some(path) = pending.pop() {
        observed = observed.saturating_add(1);
        if observed > limit {
            return Err(OciError::LimitExceeded {
                kind: "mount tree entries",
                limit,
                actual: observed,
            });
        }
        if forbidden_socket_path(&path) {
            return Err(OciError::ForbiddenMount(path.display().to_string()));
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect mounted tree", &path, source))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt as _;
            if metadata.file_type().is_socket()
                || metadata.file_type().is_block_device()
                || metadata.file_type().is_char_device()
                || metadata.file_type().is_fifo()
            {
                return Err(OciError::ForbiddenMount(path.display().to_string()));
            }
        }
        if metadata.file_type().is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|source| io_error("read mounted tree", &path, source))?
            {
                let entry = entry.map_err(|source| io_error("read mounted tree", &path, source))?;
                pending.push(entry.path());
            }
        } else if !metadata.file_type().is_file() {
            return Err(OciError::ForbiddenMount(path.display().to_string()));
        }
    }
    Ok(())
}

pub(crate) fn create_private_directory(path: &Path) -> Result<(), OciError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(OciError::UnsafePath {
                    kind: "job runtime directory",
                    path: path.to_path_buf(),
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|source| io_error("create job runtime directory", path, source))?;
        }
        Err(source) => return Err(io_error("inspect job runtime directory", path, source)),
    }
    set_private_directory_permissions(path)
}

pub(crate) fn set_private_directory_permissions(path: &Path) -> Result<(), OciError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error("secure directory", path, source))?;
    }
    Ok(())
}

pub(crate) fn validate_mount(mount: &OciMount, state_root: &Path) -> Result<PathBuf, OciError> {
    validate_container_path(&mount.destination)?;
    if mount.destination == CONTAINER_WORKSPACE
        || mount.destination.starts_with("/runtrue")
        || ["/run", "/var/run", "/proc", "/sys", "/dev"]
            .iter()
            .any(|prefix| {
                mount.destination == *prefix || mount.destination.starts_with(&format!("{prefix}/"))
            })
    {
        return Err(OciError::ForbiddenMount(mount.destination.clone()));
    }
    let metadata = fs::symlink_metadata(&mount.source)
        .map_err(|source| io_error("inspect mount source", &mount.source, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;
        if metadata.file_type().is_socket()
            || metadata.file_type().is_block_device()
            || metadata.file_type().is_char_device()
            || metadata.file_type().is_fifo()
        {
            return Err(OciError::ForbiddenMount(mount.source.display().to_string()));
        }
    }
    if metadata.file_type().is_symlink()
        || !(metadata.file_type().is_file() || metadata.file_type().is_dir())
    {
        return Err(OciError::ForbiddenMount(mount.source.display().to_string()));
    }
    let source = mount
        .source
        .canonicalize()
        .map_err(|error| io_error("canonicalize mount source", &mount.source, error))?;
    if paths_overlap(&source, state_root) || forbidden_socket_path(&source) {
        return Err(OciError::ForbiddenMount(source.display().to_string()));
    }
    let encoded = utf8_path(&source, "mount source")?;
    if encoded.contains(',') || encoded.chars().any(char::is_control) {
        return Err(OciError::ForbiddenMount(encoded.to_owned()));
    }
    Ok(source)
}

pub(crate) fn validate_broker_socket_mount(
    mount: &OciMount,
    workspace: &Path,
    state_root: &Path,
) -> Result<PathBuf, OciError> {
    const DESTINATION: &str = "/workspace/.runtrue-runtime/scm-proxy.sock";
    if mount.destination != DESTINATION || mount.read_only || forbidden_socket_path(&mount.source) {
        return Err(OciError::ForbiddenMount(mount.destination.clone()));
    }
    let metadata = fs::symlink_metadata(&mount.source)
        .map_err(|source| io_error("inspect broker socket", &mount.source, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        if !metadata.file_type().is_socket() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(OciError::ForbiddenMount(mount.source.display().to_string()));
        }
    }
    #[cfg(not(unix))]
    return Err(OciError::ForbiddenMount(mount.source.display().to_string()));
    let source = mount
        .source
        .canonicalize()
        .map_err(|error| io_error("canonicalize broker socket", &mount.source, error))?;
    let parent = source
        .parent()
        .ok_or_else(|| OciError::ForbiddenMount(source.display().to_string()))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| io_error("inspect broker socket directory", parent, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if parent_metadata.uid() != nix::unistd::geteuid().as_raw()
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(OciError::ForbiddenMount(parent.display().to_string()));
        }
    }
    if paths_overlap(&source, workspace) || paths_overlap(&source, state_root) {
        return Err(OciError::ForbiddenMount(source.display().to_string()));
    }
    Ok(source)
}

pub(crate) fn forbidden_socket_path(path: &Path) -> bool {
    let lowered = path.to_string_lossy().to_ascii_lowercase();
    FORBIDDEN_SOCKET_NAMES
        .iter()
        .any(|name| lowered.ends_with(name))
        || [
            "/var/run/docker",
            "/var/lib/docker",
            "/run/containerd",
            "/run/podman",
            "/var/run/crio",
        ]
        .iter()
        .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/")))
}

pub(crate) struct EphemeralFile {
    path: PathBuf,
    bytes: usize,
}

impl EphemeralFile {
    pub(crate) fn write_environment(
        path: &Path,
        environment: &BTreeMap<String, String>,
        limits: OciLimits,
    ) -> Result<Self, OciError> {
        validate_environment(environment, limits, EnvironmentScope::Container)?;
        let mut bytes = Zeroizing::new(Vec::new());
        for (name, value) in environment {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(b'\n');
        }
        Self::write_sensitive(path, &bytes)
    }

    pub(crate) fn write_sensitive(path: &Path, bytes: &[u8]) -> Result<Self, OciError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        }
        let mut file = options
            .open(path)
            .map_err(|source| io_error("create ephemeral OCI input", path, source))?;
        if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_data()) {
            let _ = fs::remove_file(path);
            return Err(io_error("write ephemeral OCI input", path, source));
        }
        Ok(Self {
            path: path.to_path_buf(),
            bytes: bytes.len(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EphemeralFile {
    fn drop(&mut self) {
        if self.bytes > 0 {
            if let Ok(mut file) = OpenOptions::new().write(true).open(&self.path) {
                let zeros = Zeroizing::new(vec![0_u8; self.bytes.min(1024 * 1024)]);
                let mut remaining = self.bytes;
                while remaining > 0 {
                    let count = remaining.min(zeros.len());
                    if file.write_all(&zeros[..count]).is_err() {
                        break;
                    }
                    remaining -= count;
                }
                let _ = file.sync_data();
            }
        }
        let _ = fs::remove_file(&self.path);
        self.bytes.zeroize();
    }
}

pub(crate) fn io_error(operation: &'static str, path: &Path, source: io::Error) -> OciError {
    OciError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
use crate::{
    fs, io, paths_overlap, utf8_path, validate_container_path, validate_environment, BTreeMap,
    EnvironmentScope, OciError, OciLimits, OciMount, OpenOptions, Path, PathBuf, Zeroizing,
    CONTAINER_WORKSPACE, FORBIDDEN_SOCKET_NAMES,
};
use std::io::Write as _;
use zeroize::Zeroize as _;
