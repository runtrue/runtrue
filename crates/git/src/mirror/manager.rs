#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorLimits {
    pub git: GitLimits,
    pub writer_timeout: Duration,
    pub writer_poll_interval: Duration,
    pub max_refs: usize,
    pub max_objects: usize,
    pub max_files: usize,
    pub max_pack_bytes: u64,
    pub max_object_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_command_output_bytes: usize,
}

impl Default for MirrorLimits {
    fn default() -> Self {
        Self {
            git: GitLimits::default(),
            writer_timeout: Duration::from_secs(5),
            writer_poll_interval: Duration::from_millis(10),
            max_refs: 250_000,
            max_objects: 5_000_000,
            max_files: 2_000_000,
            max_pack_bytes: 8 * 1024 * 1024 * 1024,
            max_object_file_bytes: 1024 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024 * 1024,
            max_command_output_bytes: 64 * 1024 * 1024,
        }
    }
}

impl MirrorLimits {
    fn validate(self) -> Result<Self, GitError> {
        self.git.validate()?;
        if self.writer_timeout.is_zero()
            || self.writer_poll_interval.is_zero()
            || self.writer_poll_interval > self.writer_timeout
            || self.max_refs == 0
            || self.max_objects == 0
            || self.max_files == 0
            || self.max_pack_bytes == 0
            || self.max_object_file_bytes == 0
            || self.max_total_bytes == 0
            || self.max_command_output_bytes == 0
            || self.max_pack_bytes > self.max_total_bytes
            || self.max_object_file_bytes > self.max_total_bytes
        {
            return Err(GitError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorMiss {
    WriterTimeout,
    FetchUnavailable,
    RequestedCommitUnavailable,
    CorruptQuarantined,
    MirrorUnavailable,
}

#[derive(Debug, Clone)]
pub enum MirrorSyncOutcome {
    Ready(Box<MirrorHandle>),
    Miss(MirrorMiss),
}

#[derive(Clone)]
pub struct MirrorHandle {
    pub(super) identity: RepositoryIdentity,
    pub(super) identity_digest: ContentDigest,
    pub(super) origin: NormalizedOrigin,
    pub(super) repository: GitRepository,
}

impl fmt::Debug for MirrorHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MirrorHandle")
            .field("identity", &self.identity)
            .field("identity_digest", &self.identity_digest)
            .field("origin", &self.origin)
            .field("repository", &self.repository)
            .finish()
    }
}

impl MirrorHandle {
    #[must_use]
    pub fn repository(&self) -> &GitRepository {
        &self.repository
    }

    #[must_use]
    pub fn identity(&self) -> &RepositoryIdentity {
        &self.identity
    }

    #[must_use]
    pub fn origin(&self) -> &NormalizedOrigin {
        &self.origin
    }

    #[must_use]
    pub fn identity_digest(&self) -> &ContentDigest {
        &self.identity_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationOutcome {
    Ready(HydratedWorkspace),
    DirectCloneRequired(MirrorMiss),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydratedWorkspace {
    pub(super) path: PathBuf,
    pub(super) commit: String,
    pub(super) mirror_identity_digest: ContentDigest,
}

impl HydratedWorkspace {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    #[must_use]
    pub fn mirror_identity_digest(&self) -> &ContentDigest {
        &self.mirror_identity_digest
    }

    pub fn cleanup(self) -> Result<(), GitError> {
        make_tree_owner_writable(&self.path)?;
        remove_tree_no_follow(&self.path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceOutcome {
    Completed,
    SkippedBusy,
    Quarantined,
    Missing,
}

#[derive(Clone)]
pub struct MirrorManager {
    pub(super) root: PathBuf,
    pub(super) root_fd: Arc<File>,
    pub(super) git_program: PathBuf,
    pub(super) origin_policy: OriginPolicy,
    pub(super) limits: MirrorLimits,
}

impl fmt::Debug for MirrorManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MirrorManager")
            .field("root", &self.root)
            .field("git_program", &self.git_program)
            .field("origin_policy", &self.origin_policy)
            .field("limits", &self.limits)
            .finish()
    }
}

impl MirrorManager {
    pub fn open(
        root: impl AsRef<Path>,
        origin_policy: OriginPolicy,
        limits: MirrorLimits,
    ) -> Result<Self, GitError> {
        let limits = limits.validate()?;
        let root = prepare_private_root(root.as_ref())?;
        for child in ["mirrors", "staging", "locks", "quarantine"] {
            prepare_private_child(&root, child)?;
        }
        let (root, root_fd) = open_real_directory(&root)?;
        let manager = Self {
            root,
            root_fd: Arc::new(root_fd),
            git_program: find_git()?,
            origin_policy,
            limits,
        };
        manager.probe_required_git_features()?;
        Ok(manager)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn acquire_writer(&self, name: &str) -> Result<Option<WriterLock>, GitError> {
        validate_managed_name(name)?;
        let lock_name = format!("{name}.lock");
        validate_managed_name(&lock_name)?;
        let locks = rustix::fs::openat(
            self.root_fd.as_ref(),
            "locks",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        let owned = rustix::fs::openat(
            &locks,
            lock_name.as_str(),
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| GitError::WriterLock(error.to_string()))?;
        let file = File::from(owned);
        validate_descriptor_file(&locks, &lock_name, &file, 0o600)?;
        let deadline = Instant::now()
            .checked_add(self.limits.writer_timeout)
            .ok_or(GitError::InvalidConfiguration)?;
        loop {
            match flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
                Ok(()) => return Ok(Some(WriterLock(file))),
                Err(nix::errno::Errno::EWOULDBLOCK) if Instant::now() < deadline => {
                    thread::sleep(self.limits.writer_poll_interval);
                }
                Err(nix::errno::Errno::EWOULDBLOCK) => return Ok(None),
                Err(error) => return Err(GitError::WriterLock(error.to_string())),
            }
        }
    }

    pub(super) fn create_managed_directory(
        &self,
        parent: &'static str,
        name: &str,
    ) -> Result<PathBuf, GitError> {
        validate_managed_name(name)?;
        let directory = Dir::openat(
            self.root_fd.as_raw_fd(),
            parent,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        mkdirat(directory.as_raw_fd(), name, Mode::from_bits_truncate(0o700))
            .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        fsync(directory.as_raw_fd())
            .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        let path = self.root.join(parent).join(name);
        validate_real_directory(&path, 0o700)?;
        Ok(path)
    }

    pub(super) fn rename_managed(
        &self,
        source_parent: &'static str,
        source_name: &str,
        destination_parent: &'static str,
        destination_name: &str,
    ) -> Result<(), GitError> {
        validate_managed_name(source_name)?;
        validate_managed_name(destination_name)?;
        let source = rustix::fs::openat(
            self.root_fd.as_ref(),
            source_parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        let destination = rustix::fs::openat(
            self.root_fd.as_ref(),
            destination_parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        rustix::fs::renameat_with(
            &source,
            source_name,
            &destination,
            destination_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        fsync(source.as_raw_fd())
            .and_then(|()| fsync(destination.as_raw_fd()))
            .map_err(|error| GitError::SecureFilesystem(error.to_string()))
    }

    pub(super) fn recover_staging(&self, name: &str) -> Result<(), GitError> {
        let staging_root = self.root.join("staging");
        let mut paths = fs::read_dir(&staging_root)
            .map_err(|source| GitError::Filesystem(staging_root.clone(), source))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|source| GitError::Filesystem(staging_root.clone(), source))
            })
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        for path in paths {
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                return Err(GitError::UnsafeMirrorEntry(path));
            };
            if file_name.starts_with(&format!("{name}-")) {
                validate_real_directory(&path, 0o700)?;
                self.quarantine_path(&path, name, "stale-staging")?;
            }
        }
        Ok(())
    }

    pub(super) fn quarantine_path(
        &self,
        path: &Path,
        name: &str,
        reason: &str,
    ) -> Result<PathBuf, GitError> {
        if !matches!(
            reason,
            "initialize"
                | "fetch"
                | "invalid"
                | "missing-commit"
                | "pre-fetch"
                | "post-fetch"
                | "stale-staging"
                | "hydrate"
                | "fsck"
                | "gc"
        ) {
            return Err(GitError::InvalidConfiguration);
        }
        let destination_name = format!("{name}-{reason}-{}", unique_suffix()?);
        let source_parent = if path.parent() == Some(self.root.join("staging").as_path()) {
            "staging"
        } else if path.parent() == Some(self.root.join("mirrors").as_path()) {
            "mirrors"
        } else {
            return Err(GitError::UnsafeMirrorEntry(path.to_owned()));
        };
        let source_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| GitError::UnsafeMirrorEntry(path.to_owned()))?;
        self.rename_managed(source_parent, source_name, "quarantine", &destination_name)?;
        let destination = self.root.join("quarantine").join(destination_name);
        Ok(destination)
    }

    pub(super) fn run_git_process(
        &self,
        working_directory: &Path,
        arguments: &[String],
        output_limit: usize,
        credential: Option<&GitCredential>,
        transport: Option<(&NormalizedOrigin, &[IpAddr])>,
        allow_controlled_file_transport: bool,
    ) -> Result<ProcessOutput, GitError> {
        if output_limit == 0 {
            return Err(GitError::InvalidConfiguration);
        }
        if credential.is_some() != transport.is_some() {
            return Err(GitError::InvalidConfiguration);
        }
        if let Some(credential) = credential {
            credential.ensure_live()?;
        }
        let mut command = Command::new(&self.git_program);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        command
            .arg("--no-pager")
            .arg("--no-optional-locks")
            .args(git_hardening_arguments())
            .arg("-c")
            .arg("init.templateDir=")
            .arg("-c")
            .arg("http.proxy=")
            .arg("-c")
            .arg("http.extraHeader=")
            .arg("-c")
            .arg("http.sslVerify=true")
            .arg("-c")
            .arg("http.followRedirects=false");
        if allow_controlled_file_transport {
            command.arg("-c").arg("protocol.file.allow=always");
        }
        if let Some((origin, addresses)) = transport {
            if addresses.is_empty() || addresses.len() > MAX_DNS_RESULTS {
                return Err(GitError::UnsafeOriginResolution);
            }
            for address in addresses {
                let address = match address {
                    IpAddr::V4(value) => value.to_string(),
                    IpAddr::V6(value) => format!("[{value}]"),
                };
                command.arg("-c").arg(format!(
                    "http.curloptResolve={}:{}:{address}",
                    origin.host(),
                    origin.port()
                ));
            }
            command.arg(format!(
                "--config-env=http.{}.extraHeader=RUNTRUE_GIT_AUTHORIZATION_HEADER",
                origin.as_str()
            ));
        }
        command
            .args(arguments)
            .current_dir(working_directory)
            .env_clear()
            .env("PATH", safe_path())
            .env("LC_ALL", "C")
            .env("HOME", null_device())
            .env("XDG_CONFIG_HOME", null_device())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .env("GIT_CONFIG_SYSTEM", null_device())
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_ASKPASS", null_device())
            .env("SSH_ASKPASS", null_device())
            .env("GIT_SSH_COMMAND", "false")
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(credential) = credential {
            command.env("RUNTRUE_GIT_AUTHORIZATION_HEADER", credential.header());
        }
        let mut child = command
            .spawn()
            .map_err(|source| GitError::Spawn(source.to_string()))?;
        // Drop Command immediately so its child-only environment copy does not
        // remain retained in the manager while the network operation runs.
        drop(command);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| GitError::Spawn("Git stdout pipe unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| GitError::Spawn("Git stderr pipe unavailable".to_owned()))?;
        let stdout_capture = capture(stdout, output_limit);
        let stderr_capture = capture(stderr, 64 * 1024);
        let status = wait_bounded(
            &mut child,
            self.limits.git.command_timeout,
            self.limits.git.poll_interval,
        )?;
        let mut stdout = stdout_capture
            .join()
            .map_err(|_| GitError::CaptureThread)?
            .map_err(GitError::Capture)?;
        let mut stderr = stderr_capture
            .join()
            .map_err(|_| GitError::CaptureThread)?
            .map_err(GitError::Capture)?;
        if stdout.truncated {
            stdout.bytes.zeroize();
            stderr.bytes.zeroize();
            return Err(GitError::OutputLimit {
                kind: "Git stdout bytes",
                limit: output_limit,
            });
        }
        if let Some(credential) = credential {
            if contains_credential(&stdout.bytes, credential)
                || contains_credential(&stderr.bytes, credential)
            {
                stdout.bytes.zeroize();
                stderr.bytes.zeroize();
                return Err(GitError::CredentialLeakDetected);
            }
        }
        if !status.success() {
            let diagnostic = redacted_diagnostic(&stderr.bytes, credential);
            stdout.bytes.zeroize();
            stderr.bytes.zeroize();
            return Err(GitError::CommandFailed {
                exit_code: status.code(),
                stderr: diagnostic,
            });
        }
        stderr.bytes.zeroize();
        Ok(ProcessOutput {
            stdout: stdout.bytes,
        })
    }

    fn probe_required_git_features(&self) -> Result<(), GitError> {
        let arguments = vec!["help".to_owned(), "--config".to_owned()];
        let output =
            self.run_git_process(&self.root, &arguments, 4 * 1024 * 1024, None, None, false)?;
        let supports_resolve = output
            .stdout
            .split(|byte| *byte == b'\n')
            .any(|line| line.strip_suffix(b"\r").unwrap_or(line) == b"http.curloptResolve");
        if !supports_resolve {
            return Err(GitError::GitResolvePinningUnavailable);
        }
        let config_environment_probe = vec![
            "--config-env=runtrue.probe=PATH".to_owned(),
            "config".to_owned(),
            "--get".to_owned(),
            "runtrue.probe".to_owned(),
        ];
        let output = self
            .run_git_process(
                &self.root,
                &config_environment_probe,
                16 * 1024,
                None,
                None,
                false,
            )
            .map_err(|_| GitError::GitResolvePinningUnavailable)?;
        if parse_one_line(&output.stdout, "Git config environment probe")?
            != safe_path().to_string_lossy()
        {
            return Err(GitError::GitResolvePinningUnavailable);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct ProcessOutput {
    stdout: Vec<u8>,
}

pub(super) struct WriterLock(File);

impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = flock(self.0.as_raw_fd(), FlockArg::Unlock);
    }
}

pub(super) enum FetchEndpoint {
    Https(GitCredential),
    #[cfg(test)]
    TestLocal(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MaintenanceKind {
    Fsck,
    Gc,
}
use super::{
    capture, contains_credential, find_git, flock, fmt, fs, fsync, git_hardening_arguments,
    make_tree_owner_writable, mkdirat, null_device, open_real_directory, parse_one_line,
    prepare_private_child, prepare_private_root, redacted_diagnostic, remove_tree_no_follow,
    safe_path, thread, unique_suffix, validate_descriptor_file, validate_managed_name,
    validate_real_directory, wait_bounded, Arc, Command, ContentDigest, Dir, Duration, File,
    FlockArg, GitCredential, GitError, GitLimits, GitRepository, Instant, IpAddr, Mode,
    NormalizedOrigin, OFlag, OriginPolicy, Path, PathBuf, RepositoryIdentity, Stdio,
    MAX_DNS_RESULTS,
};
use std::os::fd::AsRawFd as _;
use zeroize::Zeroize as _;
