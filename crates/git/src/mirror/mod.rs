use crate::{
    bounded_diagnostic, capture, find_git, git_hardening_arguments, null_device,
    open_real_directory, parse_one_line, safe_path, validate_object_id, wait_bounded, GitError,
    GitLimits, GitRepository, NormalizedOrigin, OriginPolicy,
};
use nix::{
    dir::Dir,
    fcntl::{flock, openat, renameat, AtFlags, FlockArg, OFlag},
    sys::stat::{fstat, fstatat, mkdirat, Mode, SFlag},
    unistd::{close, fsync, unlinkat, UnlinkatFlags},
};
use runtrue_model::ContentDigest;
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fmt, fs,
    fs::{File, OpenOptions},
    io,
    net::{IpAddr, ToSocketAddrs as _},
    os::fd::AsRawFd as _,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt as _;

mod credentials;
mod fetch;
mod hydrate;
mod identity;
mod maintenance;
mod manager;
mod metadata;
mod secure_fs;

use secure_fs::{
    digest_name, effective_uid, make_tree_owner_writable, make_tree_read_only, now_unix_ms,
    prepare_private_child, prepare_private_root, read_bounded_private_file, remove_tree_no_follow,
    sync_directory, sync_tree, unique_suffix, validate_descriptor_file, validate_managed_name,
    validate_real_directory, validate_single_component, verify_no_shared_objects,
    verify_tree_read_only, write_atomic_private_file, DNS_TIMEOUT, FETCH_REFSPECS,
    HYDRATION_MARKER, IDENTITY_METADATA_FILE, MAX_CREDENTIAL_BYTES, MAX_CREDENTIAL_TTL,
    MAX_DNS_RESULTS, MAX_IDENTITY_BYTES, MAX_METADATA_BYTES, MAX_REQUESTED_COMMITS,
    MIRROR_DIRECTORY,
};

pub use credentials::{CredentialRequest, GitCredential, GitCredentialProvider};
pub use identity::RepositoryIdentity;
use manager::{FetchEndpoint, MaintenanceKind};
pub use manager::{
    HydratedWorkspace, HydrationOutcome, MaintenanceOutcome, MirrorHandle, MirrorLimits,
    MirrorManager, MirrorMiss, MirrorSyncOutcome,
};
use metadata::{
    hydration_destination, hydration_failure_is_miss, read_hydration_metadata,
    validate_hydration_parent, verify_identity_metadata, write_hydration_metadata,
    write_identity_metadata, HydrationMetadata, IdentityMetadata,
};

fn validate_requested_commits(commits: &[String]) -> Result<(), GitError> {
    if commits.is_empty() || commits.len() > MAX_REQUESTED_COMMITS {
        return Err(GitError::InvalidConfiguration);
    }
    let mut unique = BTreeSet::new();
    for commit in commits {
        validate_object_id(commit)?;
        if !unique.insert(commit) {
            return Err(GitError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn resolve_public_addresses(origin: &NormalizedOrigin) -> Result<Vec<IpAddr>, GitError> {
    let host = origin.host().to_owned();
    let port = origin.port();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("runtrue-git-dns".to_owned())
        .spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>());
            let _ = sender.send(result);
        })
        .map_err(|_| GitError::UnsafeOriginResolution)?;
    let addresses = receiver
        .recv_timeout(DNS_TIMEOUT)
        .map_err(|_| GitError::UnsafeOriginResolution)?
        .map_err(|_| GitError::UnsafeOriginResolution)?;
    let addresses = addresses.into_iter().collect::<BTreeSet<_>>();
    if addresses.is_empty()
        || addresses.len() > MAX_DNS_RESULTS
        || addresses.iter().any(|address| !is_public_ip(*address))
    {
        return Err(GitError::UnsafeOriginResolution);
    }
    Ok(addresses.into_iter().collect())
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224
                || (a == 255 && b == 255 && c == 255 && d == 255))
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && segments[1] < 0x0200)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
        }
    }
}

fn all_commits_present(repository: &GitRepository, commits: &[String]) -> bool {
    commits.iter().all(|commit| {
        repository
            .verify_commit(commit)
            .is_ok_and(|actual| actual == *commit)
    })
}

fn fetch_failure_is_miss(error: &GitError) -> bool {
    matches!(
        error,
        GitError::CommandFailed { .. }
            | GitError::Timeout
            | GitError::Capture(_)
            | GitError::CaptureThread
            | GitError::OutputLimit { .. }
    )
}

fn mirror_corruption(error: &GitError) -> bool {
    matches!(
        error,
        GitError::UnsafeRepositoryRoot(_)
            | GitError::RepositoryRootMismatch { .. }
            | GitError::UnsafeMirrorEntry(_)
            | GitError::MirrorIdentityChanged
            | GitError::MirrorOriginChanged
            | GitError::MirrorCorrupt(_)
            | GitError::MirrorLimit { .. }
            | GitError::InvalidGitOutput(_)
            | GitError::CommandFailed { .. }
            | GitError::Timeout
            | GitError::OutputLimit { .. }
    )
}

fn exact_config(origin: &NormalizedOrigin) -> Vec<u8> {
    format!(
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n[remote \"origin\"]\n\turl = {}\n",
        origin.as_str()
    )
    .into_bytes()
}

fn write_exact_config(path: &Path, origin: &NormalizedOrigin) -> Result<(), GitError> {
    write_atomic_private_file(path, &exact_config(origin))
}

fn verify_exact_config(path: &Path, origin: &NormalizedOrigin) -> Result<(), GitError> {
    let bytes = read_bounded_private_file(path, MAX_METADATA_BYTES)?;
    if bytes != exact_config(origin) {
        return if contains_subslice(&bytes, origin.as_str().as_bytes()) {
            Err(GitError::MirrorCorrupt(
                "bare repository configuration changed".to_owned(),
            ))
        } else {
            Err(GitError::MirrorOriginChanged)
        };
    }
    Ok(())
}

fn reject_alternates(repository: &Path) -> Result<(), GitError> {
    for relative in ["objects/info/alternates", "objects/info/http-alternates"] {
        let path = repository.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(GitError::MirrorCorrupt(format!(
                    "Git alternate `{relative}` is forbidden"
                )))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(GitError::Filesystem(path, source)),
        }
    }
    Ok(())
}

fn verify_ref_and_object_counts(
    repository: &GitRepository,
    limits: MirrorLimits,
) -> Result<(), GitError> {
    let ref_limit = limits
        .max_refs
        .saturating_add(1)
        .saturating_mul(66)
        .min(limits.max_command_output_bytes);
    let refs = repository.run_git(
        &["for-each-ref", "--format=%(objectname)"],
        ref_limit.max(1),
    )?;
    let ref_count = refs
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count();
    if ref_count > limits.max_refs {
        return Err(GitError::MirrorLimit {
            kind: "reference count",
            limit: u64::try_from(limits.max_refs).unwrap_or(u64::MAX),
        });
    }
    for object in refs
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let object = std::str::from_utf8(object)
            .map_err(|_| GitError::InvalidGitOutput("reference object id"))?;
        validate_object_id(object)?;
    }
    let counts = repository.run_git(&["count-objects", "-v"], 16 * 1024)?;
    let counts = std::str::from_utf8(&counts.stdout)
        .map_err(|_| GitError::InvalidGitOutput("object counts"))?;
    let mut loose = None;
    let mut packed = None;
    for line in counts.lines() {
        if let Some(value) = line.strip_prefix("count: ") {
            loose = value.parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix("in-pack: ") {
            packed = value.parse::<u64>().ok();
        }
    }
    let objects = loose
        .and_then(|loose| packed.and_then(|packed| loose.checked_add(packed)))
        .ok_or(GitError::InvalidGitOutput("object counts"))?;
    if objects > u64::try_from(limits.max_objects).unwrap_or(u64::MAX) {
        return Err(GitError::MirrorLimit {
            kind: "object count",
            limit: u64::try_from(limits.max_objects).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

struct TreeInspection {
    entries: usize,
    total_bytes: u64,
    pack_bytes: u64,
    root_device: u64,
}

fn inspect_tree_confined(repository: &Path, limits: MirrorLimits) -> Result<(), GitError> {
    let mut root = Dir::open(
        repository,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
    let root_stat =
        fstat(root.as_raw_fd()).map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
    if SFlag::from_bits_truncate(root_stat.st_mode) != SFlag::S_IFDIR
        || root_stat.st_uid != effective_uid()
    {
        return Err(GitError::UnsafeMirrorEntry(repository.to_owned()));
    }
    let mut state = TreeInspection {
        entries: 0,
        total_bytes: 0,
        pack_bytes: 0,
        root_device: root_stat.st_dev,
    };
    inspect_directory(&mut root, Path::new(""), repository, limits, &mut state)?;
    Ok(())
}

fn inspect_directory(
    directory: &mut Dir,
    relative: &Path,
    display_root: &Path,
    limits: MirrorLimits,
    state: &mut TreeInspection,
) -> Result<(), GitError> {
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'/') {
            return Err(GitError::UnsafeMirrorEntry(display_root.join(relative)));
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    names.sort();
    let directory_fd = directory.as_raw_fd();
    for name in names {
        state.entries = state.entries.saturating_add(1);
        if state.entries > limits.max_files {
            return Err(GitError::MirrorLimit {
                kind: "file count",
                limit: u64::try_from(limits.max_files).unwrap_or(u64::MAX),
            });
        }
        let child_relative = relative.join(&name);
        let display = display_root.join(&child_relative);
        let named = fstatat(directory_fd, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
        if named.st_dev != state.root_device || named.st_uid != effective_uid() {
            return Err(GitError::UnsafeMirrorEntry(display));
        }
        match SFlag::from_bits_truncate(named.st_mode) {
            SFlag::S_IFDIR => {
                let mut child = Dir::openat(
                    directory_fd,
                    name.as_os_str(),
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
                let opened = fstat(child.as_raw_fd())
                    .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
                if opened.st_dev != named.st_dev
                    || opened.st_ino != named.st_ino
                    || SFlag::from_bits_truncate(opened.st_mode) != SFlag::S_IFDIR
                {
                    return Err(GitError::UnsafeMirrorEntry(display));
                }
                inspect_directory(&mut child, &child_relative, display_root, limits, state)?;
            }
            SFlag::S_IFREG => {
                let raw = openat(
                    directory_fd,
                    name.as_os_str(),
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|error| GitError::SecureFilesystem(error.to_string()))?;
                let opened = fstat(raw).map_err(|error| {
                    let _ = close(raw);
                    GitError::SecureFilesystem(error.to_string())
                })?;
                let _ = close(raw);
                if opened.st_dev != named.st_dev
                    || opened.st_ino != named.st_ino
                    || opened.st_nlink != 1
                    || SFlag::from_bits_truncate(opened.st_mode) != SFlag::S_IFREG
                    || opened.st_size < 0
                {
                    return Err(GitError::UnsafeMirrorEntry(display));
                }
                let size = u64::try_from(opened.st_size)
                    .map_err(|_| GitError::UnsafeMirrorEntry(display.clone()))?;
                state.total_bytes =
                    state
                        .total_bytes
                        .checked_add(size)
                        .ok_or(GitError::MirrorLimit {
                            kind: "total bytes",
                            limit: limits.max_total_bytes,
                        })?;
                if state.total_bytes > limits.max_total_bytes {
                    return Err(GitError::MirrorLimit {
                        kind: "total bytes",
                        limit: limits.max_total_bytes,
                    });
                }
                if child_relative.starts_with("objects/pack")
                    && child_relative.extension() == Some(OsStr::new("pack"))
                {
                    state.pack_bytes =
                        state
                            .pack_bytes
                            .checked_add(size)
                            .ok_or(GitError::MirrorLimit {
                                kind: "pack bytes",
                                limit: limits.max_pack_bytes,
                            })?;
                    if state.pack_bytes > limits.max_pack_bytes {
                        return Err(GitError::MirrorLimit {
                            kind: "pack bytes",
                            limit: limits.max_pack_bytes,
                        });
                    }
                } else if child_relative.starts_with("objects")
                    && size > limits.max_object_file_bytes
                {
                    return Err(GitError::MirrorLimit {
                        kind: "object file bytes",
                        limit: limits.max_object_file_bytes,
                    });
                }
            }
            _ => return Err(GitError::UnsafeMirrorEntry(display)),
        }
    }
    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_credential(bytes: &[u8], credential: &GitCredential) -> bool {
    contains_subslice(bytes, credential.header().as_bytes())
        || contains_subslice(bytes, credential.value().as_bytes())
}

fn redacted_diagnostic(bytes: &[u8], credential: Option<&GitCredential>) -> String {
    let mut redacted = Zeroizing::new(Vec::with_capacity(bytes.len().min(4096)));
    let mut offset = 0;
    while offset < bytes.len() && redacted.len() < 4096 {
        if let Some(credential) = credential {
            let header = credential.header().as_bytes();
            let value = credential.value().as_bytes();
            if bytes[offset..].starts_with(header) {
                redacted.extend_from_slice(b"<redacted>");
                offset = offset.saturating_add(header.len());
                continue;
            }
            if bytes[offset..].starts_with(value) {
                redacted.extend_from_slice(b"<redacted>");
                offset = offset.saturating_add(value.len());
                continue;
            }
        }
        redacted.push(bytes[offset]);
        offset = offset.saturating_add(1);
    }
    bounded_diagnostic(&redacted)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::{process::Command, sync::Barrier};
    use tempfile::TempDir;

    struct Fixture {
        repository: TempDir,
        first: String,
        second: String,
    }

    impl Fixture {
        fn create() -> Self {
            let repository = tempfile::tempdir().expect("repository tempdir");
            git(repository.path(), &["init", "--quiet"]);
            git(
                repository.path(),
                &["config", "user.email", "git-test@runtrue.invalid"],
            );
            git(
                repository.path(),
                &["config", "user.name", "Runtrue Git Test"],
            );
            fs::write(repository.path().join("README.md"), b"first\n").expect("first file");
            git(repository.path(), &["add", "."]);
            git(repository.path(), &["commit", "--quiet", "-m", "first"]);
            let first = git_output(repository.path(), &["rev-parse", "HEAD"]);
            fs::create_dir(repository.path().join("src")).expect("src directory");
            fs::write(repository.path().join("src/main.rs"), b"fn main() {}\n")
                .expect("second file");
            git(repository.path(), &["add", "."]);
            git(repository.path(), &["commit", "--quiet", "-m", "second"]);
            let second = git_output(repository.path(), &["rev-parse", "HEAD"]);
            Self {
                repository,
                first,
                second,
            }
        }
    }

    fn manager(temp: &TempDir) -> MirrorManager {
        MirrorManager::open(
            temp.path().join("mirror-manager"),
            OriginPolicy::new(["git.example.com".to_owned()]).unwrap(),
            MirrorLimits::default(),
        )
        .unwrap()
    }

    fn private_tempdir() -> TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn identity() -> RepositoryIdentity {
        RepositoryIdentity::new("tenant-a", "repository-a").unwrap()
    }

    fn ready(outcome: MirrorSyncOutcome) -> MirrorHandle {
        match outcome {
            MirrorSyncOutcome::Ready(handle) => *handle,
            MirrorSyncOutcome::Miss(miss) => panic!("unexpected mirror miss: {miss:?}"),
        }
    }

    #[test]
    fn cold_warm_hydration_and_maintenance_are_exact_and_read_only() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let manager = manager(&storage);
        let identity = identity();
        let origin = "https://git.example.com/org/repository-a.git";
        let cold = ready(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        assert_eq!(cold.repository().kind(), crate::GitRepositoryKind::Bare);
        assert_eq!(
            cold.repository().verify_commit(&fixture.second).unwrap(),
            fixture.second
        );

        let warm = ready(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    fixture.repository.path(),
                    &[fixture.first.clone(), fixture.second.clone()],
                )
                .unwrap(),
        );
        let workspace_parent = private_tempdir();
        let destination = workspace_parent.path().join("workspace");
        let hydrated = match manager
            .hydrate(&warm, &fixture.first, &destination)
            .unwrap()
        {
            HydrationOutcome::Ready(workspace) => workspace,
            HydrationOutcome::DirectCloneRequired(miss) => {
                panic!("unexpected hydration miss: {miss:?}")
            }
        };
        assert_eq!(
            fs::read_to_string(destination.join("README.md")).unwrap(),
            "first\n"
        );
        assert!(!destination.join("src/main.rs").exists());
        verify_tree_read_only(&destination).unwrap();
        let repeated = manager
            .hydrate(&warm, &fixture.first, &destination)
            .unwrap();
        assert!(matches!(repeated, HydrationOutcome::Ready(_)));
        assert!(matches!(
            manager.hydrate(&warm, &fixture.second, &destination),
            Err(GitError::HydrationMismatch)
        ));
        assert_eq!(
            manager.maintenance_fsck(&identity, origin).unwrap(),
            MaintenanceOutcome::Completed
        );
        assert_eq!(
            manager.maintenance_gc(&identity, origin).unwrap(),
            MaintenanceOutcome::Completed
        );
        hydrated.cleanup().unwrap();
        assert!(!destination.exists());
    }

    #[test]
    fn tenant_identity_isolates_mirrors_and_origin_changes_are_rejected() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let manager = manager(&storage);
        let first_identity = identity();
        let second_identity = RepositoryIdentity::new("tenant-b", "repository-a").unwrap();
        let origin = "https://git.example.com/org/repository-a.git";
        let first = ready(
            manager
                .sync_from_local_path(
                    &first_identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        let second = ready(
            manager
                .sync_from_local_path(
                    &second_identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        assert_ne!(first.identity_digest(), second.identity_digest());
        assert_ne!(first.repository().root(), second.repository().root());
        assert!(matches!(
            manager.sync_from_local_path(
                &first_identity,
                "https://git.example.com/org/a-different-repository.git",
                fixture.repository.path(),
                std::slice::from_ref(&fixture.second),
            ),
            Err(GitError::MirrorOriginChanged)
        ));
    }

    #[test]
    fn a_warm_fetch_outage_uses_an_already_verified_exact_commit() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let manager = manager(&storage);
        let identity = identity();
        let origin = "https://git.example.com/org/repository-a.git";
        ready(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        let unavailable = tempfile::tempdir().unwrap();
        assert!(matches!(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    unavailable.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
            MirrorSyncOutcome::Ready(_)
        ));
    }

    #[test]
    fn hardlinked_or_alternate_mirror_state_is_quarantined() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let manager = manager(&storage);
        let identity = identity();
        let origin = "https://git.example.com/org/repository-a.git";
        let mirror = ready(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        let linked = storage.path().join("linked-config");
        fs::hard_link(mirror.repository().git_dir().join("config"), &linked).unwrap();
        assert!(matches!(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
            MirrorSyncOutcome::Miss(MirrorMiss::CorruptQuarantined)
        ));
        assert!(!mirror.repository().root().exists());
        assert!(fs::read_dir(manager.root().join("quarantine"))
            .unwrap()
            .next()
            .is_some());

        // A new cold mirror is independently checked for Git alternates.
        fs::remove_file(linked).unwrap();
        let mirror = ready(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        fs::write(
            mirror
                .repository()
                .git_dir()
                .join("objects/info/alternates"),
            b"/tmp/forbidden\n",
        )
        .unwrap();
        assert_eq!(
            manager.maintenance_fsck(&identity, origin).unwrap(),
            MaintenanceOutcome::Quarantined
        );
    }

    #[test]
    fn configured_bounds_turn_an_oversized_cold_mirror_into_a_miss() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let limits = MirrorLimits {
            max_files: 1,
            ..MirrorLimits::default()
        };
        let manager = MirrorManager::open(
            storage.path().join("bounded"),
            OriginPolicy::new(["git.example.com".to_owned()]).unwrap(),
            limits,
        )
        .unwrap();
        assert!(matches!(
            manager
                .sync_from_local_path(
                    &identity(),
                    "https://git.example.com/org/repository-a.git",
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
            MirrorSyncOutcome::Miss(MirrorMiss::CorruptQuarantined)
        ));
    }

    #[test]
    fn concurrent_duplicate_hydration_is_atomic_and_idempotent() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let manager = Arc::new(manager(&storage));
        let mirror = Arc::new(ready(
            manager
                .sync_from_local_path(
                    &identity(),
                    "https://git.example.com/org/repository-a.git",
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        ));
        let workspace_parent = private_tempdir();
        let destination = workspace_parent.path().join("workspace");
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let manager = Arc::clone(&manager);
            let mirror = Arc::clone(&mirror);
            let barrier = Arc::clone(&barrier);
            let destination = destination.clone();
            let commit = fixture.second.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                manager.hydrate(&mirror, &commit, &destination)
            }));
        }
        barrier.wait();
        for thread in threads {
            assert!(matches!(
                thread.join().unwrap().unwrap(),
                HydrationOutcome::Ready(_)
            ));
        }
        verify_tree_read_only(&destination).unwrap();
        let workspace = manager
            .validate_hydrated_workspace(&mirror, &fixture.second, &destination)
            .unwrap();
        workspace.cleanup().unwrap();
    }

    #[test]
    fn a_busy_single_writer_returns_bounded_direct_clone_fallback() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let limits = MirrorLimits {
            writer_timeout: Duration::from_millis(20),
            writer_poll_interval: Duration::from_millis(2),
            ..MirrorLimits::default()
        };
        let manager = MirrorManager::open(
            storage.path().join("manager"),
            OriginPolicy::new(["git.example.com".to_owned()]).unwrap(),
            limits,
        )
        .unwrap();
        let mirror = ready(
            manager
                .sync_from_local_path(
                    &identity(),
                    "https://git.example.com/org/repository-a.git",
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        let name = digest_name(mirror.identity_digest()).unwrap();
        let _writer = manager.acquire_writer(&name).unwrap().unwrap();
        let workspace_parent = private_tempdir();
        assert!(matches!(
            manager
                .hydrate(
                    &mirror,
                    &fixture.second,
                    &workspace_parent.path().join("workspace")
                )
                .unwrap(),
            HydrationOutcome::DirectCloneRequired(MirrorMiss::WriterTimeout)
        ));
    }

    #[test]
    fn hydration_destination_symlinks_and_stale_staging_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let manager = manager(&storage);
        let identity = identity();
        let origin = "https://git.example.com/org/repository-a.git";
        let mirror = ready(
            manager
                .sync_from_local_path(
                    &identity,
                    origin,
                    fixture.repository.path(),
                    std::slice::from_ref(&fixture.second),
                )
                .unwrap(),
        );
        let workspace_parent = private_tempdir();
        let destination = workspace_parent.path().join("workspace");
        symlink(fixture.repository.path(), &destination).unwrap();
        assert!(manager
            .hydrate(&mirror, &fixture.second, &destination)
            .is_err());

        let name = digest_name(mirror.identity_digest()).unwrap();
        symlink(
            fixture.repository.path(),
            manager.root().join("staging").join(format!("{name}-evil")),
        )
        .unwrap();
        assert!(manager
            .sync_from_local_path(
                &identity,
                origin,
                fixture.repository.path(),
                std::slice::from_ref(&fixture.second),
            )
            .is_err());
    }

    #[test]
    fn manager_requires_private_real_directories() {
        use std::os::unix::fs::symlink;

        let storage = tempfile::tempdir().unwrap();
        let real = storage.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = storage.path().join("linked");
        symlink(&real, &linked).unwrap();
        assert!(MirrorManager::open(
            &linked,
            OriginPolicy::new(["git.example.com".to_owned()]).unwrap(),
            MirrorLimits::default(),
        )
        .is_err());

        let root = storage.path().join("existing");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(MirrorManager::open(
            &root,
            OriginPolicy::new(["git.example.com".to_owned()]).unwrap(),
            MirrorLimits::default(),
        )
        .is_err());
    }

    #[test]
    fn validated_dns_answer_is_pinned_in_the_child_without_changing_tls_hostname() {
        let storage = tempfile::tempdir().unwrap();
        let mut manager = manager(&storage);
        let script_directory = tempfile::tempdir().unwrap();
        let script = script_directory.path().join("record-git");
        fs::write(&script, b"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        manager.git_program = script.clone();
        let origin = manager
            .origin_policy
            .normalize("https://git.example.com/org/repository-a.git")
            .unwrap();
        let canary = "Authorization: Bearer rebinding-secret-canary";
        let credential = GitCredential::new(canary, now_unix_ms().unwrap() + 60_000).unwrap();
        let arguments = vec!["fetch".to_owned(), origin.as_str().to_owned()];
        manager
            .run_git_process(
                manager.root(),
                &arguments,
                16 * 1024,
                Some(&credential),
                Some((&origin, &["8.8.8.8".parse().unwrap()])),
                false,
            )
            .unwrap();
        let argv = fs::read_to_string(format!("{}.argv", script.display())).unwrap();
        assert!(argv.contains("http.curloptResolve=git.example.com:443:8.8.8.8"));
        assert!(
            !argv.contains("1.1.1.1"),
            "a later DNS answer was not consulted"
        );
        assert!(
            argv.contains(origin.as_str()),
            "hostname URL is retained for TLS/SNI"
        );
        assert!(argv.contains("http.followRedirects=false"));
        assert!(argv.contains("--config-env=http.https://git.example.com/org/repository-a.git.extraHeader=RUNTRUE_GIT_AUTHORIZATION_HEADER"));
        assert!(!argv.contains(canary));
        assert!(!tree_contains_bytes(manager.root(), canary.as_bytes()));
    }

    #[test]
    fn credentials_are_redacted_from_child_failures_and_debug_output() {
        let storage = tempfile::tempdir().unwrap();
        let mut manager = manager(&storage);
        let script_directory = tempfile::tempdir().unwrap();
        let script = script_directory.path().join("leaking-git");
        fs::write(
            &script,
            b"#!/bin/sh\nprintf '%s' \"$RUNTRUE_GIT_AUTHORIZATION_HEADER\" >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        manager.git_program = script;
        let origin = manager
            .origin_policy
            .normalize("https://git.example.com/org/repository-a.git")
            .unwrap();
        let canary = "Authorization: Basic credential-secret-canary";
        let credential = GitCredential::new(canary, now_unix_ms().unwrap() + 60_000).unwrap();
        assert!(!format!("{credential:?}").contains(canary));
        let error = manager
            .run_git_process(
                manager.root(),
                &["fetch".to_owned(), origin.as_str().to_owned()],
                16 * 1024,
                Some(&credential),
                Some((&origin, &["8.8.8.8".parse().unwrap()])),
                false,
            )
            .unwrap_err();
        assert!(matches!(error, GitError::CredentialLeakDetected));
        assert!(!error.to_string().contains(canary));
        assert!(!tree_contains_bytes(manager.root(), canary.as_bytes()));
    }

    #[test]
    fn private_special_purpose_dns_answers_are_all_denied() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "198.51.100.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2001::1",
            "2002::1",
            "3fff::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_public_ip(address.parse().unwrap()),
                "accepted {address}"
            );
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(address.parse().unwrap()), "denied {address}");
        }
    }

    /// Emits real measurements for a declared local fixture; it deliberately
    /// carries no checked-in performance claims. Run with:
    /// `cargo test -p runtrue-git mirror_benchmark_report -- --ignored --nocapture`.
    #[test]
    #[ignore = "explicit benchmark harness"]
    fn mirror_benchmark_report() {
        let fixture = Fixture::create();
        let storage = tempfile::tempdir().unwrap();
        let manager = manager(&storage);
        let workspace_parent = private_tempdir();
        let iterations = 5_u32;
        let mut samples = Vec::new();
        for iteration in 1..=iterations {
            let identity =
                RepositoryIdentity::new("benchmark-tenant", format!("fixture-{iteration}"))
                    .unwrap();
            let origin = "https://git.example.com/benchmark/fixture.git";
            let started = Instant::now();
            let _cold_mirror = ready(
                manager
                    .sync_from_local_path(
                        &identity,
                        origin,
                        fixture.repository.path(),
                        std::slice::from_ref(&fixture.second),
                    )
                    .unwrap(),
            );
            let cold_fetch_millis = elapsed_millis(started);
            let started = Instant::now();
            let mirror = ready(
                manager
                    .sync_from_local_path(
                        &identity,
                        origin,
                        fixture.repository.path(),
                        std::slice::from_ref(&fixture.second),
                    )
                    .unwrap(),
            );
            let warm_fetch_millis = elapsed_millis(started);
            let destination = workspace_parent
                .path()
                .join(format!("workspace-{iteration}"));
            let started = Instant::now();
            let workspace = match manager
                .hydrate(&mirror, &fixture.second, &destination)
                .unwrap()
            {
                HydrationOutcome::Ready(workspace) => workspace,
                HydrationOutcome::DirectCloneRequired(miss) => {
                    panic!("benchmark hydration miss: {miss:?}")
                }
            };
            let hydration_millis = elapsed_millis(started);
            workspace.cleanup().unwrap();
            samples.push(crate::MirrorBenchmarkSample {
                iteration,
                cold_fetch_millis,
                warm_fetch_millis,
                hydration_millis,
            });
        }
        let input = crate::MirrorBenchmarkInput {
            report_version: 1,
            fixture_name: "two-commit-local-sha1".to_owned(),
            iterations,
            warmup_iterations: 0,
            repository_bytes: tree_bytes(fixture.repository.path()),
            ref_count: 1,
            object_count: git_output(fixture.repository.path(), &["count-objects", "-v"])
                .lines()
                .find_map(|line| line.strip_prefix("count: "))
                .unwrap()
                .parse()
                .unwrap(),
            source_commit: fixture.second.clone(),
            base_commit: Some(fixture.first.clone()),
        };
        let report = crate::MirrorBenchmarkReport::from_samples(input, samples).unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&report).unwrap());
    }

    fn elapsed_millis(started: Instant) -> u64 {
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn tree_bytes(path: &Path) -> u64 {
        let metadata = fs::symlink_metadata(path).unwrap();
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::read_dir(path)
                .unwrap()
                .map(|entry| tree_bytes(&entry.unwrap().path()))
                .sum()
        } else if metadata.is_file() {
            metadata.len()
        } else {
            0
        }
    }

    fn tree_contains_bytes(root: &Path, needle: &[u8]) -> bool {
        let metadata = fs::symlink_metadata(root).unwrap();
        if metadata.file_type().is_symlink() {
            return false;
        }
        if metadata.is_dir() {
            return fs::read_dir(root)
                .unwrap()
                .any(|entry| tree_contains_bytes(&entry.unwrap().path(), needle));
        }
        fs::read(root).is_ok_and(|bytes| contains_subslice(&bytes, needle))
    }

    fn git(directory: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .status()
            .expect("Git command");
        assert!(status.success(), "Git failed: {arguments:?}");
    }

    fn git_output(directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .output()
            .expect("Git output");
        assert!(output.status.success(), "Git failed: {arguments:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}
