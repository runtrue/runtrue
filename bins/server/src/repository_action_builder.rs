use crate::scm_worker::{
    RepositoryActionBuildRequest, RepositoryActionBuilder, RepositoryActionResolveError,
};
use runtrue_git::{GitError, GitTreeEntryKind, SourceSnapshotLimits};
use runtrue_model::ContentDigest;
use runtrue_storage::{CasLimits, FsCas};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt as _, OpenOptionsExt as _, PermissionsExt as _},
        net::UnixStream,
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const MAX_ACTION_CONTEXT_ENTRIES: usize = 20_000;
const MAX_ACTION_CONTEXT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_BUILDER_RESPONSE_BYTES: u64 = 64 * 1024;
static STAGING_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct UnixRepositoryActionBuilder {
    socket: PathBuf,
    context_root: PathBuf,
    cas: FsCas,
    timeout: Duration,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildRequest<'a> {
    protocol_version: u32,
    context_id: &'a str,
    reference: &'a str,
    commit: &'a str,
    metadata_digest: &'a ContentDigest,
    dockerfile: &'a str,
    platform: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildResponse {
    protocol_version: u32,
    image: Option<String>,
    error: Option<String>,
}

impl UnixRepositoryActionBuilder {
    pub fn open(
        socket: impl Into<PathBuf>,
        context_root: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, RepositoryActionResolveError> {
        let socket = socket.into();
        let context_root = context_root.into();
        if timeout.is_zero()
            || !absolute_normal_path(&socket)
            || !absolute_normal_path(&context_root)
        {
            return Err(RepositoryActionResolveError::Rejected);
        }
        fs::create_dir_all(&context_root).map_err(|_| RepositoryActionResolveError::Unavailable)?;
        let metadata = fs::symlink_metadata(&context_root)
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(RepositoryActionResolveError::Rejected);
        }
        fs::set_permissions(&context_root, fs::Permissions::from_mode(0o700))
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        let cas = FsCas::open(context_root.join("cas"), CasLimits::default())
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        Ok(Self {
            socket,
            context_root,
            cas,
            timeout,
        })
    }

    fn stage(
        &self,
        request: &RepositoryActionBuildRequest<'_>,
    ) -> Result<String, RepositoryActionResolveError> {
        let identity = ContentDigest::sha256(
            format!(
                "runtrue.repository-action-context.v1\0{}\0{}\0{}\0{}\0{}",
                request.tenant_id,
                request.repository_id,
                request.reference,
                request.commit,
                request.metadata_digest
            )
            .as_bytes(),
        );
        let context_id = identity
            .as_str()
            .strip_prefix("sha256:")
            .expect("SHA-256 identity")
            .to_owned();
        let contexts = self.context_root.join("contexts");
        fs::create_dir_all(&contexts).map_err(|_| RepositoryActionResolveError::Unavailable)?;
        fs::set_permissions(&contexts, fs::Permissions::from_mode(0o700))
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        let destination = contexts.join(&context_id);
        if destination.is_dir() {
            return Ok(context_id);
        }
        let staging = contexts.join(format!(
            ".pending-{context_id}-{}-{}",
            std::process::id(),
            STAGING_GENERATION.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&staging).map_err(|_| RepositoryActionResolveError::Unavailable)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        let result = self.materialize(request, &staging).and_then(|()| {
            match fs::rename(&staging, &destination) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(_) => Err(RepositoryActionResolveError::Unavailable),
            }
        });
        if staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        Ok(context_id)
    }

    fn materialize(
        &self,
        request: &RepositoryActionBuildRequest<'_>,
        destination: &Path,
    ) -> Result<(), RepositoryActionResolveError> {
        let manifest = request
            .repository
            .build_source_manifest(
                request.repository_id,
                request.commit,
                SourceSnapshotLimits {
                    maximum_entries: MAX_ACTION_CONTEXT_ENTRIES,
                    maximum_total_bytes: MAX_ACTION_CONTEXT_BYTES,
                    maximum_symlink_bytes: 1,
                },
                |digest, bytes| {
                    self.cas
                        .put_verified_reader(
                            bytes,
                            digest,
                            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                        )
                        .map(|_| ())
                        .map_err(|_| GitError::InvalidGitOutput("repository action CAS"))
                },
            )
            .map_err(|_| RepositoryActionResolveError::Rejected)?;
        for entry in manifest.entries {
            let path = destination.join(&entry.path);
            if !path.starts_with(destination) {
                return Err(RepositoryActionResolveError::Rejected);
            }
            match entry.kind {
                GitTreeEntryKind::Directory => {
                    fs::create_dir_all(&path)
                        .map_err(|_| RepositoryActionResolveError::Unavailable)?;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .map_err(|_| RepositoryActionResolveError::Unavailable)?;
                }
                GitTreeEntryKind::File {
                    digest,
                    size_bytes,
                    executable,
                } => {
                    let parent = path
                        .parent()
                        .ok_or(RepositoryActionResolveError::Rejected)?;
                    fs::create_dir_all(parent)
                        .map_err(|_| RepositoryActionResolveError::Unavailable)?;
                    let bytes = self
                        .cas
                        .read_blob_limited(&digest, size_bytes)
                        .map_err(|_| RepositoryActionResolveError::Rejected)?;
                    if u64::try_from(bytes.len()).ok() != Some(size_bytes) {
                        return Err(RepositoryActionResolveError::Rejected);
                    }
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(if executable { 0o500 } else { 0o400 })
                        .open(&path)
                        .map_err(|_| RepositoryActionResolveError::Unavailable)?;
                    file.write_all(&bytes)
                        .and_then(|()| file.sync_all())
                        .map_err(|_| RepositoryActionResolveError::Unavailable)?;
                }
                GitTreeEntryKind::Symlink { .. } => {
                    return Err(RepositoryActionResolveError::Rejected)
                }
            }
        }
        File::open(destination)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| RepositoryActionResolveError::Unavailable)
    }
}

impl RepositoryActionBuilder for UnixRepositoryActionBuilder {
    fn build(
        &self,
        request: RepositoryActionBuildRequest<'_>,
    ) -> Result<String, RepositoryActionResolveError> {
        let context_id = self.stage(&request)?;
        let metadata = fs::symlink_metadata(&self.socket)
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        if !metadata.file_type().is_socket() {
            return Err(RepositoryActionResolveError::Rejected);
        }
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        let encoded = serde_json::to_vec(&BuildRequest {
            protocol_version: 1,
            context_id: &context_id,
            reference: request.reference,
            commit: request.commit,
            metadata_digest: request.metadata_digest,
            dockerfile: request.dockerfile,
            platform: "linux/amd64",
        })
        .map_err(|_| RepositoryActionResolveError::Rejected)?;
        stream
            .write_all(&encoded)
            .and_then(|()| stream.write_all(b"\n"))
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        let mut response = Vec::new();
        Read::by_ref(&mut stream)
            .take(MAX_BUILDER_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .map_err(|_| RepositoryActionResolveError::Unavailable)?;
        if response.len() as u64 > MAX_BUILDER_RESPONSE_BYTES {
            return Err(RepositoryActionResolveError::Rejected);
        }
        let response: BuildResponse = serde_json::from_slice(&response)
            .map_err(|_| RepositoryActionResolveError::Rejected)?;
        if response.protocol_version != 1 || response.error.is_some() {
            return Err(RepositoryActionResolveError::Rejected);
        }
        let image = response
            .image
            .ok_or(RepositoryActionResolveError::Rejected)?;
        if !immutable_image(&image) {
            return Err(RepositoryActionResolveError::Rejected);
        }
        Ok(image)
    }
}

fn absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::Prefix(_)))
}

fn immutable_image(value: &str) -> bool {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && !repository.contains('@')
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_git::{GitLimits, GitRepository};
    use serde_json::Value;
    use std::{
        os::unix::{fs::symlink, net::UnixListener},
        process::Command,
        sync::mpsc,
        thread,
    };

    #[test]
    fn stages_the_exact_commit_and_accepts_only_an_immutable_builder_result() {
        let repository_root = tempfile::tempdir().unwrap();
        initialize_repository(repository_root.path());
        fs::write(repository_root.path().join("Dockerfile"), b"FROM scratch\n").unwrap();
        fs::write(repository_root.path().join("action.yml"), b"metadata\n").unwrap();
        commit_all(repository_root.path());
        let commit = output(repository_root.path(), &["rev-parse", "HEAD"]);
        let repository = GitRepository::open(repository_root.path(), GitLimits::default()).unwrap();
        let state = tempfile::tempdir().unwrap();
        let socket = state.path().join("builder.sock");
        let context_root = state.path().join("contexts-root");
        let listener = UnixListener::bind(&socket).unwrap();
        let (sender, receiver) = mpsc::channel();
        let image = format!("registry.example/actions@sha256:{}", "a".repeat(64));
        let returned_image = image.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            let request: Value = serde_json::from_slice(&request).unwrap();
            sender.send(request).unwrap();
            serde_json::to_writer(
                &mut stream,
                &serde_json::json!({
                    "protocol_version": 1,
                    "image": returned_image,
                    "error": null
                }),
            )
            .unwrap();
        });
        let builder =
            UnixRepositoryActionBuilder::open(&socket, &context_root, Duration::from_secs(2))
                .unwrap();
        let metadata_digest = ContentDigest::sha256(b"metadata\n");
        let reference = format!("ci/backport@{commit}");
        let resolved = builder
            .build(RepositoryActionBuildRequest {
                tenant_id: "tenant-1",
                repository_id: "repository-backport",
                reference: &reference,
                commit: &commit,
                repository: &repository,
                metadata_digest: &metadata_digest,
                dockerfile: "Dockerfile",
            })
            .unwrap();
        assert_eq!(resolved, image);
        let request = receiver.recv().unwrap();
        let context_id = request["context_id"].as_str().unwrap();
        assert_eq!(request["reference"], reference);
        assert_eq!(request["commit"], commit);
        assert_eq!(request["dockerfile"], "Dockerfile");
        assert_eq!(request["platform"], "linux/amd64");
        assert_eq!(
            fs::read(
                context_root
                    .join("contexts")
                    .join(context_id)
                    .join("Dockerfile")
            )
            .unwrap(),
            b"FROM scratch\n"
        );
        server.join().unwrap();
    }

    #[test]
    fn rejects_symbolic_links_from_repository_action_contexts() {
        let repository_root = tempfile::tempdir().unwrap();
        initialize_repository(repository_root.path());
        fs::write(repository_root.path().join("Dockerfile"), b"FROM scratch\n").unwrap();
        symlink("x", repository_root.path().join("link")).unwrap();
        commit_all(repository_root.path());
        let commit = output(repository_root.path(), &["rev-parse", "HEAD"]);
        let repository = GitRepository::open(repository_root.path(), GitLimits::default()).unwrap();
        let state = tempfile::tempdir().unwrap();
        let builder = UnixRepositoryActionBuilder::open(
            state.path().join("missing.sock"),
            state.path().join("contexts-root"),
            Duration::from_secs(2),
        )
        .unwrap();
        let metadata_digest = ContentDigest::sha256(b"metadata");
        let reference = format!("ci/backport@{commit}");
        assert!(matches!(
            builder.build(RepositoryActionBuildRequest {
                tenant_id: "tenant-1",
                repository_id: "repository-backport",
                reference: &reference,
                commit: &commit,
                repository: &repository,
                metadata_digest: &metadata_digest,
                dockerfile: "Dockerfile",
            }),
            Err(RepositoryActionResolveError::Rejected)
        ));
    }

    fn initialize_repository(path: &Path) {
        command(path, &["init", "--quiet"]);
        command(path, &["config", "user.email", "builder@runtrue.invalid"]);
        command(
            path,
            &["config", "user.name", "Repository Action Builder Test"],
        );
    }

    fn commit_all(path: &Path) {
        command(path, &["add", "."]);
        command(path, &["commit", "--quiet", "-m", "fixture"]);
    }

    fn output(path: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(path)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn command(path: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(path)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
