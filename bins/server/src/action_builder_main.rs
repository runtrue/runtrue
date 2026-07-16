use clap::Parser;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt as _, OpenOptionsExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_METADATA_BYTES: u64 = 256 * 1024;
const MAX_OCI_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "runtrue-action-builder", version)]
struct Args {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    context_root: PathBuf,
    #[arg(long)]
    state_directory: PathBuf,
    #[arg(long)]
    image_repository: String,
    #[arg(long, default_value = "/usr/bin/docker")]
    docker: PathBuf,
    #[arg(long, default_value = "runtrue-actions-builder")]
    buildx_builder: String,
    #[arg(long)]
    admit_command: Option<PathBuf>,
    #[arg(long, conflicts_with = "socket_group")]
    socket_gid: Option<u32>,
    #[arg(long)]
    socket_group: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRequest {
    protocol_version: u32,
    context_id: String,
    reference: String,
    commit: String,
    metadata_digest: ContentDigest,
    dockerfile: String,
    platform: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildResponse {
    protocol_version: u32,
    image: Option<String>,
    error: Option<String>,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("runtrue-action-builder: {error}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    validate_args(&args)?;
    fs::create_dir_all(&args.state_directory).map_err(|_| "cannot create state directory")?;
    fs::set_permissions(&args.state_directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot secure state directory")?;
    if let Some(parent) = args.socket.parent() {
        fs::create_dir_all(parent).map_err(|_| "cannot create socket directory")?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o750))
            .map_err(|_| "cannot secure socket directory")?;
    }
    match fs::symlink_metadata(&args.socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(&args.socket).map_err(|_| "cannot remove stale socket")?;
        }
        Ok(_) => return Err("socket path is occupied by a non-socket".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("cannot inspect socket path".to_owned()),
    }
    let listener = UnixListener::bind(&args.socket).map_err(|_| "cannot bind builder socket")?;
    fs::set_permissions(&args.socket, fs::Permissions::from_mode(0o660))
        .map_err(|_| "cannot set builder socket mode")?;
    let socket_gid = match args.socket_gid {
        Some(gid) => gid,
        None => {
            nix::unistd::Group::from_name(args.socket_group.as_deref().unwrap_or("runtrue-server"))
                .map_err(|_| "cannot resolve builder socket group")?
                .ok_or_else(|| "builder socket group does not exist".to_owned())?
                .gid
                .as_raw()
        }
    };
    nix::unistd::chown(
        &args.socket,
        None,
        Some(nix::unistd::Gid::from_raw(socket_gid)),
    )
    .map_err(|_| "cannot set builder socket group")?;
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let response = handle(&args, &mut stream).unwrap_or_else(|error| BuildResponse {
                    protocol_version: 1,
                    image: None,
                    error: Some(error),
                });
                let _ = serde_json::to_writer(&mut stream, &response);
                let _ = stream.flush();
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    Ok(())
}

fn handle(args: &Args, stream: &mut UnixStream) -> Result<BuildResponse, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| "cannot set request timeout")?;
    let mut bytes = Vec::new();
    Read::by_ref(stream)
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read build request")?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("build request exceeds limit".to_owned());
    }
    let request: BuildRequest =
        serde_json::from_slice(&bytes).map_err(|_| "build request is invalid".to_owned())?;
    validate_request(&request)?;
    let context = args.context_root.join("contexts").join(&request.context_id);
    let context = context
        .canonicalize()
        .map_err(|_| "build context is unavailable".to_owned())?;
    let expected_parent = args
        .context_root
        .join("contexts")
        .canonicalize()
        .map_err(|_| "context root is unavailable".to_owned())?;
    if context.parent() != Some(expected_parent.as_path()) {
        return Err("build context escaped its root".to_owned());
    }
    let dockerfile = context.join(&request.dockerfile);
    reject_symlink_path(&context, &dockerfile)?;
    if !dockerfile.is_file() {
        return Err("Dockerfile is unavailable".to_owned());
    }
    let resolution_path = args
        .state_directory
        .join(format!("{}.json", request.context_id));
    let archive_path = args
        .state_directory
        .join(format!("{}.oci.tar", request.context_id));
    if let Ok(existing) = read_bounded(&resolution_path, MAX_METADATA_BYTES) {
        let response: BuildResponse = serde_json::from_slice(&existing)
            .map_err(|_| "cached build resolution is invalid".to_owned())?;
        validate_response(&response)?;
        validate_archive(&archive_path)?;
        if let (Some(command), Some(image)) = (&args.admit_command, &response.image) {
            admit(command, image, &archive_path, &request)?;
        }
        return Ok(response);
    }
    let tag_digest = ContentDigest::sha256(
        format!(
            "runtrue.repository-action-build.v1\0{}\0{}\0{}",
            request.reference, request.commit, request.metadata_digest
        )
        .as_bytes(),
    );
    let tag = format!(
        "{}:sha-{}",
        args.image_repository,
        &tag_digest.as_str()["sha256:".len()..][..32]
    );
    let metadata_path = args.state_directory.join(format!(
        ".build-{}-{}.json",
        request.context_id,
        std::process::id()
    ));
    let pending_archive_path = args.state_directory.join(format!(
        ".build-{}-{}.oci.tar",
        request.context_id,
        std::process::id()
    ));
    let _ = fs::remove_file(&metadata_path);
    let _ = fs::remove_file(&pending_archive_path);
    let output = format!("type=oci,dest={}", pending_archive_path.display());
    let status = Command::new(&args.docker)
        .args([
            "buildx",
            "build",
            "--builder",
            &args.buildx_builder,
            "--platform",
            &request.platform,
            "--provenance=false",
            "--sbom=false",
            "--file",
        ])
        .arg(&dockerfile)
        .args(["--tag", &tag, "--output", &output, "--metadata-file"])
        .arg(&metadata_path)
        .arg(&context)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "cannot start isolated BuildKit build".to_owned())?;
    if !status.success() {
        let _ = fs::remove_file(&metadata_path);
        let _ = fs::remove_file(&pending_archive_path);
        return Err("isolated BuildKit build failed".to_owned());
    }
    let metadata = read_bounded(&metadata_path, MAX_METADATA_BYTES)?;
    let _ = fs::remove_file(&metadata_path);
    let value: serde_json::Value =
        serde_json::from_slice(&metadata).map_err(|_| "BuildKit metadata is invalid".to_owned())?;
    let digest = value
        .get("containerimage.digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "BuildKit did not return an image digest".to_owned())?;
    let image = format!("{}@{digest}", args.image_repository);
    if !immutable_image(&image) {
        let _ = fs::remove_file(&pending_archive_path);
        return Err("BuildKit returned a mutable or malformed image".to_owned());
    }
    validate_archive(&pending_archive_path)?;
    fs::set_permissions(&pending_archive_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot secure OCI image archive".to_owned())?;
    let _ = fs::remove_file(&archive_path);
    fs::rename(&pending_archive_path, &archive_path)
        .map_err(|_| "cannot persist OCI image archive".to_owned())?;
    if let Some(command) = &args.admit_command {
        admit(command, &image, &archive_path, &request)?;
    }
    let response = BuildResponse {
        protocol_version: 1,
        image: Some(image),
        error: None,
    };
    let encoded =
        serde_json::to_vec(&response).map_err(|_| "cannot encode build resolution".to_owned())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&resolution_path)
        .map_err(|_| "cannot persist build resolution".to_owned())?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot persist build resolution".to_owned())?;
    Ok(response)
}

fn admit(
    command: &Path,
    image: &str,
    archive: &Path,
    request: &BuildRequest,
) -> Result<(), String> {
    let status = Command::new(command)
        .args([
            "--image",
            image,
            "--archive",
            archive
                .to_str()
                .ok_or_else(|| "OCI archive path is not UTF-8".to_owned())?,
            "--reference",
            &request.reference,
            "--commit",
            &request.commit,
            "--metadata-digest",
            request.metadata_digest.as_str(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|_| "cannot start image admission provider".to_owned())?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "image admission provider rejected the build".to_owned())
}

fn validate_archive(path: &Path) -> Result<(), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "OCI image archive is unavailable".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect OCI image archive".to_owned())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_OCI_ARCHIVE_BYTES {
        return Err("OCI image archive is invalid".to_owned());
    }
    Ok(())
}

fn validate_args(args: &Args) -> Result<(), String> {
    if !absolute_normal(&args.socket)
        || !absolute_normal(&args.context_root)
        || !absolute_normal(&args.state_directory)
        || !absolute_normal(&args.docker)
        || args
            .admit_command
            .as_ref()
            .is_some_and(|path| !absolute_normal(path))
        || args.image_repository.is_empty()
        || args.image_repository.contains(['@', ' ', '\n', '\r', '\t'])
        || args.buildx_builder.is_empty()
        || args.buildx_builder.len() > 128
        || args.socket_group.as_ref().is_some_and(|group| {
            group.is_empty() || group.len() > 128 || group.chars().any(char::is_whitespace)
        })
    {
        return Err("builder configuration is invalid".to_owned());
    }
    Ok(())
}

fn validate_request(request: &BuildRequest) -> Result<(), String> {
    let Some((locator, selector)) = request.reference.rsplit_once('@') else {
        return Err("action reference is invalid".to_owned());
    };
    let Some((owner, name)) = locator.split_once('/') else {
        return Err("action reference is invalid".to_owned());
    };
    if request.protocol_version != 1
        || request.context_id.len() != 64
        || !lower_hex(&request.context_id)
        || selector != request.commit
        || request.commit.len() != 40
        || !lower_hex(&request.commit)
        || owner.is_empty()
        || name.is_empty()
        || name.contains('/')
        || request.platform != "linux/amd64"
        || !normal_relative(&request.dockerfile)
    {
        return Err("action build request is invalid".to_owned());
    }
    Ok(())
}

fn validate_response(response: &BuildResponse) -> Result<(), String> {
    if response.protocol_version != 1
        || response.error.is_some()
        || !response.image.as_deref().is_some_and(immutable_image)
    {
        return Err("cached build resolution is invalid".to_owned());
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "cannot open bounded file".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect bounded file".to_owned())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("bounded file is invalid".to_owned());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read bounded file".to_owned())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("bounded file changed while reading".to_owned());
    }
    Ok(bytes)
}

fn reject_symlink_path(root: &Path, target: &Path) -> Result<(), String> {
    if !target.starts_with(root) {
        return Err("Dockerfile escaped the build context".to_owned());
    }
    let mut current = root.to_path_buf();
    for component in target
        .strip_prefix(root)
        .map_err(|_| "Dockerfile escaped the build context")?
        .components()
    {
        let Component::Normal(component) = component else {
            return Err("Dockerfile path is invalid".to_owned());
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| "Dockerfile path is unavailable".to_owned())?;
        if metadata.file_type().is_symlink() {
            return Err("Dockerfile path contains a symbolic link".to_owned());
        }
    }
    Ok(())
}

fn absolute_normal(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::Prefix(_)))
}

fn normal_relative(path: &str) -> bool {
    let path = Path::new(path);
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn immutable_image(value: &str) -> bool {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty() && !repository.contains('@') && digest.len() == 64 && lower_hex(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_exact_commit_root_docker_action_requests() {
        let valid = BuildRequest {
            protocol_version: 1,
            context_id: "a".repeat(64),
            reference: format!("ci/backport@{}", "b".repeat(40)),
            commit: "b".repeat(40),
            metadata_digest: ContentDigest::sha256(b"action.yml"),
            dockerfile: "Dockerfile".to_owned(),
            platform: "linux/amd64".to_owned(),
        };
        assert!(validate_request(&valid).is_ok());
        let mutations: [fn(&mut BuildRequest); 4] = [
            |request: &mut BuildRequest| request.reference = "ci/backport@main".to_owned(),
            |request: &mut BuildRequest| request.commit = "B".repeat(40),
            |request: &mut BuildRequest| request.dockerfile = "../Dockerfile".to_owned(),
            |request: &mut BuildRequest| request.platform = "linux/arm64".to_owned(),
        ];
        for mutate in mutations {
            let mut request = BuildRequest {
                protocol_version: valid.protocol_version,
                context_id: valid.context_id.clone(),
                reference: valid.reference.clone(),
                commit: valid.commit.clone(),
                metadata_digest: valid.metadata_digest.clone(),
                dockerfile: valid.dockerfile.clone(),
                platform: valid.platform.clone(),
            };
            mutate(&mut request);
            assert!(validate_request(&request).is_err());
        }
    }

    #[test]
    fn cached_builder_responses_must_be_exact_images() {
        let valid = BuildResponse {
            protocol_version: 1,
            image: Some(format!(
                "registry.example/actions@sha256:{}",
                "c".repeat(64)
            )),
            error: None,
        };
        assert!(validate_response(&valid).is_ok());
        assert!(validate_response(&BuildResponse {
            protocol_version: 1,
            image: Some("registry.example/actions:latest".to_owned()),
            error: None,
        })
        .is_err());
        assert!(validate_response(&BuildResponse {
            protocol_version: 1,
            image: None,
            error: Some("failed".to_owned()),
        })
        .is_err());
    }
}
