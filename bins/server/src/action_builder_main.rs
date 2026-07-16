use clap::Parser;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ffi::OsString,
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
const MAX_DOCKERFILE_BYTES: u64 = 1024 * 1024;
const MAX_OCI_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const BUILD_POLICY_ID: &str = "runtrue.repository-action-build.v2.network-none.pinned-materials";
const BUILD_ENVIRONMENT_ID: &str =
    "runtrue.buildkit.v0.30.0.remote-docker-container.bridge.no-insecure-entitlements";
const MAX_ALLOWED_BASE_IMAGES: usize = 32;

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
    /// Exact, compiled build policy. Required so old deployment units fail closed.
    #[arg(long)]
    build_policy_id: String,
    /// Reviewed BuildKit image, driver, network, and daemon configuration identity.
    #[arg(long)]
    build_environment_id: String,
    /// Reviewed immutable base materials. Repeat or use a comma-separated list.
    #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append)]
    allowed_base_image: Vec<String>,
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
    let dockerfile_bytes = read_bounded(&dockerfile, MAX_DOCKERFILE_BYTES)?;
    let allowed_base_images = normalized_allowed_base_images(args);
    validate_dockerfile_policy(&dockerfile_bytes, &allowed_base_images)?;
    let material_policy_digest = material_policy_digest(&allowed_base_images);
    let cache_id = build_cache_id(args, &request);
    let resolution_path = args.state_directory.join(format!("{cache_id}.json"));
    let archive_path = args.state_directory.join(format!("{cache_id}.oci.tar"));
    if let Ok(existing) = read_bounded(&resolution_path, MAX_METADATA_BYTES) {
        let response: BuildResponse = serde_json::from_slice(&existing)
            .map_err(|_| "cached build resolution is invalid".to_owned())?;
        validate_response(&response)?;
        validate_archive(&archive_path)?;
        if let (Some(command), Some(image)) = (&args.admit_command, &response.image) {
            admit(
                command,
                image,
                &archive_path,
                &request,
                &material_policy_digest,
            )?;
        }
        return Ok(response);
    }
    let tag_digest = ContentDigest::sha256(
        format!(
            "runtrue.repository-action-build.v2\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            args.build_policy_id,
            args.build_environment_id,
            material_policy_digest,
            args.image_repository,
            request.reference,
            request.commit,
            request.metadata_digest
        )
        .as_bytes(),
    );
    let tag = format!(
        "{}:sha-{}",
        args.image_repository,
        &tag_digest.as_str()["sha256:".len()..][..32]
    );
    let metadata_path =
        args.state_directory
            .join(format!(".build-{}-{}.json", cache_id, std::process::id()));
    let pending_archive_path = args.state_directory.join(format!(
        ".build-{}-{}.oci.tar",
        cache_id,
        std::process::id()
    ));
    let _ = fs::remove_file(&metadata_path);
    let _ = fs::remove_file(&pending_archive_path);
    let output = format!("type=oci,dest={}", pending_archive_path.display());
    let status = Command::new(&args.docker)
        .args(buildx_arguments(
            args,
            &request,
            &dockerfile,
            &tag,
            &output,
            &metadata_path,
            &context,
        ))
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
        admit(
            command,
            &image,
            &archive_path,
            &request,
            &material_policy_digest,
        )?;
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
    material_policy_digest: &ContentDigest,
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
            "--build-policy-id",
            BUILD_POLICY_ID,
            "--build-environment-id",
            BUILD_ENVIRONMENT_ID,
            "--material-policy-digest",
            material_policy_digest.as_str(),
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
    let allowed_base_images = normalized_allowed_base_images(args);
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
        || args.build_policy_id != BUILD_POLICY_ID
        || args.build_environment_id != BUILD_ENVIRONMENT_ID
        || allowed_base_images.is_empty()
        || allowed_base_images.len() > MAX_ALLOWED_BASE_IMAGES
        || allowed_base_images
            .iter()
            .any(|image| image.len() > 512 || !immutable_image(image))
        || args.socket_group.as_ref().is_some_and(|group| {
            group.is_empty() || group.len() > 128 || group.chars().any(char::is_whitespace)
        })
    {
        return Err("builder configuration is invalid".to_owned());
    }
    Ok(())
}

fn build_cache_id(args: &Args, request: &BuildRequest) -> String {
    let material_policy_digest = material_policy_digest(&normalized_allowed_base_images(args));
    let digest = ContentDigest::sha256(
        format!(
            "runtrue.repository-action-cache.v2\0{}\0{}\0{}\0{}\0{}",
            BUILD_POLICY_ID,
            BUILD_ENVIRONMENT_ID,
            material_policy_digest,
            args.image_repository,
            request.context_id
        )
        .as_bytes(),
    );
    digest.as_str()["sha256:".len()..].to_owned()
}

fn buildx_arguments(
    args: &Args,
    request: &BuildRequest,
    dockerfile: &Path,
    tag: &str,
    output: &str,
    metadata_path: &Path,
    context: &Path,
) -> Vec<OsString> {
    [
        OsString::from("buildx"),
        OsString::from("build"),
        OsString::from("--builder"),
        OsString::from(&args.buildx_builder),
        OsString::from("--platform"),
        OsString::from(&request.platform),
        OsString::from("--network"),
        OsString::from("none"),
        OsString::from("--provenance=false"),
        OsString::from("--sbom=false"),
        OsString::from("--label"),
        OsString::from(format!("org.runtrue.build-policy.id={BUILD_POLICY_ID}")),
        OsString::from("--label"),
        OsString::from(format!(
            "org.runtrue.build-environment.id={BUILD_ENVIRONMENT_ID}"
        )),
        OsString::from("--label"),
        OsString::from(format!(
            "org.runtrue.material-policy.digest={}",
            material_policy_digest(&normalized_allowed_base_images(args))
        )),
        OsString::from("--file"),
        dockerfile.as_os_str().to_owned(),
        OsString::from("--tag"),
        OsString::from(tag),
        OsString::from("--output"),
        OsString::from(output),
        OsString::from("--metadata-file"),
        metadata_path.as_os_str().to_owned(),
        context.as_os_str().to_owned(),
    ]
    .into_iter()
    .collect()
}

fn validate_dockerfile_policy(bytes: &[u8], allowed_base_images: &[String]) -> Result<(), String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "Dockerfile is not valid UTF-8 under the build policy".to_owned())?;
    let mut stages = HashSet::new();
    let mut stage_count = 0_usize;
    let mut pending = String::new();
    for physical in source.lines() {
        let line = physical.trim_end();
        let continued = line.ends_with('\\');
        let fragment = line.strip_suffix('\\').unwrap_or(line);
        pending.push_str(fragment);
        if continued {
            pending.push(' ');
            continue;
        }
        validate_dockerfile_instruction(
            &pending,
            &mut stages,
            &mut stage_count,
            allowed_base_images,
        )?;
        pending.clear();
    }
    if !pending.is_empty() {
        validate_dockerfile_instruction(
            &pending,
            &mut stages,
            &mut stage_count,
            allowed_base_images,
        )?;
    }
    if stage_count == 0 {
        return Err("Dockerfile build policy requires at least one FROM".to_owned());
    }
    Ok(())
}

fn validate_dockerfile_instruction(
    line: &str,
    stages: &mut HashSet<String>,
    stage_count: &mut usize,
    allowed_base_images: &[String],
) -> Result<(), String> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }
    if let Some(directive) = line.strip_prefix('#') {
        let directive = directive.trim_start().to_ascii_lowercase();
        if directive.starts_with("syntax=") || directive.starts_with("escape=") {
            return Err(
                "Dockerfile frontend and escape directives are forbidden by build policy"
                    .to_owned(),
            );
        }
        return Ok(());
    }
    let (instruction, arguments) = line
        .split_once(char::is_whitespace)
        .ok_or_else(|| "Dockerfile instruction is malformed under build policy".to_owned())?;
    match instruction.to_ascii_uppercase().as_str() {
        "FROM" => validate_from(arguments, stages, stage_count, allowed_base_images),
        "ADD" => Err("Dockerfile ADD is forbidden by build policy; use local COPY".to_owned()),
        "COPY" => validate_copy(arguments, stages, *stage_count, allowed_base_images),
        "RUN" if arguments.trim_start().starts_with("--") => {
            Err("Dockerfile RUN options are forbidden by build policy".to_owned())
        }
        _ => Ok(()),
    }
}

fn validate_from(
    arguments: &str,
    stages: &mut HashSet<String>,
    stage_count: &mut usize,
    allowed_base_images: &[String],
) -> Result<(), String> {
    let mut parts = arguments.split_ascii_whitespace().peekable();
    while parts.peek().is_some_and(|part| part.starts_with("--")) {
        let option = parts.next().expect("peeked FROM option");
        if option != "--platform=linux/amd64" {
            return Err("Dockerfile FROM options are forbidden by build policy".to_owned());
        }
    }
    let image = parts
        .next()
        .ok_or_else(|| "Dockerfile FROM is missing an image".to_owned())?;
    if image.contains('$') {
        return Err("Dockerfile FROM cannot use variables under build policy".to_owned());
    }
    let normalized = image.to_ascii_lowercase();
    if normalized != "scratch"
        && !stages.contains(&normalized)
        && !allowed_base_images.iter().any(|allowed| allowed == image)
    {
        return Err(
            "Dockerfile FROM must use scratch, an earlier stage, or an allowlisted exact base image"
                .to_owned(),
        );
    }
    let remainder: Vec<_> = parts.collect();
    match remainder.as_slice() {
        [] => {}
        [keyword, stage] if keyword.eq_ignore_ascii_case("AS") && valid_stage_name(stage) => {
            stages.insert(stage.to_ascii_lowercase());
        }
        _ => return Err("Dockerfile FROM stage declaration is malformed".to_owned()),
    }
    *stage_count += 1;
    Ok(())
}

fn validate_copy(
    arguments: &str,
    stages: &HashSet<String>,
    stage_count: usize,
    allowed_base_images: &[String],
) -> Result<(), String> {
    for argument in arguments.split_ascii_whitespace() {
        let Some(source) = argument.strip_prefix("--from=") else {
            if argument == "--from" {
                return Err("Dockerfile COPY --from must use the canonical equals form".to_owned());
            }
            continue;
        };
        let normalized = source.to_ascii_lowercase();
        let numeric_stage = source
            .parse::<usize>()
            .is_ok_and(|index| index < stage_count);
        if !numeric_stage
            && !stages.contains(&normalized)
            && !allowed_base_images.iter().any(|allowed| allowed == source)
        {
            return Err("Dockerfile COPY --from must name an earlier stage or an allowlisted exact base image".to_owned());
        }
    }
    Ok(())
}

fn normalized_allowed_base_images(args: &Args) -> Vec<String> {
    let mut images = args.allowed_base_image.clone();
    images.sort_unstable();
    images.dedup();
    images
}

fn material_policy_digest(images: &[String]) -> ContentDigest {
    let mut material = b"runtrue.repository-action-material-policy.v1\0".to_vec();
    for image in images {
        material.extend_from_slice(image.as_bytes());
        material.push(0);
    }
    ContentDigest::sha256(&material)
}

fn valid_stage_name(stage: &str) -> bool {
    !stage.is_empty()
        && stage.len() <= 128
        && stage
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
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
    !repository.is_empty()
        && !repository.contains('@')
        && !repository.chars().any(char::is_whitespace)
        && digest.len() == 64
        && lower_hex(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_BASE: &str = "node:22.17.0-bookworm@sha256:2fa6c977460b56d4d8278947ab56faeb312bc4cc6c4cf78920c6de27812f51c5";

    fn args() -> Args {
        Args {
            socket: PathBuf::from("/run/runtrue-action-builder/builder.sock"),
            context_root: PathBuf::from("/var/lib/runtrue-action-builder/source"),
            state_directory: PathBuf::from("/var/lib/runtrue-action-builder/builds"),
            image_repository: "runtrue.local/repository-actions".to_owned(),
            docker: PathBuf::from("/usr/bin/docker"),
            buildx_builder: "runtrue-actions-builder".to_owned(),
            build_policy_id: BUILD_POLICY_ID.to_owned(),
            build_environment_id: BUILD_ENVIRONMENT_ID.to_owned(),
            allowed_base_image: vec![NODE_BASE.to_owned()],
            admit_command: None,
            socket_gid: Some(1000),
            socket_group: None,
        }
    }

    fn request() -> BuildRequest {
        BuildRequest {
            protocol_version: 1,
            context_id: "a".repeat(64),
            reference: format!("ci/backport@{}", "b".repeat(40)),
            commit: "b".repeat(40),
            metadata_digest: ContentDigest::sha256(b"action.yml"),
            dockerfile: "Dockerfile".to_owned(),
            platform: "linux/amd64".to_owned(),
        }
    }

    #[test]
    fn accepts_only_exact_commit_root_docker_action_requests() {
        let valid = request();
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

    #[test]
    fn build_policy_is_required_and_namespaces_the_cache() {
        let valid = args();
        assert!(validate_args(&valid).is_ok());
        let first = build_cache_id(&valid, &request());
        let mut other_repository = args();
        other_repository.image_repository = "runtrue.local/other".to_owned();
        assert_ne!(first, build_cache_id(&other_repository, &request()));
        let mut other_material = args();
        other_material.allowed_base_image = vec![format!("debian@sha256:{}", "d".repeat(64))];
        assert_ne!(first, build_cache_id(&other_material, &request()));

        let mut reordered = args();
        reordered.allowed_base_image = vec![NODE_BASE.to_owned(), NODE_BASE.to_owned()];
        assert_eq!(first, build_cache_id(&reordered, &request()));

        let mut obsolete = args();
        obsolete.build_policy_id = "runtrue.repository-action-build.v1".to_owned();
        assert!(validate_args(&obsolete).is_err());
    }

    #[test]
    fn buildx_invocation_disables_run_network_and_embeds_policy() {
        let arguments = buildx_arguments(
            &args(),
            &request(),
            Path::new("/context/Dockerfile"),
            "runtrue.local/actions:test",
            "type=oci,dest=/state/image.tar",
            Path::new("/state/metadata.json"),
            Path::new("/context"),
        );
        let arguments: Vec<_> = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(arguments
            .windows(2)
            .any(|window| window == ["--network", "none"]));
        assert!(!arguments
            .iter()
            .any(|argument| argument.contains("network=host")));
        assert!(arguments.iter().any(|argument| {
            argument == &format!("org.runtrue.build-policy.id={BUILD_POLICY_ID}")
        }));
        assert!(arguments.iter().any(|argument| {
            argument == &format!("org.runtrue.build-environment.id={BUILD_ENVIRONMENT_ID}")
        }));
        assert!(arguments
            .iter()
            .any(|argument| argument.starts_with("org.runtrue.material-policy.digest=sha256:")));
    }

    #[test]
    fn dockerfile_policy_accepts_only_pinned_local_materials() {
        let valid = format!(
            "FROM {} AS build\nRUN npm test\nFROM scratch\nCOPY --from=build /out /out\n",
            NODE_BASE
        );
        let allowed = vec![NODE_BASE.to_owned()];
        assert!(validate_dockerfile_policy(valid.as_bytes(), &allowed).is_ok());
        assert!(validate_dockerfile_policy(b"FROM scratch\nCOPY . /action\n", &allowed).is_ok());

        for invalid in [
            "FROM node:22-alpine\n",
            "FROM node:22-alpine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
            "# syntax=docker/dockerfile:1\nFROM scratch\n",
            "FROM scratch\nADD https://example.test/action /action\n",
            "FROM scratch\nRUN --mount=type=secret,id=token true\n",
            "FROM scratch\nRUN --network=host curl http://127.0.0.1/\n",
            "FROM scratch\nCOPY --from=registry.internal/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa /x /x\n",
        ] {
            assert!(
                validate_dockerfile_policy(invalid.as_bytes(), &allowed).is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }
}
