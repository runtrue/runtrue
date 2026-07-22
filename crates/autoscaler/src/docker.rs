use crate::{
    AutoscalerError, FleetRequest, LaunchClaim, PreparedInstance, Provider, ProviderIdentity,
    ProviderInstance,
};
use async_trait::async_trait;
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const MAX_DOCKER_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TEMPLATE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerTemplate {
    pub image: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub environment: Vec<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub mounts: Vec<DockerMount>,
    pub network: String,
    pub user: String,
    pub memory_bytes: i64,
    pub nano_cpus: i64,
    pub pids_limit: i64,
    /// Capacity retained for Compose services and other workloads on the
    /// Docker engine. New runners are admitted only from the remainder.
    #[serde(default = "default_capacity_reserve_memory_bytes")]
    pub capacity_reserve_memory_bytes: i64,
    #[serde(default = "default_capacity_reserve_nano_cpus")]
    pub capacity_reserve_nano_cpus: i64,
    pub tmpfs: BTreeMap<String, String>,
}

const fn default_capacity_reserve_memory_bytes() -> i64 {
    2 * 1024 * 1024 * 1024
}

const fn default_capacity_reserve_nano_cpus() -> i64 {
    2_000_000_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerMount {
    #[serde(rename = "Type")]
    pub kind: String,
    #[serde(rename = "Source")]
    pub source: PathBuf,
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "ReadOnly")]
    pub read_only: bool,
}

pub struct DockerProvider {
    socket: PathBuf,
    claim_root: PathBuf,
    template: DockerTemplate,
    container_prefix: String,
}

impl std::fmt::Debug for DockerProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DockerProvider")
            .field("socket", &self.socket)
            .field("claim_root", &self.claim_root)
            .field("container_prefix", &self.container_prefix)
            .finish_non_exhaustive()
    }
}

impl DockerProvider {
    pub fn open(
        socket: impl Into<PathBuf>,
        claim_root: impl Into<PathBuf>,
        trust_root: impl AsRef<Path>,
        template_file: impl AsRef<Path>,
    ) -> Result<Self, AutoscalerError> {
        let socket = socket.into();
        let claim_root = claim_root.into();
        require_absolute(&socket, "Docker socket must be absolute")?;
        require_private_directory(&claim_root, "claim root")?;
        let template_file = template_file.as_ref();
        let metadata = fs::symlink_metadata(template_file).map_err(|error| {
            AutoscalerError::file("inspect Docker template", template_file, error)
        })?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_TEMPLATE_BYTES
        {
            return Err(AutoscalerError::InvalidConfiguration(
                "Docker template must be a bounded regular file",
            ));
        }
        let bytes = fs::read(template_file)
            .map_err(|error| AutoscalerError::file("read Docker template", template_file, error))?;
        let template: DockerTemplate = serde_json::from_slice(&bytes).map_err(|_| {
            AutoscalerError::InvalidConfiguration("Docker template JSON is malformed")
        })?;
        validate_template(&template, trust_root.as_ref())?;
        Ok(Self {
            socket,
            claim_root,
            template,
            container_prefix: "runtrue-autoscaled-".into(),
        })
    }

    async fn request(
        &self,
        operation: &'static str,
        method: &str,
        path: &str,
        input: Option<&Value>,
    ) -> Result<DockerResponse, AutoscalerError> {
        if !path.starts_with('/') || path.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
            return Err(AutoscalerError::InvalidConfiguration(
                "Docker API path is malformed",
            ));
        }
        let body = input.map(serde_json::to_vec).transpose()?;
        let mut stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|source| AutoscalerError::DockerTransport { operation, source })?;
        let encoded = body.as_deref().unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|source| AutoscalerError::DockerTransport { operation, source })?;
        stream
            .write_all(encoded)
            .await
            .map_err(|source| AutoscalerError::DockerTransport { operation, source })?;
        // `Connection: close` already delimits this exchange. Docker Engine 29
        // treats a client write-half-close as an aborted request and can return
        // `null` instead of the requested JSON document.
        let mut bytes = Vec::new();
        stream
            .take(MAX_DOCKER_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|source| AutoscalerError::DockerTransport { operation, source })?;
        if bytes.len() as u64 > MAX_DOCKER_RESPONSE_BYTES {
            return Err(AutoscalerError::MalformedDockerResponse(operation));
        }
        parse_http_response(operation, &bytes)
    }

    async fn managed_instance(
        &self,
        reference: &str,
        request_id: &str,
    ) -> Result<Option<String>, AutoscalerError> {
        let response = self
            .request(
                "inspect managed container",
                "GET",
                &format!("/v1.45/containers/{}/json", encode_segment(reference)),
                None,
            )
            .await?;
        if response.status == 404 {
            return Ok(None);
        }
        require_success("inspect managed container", &response)?;
        #[derive(Deserialize)]
        struct Inspection {
            #[serde(rename = "Id")]
            id: String,
            #[serde(rename = "Config")]
            config: InspectionConfig,
        }
        #[derive(Deserialize)]
        struct InspectionConfig {
            #[serde(rename = "Labels", default)]
            labels: BTreeMap<String, String>,
        }
        let inspection: Inspection = serde_json::from_slice(&response.body)
            .map_err(|_| AutoscalerError::MalformedDockerResponse("inspect managed container"))?;
        if inspection
            .config
            .labels
            .get("dev.runtrue.autoscaled")
            .map(String::as_str)
            != Some("true")
            || inspection
                .config
                .labels
                .get("dev.runtrue.fleet-request")
                .map(String::as_str)
                != Some(request_id)
        {
            return Err(AutoscalerError::Provider(
                "refusing Docker container without exact managed labels".into(),
            ));
        }
        Ok(Some(inspection.id))
    }

    fn instance(&self, id: String, request_id: &str) -> Result<ProviderInstance, AutoscalerError> {
        #[derive(Serialize)]
        struct Evidence<'a> {
            provider: &'a str,
            provider_instance_id: &'a str,
            fleet_request_id: &'a str,
        }
        let evidence = serde_json::to_vec(&Evidence {
            provider: "docker",
            provider_instance_id: &id,
            fleet_request_id: request_id,
        })?;
        Ok(ProviderInstance {
            id: id.clone(),
            fleet_request_id: request_id.to_owned(),
            identity: ProviderIdentity {
                provider: "docker".into(),
                provider_instance_id: id,
                nonce_digest: ContentDigest::sha256(&evidence).to_string(),
                evidence,
                endorsement: Vec::new(),
            },
        })
    }
}

#[async_trait]
impl Provider for DockerProvider {
    async fn available_capacity(&self) -> Result<u64, AutoscalerError> {
        let info = self
            .request("read Docker capacity", "GET", "/v1.45/info", None)
            .await?;
        require_success("read Docker capacity", &info)?;
        #[derive(Deserialize)]
        struct DockerInfo {
            #[serde(rename = "MemTotal")]
            memory_bytes: i64,
            #[serde(rename = "NCPU")]
            cpus: i64,
        }
        let info: DockerInfo = serde_json::from_slice(&info.body)
            .map_err(|_| AutoscalerError::MalformedDockerResponse("read Docker capacity"))?;

        let containers = self
            .request(
                "list managed containers",
                "GET",
                "/v1.45/containers/json?all=true",
                None,
            )
            .await?;
        require_success("list managed containers", &containers)?;
        #[derive(Deserialize)]
        struct ContainerSummary {
            #[serde(rename = "Labels", default)]
            labels: BTreeMap<String, String>,
        }
        let containers: Vec<ContainerSummary> = serde_json::from_slice(&containers.body)
            .map_err(|_| AutoscalerError::MalformedDockerResponse("list managed containers"))?;
        let existing = containers
            .iter()
            .filter(|container| {
                container
                    .labels
                    .get("dev.runtrue.autoscaled")
                    .map(String::as_str)
                    == Some("true")
            })
            .count() as u64;

        capacity_slots(info.memory_bytes, info.cpus, existing, &self.template)
    }

    async fn prepare(&self, request: &FleetRequest) -> Result<PreparedInstance, AutoscalerError> {
        validate_request_id(&request.id)?;
        let root = self.claim_root.join(&request.id);
        let claim_directory = root.join("claim");
        let state_directory = root.join("state");
        for directory in [
            root.clone(),
            claim_directory.clone(),
            state_directory.clone(),
            state_directory.join("runner"),
            state_directory.join("workspaces"),
        ] {
            fs::create_dir_all(&directory).map_err(|error| {
                AutoscalerError::file("create provider directory", &directory, error)
            })?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(
                |error| AutoscalerError::file("secure provider directory", &directory, error),
            )?;
            require_private_directory(&directory, "provider state directory")?;
        }
        Ok(PreparedInstance {
            provider_request_id: request.id.clone(),
            claim_directory,
            state_directory,
        })
    }

    async fn create(
        &self,
        request: &FleetRequest,
        prepared: &PreparedInstance,
    ) -> Result<ProviderInstance, AutoscalerError> {
        validate_request_id(&request.id)?;
        if request.provider != "docker" {
            return Err(AutoscalerError::Provider(
                "Docker provider cannot satisfy a different provider request".into(),
            ));
        }
        let name = format!("{}{}", self.container_prefix, request.id);
        if let Some(id) = self.managed_instance(&name, &request.id).await? {
            return self.instance(id, &request.id);
        }
        let mut labels = self.template.labels.clone();
        labels.insert("dev.runtrue.autoscaled".into(), "true".into());
        labels.insert("dev.runtrue.fleet-request".into(), request.id.clone());
        let mut mounts = self.template.mounts.clone();
        mounts.push(DockerMount {
            kind: "bind".into(),
            source: prepared.claim_directory.clone(),
            target: "/run/runtrue-launch".into(),
            read_only: true,
        });
        mounts.push(DockerMount {
            kind: "bind".into(),
            source: prepared.state_directory.clone(),
            target: "/var/lib/runtrue".into(),
            read_only: false,
        });
        let body = json!({
            "Image": self.template.image,
            "Cmd": self.template.command,
            "Env": self.template.environment,
            "Labels": labels,
            "User": self.template.user,
            "HostConfig": {
                "Mounts": mounts,
                "AutoRemove": false,
                "NetworkMode": self.template.network,
                "ReadonlyRootfs": true,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": self.template.memory_bytes,
                "NanoCpus": self.template.nano_cpus,
                "PidsLimit": self.template.pids_limit,
                "Tmpfs": self.template.tmpfs,
            }
        });
        let response = self
            .request(
                "create managed container",
                "POST",
                &format!("/v1.45/containers/create?name={}", encode_query(&name)),
                Some(&body),
            )
            .await;
        let response = match response {
            Ok(value) if (200..300).contains(&value.status) => value,
            Ok(value) if value.status == 409 => {
                let id = self.managed_instance(&name, &request.id).await?.ok_or(
                    AutoscalerError::MalformedDockerResponse("recover managed container create"),
                )?;
                return self.instance(id, &request.id);
            }
            Ok(value) => {
                return Err(AutoscalerError::DockerStatus {
                    operation: "create managed container",
                    status: value.status,
                    detail: response_detail(&value.body),
                })
            }
            Err(error) => {
                if let Ok(Some(id)) = self.managed_instance(&name, &request.id).await {
                    return self.instance(id, &request.id);
                }
                return Err(error);
            }
        };
        #[derive(Deserialize)]
        struct Created {
            #[serde(rename = "Id")]
            id: String,
        }
        let created: Created = serde_json::from_slice(&response.body)
            .map_err(|_| AutoscalerError::MalformedDockerResponse("create managed container"))?;
        if created.id.is_empty() {
            return Err(AutoscalerError::MalformedDockerResponse(
                "create managed container",
            ));
        }
        self.instance(created.id, &request.id)
    }

    async fn publish_claim(
        &self,
        _instance: &ProviderInstance,
        prepared: &PreparedInstance,
        claim: &LaunchClaim,
    ) -> Result<(), AutoscalerError> {
        require_private_directory(&prepared.claim_directory, "claim directory")?;
        let encoded = serde_json::to_vec(claim)?;
        let final_path = prepared.claim_directory.join("claim.json");
        if final_path.exists() {
            let existing = fs::read(&final_path).map_err(|error| {
                AutoscalerError::file("read existing launch claim", &final_path, error)
            })?;
            return if existing == encoded {
                Ok(())
            } else {
                Err(AutoscalerError::Provider(
                    "existing launch claim differs from exact retry".into(),
                ))
            };
        }
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| AutoscalerError::RandomnessUnavailable)?;
        let temporary = prepared
            .claim_directory
            .join(format!(".claim-{}", hex::encode(nonce)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| AutoscalerError::file("create launch claim", &temporary, error))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|error| AutoscalerError::file("write launch claim", &temporary, error))?;
        drop(file);
        fs::rename(&temporary, &final_path)
            .map_err(|error| AutoscalerError::file("publish launch claim", &final_path, error))?;
        File::open(&prepared.claim_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                AutoscalerError::file(
                    "sync launch claim directory",
                    &prepared.claim_directory,
                    error,
                )
            })
    }

    async fn start(&self, instance: &ProviderInstance) -> Result<(), AutoscalerError> {
        let response = self
            .request(
                "start managed container",
                "POST",
                &format!("/v1.45/containers/{}/start", encode_segment(&instance.id)),
                None,
            )
            .await?;
        if response.status == 304 {
            return Ok(());
        }
        require_success("start managed container", &response)
    }

    async fn destroy(&self, instance: &ProviderInstance) -> Result<(), AutoscalerError> {
        if instance.id.is_empty() || instance.fleet_request_id.is_empty() {
            return Err(AutoscalerError::Provider(
                "refusing to destroy unbound Docker instance".into(),
            ));
        }
        if self
            .managed_instance(&instance.id, &instance.fleet_request_id)
            .await?
            .is_none()
        {
            return Ok(());
        }
        let response = self
            .request(
                "destroy managed container",
                "DELETE",
                &format!(
                    "/v1.45/containers/{}?force=true&v=true",
                    encode_segment(&instance.id)
                ),
                None,
            )
            .await?;
        if response.status == 404 {
            return Ok(());
        }
        require_success("destroy managed container", &response)
    }

    async fn cleanup_claim(&self, request: &FleetRequest) -> Result<(), AutoscalerError> {
        validate_request_id(&request.id)?;
        let path = self.claim_root.join(&request.id).join("claim");
        match fs::remove_dir_all(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AutoscalerError::file(
                "remove consumed launch claim",
                path,
                error,
            )),
        }
    }
}

struct DockerResponse {
    status: u16,
    body: Vec<u8>,
}

fn parse_http_response(
    operation: &'static str,
    bytes: &[u8],
) -> Result<DockerResponse, AutoscalerError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(AutoscalerError::MalformedDockerResponse(operation))?;
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| AutoscalerError::MalformedDockerResponse(operation))?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(AutoscalerError::MalformedDockerResponse(operation))?;
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(AutoscalerError::MalformedDockerResponse(operation));
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.trim().eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| AutoscalerError::MalformedDockerResponse(operation))?,
            );
        }
    }
    let wire_body = &bytes[header_end + 4..];
    let body = if chunked {
        decode_chunked(operation, wire_body)?
    } else if let Some(length) = content_length {
        if wire_body.len() != length {
            return Err(AutoscalerError::MalformedDockerResponse(operation));
        }
        wire_body.to_vec()
    } else {
        wire_body.to_vec()
    };
    Ok(DockerResponse { status, body })
}

fn decode_chunked(operation: &'static str, bytes: &[u8]) -> Result<Vec<u8>, AutoscalerError> {
    let mut remaining = bytes;
    let mut decoded = Vec::new();
    loop {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(AutoscalerError::MalformedDockerResponse(operation))?;
        let size_text = std::str::from_utf8(&remaining[..line_end])
            .map_err(|_| AutoscalerError::MalformedDockerResponse(operation))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .map_err(|_| AutoscalerError::MalformedDockerResponse(operation))?;
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if remaining.len() < size + 2 || &remaining[size..size + 2] != b"\r\n" {
            return Err(AutoscalerError::MalformedDockerResponse(operation));
        }
        decoded.extend_from_slice(&remaining[..size]);
        if decoded.len() as u64 > MAX_DOCKER_RESPONSE_BYTES {
            return Err(AutoscalerError::MalformedDockerResponse(operation));
        }
        remaining = &remaining[size + 2..];
    }
}

fn require_success(
    operation: &'static str,
    response: &DockerResponse,
) -> Result<(), AutoscalerError> {
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(AutoscalerError::DockerStatus {
            operation,
            status: response.status,
            detail: response_detail(&response.body),
        })
    }
}

fn response_detail(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(4096)])
        .trim()
        .to_owned()
}

fn validate_template(template: &DockerTemplate, trust_root: &Path) -> Result<(), AutoscalerError> {
    if template.image.is_empty()
        || template.network.is_empty()
        || matches!(template.network.as_str(), "host" | "none")
        || template.user.is_empty()
        || template.user == "0"
        || template.user.starts_with("0:")
        || template.memory_bytes <= 0
        || template.nano_cpus <= 0
        || template.pids_limit <= 0
        || template.capacity_reserve_memory_bytes < 0
        || template.capacity_reserve_nano_cpus < 0
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "Docker template is missing hardened settings",
        ));
    }
    let trust_root = normalized_absolute(trust_root)?;
    if trust_root == Path::new("/") {
        return Err(AutoscalerError::InvalidConfiguration(
            "runner trust root cannot be the filesystem root",
        ));
    }
    let mut ca = false;
    let mut trust = false;
    for mount in &template.mounts {
        let source = normalized_absolute(&mount.source)?;
        if mount.kind != "bind"
            || !mount.read_only
            || !source.starts_with(&trust_root)
            || mount
                .source
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("docker.sock")
            || mount.target.to_ascii_lowercase().contains("docker.sock")
        {
            return Err(AutoscalerError::InvalidConfiguration(
                "Docker template contains an unsafe mount",
            ));
        }
        ca |= mount.target == "/run/runtrue-runner-ca.pem";
        trust |= mount.target == "/run/runtrue-runner-trust";
    }
    if !ca || !trust {
        return Err(AutoscalerError::InvalidConfiguration(
            "Docker template is missing runner trust mounts",
        ));
    }
    if !template.tmpfs.contains_key("/tmp") || !template.tmpfs.contains_key("/run") {
        return Err(AutoscalerError::InvalidConfiguration(
            "Docker template requires /tmp and /run tmpfs mounts",
        ));
    }
    Ok(())
}

fn capacity_slots(
    memory_bytes: i64,
    cpus: i64,
    existing: u64,
    template: &DockerTemplate,
) -> Result<u64, AutoscalerError> {
    if memory_bytes <= 0 || cpus <= 0 {
        return Err(AutoscalerError::InvalidConfiguration(
            "Docker engine returned invalid capacity",
        ));
    }
    let usable_memory = memory_bytes.saturating_sub(template.capacity_reserve_memory_bytes);
    let total_nano_cpus = cpus.saturating_mul(1_000_000_000);
    let usable_nano_cpus = total_nano_cpus.saturating_sub(template.capacity_reserve_nano_cpus);
    let memory_slots = usable_memory.max(0) / template.memory_bytes;
    let cpu_slots = usable_nano_cpus.max(0) / template.nano_cpus;
    let total_slots = memory_slots.min(cpu_slots) as u64;
    Ok(total_slots.saturating_sub(existing))
}

fn validate_request_id(value: &str) -> Result<(), AutoscalerError> {
    if value.is_empty()
        || value.len() > 200
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AutoscalerError::Provider(
            "fleet request ID is unsafe for provider storage".into(),
        ));
    }
    Ok(())
}

fn require_private_directory(path: &Path, name: &'static str) -> Result<(), AutoscalerError> {
    require_absolute(path, "autoscaler directories must be absolute")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| AutoscalerError::file("inspect private directory", path, error))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AutoscalerError::Provider(format!(
            "{name} must be an owner-only real directory"
        )));
    }
    Ok(())
}

fn require_absolute(path: &Path, message: &'static str) -> Result<(), AutoscalerError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(AutoscalerError::InvalidConfiguration(message))
    }
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, AutoscalerError> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(AutoscalerError::InvalidConfiguration(
            "Docker host paths must be absolute",
        ));
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(AutoscalerError::InvalidConfiguration(
                    "Docker host paths must be lexically canonical",
                ))
            }
        }
    }
    Ok(normalized)
}

fn encode_segment(value: &str) -> String {
    encode(value, false)
}

fn encode_query(value: &str) -> String {
    encode(value, true)
}

fn encode(value: &str, _query: bool) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_and_request_paths_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let ca = root.path().join("ca.pem");
        let trust = root.path().join("trust");
        fs::write(&ca, b"ca").unwrap();
        fs::create_dir(&trust).unwrap();
        let mut template = DockerTemplate {
            image: "runner".into(),
            command: Vec::new(),
            environment: Vec::new(),
            labels: BTreeMap::new(),
            mounts: vec![
                DockerMount {
                    kind: "bind".into(),
                    source: ca,
                    target: "/run/runtrue-runner-ca.pem".into(),
                    read_only: true,
                },
                DockerMount {
                    kind: "bind".into(),
                    source: trust,
                    target: "/run/runtrue-runner-trust".into(),
                    read_only: true,
                },
            ],
            network: "runtrue_control".into(),
            user: "10002:10002".into(),
            memory_bytes: 1,
            nano_cpus: 1,
            pids_limit: 1,
            capacity_reserve_memory_bytes: 0,
            capacity_reserve_nano_cpus: 0,
            tmpfs: BTreeMap::from([("/tmp".into(), "rw".into()), ("/run".into(), "rw".into())]),
        };
        validate_template(&template, root.path()).unwrap();
        template.mounts.push(DockerMount {
            kind: "bind".into(),
            source: PathBuf::from("/var/run/docker.sock"),
            target: "/var/run/docker.sock".into(),
            read_only: true,
        });
        assert!(validate_template(&template, root.path()).is_err());
        assert!(validate_request_id("../escape").is_err());
    }

    #[test]
    fn capacity_reserves_base_services_and_existing_runners() {
        let template = DockerTemplate {
            image: "runner".into(),
            command: Vec::new(),
            environment: Vec::new(),
            labels: BTreeMap::new(),
            mounts: Vec::new(),
            network: "control".into(),
            user: "10002:10002".into(),
            memory_bytes: 2_000,
            nano_cpus: 2_000_000_000,
            pids_limit: 1,
            capacity_reserve_memory_bytes: 2_000,
            capacity_reserve_nano_cpus: 1_000_000_000,
            tmpfs: BTreeMap::new(),
        };
        assert_eq!(capacity_slots(10_000, 8, 1, &template).unwrap(), 2);
        assert_eq!(capacity_slots(1_000, 8, 0, &template).unwrap(), 0);
    }

    #[test]
    fn parser_supports_content_length_and_chunked_responses() {
        let response =
            parse_http_response("test", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(response.body, b"{}");
        let response = parse_http_response(
            "test",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.body, b"{}");
    }
}
