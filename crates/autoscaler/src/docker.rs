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
const RUNNER_LOG_FILE: &str = "runner.log";
const AUTO_REMOVE_RUNNER_CONTAINERS: bool = false;

#[derive(Debug, Deserialize)]
struct DockerContainerSummary {
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
    #[serde(rename = "State", default)]
    state: String,
}

fn reserves_runner_capacity(container: &DockerContainerSummary) -> bool {
    container
        .labels
        .get("dev.runtrue.autoscaled")
        .map(String::as_str)
        == Some("true")
        && matches!(
            container.state.as_str(),
            "created" | "running" | "paused" | "restarting"
        )
}

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
    #[serde(default)]
    pub additional_networks: Vec<String>,
    pub user: String,
    pub runtime_uid: u32,
    pub runtime_gid: u32,
    #[serde(default = "default_state_mount_target")]
    pub state_mount_target: String,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub devices: Vec<DockerDevice>,
    #[serde(default = "default_read_only_rootfs")]
    pub read_only_rootfs: bool,
    #[serde(default = "default_cap_drop")]
    pub cap_drop: Vec<String>,
    #[serde(default = "default_security_opt")]
    pub security_opt: Vec<String>,
    #[serde(default)]
    pub state_directories: Vec<PathBuf>,
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

fn default_cap_drop() -> Vec<String> {
    vec!["ALL".to_owned()]
}

const fn default_read_only_rootfs() -> bool {
    true
}

fn default_security_opt() -> Vec<String> {
    vec!["no-new-privileges:true".to_owned()]
}

fn default_state_mount_target() -> String {
    "/var/lib/runtrue".to_owned()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerDevice {
    #[serde(rename = "PathOnHost")]
    pub path_on_host: PathBuf,
    #[serde(rename = "PathInContainer")]
    pub path_in_container: String,
    #[serde(rename = "CgroupPermissions")]
    pub cgroup_permissions: String,
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

    async fn archive_logs(
        &self,
        container_id: &str,
        request_id: &str,
    ) -> Result<(), AutoscalerError> {
        validate_request_id(request_id)?;
        let destination = self.claim_root.join(request_id).join(RUNNER_LOG_FILE);
        if destination.exists() {
            require_private_regular_file(&destination, "archived runner log")?;
            return Ok(());
        }
        let response = self
            .request(
                "read managed container logs",
                "GET",
                &format!(
                    "/v1.45/containers/{}/logs?stdout=true&stderr=true&timestamps=true",
                    encode_segment(container_id)
                ),
                None,
            )
            .await?;
        require_success("read managed container logs", &response)?;
        let logs = decode_docker_log_stream(&response.body)?;
        write_private_atomic(&destination, &logs)?;
        Ok(())
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
        let containers: Vec<DockerContainerSummary> = serde_json::from_slice(&containers.body)
            .map_err(|_| AutoscalerError::MalformedDockerResponse("list managed containers"))?;
        let existing = containers
            .iter()
            .filter(|container| reserves_runner_capacity(container))
            .count() as u64;

        capacity_slots(info.memory_bytes, info.cpus, existing, &self.template)
    }

    async fn prepare(&self, request: &FleetRequest) -> Result<PreparedInstance, AutoscalerError> {
        validate_request_id(&request.id)?;
        let root = self.claim_root.join(&request.id);
        let claim_directory = root.join("claim");
        let state_directory = root.join("state");
        let mut directories = vec![
            root.clone(),
            claim_directory.clone(),
            state_directory.clone(),
            state_directory.join("runner"),
            state_directory.join("workspaces"),
        ];
        directories.extend(
            self.template
                .state_directories
                .iter()
                .map(|directory| state_directory.join(directory)),
        );
        for directory in &directories {
            fs::create_dir_all(directory).map_err(|error| {
                AutoscalerError::file("create provider directory", directory, error)
            })?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|error| {
                AutoscalerError::file("secure provider directory", directory, error)
            })?;
            require_private_directory(directory, "provider state directory")?;
        }
        for directory in directories.iter().filter(|directory| **directory != root) {
            nix::unistd::chown(
                directory,
                Some(nix::unistd::Uid::from_raw(self.template.runtime_uid)),
                Some(nix::unistd::Gid::from_raw(self.template.runtime_gid)),
            )
            .map_err(|error| {
                AutoscalerError::file(
                    "assign provider directory ownership",
                    directory,
                    error.into(),
                )
            })?;
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
            target: self.template.state_mount_target.clone(),
            read_only: false,
        });
        let endpoints = std::iter::once(&self.template.network)
            .chain(self.template.additional_networks.iter())
            .map(|network| (network.clone(), json!({})))
            .collect::<serde_json::Map<_, _>>();
        let body = json!({
            "Image": self.template.image,
            "Cmd": self.template.command,
            "Env": self.template.environment,
            "Labels": labels,
            "User": self.template.user,
            "WorkingDir": self.template.working_directory.clone().unwrap_or_default(),
            "HostConfig": {
                "Mounts": mounts,
                // The autoscaler archives private supervisor stdout/stderr
                // before removing the container. Docker auto-removal would
                // erase the only diagnostic evidence for startup failures.
                "AutoRemove": AUTO_REMOVE_RUNNER_CONTAINERS,
                "NetworkMode": self.template.network,
                "ReadonlyRootfs": self.template.read_only_rootfs,
                "Privileged": self.template.privileged,
                "Devices": self.template.devices,
                "CapDrop": self.template.cap_drop,
                "SecurityOpt": self.template.security_opt,
                "Memory": self.template.memory_bytes,
                "NanoCpus": self.template.nano_cpus,
                "PidsLimit": self.template.pids_limit,
                "Tmpfs": self.template.tmpfs,
            },
            "NetworkingConfig": {"EndpointsConfig": endpoints},
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
        require_private_directory_owner(
            &prepared.claim_directory,
            "claim directory",
            self.template.runtime_uid,
            self.template.runtime_gid,
        )?;
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
        nix::unistd::chown(
            &temporary,
            Some(nix::unistd::Uid::from_raw(self.template.runtime_uid)),
            Some(nix::unistd::Gid::from_raw(self.template.runtime_gid)),
        )
        .map_err(|error| {
            AutoscalerError::file("assign launch claim ownership", &temporary, error.into())
        })?;
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
        let Some(container_id) = self
            .managed_instance(&instance.id, &instance.fleet_request_id)
            .await?
        else {
            return Ok(());
        };
        // Fail closed: if logs cannot be durably archived, retain the stopped
        // container so an operator can still inspect it with `docker logs`.
        self.archive_logs(&container_id, &instance.fleet_request_id)
            .await?;
        let response = self
            .request(
                "destroy managed container",
                "DELETE",
                &format!(
                    "/v1.45/containers/{}?force=true&v=true",
                    encode_segment(&container_id)
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

fn decode_docker_log_stream(bytes: &[u8]) -> Result<Vec<u8>, AutoscalerError> {
    let mut remaining = bytes;
    let mut decoded = Vec::new();
    while !remaining.is_empty() {
        if remaining.len() < 8 || !matches!(remaining[0], 1 | 2) || remaining[1..4] != [0, 0, 0] {
            return Err(AutoscalerError::MalformedDockerResponse(
                "read managed container logs",
            ));
        }
        let length =
            u32::from_be_bytes([remaining[4], remaining[5], remaining[6], remaining[7]]) as usize;
        if remaining.len() < 8 + length {
            return Err(AutoscalerError::MalformedDockerResponse(
                "read managed container logs",
            ));
        }
        decoded.extend_from_slice(&remaining[8..8 + length]);
        if decoded.len() as u64 > MAX_DOCKER_RESPONSE_BYTES {
            return Err(AutoscalerError::MalformedDockerResponse(
                "read managed container logs",
            ));
        }
        remaining = &remaining[8 + length..];
    }
    Ok(decoded)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), AutoscalerError> {
    let parent = path.parent().ok_or(AutoscalerError::InvalidConfiguration(
        "runner log path has no parent",
    ))?;
    require_private_directory(parent, "runner log directory")?;
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| AutoscalerError::RandomnessUnavailable)?;
    let temporary = parent.join(format!(".runner-log-{}", hex::encode(nonce)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| AutoscalerError::file("create runner log", &temporary, error))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| AutoscalerError::file("write runner log", &temporary, error))?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|error| AutoscalerError::file("publish runner log", path, error))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| AutoscalerError::file("sync runner log directory", parent, error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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
        || template.runtime_uid == 0
        || template.runtime_gid == 0
        || template.user != format!("{}:{}", template.runtime_uid, template.runtime_gid)
        || !template.state_mount_target.starts_with('/')
        || template
            .state_mount_target
            .split('/')
            .any(|component| component == "..")
        || template.memory_bytes <= 0
        || template.nano_cpus <= 0
        || template.pids_limit <= 0
        || template.capacity_reserve_memory_bytes < 0
        || template.capacity_reserve_nano_cpus < 0
        || (!template.privileged
            && (!template
                .cap_drop
                .iter()
                .any(|capability| capability == "ALL")
                || !template
                    .security_opt
                    .iter()
                    .any(|option| option == "no-new-privileges:true")
                || !template.devices.is_empty()))
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "Docker template is missing hardened settings",
        ));
    }
    let mut networks = std::collections::BTreeSet::from([template.network.as_str()]);
    for network in &template.additional_networks {
        if network.is_empty()
            || matches!(network.as_str(), "host" | "none")
            || !networks.insert(network)
        {
            return Err(AutoscalerError::InvalidConfiguration(
                "Docker template contains an unsafe network",
            ));
        }
    }
    if template
        .working_directory
        .as_ref()
        .is_some_and(|directory| {
            !directory.starts_with('/') || directory.split('/').any(|component| component == "..")
        })
    {
        return Err(AutoscalerError::InvalidConfiguration(
            "Docker template working directory is unsafe",
        ));
    }
    for device in &template.devices {
        if !device.path_on_host.starts_with("/dev/")
            || !device.path_in_container.starts_with("/dev/")
            || device.cgroup_permissions.is_empty()
            || !device
                .cgroup_permissions
                .bytes()
                .all(|permission| matches!(permission, b'r' | b'w' | b'm'))
        {
            return Err(AutoscalerError::InvalidConfiguration(
                "Docker template contains an unsafe device",
            ));
        }
    }
    for directory in &template.state_directories {
        if directory.as_os_str().is_empty()
            || directory.is_absolute()
            || directory
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(AutoscalerError::InvalidConfiguration(
                "Docker template contains an unsafe state directory",
            ));
        }
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
            || (!mount.read_only && !template.privileged)
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
        if !mount.read_only
            && (source == trust_root
                || matches!(
                    mount.target.as_str(),
                    "/run/runtrue-runner-ca.pem" | "/run/runtrue-runner-trust"
                ))
        {
            return Err(AutoscalerError::InvalidConfiguration(
                "Docker template contains an unsafe writable trust mount",
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
    require_private_directory_owner(
        path,
        name,
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

fn require_private_directory_owner(
    path: &Path,
    name: &'static str,
    uid: u32,
    gid: u32,
) -> Result<(), AutoscalerError> {
    require_absolute(path, "autoscaler directories must be absolute")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| AutoscalerError::file("inspect private directory", path, error))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AutoscalerError::Provider(format!(
            "{name} must be an owner-only real directory"
        )));
    }
    Ok(())
}

fn require_private_regular_file(path: &Path, name: &'static str) -> Result<(), AutoscalerError> {
    require_absolute(path, "autoscaler files must be absolute")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| AutoscalerError::file("inspect private file", path, error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.gid() != nix::unistd::getegid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_DOCKER_RESPONSE_BYTES
    {
        return Err(AutoscalerError::Provider(format!(
            "{name} must be a bounded owner-only regular file"
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
            additional_networks: Vec::new(),
            user: "10002:10002".into(),
            runtime_uid: 10002,
            runtime_gid: 10002,
            state_mount_target: default_state_mount_target(),
            working_directory: None,
            privileged: false,
            devices: Vec::new(),
            read_only_rootfs: true,
            cap_drop: default_cap_drop(),
            security_opt: default_security_opt(),
            state_directories: Vec::new(),
            memory_bytes: 1,
            nano_cpus: 1,
            pids_limit: 1,
            capacity_reserve_memory_bytes: 0,
            capacity_reserve_nano_cpus: 0,
            tmpfs: BTreeMap::from([("/tmp".into(), "rw".into()), ("/run".into(), "rw".into())]),
        };
        validate_template(&template, root.path()).unwrap();
        let writable = root.path().join("oci-store");
        fs::create_dir(&writable).unwrap();
        template.privileged = true;
        template.cap_drop.clear();
        template.security_opt = vec!["label=disable".into()];
        template.additional_networks = vec!["runtrue_scm-egress".into()];
        template.devices.push(DockerDevice {
            path_on_host: "/dev/fuse".into(),
            path_in_container: "/dev/fuse".into(),
            cgroup_permissions: "rwm".into(),
        });
        template.mounts.push(DockerMount {
            kind: "bind".into(),
            source: writable,
            target: "/var/lib/runtrue/oci-store".into(),
            read_only: false,
        });
        validate_template(&template, root.path()).unwrap();
        template.privileged = false;
        assert!(validate_template(&template, root.path()).is_err());
        template.privileged = true;
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
            additional_networks: Vec::new(),
            user: "10002:10002".into(),
            runtime_uid: 10002,
            runtime_gid: 10002,
            state_mount_target: default_state_mount_target(),
            working_directory: None,
            privileged: false,
            devices: Vec::new(),
            read_only_rootfs: true,
            cap_drop: default_cap_drop(),
            security_opt: default_security_opt(),
            state_directories: Vec::new(),
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
    fn exited_managed_containers_do_not_reserve_capacity() {
        let managed = |state: &str| DockerContainerSummary {
            labels: BTreeMap::from([("dev.runtrue.autoscaled".to_owned(), "true".to_owned())]),
            state: state.to_owned(),
        };
        for state in ["created", "running", "paused", "restarting"] {
            assert!(reserves_runner_capacity(&managed(state)), "state {state}");
        }
        for state in ["removing", "exited", "dead", ""] {
            assert!(!reserves_runner_capacity(&managed(state)), "state {state}");
        }
        let unrelated = DockerContainerSummary {
            labels: BTreeMap::new(),
            state: "running".to_owned(),
        };
        assert!(!reserves_runner_capacity(&unrelated));
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

    #[test]
    fn runner_containers_are_retained_until_logs_are_archived() {
        const { assert!(!AUTO_REMOVE_RUNNER_CONTAINERS) };
    }

    #[test]
    fn docker_log_stream_preserves_interleaved_stdout_and_stderr() {
        let frame = |stream: u8, payload: &[u8]| {
            let mut value = vec![stream, 0, 0, 0];
            value.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            value.extend_from_slice(payload);
            value
        };
        let mut encoded = frame(1, b"stdout\n");
        encoded.extend(frame(2, b"stderr\n"));
        assert_eq!(
            decode_docker_log_stream(&encoded).unwrap(),
            b"stdout\nstderr\n"
        );
        assert!(decode_docker_log_stream(b"unframed").is_err());
        assert!(decode_docker_log_stream(&[1, 0, 0, 0, 0, 0, 0, 2, b'x']).is_err());
    }

    #[test]
    fn archived_runner_logs_are_private_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let log = root.path().join(RUNNER_LOG_FILE);
        write_private_atomic(&log, b"runner failed\n").unwrap();
        require_private_regular_file(&log, "test runner log").unwrap();
        assert_eq!(fs::read(&log).unwrap(), b"runner failed\n");
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
