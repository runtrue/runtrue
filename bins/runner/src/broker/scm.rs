use super::{
    envelope::{decrypt_envelope, timestamp_millis, SecretEnvelopeBinding},
    RunnerBrokerClient,
};
use rand_core::{OsRng, RngCore as _};
use runtrue_engine::{StepState, StepStateObservation, StepStateObserver};
use runtrue_protocol::v1;
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::{NetworkPermission, NetworkProtocol};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const RUNTIME_DIRECTORY: &str = ".runtrue-runtime";
const TOKEN_FILE: &str = "scm-token";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SECRET_BYTES: usize = 1024 * 1024;
const BROKER_TIMEOUT: Duration = Duration::from_secs(15);
const REVOKE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RUNNING_OBSERVATION_ATTEMPTS: usize = 8;
const SCM_PROXY_SOCKET: &str = "scm-proxy.sock";
const MAX_PROXY_HEADER_BYTES: usize = 8 * 1024;
const MAX_PROXY_CONNECTIONS: usize = 32;
const PROXY_IO_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) struct ScmRuntimeFiles {
    root: PathBuf,
    egress: Option<ScmEgressBroker>,
}

impl ScmRuntimeFiles {
    pub(crate) fn prepare(lease: &AdmittedLease, workspace: &Path) -> Result<Option<Self>, String> {
        let Some(event) = lease.capsule.context.normalized_event_json.as_ref() else {
            return Ok(None);
        };
        let Some(scm) = lease.capsule.context.scm.as_ref() else {
            return Err("SCM-capable capsule is missing its signed runtime context".to_owned());
        };
        let root = workspace.join(RUNTIME_DIRECTORY);
        fs::create_dir(&root).map_err(|error| format!("create SCM runtime directory: {error}"))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect SCM runtime directory: {error}"))?;
        let secrets = root.join("secrets");
        fs::create_dir(&secrets)
            .map_err(|error| format!("create private runtime secret directory: {error}"))?;
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect runtime secret directory: {error}"))?;
        write_private(&root.join("event.json"), event.as_bytes())?;
        let context = serde_json::to_vec(scm)
            .map_err(|error| format!("encode signed SCM runtime context: {error}"))?;
        write_private(&root.join("scm-context.json"), &context)?;
        let job = lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == lease.job_id)
            .ok_or_else(|| "leased SCM job is absent from its signed capsule".to_owned())?;
        let has_provider_grant = job.steps.iter().any(|step| {
            step.capabilities
                .secrets
                .iter()
                .any(|grant| grant.name == "runtrue-scm-provider-token")
        });
        let mut allowed = allowed_provider_authorities(&scm.api_url)?;
        for step in &job.steps {
            if let NetworkPermission::Allow {
                destinations,
                listen,
                ..
            } = &step.capabilities.network
            {
                if !listen.is_empty() {
                    return Err("OCI CONNECT broker does not support listening ports".to_owned());
                }
                for destination in destinations {
                    if destination.protocol != NetworkProtocol::Tcp {
                        return Err("OCI CONNECT broker supports only TCP destinations".to_owned());
                    }
                    allowed.insert(validated_authority(&destination.host, destination.port)?);
                }
            }
        }
        let has_network_grant = job
            .steps
            .iter()
            .any(|step| step.capabilities.network != NetworkPermission::Deny);
        let egress = (has_provider_grant || has_network_grant)
            .then(|| ScmEgressBroker::start(workspace, Arc::new(allowed)))
            .transpose()?;
        Ok(Some(Self { root, egress }))
    }

    pub(crate) fn proxy_socket(&self) -> Option<&Path> {
        self.egress.as_ref().map(|broker| broker.socket.as_path())
    }
}

impl Drop for ScmRuntimeFiles {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.root.join(TOKEN_FILE));
        let _ = fs::remove_file(self.root.join("event.json"));
        let _ = fs::remove_file(self.root.join("scm-context.json"));
        let _ = fs::remove_dir_all(self.root.join("secrets"));
        let _ = fs::remove_dir(&self.root);
    }
}

struct ScmEgressBroker {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ScmEgressBroker {
    fn start(workspace: &Path, allowed: Arc<BTreeSet<(String, u16)>>) -> Result<Self, String> {
        let parent = workspace
            .parent()
            .ok_or_else(|| "SCM workspace has no private parent".to_owned())?;
        let directory = tempfile::Builder::new()
            .prefix(".runtrue-scm-egress-")
            .tempdir_in(parent)
            .map_err(|error| format!("create SCM egress directory: {error}"))?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect SCM egress directory: {error}"))?;
        let socket = directory.path().join(SCM_PROXY_SOCKET);
        let listener = UnixListener::bind(&socket)
            .map_err(|error| format!("bind SCM egress broker: {error}"))?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("protect SCM egress broker: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("configure SCM egress broker: {error}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let active = Arc::new(AtomicUsize::new(0));
        let worker = thread::Builder::new()
            .name("runtrue-scm-egress".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if active.fetch_add(1, Ordering::AcqRel) >= MAX_PROXY_CONNECTIONS {
                                active.fetch_sub(1, Ordering::AcqRel);
                                continue;
                            }
                            let allowed = allowed.clone();
                            let active = Arc::clone(&active);
                            let _ = thread::Builder::new()
                                .name("runtrue-scm-connect".to_owned())
                                .spawn(move || {
                                    let _guard = ActiveConnection(active);
                                    let _ = proxy_connect(stream, &allowed);
                                });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|error| format!("start SCM egress broker: {error}"))?;
        Ok(Self {
            _directory: directory,
            socket,
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for ScmEgressBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.socket);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn allowed_provider_authorities(api_url: &str) -> Result<BTreeSet<(String, u16)>, String> {
    let authority = api_url
        .strip_prefix("https://")
        .and_then(|value| value.split('/').next())
        .ok_or_else(|| "signed SCM API URL is invalid".to_owned())?;
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, 443), |(host, port)| {
            (host, port.parse::<u16>().unwrap_or(0))
        });
    let authority = validated_authority(host, port)
        .map_err(|_| "signed SCM provider authority is invalid".to_owned())?;
    let mut allowed = BTreeSet::from([authority]);
    if host == "api.github.com" && port == 443 {
        allowed.insert(("github.com".to_owned(), 443));
    }
    Ok(allowed)
}

fn validated_authority(host: &str, port: u16) -> Result<(String, u16), String> {
    let host = host.to_ascii_lowercase();
    if host.is_empty()
        || port == 0
        || host.bytes().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
        })
    {
        return Err("network destination authority is invalid".to_owned());
    }
    Ok((host, port))
}

fn proxy_connect(
    mut downstream: UnixStream,
    allowed: &BTreeSet<(String, u16)>,
) -> Result<(), std::io::Error> {
    downstream.set_read_timeout(Some(Duration::from_secs(5)))?;
    downstream.set_write_timeout(Some(PROXY_IO_TIMEOUT))?;
    let mut header = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    while header.len() < MAX_PROXY_HEADER_BYTES && !header.ends_with(b"\r\n\r\n") {
        if downstream.read(&mut byte)? == 0 {
            return Ok(());
        }
        header.push(byte[0]);
    }
    if !header.ends_with(b"\r\n\r\n") {
        return Ok(());
    }
    let first = header
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let first = std::str::from_utf8(first)
        .ok()
        .map(str::trim_end)
        .unwrap_or_default();
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or_default();
    let authority = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != "CONNECT" || version != "HTTP/1.1" || parts.next().is_some() {
        downstream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        downstream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    };
    let Ok(port) = port.parse::<u16>() else {
        return Ok(());
    };
    let host = host.to_ascii_lowercase();
    if !allowed.contains(&(host.clone(), port)) {
        downstream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let addresses = (host.as_str(), port)
        .to_socket_addrs()?
        .collect::<BTreeSet<_>>();
    if addresses.is_empty()
        || addresses.len() > 16
        || addresses.iter().any(|addr| !public_ip(addr.ip()))
    {
        downstream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let address = addresses
        .iter()
        .next()
        .copied()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut upstream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    upstream.set_read_timeout(Some(PROXY_IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(PROXY_IO_TIMEOUT))?;
    downstream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    downstream.set_read_timeout(Some(PROXY_IO_TIMEOUT))?;
    let mut downstream_read = downstream.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let forward = thread::spawn(move || std::io::copy(&mut downstream_read, &mut upstream_write));
    let _ = std::io::copy(&mut upstream, &mut downstream);
    let _ = forward.join();
    Ok(())
}

fn public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && c <= 2)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("create private runtime file: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write private runtime file: {error}"))
}

pub(crate) struct ScmCredentialObserver {
    binding: Binding,
    workspace: PathBuf,
    client: Arc<dyn RunnerBrokerClient>,
    lifecycle: Arc<dyn StepStateObserver>,
    grants: BTreeMap<String, Vec<Grant>>,
    leases: Mutex<ScmCredentialLeases>,
}

type ScmCredentialLeases = BTreeMap<(u32, String), Vec<(PathBuf, String)>>;

struct Binding {
    execution_lease_id: String,
    fencing_generation: u64,
    installation_fencing_epoch: u64,
    job_id: String,
    hard_deadline_unix_ms: u64,
}

#[derive(Clone)]
struct Grant {
    name: String,
    metadata_id: String,
    purpose: String,
}

impl ScmCredentialObserver {
    pub(crate) fn wrap(
        lease: &AdmittedLease,
        workspace: &Path,
        client: Arc<dyn RunnerBrokerClient>,
        lifecycle: Arc<dyn StepStateObserver>,
    ) -> Result<Arc<dyn StepStateObserver>, String> {
        let job = lease
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == lease.job_id)
            .ok_or_else(|| "leased SCM job is absent from its signed capsule".to_owned())?;
        let mut grants = BTreeMap::<String, Vec<Grant>>::new();
        for step in &job.steps {
            for grant in &step.capabilities.secrets {
                if grant.name != "runtrue-scm-provider-token"
                    && (grant.name.is_empty()
                        || grant.name.len() > 128
                        || grant.name == "."
                        || grant.name == ".."
                        || grant.name.bytes().any(|byte| {
                            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                        }))
                {
                    return Err(format!(
                        "secret `{}` cannot be represented as a private runtime file",
                        grant.name
                    ));
                }
                grants.entry(step.id.clone()).or_default().push(Grant {
                    name: grant.name.clone(),
                    metadata_id: grant.metadata_id.clone(),
                    purpose: grant.purpose.clone().unwrap_or_default(),
                });
            }
        }
        if grants.is_empty() {
            return Ok(lifecycle);
        }
        let has_scm_grant = grants
            .values()
            .flatten()
            .any(|grant| grant.name == "runtrue-scm-provider-token");
        if has_scm_grant && (job.permissions.scm.is_denied() || lease.capsule.context.scm.is_none())
        {
            return Err("SCM credential grant lacks signed SCM permissions or context".to_owned());
        }
        Ok(Arc::new(Self {
            binding: Binding {
                execution_lease_id: lease.lease_id.clone(),
                fencing_generation: lease.fencing_generation,
                installation_fencing_epoch: lease.installation_fencing_epoch,
                job_id: lease.job_id.clone(),
                hard_deadline_unix_ms: lease.hard_deadline_unix_ms,
            },
            workspace: workspace.to_owned(),
            client,
            lifecycle,
            grants,
            leases: Mutex::new(BTreeMap::new()),
        }))
    }

    fn release(&self, observation: &StepStateObservation, grant: &Grant) -> Result<(), String> {
        if grant.name != "runtrue-scm-provider-token" {
            return self.release_local_secret(observation, grant);
        }
        let mut scalar = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(scalar.as_mut())
            .map_err(|_| "secure randomness unavailable".to_owned())?;
        let guest_secret = StaticSecret::from(*scalar);
        let guest_public = PublicKey::from(&guest_secret).to_bytes();
        let request = v1::SecretLeaseRequest {
            execution_lease_id: self.binding.execution_lease_id.clone(),
            fencing_generation: self.binding.fencing_generation,
            job_id: self.binding.job_id.clone(),
            step_id: observation.step_id.clone(),
            secret_metadata_id: grant.metadata_id.clone(),
            purpose: grant.purpose.clone(),
            guest_session_key: Some(v1::Digest {
                algorithm: "x25519".to_owned(),
                value: guest_public.to_vec(),
            }),
            job_attempt: observation.job_attempt,
        };
        let response = call_after_running_observation(|| {
            self.client
                .request_secret_lease(request.clone(), BROKER_TIMEOUT)
        })
        .map_err(|error| format!("SCM credential broker request failed: {error}"))?;
        let expires = timestamp_millis(response.expires_at.as_ref(), "SCM credential expiry")
            .map_err(|error| error.to_string())?;
        if expires > self.binding.hard_deadline_unix_ms {
            return Err("SCM credential outlives its execution lease".to_owned());
        }
        let maximum = if grant.name == "runtrue-scm-provider-token" {
            MAX_TOKEN_BYTES
        } else {
            MAX_SECRET_BYTES
        };
        let plaintext = decrypt_envelope(
            &response,
            &guest_secret,
            &SecretEnvelopeBinding {
                execution_lease_id: &self.binding.execution_lease_id,
                fencing_generation: self.binding.fencing_generation,
                installation_fencing_epoch: self.binding.installation_fencing_epoch,
                job_id: &self.binding.job_id,
                job_attempt: observation.job_attempt,
                step_id: &observation.step_id,
                secret_lease_id: &response.secret_lease_id,
                secret_metadata_id: &grant.metadata_id,
                purpose: &grant.purpose,
                expires_unix_ms: expires,
            },
            maximum,
        )
        .map_err(|error| error.to_string())?;
        let plaintext = Zeroizing::new(plaintext);
        let path = if grant.name == "runtrue-scm-provider-token" {
            self.workspace.join(RUNTIME_DIRECTORY).join(TOKEN_FILE)
        } else {
            self.workspace
                .join(RUNTIME_DIRECTORY)
                .join("secrets")
                .join(&grant.name)
        };
        write_private(&path, plaintext.as_slice())?;
        self.leases
            .lock()
            .map_err(|_| "credential lease state unavailable".to_owned())?
            .entry((observation.job_attempt, observation.step_id.clone()))
            .or_default()
            .push((path, response.secret_lease_id));
        Ok(())
    }

    fn release_local_secret(
        &self,
        observation: &StepStateObservation,
        grant: &Grant,
    ) -> Result<(), String> {
        let directory = std::env::var_os("RUNTRUE_RUNNER_SECRET_DIRECTORY")
            .map(PathBuf::from)
            .ok_or_else(|| "runner local secret provider is not configured".to_owned())?;
        let directory_metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("inspect runner secret directory: {error}"))?;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.permissions().mode() & 0o077 != 0
        {
            return Err("runner secret directory must be a private real directory".to_owned());
        }
        let source = directory.join(&grant.name);
        let metadata = fs::symlink_metadata(&source)
            .map_err(|error| format!("inspect declared runner secret `{}`: {error}", grant.name))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_SECRET_BYTES as u64
        {
            return Err(format!(
                "declared runner secret `{}` is not a bounded private regular file",
                grant.name
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        let file = options
            .open(&source)
            .map_err(|error| format!("open declared runner secret `{}`: {error}", grant.name))?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        file.take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut plaintext)
            .map_err(|error| format!("read declared runner secret `{}`: {error}", grant.name))?;
        if plaintext.is_empty() || plaintext.len() > MAX_SECRET_BYTES {
            return Err(format!(
                "declared runner secret `{}` changed size",
                grant.name
            ));
        }
        let path = self
            .workspace
            .join(RUNTIME_DIRECTORY)
            .join("secrets")
            .join(&grant.name);
        write_private(&path, plaintext.as_slice())?;
        self.leases
            .lock()
            .map_err(|_| "credential lease state unavailable".to_owned())?
            .entry((observation.job_attempt, observation.step_id.clone()))
            .or_default()
            .push((path, String::new()));
        Ok(())
    }

    fn revoke(&self, observation: &StepStateObservation) -> Result<(), String> {
        let Some(leases) = self
            .leases
            .lock()
            .map_err(|_| "credential lease state unavailable".to_owned())?
            .remove(&(observation.job_attempt, observation.step_id.clone()))
        else {
            return Ok(());
        };
        let mut first_error = None;
        for (path, secret_lease_id) in leases {
            let _ = fs::remove_file(path);
            if secret_lease_id.is_empty() {
                continue;
            }
            if let Err(error) = self.client.revoke_secret_lease(
                v1::RevokeSecretLeaseRequest {
                    secret_lease_id,
                    execution_lease_id: self.binding.execution_lease_id.clone(),
                    fencing_generation: self.binding.fencing_generation,
                    job_attempt: observation.job_attempt,
                },
                REVOKE_TIMEOUT,
            ) {
                first_error.get_or_insert_with(|| format!("credential revocation failed: {error}"));
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn call_after_running_observation<T>(
    mut operation: impl FnMut() -> Result<T, crate::transport::TransportError>,
) -> Result<T, crate::transport::TransportError> {
    for attempt in 0..MAX_RUNNING_OBSERVATION_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error)
                if error.is_running_step_not_observed()
                    && attempt.saturating_add(1) < MAX_RUNNING_OBSERVATION_ATTEMPTS =>
            {
                let shift = u32::try_from(attempt).unwrap_or(u32::MAX).min(6);
                thread::sleep(Duration::from_millis(10_u64.saturating_mul(1_u64 << shift)));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded SCM broker loop always returns")
}

impl StepStateObserver for ScmCredentialObserver {
    fn observe(&self, observation: &StepStateObservation) -> Result<(), String> {
        let Some(grants) = self.grants.get(&observation.step_id) else {
            return self.lifecycle.observe(observation);
        };
        if observation.from == Some(StepState::Running) && observation.to.is_terminal() {
            let revoke = self.revoke(observation);
            let terminal = self.lifecycle.observe(observation);
            revoke?;
            return terminal;
        }
        self.lifecycle.observe(observation)?;
        if observation.to == StepState::Running {
            for grant in grants {
                if let Err(error) = self.release(observation, grant) {
                    let _ = self.revoke(observation);
                    let failed = StepStateObservation {
                        job_id: observation.job_id.clone(),
                        step_id: observation.step_id.clone(),
                        job_attempt: observation.job_attempt,
                        from: Some(StepState::Running),
                        to: StepState::Failed,
                    };
                    self.lifecycle.observe(&failed)?;
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn credential_release_waits_for_durable_running_observation() {
        let attempts = AtomicUsize::new(0);
        let value = call_after_running_observation(|| {
            let attempt = attempts.fetch_add(1, Ordering::AcqRel);
            if attempt < 2 {
                Err(TransportError::Status {
                    code: tonic::Code::FailedPrecondition,
                    message: "broker request requires the declared step to be currently running"
                        .to_owned(),
                })
            } else {
                Ok("credential")
            }
        })
        .unwrap();

        assert_eq!(value, "credential");
        assert_eq!(attempts.load(Ordering::Acquire), 3);
    }

    #[test]
    fn credential_release_does_not_retry_other_broker_failures() {
        let attempts = AtomicUsize::new(0);
        let error = call_after_running_observation::<()>(|| {
            attempts.fetch_add(1, Ordering::AcqRel);
            Err(TransportError::Status {
                code: tonic::Code::PermissionDenied,
                message: "runner is not authorized".to_owned(),
            })
        })
        .unwrap_err();

        assert!(matches!(
            error,
            TransportError::Status {
                code: tonic::Code::PermissionDenied,
                ..
            }
        ));
        assert_eq!(attempts.load(Ordering::Acquire), 1);
    }
}
