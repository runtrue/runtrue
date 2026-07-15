pub fn probe_inventory(
    runner_id: &str,
    workspace_root: &Path,
    region: Option<String>,
) -> Result<VerifiedInventory, InventoryError> {
    probe_inventory_with_backends(
        runner_id,
        workspace_root,
        region,
        BTreeSet::from([Isolation::Native]),
    )
}

pub fn probe_inventory_with_backends(
    runner_id: &str,
    workspace_root: &Path,
    region: Option<String>,
    isolation_backends: BTreeSet<Isolation>,
) -> Result<VerifiedInventory, InventoryError> {
    probe_inventory_with_backends_for_protocol(
        runner_id,
        workspace_root,
        region,
        isolation_backends,
        PROTOCOL_MAX,
    )
}

/// Probe the same verified inventory for one already-selected generation.
/// Selection comes from enrollment credentials or explicit direct-credential
/// configuration; probing never guesses based on a remote endpoint.
pub fn probe_inventory_with_backends_for_protocol(
    runner_id: &str,
    workspace_root: &Path,
    region: Option<String>,
    isolation_backends: BTreeSet<Isolation>,
    protocol_version: u32,
) -> Result<VerifiedInventory, InventoryError> {
    negotiate_protocol_version(protocol_version, protocol_version)?;
    let (os, os_name) = operating_system()?;
    let (architecture, architecture_name) = architecture()?;
    let logical_cpus = u32::try_from(
        std::thread::available_parallelism()
            .map_err(InventoryError::Parallelism)?
            .get(),
    )
    .map_err(|_| InventoryError::CapacityOverflow("logical CPU count"))?;
    let memory_bytes = probe_memory_bytes()?;
    let storage_bytes = probe_storage_bytes(workspace_root)?;
    let current_executable = std::env::current_exe().map_err(InventoryError::CurrentExecutable)?;
    let binary_digest = digest_file(&current_executable, MAX_BINARY_BYTES)?;
    let hostname = probe_hostname()?;

    #[derive(Serialize)]
    struct Posture<'a> {
        runner_id: &'a str,
        os: &'a str,
        architecture: &'a str,
        logical_cpus: u32,
        memory_bytes: u64,
        storage_bytes: u64,
        isolation_backends: &'a [&'static str],
        runner_binary_digest: &'a str,
        runner_version: &'static str,
        protocol_version: u32,
        region: &'a Option<String>,
    }

    let backend_names = isolation_backends
        .iter()
        .copied()
        .map(isolation_backend_name)
        .collect::<Result<Vec<_>, _>>()?;
    let posture = Posture {
        runner_id,
        os: os_name,
        architecture: architecture_name,
        logical_cpus,
        memory_bytes,
        storage_bytes,
        isolation_backends: &backend_names,
        runner_binary_digest: binary_digest.as_str(),
        runner_version: env!("CARGO_PKG_VERSION"),
        protocol_version,
        region: &region,
    };
    let posture_digest = ContentDigest::sha256(
        serde_json::to_vec(&posture).map_err(InventoryError::PostureEncoding)?,
    );
    let profile = VerifiedRunnerProfile {
        runner_id: runner_id.to_owned(),
        os,
        architecture,
        logical_cpus,
        memory_bytes,
        storage_bytes,
        isolation_backends: isolation_backends.clone(),
        capabilities: BTreeSet::new(),
        region: region.clone(),
        posture_digest: posture_digest.clone(),
    };
    profile.validate()?;

    let wire = v1::RunnerInventory {
        hostname,
        os: os_name.to_owned(),
        architecture: architecture_name.to_owned(),
        logical_cpus,
        memory_bytes,
        local_storage_bytes: storage_bytes,
        isolation_backends: backend_names
            .iter()
            .map(|backend| (*backend).to_owned())
            .collect(),
        capabilities: vec![v1::Capability {
            key: "runtrue.posture.digest".to_owned(),
            json_value: serde_json::to_string(posture_digest.as_str())
                .map_err(InventoryError::PostureEncoding)?,
            evidence_source: "local-probe".to_owned(),
        }],
        runner_binary_digest: Some(v1::Digest::try_from(&binary_digest)?),
        // A host-installed runner has no enclosing OCI image. Bind the same
        // immutable executable digest as its deployment image identity so the
        // control plane can carry one non-optional provenance subject.
        runner_image_digest: Some(v1::Digest::try_from(&binary_digest)?),
        runner_version: env!("CARGO_PKG_VERSION").to_owned(),
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version,
        region: region.unwrap_or_default(),
        labels: Default::default(),
    };
    Ok(VerifiedInventory {
        profile,
        wire,
        binary_digest,
    })
}

pub(super) fn isolation_backend_name(isolation: Isolation) -> Result<&'static str, InventoryError> {
    match isolation {
        Isolation::Native => Ok("native"),
        Isolation::Oci => Ok("oci"),
        Isolation::Wasm => Ok("wasm"),
        Isolation::Microvm => Ok("microvm"),
    }
}

fn operating_system() -> Result<(OperatingSystem, &'static str), InventoryError> {
    match std::env::consts::OS {
        "linux" => Ok((OperatingSystem::Linux, "linux")),
        "windows" => Ok((OperatingSystem::Windows, "windows")),
        "macos" => Ok((OperatingSystem::Macos, "macos")),
        value => Err(InventoryError::UnsupportedPlatform(value.to_owned())),
    }
}

fn architecture() -> Result<(Architecture, &'static str), InventoryError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok((Architecture::Amd64, "amd64")),
        "aarch64" => Ok((Architecture::Arm64, "arm64")),
        value => Err(InventoryError::UnsupportedArchitecture(value.to_owned())),
    }
}

fn probe_memory_bytes() -> Result<u64, InventoryError> {
    #[cfg(target_os = "linux")]
    {
        let value = read_bounded_public_file(Path::new("/proc/meminfo"), MAX_PROC_FILE_BYTES)?;
        let text = std::str::from_utf8(&value).map_err(|_| InventoryError::InvalidMemoryProbe)?;
        let kibibytes = text
            .lines()
            .find_map(|line| {
                let mut fields = line.split_ascii_whitespace();
                (fields.next() == Some("MemTotal:"))
                    .then(|| fields.next()?.parse::<u64>().ok())
                    .flatten()
            })
            .ok_or(InventoryError::InvalidMemoryProbe)?;
        kibibytes
            .checked_mul(1024)
            .ok_or(InventoryError::CapacityOverflow("memory bytes"))
    }
    #[cfg(not(target_os = "linux"))]
    Err(InventoryError::UnsupportedProbe("memory"))
}

fn probe_hostname() -> Result<String, InventoryError> {
    #[cfg(unix)]
    {
        let bytes = read_bounded_public_file(Path::new("/etc/hostname"), 4096)?;
        let hostname = std::str::from_utf8(&bytes)
            .map_err(|_| InventoryError::InvalidHostname)?
            .trim();
        if hostname.is_empty()
            || hostname.len() > 255
            || hostname.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(InventoryError::InvalidHostname);
        }
        Ok(hostname.to_owned())
    }
    #[cfg(not(unix))]
    Err(InventoryError::UnsupportedProbe("hostname"))
}

fn read_bounded_public_file(path: &Path, maximum: u64) -> Result<Vec<u8>, InventoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(InventoryError::UnsafeProbePath(path.to_owned()));
    }
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > maximum {
        return Err(InventoryError::UnsafeProbePath(path.to_owned()));
    }
    Ok(bytes)
}

fn digest_file(path: &Path, maximum: u64) -> Result<ContentDigest, InventoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(InventoryError::UnsafeExecutable(path.to_owned()));
    }
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut hasher = Sha256::new();
    let copied = io::copy(&mut file.by_ref().take(maximum + 1), &mut hasher)
        .map_err(|source| io_error(path, source))?;
    if copied == 0 || copied > maximum {
        return Err(InventoryError::UnsafeExecutable(path.to_owned()));
    }
    ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|_| InventoryError::UnsafeExecutable(path.to_owned()))
}
use super::{error::io_error, storage::probe_storage_bytes, InventoryError, VerifiedInventory};
use runtrue_model::ContentDigest;
use runtrue_protocol::{negotiate_protocol_version, v1, PROTOCOL_MAX};
use runtrue_runner_core::VerifiedRunnerProfile;
use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read as _},
    path::Path,
};

const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PROC_FILE_BYTES: u64 = 1024 * 1024;
