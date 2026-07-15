use crate::{RunnerAdmissionError, VerifiedRunnerProfile};
use prost_types::Timestamp;
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem, RunnerRequirements};

const MAX_WIRE_IDENTIFIER_BYTES: usize = 1024;

pub(crate) fn validate_wire_requirements(
    wire: &v1::RunnerRequirements,
    planned: &RunnerRequirements,
    profile: &VerifiedRunnerProfile,
) -> Result<(), RunnerAdmissionError> {
    let planned_os = os_name(planned.os);
    let planned_arch = architecture_name(planned.arch);
    let planned_isolation = isolation_name(planned.isolation);
    let mut planned_capabilities = planned.capabilities.clone();
    planned_capabilities.sort();
    planned_capabilities.dedup();
    let planned_region = planned.region.as_deref().unwrap_or_default();
    let planned_storage = planned.storage_bytes.unwrap_or_default();
    let posture = required_digest(wire.posture_digest.as_ref(), "runner posture digest")?;

    if wire.os != planned_os
        || wire.architecture != planned_arch
        || wire.isolation_floor != planned_isolation
        || wire.cpu != u32::from(planned.cpu)
        || wire.memory_bytes != planned.memory_bytes
        || wire.storage_bytes != planned_storage
        || wire.region != planned_region
        || wire.required_capabilities != planned_capabilities
        || posture != profile.posture_digest
    {
        return Err(RunnerAdmissionError::RequirementsDoNotMatchCapsule);
    }

    if profile.os != planned.os
        || profile.architecture != planned.arch
        || profile.logical_cpus < u32::from(planned.cpu)
        || profile.memory_bytes < planned.memory_bytes
        || profile.storage_bytes < planned_storage
        || !profile.isolation_backends.contains(&planned.isolation)
        || !planned_capabilities
            .iter()
            .all(|capability| profile.capabilities.contains(capability))
        || planned
            .region
            .as_ref()
            .is_some_and(|region| profile.region.as_ref() != Some(region))
    {
        return Err(RunnerAdmissionError::VerifiedProfileCannotSatisfyCapsule);
    }
    Ok(())
}

pub(crate) const fn os_name(value: OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Macos => "macos",
    }
}

pub(crate) const fn architecture_name(value: Architecture) -> &'static str {
    match value {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}

pub(crate) const fn isolation_name(value: Isolation) -> &'static str {
    match value {
        Isolation::Wasm => "wasm",
        Isolation::Oci => "oci",
        Isolation::Microvm => "microvm",
        Isolation::Native => "native",
    }
}

pub(crate) fn required_digest(
    digest: Option<&v1::Digest>,
    field: &'static str,
) -> Result<ContentDigest, RunnerAdmissionError> {
    let digest = digest.ok_or(RunnerAdmissionError::MissingDigest(field))?;
    ContentDigest::try_from(digest).map_err(RunnerAdmissionError::WireDigest)
}

pub(crate) fn timestamp_millis(
    timestamp: Option<&Timestamp>,
    field: &'static str,
) -> Result<u64, RunnerAdmissionError> {
    let timestamp = timestamp.ok_or(RunnerAdmissionError::MissingTimestamp(field))?;
    if timestamp.seconds < 0 || !(0..1_000_000_000).contains(&timestamp.nanos) {
        return Err(RunnerAdmissionError::InvalidTimestamp(field));
    }
    let seconds = u64::try_from(timestamp.seconds)
        .map_err(|_| RunnerAdmissionError::InvalidTimestamp(field))?;
    seconds
        .checked_mul(1000)
        .and_then(|millis| millis.checked_add(u64::from(timestamp.nanos as u32) / 1_000_000))
        .ok_or(RunnerAdmissionError::InvalidTimestamp(field))
}

pub(crate) fn validate_identifier(
    kind: &'static str,
    value: &str,
) -> Result<(), RunnerAdmissionError> {
    if value.is_empty()
        || value.len() > MAX_WIRE_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(RunnerAdmissionError::InvalidIdentifier(kind));
    }
    Ok(())
}
