use super::{
    RunnerSession, MAX_CLOCK_SKEW_MS, MAX_IDENTIFIER_BYTES, MAX_INVENTORY_CAPABILITIES,
    MAX_INVENTORY_LABELS, MAX_LIST_ITEMS, MAX_STREAM_MESSAGE_BYTES, OBJECT_TRANSFER_IDLE_TIMEOUT,
};
use crate::runner_certificates::validate_issued_certificate_chain;
use runtrue_attest::CAPSULE_MEDIA_TYPE;
use runtrue_cache::{CacheReadPolicy, CacheSourceTrust, CacheWritePolicy};
use runtrue_control_plane::{RunnerCertificateRotationRecord, SignedCapsuleRecord};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_scheduler::{Lease, RunnerRecord};
use runtrue_workflow_ir::{
    Architecture, CacheRead, CacheWrite, ExecutionCapsule, Isolation, OperatingSystem,
    RunnerRequirements,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use tonic::Status;
pub(super) fn validate_inventory(
    runner: &RunnerRecord,
    inventory: &v1::RunnerInventory,
    hello_protocol_version: u32,
) -> Result<ContentDigest, Status> {
    if inventory.protocol_version != hello_protocol_version {
        return Err(Status::failed_precondition(
            "inventory and RunnerHello protocol versions differ",
        ));
    }
    for (kind, value) in [
        ("hostname", inventory.hostname.as_str()),
        ("inventory operating system", inventory.os.as_str()),
        ("inventory architecture", inventory.architecture.as_str()),
        ("runner version", inventory.runner_version.as_str()),
        ("engine version", inventory.engine_version.as_str()),
    ] {
        validate_bounded_text(kind, value, false)?;
    }
    if inventory.capabilities.len() > MAX_INVENTORY_CAPABILITIES
        || inventory.labels.len() > MAX_INVENTORY_LABELS
        || inventory.isolation_backends.is_empty()
        || inventory.isolation_backends.len() > 16
    {
        return Err(Status::resource_exhausted(
            "runner inventory exceeds its bounds",
        ));
    }
    if inventory.logical_cpus != runner.logical_cpus
        || inventory.memory_bytes != runner.memory_bytes
        || inventory.local_storage_bytes != runner.storage_bytes
        || inventory.os != operating_system_name(runner.os)
        || inventory.architecture != architecture_name(runner.arch)
        || optional_string(&inventory.region) != runner.region.as_deref()
    {
        return Err(Status::failed_precondition(
            "runner inventory does not match its provisioned durable record",
        ));
    }
    let mut isolation = BTreeSet::new();
    for value in &inventory.isolation_backends {
        let parsed = parse_isolation(value)?;
        if !isolation.insert(parsed) {
            return Err(Status::invalid_argument(
                "runner inventory repeats an isolation backend",
            ));
        }
    }
    if isolation != runner.isolation_backends {
        return Err(Status::failed_precondition(
            "runner isolation inventory does not match its provisioned record",
        ));
    }
    let binary_digest = inventory
        .runner_binary_digest
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("runner binary digest is required"))?;
    ContentDigest::try_from(binary_digest)
        .map_err(|_| Status::invalid_argument("runner binary digest is invalid"))?;
    if let Some(image_digest) = &inventory.runner_image_digest {
        ContentDigest::try_from(image_digest)
            .map_err(|_| Status::invalid_argument("runner image digest is invalid"))?;
    }
    for (key, value) in &inventory.labels {
        validate_bounded_text("runner label key", key, false)?;
        validate_bounded_text("runner label value", value, true)?;
    }

    let mut capability_keys = BTreeSet::new();
    let mut capabilities = BTreeMap::new();
    for capability in &inventory.capabilities {
        validate_bounded_text("runner capability key", &capability.key, false)?;
        validate_bounded_text("runner capability value", &capability.json_value, false)?;
        validate_bounded_text(
            "runner capability evidence source",
            &capability.evidence_source,
            false,
        )?;
        if capability.key == "runtrue.posture.digest" {
            // Legacy runners may still send this informational claim. It is
            // intentionally excluded from both enrollment binding and the
            // authoritative posture derived by the server.
            continue;
        }
        if !capability_keys.insert(capability.key.as_str()) {
            return Err(Status::invalid_argument(
                "runner inventory repeats a capability key",
            ));
        }
        capabilities.insert(
            capability.key.clone(),
            (
                capability.json_value.clone(),
                capability.evidence_source.clone(),
            ),
        );
    }
    if capability_keys
        != runner
            .self_reported_capabilities
            .iter()
            .map(String::as_str)
            .collect()
    {
        return Err(Status::failed_precondition(
            "runner capabilities do not match the enrollment inventory",
        ));
    }

    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct InventoryBinding<'a> {
        version: u32,
        hostname: &'a str,
        os: &'a str,
        architecture: &'a str,
        logical_cpus: u32,
        memory_bytes: u64,
        local_storage_bytes: u64,
        isolation_backends: BTreeSet<&'a str>,
        capabilities: BTreeMap<String, (String, String)>,
        runner_binary_digest: String,
        runner_image_digest: Option<String>,
        runner_version: &'a str,
        engine_version: &'a str,
        protocol_version: u32,
        region: &'a str,
        labels: BTreeMap<&'a str, &'a str>,
    }
    let runner_binary_digest = ContentDigest::try_from(binary_digest)
        .map_err(|_| Status::invalid_argument("runner binary digest is invalid"))?
        .to_string();
    let runner_image_digest = inventory
        .runner_image_digest
        .as_ref()
        .map(ContentDigest::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("runner image digest is invalid"))?
        .map(|digest| digest.to_string());
    let binding = InventoryBinding {
        version: 1,
        hostname: &inventory.hostname,
        os: &inventory.os,
        architecture: &inventory.architecture,
        logical_cpus: inventory.logical_cpus,
        memory_bytes: inventory.memory_bytes,
        local_storage_bytes: inventory.local_storage_bytes,
        isolation_backends: inventory
            .isolation_backends
            .iter()
            .map(String::as_str)
            .collect(),
        capabilities,
        runner_binary_digest,
        runner_image_digest,
        runner_version: &inventory.runner_version,
        engine_version: &inventory.engine_version,
        protocol_version: inventory.protocol_version,
        region: &inventory.region,
        labels: inventory
            .labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect(),
    };
    let bytes = serde_json::to_vec(&binding)
        .map_err(|_| Status::internal("runner inventory binding could not be encoded"))?;
    Ok(ContentDigest::sha256(bytes))
}

pub(super) fn lease_offer(
    lease: &Lease,
    hard_deadline_unix_ms: u64,
    job_key: &str,
    signed_capsule: &SignedCapsuleRecord,
    posture_digest: &ContentDigest,
) -> Result<v1::LeaseOffer, Status> {
    validate_capsule_binding(lease, signed_capsule)?;
    validate_identifier_status("capsule job key", job_key)?;
    let capsule: ExecutionCapsule = serde_json::from_slice(&signed_capsule.canonical_capsule)
        .map_err(|_| Status::internal("durable execution capsule is invalid"))?;
    let job = capsule
        .jobs
        .iter()
        .find(|job| job.id == job_key)
        .ok_or_else(|| Status::internal("durable lease job is absent from its signed capsule"))?;
    Ok(v1::LeaseOffer {
        lease_id: lease.id.clone(),
        job_id: job_key.to_owned(),
        runner_id: lease.runner_id.clone(),
        fencing_generation: lease.fencing_generation,
        installation_fencing_epoch: lease.installation_fencing_epoch,
        capsule_digest: Some(
            v1::Digest::try_from(&lease.capsule_digest)
                .map_err(|_| Status::internal("durable lease capsule digest is invalid"))?,
        ),
        capsule_signature: signed_capsule.signature.signature.clone(),
        capsule_signing_key_id: signed_capsule.signature.key_id.to_string(),
        issued_at: Some(proto_timestamp(lease.issued_unix_ms)),
        accept_by: Some(proto_timestamp(lease.accept_by_unix_ms)),
        expires_at: Some(proto_timestamp(lease.expires_unix_ms)),
        requirements: Some(wire_requirements(&job.runner, posture_digest)?),
        secret_broker_audience: String::new(),
        hard_deadline: Some(proto_timestamp(hard_deadline_unix_ms)),
    })
}

pub(super) fn rotation_response(
    record: &RunnerCertificateRotationRecord,
) -> Result<v1::RotateCertificateResponse, Status> {
    validate_issued_certificate_chain(&record.certificate_chain_pem, &record.new_certificate)
        .map_err(|_| Status::internal("durable runner rotation chain is invalid"))?;
    Ok(v1::RotateCertificateResponse {
        certificate_chain_pem: record.certificate_chain_pem.clone(),
        certificate_expires_at: Some(proto_timestamp(record.new_certificate.not_after_unix_ms)),
        csr_digest: Some(
            v1::Digest::try_from(&record.csr_digest)
                .map_err(|_| Status::internal("rotation CSR digest is invalid"))?,
        ),
        certificate_fingerprint: Some(
            v1::Digest::try_from(&record.new_certificate.fingerprint)
                .map_err(|_| Status::internal("rotated certificate fingerprint is invalid"))?,
        ),
    })
}

pub(super) fn wire_requirements(
    requirements: &RunnerRequirements,
    posture_digest: &ContentDigest,
) -> Result<v1::RunnerRequirements, Status> {
    let mut capabilities = requirements.capabilities.clone();
    capabilities.sort();
    capabilities.dedup();
    Ok(v1::RunnerRequirements {
        os: operating_system_name(requirements.os).to_owned(),
        architecture: architecture_name(requirements.arch).to_owned(),
        isolation_floor: isolation_name(requirements.isolation).to_owned(),
        cpu: u32::from(requirements.cpu),
        memory_bytes: requirements.memory_bytes,
        storage_bytes: requirements.storage_bytes.unwrap_or_default(),
        region: requirements.region.clone().unwrap_or_default(),
        required_capabilities: capabilities,
        posture_digest: Some(
            v1::Digest::try_from(posture_digest)
                .map_err(|_| Status::internal("runner posture digest is invalid"))?,
        ),
    })
}

pub(super) fn fetch_capsule_response(
    signed_capsule: SignedCapsuleRecord,
) -> Result<v1::FetchExecutionCapsuleResponse, Status> {
    Ok(v1::FetchExecutionCapsuleResponse {
        canonical_capsule: signed_capsule.canonical_capsule,
        digest: Some(
            v1::Digest::try_from(&signed_capsule.digest)
                .map_err(|_| Status::internal("durable capsule digest is invalid"))?,
        ),
        signature: signed_capsule.signature.signature,
        signing_key_id: signed_capsule.signature.key_id.to_string(),
        media_type: CAPSULE_MEDIA_TYPE.to_owned(),
    })
}

pub(super) fn validate_capsule_binding(
    lease: &Lease,
    capsule: &SignedCapsuleRecord,
) -> Result<(), Status> {
    if lease.capsule_digest != capsule.digest
        || capsule.signature.capsule_digest != capsule.digest
        || ContentDigest::sha256(&capsule.canonical_capsule) != capsule.digest
        || capsule.signature.media_type != CAPSULE_MEDIA_TYPE
    {
        return Err(Status::internal(
            "durable lease and signed capsule binding is inconsistent",
        ));
    }
    Ok(())
}

pub(super) fn require_session_protocol(
    session: &RunnerSession,
    minimum: u32,
) -> Result<(), Status> {
    if session.protocol_version < minimum {
        return Err(Status::failed_precondition(
            "RPC requires a newer negotiated runner protocol generation",
        ));
    }
    Ok(())
}

pub(super) fn require_session_lease(
    session: &RunnerSession,
    lease_id: &str,
    generation: u64,
    accepted: bool,
) -> Result<(), Status> {
    let state = session.state()?;
    let known = if accepted {
        state.accepted.get(lease_id)
    } else {
        state.offered.get(lease_id)
    };
    if known != Some(&generation) {
        return Err(Status::permission_denied(
            "lease does not belong to this runner connection",
        ));
    }
    Ok(())
}

pub(super) fn validate_runner_message_identity(
    session: &RunnerSession,
    runner_id: &str,
) -> Result<(), Status> {
    validate_identifier_status("runner id", runner_id)?;
    if runner_id != session.runner_id {
        return Err(Status::permission_denied(
            "stream message belongs to another runner",
        ));
    }
    Ok(())
}

pub(super) fn validate_locality(
    locality: &v1::LocalitySummary,
) -> Result<BTreeSet<ContentDigest>, Status> {
    if locality.tenant_scoped_bloom_filter.len() > MAX_STREAM_MESSAGE_BYTES / 2
        || locality.public_content_bloom_filter.len() > MAX_STREAM_MESSAGE_BYTES / 2
        || locality.classes.len() > MAX_LIST_ITEMS
        || locality.content_digests.len() > MAX_LIST_ITEMS
    {
        return Err(Status::resource_exhausted(
            "runner locality summary exceeds its bounds",
        ));
    }
    validate_observed_timestamp(locality.generated_at.as_ref(), now_unix_ms()?)?;
    for class in &locality.classes {
        validate_bounded_text("locality class", &class.kind, false)?;
    }
    let digests = locality
        .content_digests
        .iter()
        .map(ContentDigest::try_from)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| Status::invalid_argument("runner locality digest is invalid"))?;
    if digests.len() != locality.content_digests.len() {
        return Err(Status::invalid_argument(
            "runner locality contains duplicate digests",
        ));
    }
    Ok(digests)
}

pub(super) fn validate_health(health: &v1::RunnerHealth) -> Result<(), Status> {
    if !health.cpu_load.is_finite()
        || health.cpu_load.is_sign_negative()
        || health.warnings.len() > MAX_LIST_ITEMS
    {
        return Err(Status::invalid_argument("invalid runner health sample"));
    }
    for warning in &health.warnings {
        validate_bounded_text("runner health warning", warning, false)?;
    }
    Ok(())
}

pub(super) fn validate_active_state(value: &str) -> Result<(), Status> {
    if matches!(value, "preparing" | "running" | "finalizing" | "canceling") {
        Ok(())
    } else {
        Err(Status::invalid_argument("invalid active lease state"))
    }
}

pub(super) fn validate_bounded_identifiers(
    kind: &'static str,
    values: &[String],
) -> Result<(), Status> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(Status::resource_exhausted(
            "identifier list exceeds its bound",
        ));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_identifier_status(kind, value)?;
        if !seen.insert(value) {
            return Err(Status::invalid_argument(
                "identifier list contains duplicates",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_identifier_status(kind: &'static str, value: &str) -> Result<(), Status> {
    validate_bounded_text(kind, value, false)
}

pub(super) fn validate_bounded_text(
    kind: &'static str,
    value: &str,
    allow_empty: bool,
) -> Result<(), Status> {
    if (!allow_empty && value.is_empty())
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Status::invalid_argument(format!("invalid {kind}")));
    }
    Ok(())
}

pub(super) fn validate_observed_timestamp(
    value: Option<&prost_types::Timestamp>,
    server_now_unix_ms: u64,
) -> Result<u64, Status> {
    let observed = timestamp_millis(value)?;
    let skew = observed.abs_diff(server_now_unix_ms);
    if skew > MAX_CLOCK_SKEW_MS {
        return Err(Status::failed_precondition(
            "runner timestamp is outside the allowed clock skew",
        ));
    }
    Ok(observed)
}

pub(super) fn timestamp_millis(value: Option<&prost_types::Timestamp>) -> Result<u64, Status> {
    let value = value.ok_or_else(|| Status::invalid_argument("timestamp is required"))?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(Status::invalid_argument("timestamp is invalid"));
    }
    u64::try_from(value.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|millis| millis.checked_add(u64::from(value.nanos as u32) / 1_000_000))
        .ok_or_else(|| Status::out_of_range("timestamp is outside the supported range"))
}

pub(super) fn proto_timestamp(unix_ms: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX),
        nanos: i32::try_from((unix_ms % 1000).saturating_mul(1_000_000)).unwrap_or(999_000_000),
    }
}

pub(super) fn proto_duration(duration: Duration) -> Result<prost_types::Duration, Status> {
    Ok(prost_types::Duration {
        seconds: i64::try_from(duration.as_secs())
            .map_err(|_| Status::out_of_range("duration is outside the supported range"))?,
        nanos: i32::try_from(duration.subsec_nanos())
            .map_err(|_| Status::out_of_range("duration is outside the supported range"))?,
    })
}

pub(super) fn duration_millis(duration: Duration) -> Result<u64, Status> {
    u64::try_from(duration.as_millis())
        .map_err(|_| Status::out_of_range("duration is outside the supported range"))
}

pub(super) fn runner_upload_wait_until(deadline: Instant) -> Result<Duration, Status> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(Status::deadline_exceeded(
            "blob upload absolute deadline expired",
        ))
    } else {
        Ok(OBJECT_TRANSFER_IDLE_TIMEOUT.min(remaining))
    }
}

pub(super) fn now_unix_ms() -> Result<u64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| Status::internal("system clock is outside the supported range"))
}

pub(super) fn cache_source_trust(
    capsule: &ExecutionCapsule,
    _repository: &runtrue_control_plane::RepositoryRecord,
) -> CacheSourceTrust {
    match capsule.context.source_trust {
        runtrue_workflow_ir::SourceTrust::Untrusted => CacheSourceTrust::UntrustedChange {
            // A signed normalized-event identity is safer than accepting a
            // runner-selected change number. It may reduce reuse, but never
            // broadens trust when no stable change id is in the signed capsule.
            change_id: format!("event-{}", capsule.context.normalized_event_digest),
        },
        runtrue_workflow_ir::SourceTrust::Trusted => {
            let branch = capsule
                .context
                .event_context
                .get("event.ref")
                .and_then(|value| match value {
                    runtrue_workflow_ir::ScalarValue::String(value) => Some(value.as_str()),
                    _ => None,
                })
                .and_then(|value| value.strip_prefix("refs/heads/"))
                .filter(|value| !value.is_empty())
                // Missing signed branch data fails closed to exact-commit
                // scope instead of guessing the repository default branch.
                .map_or_else(
                    || format!("exact-commit-{}", capsule.context.source_commit),
                    ToOwned::to_owned,
                );
            CacheSourceTrust::TrustedBranch { branch }
        }
        runtrue_workflow_ir::SourceTrust::ProtectedBranch => CacheSourceTrust::ProtectedMain,
    }
}

pub(super) const fn cache_read_policy(value: CacheRead) -> CacheReadPolicy {
    match value {
        CacheRead::Deny => CacheReadPolicy::Deny,
        CacheRead::Public => CacheReadPolicy::Public,
        CacheRead::Verified => CacheReadPolicy::Verified,
        CacheRead::Branch => CacheReadPolicy::Branch,
        CacheRead::Run => CacheReadPolicy::Run,
    }
}

pub(super) const fn cache_write_policy(value: CacheWrite) -> CacheWritePolicy {
    match value {
        CacheWrite::Deny => CacheWritePolicy::Deny,
        CacheWrite::Quarantine => CacheWritePolicy::Quarantine,
        CacheWrite::Branch => CacheWritePolicy::Branch,
        CacheWrite::Verified => CacheWritePolicy::Verified,
    }
}

pub(super) const fn operating_system_name(value: OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Macos => "macos",
    }
}

pub(super) const fn architecture_name(value: Architecture) -> &'static str {
    match value {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}

pub(super) const fn isolation_name(value: Isolation) -> &'static str {
    match value {
        Isolation::Wasm => "wasm",
        Isolation::Oci => "oci",
        Isolation::Microvm => "microvm",
        Isolation::Native => "native",
    }
}

pub(super) fn parse_isolation(value: &str) -> Result<Isolation, Status> {
    match value {
        "wasm" => Ok(Isolation::Wasm),
        "oci" => Ok(Isolation::Oci),
        "microvm" => Ok(Isolation::Microvm),
        "native" => Ok(Isolation::Native),
        _ => Err(Status::invalid_argument(
            "runner inventory contains an unknown isolation backend",
        )),
    }
}

pub(super) fn optional_string(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

pub(super) fn parse_guest_session_key(value: Option<&v1::Digest>) -> Result<[u8; 32], Status> {
    let value = value
        .ok_or_else(|| Status::invalid_argument("guest session X25519 public key is required"))?;
    if value.algorithm != "x25519" {
        return Err(Status::invalid_argument(
            "guest session key algorithm must be x25519, not a content digest",
        ));
    }
    value
        .value
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("guest session X25519 key must be exactly 32 bytes"))
}

pub(super) fn canonical_json<T>(bytes: &[u8], kind: &'static str) -> Result<T, Status>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_STREAM_MESSAGE_BYTES {
        return Err(Status::invalid_argument(format!(
            "{kind} is empty or oversized"
        )));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| Status::invalid_argument(format!("{kind} JSON is invalid")))?;
    if serde_json::to_vec(&value).ok().as_deref() != Some(bytes) {
        return Err(Status::invalid_argument(format!(
            "{kind} JSON is noncanonical"
        )));
    }
    Ok(value)
}
