use super::{error::RunnerError, executor::JobExecution};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MIN_HEARTBEAT_MILLIS: u64 = 100;
const MAX_HEARTBEAT_MILLIS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy)]
pub(super) struct ServerClock {
    offset_millis: i128,
}

impl ServerClock {
    pub(super) fn new(local_unix_ms: u64, server_unix_ms: u64) -> Result<Self, RunnerError> {
        Ok(Self {
            offset_millis: i128::from(server_unix_ms) - i128::from(local_unix_ms),
        })
    }

    pub(super) fn now(self) -> Result<u64, RunnerError> {
        let adjusted = i128::from(now_unix_ms()?) + self.offset_millis;
        u64::try_from(adjusted).map_err(|_| RunnerError::ClockRange)
    }
}

pub(super) fn deadline_instant(
    clock: &ServerClock,
    server_deadline_unix_ms: u64,
    safety_margin_millis: u64,
) -> Result<tokio::time::Instant, RunnerError> {
    let remaining = server_deadline_unix_ms
        .checked_sub(clock.now()?)
        .and_then(|remaining| remaining.checked_sub(safety_margin_millis))
        .filter(|remaining| *remaining > 0)
        .ok_or(RunnerError::DeadlineElapsed)?;
    tokio::time::Instant::now()
        .checked_add(Duration::from_millis(remaining))
        .ok_or(RunnerError::ClockRange)
}

pub(super) async fn wait_until(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

pub(super) fn failed_execution_outcome(job_attempt: u32) -> JobExecution {
    #[derive(Serialize)]
    struct FailedResult {
        state: &'static str,
        error_code: &'static str,
    }
    let encoded = serde_json::to_vec(&FailedResult {
        state: "failed",
        error_code: "runner_execution_error",
    })
    .expect("static failed outcome serializes");
    JobExecution {
        final_state: "failed".to_owned(),
        exit_code: None,
        error_code: "runner_execution_error".to_owned(),
        result_digest: ContentDigest::sha256(encoded),
        log_frames: Vec::new(),
        final_job_attempt: job_attempt,
        artifact_ids: Vec::new(),
        cache_entry_ids: Vec::new(),
        credential_taint: runtrue_engine::CredentialTaint::None,
    }
}

pub(super) fn duration(value: Option<&prost_types::Duration>) -> Result<Duration, RunnerError> {
    let value = value.ok_or(RunnerError::InvalidHeartbeatInterval)?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(RunnerError::InvalidHeartbeatInterval);
    }
    let millis = u64::try_from(value.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|millis| millis.checked_add(u64::from(value.nanos as u32) / 1_000_000))
        .ok_or(RunnerError::InvalidHeartbeatInterval)?;
    if !(MIN_HEARTBEAT_MILLIS..=MAX_HEARTBEAT_MILLIS).contains(&millis) {
        return Err(RunnerError::InvalidHeartbeatInterval);
    }
    Ok(Duration::from_millis(millis))
}

pub(super) fn timestamp_millis(value: Option<&prost_types::Timestamp>) -> Result<u64, RunnerError> {
    let value = value.ok_or(RunnerError::InvalidServerTime)?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(RunnerError::InvalidServerTime);
    }
    u64::try_from(value.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|millis| millis.checked_add(u64::from(value.nanos as u32) / 1_000_000))
        .ok_or(RunnerError::InvalidServerTime)
}

pub(super) fn timestamp(unix_ms: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX),
        nanos: i32::try_from((unix_ms % 1000) * 1_000_000).unwrap_or(999_000_000),
    }
}

pub(super) fn now_unix_ms() -> Result<u64, RunnerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(RunnerError::ClockRange)
}

pub(super) fn random_connection_id() -> Result<String, RunnerError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| RunnerError::RandomnessUnavailable)?;
    Ok(format!("connection-{}", hex::encode(bytes)))
}

pub(super) fn validate_runner_id(value: &str) -> Result<(), RunnerError> {
    if value.is_empty() || value.len() > 1024 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(RunnerError::InvalidRunnerId);
    }
    Ok(())
}
