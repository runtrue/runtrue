use crate::StepSignal;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestEvent {
    Hello {
        guest_image_digest: ContentDigest,
        capsule_digest: ContentDigest,
        lease_id: String,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
    },
    JobAccepted {
        job_id: String,
    },
    MountAccepted {
        mount_id: String,
    },
    StepReady {
        step_id: String,
        attempt: u32,
    },
    SignalAcknowledged {
        step_id: String,
        signal: StepSignal,
    },
    StepResult(GuestStepResult),
    LogFrame(LogFrame),
    ResourceSample(ResourceSample),
    JobResult {
        job_id: String,
        succeeded: bool,
    },
    ShutdownReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestStepResult {
    pub step_id: String,
    pub attempt: u32,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub canceled: bool,
    pub skipped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
    System,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogFrame {
    pub step_id: String,
    pub stream: LogStream,
    pub sequence: u64,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for LogFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogFrame")
            .field("step_id", &self.step_id)
            .field("stream", &self.stream)
            .field("sequence", &self.sequence)
            .field(
                "bytes",
                &format_args!("<redacted:{} bytes>", self.bytes.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSample {
    pub step_id: String,
    pub monotonic_ms: u64,
    pub cpu_time_ms: u64,
    pub resident_memory_bytes: u64,
    pub read_bytes: u64,
    pub written_bytes: u64,
}
