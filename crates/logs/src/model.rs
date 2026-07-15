#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseBinding {
    pub run_id: String,
    pub job_id: String,
    pub lease_id: String,
    pub fencing_generation: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LogInputFrame {
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub lease_id: String,
    pub fencing_generation: u64,
    pub stream: LogStream,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl fmt::Debug for LogInputFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogInputFrame")
            .field("run_id", &self.run_id)
            .field("job_id", &self.job_id)
            .field("step_id", &self.step_id)
            .field("lease_id", &self.lease_id)
            .field("fencing_generation", &self.fencing_generation)
            .field("stream", &self.stream)
            .field("sequence", &self.sequence)
            .field("payload_bytes", &self.payload.len())
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl Drop for LogInputFrame {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub enum LogPayload {
    Utf8 { data: String },
    Base64 { data: String, decoded_bytes: usize },
}

impl LogPayload {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(value) => Self::Utf8 {
                data: value.to_owned(),
            },
            Err(_) => Self::Base64 {
                data: Base64::encode_string(bytes),
                decoded_bytes: bytes.len(),
            },
        }
    }

    pub fn decode(&self) -> Result<Vec<u8>, LogError> {
        match self {
            Self::Utf8 { data } => Ok(data.as_bytes().to_vec()),
            Self::Base64 {
                data,
                decoded_bytes,
            } => {
                let bytes = Base64::decode_vec(data)
                    .map_err(|_| LogError::Integrity("invalid binary log encoding".to_owned()))?;
                if bytes.len() != *decoded_bytes {
                    return Err(LogError::Integrity(
                        "binary log length does not match its encoding".to_owned(),
                    ));
                }
                Ok(bytes)
            }
        }
    }

    pub(crate) fn byte_len(&self) -> usize {
        match self {
            Self::Utf8 { data } => data.len(),
            Self::Base64 { decoded_bytes, .. } => *decoded_bytes,
        }
    }
}

impl fmt::Debug for LogPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogPayload")
            .field(
                "encoding",
                &match self {
                    Self::Utf8 { .. } => "utf8",
                    Self::Base64 { .. } => "base64",
                },
            )
            .field("decoded_bytes", &self.byte_len())
            .field("data", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncationScope {
    Frame,
    Line,
    Step,
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredFrameKind {
    Data,
    Truncation { scope: TruncationScope },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredLogFrame {
    pub journal_index: u64,
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub lease_id: String,
    pub fencing_generation: u64,
    pub stream: LogStream,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<u64>,
    pub payload: LogPayload,
    pub redacted: bool,
    pub truncated: bool,
    pub frame_kind: StoredFrameKind,
}

impl fmt::Debug for StoredLogFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredLogFrame")
            .field("journal_index", &self.journal_index)
            .field("run_id", &self.run_id)
            .field("job_id", &self.job_id)
            .field("step_id", &self.step_id)
            .field("lease_id", &self.lease_id)
            .field("fencing_generation", &self.fencing_generation)
            .field("stream", &self.stream)
            .field("source_sequence", &self.source_sequence)
            .field("payload", &self.payload)
            .field("redacted", &self.redacted)
            .field("truncated", &self.truncated)
            .field("frame_kind", &self.frame_kind)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    Bound,
    AlreadyBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishOutcome {
    Finished,
    AlreadyFinished,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamKey {
    pub(crate) run_id: String,
    pub(crate) job_id: String,
    pub(crate) step_id: String,
    pub(crate) lease_id: String,
    pub(crate) fencing_generation: u64,
    pub(crate) stream: LogStream,
}

impl StreamKey {
    pub(crate) fn from_input(frame: &LogInputFrame) -> Self {
        Self {
            run_id: frame.run_id.clone(),
            job_id: frame.job_id.clone(),
            step_id: frame.step_id.clone(),
            lease_id: frame.lease_id.clone(),
            fencing_generation: frame.fencing_generation,
            stream: frame.stream,
        }
    }

    pub(crate) fn step_key(&self) -> StepKey {
        StepKey {
            run_id: self.run_id.clone(),
            job_id: self.job_id.clone(),
            step_id: self.step_id.clone(),
            lease_id: self.lease_id.clone(),
            fencing_generation: self.fencing_generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StepKey {
    pub(crate) run_id: String,
    pub(crate) job_id: String,
    pub(crate) step_id: String,
    pub(crate) lease_id: String,
    pub(crate) fencing_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LeaseKey {
    pub(crate) run_id: String,
    pub(crate) job_id: String,
}
use crate::LogError;
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize as _;
