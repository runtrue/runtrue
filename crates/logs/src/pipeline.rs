//! Structured, lease-fenced, redacted, bounded log persistence.
//!
//! The journal never contains raw input chunks. It records a digest for exact
//! replay detection and output only after streaming redaction. Redaction keeps
//! every suffix that could begin a registered secret until the next chunk, so
//! a canary split across arbitrary frame boundaries cannot leak.

use crate::{
    journal::{input_digest, journal_hash, verify_journal, JournalEnvelope, JournalEvent},
    limits::LineLimiter,
    model::{
        AppendOutcome, BindOutcome, FinishOutcome, LeaseBinding, LeaseKey, LogInputFrame,
        LogPayload, LogStream, StepKey, StoredFrameKind, StoredLogFrame, StreamKey,
        TruncationScope,
    },
    quota::{truncate_frame, PendingEmission, QuotaBuffer},
    redaction::StreamingRedactor,
    secure_io::{ensure_journal_file, io_failure, open_journal_append, prepare_root},
    validation::{validate_binding, validate_identifier, validate_input},
    InputDigestKey, LogError, LogLimits, SecretSet,
};
use runtrue_model::ContentDigest;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(crate) const JOURNAL_VERSION: u32 = 1;
pub(crate) const JOURNAL_FILE: &str = "log.journal.jsonl";
pub(crate) const INPUT_DIGEST_DOMAIN: &[u8] = b"runtrue.log.input.v1\0";
pub(crate) const JOURNAL_DIGEST_DOMAIN: &[u8] = b"runtrue.log.journal.v1\0";
pub(crate) const REDACTION_MARKER: &[u8] = b"[REDACTED]";
pub(crate) const FRAME_TRUNCATION_MARKER: &[u8] = b"[runtrue:frame-truncated]";
pub(crate) const LINE_TRUNCATION_MARKER: &[u8] = b"[runtrue:line-truncated]";
pub(crate) const STEP_TRUNCATION_MARKER: &[u8] = b"[runtrue:step-truncated]";
pub(crate) const RUN_TRUNCATION_MARKER: &[u8] = b"[runtrue:run-truncated]";
pub(crate) const MIN_INPUT_DIGEST_KEY_BYTES: usize = 32;
pub(crate) const MAX_INPUT_DIGEST_KEY_BYTES: usize = 1024;

pub(crate) struct StreamState {
    pub(crate) expected_sequence: u64,
    pub(crate) input_digests: BTreeMap<u64, ContentDigest>,
    redactor: StreamingRedactor,
    lines: LineLimiter,
    pub(crate) finished: bool,
    pub(crate) interrupted: bool,
}

impl StreamState {
    pub(crate) fn new(secrets: &SecretSet, limits: LogLimits) -> Self {
        Self {
            expected_sequence: 0,
            input_digests: BTreeMap::new(),
            redactor: StreamingRedactor::new(secrets.clone()),
            lines: LineLimiter::new(limits.max_line_bytes, limits.line_tail_bytes),
            finished: false,
            interrupted: false,
        }
    }
}

/// Append-only local structured log pipeline.
pub struct LogPipeline {
    root: PathBuf,
    journal_path: PathBuf,
    journal: File,
    journal_bytes: u64,
    next_index: u64,
    previous_hash: ContentDigest,
    limits: LogLimits,
    secrets: SecretSet,
    input_digest_key: InputDigestKey,
    leases: BTreeMap<LeaseKey, LeaseBinding>,
    streams: BTreeMap<StreamKey, StreamState>,
    step_quotas: BTreeMap<StepKey, QuotaBuffer>,
    run_quotas: BTreeMap<String, QuotaBuffer>,
    closed_steps: BTreeSet<StepKey>,
    closed_runs: BTreeSet<String>,
    interrupted_runs: BTreeSet<String>,
    frames: Vec<StoredLogFrame>,
}

impl LogPipeline {
    /// Open a new or existing journal and verify its complete integrity chain.
    /// Runs left unfinished by a process crash are readable but cannot resume;
    /// this prevents loss of an unpersisted secret-prefix buffer from becoming
    /// a redaction bypass.
    pub fn open(
        root: impl AsRef<Path>,
        limits: LogLimits,
        secrets: SecretSet,
        input_digest_key: InputDigestKey,
    ) -> Result<Self, LogError> {
        let limits = limits.validate()?;
        if secrets.len() > limits.max_secrets || secrets.max_pattern_bytes > limits.max_secret_bytes
        {
            return Err(LogError::InvalidSecrets);
        }
        let root = prepare_root(root.as_ref())?;
        let journal_path = root.join(JOURNAL_FILE);
        ensure_journal_file(&journal_path)?;
        let metadata = fs::symlink_metadata(&journal_path)
            .map_err(|source| io_failure("inspect log journal", &journal_path, source))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(LogError::UnsafeJournalPath(journal_path));
        }
        if metadata.len() > limits.max_journal_bytes {
            return Err(LogError::JournalLimit {
                limit: limits.max_journal_bytes,
                actual: metadata.len(),
            });
        }

        let verified = verify_journal(&journal_path, limits, &secrets)?;
        let journal = open_journal_append(&journal_path)?;
        Ok(Self {
            root,
            journal_path,
            journal,
            journal_bytes: metadata.len(),
            next_index: verified.next_index,
            previous_hash: verified.previous_hash,
            limits,
            secrets,
            input_digest_key,
            leases: verified.leases,
            streams: verified.streams,
            step_quotas: BTreeMap::new(),
            run_quotas: BTreeMap::new(),
            closed_steps: verified.closed_steps,
            closed_runs: verified.closed_runs,
            interrupted_runs: verified.interrupted_runs,
            frames: verified.frames,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    #[must_use]
    pub fn frames(&self) -> &[StoredLogFrame] {
        &self.frames
    }

    /// Return decoded output bytes in journal order for one stream.
    pub fn rendered_stream(
        &self,
        run_id: &str,
        job_id: &str,
        step_id: &str,
        stream: LogStream,
    ) -> Result<Vec<u8>, LogError> {
        let mut output = Vec::new();
        for frame in &self.frames {
            if frame.run_id == run_id
                && frame.job_id == job_id
                && frame.step_id == step_id
                && frame.stream == stream
            {
                output.extend_from_slice(&frame.payload.decode()?);
            }
        }
        Ok(output)
    }

    pub fn bind_lease(&mut self, binding: LeaseBinding) -> Result<BindOutcome, LogError> {
        validate_binding(&binding, self.limits)?;
        if self.closed_runs.contains(&binding.run_id)
            || self.interrupted_runs.contains(&binding.run_id)
        {
            return Err(LogError::RunClosedOrInterrupted);
        }
        let key = LeaseKey {
            run_id: binding.run_id.clone(),
            job_id: binding.job_id.clone(),
        };
        if let Some(current) = self.leases.get(&key) {
            if current == &binding {
                return Ok(BindOutcome::AlreadyBound);
            }
            if binding.fencing_generation <= current.fencing_generation {
                return Err(LogError::StaleLease);
            }
        }
        self.append_event(JournalEvent::LeaseBound {
            binding: binding.clone(),
        })?;
        self.leases.insert(key, binding);
        Ok(BindOutcome::Bound)
    }

    pub fn append(&mut self, frame: LogInputFrame) -> Result<AppendOutcome, LogError> {
        validate_input(&frame, self.limits)?;
        self.require_active_frame(&frame)?;
        let stream_key = StreamKey::from_input(&frame);
        let step_key = stream_key.step_key();
        let input_digest = input_digest(&frame, &self.input_digest_key)?;

        if let Some(state) = self.streams.get(&stream_key) {
            if frame.sequence < state.expected_sequence {
                return if state.input_digests.get(&frame.sequence) == Some(&input_digest) {
                    Ok(AppendOutcome::Duplicate)
                } else {
                    Err(LogError::ConflictingDuplicate)
                };
            }
            if frame.sequence > state.expected_sequence {
                return Err(LogError::OutOfOrder {
                    expected: state.expected_sequence,
                    received: frame.sequence,
                });
            }
            if state.finished || self.closed_steps.contains(&step_key) {
                return Err(LogError::StreamFinished);
            }
            if state.interrupted {
                return Err(LogError::RunClosedOrInterrupted);
            }
        } else {
            if frame.sequence != 0 {
                return Err(LogError::OutOfOrder {
                    expected: 0,
                    received: frame.sequence,
                });
            }
            if self.closed_steps.contains(&step_key) {
                return Err(LogError::StreamFinished);
            }
        }
        if self.closed_runs.contains(&frame.run_id) || self.interrupted_runs.contains(&frame.run_id)
        {
            return Err(LogError::RunClosedOrInterrupted);
        }
        if frame.sequence >= self.limits.max_frames_per_stream {
            return Err(LogError::FrameCountLimit);
        }

        let (bounded, frame_truncated) = truncate_frame(
            &frame.payload,
            self.limits.max_frame_bytes,
            self.limits.frame_tail_bytes,
        );
        let bounded = Zeroizing::new(bounded);
        self.append_event(JournalEvent::InputAccepted {
            stream: stream_key.clone(),
            sequence: frame.sequence,
            input_digest: input_digest.clone(),
            input_bytes: u64::try_from(frame.payload.len()).unwrap_or(u64::MAX),
            frame_truncated,
        })?;

        let state = self
            .streams
            .entry(stream_key.clone())
            .or_insert_with(|| StreamState::new(&self.secrets, self.limits));
        state.input_digests.insert(frame.sequence, input_digest);
        state.expected_sequence = state.expected_sequence.saturating_add(1);
        let (redacted, redaction_applied) = state.redactor.push(&bounded);
        let lines = state.lines.push(
            &redacted,
            redaction_applied,
            frame_truncated,
            Some(frame.sequence),
        );
        for line in lines {
            self.accept_step_emission(PendingEmission {
                stream: stream_key.clone(),
                source_sequence: line.source_sequence,
                bytes: line.bytes,
                redacted: line.redacted,
                truncated: line.truncated,
                frame_kind: if line.truncated {
                    StoredFrameKind::Truncation {
                        scope: TruncationScope::Line,
                    }
                } else if frame_truncated {
                    StoredFrameKind::Truncation {
                        scope: TruncationScope::Frame,
                    }
                } else {
                    StoredFrameKind::Data
                },
            })?;
        }
        Ok(AppendOutcome::Appended)
    }

    pub fn finish_step(
        &mut self,
        binding: &LeaseBinding,
        step_id: &str,
    ) -> Result<FinishOutcome, LogError> {
        validate_identifier("step_id", step_id, self.limits)?;
        self.require_active_binding(binding)?;
        let step_key = StepKey {
            run_id: binding.run_id.clone(),
            job_id: binding.job_id.clone(),
            step_id: step_id.to_owned(),
            lease_id: binding.lease_id.clone(),
            fencing_generation: binding.fencing_generation,
        };
        if self.closed_steps.contains(&step_key) {
            return Ok(FinishOutcome::AlreadyFinished);
        }
        if self.interrupted_runs.contains(&binding.run_id) {
            return Err(LogError::RunClosedOrInterrupted);
        }

        let keys = self
            .streams
            .keys()
            .filter(|key| key.step_key() == step_key)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            let lines = {
                let state = self.streams.get_mut(&key).expect("collected stream exists");
                if state.finished {
                    Vec::new()
                } else {
                    let (redacted, redaction_applied) = state.redactor.finish();
                    let mut lines = state.lines.push(&redacted, redaction_applied, false, None);
                    if let Some(line) = state.lines.finish() {
                        lines.push(line);
                    }
                    state.finished = true;
                    lines
                }
            };
            for line in lines {
                self.accept_step_emission(PendingEmission {
                    stream: key.clone(),
                    source_sequence: line.source_sequence,
                    bytes: line.bytes,
                    redacted: line.redacted,
                    truncated: line.truncated,
                    frame_kind: if line.truncated {
                        StoredFrameKind::Truncation {
                            scope: TruncationScope::Line,
                        }
                    } else {
                        StoredFrameKind::Data
                    },
                })?;
            }
        }

        if let Some(quota) = self.step_quotas.remove(&step_key) {
            for emission in quota.finish(TruncationScope::Step, STEP_TRUNCATION_MARKER) {
                self.accept_run_emission(emission)?;
            }
        }
        self.append_event(JournalEvent::StepFinished {
            step: step_key.clone(),
        })?;
        self.closed_steps.insert(step_key);
        Ok(FinishOutcome::Finished)
    }

    pub fn finish_run(&mut self, run_id: &str) -> Result<FinishOutcome, LogError> {
        validate_identifier("run_id", run_id, self.limits)?;
        if self.closed_runs.contains(run_id) {
            return Ok(FinishOutcome::AlreadyFinished);
        }
        if self.interrupted_runs.contains(run_id) {
            return Err(LogError::RunClosedOrInterrupted);
        }
        if self
            .streams
            .iter()
            .any(|(key, state)| key.run_id == run_id && !state.finished)
            || self
                .step_quotas
                .keys()
                .any(|step| step.run_id == run_id && !self.closed_steps.contains(step))
        {
            return Err(LogError::OpenStep);
        }
        if let Some(quota) = self.run_quotas.remove(run_id) {
            for emission in quota.finish(TruncationScope::Run, RUN_TRUNCATION_MARKER) {
                self.persist_emission(emission)?;
            }
        }
        self.append_event(JournalEvent::RunFinished {
            run_id: run_id.to_owned(),
        })?;
        self.closed_runs.insert(run_id.to_owned());
        Ok(FinishOutcome::Finished)
    }

    fn require_active_frame(&self, frame: &LogInputFrame) -> Result<(), LogError> {
        self.require_active_binding(&LeaseBinding {
            run_id: frame.run_id.clone(),
            job_id: frame.job_id.clone(),
            lease_id: frame.lease_id.clone(),
            fencing_generation: frame.fencing_generation,
        })
    }

    fn require_active_binding(&self, binding: &LeaseBinding) -> Result<(), LogError> {
        let key = LeaseKey {
            run_id: binding.run_id.clone(),
            job_id: binding.job_id.clone(),
        };
        if self.leases.get(&key) == Some(binding) {
            Ok(())
        } else {
            Err(LogError::StaleLease)
        }
    }

    fn accept_step_emission(&mut self, emission: PendingEmission) -> Result<(), LogError> {
        if emission.bytes.is_empty() {
            return Ok(());
        }
        let step = emission.stream.step_key();
        let outputs = self
            .step_quotas
            .entry(step)
            .or_insert_with(|| {
                QuotaBuffer::new(
                    self.limits.max_step_bytes,
                    self.limits.step_tail_bytes,
                    STEP_TRUNCATION_MARKER.len(),
                )
            })
            .push(emission);
        for output in outputs {
            self.accept_run_emission(output)?;
        }
        Ok(())
    }

    fn accept_run_emission(&mut self, emission: PendingEmission) -> Result<(), LogError> {
        let run_id = emission.stream.run_id.clone();
        let outputs = self
            .run_quotas
            .entry(run_id)
            .or_insert_with(|| {
                QuotaBuffer::new(
                    self.limits.max_run_bytes,
                    self.limits.run_tail_bytes,
                    RUN_TRUNCATION_MARKER.len(),
                )
            })
            .push(emission);
        for output in outputs {
            self.persist_emission(output)?;
        }
        Ok(())
    }

    fn persist_emission(&mut self, emission: PendingEmission) -> Result<(), LogError> {
        if emission.bytes.is_empty() {
            return Ok(());
        }
        let frame = StoredLogFrame {
            journal_index: self.next_index,
            run_id: emission.stream.run_id,
            job_id: emission.stream.job_id,
            step_id: emission.stream.step_id,
            lease_id: emission.stream.lease_id,
            fencing_generation: emission.stream.fencing_generation,
            stream: emission.stream.stream,
            source_sequence: emission.source_sequence,
            payload: LogPayload::from_bytes(&emission.bytes),
            redacted: emission.redacted,
            truncated: emission.truncated,
            frame_kind: emission.frame_kind,
        };
        self.append_event(JournalEvent::Output {
            frame: frame.clone(),
        })?;
        self.frames.push(frame);
        Ok(())
    }

    fn append_event(&mut self, event: JournalEvent) -> Result<(), LogError> {
        let event_bytes = serde_json::to_vec(&event).map_err(LogError::Serialize)?;
        let event_hash = journal_hash(self.next_index, &self.previous_hash, &event_bytes)?;
        let envelope = JournalEnvelope {
            journal_version: JOURNAL_VERSION,
            index: self.next_index,
            previous_hash: self.previous_hash.clone(),
            event_hash: event_hash.clone(),
            event,
        };
        let mut bytes = serde_json::to_vec(&envelope).map_err(LogError::Serialize)?;
        bytes.push(b'\n');
        if bytes.len() > self.limits.max_journal_record_bytes {
            return Err(LogError::JournalRecordLimit);
        }
        let next_size =
            self.journal_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(LogError::JournalLimit {
                    limit: self.limits.max_journal_bytes,
                    actual: u64::MAX,
                })?;
        if next_size > self.limits.max_journal_bytes {
            return Err(LogError::JournalLimit {
                limit: self.limits.max_journal_bytes,
                actual: next_size,
            });
        }
        self.journal
            .write_all(&bytes)
            .map_err(|source| io_failure("append log journal", &self.journal_path, source))?;
        self.journal
            .sync_data()
            .map_err(|source| io_failure("sync log journal", &self.journal_path, source))?;
        self.journal_bytes = next_size;
        self.next_index = self.next_index.saturating_add(1);
        self.previous_hash = event_hash;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom};
    use tempfile::tempdir;

    fn binding(fence: u64) -> LeaseBinding {
        LeaseBinding {
            run_id: "run-1".to_owned(),
            job_id: "job-1".to_owned(),
            lease_id: format!("lease-{fence}"),
            fencing_generation: fence,
        }
    }

    fn frame(
        binding: &LeaseBinding,
        step: &str,
        stream: LogStream,
        sequence: u64,
        payload: impl Into<Vec<u8>>,
    ) -> LogInputFrame {
        LogInputFrame {
            run_id: binding.run_id.clone(),
            job_id: binding.job_id.clone(),
            step_id: step.to_owned(),
            lease_id: binding.lease_id.clone(),
            fencing_generation: binding.fencing_generation,
            stream,
            sequence,
            payload: payload.into(),
        }
    }

    fn open_pipeline(directory: &Path, limits: LogLimits, secrets: Vec<Vec<u8>>) -> LogPipeline {
        let secrets = SecretSet::new(secrets, limits).unwrap();
        LogPipeline::open(
            directory,
            limits,
            secrets,
            InputDigestKey::from_array([0x42; 32]),
        )
        .unwrap()
    }

    fn all_output(pipeline: &LogPipeline) -> Vec<u8> {
        let mut output = Vec::new();
        for frame in pipeline.frames() {
            output.extend_from_slice(&frame.payload.decode().unwrap());
        }
        output
    }

    #[test]
    fn secret_split_across_chunks_never_reaches_frames_or_journal() {
        let directory = tempdir().unwrap();
        let limits = LogLimits::default();
        let secret = b"token=super-secret-canary".to_vec();
        let mut pipeline = open_pipeline(directory.path(), limits, vec![secret.clone()]);
        let lease = binding(1);
        pipeline.bind_lease(lease.clone()).unwrap();

        pipeline
            .append(frame(
                &lease,
                "step",
                LogStream::Stdout,
                0,
                b"before token=super-se".to_vec(),
            ))
            .unwrap();
        assert!(pipeline.frames().is_empty());
        let journal_after_prefix = fs::read(pipeline.journal_path()).unwrap();
        assert!(!journal_after_prefix
            .windows(b"token=super-se".len())
            .any(|window| window == b"token=super-se"));

        pipeline
            .append(frame(
                &lease,
                "step",
                LogStream::Stdout,
                1,
                b"cret-canary after\n".to_vec(),
            ))
            .unwrap();
        pipeline.finish_step(&lease, "step").unwrap();
        pipeline.finish_run("run-1").unwrap();
        let output = all_output(&pipeline);
        assert!(output
            .windows(REDACTION_MARKER.len())
            .any(|window| window == REDACTION_MARKER));
        assert!(!output
            .windows(secret.len())
            .any(|window| window == secret.as_slice()));
        let journal = fs::read(pipeline.journal_path()).unwrap();
        assert!(!journal
            .windows(secret.len())
            .any(|window| window == secret.as_slice()));
    }

    #[test]
    fn every_two_chunk_secret_split_is_redacted() {
        let secret = b"boundary-canary";
        for split in 1..secret.len() {
            let directory = tempdir().unwrap();
            let limits = LogLimits::default();
            let mut pipeline = open_pipeline(directory.path(), limits, vec![secret.to_vec()]);
            let lease = binding(1);
            pipeline.bind_lease(lease.clone()).unwrap();
            pipeline
                .append(frame(
                    &lease,
                    "step",
                    LogStream::Stdout,
                    0,
                    secret[..split].to_vec(),
                ))
                .unwrap();
            let mut suffix = secret[split..].to_vec();
            suffix.push(b'\n');
            pipeline
                .append(frame(&lease, "step", LogStream::Stdout, 1, suffix))
                .unwrap();
            pipeline.finish_step(&lease, "step").unwrap();
            pipeline.finish_run("run-1").unwrap();

            let output = all_output(&pipeline);
            assert!(!output.windows(secret.len()).any(|window| window == secret));
            assert!(output
                .windows(REDACTION_MARKER.len())
                .any(|window| window == REDACTION_MARKER));
            let journal = fs::read(pipeline.journal_path()).unwrap();
            assert!(!journal.windows(secret.len()).any(|window| window == secret));
        }
    }

    #[test]
    fn frame_and_line_limits_emit_markers_and_retain_tails() {
        let directory = tempdir().unwrap();
        let limits = LogLimits {
            max_frame_bytes: 64,
            frame_tail_bytes: 8,
            max_line_bytes: 80,
            line_tail_bytes: 8,
            max_step_bytes: 1024,
            step_tail_bytes: 16,
            max_run_bytes: 2048,
            run_tail_bytes: 16,
            max_journal_record_bytes: 4096,
            ..LogLimits::default()
        };
        let mut pipeline = open_pipeline(directory.path(), limits, Vec::new());
        let lease = binding(1);
        pipeline.bind_lease(lease.clone()).unwrap();
        let mut oversized_frame = vec![b'F'; 100];
        oversized_frame.push(b'\n');
        pipeline
            .append(frame(
                &lease,
                "frame",
                LogStream::Stdout,
                0,
                oversized_frame,
            ))
            .unwrap();
        pipeline.finish_step(&lease, "frame").unwrap();

        for sequence in 0..3 {
            pipeline
                .append(frame(
                    &lease,
                    "line",
                    LogStream::Stdout,
                    sequence,
                    vec![b'L'; 40],
                ))
                .unwrap();
        }
        pipeline
            .append(frame(&lease, "line", LogStream::Stdout, 3, b"\n".to_vec()))
            .unwrap();
        pipeline.finish_step(&lease, "line").unwrap();
        pipeline.finish_run("run-1").unwrap();
        let output = all_output(&pipeline);
        assert!(output
            .windows(FRAME_TRUNCATION_MARKER.len())
            .any(|window| window == FRAME_TRUNCATION_MARKER));
        assert!(output
            .windows(LINE_TRUNCATION_MARKER.len())
            .any(|window| window == LINE_TRUNCATION_MARKER));
        assert!(output.ends_with(&[b'L'; 8].into_iter().chain([b'\n']).collect::<Vec<_>>()));
    }

    #[test]
    fn step_and_run_quotas_emit_markers_with_bounded_retained_tail() {
        let directory = tempdir().unwrap();
        let limits = LogLimits {
            max_frame_bytes: 128,
            frame_tail_bytes: 8,
            max_line_bytes: 128,
            line_tail_bytes: 8,
            max_step_bytes: 80,
            step_tail_bytes: 8,
            max_run_bytes: 130,
            run_tail_bytes: 8,
            max_journal_record_bytes: 4096,
            ..LogLimits::default()
        };
        let mut pipeline = open_pipeline(directory.path(), limits, Vec::new());
        let lease = binding(1);
        pipeline.bind_lease(lease.clone()).unwrap();
        for (step, byte) in [("one", b'A'), ("two", b'B')] {
            for sequence in 0..2 {
                let mut payload = vec![byte; 50];
                payload.push(b'\n');
                pipeline
                    .append(frame(&lease, step, LogStream::Stdout, sequence, payload))
                    .unwrap();
            }
            pipeline.finish_step(&lease, step).unwrap();
        }
        pipeline.finish_run("run-1").unwrap();
        let output = all_output(&pipeline);
        assert!(output.len() <= limits.max_run_bytes);
        assert!(output
            .windows(STEP_TRUNCATION_MARKER.len())
            .any(|window| window == STEP_TRUNCATION_MARKER));
        assert!(output
            .windows(RUN_TRUNCATION_MARKER.len())
            .any(|window| window == RUN_TRUNCATION_MARKER));
        assert!(output.ends_with(&[b'B'; 7].into_iter().chain([b'\n']).collect::<Vec<_>>()));
    }

    #[test]
    fn stale_reordered_duplicate_and_conflicting_frames_are_distinct() {
        let directory = tempdir().unwrap();
        let mut pipeline = open_pipeline(directory.path(), LogLimits::default(), Vec::new());
        let active = binding(2);
        pipeline.bind_lease(active.clone()).unwrap();
        let stale = binding(1);
        assert!(matches!(
            pipeline.append(frame(
                &stale,
                "step",
                LogStream::Stdout,
                0,
                b"stale\n".to_vec()
            )),
            Err(LogError::StaleLease)
        ));
        assert!(matches!(
            pipeline.append(frame(
                &active,
                "step",
                LogStream::Stdout,
                1,
                b"late\n".to_vec()
            )),
            Err(LogError::OutOfOrder {
                expected: 0,
                received: 1
            })
        ));
        let accepted = frame(
            &active,
            "step",
            LogStream::Stdout,
            0,
            b"accepted\n".to_vec(),
        );
        assert_eq!(
            pipeline.append(accepted.clone()).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(pipeline.append(accepted).unwrap(), AppendOutcome::Duplicate);
        assert!(matches!(
            pipeline.append(frame(
                &active,
                "step",
                LogStream::Stdout,
                0,
                b"conflict\n".to_vec()
            )),
            Err(LogError::ConflictingDuplicate)
        ));
    }

    #[test]
    fn binary_payload_round_trips_without_utf8_loss() {
        let directory = tempdir().unwrap();
        let mut pipeline = open_pipeline(directory.path(), LogLimits::default(), Vec::new());
        let lease = binding(1);
        pipeline.bind_lease(lease.clone()).unwrap();
        let bytes = vec![0xff, 0x00, 0xfe, b'\n'];
        pipeline
            .append(frame(&lease, "binary", LogStream::Stderr, 0, bytes.clone()))
            .unwrap();
        pipeline.finish_step(&lease, "binary").unwrap();
        pipeline.finish_run("run-1").unwrap();
        assert_eq!(
            pipeline
                .rendered_stream("run-1", "job-1", "binary", LogStream::Stderr)
                .unwrap(),
            bytes
        );
        assert!(pipeline
            .frames()
            .iter()
            .any(|frame| matches!(frame.payload, LogPayload::Base64 { .. })));
    }

    #[test]
    fn completed_journal_reopens_and_exact_replay_remains_idempotent() {
        let directory = tempdir().unwrap();
        let limits = LogLimits::default();
        let lease = binding(1);
        let accepted = frame(&lease, "step", LogStream::Stdout, 0, b"value\n".to_vec());
        let expected_frames = {
            let mut pipeline = open_pipeline(directory.path(), limits, Vec::new());
            pipeline.bind_lease(lease.clone()).unwrap();
            pipeline.append(accepted.clone()).unwrap();
            pipeline.finish_step(&lease, "step").unwrap();
            pipeline.finish_run("run-1").unwrap();
            pipeline.frames().to_vec()
        };
        let mut reopened = open_pipeline(directory.path(), limits, Vec::new());
        assert_eq!(reopened.frames(), expected_frames);
        assert_eq!(reopened.append(accepted).unwrap(), AppendOutcome::Duplicate);
    }

    #[test]
    fn journal_tampering_is_detected_on_reopen() {
        let directory = tempdir().unwrap();
        let limits = LogLimits::default();
        let journal_path = {
            let mut pipeline = open_pipeline(directory.path(), limits, Vec::new());
            let lease = binding(1);
            pipeline.bind_lease(lease.clone()).unwrap();
            pipeline
                .append(frame(
                    &lease,
                    "step",
                    LogStream::Stdout,
                    0,
                    b"value\n".to_vec(),
                ))
                .unwrap();
            pipeline.finish_step(&lease, "step").unwrap();
            pipeline.finish_run("run-1").unwrap();
            pipeline.journal_path().to_path_buf()
        };
        let mut file = OpenOptions::new().write(true).open(journal_path).unwrap();
        file.seek(SeekFrom::Start(12)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            LogPipeline::open(
                directory.path(),
                limits,
                SecretSet::empty(),
                InputDigestKey::from_array([0x42; 32]),
            ),
            Err(LogError::Integrity(_))
        ));
    }

    #[test]
    fn debug_output_never_contains_raw_payload_or_secret() {
        let limits = LogLimits::default();
        let canary = b"do-not-print-this-canary".to_vec();
        let secrets = SecretSet::new(vec![canary.clone()], limits).unwrap();
        let input = LogInputFrame {
            run_id: "run".to_owned(),
            job_id: "job".to_owned(),
            step_id: "step".to_owned(),
            lease_id: "lease".to_owned(),
            fencing_generation: 1,
            stream: LogStream::Stdout,
            sequence: 0,
            payload: canary.clone(),
        };
        let debug = format!("{secrets:?} {input:?}");
        assert!(!debug.contains(std::str::from_utf8(&canary).unwrap()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn input_replay_digests_are_keyed_and_keys_never_serialize_or_debug() {
        let limits = LogLimits::default();
        let lease = binding(1);
        let input = frame(
            &lease,
            "step",
            LogStream::Stdout,
            0,
            b"low-entropy-secret\n".to_vec(),
        );
        let mut digests = Vec::new();
        for key_byte in [b'K', b'L'] {
            let directory = tempdir().unwrap();
            let key_material = vec![key_byte; 32];
            let key = InputDigestKey::new(key_material.clone()).unwrap();
            assert_eq!(format!("{key:?}"), "InputDigestKey(<redacted>)");
            let mut pipeline =
                LogPipeline::open(directory.path(), limits, SecretSet::empty(), key).unwrap();
            pipeline.bind_lease(lease.clone()).unwrap();
            pipeline.append(input.clone()).unwrap();
            let digest = pipeline
                .streams
                .values()
                .next()
                .unwrap()
                .input_digests
                .get(&0)
                .unwrap()
                .clone();
            digests.push(digest);
            let journal = fs::read(pipeline.journal_path()).unwrap();
            assert!(!journal
                .windows(key_material.len())
                .any(|window| window == key_material));
        }
        assert_ne!(digests[0], digests[1]);
    }
}
