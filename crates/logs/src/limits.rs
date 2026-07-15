#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogLimits {
    pub max_frame_bytes: usize,
    pub frame_tail_bytes: usize,
    pub max_line_bytes: usize,
    pub line_tail_bytes: usize,
    pub max_step_bytes: usize,
    pub step_tail_bytes: usize,
    pub max_run_bytes: usize,
    pub run_tail_bytes: usize,
    pub max_frames_per_stream: u64,
    pub max_identifier_bytes: usize,
    pub max_secrets: usize,
    pub max_secret_bytes: usize,
    pub max_journal_record_bytes: usize,
    pub max_journal_bytes: u64,
}

impl Default for LogLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 64 * 1024,
            frame_tail_bytes: 4 * 1024,
            max_line_bytes: 64 * 1024,
            line_tail_bytes: 4 * 1024,
            max_step_bytes: 10 * 1024 * 1024,
            step_tail_bytes: 64 * 1024,
            max_run_bytes: 100 * 1024 * 1024,
            run_tail_bytes: 256 * 1024,
            max_frames_per_stream: 1_000_000,
            max_identifier_bytes: 512,
            max_secrets: 1_024,
            max_secret_bytes: 64 * 1024,
            max_journal_record_bytes: 256 * 1024,
            max_journal_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

impl LogLimits {
    pub(crate) fn validate(self) -> Result<Self, LogError> {
        if self.max_frame_bytes == 0
            || self.max_line_bytes == 0
            || self.max_step_bytes == 0
            || self.max_run_bytes == 0
            || self.max_frames_per_stream == 0
            || self.max_identifier_bytes == 0
            || self.max_secrets == 0
            || self.max_secret_bytes == 0
            || self.max_journal_record_bytes == 0
            || self.max_journal_bytes == 0
            || self.max_run_bytes < self.max_step_bytes
            || !tail_and_marker_fit(
                self.frame_tail_bytes,
                FRAME_TRUNCATION_MARKER.len(),
                self.max_frame_bytes,
            )
            || !tail_and_marker_fit(
                self.line_tail_bytes,
                LINE_TRUNCATION_MARKER.len(),
                self.max_line_bytes,
            )
            || !tail_and_marker_fit(
                self.step_tail_bytes,
                STEP_TRUNCATION_MARKER.len(),
                self.max_step_bytes,
            )
            || !tail_and_marker_fit(
                self.run_tail_bytes,
                RUN_TRUNCATION_MARKER.len(),
                self.max_run_bytes,
            )
        {
            return Err(LogError::InvalidConfiguration(
                "log limits are zero, inconsistent, or cannot contain truncation markers"
                    .to_owned(),
            ));
        }
        Ok(self)
    }
}

fn tail_and_marker_fit(tail: usize, marker: usize, limit: usize) -> bool {
    tail.checked_add(marker)
        .is_some_and(|required| required <= limit)
}
pub(crate) struct LinePiece {
    pub(crate) bytes: Vec<u8>,
    pub(crate) redacted: bool,
    pub(crate) truncated: bool,
    pub(crate) source_sequence: Option<u64>,
}

pub(crate) struct LineLimiter {
    max_bytes: usize,
    retained_tail: usize,
    head_budget: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    observed: usize,
    overflow: bool,
    redacted: bool,
    frame_truncated: bool,
    source_sequence: Option<u64>,
}

impl LineLimiter {
    pub(crate) fn new(max_bytes: usize, retained_tail: usize) -> Self {
        Self {
            max_bytes,
            retained_tail,
            head_budget: max_bytes - retained_tail - LINE_TRUNCATION_MARKER.len(),
            head: Vec::new(),
            tail: VecDeque::new(),
            observed: 0,
            overflow: false,
            redacted: false,
            frame_truncated: false,
            source_sequence: None,
        }
    }

    pub(crate) fn push(
        &mut self,
        bytes: &[u8],
        redacted: bool,
        frame_truncated: bool,
        source_sequence: Option<u64>,
    ) -> Vec<LinePiece> {
        let mut output = Vec::new();
        if bytes.is_empty() {
            self.merge_metadata(redacted, frame_truncated, source_sequence);
            return output;
        }
        for byte in bytes {
            // Re-apply chunk metadata after every newline resets the line state.
            // A single input frame can contain more than one logical line.
            self.merge_metadata(redacted, frame_truncated, source_sequence);
            if *byte == b'\n' {
                output.push(self.finish_line(true));
            } else {
                self.push_byte(*byte);
            }
        }
        output
    }

    fn merge_metadata(
        &mut self,
        redacted: bool,
        frame_truncated: bool,
        source_sequence: Option<u64>,
    ) {
        self.redacted |= redacted;
        self.frame_truncated |= frame_truncated;
        if source_sequence.is_some() {
            self.source_sequence = source_sequence;
        }
    }

    pub(crate) fn finish(&mut self) -> Option<LinePiece> {
        if self.observed == 0 && self.head.is_empty() && self.tail.is_empty() {
            None
        } else {
            Some(self.finish_line(false))
        }
    }

    fn push_byte(&mut self, byte: u8) {
        self.observed = self.observed.saturating_add(1);
        if self.head.len() < self.head_budget {
            self.head.push(byte);
            return;
        }
        self.tail.push_back(byte);
        if self.observed > self.max_bytes {
            self.overflow = true;
        }
        let capacity = if self.overflow {
            self.retained_tail
        } else {
            self.retained_tail + LINE_TRUNCATION_MARKER.len()
        };
        while self.tail.len() > capacity {
            self.tail.pop_front();
        }
    }

    fn finish_line(&mut self, newline: bool) -> LinePiece {
        let mut bytes = std::mem::take(&mut self.head);
        if self.overflow {
            bytes.extend_from_slice(LINE_TRUNCATION_MARKER);
        }
        bytes.extend(self.tail.drain(..));
        if newline {
            bytes.push(b'\n');
        }
        let piece = LinePiece {
            bytes,
            redacted: self.redacted,
            truncated: self.overflow || self.frame_truncated,
            source_sequence: self.source_sequence,
        };
        self.observed = 0;
        self.overflow = false;
        self.redacted = false;
        self.frame_truncated = false;
        self.source_sequence = None;
        piece
    }
}
use crate::{
    pipeline::{
        FRAME_TRUNCATION_MARKER, LINE_TRUNCATION_MARKER, RUN_TRUNCATION_MARKER,
        STEP_TRUNCATION_MARKER,
    },
    LogError,
};
use std::collections::VecDeque;
