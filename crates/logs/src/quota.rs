#[derive(Clone)]
pub(crate) struct PendingEmission {
    pub(crate) stream: StreamKey,
    pub(crate) source_sequence: Option<u64>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) redacted: bool,
    pub(crate) truncated: bool,
    pub(crate) frame_kind: StoredFrameKind,
}

impl PendingEmission {
    fn split_prefix(&mut self, count: usize) -> Self {
        let remainder = self.bytes.split_off(count);
        let prefix = std::mem::replace(&mut self.bytes, remainder);
        Self {
            stream: self.stream.clone(),
            source_sequence: self.source_sequence,
            bytes: prefix,
            redacted: self.redacted,
            truncated: self.truncated,
            frame_kind: self.frame_kind.clone(),
        }
    }

    fn marker(template: &Self, scope: TruncationScope, bytes: &'static [u8]) -> Self {
        Self {
            stream: template.stream.clone(),
            source_sequence: None,
            bytes: bytes.to_vec(),
            redacted: false,
            truncated: true,
            frame_kind: StoredFrameKind::Truncation { scope },
        }
    }
}
pub(crate) struct QuotaBuffer {
    limit: usize,
    retained_tail: usize,
    marker_bytes: usize,
    head_budget: usize,
    observed: usize,
    head_emitted: usize,
    overflow: bool,
    tail: VecDeque<PendingEmission>,
    tail_bytes: usize,
    template: Option<PendingEmission>,
}

impl QuotaBuffer {
    pub(crate) fn new(limit: usize, retained_tail: usize, marker_bytes: usize) -> Self {
        Self {
            limit,
            retained_tail,
            marker_bytes,
            head_budget: limit - retained_tail - marker_bytes,
            observed: 0,
            head_emitted: 0,
            overflow: false,
            tail: VecDeque::new(),
            tail_bytes: 0,
            template: None,
        }
    }

    pub(crate) fn push(&mut self, mut emission: PendingEmission) -> Vec<PendingEmission> {
        if emission.bytes.is_empty() {
            return Vec::new();
        }
        if self.template.is_none() {
            self.template = Some(emission.clone());
        }
        self.observed = self.observed.saturating_add(emission.bytes.len());
        let mut immediate = Vec::new();
        let remaining_head = self.head_budget.saturating_sub(self.head_emitted);
        if remaining_head > 0 {
            let retained = remaining_head.min(emission.bytes.len());
            let prefix = emission.split_prefix(retained);
            self.head_emitted += prefix.bytes.len();
            immediate.push(prefix);
        }
        if !emission.bytes.is_empty() {
            self.tail_bytes = self.tail_bytes.saturating_add(emission.bytes.len());
            self.tail.push_back(emission);
        }
        if self.observed > self.limit {
            self.overflow = true;
        }
        let capacity = if self.overflow {
            self.retained_tail
        } else {
            self.retained_tail + self.marker_bytes
        };
        self.trim_tail(capacity);
        immediate
    }

    pub(crate) fn finish(
        self,
        scope: TruncationScope,
        marker_bytes: &'static [u8],
    ) -> Vec<PendingEmission> {
        let mut output = Vec::new();
        if self.overflow {
            if let Some(template) = &self.template {
                output.push(PendingEmission::marker(template, scope, marker_bytes));
            }
        }
        output.extend(self.tail);
        output
    }

    fn trim_tail(&mut self, capacity: usize) {
        while self.tail_bytes > capacity {
            let excess = self.tail_bytes - capacity;
            let Some(front) = self.tail.front_mut() else {
                self.tail_bytes = 0;
                break;
            };
            if front.bytes.len() <= excess {
                self.tail_bytes -= front.bytes.len();
                self.tail.pop_front();
            } else {
                front.bytes.drain(..excess);
                self.tail_bytes -= excess;
            }
        }
    }
}

pub(crate) fn truncate_frame(bytes: &[u8], limit: usize, retained_tail: usize) -> (Vec<u8>, bool) {
    if bytes.len() <= limit {
        return (bytes.to_vec(), false);
    }
    let head = limit - retained_tail - FRAME_TRUNCATION_MARKER.len();
    let mut output = Vec::with_capacity(limit);
    output.extend_from_slice(&bytes[..head]);
    output.extend_from_slice(FRAME_TRUNCATION_MARKER);
    output.extend_from_slice(&bytes[bytes.len() - retained_tail..]);
    (output, true)
}
use crate::{
    model::{StoredFrameKind, StreamKey, TruncationScope},
    pipeline::FRAME_TRUNCATION_MARKER,
};
use std::collections::VecDeque;
