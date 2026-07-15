use std::sync::atomic::{AtomicU64, Ordering};
/// Non-sensitive counters for protocol rollout and drain decisions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunnerProtocolMetricsSnapshot {
    pub enrollment_selected_v1: u64,
    pub enrollment_selected_v2: u64,
    pub enrollment_rejected: u64,
    pub stream_version_rejected: u64,
}

#[derive(Debug, Default)]
pub(super) struct RunnerProtocolMetrics {
    enrollment_selected_v1: AtomicU64,
    enrollment_selected_v2: AtomicU64,
    pub(super) enrollment_rejected: AtomicU64,
    pub(super) stream_version_rejected: AtomicU64,
}

impl RunnerProtocolMetrics {
    pub(super) fn snapshot(&self) -> RunnerProtocolMetricsSnapshot {
        RunnerProtocolMetricsSnapshot {
            enrollment_selected_v1: self.enrollment_selected_v1.load(Ordering::Relaxed),
            enrollment_selected_v2: self.enrollment_selected_v2.load(Ordering::Relaxed),
            enrollment_rejected: self.enrollment_rejected.load(Ordering::Relaxed),
            stream_version_rejected: self.stream_version_rejected.load(Ordering::Relaxed),
        }
    }

    pub(super) fn record_selection(&self, selected: u32) {
        let counter = match selected {
            1 => &self.enrollment_selected_v1,
            2 => &self.enrollment_selected_v2,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}
