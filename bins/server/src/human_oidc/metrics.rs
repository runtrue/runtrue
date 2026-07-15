use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HumanAuthMetricsSnapshot {
    pub login_started: u64,
    pub callback_succeeded: u64,
    pub callback_failed: u64,
    pub session_rotated: u64,
    pub refresh_replay_revoked: u64,
    pub session_logged_out: u64,
    pub live_policy_snapshots: u64,
    pub live_policy_failures: u64,
}

#[derive(Debug, Default)]
pub struct HumanAuthMetrics {
    login_started: AtomicU64,
    callback_succeeded: AtomicU64,
    callback_failed: AtomicU64,
    session_rotated: AtomicU64,
    refresh_replay_revoked: AtomicU64,
    session_logged_out: AtomicU64,
    live_policy_snapshots: AtomicU64,
    live_policy_failures: AtomicU64,
}

impl HumanAuthMetrics {
    pub fn snapshot(&self) -> HumanAuthMetricsSnapshot {
        HumanAuthMetricsSnapshot {
            login_started: self.login_started.load(Ordering::Relaxed),
            callback_succeeded: self.callback_succeeded.load(Ordering::Relaxed),
            callback_failed: self.callback_failed.load(Ordering::Relaxed),
            session_rotated: self.session_rotated.load(Ordering::Relaxed),
            refresh_replay_revoked: self.refresh_replay_revoked.load(Ordering::Relaxed),
            session_logged_out: self.session_logged_out.load(Ordering::Relaxed),
            live_policy_snapshots: self.live_policy_snapshots.load(Ordering::Relaxed),
            live_policy_failures: self.live_policy_failures.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn login_started(&self) {
        self.login_started.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn callback_succeeded(&self) {
        self.callback_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn callback_failed(&self) {
        self.callback_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn session_rotated(&self) {
        self.session_rotated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn refresh_replay_revoked(&self) {
        self.refresh_replay_revoked.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn session_logged_out(&self) {
        self.session_logged_out.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn live_policy_snapshot(&self) {
        self.live_policy_snapshots.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn live_policy_failure(&self) {
        self.live_policy_failures.fetch_add(1, Ordering::Relaxed);
    }
}
