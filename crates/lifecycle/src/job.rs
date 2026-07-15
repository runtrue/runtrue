use serde::{Deserialize, Serialize};

/// Job states include scheduler-visible states plus the local engine's skipped
/// conclusion. Terminal states can never transition to another state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Created,
    BlockedPolicy,
    AwaitingApproval,
    Queued,
    Leased,
    Preparing,
    Running,
    Finalizing,
    Succeeded,
    Failed,
    Canceled,
    TimedOut,
    Lost,
    Rejected,
    Skipped,
}

impl JobState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Canceled
                | Self::TimedOut
                | Self::Lost
                | Self::Rejected
                | Self::Skipped
        )
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        use JobState::{
            AwaitingApproval, BlockedPolicy, Canceled, Created, Failed, Finalizing, Leased, Lost,
            Preparing, Queued, Rejected, Running, Skipped, Succeeded, TimedOut,
        };
        match self {
            Created => matches!(
                next,
                BlockedPolicy
                    | AwaitingApproval
                    | Queued
                    | Preparing
                    | Rejected
                    | Canceled
                    | Skipped
            ),
            BlockedPolicy => matches!(next, AwaitingApproval | Queued | Rejected | Canceled),
            AwaitingApproval => matches!(next, Queued | Rejected | Canceled),
            Queued => matches!(next, Leased | Preparing | Rejected | Canceled | Lost),
            // An offer that was never accepted may safely return to the queue;
            // the next offer receives a fresh fencing generation.
            Leased => matches!(next, Queued | Preparing | Canceled | Lost),
            Preparing => matches!(
                next,
                Running | Finalizing | Failed | Canceled | TimedOut | Lost
            ),
            Running => matches!(next, Finalizing | Failed | Canceled | TimedOut | Lost),
            Finalizing => matches!(next, Succeeded | Failed | Canceled | TimedOut | Lost),
            Succeeded | Failed | Canceled | TimedOut | Lost | Rejected | Skipped => false,
        }
    }
}
