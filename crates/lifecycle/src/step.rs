use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Created,
    Running,
    Succeeded,
    Failed,
    Canceled,
    TimedOut,
    Skipped,
}

impl StepState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Created | Self::Running)
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Created => matches!(
                next,
                Self::Running | Self::Failed | Self::Canceled | Self::TimedOut | Self::Skipped
            ),
            Self::Running => matches!(
                next,
                Self::Succeeded | Self::Failed | Self::Canceled | Self::TimedOut
            ),
            Self::Succeeded | Self::Failed | Self::Canceled | Self::TimedOut | Self::Skipped => {
                false
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    ConditionFalse,
    DependencyNotSuccessful,
    PreviousStepFailed,
    RunCanceled,
}
