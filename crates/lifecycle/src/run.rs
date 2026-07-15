use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Created,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

impl RunState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Canceled)
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            // A remote run may fail policy/DAG admission before any job starts.
            Self::Created => matches!(next, Self::Running | Self::Failed | Self::Canceled),
            Self::Running => matches!(next, Self::Succeeded | Self::Failed | Self::Canceled),
            Self::Succeeded | Self::Failed | Self::Canceled => false,
        }
    }
}
