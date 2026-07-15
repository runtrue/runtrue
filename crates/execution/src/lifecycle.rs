use crate::ExecutionModelError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    AdmissionRejected,
    PolicyDenied,
    CapacityUnavailable,
    RuntimeFailure,
    ProgramFailure,
    TimedOut,
    Canceled,
    ResourceExhausted,
    ExternalEffectIndeterminate,
    RunnerIntegrityFailure,
}

impl FailureClass {
    #[must_use]
    pub const fn is_safety_override(self) -> bool {
        matches!(
            self,
            Self::ExternalEffectIndeterminate | Self::RunnerIntegrityFailure
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionState {
    Proposed,
    Admitted,
    Queued,
    Leased,
    Running,
    Finalizing,
    Terminal,
}

impl ExecutionState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Proposed => matches!(next, Self::Admitted | Self::Terminal),
            Self::Admitted => matches!(next, Self::Queued | Self::Terminal),
            Self::Queued => matches!(next, Self::Leased | Self::Terminal),
            Self::Leased => matches!(next, Self::Running | Self::Finalizing),
            Self::Running => matches!(next, Self::Finalizing),
            Self::Finalizing => matches!(next, Self::Terminal),
            Self::Terminal => false,
        }
    }

    pub fn transition(&mut self, next: Self) -> Result<(), ExecutionModelError> {
        if !self.can_transition_to(next) {
            return Err(ExecutionModelError::InvalidTransition {
                subject: "Execution",
                from: self.name(),
                to: next.name(),
            });
        }
        *self = next;
        Ok(())
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Admitted => "admitted",
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Running => "running",
            Self::Finalizing => "finalizing",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    Proposed,
    Admitted,
    Provisioning,
    Active,
    Suspending,
    Suspended,
    Restoring,
    Destroying,
    Terminal,
}

impl SessionState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Proposed => matches!(next, Self::Admitted | Self::Terminal),
            Self::Admitted => matches!(next, Self::Provisioning | Self::Destroying),
            Self::Provisioning => matches!(next, Self::Active | Self::Destroying),
            Self::Active => matches!(next, Self::Suspending | Self::Destroying),
            Self::Suspending => {
                matches!(next, Self::Suspended | Self::Active | Self::Destroying)
            }
            Self::Suspended => matches!(next, Self::Restoring | Self::Destroying),
            Self::Restoring => {
                matches!(next, Self::Active | Self::Suspended | Self::Destroying)
            }
            Self::Destroying => matches!(next, Self::Terminal),
            Self::Terminal => false,
        }
    }

    pub fn transition(&mut self, next: Self) -> Result<(), ExecutionModelError> {
        if !self.can_transition_to(next) {
            return Err(ExecutionModelError::InvalidTransition {
                subject: "Session",
                from: self.name(),
                to: next.name(),
            });
        }
        *self = next;
        Ok(())
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Admitted => "admitted",
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Suspending => "suspending",
            Self::Suspended => "suspended",
            Self::Restoring => "restoring",
            Self::Destroying => "destroying",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalCause {
    Succeeded,
    Failed(FailureClass),
}

/// Durable first-winner terminal decision with the two fail-closed safety
/// overrides. All observed failures are retained even when an override changes
/// the primary result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TerminalDecision {
    primary: Option<TerminalCause>,
    observed_failures: BTreeSet<FailureClass>,
    success_observed: bool,
}

impl TerminalDecision {
    #[must_use]
    pub const fn primary(&self) -> Option<TerminalCause> {
        self.primary
    }

    #[must_use]
    pub const fn success_observed(&self) -> bool {
        self.success_observed
    }

    #[must_use]
    pub const fn is_committed(&self) -> bool {
        self.primary.is_some()
    }

    #[must_use]
    pub fn observed_failures(&self) -> &BTreeSet<FailureClass> {
        &self.observed_failures
    }

    /// Commit an observed cause. Returns true only when the primary result
    /// changes; replaying or retaining a secondary cause returns false.
    pub fn commit(&mut self, cause: TerminalCause) -> bool {
        match cause {
            TerminalCause::Succeeded => self.success_observed = true,
            TerminalCause::Failed(failure) => {
                self.observed_failures.insert(failure);
            }
        }

        let next = match self.primary {
            None => cause,
            Some(TerminalCause::Failed(FailureClass::RunnerIntegrityFailure)) => {
                return false;
            }
            Some(_) if cause == TerminalCause::Failed(FailureClass::RunnerIntegrityFailure) => {
                cause
            }
            Some(TerminalCause::Failed(FailureClass::ExternalEffectIndeterminate)) => return false,
            Some(_)
                if cause == TerminalCause::Failed(FailureClass::ExternalEffectIndeterminate) =>
            {
                cause
            }
            Some(_) => return false,
        };
        let changed = self.primary != Some(next);
        self.primary = Some(next);
        changed
    }
}
