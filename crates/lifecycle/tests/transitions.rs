use runtrue_lifecycle::{JobState, RunState};

#[test]
fn terminal_states_never_transition() {
    let jobs = [
        JobState::Succeeded,
        JobState::Failed,
        JobState::Canceled,
        JobState::TimedOut,
        JobState::Lost,
        JobState::Rejected,
        JobState::Skipped,
    ];
    for state in jobs {
        assert!(state.is_terminal());
        for next in jobs {
            assert!(!state.can_transition_to(next));
        }
    }
}

#[test]
fn representative_remote_and_local_paths_are_valid() {
    assert!(JobState::Created.can_transition_to(JobState::Queued));
    assert!(JobState::Queued.can_transition_to(JobState::Leased));
    assert!(JobState::Leased.can_transition_to(JobState::Preparing));
    assert!(JobState::Preparing.can_transition_to(JobState::Running));
    assert!(JobState::Running.can_transition_to(JobState::Finalizing));
    assert!(JobState::Finalizing.can_transition_to(JobState::Succeeded));
    assert!(JobState::Created.can_transition_to(JobState::Preparing));
    assert!(RunState::Created.can_transition_to(RunState::Running));
    assert!(RunState::Running.can_transition_to(RunState::Succeeded));
}
