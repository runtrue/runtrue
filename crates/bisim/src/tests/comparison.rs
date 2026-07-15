use super::fixtures::{backend, capsule, output, ScriptedExecutor};
use crate::{compare_bisim, observe_backend};
use runtrue_workflow_ir::PlannedFinalizer;
use std::collections::VecDeque;

#[test]
fn timing_is_normalized_but_results_and_events_remain_exact() {
    let left = observe_backend(
        &capsule(),
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("same", 10)]),
        },
        &[],
    )
    .unwrap();
    let right = observe_backend(
        &capsule(),
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("same", 999)]),
        },
        &[],
    )
    .unwrap();
    assert!(compare_bisim(&left, &right).unwrap().matches);

    let changed = observe_backend(
        &capsule(),
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("different", 10)]),
        },
        &[],
    )
    .unwrap();
    let comparison = compare_bisim(&left, &changed).unwrap();
    assert!(!comparison.matches);
    assert!(comparison.same_capsule);
    assert!(!comparison.same_result);
    assert!(comparison.same_events);
}

#[test]
fn bisim_requires_both_capsule_identity_and_behavioral_equivalence() {
    let left = observe_backend(
        &capsule(),
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("same", 10)]),
        },
        &[],
    )
    .unwrap();
    let mut changed_capsule = capsule();
    changed_capsule.compiler_version = "another-compiler".to_owned();
    let right = observe_backend(
        &changed_capsule,
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("same", 10)]),
        },
        &[],
    )
    .unwrap();

    let comparison = compare_bisim(&left, &right).unwrap();
    assert!(!comparison.matches);
    assert!(!comparison.same_capsule);
    assert!(comparison.same_result);
    assert!(comparison.same_events);
    assert_eq!(comparison.differences, ["capsule_digest"]);
}

#[test]
fn finalizer_timing_uses_the_same_normalized_bisim_contract() {
    let mut execution_capsule = capsule();
    let mut cleanup = execution_capsule.jobs[0].steps[0].clone();
    cleanup.id = "cleanup".to_owned();
    cleanup.name = "cleanup".to_owned();
    execution_capsule.jobs[0].finalizers.push(PlannedFinalizer {
        step: cleanup,
        required: true,
        run_on_cancel: true,
    });
    let left = observe_backend(
        &execution_capsule,
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("same", 10), output("cleanup", 20)]),
        },
        &[],
    )
    .unwrap();
    let right = observe_backend(
        &execution_capsule,
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("same", 999), output("cleanup", 888)]),
        },
        &[],
    )
    .unwrap();

    assert!(compare_bisim(&left, &right).unwrap().matches);
    assert_eq!(
        left.normalized_result.jobs["job"].attempts[0].finalizers[0]
            .output
            .as_ref()
            .unwrap()
            .duration_ms,
        0
    );
}
