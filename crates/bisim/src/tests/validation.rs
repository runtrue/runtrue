use super::fixtures::{backend, capsule, output, ScriptedExecutor};
use crate::{observe_backend, BisimError};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::Isolation;
use std::collections::VecDeque;

#[test]
fn backend_isolation_and_observation_tampering_fail_closed() {
    let mut wrong = backend();
    wrong.isolation = Isolation::Oci;
    assert!(matches!(
        observe_backend(
            &capsule(),
            wrong,
            ScriptedExecutor {
                outputs: VecDeque::new(),
            },
            &[]
        ),
        Err(BisimError::BackendIsolationMismatch { .. })
    ));
    let mut observation = observe_backend(
        &capsule(),
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("ok", 1)]),
        },
        &[],
    )
    .unwrap();
    observation.normalized_result_digest = ContentDigest::sha256(b"forged");
    assert!(matches!(
        observation.verify(),
        Err(BisimError::ResultDigestMismatch)
    ));
}
