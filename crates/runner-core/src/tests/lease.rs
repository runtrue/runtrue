use super::fixtures::{admission, capsule, offer_and_capsule, profile};
use crate::{LeaseCompletion, RunnerAdmissionError};
use runtrue_attest::CapsuleSigningKey;
use runtrue_model::ContentDigest;
use std::collections::BTreeSet;

#[test]
fn execution_guard_fences_broker_operations_and_idempotent_completion() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let capsule = capsule(Vec::new());
    let (offer, fetched) = offer_and_capsule(&key, &capsule);
    let admitted = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect("admit");
    let mut guard = admitted.into_guard();
    assert!(matches!(
        guard.authorize_active("lease-1", 3, 9, 1500),
        Err(RunnerAdmissionError::InvalidLeaseState)
    ));
    guard.start("lease-1", 3, 9, 1500).expect("start");
    guard
        .authorize_active("lease-1", 3, 9, 1500)
        .expect("active");
    guard
        .authorize_active("lease-1", 3, 9, 5000)
        .expect("initial soft expiry does not terminate local execution");
    assert!(matches!(
        guard.authorize_active("lease-1", 3, 9, 10_000),
        Err(RunnerAdmissionError::LeaseExpired)
    ));
    assert!(matches!(
        guard.authorize_active("lease-1", 2, 9, 1500),
        Err(RunnerAdmissionError::StaleLeaseFence)
    ));
    let completion = LeaseCompletion {
        final_state: "succeeded".to_owned(),
        result_digest: ContentDigest::sha256(b"result"),
    };
    assert!(guard
        .complete("lease-1", 3, 9, 2000, completion.clone())
        .expect("first completion"));
    assert!(!guard
        .complete("lease-1", 3, 9, 2000, completion)
        .expect("idempotent completion"));
    let conflicting = LeaseCompletion {
        final_state: "failed".to_owned(),
        result_digest: ContentDigest::sha256(b"other"),
    };
    assert!(matches!(
        guard.complete("lease-1", 3, 9, 2000, conflicting),
        Err(RunnerAdmissionError::ConflictingCompletion)
    ));
}
