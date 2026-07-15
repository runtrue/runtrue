use super::fixtures::{admission, capsule, offer_and_capsule, profile};
use crate::RunnerAdmissionError;
use runtrue_attest::CapsuleSigningKey;
use runtrue_model::ContentDigest;
use std::collections::BTreeSet;

#[test]
fn admits_only_an_exact_signed_capsule_for_the_verified_runner() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let capsule = capsule(Vec::new());
    let (offer, fetched) = offer_and_capsule(&key, &capsule);
    let admitted = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect("admit");
    assert_eq!(admitted.capsule_digest, capsule.digest().expect("digest"));
    assert_eq!(admitted.job_id, "build");
    assert_eq!(admitted.expires_unix_ms, 3000);
    assert_eq!(admitted.hard_deadline_unix_ms, 10_000);
}

#[test]
fn rejects_noncanonical_bytes_even_when_their_transport_digest_matches() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let capsule = capsule(Vec::new());
    let (mut offer, mut fetched) = offer_and_capsule(&key, &capsule);
    fetched.canonical_capsule.push(b' ');
    let changed_digest = ContentDigest::sha256(&fetched.canonical_capsule);
    let wire = runtrue_protocol::v1::Digest::try_from(changed_digest).expect("wire");
    offer.capsule_digest = Some(wire.clone());
    fetched.digest = Some(wire);
    let error = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect_err("noncanonical");
    assert!(matches!(error, RunnerAdmissionError::NonCanonicalCapsule));
}

#[test]
fn rejects_signature_tampering_and_untrusted_keys() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let capsule = capsule(Vec::new());
    let (offer, mut fetched) = offer_and_capsule(&key, &capsule);
    fetched.signature[0] ^= 1;
    let mut changed_offer = offer.clone();
    changed_offer.capsule_signature = fetched.signature.clone();
    let error = admission(&key, profile(BTreeSet::new()))
        .admit(&changed_offer, &fetched, 1500)
        .expect_err("tamper");
    assert!(matches!(
        error,
        RunnerAdmissionError::InvalidCapsuleSignature(_)
    ));

    let other = CapsuleSigningKey::from_seed([8; 32]);
    let error = admission(&other, profile(BTreeSet::new()))
        .admit(&offer, &offer_and_capsule(&key, &capsule).1, 1500)
        .expect_err("untrusted key");
    assert!(matches!(
        error,
        RunnerAdmissionError::UntrustedSigningKey(_)
    ));
}

#[test]
fn rejects_signed_unknown_capsule_and_engine_generations() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let mut changed = capsule(Vec::new());
    changed.schema_version += 1;
    let (offer, fetched) = offer_and_capsule(&key, &changed);
    let error = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect_err("unknown capsule schema");
    assert!(matches!(
        error,
        RunnerAdmissionError::UnsupportedCapsuleSchemaVersion { .. }
    ));

    let mut changed = capsule(Vec::new());
    changed.engine_compatibility_version = "future-engine".to_owned();
    let (offer, fetched) = offer_and_capsule(&key, &changed);
    let error = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect_err("unknown engine generation");
    assert!(matches!(
        error,
        RunnerAdmissionError::UnsupportedEngineCompatibilityVersion { .. }
    ));
}

#[test]
fn self_reported_or_offered_capabilities_cannot_expand_verified_posture() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let capsule = capsule(vec!["gpu".to_owned()]);
    let (offer, fetched) = offer_and_capsule(&key, &capsule);
    let error = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect_err("unverified capability");
    assert!(matches!(
        error,
        RunnerAdmissionError::VerifiedProfileCannotSatisfyCapsule
    ));
}

#[test]
fn runner_epoch_fence_and_acceptance_deadline_are_mandatory() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let capsule = capsule(Vec::new());
    let (mut offer, fetched) = offer_and_capsule(&key, &capsule);
    offer.installation_fencing_epoch = 8;
    let error = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect_err("old epoch");
    assert!(matches!(
        error,
        RunnerAdmissionError::StaleInstallationEpoch { .. }
    ));
    offer.installation_fencing_epoch = 9;
    let error = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 2000)
        .expect_err("late accept");
    assert!(matches!(
        error,
        RunnerAdmissionError::OfferOutsideAcceptanceWindow
    ));
}

#[test]
fn hard_deadline_is_immutable_and_old_server_fallback_is_conservative() {
    let key = CapsuleSigningKey::from_seed([7; 32]);
    let capsule = capsule(Vec::new());
    let (mut offer, fetched) = offer_and_capsule(&key, &capsule);
    offer.hard_deadline = Some(prost_types::Timestamp {
        seconds: 2,
        nanos: 500_000_000,
    });
    assert!(matches!(
        admission(&key, profile(BTreeSet::new())).admit(&offer, &fetched, 1500),
        Err(RunnerAdmissionError::InvalidLeaseWindow)
    ));

    offer.hard_deadline = None;
    let admitted = admission(&key, profile(BTreeSet::new()))
        .admit(&offer, &fetched, 1500)
        .expect("old server fallback");
    assert_eq!(admitted.hard_deadline_unix_ms, admitted.expires_unix_ms);
}
