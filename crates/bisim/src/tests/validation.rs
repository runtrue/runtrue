use super::fixtures::{
    backend, capsule, evidence_factory, output, portable, portable_evidence, ScriptedExecutor,
    TestEvidenceVerifier,
};
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
            &[],
            &TestEvidenceVerifier,
            evidence_factory(&capsule()),
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
        &TestEvidenceVerifier,
        evidence_factory(&capsule()),
    )
    .unwrap();
    observation.normalized_result_digest = ContentDigest::sha256(b"forged");
    assert!(matches!(
        observation.verify(),
        Err(BisimError::ResultDigestMismatch)
    ));

    let mut identity_substitution = observe_backend(
        &capsule(),
        backend(),
        ScriptedExecutor {
            outputs: VecDeque::from([output("ok", 1)]),
        },
        &[],
        &TestEvidenceVerifier,
        evidence_factory(&capsule()),
    )
    .unwrap();
    identity_substitution.portable.provider_identity_digest =
        ContentDigest::sha256(b"unadmitted-provider");
    assert!(matches!(
        identity_substitution.verify(),
        Err(BisimError::ProviderContract(_))
    ));
}

#[test]
fn caller_cannot_fabricate_portable_values_outside_signed_evidence() {
    let execution_capsule = capsule();
    let mut fabricated = portable(&execution_capsule);
    // This field was previously caller-controlled and is not part of the
    // provider-contract portable comparison digest. The Bisim Evidence payload
    // deliberately binds the complete active observation.
    fabricated.backend_security_result_digest = ContentDigest::sha256(b"fabricated-security");

    assert!(matches!(
        observe_backend(
            &execution_capsule,
            backend(),
            ScriptedExecutor {
                outputs: VecDeque::from([output("ok", 1)]),
            },
            &[],
            &TestEvidenceVerifier,
            |binding, _result| { Ok((fabricated, portable_evidence(&execution_capsule, binding))) },
        ),
        Err(BisimError::InvalidEvidenceBinding(
            "portable observation differs from its signed Evidence payload"
        ))
    ));
}

#[test]
fn structurally_valid_but_cryptographically_forged_evidence_is_rejected() {
    let execution_capsule = capsule();

    assert!(matches!(
        observe_backend(
            &execution_capsule,
            backend(),
            ScriptedExecutor {
                outputs: VecDeque::from([output("ok", 1)]),
            },
            &[],
            &TestEvidenceVerifier,
            |binding, _result| {
                let mut forged = portable_evidence(&execution_capsule, binding);
                forged.events[0].signature.signature[0] ^= 1;
                Ok((portable(&execution_capsule), forged))
            },
        ),
        Err(BisimError::ProviderContract(_))
    ));
}

#[test]
fn signed_evidence_from_another_result_cannot_be_reused() {
    let execution_capsule = capsule();
    assert!(matches!(
        observe_backend(
            &execution_capsule,
            backend(),
            ScriptedExecutor {
                outputs: VecDeque::from([output("actual-result", 1)]),
            },
            &[],
            &TestEvidenceVerifier,
            |binding, _result| {
                let mut other_run = binding.clone();
                other_run.normalized_result_digest = ContentDigest::sha256(b"another-result");
                Ok((
                    portable(&execution_capsule),
                    portable_evidence(&execution_capsule, &other_run),
                ))
            },
        ),
        Err(BisimError::InvalidEvidenceBinding(
            "portable observation differs from its signed Evidence payload"
        ))
    ));
}
