use super::session::CredentialTaintState;
use super::{
    patterns::{expand_pattern, expand_patterns},
    transfer::{call_after_lifecycle, temporary_cas},
    wire::classification_name,
};
use runtrue_engine::CredentialTaint;
use runtrue_workflow_ir::ArtifactClassification;
use std::fs;

#[test]
fn cache_patterns_expand_deterministically_to_minimal_real_roots() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("src/nested")).unwrap();
    fs::write(directory.path().join("src/lib.rs"), b"lib").unwrap();
    fs::write(directory.path().join("src/nested/mod.rs"), b"mod").unwrap();
    fs::write(directory.path().join("src/notes.txt"), b"notes").unwrap();
    assert_eq!(
        expand_patterns(directory.path(), &["src/**".to_owned()]).unwrap(),
        vec!["src"]
    );
    assert_eq!(
        expand_patterns(directory.path(), &["**/*.rs".to_owned()]).unwrap(),
        vec!["src/lib.rs", "src/nested/mod.rs"]
    );
    assert_eq!(
        expand_pattern(directory.path(), "missing/**").unwrap(),
        Vec::<String>::new()
    );
}

#[cfg(unix)]
#[test]
fn cache_pattern_walk_never_descends_through_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"outside").unwrap();
    symlink(outside.path(), directory.path().join("linked")).unwrap();
    assert_eq!(
        expand_patterns(directory.path(), &["linked/**".to_owned()]).unwrap(),
        vec!["linked"]
    );
    let (_, cas) = temporary_cas().unwrap();
    assert!(cas
        .capture_path_beneath(directory.path(), "linked")
        .is_err());
}

#[test]
fn lifecycle_retry_is_bounded_and_only_for_observation_races() {
    let mut attempts = 0;
    let value = call_after_lifecycle(|| {
        attempts += 1;
        if attempts < 3 {
            Err(crate::transport::TransportError::Status {
                code: tonic::Code::FailedPrecondition,
                message: "broker request requires the declared step to be currently running"
                    .to_owned(),
            })
        } else {
            Ok(7)
        }
    })
    .unwrap();
    assert_eq!(value, 7);
    assert_eq!(attempts, 3);
}
#[test]
fn artifact_classification_uses_wire_canonical_kebab_case() {
    assert_eq!(
        classification_name(ArtifactClassification::VerifiedTestOutput),
        "verified-test-output"
    );
    assert_eq!(
        classification_name(ArtifactClassification::ReleaseCandidate),
        "release-candidate"
    );
}

#[test]
fn credential_taint_denies_cache_and_artifact_publication() {
    let taint = CredentialTaintState::default();
    assert!(taint.permits_publication());

    taint.observe(CredentialTaint::CredentialReleased);

    // Both cache save and artifact capture use this shared fail-closed gate.
    assert!(!taint.permits_publication());
    // Taint is monotonic for the workspace, including later retries/steps.
    taint.observe(CredentialTaint::None);
    assert!(!taint.permits_publication());
}
