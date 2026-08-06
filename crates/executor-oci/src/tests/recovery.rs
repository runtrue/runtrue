use super::*;
use crate::recovery::recovery_runtime_prefix;

#[test]
fn prehydrated_images_do_not_share_runtime_state() {
    let prefix = recovery_runtime_prefix(
        Path::new("/private/runner/probe"),
        Some(Path::new("/shared/images")),
    )
    .unwrap();
    assert_eq!(
        prefix,
        [
            "--root=/private/runner/probe/storage",
            "--runroot=/private/runner/probe/run",
            "--tmpdir=/private/runner/probe/tmp",
            "--imagestore=/shared/images",
        ]
    );
}

#[test]
fn stale_runtime_state_is_not_reused() {
    let mut fixture = fixture_with(AdmissionMode::Exact);
    let request = command_request();
    let stale = fixture
        .executor
        .state_root
        .join(format!("job-{}-1", short_identity(&request.job_id)));
    fs::create_dir(stale).unwrap();
    assert!(matches!(
        fixture.executor.execute_request(&request),
        Err(OciError::InvalidState(_))
    ));
    assert!(fixture.executor.runtime().invocations.is_empty());
}
