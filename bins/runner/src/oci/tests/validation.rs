use super::*;
#[test]
fn runtime_environment_and_duplicate_json_are_rejected() {
    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    private_file(
        &fixture.paths.runtime_environment,
        br#"{"DOCKER_HOST":"unix:///var/run/docker.sock"}"#,
    );
    assert!(fixture.load(RecordingFactory::default()).is_err());

    let fixture = Fixture::new(false);
    fixture.write_job_manifest();
    private_file(
        &fixture.paths.runtime_environment,
        br#"{"PATH":"a","PATH":"b"}"#,
    );
    assert!(fixture.load(RecordingFactory::default()).is_err());
}
