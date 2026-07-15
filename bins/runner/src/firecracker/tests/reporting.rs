use super::*;
#[test]
fn remote_v1_never_emits_an_incompatible_system_log_stream() {
    let lease = lease(capsule());
    let mut report = OneJobReport::default();
    report.succeeded = true;
    report.step_results.push(GuestStepResult {
        step_id: "step".to_owned(),
        attempt: 1,
        exit_code: Some(0),
        timed_out: false,
        canceled: false,
        skipped: false,
    });
    report.logs.push(runtrue_guest_core::LogFrame {
        step_id: "step".to_owned(),
        stream: LogStream::System,
        sequence: 0,
        bytes: b"truncated".to_vec(),
    });
    assert!(matches!(
        job_execution_from_report(&lease, &ContentDigest::sha256(b"images"), report),
        Err(RunnerError::FirecrackerAssignment(message))
            if message.contains("system log frame")
    ));
}
