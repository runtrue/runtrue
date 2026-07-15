#![allow(unused_imports)]

use runtrue_compiler::{
    CompileContext, Compiler, ReusableWorkflowSource, ReusableWorkflowSources,
    MAX_REUSABLE_SOURCE_BYTES,
};
use runtrue_lock::LockFile;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::ExecutionCapsule;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};
use tempfile::tempdir;

mod support;
use support::*;

#[test]
fn submit_reports_exact_pending_approvals_without_attempting_a_run() {
    let (workspace, mut capsule) = submit_workspace();
    for approval in capsule["approval_requests"].as_array_mut().unwrap() {
        approval["status"] = json!("pending");
    }
    let expected = capsule["approval_requests"].clone();
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse::json(capsule, false)]);
    let output = submit_invocation(workspace.path(), &server)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["run_created"], false);
    assert_eq!(report["status"], "awaiting_approval");
    assert_eq!(report["approval_requests"], expected);
    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].path.ends_with("/capsules"));
}

#[test]
fn submit_proves_exact_locked_selected_job_parity_and_is_idempotent() {
    let (workspace, capsule) = submit_workspace();
    let run = mock_run_response();
    let (server, handle) = spawn_http_mock(vec![
        MockHttpResponse::json(capsule.clone(), false),
        MockHttpResponse::json(run.clone(), false),
        MockHttpResponse::json(capsule, true),
        MockHttpResponse::json(run, true),
    ]);

    let first = submit_invocation(workspace.path(), &server)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_report: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_report["parity"], "exact");
    assert_eq!(first_report["run_id"], "run-submit");
    assert_eq!(first_report["capsule_idempotency_replayed"], false);
    assert_eq!(first_report["run_idempotency_replayed"], false);

    let replay = submit_invocation(workspace.path(), &server)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay_report: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay_report["capsule_idempotency_replayed"], true);
    assert_eq!(replay_report["run_idempotency_replayed"], true);

    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[0].path,
        "/api/v1/repositories/repo-submit/capsules"
    );
    assert_eq!(requests[1].path, "/api/v1/capsules/capsule-submit/runs");
    assert_eq!(requests[2].path, requests[0].path);
    assert_eq!(requests[3].path, requests[1].path);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer mock-submit-token")
    );
    assert!(requests
        .iter()
        .all(|request| request.authorization == requests[0].authorization));
    assert_eq!(requests[0].idempotency_key, requests[2].idempotency_key);
    assert_eq!(requests[1].idempotency_key, requests[3].idempotency_key);
    assert_ne!(requests[0].idempotency_key, requests[1].idempotency_key);
    assert_eq!(requests[0].body, requests[2].body);
    assert_eq!(requests[1].body, requests[3].body);
    let run_request: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(run_request, json!({"priority": 0}));
    let capsule_request: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(capsule_request["selected_job"], "report");
    assert!(capsule_request["lockfile_toml"]
        .as_str()
        .unwrap()
        .contains("registry.example/postgres:17"));
    let reusable = capsule_request["reusable_workflows"].as_array().unwrap();
    assert_eq!(reusable.len(), 1);
    assert_eq!(
        reusable[0]["reference"],
        "git+https://github.com/octo/shared.git//ci.yaml@v1"
    );
    assert!(reusable[0]["source_hex"]
        .as_str()
        .unwrap()
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
}

#[test]
fn submit_aborts_before_run_on_remote_digest_or_capsule_mismatch() {
    let (workspace, mut digest_mismatch) = submit_workspace();
    digest_mismatch["digest"] = json!(ContentDigest::sha256(b"wrong-capsule"));
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse::json(digest_mismatch, false)]);
    let output = submit_invocation(workspace.path(), &server)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "remote_capsule_digest_mismatch");
    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].path.ends_with("/capsules"));

    let (workspace, mut capsule_mismatch) = submit_workspace();
    capsule_mismatch["capsule"]["compiler_version"] = json!("tampered-compiler");
    let changed: ExecutionCapsule =
        serde_json::from_value(capsule_mismatch["capsule"].clone()).unwrap();
    capsule_mismatch["digest"] = json!(changed.digest().unwrap());
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse::json(capsule_mismatch, false)]);
    let output = submit_invocation(workspace.path(), &server)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "capsule_parity_mismatch");
    assert_eq!(handle.join().unwrap().len(), 1);
}

#[test]
fn submit_rejects_redirect_malformed_oversized_and_token_echo_responses() {
    let (workspace, _) = submit_workspace();
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse {
        status: "307 Temporary Redirect",
        content_type: "text/plain",
        replayed: None,
        declared_length: None,
        body: Vec::new(),
        extra_headers: vec![("location", "http://127.0.0.1:9/stolen".to_owned())],
    }]);
    let output = submit_invocation(workspace.path(), &server)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "submit_remote_rejected");
    assert_eq!(handle.join().unwrap().len(), 1);

    let (workspace, _) = submit_workspace();
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse {
        status: "201 Created",
        content_type: "application/json",
        replayed: Some(false),
        declared_length: None,
        body: b"{not-json".to_vec(),
        extra_headers: Vec::new(),
    }]);
    let output = submit_invocation(workspace.path(), &server)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "submit_response_invalid");
    assert_eq!(handle.join().unwrap().len(), 1);

    let (workspace, _) = submit_workspace();
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse {
        status: "201 Created",
        content_type: "application/json",
        replayed: Some(false),
        declared_length: Some(16 * 1024 * 1024 + 1),
        body: Vec::new(),
        extra_headers: Vec::new(),
    }]);
    let output = submit_invocation(workspace.path(), &server)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "submit_response_too_large");
    assert_eq!(handle.join().unwrap().len(), 1);

    let (workspace, _) = submit_workspace();
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse {
        status: "401 Unauthorized",
        content_type: "text/plain",
        replayed: None,
        declared_length: None,
        body: b"Bearer mock-submit-token".to_vec(),
        extra_headers: Vec::new(),
    }]);
    let output = submit_invocation(workspace.path(), &server)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("mock-submit-token"));
    assert_eq!(
        handle.join().unwrap()[0].authorization.as_deref(),
        Some("Bearer mock-submit-token")
    );
}

#[cfg(unix)]
#[test]
fn submit_token_file_is_private_regular_and_never_follows_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let (workspace, _) = submit_workspace();
    let token = workspace.path().join("submit.token");
    fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
    let output = submit_invocation(workspace.path(), "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "unsafe_token_file");

    let (workspace, _) = submit_workspace();
    let token = workspace.path().join("submit.token");
    fs::remove_file(&token).unwrap();
    let victim = workspace.path().join("victim.token");
    fs::write(&victim, "must-not-leak").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&victim, &token).unwrap();
    let output = submit_invocation(workspace.path(), "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("must-not-leak"));
    let error: Value = serde_json::from_str(&stderr).unwrap();
    assert_eq!(error["error"]["code"], "token_read_failed");
}

#[test]
fn seal_approve_posts_an_exact_subject_with_hardened_transport() {
    let (workspace, _) = submit_workspace();
    let subject = ContentDigest::sha256(b"approval-subject");
    let response = json!({
        "id": "approval-1",
        "subject_digest": subject,
        "approval_kind": "workflow_definition",
        "status": "approved",
        "risk_score": 42,
        "expires_at": "2026-07-12T00:00:00Z"
    });
    let (server, handle) = spawn_http_mock(vec![MockHttpResponse::json(response, false)]);
    let output = runtrue()
        .current_dir(workspace.path())
        .args(["seal", "approve"])
        .arg("approval-1")
        .arg("--subject-digest")
        .arg(subject.to_string())
        .args([
            "--reason",
            "reviewed exact workflow and risk diff",
            "--rule-id",
            "workflow-security-owner",
            "--server",
        ])
        .arg(&server)
        .args([
            "--token-file",
            "submit.token",
            "--allow-loopback-http",
            "--json",
        ])
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["approval"]["id"], "approval-1");
    assert_eq!(report["approval"]["subject_digest"], subject.to_string());
    assert_eq!(report["idempotency_replayed"], false);

    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        "/api/v1/approval-requests/approval-1/decisions"
    );
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer mock-submit-token")
    );
    assert!(requests[0]
        .idempotency_key
        .as_deref()
        .is_some_and(|key| key.starts_with("seal-")));
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["decision"], "approve");
    assert_eq!(body["subject_digest"], subject.to_string());
    assert_eq!(body["rule_id"], "workflow-security-owner");
}
