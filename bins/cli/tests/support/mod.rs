#![allow(dead_code)]

use runtrue_compiler::{CompileContext, Compiler, ReusableWorkflowSource, ReusableWorkflowSources};
use runtrue_lock::LockFile;
use runtrue_model::ContentDigest;
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

pub(crate) fn runtrue() -> Command {
    Command::new(env!("CARGO_BIN_EXE_runtrue"))
}

pub(crate) fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/workflows/secure-ci.yaml")
}

#[derive(Debug)]
pub(crate) struct CapturedHttpRequest {
    pub(crate) path: String,
    pub(crate) authorization: Option<String>,
    pub(crate) idempotency_key: Option<String>,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct MockHttpResponse {
    pub(crate) status: &'static str,
    pub(crate) content_type: &'static str,
    pub(crate) replayed: Option<bool>,
    pub(crate) declared_length: Option<usize>,
    pub(crate) body: Vec<u8>,
    pub(crate) extra_headers: Vec<(&'static str, String)>,
}

impl MockHttpResponse {
    pub(crate) fn json(value: Value, replayed: bool) -> Self {
        Self {
            status: "201 Created",
            content_type: "application/json",
            replayed: Some(replayed),
            declared_length: None,
            body: serde_json::to_vec(&value).unwrap(),
            extra_headers: Vec::new(),
        }
    }
}

pub(crate) fn spawn_http_mock(
    responses: Vec<MockHttpResponse>,
) -> (String, thread::JoinHandle<Vec<CapturedHttpRequest>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut captured = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            captured.push(read_http_request(&mut stream));
            let mut headers = format!(
                "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n",
                response.status,
                response.content_type,
                response.declared_length.unwrap_or(response.body.len())
            );
            if let Some(replayed) = response.replayed {
                headers.push_str(&format!(
                    "idempotency-replayed: {}\r\n",
                    if replayed { "true" } else { "false" }
                ));
            }
            for (name, value) in response.extra_headers {
                headers.push_str(name);
                headers.push_str(": ");
                headers.push_str(&value);
                headers.push_str("\r\n");
            }
            headers.push_str("\r\n");
            stream.write_all(headers.as_bytes()).unwrap();
            if !response.body.is_empty() {
                let _ = stream.write_all(&response.body);
            }
        }
        captured
    });
    (format!("http://{address}"), handle)
}

pub(crate) fn read_http_request(stream: &mut TcpStream) -> CapturedHttpRequest {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        let mut buffer = [0_u8; 4096];
        let count = stream.read(&mut buffer).unwrap();
        assert!(count != 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 64 * 1024, "request headers are oversized");
    };
    let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let mut lines = header.split("\r\n");
    let request_line = lines.next().unwrap();
    let path = request_line.split_whitespace().nth(1).unwrap().to_owned();
    let mut content_length = 0usize;
    let mut authorization = None;
    let mut idempotency_key = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap();
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("idempotency-key") {
            idempotency_key = Some(value.to_owned());
        }
    }
    while bytes.len() - header_end < content_length {
        let mut buffer = [0_u8; 4096];
        let count = stream.read(&mut buffer).unwrap();
        assert!(count != 0, "request ended before body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    CapturedHttpRequest {
        path,
        authorization,
        idempotency_key,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

pub(crate) fn submit_workspace() -> (tempfile::TempDir, Value) {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempdir().unwrap();
    let workflows = directory.path().join(".runtrue/workflows");
    fs::create_dir_all(&workflows).unwrap();
    let workflow = r#"version: 1
name: submit-test
permissions:
  network: deny
  repository: deny
jobs:
  shared:
    uses: git+https://github.com/octo/shared.git//ci.yaml@v1
  build:
    services:
      db:
        image: registry.example/postgres:17
    steps:
      - run: { command: ["true"] }
  report:
    needs: [build, shared]
    steps:
      - run: { command: ["true"] }
  unrelated:
    steps:
      - run: { command: ["true"] }
"#;
    fs::write(workflows.join("ci.yaml"), workflow).unwrap();
    let digest = "d".repeat(64);
    let reusable = b"version: 1\njobs:\n  check:\n    steps: [{ run: { command: [\"true\"] } }]\n";
    let reusable_digest = ContentDigest::sha256(reusable);
    let reusable_hex = reusable_digest.as_str().strip_prefix("sha256:").unwrap();
    let reusable_commit = "e".repeat(40);
    let lock_text = format!(
        r#"lock_version = 1
[[image]]
source = "registry.example/postgres:17"
resolved = "registry.example/postgres@sha256:{digest}"
platform = "linux/amd64"

[[workflow]]
source = "git+https://github.com/octo/shared.git//ci.yaml@v1"
commit = "{reusable_commit}"
digest = "{reusable_digest}"
"#
    );
    fs::write(directory.path().join(".runtrue.lock"), &lock_text).unwrap();
    let reusable_store = directory.path().join(".runtrue/reusable-workflows/sha256");
    fs::create_dir_all(&reusable_store).unwrap();
    fs::write(
        reusable_store.join(format!("{reusable_hex}.yaml")),
        reusable,
    )
    .unwrap();
    let token_path = directory.path().join("submit.token");
    fs::write(&token_path, "mock-submit-token\n").unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();

    let lock = LockFile::parse(lock_text.as_bytes()).unwrap();
    let compilation = Compiler::default()
        .compile_yaml(
            workflow,
            CompileContext {
                installation_id: "remote-server".to_owned(),
                tenant_id: "remote-server".to_owned(),
                repository_id: "repo-submit".to_owned(),
                workflow_path: ".runtrue/workflows/ci.yaml".to_owned(),
                source_commit: "local-worktree".to_owned(),
                event: json!({"type": "manual"}),
                reusable_workflows: ReusableWorkflowSources::new(BTreeMap::from([(
                    "git+https://github.com/octo/shared.git//ci.yaml@v1".to_owned(),
                    ReusableWorkflowSource::new(&reusable_commit, reusable.to_vec()).unwrap(),
                )]))
                .unwrap(),
                lockfile: Some(lock),
                policy_version_ids: vec!["server-default-deny-v1".to_owned()],
                selected_job: Some("report".to_owned()),
                workflow_changed: true,
                ..CompileContext::default()
            },
        )
        .unwrap();
    let capsule = &compilation.capsule;
    let mut approval_requests = Vec::new();
    if capsule.approval.workflow_definition {
        approval_requests.push(json!({
            "id": "approval-workflow",
            "approval_kind": "workflow-definition",
            "subject_digest": compilation.approval_subject_digest,
            "status": "approved"
        }));
    }
    if capsule.approval.privileged_execution {
        approval_requests.push(json!({
            "id": "approval-privileged",
            "approval_kind": "privileged-execution",
            "subject_digest": compilation.approval_subject_digest,
            "status": "approved"
        }));
    }
    let response = json!({
        "id": "capsule-submit",
        "repository_id": "repo-submit",
        "digest": compilation.capsule_digest,
        "status": "signed",
        "workflow_digest": capsule.workflow.digest,
        "lock_digest": capsule.context.lockfile_digest,
        "risk_score": compilation.risk_report.score,
        "approval_required": capsule.approval.workflow_definition || capsule.approval.privileged_execution,
        "approval_requests": approval_requests,
        "parity_grade": capsule.expected_parity,
        "created_at": "2026-07-11T00:00:00Z",
        "signature": {"key_id": "mock", "signature": "mock"},
        "capsule": capsule,
    });
    (directory, response)
}

pub(crate) fn submit_invocation(workspace: &std::path::Path, server: &str) -> Command {
    let mut command = runtrue();
    command
        .current_dir(workspace)
        .args(["submit", "report"])
        .arg("--workflow")
        .arg(".runtrue/workflows/ci.yaml")
        .arg("--server")
        .arg(server)
        .arg("--repository-id")
        .arg("repo-submit")
        .arg("--token-file")
        .arg("submit.token")
        .arg("--allow-loopback-http")
        .arg("--json");
    command
}

pub(crate) fn mock_run_response() -> Value {
    json!({
        "id": "run-submit",
        "capsule_id": "capsule-submit",
        "status": "queued",
        "created_at": "2026-07-11T00:00:01Z",
        "started_at": null,
        "completed_at": null
    })
}

pub(crate) fn output_with_stdin(mut command: Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

pub(crate) struct ReusableWorkspace {
    pub(crate) directory: tempfile::TempDir,
    pub(crate) workflow: PathBuf,
    pub(crate) source_path: PathBuf,
}

pub(crate) fn reusable_workspace(source: &[u8]) -> ReusableWorkspace {
    let directory = tempdir().unwrap();
    let workflow = directory.path().join("workflow.yaml");
    let reference = "git+https://github.com/octo/shared.git//ci.yaml@v1";
    fs::write(
        &workflow,
        format!("version: 1\njobs:\n  shared:\n    uses: {reference}\n"),
    )
    .unwrap();
    let digest = ContentDigest::sha256(source);
    fs::write(
        directory.path().join(".runtrue.lock"),
        format!(
            "lock_version = 1\n[[workflow]]\nsource = \"{reference}\"\ncommit = \"{}\"\ndigest = \"{digest}\"\n",
            "a".repeat(40)
        ),
    )
    .unwrap();
    let store = directory.path().join(".runtrue/reusable-workflows/sha256");
    fs::create_dir_all(&store).unwrap();
    let source_path = store.join(format!(
        "{}.yaml",
        digest.as_str().strip_prefix("sha256:").unwrap()
    ));
    fs::write(&source_path, source).unwrap();
    ReusableWorkspace {
        directory,
        workflow,
        source_path,
    }
}

pub(crate) fn native_reusable_source() -> &'static [u8] {
    b"version: 1\njobs:\n  build:\n    trust: trusted-only\n    runner: { isolation: native }\n    steps: [{ run: { command: [\"/bin/true\"] } }]\n"
}

pub(crate) fn validate_reusable_workspace(workspace: &ReusableWorkspace) -> Output {
    runtrue()
        .current_dir(workspace.directory.path())
        .args(["validate", "--workflow"])
        .arg(&workspace.workflow)
        .arg("--json")
        .output()
        .unwrap()
}
