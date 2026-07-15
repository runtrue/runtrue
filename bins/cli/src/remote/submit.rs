use super::{
    super::{
        absolute, display_path, print_json, read_bounded_file, read_event, resolve_one_workflow,
        reusable::hydrate_workspace_sources, CliError, EXIT_OK, EXIT_VALIDATION,
        MAX_WORKFLOW_BYTES,
    },
    authentication::{idempotency_key, read_bearer_token, valid_api_identifier},
    client::{RemoteClient, ServerOrigin},
    models::{
        CreateCapsuleRequest, CreateRunRequest, PendingApprovalReport, RunResponse,
        SignedCapsuleResponse, SubmitReport,
    },
    SubmitArgs, SubmitError, MAX_SUBMIT_REQUEST_BYTES, SERVER_POLICY_VERSION_ID,
};
use runtrue_compiler::{CompileContext, Compiler};
use runtrue_lock::{LockFile, MAX_LOCKFILE_BYTES};
use runtrue_model::ContentDigest;
use serde::Serialize;
use std::{fs, io, path::Path};

pub(crate) fn execute(workspace: &Path, args: SubmitArgs) -> Result<u8, CliError> {
    if !valid_api_identifier(&args.repository_id) {
        return Err(SubmitError::InvalidRepositoryId.into());
    }
    let origin = ServerOrigin::parse(&args.server, args.allow_loopback_http)?;
    let token_path = absolute(workspace, args.token_file);
    let token = read_bearer_token(&token_path)?;

    let workflow = resolve_one_workflow(workspace, args.context.workflow)?;
    let workflow_bytes = read_bounded_file(&workflow, MAX_WORKFLOW_BYTES, "workflow")?;
    let workflow_yaml = String::from_utf8(workflow_bytes).map_err(|source| CliError::Utf8 {
        path: workflow.clone(),
        source,
    })?;
    let workflow_path = display_path(workspace, &workflow);
    let event = read_event(args.context.event.as_deref(), workspace)?;
    let (lockfile, lockfile_toml) = read_lockfile(workspace)?;
    let hydrated = hydrate_workspace_sources(workspace, lockfile.as_ref())?;

    let local = Compiler::default().compile_yaml(
        &workflow_yaml,
        CompileContext {
            installation_id: "remote-server".to_owned(),
            tenant_id: "remote-server".to_owned(),
            repository_id: args.repository_id.clone(),
            workflow_path: workflow_path.clone(),
            source_commit: args.context.source_commit.clone(),
            base_commit: args.context.base_commit.clone(),
            event: event.clone(),
            reusable_workflows: hydrated.compiler,
            lockfile,
            policy_version_ids: vec![SERVER_POLICY_VERSION_ID.to_owned()],
            selected_job: args.job.clone(),
            // Direct API source is not authenticated SCM content. The server
            // deliberately requires Gate A for the exact submitted capsule.
            workflow_changed: true,
            ..CompileContext::default()
        },
    )?;
    let local_canonical = local
        .capsule
        .canonical_bytes()
        .map_err(runtrue_compiler::CompileError::from)?;

    let capsule_request = CreateCapsuleRequest {
        source_commit: args.context.source_commit,
        base_commit: args.context.base_commit,
        workflow_path,
        workflow_yaml,
        event,
        lockfile_toml,
        reusable_workflows: hydrated.transport,
        selected_job: args.job,
    };
    let capsule_request_bytes = bounded_request_bytes(&capsule_request)?;
    let capsule_idempotency_key = idempotency_key("submit-capsule", &capsule_request_bytes);
    let client = RemoteClient::new(origin, token);
    let capsule_path = format!("/api/v1/repositories/{}/capsules", args.repository_id);
    let (remote, capsule_replayed): (SignedCapsuleResponse, bool) = client.post_json(
        "create capsule",
        &capsule_path,
        &capsule_idempotency_key,
        &capsule_request_bytes,
    )?;
    validate_signed_capsule_response(
        &remote,
        &args.repository_id,
        &local.capsule_digest,
        &local_canonical,
        &local.approval_subject_digest,
    )?;

    if remote.approval_required
        && !remote
            .approval_requests
            .iter()
            .all(|approval| matches!(approval.status.as_str(), "approved" | "consumed"))
    {
        let closed = remote
            .approval_requests
            .iter()
            .any(|approval| matches!(approval.status.as_str(), "denied" | "expired"));
        let status = if closed {
            "approval_closed"
        } else {
            "awaiting_approval"
        };
        let report = PendingApprovalReport {
            run_created: false,
            status,
            capsule_id: remote.id,
            capsule_digest: remote.digest,
            approval_subject_digest: local.approval_subject_digest,
            approval_requests: remote.approval_requests,
            capsule_idempotency_replayed: capsule_replayed,
        };
        if args.json {
            print_json(&report)?;
        } else {
            println!("capsule {}  {}", report.capsule_digest, report.capsule_id);
            println!("run not created: {status}");
            for approval in &report.approval_requests {
                println!(
                    "runtrue seal approve {} --subject-digest {}  ({})",
                    approval.id, approval.subject_digest, approval.approval_kind
                );
            }
            println!("rerun submit after every listed approval is approved");
        }
        return Ok(if closed { EXIT_VALIDATION } else { EXIT_OK });
    }

    let run_request = CreateRunRequest {
        priority: args.priority,
    };
    let run_request_bytes = bounded_request_bytes(&run_request)?;
    let mut run_subject = remote.id.as_bytes().to_vec();
    run_subject.push(0);
    run_subject.extend_from_slice(&run_request_bytes);
    let run_idempotency_key = idempotency_key("submit-run", &run_subject);
    let run_path = format!("/api/v1/capsules/{}/runs", remote.id);
    let (run, run_replayed): (RunResponse, bool) = client.post_json(
        "create run",
        &run_path,
        &run_idempotency_key,
        &run_request_bytes,
    )?;
    if run.capsule_id != remote.id
        || !valid_api_identifier(&run.id)
        || !run.status.is_string()
        || run.created_at.is_empty()
        || run.started_at.as_deref() == Some("")
        || run.completed_at.as_deref() == Some("")
    {
        return Err(SubmitError::MalformedResponse.into());
    }

    let report = SubmitReport {
        run_created: true,
        run_id: run.id,
        run_status: run.status,
        capsule_id: remote.id,
        capsule_digest: remote.digest,
        parity: "exact",
        expected_parity: remote.capsule.expected_parity,
        risk_score: remote.risk_score,
        approval_required: remote.approval_required,
        approval_subject_digest: local.approval_subject_digest,
        approval_requests: remote.approval_requests,
        capsule_idempotency_replayed: capsule_replayed,
        run_idempotency_replayed: run_replayed,
    };
    if args.json {
        print_json(&report)?;
    } else {
        println!("submitted run {}", report.run_id);
        println!("capsule {}  {}", report.capsule_digest, report.capsule_id);
        println!(
            "parity exact  {}",
            serde_json::to_string(&report.expected_parity)?
        );
    }
    Ok(EXIT_OK)
}

fn validate_signed_capsule_response(
    remote: &SignedCapsuleResponse,
    repository_id: &str,
    local_digest: &ContentDigest,
    local_canonical: &[u8],
    local_approval_subject: &ContentDigest,
) -> Result<(), SubmitError> {
    if remote.status != "signed"
        || remote.repository_id != repository_id
        || !valid_api_identifier(&remote.id)
        || !remote.signature.is_object()
        || remote.created_at.is_empty()
        || remote.risk_score > 100
        || remote.workflow_digest != remote.capsule.workflow.digest
        || remote.lock_digest != remote.capsule.context.lockfile_digest
        || remote.parity_grade
            != serde_json::to_value(remote.capsule.expected_parity)
                .map_err(|_| SubmitError::MalformedResponse)?
        || remote.approval_requests.len() > 32
    {
        return Err(SubmitError::MalformedResponse);
    }
    let expected_approvals = usize::from(remote.capsule.approval.workflow_definition)
        .saturating_add(usize::from(remote.capsule.approval.privileged_execution));
    let mut approval_ids = std::collections::BTreeSet::new();
    let mut approval_kinds = std::collections::BTreeSet::new();
    for approval in &remote.approval_requests {
        if !valid_api_identifier(&approval.id)
            || approval.subject_digest != *local_approval_subject
            || !matches!(
                approval.status.as_str(),
                "pending" | "approved" | "denied" | "expired" | "consumed"
            )
            || !matches!(
                approval.approval_kind.as_str(),
                "workflow-definition" | "privileged-execution"
            )
            || !approval_ids.insert(approval.id.as_str())
            || !approval_kinds.insert(approval.approval_kind.as_str())
        {
            return Err(SubmitError::MalformedResponse);
        }
    }
    if remote.approval_required != (expected_approvals != 0)
        || remote.approval_requests.len() != expected_approvals
        || remote.capsule.approval.workflow_definition
            != approval_kinds.contains("workflow-definition")
        || remote.capsule.approval.privileged_execution
            != approval_kinds.contains("privileged-execution")
    {
        return Err(SubmitError::MalformedResponse);
    }
    let remote_canonical = remote
        .capsule
        .canonical_bytes()
        .map_err(|_| SubmitError::MalformedResponse)?;
    let remote_digest = ContentDigest::sha256(&remote_canonical);
    if remote.digest != remote_digest {
        return Err(SubmitError::RemoteDigestMismatch);
    }
    if &remote.digest != local_digest || remote_canonical != local_canonical {
        return Err(SubmitError::CapsuleParityMismatch);
    }
    Ok(())
}

fn read_lockfile(workspace: &Path) -> Result<(Option<LockFile>, Option<String>), CliError> {
    let path = workspace.join(".runtrue.lock");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_bounded_file(
                &path,
                u64::try_from(MAX_LOCKFILE_BYTES).expect("lockfile limit fits u64"),
                "lock file",
            )?;
            let lockfile = LockFile::parse(&bytes)?;
            let text = String::from_utf8(bytes).map_err(|source| CliError::Utf8 {
                path: path.clone(),
                source,
            })?;
            Ok((Some(lockfile), Some(text)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((None, None)),
        Err(source) => Err(CliError::Read { path, source }),
    }
}

pub(in crate::cli::remote) fn bounded_request_bytes(
    value: &impl Serialize,
) -> Result<Vec<u8>, SubmitError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SubmitError::RequestEncoding)?;
    if bytes.len() > MAX_SUBMIT_REQUEST_BYTES {
        return Err(SubmitError::RequestTooLarge);
    }
    Ok(bytes)
}
