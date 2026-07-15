use crate::app::{
    authorize_resource, control_plane_problem, idempotency_key, internal_problem, now_unix_ms,
    problem_response, random_id, randomness_problem, required_json, timestamp, AppState, RequestId,
    RequestPrincipal, ServerResource, IDEMPOTENCY_REPLAYED, MAX_CAPSULE_EVENT_BYTES,
    MAX_CAPSULE_TEXT_BYTES, MAX_CAPSULE_WORKFLOW_BYTES, SERVER_POLICY_VERSION_ID,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_compiler::{
    CompileContext, Compiler, ReusableWorkflowSource, ReusableWorkflowSources,
    MAX_REUSABLE_BUNDLE_BYTES, MAX_REUSABLE_SOURCES, MAX_REUSABLE_SOURCE_BYTES,
};
use runtrue_control_plane::{CapsuleApiMetadata, ControlPlane, SignedCapsuleRecord};
use runtrue_lock::{LockFile, MAX_LOCKFILE_BYTES};
use runtrue_policy::{ApprovalKind, ApprovalRequest, ApprovalRule, CedarAction, CedarResourceKind};
use runtrue_workflow_ir::ExecutionCapsule;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Serialize)]
struct SignedCapsuleView {
    id: String,
    repository_id: String,
    digest: String,
    status: &'static str,
    workflow_digest: String,
    lock_digest: Option<String>,
    risk_score: u32,
    approval_required: bool,
    approval_requests: Vec<CapsuleApprovalView>,
    parity_grade: Value,
    created_at: String,
    signature: Value,
    capsule: Value,
}

#[derive(Serialize)]
struct CapsuleApprovalView {
    id: String,
    approval_kind: Value,
    subject_digest: String,
    status: Value,
}

impl CapsuleApprovalView {
    fn from_record(record: ApprovalRequest) -> Result<Self, ()> {
        Ok(Self {
            id: record.id,
            approval_kind: serde_json::to_value(record.kind).map_err(|_| ())?,
            subject_digest: record.subject_digest.to_string(),
            status: serde_json::to_value(record.status).map_err(|_| ())?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCapsuleBody {
    source_commit: String,
    #[serde(default)]
    base_commit: Option<String>,
    #[serde(default = "default_workflow_path")]
    workflow_path: String,
    workflow_yaml: String,
    event: Value,
    #[serde(default)]
    lockfile_toml: Option<String>,
    #[serde(default)]
    reusable_workflows: Vec<ReusableWorkflowBody>,
    #[serde(default)]
    selected_job: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReusableWorkflowBody {
    reference: String,
    commit: String,
    source_hex: String,
}

fn default_workflow_path() -> String {
    ".runtrue/workflows/ci.yaml".to_owned()
}

fn reusable_workflow_bundle(
    supplied: &[ReusableWorkflowBody],
    lockfile: Option<&LockFile>,
) -> Result<ReusableWorkflowSources, ()> {
    if supplied.len() > MAX_REUSABLE_SOURCES {
        return Err(());
    }
    let locked = lockfile.map_or(&[][..], LockFile::workflows);
    if supplied.len() != locked.len() {
        return Err(());
    }
    let locked = locked
        .iter()
        .map(|entry| (entry.source(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut entries = BTreeMap::new();
    let mut total = 0usize;
    for source in supplied {
        let locked = locked.get(source.reference.as_str()).ok_or(())?;
        if source.commit != locked.commit()
            || source.source_hex.len() > MAX_REUSABLE_SOURCE_BYTES.saturating_mul(2)
            || source.source_hex.len() % 2 != 0
            || source
                .source_hex
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
            || entries.contains_key(&source.reference)
        {
            return Err(());
        }
        total = total.saturating_add(source.source_hex.len() / 2);
        if total > MAX_REUSABLE_BUNDLE_BYTES {
            return Err(());
        }
        let bytes = hex::decode(&source.source_hex).map_err(|_| ())?;
        entries.insert(
            source.reference.clone(),
            ReusableWorkflowSource::new(&source.commit, bytes).map_err(|_| ())?,
        );
    }
    ReusableWorkflowSources::new(entries).map_err(|_| ())
}

pub(in crate::app) async fn create_capsule(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(repository_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateCapsuleBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let event_bytes = match serde_json::to_vec(&body.event) {
        Ok(event) => event.len(),
        Err(_) => return internal_problem(&request_id),
    };
    if !body.event.is_object()
        || event_bytes > MAX_CAPSULE_EVENT_BYTES
        || body.workflow_yaml.is_empty()
        || body.workflow_yaml.len() > MAX_CAPSULE_WORKFLOW_BYTES
        || body.source_commit.is_empty()
        || body.source_commit.len() > MAX_CAPSULE_TEXT_BYTES
        || body
            .base_commit
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_CAPSULE_TEXT_BYTES)
        || body.workflow_path.is_empty()
        || body.workflow_path.len() > MAX_CAPSULE_TEXT_BYTES
        || body
            .selected_job
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_CAPSULE_TEXT_BYTES)
        || body
            .lockfile_toml
            .as_ref()
            .is_some_and(|value| value.len() > MAX_LOCKFILE_BYTES)
    {
        return problem_response(
            &request_id,
            StatusCode::BAD_REQUEST,
            "Invalid capsule input",
            "capsule fields must be non-empty where required and fit their documented bounds",
        );
    }
    let lockfile = match body
        .lockfile_toml
        .as_deref()
        .map(|value| LockFile::parse(value.as_bytes()))
        .transpose()
    {
        Ok(lockfile) => lockfile,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid capsule input",
                "lockfile_toml is not a valid strict Runtrue lockfile",
            )
        }
    };
    let reusable_workflows = match reusable_workflow_bundle(&body.reusable_workflows, lockfile.as_ref()) {
        Ok(bundle) => bundle,
        Err(()) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid capsule input",
                "reusable_workflows must exactly match the lockfile and fit the authenticated source bounds",
            )
        }
    };
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let repository = match state.control_plane.repository(&repository_id) {
        Ok(repository) => repository,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::EditWorkflowSettings,
        ServerResource::new(
            CedarResourceKind::Workflow,
            &repository.id,
            &repository.tenant_id,
        )
        .in_repository(&repository.id),
    ) {
        return response;
    }
    let compilation = match Compiler::default().compile_yaml(
        &body.workflow_yaml,
        CompileContext {
            installation_id: state.control_plane.installation_id().to_owned(),
            tenant_id: repository.tenant_id.clone(),
            repository_id: repository.id.clone(),
            workflow_path: body.workflow_path,
            source_commit: body.source_commit,
            base_commit: body.base_commit,
            source_trust: runtrue_workflow_ir::SourceTrust::Untrusted,
            event: body.event,
            reusable_workflows,
            lockfile,
            policy_version_ids: vec![SERVER_POLICY_VERSION_ID.to_owned()],
            selected_job: body.selected_job,
            workflow_changed: true,
            ..CompileContext::default()
        },
    ) {
        Ok(compilation) => compilation,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Workflow compilation failed",
                "the workflow or compilation context is invalid",
            )
        }
    };
    let signature = match state.capsule_signing_key.sign_capsule(&compilation.capsule) {
        Ok(signature) => signature,
        Err(_) => return internal_problem(&request_id),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let capsule_id = match random_id("capsule") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let record = SignedCapsuleRecord {
        id: capsule_id.clone(),
        repository_id: repository.id,
        digest: signature.capsule_digest.clone(),
        canonical_capsule: match compilation.capsule.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return internal_problem(&request_id),
        },
        signature,
        created_unix_ms: now,
    };
    let metadata = CapsuleApiMetadata {
        capsule_id,
        approval_subject_digest: compilation.approval_subject_digest.clone(),
        risk_score: compilation.risk_report.score,
    };
    let mut approvals = Vec::new();
    for kind in [
        compilation
            .capsule
            .approval
            .workflow_definition
            .then_some(ApprovalKind::WorkflowDefinition),
        compilation
            .capsule
            .approval
            .privileged_execution
            .then_some(ApprovalKind::PrivilegedExecution),
    ]
    .into_iter()
    .flatten()
    {
        let rule = ApprovalRule {
            id: "bootstrap-security-review".to_owned(),
            required_approvals: 1,
            eligible_approvers: BTreeSet::from(["bootstrap".to_owned()]),
            forbidden_approvers: BTreeSet::new(),
            one_shot: true,
        };
        let approval_id = match random_id("approval") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        };
        let approval = match ApprovalRequest::create(
            approval_id,
            kind,
            compilation.approval_subject_digest.clone(),
            compilation.risk_report.score,
            now,
            now.saturating_add(24 * 60 * 60 * 1000),
            rule,
        ) {
            Ok(approval) => approval,
            Err(_) => return internal_problem(&request_id),
        };
        approvals.push(approval);
    }
    match state.control_plane.store_compiled_capsule_idempotent(
        &idempotency_key,
        &record,
        &state.capsule_signing_key.verifying_key(),
        &metadata,
        &approvals,
    ) {
        Ok(result) => match signed_capsule_view(&state.control_plane, result.value) {
            Ok(view) => {
                let mut response = (StatusCode::CREATED, Json(view)).into_response();
                response.headers_mut().insert(
                    IDEMPOTENCY_REPLAYED.clone(),
                    HeaderValue::from_static(if result.replayed { "true" } else { "false" }),
                );
                response
            }
            Err(()) => internal_problem(&request_id),
        },
        Err(error) => control_plane_problem(&request_id, error),
    }
}

fn signed_capsule_view(
    control_plane: &ControlPlane,
    record: SignedCapsuleRecord,
) -> Result<SignedCapsuleView, ()> {
    let capsule: ExecutionCapsule =
        serde_json::from_slice(&record.canonical_capsule).map_err(|_| ())?;
    let metadata = control_plane.capsule_api_metadata(&record.id).ok();
    let approval_requests = control_plane
        .approval_requests_for_capsule(&record.id)
        .map_err(|_| ())?
        .into_iter()
        .map(CapsuleApprovalView::from_record)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SignedCapsuleView {
        id: record.id,
        repository_id: record.repository_id,
        digest: record.digest.to_string(),
        status: "signed",
        workflow_digest: capsule.workflow.digest.to_string(),
        lock_digest: capsule
            .context
            .lockfile_digest
            .map(|digest| digest.to_string()),
        risk_score: metadata.as_ref().map_or(0, |value| value.risk_score),
        approval_required: capsule.approval.workflow_definition
            || capsule.approval.privileged_execution,
        approval_requests,
        parity_grade: serde_json::to_value(capsule.expected_parity).map_err(|_| ())?,
        created_at: timestamp(record.created_unix_ms)?,
        signature: serde_json::to_value(record.signature).map_err(|_| ())?,
        capsule: serde_json::from_slice(&record.canonical_capsule).map_err(|_| ())?,
    })
}

pub(in crate::app) async fn get_capsule(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(capsule_id): Path<String>,
) -> Response {
    let record = match state.control_plane.signed_capsule(&capsule_id) {
        Ok(record) => record,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.control_plane.repository(&record.repository_id) {
        Ok(repository) => repository,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ViewRun,
        ServerResource::new(
            CedarResourceKind::Workflow,
            &record.id,
            &repository.tenant_id,
        )
        .in_repository(&repository.id),
    ) {
        return response;
    }
    match signed_capsule_view(&state.control_plane, record) {
        Ok(view) => Json(view).into_response(),
        Err(()) => internal_problem(&request_id),
    }
}
use axum::response::IntoResponse as _;
