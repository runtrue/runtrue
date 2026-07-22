use crate::app::{
    api_token_tenant, approval_actor_id, authorize_resource, authorize_tenant_collection,
    control_plane_problem, idempotency_key, internal_problem, invalid_object_problem, now_unix_ms,
    optional_json, problem_response, random_id, randomness_problem, timestamp, AppState, RequestId,
    RequestPrincipal, ServerResource, IDEMPOTENCY_REPLAYED,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::{
    ControlPlaneError, CreateRunRequest as StoreCreateRunRequest, CredentialTaintState, NewJob,
    NormalizedTriggerEventRecord, ReplayBundleRecord, RepositoryRecord, RunRecord,
};
use runtrue_model::ContentDigest;
use runtrue_policy::{CedarAction, CedarResourceKind};
use runtrue_replay::ReplayBundle;
use runtrue_scheduler::SchedulingRequirements;
use runtrue_workflow_ir::ExecutionCapsule;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRunBody {
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    source_snapshot_id: Option<String>,
}

#[derive(Serialize)]
struct RunView {
    id: String,
    capsule_id: String,
    status: Value,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct RunListQuery {
    #[serde(default)]
    repository_id: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct RunPage {
    items: Vec<RunView>,
    next_cursor: Option<String>,
}

pub(in crate::app) async fn list_runs(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Query(query): Query<RunListQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50);
    let records = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ViewRun,
            tenant_id,
        )
        .await
        {
            return response;
        }
        state
            .store
            .list_runs_page_for_tenant(
                tenant_id,
                query.repository_id.as_deref(),
                query.cursor.as_deref(),
                limit,
            )
            .await
    } else {
        state
            .store
            .list_runs_page(
                query.repository_id.as_deref(),
                query.cursor.as_deref(),
                limit,
            )
            .await
    };
    let records = match records {
        Ok(records) => records,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let next_cursor = (records.len() == limit)
        .then(|| records.last().map(|record| record.id.clone()))
        .flatten();
    let items = match records
        .into_iter()
        .map(RunView::from_record)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(items) => items,
        Err(()) => return internal_problem(&request_id),
    };
    Json(RunPage { items, next_cursor }).into_response()
}

impl RunView {
    fn from_record(record: RunRecord) -> Result<Self, ()> {
        Ok(Self {
            id: record.id,
            capsule_id: record.capsule_id,
            status: serde_json::to_value(record.status).map_err(|_| ())?,
            created_at: timestamp(record.created_unix_ms)?,
            started_at: record.started_unix_ms.map(timestamp).transpose()?,
            completed_at: record.completed_unix_ms.map(timestamp).transpose()?,
        })
    }
}

pub(in crate::app) async fn create_run(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(capsule_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match optional_json::<CreateRunBody>(&request_id, body) {
        Ok(body) => body.unwrap_or_default(),
        Err(response) => return response,
    };
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let signed = match state.store.signed_capsule(&capsule_id).await {
        Ok(signed) => signed,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.store.repository(&signed.repository_id).await {
        Ok(repository) => repository,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::CreateRun,
        ServerResource::new(
            CedarResourceKind::Workflow,
            &signed.id,
            &repository.tenant_id,
        )
        .in_repository(&repository.id),
    )
    .await
    {
        return response;
    }
    let capsule: ExecutionCapsule = match serde_json::from_slice(&signed.canonical_capsule) {
        Ok(capsule) => capsule,
        Err(_) => return internal_problem(&request_id),
    };
    let source_bound = capsule.context.source_tree_digest.is_some();
    let source_snapshot_id = match (source_bound, body.source_snapshot_id.as_deref()) {
        (true, Some(snapshot_id))
            if !snapshot_id.is_empty()
                && snapshot_id.len() <= 512
                && !snapshot_id.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Some(snapshot_id.to_owned())
        }
        (true, _) => {
            return invalid_object_problem(
                &request_id,
                "a source-bound remote capsule requires source_snapshot_id",
            )
        }
        (false, None) => None,
        (false, Some(_)) => {
            return invalid_object_problem(
                &request_id,
                "source_snapshot_id is invalid for a capsule without a source-tree binding",
            )
        }
    };
    let signed_capsule_digest = signed.digest.clone();
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let run_id = match random_id("run") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let mut jobs = Vec::with_capacity(capsule.jobs.len());
    for planned in capsule.jobs {
        let job_id = match random_id("job") {
            Ok(id) => id,
            Err(()) => return randomness_problem(&request_id),
        };
        jobs.push(NewJob {
            id: job_id,
            job_key: planned.id,
            attempt: 1,
            requirements: SchedulingRequirements {
                os: planned.runner.os,
                arch: planned.runner.arch,
                isolation: planned.runner.isolation,
                cpu: u32::from(planned.runner.cpu),
                memory_bytes: planned.runner.memory_bytes,
                storage_bytes: planned.runner.storage_bytes.unwrap_or(0),
                region: planned.runner.region,
                required_capabilities: planned.runner.capabilities.into_iter().collect(),
                allowed_pools: BTreeSet::new(),
            },
        });
    }
    let request = StoreCreateRunRequest {
        id: run_id,
        repository_id: signed.repository_id,
        capsule_id,
        priority: body.priority,
        remote: true,
        created_unix_ms: now,
        jobs,
    };
    let result = match state
        .store
        .create_run_idempotent(&idempotency_key, &request)
        .await
    {
        Ok(result) => result,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if let Some(snapshot_id) = source_snapshot_id.as_deref() {
        if let Err(error) = state
            .store
            .bind_run_source_snapshot(
                &repository.tenant_id,
                &result.value.id,
                snapshot_id,
                &signed_capsule_digest,
                now,
            )
            .await
        {
            return control_plane_problem(&request_id, error);
        }
    }
    let trigger = match normalized_api_run_trigger(
        &repository,
        &request.capsule_id,
        &idempotency_key,
        &principal,
        request.priority,
        source_snapshot_id.as_deref(),
        &result.value,
    ) {
        Ok(trigger) => trigger,
        Err(()) => return internal_problem(&request_id),
    };
    if let Err(error) = state.store.record_normalized_trigger(&trigger).await {
        return control_plane_problem(&request_id, error);
    }
    match RunView::from_record(result.value) {
        Ok(run) => {
            let mut response = (StatusCode::CREATED, Json(run)).into_response();
            response.headers_mut().insert(
                IDEMPOTENCY_REPLAYED.clone(),
                HeaderValue::from_static(if result.replayed { "true" } else { "false" }),
            );
            response
        }
        Err(()) => internal_problem(&request_id),
    }
}

fn normalized_api_run_trigger(
    repository: &RepositoryRecord,
    capsule_id: &str,
    idempotency_key: &str,
    principal: &RequestPrincipal,
    priority: i32,
    source_snapshot_id: Option<&str>,
    run: &RunRecord,
) -> Result<NormalizedTriggerEventRecord, ()> {
    let actor_identity = approval_actor_id(principal);
    let idempotency_identity = format!("{actor_identity}:{idempotency_key}");
    let normalized_envelope = runtrue_workflow_ir::canonicalize_value(serde_json::json!({
        "actor_identity": actor_identity.clone(),
        "capsule_id": capsule_id,
        "priority": priority,
        "repository_id": repository.id,
        "run_id": run.id,
        "source_snapshot_id": source_snapshot_id,
        "trigger_kind": "api",
        "version": 1,
    }));
    let canonical = serde_json::to_vec(&normalized_envelope).map_err(|_| ())?;
    let normalized_digest = ContentDigest::sha256(canonical);
    let identity_digest = ContentDigest::sha256(
        format!(
            "runtrue.api-run-trigger.v1\0{}\0{}\0{}",
            repository.tenant_id, repository.id, idempotency_identity
        )
        .as_bytes(),
    );
    Ok(NormalizedTriggerEventRecord {
        id: format!(
            "api-trigger-{}",
            identity_digest.as_str().trim_start_matches("sha256:")
        ),
        tenant_id: repository.tenant_id.clone(),
        repository_id: repository.id.clone(),
        trigger_kind: "api".to_owned(),
        idempotency_identity,
        normalized_digest,
        normalized_envelope,
        actor_identity,
        created_unix_ms: run.created_unix_ms,
    })
}

pub(in crate::app) async fn get_run(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(run_id): Path<String>,
) -> Response {
    match state.store.run(&run_id).await {
        Ok(record) => {
            let repository = match state.store.repository(&record.repository_id).await {
                Ok(repository) => repository,
                Err(_) => return internal_problem(&request_id),
            };
            if let Err(response) = authorize_resource(
                &state,
                &request_id,
                &principal,
                CedarAction::ViewRun,
                ServerResource::new(CedarResourceKind::Run, &record.id, &repository.tenant_id)
                    .in_repository(&repository.id),
            )
            .await
            {
                return response;
            }
            match RunView::from_record(record) {
                Ok(run) => Json(run).into_response(),
                Err(()) => internal_problem(&request_id),
            }
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct RunLogQuery {
    #[serde(default)]
    limit: Option<usize>,
}

pub(in crate::app) async fn get_run_logs(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(run_id): Path<String>,
    Query(query): Query<RunLogQuery>,
) -> Response {
    let run = match state.store.run(&run_id).await {
        Ok(run) => run,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.store.repository(&run.repository_id).await {
        Ok(repository) => repository,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ViewRun,
        ServerResource::new(CedarResourceKind::Run, &run.id, &repository.tenant_id)
            .in_repository(&repository.id),
    )
    .await
    {
        return response;
    }
    match state
        .store
        .runner_logs_for_run(&run_id, query.limit.unwrap_or(1_000))
        .await
    {
        Ok(frames) => {
            let mut response = Json(frames).into_response();
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelRunBody {
    #[serde(default)]
    reason: Option<String>,
}

pub(in crate::app) async fn cancel_run(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let existing = match state.store.run(&run_id).await {
        Ok(run) => run,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.store.repository(&existing.repository_id).await {
        Ok(repository) => repository,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::CancelRun,
        ServerResource::new(CedarResourceKind::Run, &existing.id, &repository.tenant_id)
            .in_repository(&repository.id),
    )
    .await
    {
        return response;
    }
    let body = match optional_json::<CancelRunBody>(&request_id, body) {
        Ok(body) => body.unwrap_or_default(),
        Err(response) => return response,
    };
    let reason = body
        .reason
        .unwrap_or_else(|| "requested through the control-plane API".to_owned());
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    match state
        .store
        .cancel_run_idempotent(&idempotency_key, &run_id, &reason, now)
        .await
    {
        Ok(result) => match RunView::from_record(result.value) {
            Ok(run) => {
                let mut response = (StatusCode::ACCEPTED, Json(run)).into_response();
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

#[derive(Serialize)]
struct ReplayBundleView {
    id: String,
    digest: String,
    run_id: String,
    download_url: String,
    expires_at: String,
}

fn replay_bundle_view(record: ReplayBundleRecord) -> Result<ReplayBundleView, ()> {
    Ok(ReplayBundleView {
        id: record.id,
        digest: record.digest.to_string(),
        run_id: record.run_id.clone(),
        download_url: format!("/api/v1/runs/{}/replay-bundle", record.run_id),
        expires_at: timestamp(record.expires_unix_ms)?,
    })
}

pub(in crate::app) async fn create_replay_bundle(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let run = match state.store.run(&run_id).await {
        Ok(run) => run,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.store.repository(&run.repository_id).await {
        Ok(repository) => repository,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ViewRun,
        ServerResource::new(CedarResourceKind::Run, &run.id, &repository.tenant_id)
            .in_repository(&repository.id),
    )
    .await
    {
        return response;
    }
    match state.store.runner_run_credential_taint(&run.id).await {
        Ok(CredentialTaintState::None) => {}
        Ok(CredentialTaintState::CredentialReleased) => {
            return problem_response(
                &request_id,
                StatusCode::CONFLICT,
                "Replay Bundle publication blocked",
                "the execution released credential material into its guest or workspace",
            )
        }
        Ok(CredentialTaintState::Unknown) => {
            return problem_response(
                &request_id,
                StatusCode::CONFLICT,
                "Replay Bundle publication blocked",
                "the execution does not have explicit credential-taint evidence",
            )
        }
        Err(error) => return control_plane_problem(&request_id, error),
    }
    let signed = match state.store.signed_capsule(&run.capsule_id).await {
        Ok(capsule) => capsule,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let metadata = match state.store.capsule_api_metadata(&run.capsule_id).await {
        Ok(metadata) => metadata,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let capsule: ExecutionCapsule = match serde_json::from_slice(&signed.canonical_capsule) {
        Ok(capsule) => capsule,
        Err(_) => return internal_problem(&request_id),
    };
    let workflow_frontend_report_digest = capsule
        .context
        .workflow_frontend
        .as_ref()
        .and_then(|provenance| provenance.report_digest.clone());
    let bundle = match ReplayBundle::new(capsule, metadata.approval_subject_digest, None) {
        Ok(bundle) => bundle,
        Err(_) => return internal_problem(&request_id),
    };
    let bundle = match state.store.workflow_frontend_report(&run.capsule_id).await {
        Ok(record) => {
            let Some(digest) = workflow_frontend_report_digest else {
                return internal_problem(&request_id);
            };
            bundle.with_workflow_frontend_report(
                runtrue_workflow_ir::WorkflowFrontendReportArtifact {
                    media_type: record.media_type,
                    digest,
                    bytes: record.bytes,
                },
            )
        }
        Err(ControlPlaneError::NotFound { .. }) => bundle,
        Err(_) => return internal_problem(&request_id),
    };
    let envelope = match bundle.seal() {
        Ok(envelope) => envelope,
        Err(_) => return internal_problem(&request_id),
    };
    let canonical_bundle = match envelope.canonical_bytes() {
        Ok(bytes) => bytes,
        Err(_) => return internal_problem(&request_id),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match random_id("replay") {
        Ok(id) => id,
        Err(()) => return randomness_problem(&request_id),
    };
    let record = ReplayBundleRecord {
        id,
        run_id,
        digest: ContentDigest::sha256(&canonical_bundle),
        canonical_bundle,
        created_unix_ms: now,
        expires_unix_ms: now.saturating_add(24 * 60 * 60 * 1000),
    };
    match state
        .store
        .store_replay_bundle_idempotent(&idempotency_key, &record)
        .await
    {
        Ok(result) => match replay_bundle_view(result.value) {
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

pub(in crate::app) async fn get_replay_bundle(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(run_id): Path<String>,
) -> Response {
    let run = match state.store.run(&run_id).await {
        Ok(run) => run,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let repository = match state.store.repository(&run.repository_id).await {
        Ok(repository) => repository,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ViewRun,
        ServerResource::new(CedarResourceKind::Run, &run.id, &repository.tenant_id)
            .in_repository(&repository.id),
    )
    .await
    {
        return response;
    }
    match state.store.replay_bundle_for_run(&run_id).await {
        Ok(record) => {
            let mut response = record.canonical_bundle.into_response();
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/vnd.runtrue.replay+json"),
            );
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}
use axum::response::IntoResponse as _;
