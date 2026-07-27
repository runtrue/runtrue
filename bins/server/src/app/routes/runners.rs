use crate::app::{
    api_token_tenant, approval_actor_id, authorize_resource, authorize_tenant_collection,
    control_plane_problem, idempotency_key, internal_problem, now_unix_ms, optional_json,
    problem_response, protect_sensitive_response, random_id, required_json, timestamp, AppState,
    RequestId, RequestPrincipal, ServerResource, IDEMPOTENCY_REPLAYED,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use runtrue_control_plane::{
    ControlPlaneError, EnrollmentTokenIssueResult, RunnerFleetRequestRecord,
    RunnerFleetRequestState, RunnerPoolFleetSnapshot, RunnerPoolRecord, RunnerPoolScalingPolicy,
    RunnerPoolStatus, RunnerPoolTemplateRecord, RunnerPoolUpdatePolicy, RunnerReplacementRecord,
    RunnerSlotRecord, VerifiedRunnerUpdateReleaseRegistration,
};
use runtrue_model::ContentDigest;
use runtrue_policy::{CedarAction, CedarResourceKind};
use runtrue_scheduler::RunnerRecord;
use serde::{Deserialize, Serialize};
#[derive(Serialize)]
pub(in crate::app) struct Items<T> {
    pub(in crate::app) items: Vec<T>,
}

pub(in crate::app) async fn list_runner_pools(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
) -> Response {
    let pools = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ManageRunnerPool,
            tenant_id,
        )
        .await
        {
            return response;
        }
        state.store.runner_pools_for_tenant(tenant_id).await
    } else {
        state.store.runner_pools().await
    };
    match pools {
        Ok(items) => Json(Items { items }).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct CreateRunnerPoolBody {
    id: String,
    tenant_id: String,
    name: String,
    #[serde(default)]
    region: Option<String>,
}

pub(in crate::app) async fn create_runner_pool(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    body: Result<Json<CreateRunnerPoolBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid runner pool",
                "request body must contain only id, tenant_id, name, and optional region",
            )
        }
    };
    if let Some(tenant_id) = api_token_tenant(&principal) {
        if tenant_id != body.tenant_id {
            return problem_response(
                &request_id,
                StatusCode::FORBIDDEN,
                "Forbidden",
                "runner pool tenant does not match the API token tenant",
            );
        }
    }
    if let Err(response) = authorize_tenant_collection(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRunnerPool,
        &body.tenant_id,
    )
    .await
    {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let pool = RunnerPoolRecord {
        id: body.id,
        tenant_id: body.tenant_id,
        name: body.name,
        region: body.region,
        status: RunnerPoolStatus::Active,
        created_unix_ms: now,
    };
    match state
        .store
        .put_runner_pool_configuration(&runtrue_control_plane::RunnerPoolConfiguration {
            pool: pool.clone(),
            scaling_policy: None,
            templates: Vec::new(),
        })
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(pool)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_runner_pool(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
) -> Response {
    match state.store.runner_pool_configuration(&pool_id).await {
        Ok(configuration) => {
            let pool = configuration.pool;
            if let Err(response) = authorize_resource(
                &state,
                &request_id,
                &principal,
                CedarAction::ManageRunnerPool,
                ServerResource::new(CedarResourceKind::RunnerPool, &pool.id, &pool.tenant_id),
            )
            .await
            {
                return response;
            }
            Json(pool).into_response()
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Serialize)]
struct CapsuleTrustKeyView {
    key_id: String,
    algorithm: &'static str,
    public_key_hex: String,
}

pub(in crate::app) async fn get_runner_capsule_trust_key(
    State(state): State<AppState>,
) -> Response {
    let key = state.capsule_signing_key.verifying_key();
    Json(CapsuleTrustKeyView {
        key_id: key.key_id().to_string(),
        algorithm: "ed25519",
        public_key_hex: hex::encode(key.to_bytes()),
    })
    .into_response()
}

#[derive(Serialize)]
struct RunnerView {
    #[serde(flatten)]
    runner: RunnerRecord,
    created_at: String,
    updated_at: String,
}

fn runner_view(record: runtrue_control_plane::PersistedRunner) -> Result<RunnerView, ()> {
    Ok(RunnerView {
        runner: record.runner,
        created_at: timestamp(record.created_unix_ms)?,
        updated_at: timestamp(record.updated_unix_ms)?,
    })
}

pub(in crate::app) async fn list_runners(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
) -> Response {
    let records = if let Some(tenant_id) = api_token_tenant(&principal) {
        if let Err(response) = authorize_tenant_collection(
            &state,
            &request_id,
            &principal,
            CedarAction::ManageRunnerPool,
            tenant_id,
        )
        .await
        {
            return response;
        }
        state.store.pool_runners_for_tenant(tenant_id).await
    } else {
        state.store.pool_runners().await
    };
    match records {
        Ok(records) => {
            let items = match records
                .into_iter()
                .map(runner_view)
                .collect::<Result<_, _>>()
            {
                Ok(items) => items,
                Err(()) => return internal_problem(&request_id),
            };
            Json(Items { items }).into_response()
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn get_runner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(runner_id): Path<String>,
) -> Response {
    match state.store.pool_runner(&runner_id).await {
        Ok(record) => {
            let pool = match state
                .store
                .runner_pool_configuration(&record.runner.pool_id)
                .await
            {
                Ok(configuration) => configuration.pool,
                Err(_) => return internal_problem(&request_id),
            };
            if let Err(response) = authorize_resource(
                &state,
                &request_id,
                &principal,
                CedarAction::ManageRunnerPool,
                ServerResource::new(
                    CedarResourceKind::Runner,
                    &record.runner.id,
                    &pool.tenant_id,
                ),
            )
            .await
            {
                return response;
            }
            match runner_view(record) {
                Ok(runner) => Json(runner).into_response(),
                Err(()) => internal_problem(&request_id),
            }
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentTokenBody {
    #[serde(default = "default_enrollment_lifetime")]
    expires_in_seconds: u64,
}

const fn default_enrollment_lifetime() -> u64 {
    600
}

#[derive(Serialize)]
struct EnrollmentTokenView<'a> {
    token: &'a str,
    expires_at: String,
}

pub(in crate::app) async fn create_enrollment_token(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let pool = match state.store.runner_pool_configuration(&pool_id).await {
        Ok(configuration) => configuration.pool,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRunnerPool,
        ServerResource::new(CedarResourceKind::RunnerPool, &pool.id, &pool.tenant_id),
    )
    .await
    {
        return response;
    }
    let idempotency_key = match idempotency_key(&request_id, &headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let body: EnrollmentTokenBody = match optional_json(&request_id, body) {
        Ok(body) => body.unwrap_or(EnrollmentTokenBody {
            expires_in_seconds: default_enrollment_lifetime(),
        }),
        Err(response) => return response,
    };
    if !(60..=3600).contains(&body.expires_in_seconds) {
        return problem_response(
            &request_id,
            StatusCode::BAD_REQUEST,
            "Invalid enrollment expiry",
            "expires_in_seconds must be between 60 and 3600",
        );
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let expires = match body
        .expires_in_seconds
        .checked_mul(1000)
        .and_then(|delta| now.checked_add(delta))
    {
        Some(expires) => expires,
        None => return internal_problem(&request_id),
    };
    match state
        .store
        .create_pool_enrollment_token_idempotent(
            &idempotency_key,
            &pool_id,
            body.expires_in_seconds,
            now,
            expires,
        )
        .await
    {
        Ok(EnrollmentTokenIssueResult::Issued(issued)) => {
            match timestamp(issued.metadata.expires_unix_ms) {
                Ok(expires_at) => {
                    let mut response = (
                        StatusCode::CREATED,
                        Json(EnrollmentTokenView {
                            token: issued.token.expose(),
                            expires_at,
                        }),
                    )
                        .into_response();
                    response.headers_mut().insert(
                        IDEMPOTENCY_REPLAYED.clone(),
                        HeaderValue::from_static("false"),
                    );
                    protect_sensitive_response(&mut response);
                    response
                }
                Err(()) => internal_problem(&request_id),
            }
        }
        Ok(EnrollmentTokenIssueResult::Replayed(_)) => {
            let mut response = problem_response(
                &request_id,
                StatusCode::CONFLICT,
                "Enrollment token already issued",
                "this idempotent request already issued a one-time token; its bearer value cannot be replayed",
            );
            response.headers_mut().insert(
                IDEMPOTENCY_REPLAYED.clone(),
                HeaderValue::from_static("true"),
            );
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn drain_runner(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(runner_id): Path<String>,
) -> Response {
    let existing = match state.store.pool_runner(&runner_id).await {
        Ok(runner) => runner,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let pool = match state
        .store
        .runner_pool_configuration(&existing.runner.pool_id)
        .await
    {
        Ok(configuration) => configuration.pool,
        Err(_) => return internal_problem(&request_id),
    };
    if let Err(response) = authorize_resource(
        &state,
        &request_id,
        &principal,
        CedarAction::ManageRunnerPool,
        ServerResource::new(
            CedarResourceKind::Runner,
            &existing.runner.id,
            &pool.tenant_id,
        ),
    )
    .await
    {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    match state.store.drain_pool_runner(&runner_id, now).await {
        Ok(record) => match runner_view(record) {
            Ok(view) => (StatusCode::ACCEPTED, Json(view)).into_response(),
            Err(()) => internal_problem(&request_id),
        },
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[allow(clippy::result_large_err)]
async fn authorize_fleet_pool(
    state: &AppState,
    request_id: &RequestId,
    principal: &RequestPrincipal,
    pool_id: &str,
) -> Result<RunnerPoolRecord, Response> {
    let pool = state
        .store
        .runner_pool_configuration(pool_id)
        .await
        .map(|configuration| configuration.pool)
        .map_err(|error| control_plane_problem(request_id, error))?;
    authorize_resource(
        state,
        request_id,
        principal,
        CedarAction::ManageRunnerPool,
        ServerResource::new(CedarResourceKind::RunnerPool, &pool.id, &pool.tenant_id),
    )
    .await?;
    Ok(pool)
}

#[derive(Serialize)]
struct FleetRequestView {
    #[serde(flatten)]
    request: RunnerFleetRequestRecord,
    runner_active_jobs: u32,
    runner_last_heartbeat_unix_ms: u64,
    runner_status: Option<runtrue_scheduler::RunnerStatus>,
}

#[derive(Serialize)]
struct RunnerFleetView {
    policy: RunnerPoolScalingPolicy,
    templates: Vec<RunnerPoolTemplateRecord>,
    requests: Vec<FleetRequestView>,
    replacements: Vec<RunnerReplacementRecord>,
    #[serde(flatten)]
    snapshot: RunnerPoolFleetSnapshot,
}

pub(in crate::app) async fn get_runner_fleet(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let configuration = match state.store.runner_pool_configuration(&pool_id).await {
        Ok(configuration) => configuration,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let policy = match configuration.scaling_policy {
        Some(policy) => policy,
        None => {
            return control_plane_problem(
                &request_id,
                ControlPlaneError::NotFound {
                    kind: "runner pool scaling policy",
                    id: pool_id.clone(),
                },
            )
        }
    };
    let templates = configuration.templates;
    let requests = match state.store.fleet_requests(&pool_id).await {
        Ok(requests) => requests,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let mut request_views = Vec::with_capacity(requests.len());
    for request in requests {
        let runner = match request.runner_id.as_deref() {
            Some(runner_id) => state.store.pool_runner(runner_id).await.ok(),
            None => None,
        };
        let runner_active_jobs = match request.runner_id.as_deref() {
            Some(runner_id) => match state
                .store
                .open_runner_execution_leases(
                    runner_id,
                    crate::runner_service::MAX_ACTIVE_LEASES_PER_RUNNER,
                )
                .await
            {
                Ok(leases) => u32::try_from(leases.len()).unwrap_or(u32::MAX),
                Err(error) => return control_plane_problem(&request_id, error),
            },
            None => 0,
        };
        request_views.push(FleetRequestView {
            runner_status: runner.as_ref().map(|runner| runner.runner.status),
            runner_active_jobs,
            runner_last_heartbeat_unix_ms: runner
                .as_ref()
                .map_or(0, |runner| runner.runner.last_heartbeat_unix_ms),
            request,
        });
    }
    let snapshot = match state.store.pool_fleet_snapshot(&pool_id, now).await {
        Ok(snapshot) => snapshot,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let replacements = match state.store.replacements(&pool_id).await {
        Ok(values) => values,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    Json(RunnerFleetView {
        policy,
        templates,
        requests: request_views,
        replacements,
        snapshot,
    })
    .into_response()
}

pub(in crate::app) async fn put_runner_update_release(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    body: Result<
        Json<VerifiedRunnerUpdateReleaseRegistration>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let Json(registration) = match body {
        Ok(value) => value,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid runner release",
                "request body is not a closed runner update release",
            )
        }
    };
    let now = match now_unix_ms(&request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match state.store.put_runner_release(&registration, now).await {
        Ok(()) => (StatusCode::CREATED, Json(registration.release)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn put_runner_update_policy(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    body: Result<Json<RunnerPoolUpdatePolicy>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let Json(policy) = match body {
        Ok(value) if value.pool_id == pool_id => value,
        _ => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid runner update policy",
                "policy must be closed and bound to this pool",
            )
        }
    };
    match state.store.put_pool_update_policy(&policy).await {
        Ok(()) => (StatusCode::CREATED, Json(policy)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct PlanRunnerReplacementBody {
    fencing_generation: u64,
    #[serde(default)]
    source_runner_id: Option<String>,
}

pub(in crate::app) async fn plan_runner_replacement(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    body: Result<Json<PlanRunnerReplacementBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid replacement request",
                "request body is malformed",
            )
        }
    };
    let existing = match state.store.replacements(&pool_id).await {
        Ok(values) => values,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let source = match body.source_runner_id {
        Some(id) => id,
        None => {
            let runners = match state.store.pool_runners().await {
                Ok(values) => values,
                Err(error) => return control_plane_problem(&request_id, error),
            };
            match runners.into_iter().find(|runner| {
                runner.runner.pool_id == pool_id
                    && runner.runner.status == runtrue_scheduler::RunnerStatus::Online
                    && !existing.iter().any(|replacement| {
                        !matches!(
                            replacement.state,
                            runtrue_control_plane::RunnerReplacementState::Completed
                                | runtrue_control_plane::RunnerReplacementState::Failed
                                | runtrue_control_plane::RunnerReplacementState::Canceled
                        ) && (replacement.source_runner_id == runner.runner.id
                            || replacement.target_runner_id.as_deref() == Some(&runner.runner.id))
                    })
            }) {
                Some(value) => value.runner.id,
                None => return StatusCode::NO_CONTENT.into_response(),
            }
        }
    };
    let replacement_id = match random_id("replace") {
        Ok(value) => value,
        Err(()) => return internal_problem(&request_id),
    };
    let fleet_id = match random_id("fleet") {
        Ok(value) => value,
        Err(()) => return internal_problem(&request_id),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let owner = approval_actor_id(&principal);
    match state
        .store
        .plan_autoscaled_replacement(runtrue_control_plane::AutoscaledReplacementPlan {
            pool_id: &pool_id,
            source_runner_id: &source,
            replacement_id: &replacement_id,
            fleet_request_id: &fleet_id,
            owner_id: &owner,
            fencing_generation: body.fencing_generation,
            now_unix_ms: now,
        })
        .await
    {
        Ok(value) => (StatusCode::CREATED, Json(value)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn activate_runner_replacement(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((pool_id, replacement_id)): Path<(String, String)>,
    body: Result<Json<PlanRunnerReplacementBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let now = match now_unix_ms(&request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid activation request",
                "fencing_generation is required",
            )
        }
    };
    let owner = approval_actor_id(&principal);
    match state
        .store
        .activate_replacement(&replacement_id, &owner, body.fencing_generation, now)
        .await
    {
        Ok(value) if value.pool_id == pool_id => Json(value).into_response(),
        Ok(_) => problem_response(
            &request_id,
            StatusCode::NOT_FOUND,
            "Resource not found",
            "replacement is not in this pool",
        ),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn put_runner_slot(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    body: Result<Json<RunnerSlotRecord>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let Json(slot) = match body {
        Ok(value) if value.pool_id == pool_id => value,
        _ => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid runner slot",
                "slot must be closed and bound to this pool",
            )
        }
    };
    match state.store.put_fixed_runner_slot(&slot).await {
        Ok(()) => (StatusCode::CREATED, Json(slot)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct FixedUpdateClaimBody {
    public_key_hex: String,
    signature_hex: String,
    nonce_digest: ContentDigest,
    issued_unix_ms: u64,
    #[serde(default = "default_launch_claim_lifetime_ms")]
    expires_in_ms: u64,
}

pub(in crate::app) async fn create_fixed_update_claim(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((pool_id, slot_id)): Path<(String, String)>,
    body: Result<Json<FixedUpdateClaimBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let Json(body) = match body {
        Ok(value) => value,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid fixed-host update claim",
                "identity proof and bounded expiry are required",
            )
        }
    };
    let now = match now_unix_ms(&request_id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(expires) = now.checked_add(body.expires_in_ms) else {
        return internal_problem(&request_id);
    };
    if body.issued_unix_ms > now.saturating_add(5_000)
        || now.saturating_sub(body.issued_unix_ms) > 60_000
    {
        return problem_response(
            &request_id,
            StatusCode::BAD_REQUEST,
            "Invalid fixed-host update claim",
            "updater identity proof is not fresh",
        );
    }
    let slot = match state.store.fixed_runner_slot(&slot_id).await {
        Ok(slot) if slot.pool_id == pool_id => slot,
        Ok(_) => {
            return problem_response(
                &request_id,
                StatusCode::NOT_FOUND,
                "Resource not found",
                "the requested runner slot was not found",
            )
        }
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let public_key = match hex::decode(&body.public_key_hex)
        .ok()
        .and_then(|value| <[u8; 32]>::try_from(value).ok())
    {
        Some(value) if ContentDigest::sha256(value) == slot.updater_identity_digest => value,
        _ => {
            return problem_response(
                &request_id,
                StatusCode::FORBIDDEN,
                "Forbidden",
                "updater public key does not match the registered slot identity",
            )
        }
    };
    let signature = match hex::decode(&body.signature_hex)
        .ok()
        .and_then(|value| <[u8; 64]>::try_from(value).ok())
    {
        Some(value) => Signature::from_bytes(&value),
        None => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid fixed-host update claim",
                "updater identity signature is malformed",
            )
        }
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key) {
        Ok(value) => value,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid fixed-host update claim",
                "updater public key is malformed",
            )
        }
    };
    let nonce = match runtrue_protocol::v1::Digest::try_from(&body.nonce_digest) {
        Ok(value) => value,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid fixed-host update claim",
                "updater identity nonce digest is malformed",
            )
        }
    };
    let proof_message = match runtrue_update::fixed_updater_claim_proof_message(
        &pool_id,
        &slot_id,
        &body.nonce_digest,
        body.issued_unix_ms,
    ) {
        Ok(value) => value,
        Err(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid fixed-host update claim",
                "updater identity proof fields are malformed",
            )
        }
    };
    if verifying_key.verify(&proof_message, &signature).is_err() {
        return problem_response(
            &request_id,
            StatusCode::FORBIDDEN,
            "Forbidden",
            "updater identity signature is invalid",
        );
    }
    let proof = runtrue_protocol::v1::AttestationEvidence {
        kind: "runtrue.update.fixed-host".into(),
        evidence: public_key.to_vec(),
        endorsement: signature.to_bytes().to_vec(),
        nonce: Some(nonce),
    };
    let identity_proof_digest = crate::runner_service::launch_identity_proof_digest(&proof);
    match state
        .store
        .create_fixed_update_claim(&slot_id, &identity_proof_digest, now, expires)
        .await
    {
        Ok(issued) => {
            let mut response = (
                StatusCode::CREATED,
                Json(LaunchClaimView {
                    token: issued.token.expose(),
                    expires_unix_ms: issued.metadata.expires_unix_ms,
                }),
            )
                .into_response();
            protect_sensitive_response(&mut response);
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct AcquireAutoscalerLeaseBody {
    expires_in_ms: u64,
}

pub(in crate::app) async fn acquire_runner_fleet_lease(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let body: AcquireAutoscalerLeaseBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let owner_id = approval_actor_id(&principal);
    if !(10_000..=300_000).contains(&body.expires_in_ms) {
        return problem_response(
            &request_id,
            StatusCode::BAD_REQUEST,
            "Invalid autoscaler lease",
            "expires_in_ms must be between 10000 and 300000",
        );
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let Some(expires) = now.checked_add(body.expires_in_ms) else {
        return internal_problem(&request_id);
    };
    match state
        .store
        .acquire_autoscaler_lease(&pool_id, &owner_id, now, expires)
        .await
    {
        Ok(lease) => Json(lease).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetTemplateBody {
    runtime_compatibility_digest: ContentDigest,
    provider: String,
    provider_template_id: String,
    runner_template_digest: ContentDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct CreateFleetRequestBody {
    #[serde(default)]
    request_id: Option<String>,
    fencing_generation: u64,
    template: FleetTemplateBody,
}

pub(in crate::app) async fn create_runner_fleet_request(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(pool_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let body: CreateFleetRequestBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match body.request_id {
        Some(id) if id.starts_with("fleet-") && id.len() <= 200 => id,
        Some(_) => {
            return problem_response(
                &request_id,
                StatusCode::BAD_REQUEST,
                "Invalid fleet request",
                "request_id must be a bounded fleet-* identifier",
            )
        }
        None => match random_id("fleet") {
            Ok(id) => id,
            Err(()) => return internal_problem(&request_id),
        },
    };
    let request = RunnerFleetRequestRecord {
        id,
        pool_id,
        runtime_compatibility_digest: body.template.runtime_compatibility_digest,
        provider: body.template.provider,
        provider_template_id: body.template.provider_template_id,
        runner_template_digest: body.template.runner_template_digest,
        state: RunnerFleetRequestState::Requested,
        provider_request_id: None,
        provider_instance_id: None,
        runner_id: None,
        failure_code: None,
        created_unix_ms: now,
        updated_unix_ms: now,
    };
    let owner_id = approval_actor_id(&principal);
    match state
        .store
        .create_fleet_request(&request, &owner_id, body.fencing_generation)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(request)).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct TransitionFleetRequestBody {
    expected_state: RunnerFleetRequestState,
    next_state: RunnerFleetRequestState,
    fencing_generation: u64,
    #[serde(default)]
    detail: Option<String>,
}

pub(in crate::app) async fn transition_runner_fleet_request(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((pool_id, fleet_request_id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let existing = match state.store.fleet_request(&fleet_request_id).await {
        Ok(existing) if existing.pool_id == pool_id => existing,
        Ok(_) => {
            return problem_response(
                &request_id,
                StatusCode::NOT_FOUND,
                "Resource not found",
                "the fleet request was not found in this runner pool",
            )
        }
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let body: TransitionFleetRequestBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if existing.state != body.expected_state {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Conflict",
            "the fleet request state changed before this transition",
        );
    }
    let detail = body.detail.as_deref();
    let provider_request_id = (body.next_state == RunnerFleetRequestState::Provisioning)
        .then_some(detail)
        .flatten();
    let failure_code = matches!(
        body.next_state,
        RunnerFleetRequestState::Failed | RunnerFleetRequestState::Quarantined
    )
    .then_some(detail)
    .flatten();
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let owner_id = approval_actor_id(&principal);
    match state
        .store
        .transition_fleet_request(
            &fleet_request_id,
            body.expected_state,
            body.next_state,
            provider_request_id,
            None,
            None,
            failure_code,
            &owner_id,
            body.fencing_generation,
            now,
        )
        .await
    {
        Ok(request) => Json(request).into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::app) struct CreateLaunchClaimBody {
    fencing_generation: u64,
    provider_instance_id: String,
    identity_proof_digest: ContentDigest,
    #[serde(default = "default_launch_claim_lifetime_ms")]
    expires_in_ms: u64,
}

const fn default_launch_claim_lifetime_ms() -> u64 {
    5 * 60 * 1_000
}

#[derive(Serialize)]
struct LaunchClaimView<'a> {
    token: &'a str,
    expires_unix_ms: u64,
}

pub(in crate::app) async fn create_runner_launch_claim(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path((pool_id, fleet_request_id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = authorize_fleet_pool(&state, &request_id, &principal, &pool_id).await {
        return response;
    }
    let existing = match state.store.fleet_request(&fleet_request_id).await {
        Ok(existing) if existing.pool_id == pool_id => existing,
        Ok(_) => {
            return problem_response(
                &request_id,
                StatusCode::NOT_FOUND,
                "Resource not found",
                "the fleet request was not found in this runner pool",
            )
        }
        Err(error) => return control_plane_problem(&request_id, error),
    };
    if existing.state != RunnerFleetRequestState::Provisioning {
        return problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Conflict",
            "the fleet request is not awaiting a launch claim",
        );
    }
    let body: CreateLaunchClaimBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !(60_000..=15 * 60 * 1_000).contains(&body.expires_in_ms) {
        return problem_response(
            &request_id,
            StatusCode::BAD_REQUEST,
            "Invalid launch claim",
            "expires_in_ms must be between 60000 and 900000",
        );
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let Some(expires) = now.checked_add(body.expires_in_ms) else {
        return internal_problem(&request_id);
    };
    let owner_id = approval_actor_id(&principal);
    match state
        .store
        .create_launch_claim(
            &fleet_request_id,
            &body.provider_instance_id,
            &body.identity_proof_digest,
            &owner_id,
            body.fencing_generation,
            now,
            expires,
        )
        .await
    {
        Ok(issued) => {
            let mut response = (
                StatusCode::CREATED,
                Json(LaunchClaimView {
                    token: issued.token.expose(),
                    expires_unix_ms: issued.metadata.expires_unix_ms,
                }),
            )
                .into_response();
            protect_sensitive_response(&mut response);
            response
        }
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn scope_tenant(
    state: &AppState,
    scope: &str,
) -> Result<String, ControlPlaneError> {
    if let Some(repository_id) = scope.strip_prefix("repository:") {
        return state
            .store
            .repository(repository_id)
            .await
            .map(|repository| repository.tenant_id);
    }
    if let Some(tenant_id) = scope.strip_prefix("tenant:") {
        if tenant_id.is_empty() {
            return Err(ControlPlaneError::InvalidInput("tenant scope is empty"));
        }
        return Ok(tenant_id.to_owned());
    }
    Ok("default".to_owned())
}
use axum::response::IntoResponse as _;
