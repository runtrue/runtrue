use crate::app::{
    api_token_tenant, approval_actor_id, authorize_resource, control_plane_problem,
    idempotency_key, internal_problem, invalid_object_problem, now_unix_ms, optional_json,
    problem_response, random_id, randomness_problem, require_bootstrap, required_json, AppState,
    RequestId, RequestPrincipal, ServerResource, IDEMPOTENCY_REPLAYED,
};
use axum::body::{boxed, Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use runtrue_control_plane::{
    ArtifactCatalogRecord, ArtifactDownloadTicketRecord, ControlPlaneError, PromotionRequestRecord,
};
use runtrue_model::ContentDigest;
use runtrue_policy::{CedarAction, CedarResourceKind};
use serde::Deserialize;
use serde_json::Value;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPromotionBody {
    target_classification: String,
    #[serde(default)]
    approval_id: Option<String>,
}

#[allow(clippy::result_large_err)]
fn artifact_for_principal(
    state: &AppState,
    request_id: &RequestId,
    principal: &RequestPrincipal,
    artifact_id: &str,
) -> Result<ArtifactCatalogRecord, Response> {
    let artifact = match api_token_tenant(principal) {
        Some(tenant_id) => state
            .control_plane
            .artifact_for_tenant(tenant_id, artifact_id),
        None => state.control_plane.artifact(artifact_id),
    }
    .map_err(|error| control_plane_problem(request_id, error))?;
    authorize_resource(
        state,
        request_id,
        principal,
        CedarAction::ViewRun,
        ServerResource::new(
            CedarResourceKind::Artifact,
            &artifact.artifact_id,
            &artifact.tenant_id,
        )
        .in_repository(&artifact.repository_id),
    )?;
    Ok(artifact)
}

pub(in crate::app) async fn get_artifact(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(artifact_id): Path<String>,
) -> Response {
    match artifact_for_principal(&state, &request_id, &principal, &artifact_id) {
        Ok(artifact) => {
            let mut response = Json(artifact).into_response();
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(response) => response,
    }
}

pub(in crate::app) async fn get_artifact_provenance(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(artifact_id): Path<String>,
) -> Response {
    let catalog = match artifact_for_principal(&state, &request_id, &principal, &artifact_id) {
        Ok(artifact) => artifact,
        Err(response) => return response,
    };
    let Some(data_plane) = &state.runner_data_plane else {
        return problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Artifact storage unavailable",
            "the artifact data plane is not configured",
        );
    };
    let artifact_id = match ContentDigest::parse(artifact_id) {
        Ok(artifact_id) => artifact_id,
        Err(_) => return not_found_problem(&request_id, "artifact"),
    };
    let artifact = match data_plane.load_artifact(&artifact_id) {
        Ok(artifact) => artifact,
        Err(_) => return internal_problem(&request_id),
    };
    if artifact.record.provenance.statement_digest != catalog.provenance_digest {
        return internal_problem(&request_id);
    }
    let mut response = Json(serde_json::json!({
        "artifact_id": artifact.artifact_id,
        "statement_digest": artifact.record.provenance.statement_digest,
        "signer_key_id": artifact.record.provenance.signer_key_id,
        "output_name": artifact.record.provenance.output_name,
        "statement": artifact.record.provenance.signed.statement,
        "signature": artifact.record.provenance.signed.signature,
    }))
    .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactDownloadTicketBody {
    #[serde(default = "default_artifact_download_ttl_seconds")]
    ttl_seconds: u64,
}

const fn default_artifact_download_ttl_seconds() -> u64 {
    300
}

pub(in crate::app) async fn create_artifact_download_ticket(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(artifact_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let artifact = match artifact_for_principal(&state, &request_id, &principal, &artifact_id) {
        Ok(artifact) => artifact,
        Err(response) => return response,
    };
    let body: ArtifactDownloadTicketBody = match optional_json(&request_id, body) {
        Ok(body) => body.unwrap_or(ArtifactDownloadTicketBody {
            ttl_seconds: default_artifact_download_ttl_seconds(),
        }),
        Err(response) => return response,
    };
    if body.ttl_seconds == 0 || body.ttl_seconds > 15 * 60 {
        return invalid_object_problem(&request_id, "artifact download TTL is invalid");
    }
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let token = match random_id("artifact-download") {
        Ok(token) => token,
        Err(()) => return randomness_problem(&request_id),
    };
    let token_hash = ContentDigest::sha256(
        [
            b"runtrue.artifact.download-ticket.v1\0".as_slice(),
            token.as_bytes(),
        ]
        .concat(),
    );
    let ticket = ArtifactDownloadTicketRecord {
        token_hash,
        artifact_id: artifact.artifact_id.clone(),
        tenant_id: artifact.tenant_id.clone(),
        principal_id: approval_actor_id(&principal),
        classification: artifact.classification.clone(),
        manifest_digest: artifact.manifest_digest.clone(),
        issued_unix_ms: now,
        expires_unix_ms: now.saturating_add(body.ttl_seconds.saturating_mul(1_000)),
        used_unix_ms: None,
    };
    match state.control_plane.issue_artifact_download_ticket(&ticket) {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "token": token,
                "artifact_id": artifact.artifact_id,
                "expires_unix_ms": ticket.expires_unix_ms,
                "download_path": format!("/api/v1/artifact-downloads/{token}"),
            })),
        )
            .into_response(),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn download_artifact(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(token): Path<String>,
) -> Response {
    if token.len() > 256 || !token.starts_with("artifact-download_") {
        return not_found_problem(&request_id, "artifact download");
    }
    let token_hash = ContentDigest::sha256(
        [
            b"runtrue.artifact.download-ticket.v1\0".as_slice(),
            token.as_bytes(),
        ]
        .concat(),
    );
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let ticket = match state.control_plane.consume_artifact_download_ticket(
        &token_hash,
        api_token_tenant(&principal),
        &approval_actor_id(&principal),
        now,
    ) {
        Ok(ticket) => ticket,
        Err(ControlPlaneError::NotFound { .. }) => {
            return not_found_problem(&request_id, "artifact download");
        }
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let Some(data_plane) = &state.runner_data_plane else {
        return internal_problem(&request_id);
    };
    let artifact_id = match ContentDigest::parse(ticket.artifact_id.clone()) {
        Ok(artifact_id) => artifact_id,
        Err(_) => return internal_problem(&request_id),
    };
    let (artifact, mut reader) = match data_plane.artifact_file_reader(&artifact_id) {
        Ok(value) => value,
        Err(_) => return internal_problem(&request_id),
    };
    if artifact.record.provenance.statement_digest
        != state
            .control_plane
            .artifact_for_tenant(&ticket.tenant_id, &ticket.artifact_id)
            .map(|record| record.provenance_digest)
            .unwrap_or_else(|_| ContentDigest::sha256(b"invalid-artifact-catalog"))
    {
        return internal_problem(&request_id);
    }
    let size = reader.size_bytes();
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender
                        .blocking_send(Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(
                            &buffer[..count],
                        )))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.blocking_send(Err(error));
                    break;
                }
            }
        }
    });
    let filename = safe_download_filename(&artifact.record.name);
    let mut response = Response::new(boxed(Body::wrap_stream(
        tokio_stream::wrappers::ReceiverStream::new(receiver),
    )));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("content-length"),
        HeaderValue::from_str(&size.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("content-disposition"), value);
    }
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn safe_download_filename(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(128)
        .collect();
    if sanitized.is_empty() {
        "artifact.bin".to_owned()
    } else {
        sanitized
    }
}

fn not_found_problem(request_id: &RequestId, kind: &str) -> Response {
    problem_response(
        request_id,
        StatusCode::NOT_FOUND,
        "Resource not found",
        format!("the requested {kind} was not found"),
    )
}

pub(in crate::app) async fn promote_artifact(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<RequestPrincipal>,
    Path(artifact_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(response) = require_bootstrap(&request_id, &principal) {
        return response;
    }
    let body: ArtifactPromotionBody = match required_json(&request_id, body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let allowed = [
        "quarantined",
        "verified-test-output",
        "release-candidate",
        "promoted-release",
        "public",
    ];
    if !allowed.contains(&body.target_classification.as_str()) {
        return invalid_object_problem(&request_id, "invalid target artifact classification");
    }
    create_promotion_response(
        &state,
        &request_id,
        &headers,
        "artifact",
        artifact_id,
        serde_json::json!({"classification": body.target_classification}),
        serde_json::json!({"approval_id": body.approval_id}),
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::app) fn create_promotion_response(
    state: &AppState,
    request_id: &RequestId,
    headers: &HeaderMap,
    kind: &str,
    source_id: String,
    target: Value,
    evidence: Value,
) -> Response {
    let idempotency_key = match idempotency_key(request_id, headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let now = match now_unix_ms(request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let id = match random_id("promotion") {
        Ok(id) => id,
        Err(()) => return randomness_problem(request_id),
    };
    let request = PromotionRequestRecord {
        id,
        kind: kind.to_owned(),
        source_id,
        target,
        evidence,
        status: "pending".to_owned(),
        created_unix_ms: now,
    };
    match state
        .control_plane
        .create_promotion_request_idempotent(&idempotency_key, &request)
    {
        Ok(result) => {
            let mut response = (StatusCode::ACCEPTED, Json(result.value)).into_response();
            response.headers_mut().insert(
                IDEMPOTENCY_REPLAYED.clone(),
                HeaderValue::from_static(if result.replayed { "true" } else { "false" }),
            );
            response
        }
        Err(error) => control_plane_problem(request_id, error),
    }
}
use axum::response::IntoResponse as _;
use std::io::Read as _;
