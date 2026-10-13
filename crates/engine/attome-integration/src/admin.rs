//! `/api/v1/admin/integrations/systems` — the three operations the generic
//! entity API (`/api/v1/integration_system`, still used for list/read/
//! rename/deactivate/delete) genuinely cannot express (guidelines §9):
//!
//! * **Create** (`POST .../systems`) — SSRF-screens `base_url` at save time
//!   and, if a `credential_value` is supplied, provisions it into
//!   `integration_credential` (D-424) before the entity row is ever
//!   readable with a real `credential_ref`. Both writes go through
//!   `attome_records::entity_crud::{create_record_for,update_record_for}` — the
//!   same generic-entity mutation path any other create/update takes, so
//!   rules/state/audit/security-share-grant all apply identically (D-425;
//!   this crate's admin caller is not a service principal, unlike the
//!   inbound webhook path in `webhook.rs`, but it is still never a
//!   route-local `UPDATE ... SET` against a provisioned entity table).
//! * **Rotate credential** (`POST .../systems/{id}/credential`) — the only
//!   writer of a system's credential after creation. Never returns the
//!   value back (D-424).
//! * **Test connection** (`POST .../systems/{id}/test-connection`) — calls
//!   the system's `Connector::health`, dial-time SSRF-guarded
//!   (`connector::adapters::rest`'s module doc).

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::connector::ConnectorKind;
use crate::{credential, guard, system};

const ENTITY: &str = "integration_system";

fn valid_kind(s: &str) -> bool {
    ConnectorKind::parse(s).is_some()
}

fn valid_auth_type(s: &str) -> bool {
    matches!(
        s,
        "api_key" | "oauth2_client_credentials" | "basic" | "hmac"
    )
}

// ── Request/response types ──────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CreateSystemBody {
    name: String,
    kind: String,
    base_url: String,
    auth_type: String,
    /// The `user_account` id whose `SecurityContext` gates every
    /// write this system's inbound webhook makes (D-425) — see
    /// `system::ensure_service_principal_exists`.
    service_principal_ref: Uuid,
    #[serde(default)]
    rate_limit: Option<f64>,
    /// JSON-encoded adapter config (endpoint templates, pagination style) —
    /// stored as-is; `connector::adapters::rest` reads it once Phase 2 needs
    /// per-system endpoint shaping.
    #[serde(default)]
    config: Option<String>,
    /// Plaintext, accepted exactly once — never stored on the entity row,
    /// never echoed back. Optional: a system can be registered before its
    /// credential is known and rotated in later.
    #[serde(default)]
    credential_value: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct SystemCreatedResponse {
    id: Uuid,
    name: String,
    kind: String,
    status: String,
    /// Whether `credential_value` was provided and stored — never the value
    /// itself.
    credential_configured: bool,
}

#[derive(Deserialize, ToSchema)]
struct RotateCredentialBody {
    credential_value: String,
}

#[derive(Serialize, ToSchema)]
struct RotateCredentialResponse {
    system_id: Uuid,
    /// "configured, ending in ****1234" — never the full value (D-424).
    secret_last4: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct TestConnectionResponse {
    ok: bool,
    detail: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/admin/integrations/systems",
    tag = "admin-integrations",
    request_body = CreateSystemBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = SystemCreatedResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_system(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateSystemBody>,
) -> Result<(StatusCode, Json<SystemCreatedResponse>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if !valid_kind(&body.kind) {
        return Err(AppError::Validation(format!(
            "kind must be one of {:?}",
            [
                "rest",
                "mailbox",
                "channel",
                "esign",
                "calendar",
                "file_drop"
            ]
        )));
    }
    if !valid_auth_type(&body.auth_type) {
        return Err(AppError::Validation(
            "auth_type must be one of [\"api_key\", \"oauth2_client_credentials\", \"basic\", \"hmac\"]"
                .into(),
        ));
    }
    if !state.base.config.integration.enabled {
        return Err(AppError::Validation(
            "integration systems are disabled on this deployment (integration.enabled = false)"
                .into(),
        ));
    }
    let url = reqwest::Url::parse(&body.base_url)
        .map_err(|_| AppError::Validation("base_url is not a valid URL".into()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(AppError::Validation(
            "base_url must be http or https".into(),
        ));
    }
    // Save-time SSRF screening — re-checked again at every send
    // (`connector::adapters::rest`'s module doc), since DNS can change
    // between now and then.
    attome_server::ssrf_guard::validate_url(&url)
        .await
        .map_err(|e| AppError::Validation(format!("base_url rejected: {e}")))?;

    system::ensure_service_principal_exists(&state.base.db, body.service_principal_ref).await?;

    // The privilege check `Authorized<RecordScoped<Create>>` would perform
    // for an HTTP caller of the generic route — see `create_record_for`'s
    // doc for why a non-HTTP-shaped caller (this bespoke handler) must do
    // it explicitly.
    ctx.require(ENTITY, "create")?;

    let record = serde_json::json!({
        "name": body.name.trim(),
        "kind": body.kind,
        "base_url": url.as_str(),
        "auth_type": body.auth_type,
        "status": "active",
        "rate_limit": body.rate_limit,
        "config": body.config,
        "service_principal_ref": body.service_principal_ref.to_string(),
    });

    let (record_id, _response) =
        attome_records::entity_crud::create_record_for(&state, &ctx, ctx.user_id, ENTITY, record)
            .await?;

    let mut credential_configured = false;
    if let Some(plaintext) = body.credential_value.as_deref().filter(|v| !v.is_empty()) {
        let ring = state.base.secrets.load().integration_credential_key.clone();
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let credential_id = credential::store(&mut tx, &ring, record_id, plaintext).await?;
        attome_db::tx::commit(tx).await?;

        // Backfill credential_ref through the generic engine (D-425), not a
        // route-local UPDATE — see this module's doc comment.
        let row = system::load(&state.base.db, record_id)
            .await?
            .ok_or_else(|| AppError::internal("just-created integration system vanished"))?;
        attome_records::entity_crud::update_record_for(
            &state,
            &ctx,
            ctx.user_id,
            ENTITY,
            record_id,
            row.row_version,
            serde_json::json!({ "credential_ref": credential_id.to_string() }),
        )
        .await?;
        credential_configured = true;
    }

    Ok((
        StatusCode::CREATED,
        Json(SystemCreatedResponse {
            id: record_id,
            name: body.name.trim().to_string(),
            kind: body.kind,
            status: "active".to_string(),
            credential_configured,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/integrations/systems/{id}/credential",
    tag = "admin-integrations",
    params(("id" = Uuid, Path)),
    request_body = RotateCredentialBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, attome_audit::AuditOperation::Rotate)])))),
    responses(
        (status = 200, description = "Success", body = RotateCredentialResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rotate_credential(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<RotateCredentialBody>,
) -> Result<Json<RotateCredentialResponse>, AppError> {
    if body.credential_value.is_empty() {
        return Err(AppError::Validation(
            "credential_value must not be empty".into(),
        ));
    }
    let row = system::load(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;

    ctx.require(ENTITY, "update")?;

    let ring = state.base.secrets.load().integration_credential_key.clone();
    // D-351: serializes concurrent rotations for the same system so the
    // "supersede old row, insert new" pair in `credential::rotate` can never
    // interleave with a second rotation and leave two "active" rows.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-integration/system:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another credential rotation for this system is already in progress",
        ));
    }
    let credential_id = credential::rotate(&mut tx, &ring, id, &body.credential_value).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Credential,
            attome_audit::AuditOperation::Rotate,
            ctx.user_id,
            ENTITY,
            Some(id),
        )
        .named("integration_system.credential.rotate"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    attome_records::entity_crud::update_record_for(
        &state,
        &ctx,
        ctx.user_id,
        ENTITY,
        id,
        row.row_version,
        serde_json::json!({ "credential_ref": credential_id.to_string() }),
    )
    .await?;

    let meta = credential::meta(&state.base.db, &credential_id.to_string())
        .await?
        .ok_or_else(|| AppError::internal("just-rotated credential vanished"))?;

    Ok(Json(RotateCredentialResponse {
        system_id: id,
        secret_last4: meta.secret_last4,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/integrations/systems/{id}/test-connection",
    tag = "admin-integrations",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = TestConnectionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn test_connection(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestConnectionResponse>, AppError> {
    let row = system::load(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    // "update", not "read": a successful call persists health_last_ok_at/
    // health_last_error below.
    ctx.require(ENTITY, "update")?;

    let ring = state.base.secrets.load().integration_credential_key.clone();
    let credential =
        credential::resolve(&state.base.db, &ring, row.credential_ref.as_deref()).await?;

    let Some(kind) = ConnectorKind::parse(&row.kind) else {
        return Ok(Json(TestConnectionResponse {
            ok: false,
            detail: Some(format!("unknown connector kind {:?}", row.kind)),
        }));
    };
    // M101 slice 1 — through `guard::outbound`, never `connector_for`
    // directly: this is an outbound call and it spends the customer's quota
    // with the third party, so `integration_system.rate_limit` is
    // enforced here or nowhere (it was nowhere until this change). A caller
    // over quota gets 429 before any socket is opened.
    let result = guard::outbound(&state.base.redis_coordination, &row, kind)
        .await?
        .health(&row, credential.as_deref())
        .await?;

    // Best-effort health status write-back through the generic engine
    // (D-425) — never fails the response if it can't, same posture the M62
    // delivery job's status writes take: a stale health field is a display
    // nuisance, not a correctness problem, and this handler's job is to
    // report the probe result either way.
    let mut fields = serde_json::Map::new();
    if result.ok {
        fields.insert(
            "health_last_ok_at".into(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );
        fields.insert("health_last_error".into(), serde_json::Value::Null);
    } else if let Some(detail) = &result.detail {
        fields.insert(
            "health_last_error".into(),
            serde_json::Value::String(detail.clone()),
        );
    }
    if !fields.is_empty()
        && let Err(error) = attome_records::entity_crud::update_record_for(
            &state,
            &ctx,
            ctx.user_id,
            ENTITY,
            id,
            row.row_version,
            serde_json::Value::Object(fields),
        )
        .await
    {
        tracing::warn!(%error, system_id = %id, "failed to persist test-connection health status");
    }

    Ok(Json(TestConnectionResponse {
        ok: result.ok,
        detail: result.detail,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/integrations/systems", post(create_system))
        .route(
            "/api/v1/admin/integrations/systems/{id}/credential",
            post(rotate_credential),
        )
        .route(
            "/api/v1/admin/integrations/systems/{id}/test-connection",
            post(test_connection),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(create_system, rotate_credential, test_connection))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
