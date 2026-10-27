//! The runtime AI switch — the admin routes and the audited write (C11 B5,
//! P-5, row A-85).
//!
//! The read side, which every AI surface consults, is
//! `attome_core::ai_runtime_switch`; this module is how an administrator
//! changes it. Each change is one upsert of `ai_runtime_switch` (migration
//! 0494) and its `Configuration` security event, committed together (D-542).
//!
//! **It can only narrow.** The effective state is `config AND runtime`. Turning
//! a surface back on here restores what the configuration allows and nothing
//! more; a surface the configuration disabled stays disabled, and the read
//! route shows both columns so an administrator can never mistake one for the
//! other.
//!
//! **Last writer wins**, by design. Two administrators flipping the same switch
//! at once both succeed and the later one stands: each change is audited, and
//! a switch whose purpose is "off, now" must not refuse a write because
//! someone else touched it first.

use attome_core::EngineState;
use attome_core::ai_runtime_switch::{self as switch, SwitchSurface};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Longest reason an administrator may record.
const MAX_REASON_CHARS: usize = 500;

/// One surface as the admin screen shows it.
#[derive(Debug, Serialize, ToSchema)]
pub struct SurfaceSwitchView {
    /// `all`, `fields`, `chat`, `semantic_search`, `workflow_nodes` or `webchat`.
    pub surface: String,
    /// What the deployment's configuration allows. Changing it takes a
    /// restart; this route never does.
    pub configured: bool,
    /// The runtime switch: `false` only when an administrator turned it off.
    /// `null` when the switch state could not be read — which every AI
    /// surface treats as off.
    pub runtime_enabled: Option<bool>,
    /// `configured AND runtime_enabled`, as the gate applies it.
    pub effective: bool,
    pub reason: Option<String>,
    pub changed_by: Option<Uuid>,
    pub changed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuntimeSwitchView {
    pub surfaces: Vec<SurfaceSwitchView>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetSwitchRequest {
    pub enabled: bool,
    /// Why — shown beside the switch and recorded in the audit event.
    pub reason: Option<String>,
}

fn configured(state: &EngineState, surface: SwitchSurface) -> bool {
    let config = &state.base.config;
    let ai = &config.inference.ai;
    match surface {
        SwitchSurface::All => ai.enabled,
        SwitchSurface::Fields => ai.enabled && ai.fields,
        SwitchSurface::Chat => ai.enabled && ai.chat,
        SwitchSurface::SemanticSearch => ai.enabled && ai.semantic_search,
        SwitchSurface::WorkflowNodes => ai.enabled && ai.workflow_nodes,
        SwitchSurface::WebChat => ai.enabled && ai.chat && config.webchat.enabled,
    }
}

async fn view(state: &EngineState) -> Result<RuntimeSwitchView, AppError> {
    switch::refresh(&state.base.db).await;
    type Row = (String, Option<String>, Uuid, DateTime<Utc>);
    let rows: Vec<Row> =
        sqlx::query_as("SELECT surface, reason, changed_by, changed_at FROM ai_runtime_switch")
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let surfaces = SwitchSurface::ALL
        .into_iter()
        .map(|surface| {
            let row = rows.iter().find(|r| r.0 == surface.as_str());
            let configured = configured(state, surface);
            let runtime_enabled = switch::runtime_enabled(surface);
            let all_on = switch::runtime_enabled(SwitchSurface::All).unwrap_or(false);
            let effective = configured
                && runtime_enabled.unwrap_or(false)
                && (surface == SwitchSurface::All || all_on);
            SurfaceSwitchView {
                surface: surface.as_str().to_owned(),
                configured,
                runtime_enabled,
                effective,
                reason: row.and_then(|r| r.1.clone()),
                changed_by: row.map(|r| r.2),
                changed_at: row.map(|r| r.3),
            }
        })
        .collect();
    Ok(RuntimeSwitchView { surfaces })
}

/// Turns `surface` on or off at runtime, audited in the same transaction.
pub async fn set(
    state: &EngineState,
    surface: SwitchSurface,
    enabled: bool,
    reason: Option<&str>,
    actor: Uuid,
) -> Result<(), AppError> {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    if reason.is_some_and(|r| r.chars().count() > MAX_REASON_CHARS) {
        return Err(AppError::Validation(format!(
            "reason is longer than {MAX_REASON_CHARS} characters"
        )));
    }
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Configuration,
        attome_audit::AuditOperation::Update,
        actor,
        "ai_runtime_switch",
        None,
    )
    .named("ai.runtime_switch")
    .comment(format!(
        "{} {}{}",
        surface.as_str(),
        if enabled { "on" } else { "off" },
        reason.map(|r| format!(": {r}")).unwrap_or_default()
    ));
    let mut stx = attome_audit::security::SecurityTx::begin(state, event).await?;
    sqlx::query(
        "INSERT INTO ai_runtime_switch (surface, enabled, reason, changed_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (surface) DO UPDATE \
            SET enabled = EXCLUDED.enabled, reason = EXCLUDED.reason, \
                changed_by = EXCLUDED.changed_by, changed_at = NOW(), \
                row_version = ai_runtime_switch.row_version + 1",
    )
    .bind(surface.as_str())
    .bind(enabled)
    .bind(reason)
    .bind(actor)
    .execute(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    stx.commit().await?;
    // This node sees the change at once; every other within the snapshot's
    // staleness bound.
    switch::reload(&state.base.db).await;
    Ok(())
}

/// `GET /api/v1/admin/ai/runtime-switch` — every surface: what the
/// configuration allows, what the runtime switch says, and the effect.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/runtime-switch",
    tag = "action",
    responses(
        (status = 200, description = "Success", body = RuntimeSwitchView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_runtime_switch(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<RuntimeSwitchView>, AppError> {
    Ok(Json(view(&state).await?))
}

/// `PUT /api/v1/admin/ai/runtime-switch/{surface}` — turn one AI surface off,
/// or back on, without a restart (row A-85). It can only narrow: turning a
/// surface on restores what the configuration allows, never more. A running
/// conversation turn stops at its next step; nothing already dispatched is
/// undone.
#[utoipa::path(
    put,
    path = "/api/v1/admin/ai/runtime-switch/{surface}",
    tag = "action",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    params(("surface" = String, Path, description = "all, fields, chat, semantic_search, workflow_nodes or webchat")),
    request_body = SetSwitchRequest,
    responses(
        (status = 200, description = "The switch is set; the whole view is returned", body = RuntimeSwitchView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such surface", body = ErrorResponse),
        (status = 422, description = "The reason is too long, or an unknown field was sent", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_runtime_switch(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(surface): Path<String>,
    Json(body): Json<SetSwitchRequest>,
) -> Result<Json<RuntimeSwitchView>, AppError> {
    let surface = SwitchSurface::parse(&surface).ok_or(AppError::NotFound)?;
    set(
        &state,
        surface,
        body.enabled,
        body.reason.as_deref(),
        ctx.user_id,
    )
    .await?;
    Ok(Json(view(&state).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/ai/runtime-switch", get(get_runtime_switch))
        .route(
            "/api/v1/admin/ai/runtime-switch/{surface}",
            put(put_runtime_switch),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_runtime_switch, put_runtime_switch))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
